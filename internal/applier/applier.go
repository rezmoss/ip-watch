// Package applier: pick transport, fetch ranges, run engine.
package applier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/rezmoss/ip-watch/internal/config"
	"github.com/rezmoss/ip-watch/internal/docker"
	"github.com/rezmoss/ip-watch/internal/engine"
	"github.com/rezmoss/ip-watch/internal/fetcher"
	"github.com/rezmoss/ip-watch/internal/history"
	"github.com/rezmoss/ip-watch/internal/state"
	"github.com/rezmoss/ip-watch/internal/transport"
)

// Result of one target
type Result struct {
	TargetID string    `json:"target_id"`
	Provider string    `json:"provider"`
	OK       bool      `json:"ok"`
	Changed  bool      `json:"changed"`
	Hash     string    `json:"hash,omitempty"`
	Ranges   int       `json:"ranges,omitempty"`
	Message  string    `json:"message"`
	Validate string    `json:"validate,omitempty"`
	When     time.Time `json:"when"`
}

type Applier struct {
	cfg    *config.Config
	fetch  *fetcher.Fetcher
	state  *state.Store
	dryRun bool
}

// New; dryRun: report plan only, no writes
func New(cfg *config.Config, dryRun bool) *Applier {
	store, err := state.Load(cfg.StateDir)
	if err != nil {
		log.Printf("applier: no state, change-detection off: %v", err)
		store = nil
	}
	return &Applier{
		cfg:    cfg,
		fetch:  fetcher.New(cfg.DataSource).AllowMalformed(cfg.AllowMalformedProviderData),
		state:  store,
		dryRun: dryRun,
	}
}

// serializes applies/removes vs FS, engine, cfg races
var gate sync.Mutex

// Guard: fn under in-proc gate only; mutations use GuardConfig
func Guard(fn func() error) error {
	gate.Lock()
	defer gate.Unlock()
	return fn()
}

// GuardConfig: gate + file lock; fail closed unless unsafe
func GuardConfig(stateDir string, unsafe bool, fn func() error) error {
	gate.Lock()
	defer gate.Unlock()
	release, ok := acquireFileLock(stateDir)
	if !ok {
		if !unsafe {
			return fmt.Errorf("cross-process lock unavailable at %s; refusing config mutation "+
				"(set lock_unsafe:true to override)", lockTarget(stateDir))
		}
		log.Printf("applier: WARN no file lock at %s; config save proceeding (lock_unsafe)", lockTarget(stateDir))
	}
	defer release()
	return fn()
}

// lock path for msgs
func lockTarget(stateDir string) string {
	if stateDir == "" {
		return "<no state_dir configured>"
	}
	return filepath.Join(stateDir, ".lock")
}

// advisory lock on stateDir/.lock; false = unavailable
func acquireFileLock(stateDir string) (func(), bool) {
	if stateDir == "" {
		return func() {}, false
	}
	_ = os.MkdirAll(stateDir, 0o755)
	f, err := os.OpenFile(filepath.Join(stateDir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, false
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return func() {}, false
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, true
}

// gate + file lock; fail closed unless dry-run/lock_unsafe
func (a *Applier) lock() (func(), error) {
	gate.Lock()
	release, ok := acquireFileLock(a.cfg.StateDir)
	if ok {
		return func() { release(); gate.Unlock() }, nil
	}
	if a.dryRun || a.cfg.LockUnsafe {
		if !a.dryRun {
			log.Printf("applier: WARN no file lock at %s; proceeding (lock_unsafe)", lockTarget(a.cfg.StateDir))
		}
		return gate.Unlock, nil
	}
	gate.Unlock()
	return nil, fmt.Errorf("cross-process lock unavailable at %s; refusing to apply/remove "+
		"(set lock_unsafe:true to override)", lockTarget(a.cfg.StateDir))
}

// ApplyAll: all enabled targets; !force skips unchanged
func (a *Applier) ApplyAll(ctx context.Context, force bool) []Result {
	release, err := a.lock()
	if err != nil {
		return []Result{{OK: false, Message: err.Error(), When: time.Now()}}
	}
	defer release()
	// snapshot under gate vs cfg edit
	targets := append([]config.Target(nil), a.cfg.Targets...)
	var out []Result
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		out = append(out, a.applyLocked(ctx, t, force))
	}
	return out
}

// Apply: one target
func (a *Applier) Apply(ctx context.Context, t config.Target, force bool) Result {
	release, err := a.lock()
	if err != nil {
		return Result{TargetID: t.ID, Provider: t.Provider, When: time.Now(), Message: err.Error()}
	}
	defer release()
	return a.applyLocked(ctx, t, force)
}

func (a *Applier) applyLocked(ctx context.Context, t config.Target, force bool) Result {
	r := Result{TargetID: t.ID, Provider: t.Provider, When: time.Now()}

	if err := t.Validate(); err != nil {
		r.Message = err.Error()
		return r
	}
	eng, err := engine.For(t.Engine)
	if err != nil {
		r.Message = err.Error()
		return r
	}
	tr, err := transportFor(ctx, t)
	if err != nil {
		r.Message = err.Error()
		return r
	}

	providers := t.EffectiveProviders()
	if len(providers) == 0 {
		r.Message = "no provider configured"
		return r
	}
	cidrs, err := a.fetch.FetchMerged(ctx, providers)
	if err != nil {
		r.Message = "fetch failed: " + err.Error()
		return r
	}
	// anti-lockout: keep operator access in allow mode
	if t.Mode == "allow" && len(t.AdminAllowIPs) > 0 {
		cidrs = cidrs.WithExtra(t.AdminAllowIPs)
	}
	r.Provider = cidrs.Provider
	r.Hash = cidrs.Hash
	r.Ranges = len(cidrs.V4) + len(cidrs.V6)
	fingerprint := desiredFingerprint(t, cidrs.Hash)

	// skip unchanged on !force runs; compares full fingerprint, not CIDR hash
	if !a.dryRun && !force && a.state != nil {
		if prev, ok := a.state.Get(t.ID); ok && prev.Fingerprint == fingerprint {
			r.OK = true
			r.Message = fmt.Sprintf("up to date (%d ranges, hash %s)", r.Ranges, cidrs.Hash)
			// count no-op, skip recent log
			a.recordHistory(t, r, false)
			return r
		}
	}

	out := eng.Apply(ctx, tr, engine.Input{Target: t, CIDRs: cidrs, DryRun: a.dryRun, Force: force})
	r.OK = out.OK
	r.Changed = out.Changed
	r.Validate = out.Validate
	r.Message = out.Message

	if !a.dryRun {
		// record hash on success so scheduled runs skip again
		if out.OK && a.state != nil {
			if err := a.state.Record(t.ID, cidrs.Hash, fingerprint, r.When); err != nil {
				log.Printf("applier: record state %s: %v", t.ID, err)
			}
		}
		// count every apply; log keeps changes/failures
		a.recordHistory(t, r, out.Changed || !out.OK)
	}
	return r
}

func (a *Applier) recordHistory(t config.Target, r Result, keepRecent bool) {
	if err := history.Record(a.cfg.StateDir, history.Entry{
		TargetID: t.ID, Provider: r.Provider, Engine: t.Engine,
		OK: r.OK, Changed: r.Changed, Ranges: r.Ranges, Message: r.Message, When: r.When,
	}, keepRecent); err != nil {
		log.Printf("applier: record history %s: %v", t.ID, err)
	}
}

// Remove: uninstall target + clear state
func (a *Applier) Remove(ctx context.Context, t config.Target) Result {
	release, err := a.lock()
	if err != nil {
		return Result{TargetID: t.ID, Provider: t.Provider, When: time.Now(), Message: err.Error()}
	}
	defer release()
	r := Result{TargetID: t.ID, Provider: t.Provider, When: time.Now()}
	eng, err := engine.For(t.Engine)
	if err != nil {
		r.Message = err.Error()
		return r
	}
	tr, err := transportFor(ctx, t)
	if err != nil {
		r.Message = err.Error()
		return r
	}
	out := eng.Remove(ctx, tr, engine.Input{Target: t})
	r.OK = out.OK
	r.Changed = out.Changed
	r.Validate = out.Validate
	r.Message = out.Message
	if out.OK && a.state != nil {
		_ = a.state.Forget(t.ID)
	}
	return r
}

// desiredFingerprint: enforcement-shaping fields + cidrHash, for skip-check.
func desiredFingerprint(t config.Target, cidrHash string) string {
	tr := t.Transport
	if tr == "" {
		tr = "local"
	}
	h := sha256.New()
	fmt.Fprintln(h, cidrHash)
	fmt.Fprintln(h, t.Mode)
	fmt.Fprintln(h, t.Engine)
	fmt.Fprintln(h, tr)
	fmt.Fprintln(h, t.Config.File)
	fmt.Fprintln(h, t.Config.Selector)
	fmt.Fprintln(h, t.Config.RealIP)
	fmt.Fprintln(h, t.Docker.Container)
	fmt.Fprintln(h, t.Docker.Socket)
	fmt.Fprintln(h, t.Firewall.AllowAdminPorts)
	for _, port := range t.Firewall.Ports {
		fmt.Fprintln(h, port)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// resolve transport; ctx scopes Docker file ops
func transportFor(ctx context.Context, t config.Target) (transport.Transport, error) {
	switch t.Transport {
	case "", "local":
		return transport.NewLocal(), nil
	case "docker":
		if t.Docker.Container == "" {
			return nil, fmt.Errorf("docker transport requires docker.container")
		}
		return docker.NewTransport(ctx, t.Docker.Socket, t.Docker.Container), nil
	default:
		return nil, fmt.Errorf("unknown transport %q", t.Transport)
	}
}
