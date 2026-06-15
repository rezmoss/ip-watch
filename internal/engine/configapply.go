package engine

import (
	"bytes"
	"context"
	"path"
	"time"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// configPlan: cfg-engine apply shape (inject confFile, or drop-in dir)
type configPlan struct {
	bin         string
	managedPath string
	managedData []byte

	dropIn    bool
	confFile  string
	reference string
	selector  string
	inject    func(conf []byte, key, reference, selector string) ([]byte, error)
	// extra managed-block keys to strip on uninstall
	extraStripKeys []string

	validate func(ctx context.Context, tr transport.Transport, bin string) (string, bool, error)
	reload   func(ctx context.Context, tr transport.Transport, bin string) (string, error)
}

// safe-apply: stage, validate, reload; restore touched files on fail
func applyConfig(ctx context.Context, tr transport.Transport, in Input, plan configPlan) Outcome {
	if in.DryRun {
		return dryRunConfig(ctx, tr, plan)
	}

	// diff first so unchanged re-apply is true no-op
	priorManaged, managedExisted := readMaybe(tr, plan.managedPath)
	managedChanged := !managedExisted || !bytes.Equal(priorManaged, plan.managedData)

	var origConf, newConf []byte
	confChanged := false
	if !plan.dropIn {
		var err error
		origConf, err = tr.ReadFile(plan.confFile)
		if err != nil {
			return fail("reading %s: %v", plan.confFile, err)
		}
		newConf, err = plan.inject(origConf, plan.managedPath, plan.reference, plan.selector)
		if err != nil {
			return fail("editing %s: %v", plan.confFile, err)
		}
		confChanged = !bytes.Equal(origConf, newConf)
	}

	if !managedChanged && !confChanged {
		return Outcome{OK: true, Changed: false, Message: "already up to date: " + describeTarget(plan)}
	}

	// Stage 1: write managed file, keep undo
	if err := tr.MkdirAll(path.Dir(plan.managedPath), 0o755); err != nil {
		return fail("creating %s: %v", path.Dir(plan.managedPath), err)
	}
	if err := tr.WriteFile(plan.managedPath, plan.managedData, 0o644); err != nil {
		return fail("writing %s: %v", plan.managedPath, err)
	}
	restoreManaged := func() {
		if managedExisted {
			_ = tr.WriteFile(plan.managedPath, priorManaged, 0o644)
		} else {
			_ = tr.Remove(plan.managedPath)
		}
	}

	// Stage 2: inject engines edit cfg file
	if !plan.dropIn {
		backup := plan.confFile + ".ipwatch-" + time.Now().Format("20060102-150405") + ".bak"
		_ = tr.WriteFile(backup, origConf, 0o644)
		if err := tr.WriteFile(plan.confFile, newConf, 0o644); err != nil {
			restoreManaged()
			return fail("writing %s: %v", plan.confFile, err)
		}
	}
	restoreAll := func() {
		if !plan.dropIn {
			_ = tr.WriteFile(plan.confFile, origConf, 0o644)
		}
		restoreManaged()
	}

	// Stage 3: validate; never reload cfg failing its checker
	vout, ok, err := plan.validate(ctx, tr, plan.bin)
	out := Outcome{Validate: vout}
	if err != nil || !ok {
		restoreAll()
		out.Message = "validation failed, rolled back: " + errorLine(vout)
		return out
	}

	// Stage 4: reload; on fail restore + reload known-good
	if _, err := plan.reload(ctx, tr, plan.bin); err != nil {
		restoreAll()
		_, _ = plan.reload(ctx, tr, plan.bin)
		out.Message = "reload failed, rolled back: " + err.Error()
		return out
	}

	out.OK = true
	out.Changed = true
	out.Message = "applied " + describeTarget(plan)
	return out
}

// strip block, validate, del managed file + reload; restore on fail
func removeConfig(ctx context.Context, tr transport.Transport, plan configPlan) Outcome {
	if !tr.Exists(plan.confFile) {
		_ = tr.Remove(plan.managedPath)
		return Outcome{OK: true, Message: "nothing to remove (" + plan.confFile + " absent)"}
	}
	orig, err := tr.ReadFile(plan.confFile)
	if err != nil {
		return fail("reading %s: %v", plan.confFile, err)
	}
	cleaned := stripManaged(string(orig), plan.managedPath)
	for _, key := range plan.extraStripKeys {
		cleaned = stripManaged(cleaned, key)
	}
	stripped := []byte(cleaned)
	if bytes.Equal(stripped, orig) && !tr.Exists(plan.managedPath) {
		return Outcome{OK: true, Message: "already removed"}
	}

	backup := plan.confFile + ".ipwatch-" + time.Now().Format("20060102-150405") + ".bak"
	_ = tr.WriteFile(backup, orig, 0o644)
	if err := tr.WriteFile(plan.confFile, stripped, 0o644); err != nil {
		return fail("writing %s: %v", plan.confFile, err)
	}

	// keep managed file until reload ok, so fail restores fully
	vout, ok, err := plan.validate(ctx, tr, plan.bin)
	if err != nil || !ok {
		_ = tr.WriteFile(plan.confFile, orig, 0o644)
		return Outcome{Validate: vout, Message: "validation failed after removal, restored: " + errorLine(vout)}
	}
	if _, err := plan.reload(ctx, tr, plan.bin); err != nil {
		_ = tr.WriteFile(plan.confFile, orig, 0o644)
		_, _ = plan.reload(ctx, tr, plan.bin) // known-good back live
		return Outcome{Message: "reload failed during removal, restored prior config: " + err.Error()}
	}
	// reload ok w/ include gone -> del managed file
	_ = tr.Remove(plan.managedPath)
	return Outcome{OK: true, Changed: true, Message: "removed from " + plan.confFile}
}

func dryRunConfig(ctx context.Context, tr transport.Transport, plan configPlan) Outcome {
	out := Outcome{}
	// managed file changes w/ ranges, even if marker exists
	current, existed := readMaybe(tr, plan.managedPath)
	managedChanged := !existed || !bytes.Equal(current, plan.managedData)
	if plan.dropIn {
		out.Changed = managedChanged
	} else {
		orig, err := tr.ReadFile(plan.confFile)
		if err != nil {
			return fail("reading %s: %v", plan.confFile, err)
		}
		newConf, err := plan.inject(orig, plan.managedPath, plan.reference, plan.selector)
		if err != nil {
			return fail("editing %s: %v", plan.confFile, err)
		}
		out.Changed = managedChanged || !bytes.Equal(newConf, orig)
	}
	vout, ok, _ := plan.validate(ctx, tr, plan.bin)
	out.OK = ok
	out.Validate = vout
	out.Message = "dry-run: would update " + describeTarget(plan)
	return out
}

func describeTarget(plan configPlan) string {
	if plan.dropIn {
		return plan.managedPath
	}
	return plan.confFile
}

func readMaybe(tr transport.Transport, p string) ([]byte, bool) {
	if !tr.Exists(p) {
		return nil, false
	}
	data, err := tr.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return data, true
}
