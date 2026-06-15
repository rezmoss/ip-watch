package applier

import (
	"context"
	"strings"
	"testing"

	"github.com/rezmoss/ip-watch/internal/config"
)

func TestTransportFor(t *testing.T) {
	ctx := context.Background()
	local, err := transportFor(ctx, config.Target{Transport: "local"})
	if err != nil || local.Name() != "local" {
		t.Fatalf("local: %v %v", local, err)
	}
	def, err := transportFor(ctx, config.Target{})
	if err != nil || def.Name() != "local" {
		t.Fatalf("empty should default to local: %v %v", def, err)
	}
	dock, err := transportFor(ctx, config.Target{Transport: "docker", Docker: config.DockerOpts{Container: "c"}})
	if err != nil || dock.Name() != "docker:c" {
		t.Fatalf("docker: %v %v", dock, err)
	}
	if _, err := transportFor(ctx, config.Target{Transport: "docker"}); err == nil {
		t.Fatal("docker without container should error")
	}
	if _, err := transportFor(ctx, config.Target{Transport: "bogus"}); err == nil {
		t.Fatal("unknown transport should error")
	}
}

func TestApplyUnknownEngine(t *testing.T) {
	a := New(&config.Config{StateDir: t.TempDir()}, true)
	r := a.Apply(t.Context(), config.Target{ID: "x", Engine: "bogus", Provider: "cloudflare"}, true)
	if r.OK {
		t.Fatal("unknown engine should not be OK")
	}
}

// non-dry apply fails closed w/o lock, unless lock_unsafe
func TestApplyFailsClosedWithoutLock(t *testing.T) {
	tgt := config.Target{ID: "x", Engine: "nginx", Provider: "cloudflare", Mode: "allow"}

	a := New(&config.Config{StateDir: ""}, false)
	if r := a.Apply(t.Context(), tgt, true); r.OK || !strings.Contains(r.Message, "lock") {
		t.Fatalf("expected fail-closed lock error, got %+v", r)
	}

	// lock_unsafe proceeds past locking
	au := New(&config.Config{StateDir: "", LockUnsafe: true}, false)
	if r := au.Apply(t.Context(), tgt, true); strings.Contains(r.Message, "lock unavailable") {
		t.Fatalf("lock_unsafe should bypass the lock failure, got %+v", r)
	}

	// dry run never blocked by lock
	ad := New(&config.Config{StateDir: ""}, true)
	if r := ad.Apply(t.Context(), tgt, true); strings.Contains(r.Message, "lock unavailable") {
		t.Fatalf("dry run should not fail closed on lock, got %+v", r)
	}
}

func TestGuardConfigFailsClosedWithoutLock(t *testing.T) {
	called := false
	if err := GuardConfig("", false, func() error { called = true; return nil }); err == nil || called {
		t.Fatalf("empty state dir should fail closed: err=%v called=%v", err, called)
	}
	if err := GuardConfig("", true, func() error { called = true; return nil }); err != nil || !called {
		t.Fatalf("lock_unsafe should proceed: err=%v called=%v", err, called)
	}
	// lockable dir runs fn, holds lock
	if err := GuardConfig(t.TempDir(), false, func() error { return nil }); err != nil {
		t.Fatalf("lockable dir should succeed: %v", err)
	}
}

func TestDesiredFingerprint(t *testing.T) {
	base := config.Target{
		ID:       "web",
		Mode:     "deny",
		Engine:   "nginx",
		Provider: "cloudflare",
	}
	hash := "abc123"
	want := desiredFingerprint(base, hash)

	// same target + same ranges → same fingerprint (scheduled run skips)
	if got := desiredFingerprint(base, hash); got != want {
		t.Fatalf("identical target changed fingerprint: %q vs %q", got, want)
	}

	// enforcement-shaping edits must change the fingerprint even when ranges don't
	mutations := map[string]config.Target{
		"mode":     {ID: "web", Mode: "allow", Engine: "nginx", Provider: "cloudflare"},
		"engine":   {ID: "web", Mode: "deny", Engine: "caddy", Provider: "cloudflare"},
		"selector": {ID: "web", Mode: "deny", Engine: "nginx", Provider: "cloudflare", Config: config.ConfigOpts{Selector: "example.com"}},
		"realip":   {ID: "web", Mode: "deny", Engine: "nginx", Provider: "cloudflare", Config: config.ConfigOpts{RealIP: true}},
		"ports":    {ID: "web", Mode: "deny", Engine: "nginx", Provider: "cloudflare", Firewall: config.FirewallOpts{Ports: []int{8443}}},
	}
	for name, mutated := range mutations {
		if desiredFingerprint(mutated, hash) == want {
			t.Errorf("%s change did not alter fingerprint", name)
		}
	}

	// a CIDR-hash change still alters it
	if desiredFingerprint(base, "different") == want {
		t.Error("range change did not alter fingerprint")
	}
}
