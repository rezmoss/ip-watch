package engine

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// fakeNftTransport: in-mem host w/ nft installed
type fakeNftTransport struct {
	files map[string][]byte
	loads int // count of nft -f loads, not checks
}

func newFakeNftTransport() *fakeNftTransport {
	return &fakeNftTransport{files: map[string][]byte{}}
}

func (f *fakeNftTransport) Name() string { return "fake" }

func (f *fakeNftTransport) ReadFile(p string) ([]byte, error) {
	if data, ok := f.files[p]; ok {
		return data, nil
	}
	return nil, os.ErrNotExist
}

func (f *fakeNftTransport) WriteFile(p string, data []byte, _ os.FileMode) error {
	f.files[p] = append([]byte(nil), data...)
	return nil
}

func (f *fakeNftTransport) MkdirAll(string, os.FileMode) error { return nil }

func (f *fakeNftTransport) Remove(p string) error { delete(f.files, p); return nil }

func (f *fakeNftTransport) Exists(p string) bool { _, ok := f.files[p]; return ok }

func (f *fakeNftTransport) LookPath(name string) (string, error) {
	if name == "nft" {
		return "/usr/sbin/nft", nil
	}
	return "", os.ErrNotExist
}

func (f *fakeNftTransport) Run(_ context.Context, _ string, args ...string) (transport.Result, error) {
	// -v version; -c -f check; -f load
	switch {
	case len(args) == 1 && args[0] == "-v":
		return transport.Result{Stdout: "nftables v1.0.6"}, nil
	case len(args) >= 1 && args[0] == "-c":
		return transport.Result{ExitCode: 0}, nil
	case len(args) >= 1 && args[0] == "-f":
		f.loads++
		return transport.Result{ExitCode: 0}, nil
	}
	return transport.Result{ExitCode: 0}, nil
}

// forced re-runs nft -f even if file matches (kernel may be gone)
func TestNftablesForceBypassesFileNoOp(t *testing.T) {
	in := testInput("nftables", "allow")
	ruleset := []byte(renderNftables(in))
	rulesPath := path.Join(nftRulesDir, in.Target.ID+".nft")

	// non-forced: file matches -> no-op
	tr := newFakeNftTransport()
	tr.files[rulesPath] = ruleset
	out := Firewall{}.Apply(context.Background(), tr, in)
	if !out.OK || out.Changed {
		t.Fatalf("non-forced apply should no-op: OK=%v Changed=%v msg=%q", out.OK, out.Changed, out.Message)
	}
	if tr.loads != 0 {
		t.Fatalf("non-forced apply ran nft -f %d times, want 0", tr.loads)
	}

	// forced: identical file must NOT short-circuit
	trF := newFakeNftTransport()
	trF.files[rulesPath] = ruleset
	inF := in
	inF.Force = true
	outF := Firewall{}.Apply(context.Background(), trF, inF)
	if !outF.OK || !outF.Changed {
		t.Fatalf("forced apply should re-load: OK=%v Changed=%v msg=%q", outF.OK, outF.Changed, outF.Message)
	}
	if trF.loads != 1 {
		t.Fatalf("forced apply ran nft -f %d times, want 1", trF.loads)
	}
	if !strings.Contains(outF.Message, "loaded nftables table") {
		t.Fatalf("unexpected forced message: %q", outF.Message)
	}
}
