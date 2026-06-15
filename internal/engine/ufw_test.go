package engine

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// fakeUFWTransport: fakes ufw status for the fail-closed check
type fakeUFWTransport struct {
	statusOut  string
	statusCode int
	statusErr  error
	files      map[string][]byte
}

func (f *fakeUFWTransport) Name() string                    { return "fake" }
func (f *fakeUFWTransport) ReadFile(string) ([]byte, error) { return nil, os.ErrNotExist }
func (f *fakeUFWTransport) WriteFile(p string, d []byte, _ os.FileMode) error {
	if f.files == nil {
		f.files = map[string][]byte{}
	}
	f.files[p] = d
	return nil
}
func (f *fakeUFWTransport) MkdirAll(string, os.FileMode) error { return nil }
func (f *fakeUFWTransport) Remove(string) error                { return nil }
func (f *fakeUFWTransport) Exists(string) bool                 { return false }
func (f *fakeUFWTransport) LookPath(name string) (string, error) {
	if name == "ufw" {
		return "/usr/sbin/ufw", nil
	}
	return "", os.ErrNotExist
}

func (f *fakeUFWTransport) Run(_ context.Context, _ string, args ...string) (transport.Result, error) {
	switch {
	case len(args) == 1 && args[0] == "version":
		return transport.Result{Stdout: "ufw 0.36"}, nil
	case len(args) == 2 && args[0] == "status" && args[1] == "verbose":
		return transport.Result{Stdout: f.statusOut, ExitCode: f.statusCode}, f.statusErr
	default:
		// script exec + anything else: succeed
		return transport.Result{ExitCode: 0}, nil
	}
}

func TestUFWAllowFailsClosed(t *testing.T) {
	in := testInput("ufw", "allow")
	cases := []struct {
		name     string
		tr       *fakeUFWTransport
		wantOK   bool
		wantWord string
	}{
		{"status command errors", &fakeUFWTransport{statusErr: fmt.Errorf("boom")}, false, "cannot verify"},
		{"status non-zero exit", &fakeUFWTransport{statusOut: "garbled", statusCode: 1}, false, "cannot verify"},
		{"default allow incoming", &fakeUFWTransport{statusOut: "Status: active\nDefault: allow (incoming)", statusCode: 0}, false, "requires default deny"},
		{"default deny incoming", &fakeUFWTransport{statusOut: "Status: active\nDefault: deny (incoming), allow (outgoing)", statusCode: 0}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := UFW{}.Apply(context.Background(), c.tr, in)
			if out.OK != c.wantOK {
				t.Fatalf("OK = %v, want %v (msg: %q)", out.OK, c.wantOK, out.Message)
			}
			if c.wantWord != "" && !strings.Contains(out.Message, c.wantWord) {
				t.Fatalf("message %q should contain %q", out.Message, c.wantWord)
			}
		})
	}
}

// deny mode: policy check irrelevant, must not run
func TestUFWDenyModeSkipsPolicyCheck(t *testing.T) {
	in := testInput("ufw", "deny")
	tr := &fakeUFWTransport{statusErr: fmt.Errorf("should not be called")}
	out := UFW{}.Apply(context.Background(), tr, in)
	if !out.OK {
		t.Fatalf("deny mode should apply without a policy check: %q", out.Message)
	}
}
