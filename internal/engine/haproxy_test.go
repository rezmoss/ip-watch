package engine

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// fakeHAProxyTransport controls systemctl presence, PID 1's comm, and kill.
type fakeHAProxyTransport struct {
	hasSystemctl bool
	pid1Comm     string
}

func (f *fakeHAProxyTransport) Name() string                                { return "fake" }
func (f *fakeHAProxyTransport) ReadFile(string) ([]byte, error)             { return nil, os.ErrNotExist }
func (f *fakeHAProxyTransport) WriteFile(string, []byte, os.FileMode) error { return nil }
func (f *fakeHAProxyTransport) MkdirAll(string, os.FileMode) error          { return nil }
func (f *fakeHAProxyTransport) Remove(string) error                         { return nil }
func (f *fakeHAProxyTransport) Exists(string) bool                          { return false }
func (f *fakeHAProxyTransport) LookPath(name string) (string, error) {
	if name == "systemctl" && f.hasSystemctl {
		return "/usr/bin/systemctl", nil
	}
	return "", os.ErrNotExist
}

func (f *fakeHAProxyTransport) Run(_ context.Context, _ string, args ...string) (transport.Result, error) {
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "/proc/1/comm"):
		return transport.Result{Stdout: f.pid1Comm + "\n"}, nil
	default:
		// systemctl reload, kill -USR2 1, etc. all succeed
		return transport.Result{ExitCode: 0}, nil
	}
}

func TestHAProxyReloadGuardsPID1(t *testing.T) {
	ctx := context.Background()

	// PID 1 is haproxy, no systemctl -> SIGUSR2 fallback is allowed
	if _, err := haproxyReload(ctx, &fakeHAProxyTransport{pid1Comm: "haproxy"}, ""); err != nil {
		t.Fatalf("haproxy-as-pid1 should reload, got %v", err)
	}

	// PID 1 is not haproxy and no systemctl -> refuse, don't signal init
	_, err := haproxyReload(ctx, &fakeHAProxyTransport{pid1Comm: "bash"}, "")
	if err == nil || !strings.Contains(err.Error(), "PID 1 is not the haproxy master") {
		t.Fatalf("non-haproxy pid1 should be refused, got %v", err)
	}

	// systemctl present and working -> reload via systemd, no fallback needed
	if _, err := haproxyReload(ctx, &fakeHAProxyTransport{hasSystemctl: true, pid1Comm: "bash"}, ""); err != nil {
		t.Fatalf("systemctl reload should succeed, got %v", err)
	}
}
