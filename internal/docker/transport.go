package docker

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// Transport: transport.Transport over one ctr.
type Transport struct {
	client    *Client
	container string
	// ctx scopes file ops to apply req (Run uses per-call ctx)
	ctx context.Context
}

// NewTransport: bound to ctr; file ops scoped to ctx.
func NewTransport(ctx context.Context, socket, container string) *Transport {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Transport{client: NewClient(socket), container: container, ctx: ctx}
}

func (t *Transport) Name() string { return "docker:" + t.container }

func (t *Transport) ReadFile(filePath string) ([]byte, error) {
	return t.client.CopyFrom(t.ctx, t.container, filePath)
}

func (t *Transport) WriteFile(filePath string, data []byte, perm os.FileMode) error {
	return t.client.CopyTo(t.ctx, t.container, path.Dir(filePath), path.Base(filePath), int64(perm), data)
}

func (t *Transport) MkdirAll(dirPath string, _ os.FileMode) error {
	_, stderr, code, err := t.client.Exec(t.ctx, t.container, []string{"mkdir", "-p", dirPath})
	if err != nil {
		return fmt.Errorf("docker exec mkdir %s: %w", dirPath, err)
	}
	if code != 0 {
		return fmt.Errorf("mkdir -p %s: %s", dirPath, strings.TrimSpace(stderr))
	}
	return nil
}

func (t *Transport) Remove(filePath string) error {
	_, stderr, code, err := t.client.Exec(t.ctx, t.container, []string{"rm", "-f", filePath})
	if err != nil {
		return fmt.Errorf("docker exec rm %s: %w", filePath, err)
	}
	if code != 0 {
		return fmt.Errorf("rm %s: %s", filePath, strings.TrimSpace(stderr))
	}
	return nil
}

func (t *Transport) Exists(p string) bool {
	return t.client.Exists(t.ctx, t.container, p)
}

// LookPath: resolve binary via `command -v`.
func (t *Transport) LookPath(name string) (string, error) {
	stdout, _, code, err := t.client.Exec(t.ctx, t.container, []string{"sh", "-c", "command -v " + name})
	if err != nil {
		return "", err
	}
	resolved := strings.TrimSpace(stdout)
	if code != 0 || resolved == "" {
		return "", fmt.Errorf("%s not found in container %s", name, t.container)
	}
	return resolved, nil
}

func (t *Transport) Run(ctx context.Context, name string, args ...string) (transport.Result, error) {
	stdout, stderr, code, err := t.client.Exec(ctx, t.container, append([]string{name}, args...))
	if err != nil {
		return transport.Result{}, err
	}
	return transport.Result{Stdout: stdout, Stderr: stderr, ExitCode: code}, nil
}

var _ transport.Transport = (*Transport)(nil)
