// Package transport: reach mgmt target via Local or Docker.
package transport

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
)

// Result: command outcome.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Transport: minimal engine surface: rw files + run ctrl binary.
type Transport interface {
	Name() string
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
	Remove(path string) error
	Exists(path string) bool
	LookPath(name string) (string, error)
	// Run name w/ args. Non-zero -> ExitCode; err only on start fail.
	Run(ctx context.Context, name string, args ...string) (Result, error)
}

// Local: run directly on host.
type Local struct{}

func NewLocal() *Local { return &Local{} }

func (l *Local) Name() string { return "local" }

func (l *Local) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

func (l *Local) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (l *Local) MkdirAll(path string, perm os.FileMode) error { return os.MkdirAll(path, perm) }

func (l *Local) Remove(path string) error { return os.Remove(path) }

func (l *Local) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (l *Local) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (l *Local) Run(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	return res, err
}

var _ Transport = (*Local)(nil)
