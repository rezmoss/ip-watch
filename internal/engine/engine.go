// Package engine: detect, render, apply; safe-apply varies by family.
package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/rezmoss/ip-watch/internal/config"
	"github.com/rezmoss/ip-watch/internal/fetcher"
	"github.com/rezmoss/ip-watch/internal/transport"
)

// Detection: software found on a transport.
type Detection struct {
	Found      bool   `json:"found"`
	Binary     string `json:"binary,omitempty"`
	Version    string `json:"version,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
	Message    string `json:"message,omitempty"`
}

// Input: all needed for one apply.
type Input struct {
	Target config.Target
	CIDRs  *fetcher.CIDRs
	DryRun bool
	// re-assert even if no change (reboot/flush dropped kernel state)
	Force bool
}

// Outcome: engine part of result; applier fills shared fields.
type Outcome struct {
	OK       bool
	Changed  bool
	Validate string
	Message  string
}

type Engine interface {
	Name() string
	Detect(ctx context.Context, tr transport.Transport) (*Detection, error)
	Apply(ctx context.Context, tr transport.Transport, in Input) Outcome
	// undo Apply: strip cfg/rules, del managed files. CIDRs may be nil.
	Remove(ctx context.Context, tr transport.Transport, in Input) Outcome
}

func For(name string) (Engine, error) {
	switch name {
	case "nginx":
		return Nginx{}, nil
	case "caddy":
		return Caddy{}, nil
	case "apache":
		return Apache{}, nil
	case "haproxy":
		return HAProxy{}, nil
	case "nftables":
		return Firewall{}, nil
	case "iptables":
		return IPTables{}, nil
	case "ufw":
		return UFW{}, nil
	default:
		return nil, fmt.Errorf("unsupported engine %q", name)
	}
}

// UI engines
func Names() []string {
	return []string{"nginx", "caddy", "apache", "haproxy", "nftables", "iptables", "ufw"}
}

func fail(format string, args ...any) Outcome {
	return Outcome{Message: fmt.Sprintf(format, args...)}
}

// err-tagged line if any, else last non-empty
func errorLine(s string) string {
	last := strings.TrimSpace(s)
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		last = line
		lower := strings.ToLower(line)
		if strings.Contains(lower, "emerg") || strings.Contains(lower, "error") || strings.Contains(lower, "fail") {
			return line
		}
	}
	return last
}
