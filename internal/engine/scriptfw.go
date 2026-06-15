package engine

import (
	"context"
	"path"
	"strconv"
	"strings"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// stage + run fw script; non-atomic, set -e + web-port scope
func runFirewallScript(ctx context.Context, tr transport.Transport, in Input, dir, script, applyMsg string) Outcome {
	scriptPath := path.Join(dir, in.Target.ID+".sh")
	if in.DryRun {
		return Outcome{OK: true, Changed: true, Validate: script,
			Message: "dry-run: would run " + scriptPath}
	}
	return runScript(ctx, tr, scriptPath, script, applyMsg)
}

func runScript(ctx context.Context, tr transport.Transport, scriptPath, script, okMsg string) Outcome {
	if err := tr.MkdirAll(path.Dir(scriptPath), 0o755); err != nil {
		return fail("creating %s: %v", path.Dir(scriptPath), err)
	}
	if err := tr.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		return fail("writing script: %v", err)
	}
	res, err := tr.Run(ctx, "sh", scriptPath)
	if err != nil {
		return fail("running %s: %v", scriptPath, err)
	}
	out := strings.TrimSpace(res.Stderr + res.Stdout)
	if res.ExitCode != 0 {
		return Outcome{Validate: out, Message: "firewall script failed: " + errorLine(out)}
	}
	return Outcome{OK: true, Changed: true, Validate: out, Message: okMsg}
}

// firewallPorts: cfg ports or dflt web.
func firewallPorts(in Input) []int {
	if len(in.Target.Firewall.Ports) > 0 {
		return in.Target.Firewall.Ports
	}
	return []int{80, 443}
}

// portsCSV: comma list, no spaces (multiport/ufw).
func portsCSV(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}
