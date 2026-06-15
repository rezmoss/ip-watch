package engine

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// UFW: port-scoped tagged rules; allow needs default-deny
type UFW struct{}

const ufwScriptDir = "/etc/ip-watch/ufw"

var reUFWVersion = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)

func (UFW) Name() string { return "ufw" }

func (UFW) Detect(ctx context.Context, tr transport.Transport) (*Detection, error) {
	bin, ok := lookAny(tr, "ufw")
	if !ok {
		return &Detection{Message: "ufw binary not found in PATH"}, nil
	}
	return &Detection{Found: true, Binary: bin, Version: versionVia(ctx, tr, bin, reUFWVersion, "version")}, nil
}

func (UFW) Apply(ctx context.Context, tr transport.Transport, in Input) Outcome {
	det, _ := UFW{}.Detect(ctx, tr)
	if det == nil || !det.Found {
		return fail("ufw not detected: %s", msgOf(det))
	}
	// allow only when default incoming deny; fail closed: unconfirmed -> refuse
	if in.Target.Mode == "allow" && !in.DryRun {
		res, err := tr.Run(ctx, det.Binary, "status", "verbose")
		switch {
		case err != nil:
			return fail("ufw allow: cannot verify default incoming policy ('ufw status verbose' failed: %v); refusing", err)
		case res.ExitCode != 0:
			return fail("ufw allow: cannot verify default incoming policy ('ufw status verbose' exited %d: %s); refusing",
				res.ExitCode, errorLine(res.Stderr+res.Stdout))
		case !strings.Contains(res.Stdout, "deny (incoming)"):
			return fail("ufw allow requires default deny incoming (run 'ufw default deny incoming') " +
				"or use nftables; allow rules won't restrict otherwise")
		}
	}
	return runFirewallScript(ctx, tr, in, ufwScriptDir, renderUFW(in),
		fmt.Sprintf("applied %d ufw rules", len(allCIDRs(in.CIDRs.V4, in.CIDRs.V6))))
}

func (UFW) Remove(ctx context.Context, tr transport.Transport, in Input) Outcome {
	det, _ := UFW{}.Detect(ctx, tr)
	if det == nil || !det.Found {
		return fail("ufw not detected: %s", msgOf(det))
	}
	return runScript(ctx, tr, ufwScriptDir+"/"+in.Target.ID+"-remove.sh",
		ufwDeleteScript("ip-watch:"+in.Target.ID), "removed ufw rules for "+in.Target.ID)
}

func ufwDeleteScript(tag string) string {
	return "#!/bin/sh\nset -e\n" + ufwDeleteLoop(tag)
}

// ufwDeleteLoop: del tagged rules highest-num-first, indexes stay valid
func ufwDeleteLoop(tag string) string {
	var b strings.Builder
	b.WriteString("while true; do\n")
	fmt.Fprintf(&b, "  n=$(ufw status numbered 2>/dev/null | grep '%s' | head -1 | sed -E 's/^\\[ *([0-9]+)\\].*/\\1/')\n", tag)
	b.WriteString("  [ -z \"$n\" ] && break\n")
	b.WriteString("  ufw --force delete \"$n\" >/dev/null\n")
	b.WriteString("done\n")
	return b.String()
}

func renderUFW(in Input) string {
	tag := "ip-watch:" + in.Target.ID
	ports := portsCSV(firewallPorts(in))
	action := "allow"
	if in.Target.Mode == "deny" {
		action = "deny"
	}

	var b strings.Builder
	b.WriteString("#!/bin/sh\nset -e\n")
	fmt.Fprintf(&b, "# ip-watch managed - provider: %s  mode: %s\n", in.CIDRs.Provider, in.Target.Mode)

	b.WriteString(ufwDeleteLoop(tag)) // rm prior rules first (idempotent)

	for _, cidr := range allCIDRs(in.CIDRs.V4, in.CIDRs.V6) {
		fmt.Fprintf(&b, "ufw %s proto tcp from %s to any port %s comment '%s'\n", action, cidr, ports, tag)
	}
	return b.String()
}
