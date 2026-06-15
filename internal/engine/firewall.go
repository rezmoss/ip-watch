package engine

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// Firewall: nftables ruleset on cfg TCP ports only (SSH untouched)
type Firewall struct{}

const nftRulesDir = "/etc/ip-watch/nftables"

var reNftVersion = regexp.MustCompile(`v(\d+\.\d+\.\d+)`)

func (Firewall) Name() string { return "nftables" }

func (Firewall) Detect(ctx context.Context, tr transport.Transport) (*Detection, error) {
	bin, ok := lookAny(tr, "nft")
	if !ok {
		return &Detection{Message: "nft binary not found in PATH"}, nil
	}
	return &Detection{
		Found:   true,
		Binary:  bin,
		Version: versionVia(ctx, tr, bin, reNftVersion, "-v"),
	}, nil
}

func (Firewall) Apply(ctx context.Context, tr transport.Transport, in Input) Outcome {
	det, _ := Firewall{}.Detect(ctx, tr)
	if det == nil || !det.Found {
		return fail("nftables not detected: %s", msgOf(det))
	}

	ruleset := []byte(renderNftables(in))
	rulesPath := path.Join(nftRulesDir, in.Target.ID+".nft")

	if in.DryRun {
		check := rulesPath + ".check"
		if err := writeTemp(tr, check, ruleset); err != nil {
			return fail("staging ruleset: %v", err)
		}
		out, ok, _ := nftCheck(ctx, tr, det.Binary, check)
		_ = tr.Remove(check)
		return Outcome{OK: ok, Changed: true, Validate: out,
			Message: "dry-run: would load nftables table for " + in.Target.ID}
	}

	// file = "loaded once" not "in kernel"; no-op only when !forced
	if !in.Force {
		if prev, ok := readMaybe(tr, rulesPath); ok && bytes.Equal(prev, ruleset) {
			return Outcome{OK: true, Changed: false,
				Message: fmt.Sprintf("already up to date: nftables table ipwatch_%s", sanitize(in.Target.ID))}
		}
	}

	// stage->check->load->persist on success only (no false no-op)
	stagingPath := rulesPath + ".tmp"
	if err := writeTemp(tr, stagingPath, ruleset); err != nil {
		return fail("staging ruleset: %v", err)
	}
	vout, ok, err := nftCheck(ctx, tr, det.Binary, stagingPath)
	if err != nil || !ok {
		_ = tr.Remove(stagingPath)
		return Outcome{Validate: vout, Message: "ruleset invalid: " + errorLine(vout)}
	}
	if res, err := tr.Run(ctx, det.Binary, "-f", stagingPath); err != nil {
		_ = tr.Remove(stagingPath)
		return fail("nft -f: %v", err)
	} else if res.ExitCode != 0 {
		_ = tr.Remove(stagingPath)
		return Outcome{Validate: strings.TrimSpace(res.Stderr), Message: "nft -f failed: " + errorLine(res.Stderr)}
	}
	if err := tr.WriteFile(rulesPath, ruleset, 0o644); err != nil {
		_ = tr.Remove(stagingPath)
		return fail("persisting ruleset: %v", err)
	}
	_ = tr.Remove(stagingPath)

	return Outcome{OK: true, Changed: true, Validate: vout,
		Message: fmt.Sprintf("loaded nftables table ipwatch_%s", sanitize(in.Target.ID))}
}

func (Firewall) Remove(ctx context.Context, tr transport.Transport, in Input) Outcome {
	det, _ := Firewall{}.Detect(ctx, tr)
	if det == nil || !det.Found {
		return fail("nftables not detected: %s", msgOf(det))
	}
	table := "ipwatch_" + sanitize(in.Target.ID)
	rulesPath := path.Join(nftRulesDir, in.Target.ID+".nft")
	// add+delete = idempotent teardown w/ or w/o table
	teardown := fmt.Sprintf("add table inet %s\ndelete table inet %s\n", table, table)
	removePath := rulesPath + ".remove"
	if err := writeTemp(tr, removePath, []byte(teardown)); err != nil {
		return fail("staging teardown: %v", err)
	}
	res, err := tr.Run(ctx, det.Binary, "-f", removePath)
	_ = tr.Remove(removePath)
	if err != nil {
		return fail("nft -f teardown: %v", err)
	}
	if res.ExitCode != 0 {
		return Outcome{Validate: strings.TrimSpace(res.Stderr), Message: "teardown failed: " + errorLine(res.Stderr)}
	}
	_ = tr.Remove(rulesPath)
	return Outcome{OK: true, Changed: true, Message: "removed nftables table " + table}
}

func nftCheck(ctx context.Context, tr transport.Transport, bin, file string) (string, bool, error) {
	res, err := tr.Run(ctx, bin, "-c", "-f", file)
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(res.Stderr + res.Stdout), res.ExitCode == 0, nil
}

func writeTemp(tr transport.Transport, p string, data []byte) error {
	if err := tr.MkdirAll(path.Dir(p), 0o755); err != nil {
		return fmt.Errorf("creating dir for %s: %w", p, err)
	}
	return tr.WriteFile(p, data, 0o644)
}

// renderNftables: idempotent; add/delete pair = clean slate
func renderNftables(in Input) string {
	table := "ipwatch_" + sanitize(in.Target.ID)
	portSet := "{ " + joinInts(firewallPorts(in)) + " }"

	var b strings.Builder
	fmt.Fprintf(&b, "#!/usr/sbin/nft -f\n")
	fmt.Fprintf(&b, "# ip-watch managed ruleset - provider: %s  mode: %s\n", in.CIDRs.Provider, in.Target.Mode)
	fmt.Fprintf(&b, "add table inet %s\n", table)
	fmt.Fprintf(&b, "delete table inet %s\n", table)
	fmt.Fprintf(&b, "table inet %s {\n", table)

	if len(in.CIDRs.V4) > 0 {
		fmt.Fprintf(&b, "  set allowed_v4 {\n    type ipv4_addr\n    flags interval\n    elements = { %s }\n  }\n", strings.Join(in.CIDRs.V4, ", "))
	}
	if len(in.CIDRs.V6) > 0 {
		fmt.Fprintf(&b, "  set allowed_v6 {\n    type ipv6_addr\n    flags interval\n    elements = { %s }\n  }\n", strings.Join(in.CIDRs.V6, ", "))
	}

	// policy accept + targeted drops: only listed ports
	b.WriteString("  chain input {\n    type filter hook input priority -10; policy accept;\n")
	allow := in.Target.Mode != "deny"

	emit := func(family, proto, set string, cidrs []string) {
		switch {
		case len(cidrs) > 0 && allow: // allow: drop new NOT in set
			fmt.Fprintf(&b, "    tcp dport %s ct state new %s saddr != @%s drop\n", portSet, family, set)
		case len(cidrs) > 0: // deny: drop new IN set
			fmt.Fprintf(&b, "    tcp dport %s ct state new %s saddr @%s drop\n", portSet, family, set)
		case allow: // allow, no ranges: fail closed, drop all new
			fmt.Fprintf(&b, "    tcp dport %s meta nfproto %s ct state new drop\n", portSet, proto)
		}
		// deny, no ranges: nothing
	}
	emit("ip", "ipv4", "allowed_v4", in.CIDRs.V4)
	emit("ip6", "ipv6", "allowed_v6", in.CIDRs.V6)

	b.WriteString("  }\n}\n")
	return b.String()
}

func joinInts(ints []int) string {
	parts := make([]string, len(ints))
	for i, n := range ints {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}
