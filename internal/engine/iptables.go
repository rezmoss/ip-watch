package engine

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// IPTables: ipset + own chain on cfg ports; atomic ipset swap
type IPTables struct{}

const iptablesScriptDir = "/etc/ip-watch/iptables"

var reIptablesVersion = regexp.MustCompile(`v(\d+\.\d+\.\d+)`)

func (IPTables) Name() string { return "iptables" }

func (IPTables) Detect(ctx context.Context, tr transport.Transport) (*Detection, error) {
	bin, ok := lookAny(tr, "iptables")
	if !ok {
		return &Detection{Message: "iptables binary not found in PATH"}, nil
	}
	if _, ok := lookAny(tr, "ipset"); !ok {
		return &Detection{Message: "ipset not found (required by the iptables engine; consider the nftables engine)"}, nil
	}
	return &Detection{Found: true, Binary: bin, Version: versionVia(ctx, tr, bin, reIptablesVersion, "--version")}, nil
}

func (IPTables) Apply(ctx context.Context, tr transport.Transport, in Input) Outcome {
	det, _ := IPTables{}.Detect(ctx, tr)
	if det == nil || !det.Found {
		return fail("iptables engine unavailable: %s", msgOf(det))
	}
	return runFirewallScript(ctx, tr, in, iptablesScriptDir, renderIPTables(in),
		fmt.Sprintf("applied iptables chain IPWATCH_%s", sanitize(in.Target.ID)))
}

func (IPTables) Remove(ctx context.Context, tr transport.Transport, in Input) Outcome {
	det, _ := IPTables{}.Detect(ctx, tr)
	if det == nil || !det.Found {
		return fail("iptables engine unavailable: %s", msgOf(det))
	}
	name := sanitize(in.Target.ID)
	chain := "IPWATCH_" + name
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	for _, ipt := range []string{"iptables", "ip6tables"} {
		fmt.Fprintf(&b, "%s -D INPUT -j %s 2>/dev/null || true\n", ipt, chain)
		fmt.Fprintf(&b, "%s -F %s 2>/dev/null || true\n", ipt, chain)
		fmt.Fprintf(&b, "%s -X %s 2>/dev/null || true\n", ipt, chain)
	}
	for _, suffix := range []string{"v4", "v6"} {
		fmt.Fprintf(&b, "ipset destroy ipwatch_%s_%s 2>/dev/null || true\n", name, suffix)
	}
	return runScript(ctx, tr, iptablesScriptDir+"/"+in.Target.ID+"-remove.sh", b.String(),
		"removed iptables chain "+chain)
}

func renderIPTables(in Input) string {
	name := sanitize(in.Target.ID)
	chain := "IPWATCH_" + name
	ports := portsCSV(firewallPorts(in))

	var b strings.Builder
	b.WriteString("#!/bin/sh\nset -e\n")
	fmt.Fprintf(&b, "# ip-watch managed - provider: %s  mode: %s\n", in.CIDRs.Provider, in.Target.Mode)

	allow := in.Target.Mode != "deny"
	negate := "! " // allow: drop new NOT in set
	if !allow {
		negate = "" // deny: drop new IN set
	}

	emit := func(iptablesBin, ipsetFamily, suffix string, cidrs []string) {
		if len(cidrs) == 0 && !allow {
			return // deny, no ranges: nothing
		}
		chainRule := func() {
			fmt.Fprintf(&b, "%s -N %s 2>/dev/null || true\n", iptablesBin, chain)
			fmt.Fprintf(&b, "%s -F %s\n", iptablesBin, chain)
		}
		if len(cidrs) == 0 {
			// allow, no ranges this family: fail closed, drop all new
			chainRule()
			fmt.Fprintf(&b, "%s -A %s -p tcp -m multiport --dports %s -m conntrack --ctstate NEW -j DROP\n",
				iptablesBin, chain, ports)
			fmt.Fprintf(&b, "%s -C INPUT -j %s 2>/dev/null || %s -I INPUT -j %s\n", iptablesBin, chain, iptablesBin, chain)
			return
		}
		setBase := "ipwatch_" + name + "_" + suffix
		swapSet := setBase + "t"
		fmt.Fprintf(&b, "ipset create %s hash:net family %s -exist\n", setBase, ipsetFamily)
		fmt.Fprintf(&b, "ipset create %s hash:net family %s -exist\n", swapSet, ipsetFamily)
		fmt.Fprintf(&b, "ipset flush %s\n", swapSet)
		for _, cidr := range cidrs {
			fmt.Fprintf(&b, "ipset add %s %s\n", swapSet, cidr)
		}
		fmt.Fprintf(&b, "ipset swap %s %s\n", swapSet, setBase)
		fmt.Fprintf(&b, "ipset destroy %s\n", swapSet)
		chainRule()
		fmt.Fprintf(&b, "%s -A %s -p tcp -m multiport --dports %s -m conntrack --ctstate NEW -m set %s--match-set %s src -j DROP\n",
			iptablesBin, chain, ports, negate, setBase)
		fmt.Fprintf(&b, "%s -C INPUT -j %s 2>/dev/null || %s -I INPUT -j %s\n", iptablesBin, chain, iptablesBin, chain)
	}

	// allow: both families (empty fails closed); deny: only w/ ranges
	emit("iptables", "inet", "v4", in.CIDRs.V4)
	emit("ip6tables", "inet6", "v6", in.CIDRs.V6)
	return b.String()
}
