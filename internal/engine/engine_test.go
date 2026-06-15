package engine

import (
	"strings"
	"testing"

	"github.com/rezmoss/ip-watch/internal/config"
	"github.com/rezmoss/ip-watch/internal/fetcher"
)

func testInput(eng, mode string) Input {
	return Input{
		Target: config.Target{ID: "web1", Provider: "cloudflare", Mode: mode, Engine: eng},
		CIDRs:  &fetcher.CIDRs{Provider: "cloudflare", V4: []string{"1.2.3.0/24", "4.5.6.0/24"}, V6: []string{"2001:db8::/32"}, Hash: "h"},
	}
}

func TestRenderCaddyAllowVsDeny(t *testing.T) {
	allow := string(renderCaddy(testInput("caddy", "allow")))
	if !strings.Contains(allow, "@ipwatch_web1 not remote_ip 1.2.3.0/24 4.5.6.0/24 2001:db8::/32") {
		t.Fatalf("allow matcher wrong:\n%s", allow)
	}
	if !strings.Contains(allow, "abort @ipwatch_web1") {
		t.Fatal("missing abort")
	}
	deny := string(renderCaddy(testInput("caddy", "deny")))
	if !strings.Contains(deny, "@ipwatch_web1 remote_ip 1.2.3.0/24") || strings.Contains(deny, "not remote_ip") {
		t.Fatalf("deny matcher wrong:\n%s", deny)
	}
}

func TestRenderApacheModes(t *testing.T) {
	allow := string(renderApache(testInput("apache", "allow")))
	if !strings.Contains(allow, "Require ip 1.2.3.0/24 4.5.6.0/24 2001:db8::/32") {
		t.Fatalf("allow wrong:\n%s", allow)
	}
	deny := string(renderApache(testInput("apache", "deny")))
	if !strings.Contains(deny, "Require not ip 1.2.3.0/24") || !strings.Contains(deny, "<RequireAll>") {
		t.Fatalf("deny wrong:\n%s", deny)
	}
}

func TestRenderApacheRealIP(t *testing.T) {
	in := testInput("apache", "allow")
	in.Target.Config.RealIP = true
	out := string(renderApache(in))
	if !strings.Contains(out, "RemoteIPHeader CF-Connecting-IP") || !strings.Contains(out, "RemoteIPTrustedProxy 1.2.3.0/24") {
		t.Fatalf("real-ip missing:\n%s", out)
	}
}

func TestRenderNftablesModes(t *testing.T) {
	allow := renderNftables(testInput("nftables", "allow"))
	for _, want := range []string{
		"add table inet ipwatch_web1",
		"delete table inet ipwatch_web1",
		"policy accept;",
		"tcp dport { 80, 443 } ct state new ip saddr != @allowed_v4 drop",
		"ip6 saddr != @allowed_v6 drop",
	} {
		if !strings.Contains(allow, want) {
			t.Fatalf("allow ruleset missing %q:\n%s", want, allow)
		}
	}
	deny := renderNftables(testInput("nftables", "deny"))
	if !strings.Contains(deny, "ip saddr @allowed_v4 drop") || strings.Contains(deny, "!=") {
		t.Fatalf("deny ruleset wrong:\n%s", deny)
	}
}

func TestNftablesCustomPorts(t *testing.T) {
	in := testInput("nftables", "allow")
	in.Target.Firewall.Ports = []int{8080, 8443}
	if !strings.Contains(renderNftables(in), "tcp dport { 8080, 8443 }") {
		t.Fatal("custom ports not honored")
	}
}

func TestRenderIPTablesModes(t *testing.T) {
	allow := renderIPTables(testInput("iptables", "allow"))
	for _, want := range []string{
		"ipset create ipwatch_web1_v4 hash:net family inet -exist",
		"ipset swap ipwatch_web1_v4t ipwatch_web1_v4",
		"-m set ! --match-set ipwatch_web1_v4 src -j DROP",
		"ip6tables -A IPWATCH_web1",
		"-C INPUT -j IPWATCH_web1 2>/dev/null || iptables -I INPUT -j IPWATCH_web1",
	} {
		if !strings.Contains(allow, want) {
			t.Fatalf("allow script missing %q:\n%s", want, allow)
		}
	}
	deny := renderIPTables(testInput("iptables", "deny"))
	if !strings.Contains(deny, "-m set --match-set ipwatch_web1_v4 src -j DROP") || strings.Contains(deny, "! --match-set") {
		t.Fatalf("deny script wrong:\n%s", deny)
	}
}

func TestRenderIPTablesCustomPorts(t *testing.T) {
	in := testInput("iptables", "allow")
	in.Target.Firewall.Ports = []int{8080, 8443}
	if !strings.Contains(renderIPTables(in), "--dports 8080,8443") {
		t.Fatal("custom ports not honored")
	}
}

func TestRenderUFW(t *testing.T) {
	allow := renderUFW(testInput("ufw", "allow"))
	if !strings.Contains(allow, "ufw allow proto tcp from 1.2.3.0/24 to any port 80,443 comment 'ip-watch:web1'") {
		t.Fatalf("ufw allow rule wrong:\n%s", allow)
	}
	// cleans own prior rules first
	if !strings.Contains(allow, "ufw status numbered") || !strings.Contains(allow, "ufw --force delete") {
		t.Fatalf("ufw missing self-cleanup:\n%s", allow)
	}
	deny := renderUFW(testInput("ufw", "deny"))
	if !strings.Contains(deny, "ufw deny proto tcp from 1.2.3.0/24") {
		t.Fatalf("ufw deny wrong:\n%s", deny)
	}
}

// admin-allow CIDRs must surface in every engine's output
func TestAdminAllowIPsReachEveryEngine(t *testing.T) {
	const adminV4 = "203.0.113.5/32"
	const adminV6 = "2001:db8:dead::/48"

	base := testInput("", "allow")
	// repro applier allow-mode merge
	base.CIDRs = base.CIDRs.WithExtra([]string{adminV4, adminV6})

	renderers := map[string]func(Input) string{
		"caddy":    func(in Input) string { return string(renderCaddy(in)) },
		"apache":   func(in Input) string { return string(renderApache(in)) },
		"haproxy":  func(in Input) string { return string(renderHAProxyACL(in)) },
		"nftables": renderNftables,
		"iptables": renderIPTables,
		"ufw":      renderUFW,
	}
	for name, render := range renderers {
		out := render(base)
		if !strings.Contains(out, adminV4) {
			t.Errorf("%s: admin v4 CIDR %q missing from rendered output:\n%s", name, adminV4, out)
		}
		if !strings.Contains(out, adminV6) {
			t.Errorf("%s: admin v6 CIDR %q missing from rendered output:\n%s", name, adminV6, out)
		}
	}
}

func TestInjectCaddySiteBlock(t *testing.T) {
	conf := []byte("example.com {\n\treverse_proxy localhost:8000\n}\n")
	isHeader := func(raw, trimmed string) bool { return !startsWithSpace(raw) && strings.HasSuffix(trimmed, "{") }
	out, err := injectAfterHeader(conf, "k", []string{"import /x"}, "\t", "", isHeader)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Index(s, "import /x") > strings.Index(s, "reverse_proxy") {
		t.Fatalf("import not first in block:\n%s", s)
	}
	// idempotent
	again, _ := injectAfterHeader(out, "k", []string{"import /x"}, "\t", "", isHeader)
	if strings.Count(string(again), "import /x") != 1 {
		t.Fatalf("not idempotent:\n%s", again)
	}
}

func TestInjectHAProxyFrontendSelector(t *testing.T) {
	conf := []byte("frontend http\n    bind *:80\nfrontend admin\n    bind *:9000\n")
	out, err := injectAfterHeader(conf, "k", []string{"acl x src -f /f"}, "    ", "admin", haproxyFrontendMatcher("admin"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// must land in admin frontend
	if strings.Index(s, "acl x src -f /f") < strings.Index(s, "bind *:80") {
		t.Fatalf("injected into wrong frontend:\n%s", s)
	}
}

// "admin" must not match "frontend admin-old"
func TestHAProxyFrontendMatcherExact(t *testing.T) {
	m := haproxyFrontendMatcher("admin")
	if m("frontend admin-old", "frontend admin-old") {
		t.Error(`"admin" must not match "frontend admin-old"`)
	}
	if !m("frontend admin", "frontend admin") {
		t.Error(`"admin" should match "frontend admin"`)
	}
	if m("    frontend admin", "frontend admin") {
		t.Error("an indented (nested) line is not a frontend header")
	}
	// decoy first: selector reaches exact frontend
	conf := []byte("frontend admin-old\n    bind *:8000\nfrontend admin\n    bind *:9000\n")
	out, err := injectAfterHeader(conf, "k", []string{"acl x src -f /f"}, "    ", "admin", haproxyFrontendMatcher("admin"))
	if err != nil {
		t.Fatal(err)
	}
	if s := string(out); strings.Index(s, "acl x src -f /f") < strings.Index(s, "bind *:8000") {
		t.Fatalf("injected into the decoy admin-old frontend:\n%s", s)
	}
}

// "example.com": no longer-label match; any label in multi-label
func TestCaddySiteMatcherExact(t *testing.T) {
	m := caddySiteMatcher("example.com")
	if m("example.com.evil.test {", "example.com.evil.test {") {
		t.Error(`"example.com" must not match "example.com.evil.test {"`)
	}
	if !m("example.com {", "example.com {") {
		t.Error(`"example.com" should match "example.com {"`)
	}
	if !m("example.com, www.example.com {", "example.com, www.example.com {") {
		t.Error("should match a label inside a multi-label header")
	}
	if !caddySiteMatcher("www.example.com")("example.com, www.example.com {", "example.com, www.example.com {") {
		t.Error("should match the second label in a multi-label header")
	}
	// decoy longer label first must not match
	conf := []byte("example.com.evil.test {\n\trespond \"x\"\n}\nexample.com {\n\trespond \"y\"\n}\n")
	out, err := injectAfterHeader(conf, "k", []string{"import /x"}, "\t", "example.com", caddySiteMatcher("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if s := string(out); strings.Index(s, "import /x") < strings.Index(s, `respond "x"`) {
		t.Fatalf("injected into the decoy evil block:\n%s", s)
	}
}

func TestCaddyTrustedProxiesNoGlobalBlock(t *testing.T) {
	conf := []byte(":80 {\n\tfile_server\n}\n")
	out, err := caddyEnsureTrustedProxies(conf, "k", []string{"1.2.3.0/24", "2606:4700::/32"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "trusted_proxies static 1.2.3.0/24 2606:4700::/32") {
		t.Fatalf("trusted_proxies missing:\n%s", s)
	}
	if !strings.HasPrefix(strings.TrimSpace(s), "# >>> ip-watch:k") {
		t.Fatalf("global block not prepended:\n%s", s)
	}
	// idempotent
	again, _ := caddyEnsureTrustedProxies(out, "k", []string{"1.2.3.0/24"})
	if strings.Count(string(again), "trusted_proxies") != 1 {
		t.Fatalf("not idempotent:\n%s", again)
	}
}

func TestCaddyTrustedProxiesMergesIntoGlobal(t *testing.T) {
	conf := []byte("{\n\tadmin off\n}\n:80 {\n\tfile_server\n}\n")
	out, err := caddyEnsureTrustedProxies(conf, "k", []string{"1.2.3.0/24"})
	if err != nil {
		t.Fatalf("should merge into global block without servers: %v", err)
	}
	if !strings.Contains(string(out), "trusted_proxies static 1.2.3.0/24") {
		t.Fatalf("did not merge trusted_proxies:\n%s", out)
	}
}

func TestCaddyTrustedProxiesErrorsOnExistingServers(t *testing.T) {
	conf := []byte("{\n\tservers {\n\t\tprotocols h1 h2\n\t}\n}\n:80 {\n\tfile_server\n}\n")
	if _, err := caddyEnsureTrustedProxies(conf, "k", []string{"1.2.3.0/24"}); err == nil {
		t.Fatal("expected error when a servers block already exists")
	}
}

func TestInjectApacheVhostSelector(t *testing.T) {
	conf := []byte("<VirtualHost *:80>\n    ServerName a.example.com\n</VirtualHost>\n<VirtualHost *:80>\n    ServerName b.example.com\n</VirtualHost>\n")
	out, err := injectApacheVhost(conf, "k", "Include /m", "b.example.com")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// Include in b vhost: after a's, before b's ServerName
	if strings.Index(s, "Include /m") < strings.Index(s, "a.example.com") {
		t.Fatalf("injected into wrong vhost:\n%s", s)
	}
	if strings.Index(s, "Include /m") > strings.Index(s, "b.example.com") {
		t.Fatalf("not placed right after <VirtualHost>:\n%s", s)
	}
}

func TestInjectApacheVhostNoMatch(t *testing.T) {
	conf := []byte("<VirtualHost *:80>\n    ServerName a.example.com\n</VirtualHost>\n")
	if _, err := injectApacheVhost(conf, "k", "Include /m", "nope.com"); err == nil {
		t.Fatal("expected error for unmatched selector")
	}
}

func TestAppendIncludeIdempotent(t *testing.T) {
	conf := []byte("ServerRoot /x\nListen 80\n")
	once, _ := appendInclude(conf, "k", "Include /m", "")
	twice, _ := appendInclude(once, "k", "Include /m", "")
	if strings.Count(string(twice), "Include /m") != 1 {
		t.Fatalf("appendInclude not idempotent:\n%s", twice)
	}
}
