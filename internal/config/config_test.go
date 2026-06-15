package config

import (
	"path/filepath"
	"testing"
)

func TestLoadCreatesDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8080" || c.DataSource == "" || c.UpdateHour != 3 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	// reload identically
	again, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Listen != c.Listen {
		t.Fatal("reload mismatch")
	}
}

func TestApplyDefaultsKeepsExplicit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := &Config{Listen: ":9999", Targets: []Target{{ID: "a"}}}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Listen != ":9999" {
		t.Fatalf("explicit listen overwritten: %q", loaded.Listen)
	}
	if loaded.DataSource != DefaultDataSource {
		t.Fatal("missing data_source not defaulted")
	}
}

func TestEffectiveProviders(t *testing.T) {
	cases := []struct {
		target Target
		want   []string
	}{
		{Target{Providers: []string{"a", "b"}}, []string{"a", "b"}},
		{Target{Provider: "x"}, []string{"x"}},
		{Target{Providers: []string{"a"}, Provider: "x"}, []string{"a"}}, // list wins
		{Target{}, nil},
	}
	for _, c := range cases {
		got := c.target.EffectiveProviders()
		if len(got) != len(c.want) {
			t.Fatalf("EffectiveProviders(%+v) = %v, want %v", c.target, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("EffectiveProviders(%+v) = %v, want %v", c.target, got, c.want)
			}
		}
	}
}

func TestTargetValidate(t *testing.T) {
	valid := Target{ID: "web1", Mode: "allow", Providers: []string{"cloudflare"}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
	bad := []Target{
		{ID: "", Mode: "allow", Providers: []string{"cloudflare"}},                                                  // empty id
		{ID: "a b", Mode: "allow", Providers: []string{"cloudflare"}},                                               // space
		{ID: "a;rm", Mode: "allow", Providers: []string{"cloudflare"}},                                              // metachar
		{ID: "../etc", Mode: "allow", Providers: []string{"cloudflare"}},                                            // traversal
		{ID: "web1", Mode: "blok", Providers: []string{"cloudflare"}},                                               // bad mode
		{ID: "web1", Mode: "allow"},                                                                                 // no provider
		{ID: "web1", Mode: "allow", Providers: []string{"Cloud Flare"}},                                             // bad provider
		{ID: "web1", Mode: "allow", Providers: []string{"cloudflare"}, Firewall: FirewallOpts{Ports: []int{0}}},     // port 0
		{ID: "web1", Mode: "allow", Providers: []string{"cloudflare"}, Firewall: FirewallOpts{Ports: []int{70000}}}, // port big
	}
	for i, tt := range bad {
		if err := tt.Validate(); err == nil {
			t.Fatalf("case %d: expected validation error for %+v", i, tt)
		}
	}
}

func TestValidateAdminPortsAndAllowIPs(t *testing.T) {
	base := func() Target {
		return Target{ID: "fw", Mode: "allow", Providers: []string{"cloudflare"}, Engine: "nftables"}
	}
	// SSH on allow-mode fw rejected w/o override
	ssh := base()
	ssh.Firewall.Ports = []int{22}
	if err := ssh.Validate(); err == nil {
		t.Fatal("expected rejection of port 22 in allow mode")
	}
	// but allowed w/ override
	ssh.Firewall.AllowAdminPorts = true
	if err := ssh.Validate(); err != nil {
		t.Fatalf("override should permit admin port: %v", err)
	}
	// deny mode skips admin-port guard
	denySSH := base()
	denySSH.Mode = "deny"
	denySSH.Firewall.Ports = []int{22}
	if err := denySSH.Validate(); err != nil {
		t.Fatalf("deny mode should allow port 22: %v", err)
	}
	// admin_allow_ips must be CIDRs
	badIP := base()
	badIP.AdminAllowIPs = []string{"not-an-ip"}
	if err := badIP.Validate(); err == nil {
		t.Fatal("expected rejection of bad admin_allow_ips")
	}
	okIP := base()
	okIP.AdminAllowIPs = []string{"203.0.113.5/32"}
	if err := okIP.Validate(); err != nil {
		t.Fatalf("valid admin IP rejected: %v", err)
	}
}

func TestUpsertAndRemoveTarget(t *testing.T) {
	c := Default()
	c.UpsertTarget(Target{ID: "a", Provider: "p1"})
	c.UpsertTarget(Target{ID: "a", Provider: "p2"}) // replace
	if len(c.Targets) != 1 || c.Targets[0].Provider != "p2" {
		t.Fatalf("upsert did not replace: %+v", c.Targets)
	}
	if _, ok := c.Target("a"); !ok {
		t.Fatal("Target lookup failed")
	}
	if !c.RemoveTarget("a") || c.RemoveTarget("a") {
		t.Fatal("RemoveTarget semantics wrong")
	}
}
