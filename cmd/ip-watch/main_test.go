package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rezmoss/ip-watch/internal/config"
)

func TestParseGlobal(t *testing.T) {
	def := defaultConfigPath()
	cases := []struct {
		name    string
		argv    []string
		cmd     string
		cfgPath string
		rest    []string
	}{
		{"default", nil, "serve", def, nil},
		{"command only", []string{"apply"}, "apply", def, []string{}},
		{"flag after command stays in rest", []string{"apply", "-dry"}, "apply", def, []string{"-dry"}},
		{"config before command", []string{"-config", "/tmp/c.json", "apply"}, "apply", "/tmp/c.json", []string{}},
		{"config= form", []string{"-config=/tmp/c.json", "apply", "-dry"}, "apply", "/tmp/c.json", []string{"-dry"}},
		{"remove with id", []string{"remove", "web1"}, "remove", def, []string{"web1"}},
		{"add with flags", []string{"add", "-id", "x", "-provider", "cloudflare"}, "add", def, []string{"-id", "x", "-provider", "cloudflare"}},
		{"-h becomes help", []string{"-h"}, "help", def, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfgPath, cmd, rest, err := parseGlobal(c.argv)
			if err != nil {
				t.Fatal(err)
			}
			if cmd != c.cmd || cfgPath != c.cfgPath || !reflect.DeepEqual(rest, c.rest) {
				t.Fatalf("parseGlobal(%v) = cfg=%s cmd=%s rest=%v, want cfg=%s cmd=%s rest=%v",
					c.argv, cfgPath, cmd, rest, c.cfgPath, c.cmd, c.rest)
			}
		})
	}
}

func TestParseGlobalErrors(t *testing.T) {
	for _, argv := range [][]string{
		{"-config"},         // missing value
		{"-bogus", "apply"}, // unknown global flag
	} {
		if _, _, _, err := parseGlobal(argv); err == nil {
			t.Errorf("parseGlobal(%v) should error", argv)
		}
	}
}

// each cmd well-formed + discoverable
func TestCommandRegistryIntegrity(t *testing.T) {
	if len(commands) == 0 {
		t.Fatal("command registry is empty")
	}
	seen := map[string]bool{}
	for _, c := range commands {
		if c.name == "" || c.summary == "" || c.run == nil {
			t.Errorf("command %+v missing name/summary/run", c)
		}
		if seen[c.name] {
			t.Errorf("duplicate command %q", c.name)
		}
		seen[c.name] = true
		if lookupCommand(c.name) != c {
			t.Errorf("lookupCommand(%q) did not return the registered command", c.name)
		}
		c.printHelp() // no panic
	}
	for _, required := range []string{"serve", "apply", "add", "rm", "targets", "providers", "config", "status", "history", "metrics", "settings", "help"} {
		if lookupCommand(required) == nil {
			t.Errorf("expected command %q to be registered", required)
		}
	}
}

func TestParseIntsAndSplit(t *testing.T) {
	got, err := parseInts("80, 443,8080")
	if err != nil || !reflect.DeepEqual(got, []int{80, 443, 8080}) {
		t.Fatalf("parseInts = %v, %v", got, err)
	}
	if _, err := parseInts("80,bad"); err == nil {
		t.Fatal("parseInts should reject non-numbers")
	}
	if s := splitComma(" a, ,b ,, c"); !reflect.DeepEqual(s, []string{"a", "b", "c"}) {
		t.Fatalf("splitComma = %v", s)
	}
}

func TestProbeAddr(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0:8080":   "127.0.0.1:8080", // docker bind
		":8080":          "127.0.0.1:8080",
		"[::]:8080":      "127.0.0.1:8080",
		"127.0.0.1:8080": "127.0.0.1:8080",
		"192.168.1.5:80": "192.168.1.5:80", // real addr kept
		"notanaddr":      "notanaddr",      // as-is
	}
	for in, want := range cases {
		if got := probeAddr(in); got != want {
			t.Errorf("probeAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// enforce cmds gated on valid cfg; repair/inspect not
func TestRequireValidGating(t *testing.T) {
	strict := map[string]bool{"apply": true, "remove": true}
	repair := []string{"add", "rm", "settings", "config", "serve", "help", "version", "targets", "status"}
	for name := range strict {
		if c := lookupCommand(name); c == nil || !c.requireValid {
			t.Errorf("command %q must have requireValid=true", name)
		}
	}
	for _, name := range repair {
		if c := lookupCommand(name); c != nil && c.requireValid {
			t.Errorf("command %q must NOT be requireValid (repair/inspect path)", name)
		}
	}
}

// add -apply on invalid cfg: save but don't enforce
func TestAddApplyGatedOnInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		StateDir:   dir,
		DataSource: config.DefaultDataSource,
		Targets: []config.Target{
			{ID: "dup", Providers: []string{"cloudflare"}, Mode: "allow", Engine: "nginx", Enabled: true},
			{ID: "dup", Providers: []string{"cloudflare"}, Mode: "allow", Engine: "nginx", Enabled: true},
		},
	}
	if cfg.Validate() == nil {
		t.Fatal("setup: config should be invalid (duplicate ids)")
	}
	cx := &cmdCtx{cfg: cfg, cfgPath: filepath.Join(dir, "config.json"), valid: false}
	add := lookupCommand("add")
	// dups remain -> cfg invalid -> apply skipped
	if err := add.run(add, cx, []string{"-id", "newt", "-provider", "cloudflare", "-engine", "nginx", "-apply"}); err != nil {
		t.Fatalf("add -apply on invalid config should save+skip-apply, got error: %v", err)
	}
	if _, ok := cx.cfg.Target("newt"); !ok {
		t.Fatal("new target should have been saved (repair path)")
	}
}

// rm on invalid cfg: refuse live uninstall, allow -uninstall=false
func TestRmUninstallGatedOnInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		StateDir:   dir,
		DataSource: config.DefaultDataSource,
		Targets: []config.Target{
			{ID: "dup", Providers: []string{"cloudflare"}, Mode: "allow", Engine: "nginx", Enabled: true},
			{ID: "dup", Providers: []string{"cloudflare"}, Mode: "allow", Engine: "nginx", Enabled: true},
		},
	}
	cx := &cmdCtx{cfg: cfg, cfgPath: filepath.Join(dir, "config.json"), valid: false}
	rm := lookupCommand("rm")
	if err := rm.run(rm, cx, []string{"dup"}); err == nil || !strings.Contains(err.Error(), "uninstall") {
		t.Fatalf("rm default must refuse live uninstall on invalid config, got %v", err)
	}
	if err := rm.run(rm, cx, []string{"dup", "-uninstall=false"}); err != nil {
		t.Fatalf("rm -uninstall=false (config-only) should succeed for repair: %v", err)
	}
	if cfg.Validate() != nil {
		t.Errorf("removing one duplicate should leave a valid config: %v", cfg.Validate())
	}
}
