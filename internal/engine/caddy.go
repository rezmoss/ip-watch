package engine

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// Caddy: remote_ip matcher + abort in site block, via import.
type Caddy struct{}

const defaultCaddyfile = "/etc/caddy/Caddyfile"

var reCaddyVersion = regexp.MustCompile(`v?(\d+\.\d+\.\d+)`)

func (Caddy) Name() string { return "caddy" }

func (Caddy) Detect(ctx context.Context, tr transport.Transport) (*Detection, error) {
	bin, ok := lookAny(tr, "caddy")
	if !ok {
		return &Detection{Message: "caddy binary not found in PATH"}, nil
	}
	det := &Detection{Found: true, Binary: bin, ConfigPath: defaultCaddyfile}
	det.Version = versionVia(ctx, tr, bin, reCaddyVersion, "version")
	return det, nil
}

func (e Caddy) Apply(ctx context.Context, tr transport.Transport, in Input) Outcome {
	plan, out, ok := e.plan(ctx, tr, in)
	if !ok {
		return out
	}
	return applyConfig(ctx, tr, in, plan)
}

func (e Caddy) Remove(ctx context.Context, tr transport.Transport, in Input) Outcome {
	plan, out, ok := e.plan(ctx, tr, in)
	if !ok {
		return out
	}
	return removeConfig(ctx, tr, plan)
}

func (Caddy) plan(ctx context.Context, tr transport.Transport, in Input) (configPlan, Outcome, bool) {
	det, _ := Caddy{}.Detect(ctx, tr)
	if det == nil || !det.Found {
		return configPlan{}, fail("caddy not detected: %s", detectMessage(nil, msgOf(det))), false
	}
	confFile := in.Target.Config.File
	if confFile == "" {
		confFile = det.ConfigPath
	}
	managedPath := path.Join(path.Dir(confFile), "ip-watch", in.Target.ID+".conf")

	var managedData []byte
	if in.CIDRs != nil {
		managedData = renderCaddy(in)
	}
	globalKey := managedPath + " global"
	return configPlan{
		bin:            det.Binary,
		managedPath:    managedPath,
		managedData:    managedData,
		confFile:       confFile,
		reference:      "import " + managedPath,
		selector:       in.Target.Config.Selector,
		extraStripKeys: []string{globalKey},
		inject: func(conf []byte, key, reference, selector string) ([]byte, error) {
			out, err := injectAfterHeader(conf, key, []string{reference}, "\t", selector, caddySiteMatcher(selector))
			if err != nil {
				return nil, err
			}
			// real_ip needs trusted_proxies global
			if in.Target.Config.RealIP && in.CIDRs != nil {
				out, err = caddyEnsureTrustedProxies(out, globalKey, allCIDRs(in.CIDRs.V4, in.CIDRs.V6))
				if err != nil {
					return nil, err
				}
			}
			return out, nil
		},
		validate: func(ctx context.Context, tr transport.Transport, bin string) (string, bool, error) {
			res, err := tr.Run(ctx, bin, "validate", "--adapter", "caddyfile", "--config", confFile)
			if err != nil {
				return "", false, err
			}
			return strings.TrimSpace(res.Stderr + res.Stdout), res.ExitCode == 0, nil
		},
		reload: func(ctx context.Context, tr transport.Transport, bin string) (string, error) {
			res, err := tr.Run(ctx, bin, "reload", "--adapter", "caddyfile", "--config", confFile)
			if err != nil {
				return "", err
			}
			if res.ExitCode != 0 {
				return "", fmt.Errorf("caddy reload: %s", strings.TrimSpace(res.Stderr+res.Stdout))
			}
			return "", nil
		},
	}, Outcome{}, true
}

// site block w/ label == selector exactly; empty = first
func caddySiteMatcher(selector string) func(raw, trimmed string) bool {
	return func(raw, trimmed string) bool {
		if startsWithSpace(raw) || !strings.HasSuffix(trimmed, "{") {
			return false
		}
		if selector == "" {
			return true
		}
		labels := strings.FieldsFunc(strings.TrimSuffix(trimmed, "{"), func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		})
		for _, l := range labels {
			if l == selector {
				return true
			}
		}
		return false
	}
}

// snippet: matcher + abort
func renderCaddy(in Input) []byte {
	matcher := "@ipwatch_" + sanitize(in.Target.ID)
	cidrs := joinCIDRs(allCIDRs(in.CIDRs.V4, in.CIDRs.V6))

	var b strings.Builder
	fmt.Fprintf(&b, "# ip-watch managed snippet - do not edit by hand\n")
	fmt.Fprintf(&b, "# provider: %s  mode: %s\n", in.CIDRs.Provider, in.Target.Mode)
	switch in.Target.Mode {
	case "allow":
		fmt.Fprintf(&b, "%s not remote_ip %s\n", matcher, cidrs)
	default:
		fmt.Fprintf(&b, "%s remote_ip %s\n", matcher, cidrs)
	}
	fmt.Fprintf(&b, "abort %s\n", matcher)
	return []byte(b.String())
}

// real-IP global trusted_proxies: prepend/merge if absent, err if set
func caddyEnsureTrustedProxies(conf []byte, key string, cidrs []string) ([]byte, error) {
	src := stripManaged(string(conf), key)
	tp := "trusted_proxies static " + joinCIDRs(cidrs)

	if !caddyHasGlobalBlock(src) {
		block := beginMark(key) + "\n{\n\tservers {\n\t\t" + tp + "\n\t}\n}\n" + endMark(key) + "\n"
		return []byte(block + src), nil
	}
	if caddyGlobalHasServers(src) {
		return nil, fmt.Errorf("real_ip: Caddyfile already defines servers/trusted_proxies global opt; " +
			"set it there manually or disable real_ip")
	}
	// merge servers block into global (after its `{`)
	return injectAfterHeader([]byte(src), key, []string{"servers {", "\t" + tp, "}"}, "\t", "",
		func(raw, trimmed string) bool { return !startsWithSpace(raw) && trimmed == "{" })
}

var reCaddyServers = regexp.MustCompile(`(?m)^\s*(servers\s*\{|trusted_proxies\b)`)

func caddyGlobalHasServers(src string) bool {
	return reCaddyServers.MatchString(src)
}

// Caddyfile opens w/ global block (first real line "{")
func caddyHasGlobalBlock(conf string) bool {
	for _, line := range strings.Split(conf, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return t == "{"
	}
	return false
}

func startsWithSpace(s string) bool {
	return len(s) > 0 && (s[0] == ' ' || s[0] == '\t')
}

func sanitize(s string) string {
	return strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(s)
}

func msgOf(det *Detection) string {
	if det == nil {
		return ""
	}
	return det.Message
}
