package engine

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// HAProxy: src ACL (managed file) + http-request deny in frontend.
type HAProxy struct{}

var reHAProxyVersion = regexp.MustCompile(`version (\S+)`)

func (HAProxy) Name() string { return "haproxy" }

func (HAProxy) Detect(ctx context.Context, tr transport.Transport) (*Detection, error) {
	bin, ok := lookAny(tr, "haproxy")
	if !ok {
		return &Detection{Message: "haproxy binary not found in PATH"}, nil
	}
	det := &Detection{Found: true, Binary: bin}
	det.Version = versionVia(ctx, tr, bin, reHAProxyVersion, "-v")
	for _, candidate := range []string{"/usr/local/etc/haproxy/haproxy.cfg", "/etc/haproxy/haproxy.cfg"} {
		if tr.Exists(candidate) {
			det.ConfigPath = candidate
			break
		}
	}
	return det, nil
}

func (e HAProxy) Apply(ctx context.Context, tr transport.Transport, in Input) Outcome {
	plan, out, ok := e.plan(ctx, tr, in)
	if !ok {
		return out
	}
	return applyConfig(ctx, tr, in, plan)
}

func (e HAProxy) Remove(ctx context.Context, tr transport.Transport, in Input) Outcome {
	plan, out, ok := e.plan(ctx, tr, in)
	if !ok {
		return out
	}
	return removeConfig(ctx, tr, plan)
}

func (HAProxy) plan(ctx context.Context, tr transport.Transport, in Input) (configPlan, Outcome, bool) {
	det, _ := HAProxy{}.Detect(ctx, tr)
	if det == nil || !det.Found {
		return configPlan{}, fail("haproxy not detected: %s", msgOf(det)), false
	}
	confFile := in.Target.Config.File
	if confFile == "" {
		confFile = det.ConfigPath
	}
	if confFile == "" {
		return configPlan{}, fail("could not determine haproxy config file; set config.file"), false
	}
	managedPath := path.Join(path.Dir(confFile), "ip-watch", in.Target.ID+".acl")

	acl := "ipwatch_" + sanitize(in.Target.ID)
	condition := "!" + acl // allow: deny NOT in set
	if in.Target.Mode == "deny" {
		condition = acl // deny: deny in set
	}
	payload := []string{
		fmt.Sprintf("acl %s src -f %s", acl, managedPath),
		fmt.Sprintf("http-request deny if %s", condition),
	}
	// real_ip: deny ran on conn IP, safe to rewrite src to fwd IP
	if in.Target.Config.RealIP && in.CIDRs != nil {
		header := "X-Forwarded-For"
		if strings.Contains(in.CIDRs.Provider, "cloudflare") {
			header = "CF-Connecting-IP"
		}
		payload = append(payload,
			"option forwardfor",
			fmt.Sprintf("http-request set-src hdr_ip(%s) if { req.hdr(%s) -m found }", header, header))
	}

	var managedData []byte
	if in.CIDRs != nil {
		managedData = renderHAProxyACL(in)
	}
	return configPlan{
		bin:         det.Binary,
		managedPath: managedPath,
		managedData: managedData,
		confFile:    confFile,
		selector:    in.Target.Config.Selector,
		inject: func(conf []byte, key, _, selector string) ([]byte, error) {
			return injectAfterHeader(conf, key, payload, "    ", selector, haproxyFrontendMatcher(selector))
		},
		validate: func(ctx context.Context, tr transport.Transport, bin string) (string, bool, error) {
			res, err := tr.Run(ctx, bin, "-c", "-f", confFile)
			if err != nil {
				return "", false, err
			}
			return strings.TrimSpace(res.Stderr + res.Stdout), res.ExitCode == 0, nil
		},
		reload: haproxyReload,
	}, Outcome{}, true
}

// haproxyFrontendMatcher: name == selector exactly; empty = first
func haproxyFrontendMatcher(selector string) func(raw, trimmed string) bool {
	return func(raw, trimmed string) bool {
		if startsWithSpace(raw) {
			return false
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 || fields[0] != "frontend" {
			return false
		}
		if selector == "" {
			return true
		}
		return len(fields) >= 2 && fields[1] == selector
	}
}

func renderHAProxyACL(in Input) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# ip-watch managed acl - do not edit by hand\n")
	fmt.Fprintf(&b, "# provider: %s  mode: %s\n", in.CIDRs.Provider, in.Target.Mode)
	for _, cidr := range allCIDRs(in.CIDRs.V4, in.CIDRs.V6) {
		fmt.Fprintln(&b, cidr)
	}
	return []byte(b.String())
}

// haproxyReload: systemctl if present, else SIGUSR2 to master
func haproxyReload(ctx context.Context, tr transport.Transport, _ string) (string, error) {
	if _, ok := lookAny(tr, "systemctl"); ok {
		if res, err := tr.Run(ctx, "systemctl", "reload", "haproxy"); err == nil && res.ExitCode == 0 {
			return "", nil
		}
	}
	// SIGUSR2 master = no-drop reload; only if PID 1 is haproxy, else we'd hit init/supervisor
	if !pid1IsHAProxy(ctx, tr) {
		return "", fmt.Errorf("cannot reload haproxy: no working 'systemctl reload haproxy' " +
			"and PID 1 is not the haproxy master; run haproxy as main process " +
			"(master-worker mode) or provide systemctl")
	}
	res, err := tr.Run(ctx, "sh", "-c", "kill -USR2 1")
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("haproxy reload (SIGUSR2 pid 1): %s", strings.TrimSpace(res.Stderr+res.Stdout))
	}
	return "", nil
}

// pid1IsHAProxy: PID 1 cmd == haproxy, via /proc/1/comm.
func pid1IsHAProxy(ctx context.Context, tr transport.Transport) bool {
	res, err := tr.Run(ctx, "sh", "-c", "cat /proc/1/comm")
	if err != nil || res.ExitCode != 0 {
		return false
	}
	return strings.TrimSpace(res.Stdout) == "haproxy"
}
