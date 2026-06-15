package engine

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// Apache: Require ip/not ip in <Location />, via Include.
type Apache struct{}

var (
	reApacheVersion = regexp.MustCompile(`Apache/(\S+)`)
	reServerConfig  = regexp.MustCompile(`SERVER_CONFIG_FILE="([^"]+)"`)
	reHTTPDRoot     = regexp.MustCompile(`HTTPD_ROOT="([^"]+)"`)
)

func (Apache) Name() string { return "apache" }

func (Apache) Detect(ctx context.Context, tr transport.Transport) (*Detection, error) {
	bin, ok := lookAny(tr, "apachectl", "apache2ctl", "httpd")
	if !ok {
		return &Detection{Message: "apache binary not found (apachectl/apache2ctl/httpd)"}, nil
	}
	det := &Detection{Found: true, Binary: bin}
	det.Version = versionVia(ctx, tr, bin, reApacheVersion, "-v")
	det.ConfigPath = apacheConfigPath(ctx, tr, bin)
	return det, nil
}

func (e Apache) Apply(ctx context.Context, tr transport.Transport, in Input) Outcome {
	plan, out, ok := e.plan(ctx, tr, in)
	if !ok {
		return out
	}
	return applyConfig(ctx, tr, in, plan)
}

func (e Apache) Remove(ctx context.Context, tr transport.Transport, in Input) Outcome {
	plan, out, ok := e.plan(ctx, tr, in)
	if !ok {
		return out
	}
	return removeConfig(ctx, tr, plan)
}

func (Apache) plan(ctx context.Context, tr transport.Transport, in Input) (configPlan, Outcome, bool) {
	det, _ := Apache{}.Detect(ctx, tr)
	if det == nil || !det.Found {
		return configPlan{}, fail("apache not detected: %s", msgOf(det)), false
	}
	confFile := in.Target.Config.File
	if confFile == "" {
		confFile = det.ConfigPath
	}
	if confFile == "" {
		return configPlan{}, fail("could not determine apache config file; set config.file"), false
	}
	managedPath := path.Join(path.Dir(confFile), "ip-watch", in.Target.ID+".conf")

	var managedData []byte
	if in.CIDRs != nil {
		managedData = renderApache(in)
	}
	// blank selector=global; else vhost by ServerName/Alias
	inject := appendInclude
	if in.Target.Config.Selector != "" {
		inject = injectApacheVhost
	}
	return configPlan{
		bin:         det.Binary,
		managedPath: managedPath,
		managedData: managedData,
		confFile:    confFile,
		reference:   "Include " + managedPath,
		selector:    in.Target.Config.Selector,
		inject:      inject,
		validate: func(ctx context.Context, tr transport.Transport, bin string) (string, bool, error) {
			res, err := tr.Run(ctx, bin, "-t")
			if err != nil {
				return "", false, err
			}
			return strings.TrimSpace(res.Stderr + res.Stdout), res.ExitCode == 0, nil
		},
		reload: func(ctx context.Context, tr transport.Transport, bin string) (string, error) {
			res, err := tr.Run(ctx, bin, "-k", "graceful")
			if err != nil {
				return "", err
			}
			if res.ExitCode != 0 {
				return "", fmt.Errorf("apache graceful: %s", strings.TrimSpace(res.Stderr+res.Stdout))
			}
			return "", nil
		},
	}, Outcome{}, true
}

// append ref at EOF, marker-wrapped (server scope)
func appendInclude(conf []byte, key, reference, _ string) ([]byte, error) {
	src := strings.TrimRight(stripManaged(string(conf), key), "\n")
	block := "\n" + beginMark(key) + "\n" + reference + "\n" + endMark(key) + "\n"
	return []byte(src + "\n" + block), nil
}

// inject Include in vhost w/ ServerName/Alias == selector
func injectApacheVhost(conf []byte, key, reference, selector string) ([]byte, error) {
	src := stripManaged(string(conf), key)
	lines := strings.Split(src, "\n")
	open := -1
	for i, line := range lines {
		low := strings.ToLower(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(low, "<virtualhost"):
			open = i
		case strings.HasPrefix(low, "</virtualhost"):
			open = -1
		case open >= 0 && (strings.HasPrefix(low, "servername") || strings.HasPrefix(low, "serveralias")):
			for _, field := range strings.Fields(strings.TrimSpace(line))[1:] {
				if field == selector {
					return insertAfterLine(lines, open, key, reference), nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no <VirtualHost> with ServerName/ServerAlias %q (set config.file to the vhost file?)", selector)
}

// insert ref after lines[idx], indent +1
func insertAfterLine(lines []string, idx int, key, reference string) []byte {
	indent := leadingWhitespace(lines[idx]) + "    "
	block := []string{indent + beginMark(key), indent + reference, indent + endMark(key)}
	out := make([]string, 0, len(lines)+len(block))
	out = append(out, lines[:idx+1]...)
	out = append(out, block...)
	out = append(out, lines[idx+1:]...)
	return []byte(strings.Join(out, "\n"))
}

func leadingWhitespace(s string) string {
	end := 0
	for end < len(s) && (s[end] == ' ' || s[end] == '\t') {
		end++
	}
	return s[:end]
}

func renderApache(in Input) []byte {
	cidrs := joinCIDRs(allCIDRs(in.CIDRs.V4, in.CIDRs.V6))
	var b strings.Builder
	fmt.Fprintf(&b, "# ip-watch managed file - do not edit by hand\n")
	fmt.Fprintf(&b, "# provider: %s  mode: %s\n", in.CIDRs.Provider, in.Target.Mode)

	if in.Target.Config.RealIP {
		header := "X-Forwarded-For"
		if strings.Contains(in.CIDRs.Provider, "cloudflare") {
			header = "CF-Connecting-IP"
		}
		fmt.Fprintf(&b, "RemoteIPHeader %s\n", header)
		for _, cidr := range allCIDRs(in.CIDRs.V4, in.CIDRs.V6) {
			fmt.Fprintf(&b, "RemoteIPTrustedProxy %s\n", cidr)
		}
	}

	b.WriteString("<Location />\n")
	if in.Target.Mode == "allow" {
		fmt.Fprintf(&b, "    Require ip %s\n", cidrs)
	} else {
		b.WriteString("    <RequireAll>\n")
		b.WriteString("        Require all granted\n")
		fmt.Fprintf(&b, "        Require not ip %s\n", cidrs)
		b.WriteString("    </RequireAll>\n")
	}
	b.WriteString("</Location>\n")
	return []byte(b.String())
}

func apacheConfigPath(ctx context.Context, tr transport.Transport, bin string) string {
	res, err := tr.Run(ctx, bin, "-V")
	if err != nil {
		return ""
	}
	out := res.Stderr + res.Stdout
	conf := firstGroup(reServerConfig, out)
	if conf == "" {
		return ""
	}
	if strings.HasPrefix(conf, "/") {
		return conf
	}
	if root := firstGroup(reHTTPDRoot, out); root != "" {
		return path.Join(root, conf)
	}
	return conf
}

func firstGroup(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}
