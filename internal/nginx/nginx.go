// Package nginx: detect/render/validate/reload; apply in applier.
package nginx

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/rezmoss/ip-watch/internal/config"
	"github.com/rezmoss/ip-watch/internal/fetcher"
	"github.com/rezmoss/ip-watch/internal/transport"
)

// Detection: nginx install found.
type Detection struct {
	Found      bool   `json:"found"`
	Binary     string `json:"binary,omitempty"`
	Version    string `json:"version,omitempty"`
	ConfigPath string `json:"config_path,omitempty"` // main conf
	Message    string `json:"message,omitempty"`
}

var (
	reVersion  = regexp.MustCompile(`nginx/(\S+)`)
	reConfPath = regexp.MustCompile(`configuration file (\S+) `)
	reConfArg  = regexp.MustCompile(`--conf-path=(\S+)`)
)

// Detect: find nginx & main cfg.
func Detect(ctx context.Context, t transport.Transport) (*Detection, error) {
	bin, err := t.LookPath("nginx")
	if err != nil {
		return &Detection{Found: false, Message: "nginx binary not found in PATH"}, nil
	}
	d := &Detection{Found: true, Binary: bin}

	if res, err := t.Run(ctx, bin, "-v"); err == nil {
		if m := reVersion.FindStringSubmatch(res.Stderr + res.Stdout); m != nil {
			d.Version = m[1]
		}
	}
	// -t prints active cfg path on stderr
	if res, err := t.Run(ctx, bin, "-t"); err == nil {
		if m := reConfPath.FindStringSubmatch(res.Stderr); m != nil {
			d.ConfigPath = m[1]
		}
	}
	// fallback: compiled-in --conf-path
	if d.ConfigPath == "" {
		if res, err := t.Run(ctx, bin, "-V"); err == nil {
			if m := reConfArg.FindStringSubmatch(res.Stderr); m != nil {
				d.ConfigPath = m[1]
			}
		}
	}
	return d, nil
}

// Validate: `nginx -t`; output + pass/fail.
func Validate(ctx context.Context, t transport.Transport, bin string) (string, bool, error) {
	res, err := t.Run(ctx, bin, "-t")
	if err != nil {
		return "", false, err
	}
	out := strings.TrimSpace(res.Stderr + res.Stdout)
	return out, res.ExitCode == 0, nil
}

// Reload: `nginx -s reload`.
func Reload(ctx context.Context, t transport.Transport, bin string) (string, error) {
	res, err := t.Run(ctx, bin, "-s", "reload")
	if err != nil {
		return "", err
	}
	out := strings.TrimSpace(res.Stderr + res.Stdout)
	if res.ExitCode != 0 {
		return out, fmt.Errorf("nginx -s reload exited %d: %s", res.ExitCode, out)
	}
	return out, nil
}

// RenderInclude: managed include; allow/deny rules + RealIP
func RenderInclude(t config.Target, c *fetcher.CIDRs) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# ip-watch managed file - do not edit by hand\n")
	fmt.Fprintf(&b, "# provider: %s  mode: %s  ranges: %d\n", c.Provider, t.Mode, len(c.V4)+len(c.V6))
	fmt.Fprintf(&b, "# source hash: %s\n\n", c.Hash)

	keyword := "deny"
	if t.Mode == "allow" {
		keyword = "allow"
	}
	for _, cidr := range c.V4 {
		fmt.Fprintf(&b, "%s %s;\n", keyword, cidr)
	}
	for _, cidr := range c.V6 {
		fmt.Fprintf(&b, "%s %s;\n", keyword, cidr)
	}
	if t.Mode == "allow" {
		b.WriteString("deny all;\n")
	}

	if t.Config.RealIP {
		b.WriteString("\n# real client IP recovery\n")
		for _, cidr := range c.V4 {
			fmt.Fprintf(&b, "set_real_ip_from %s;\n", cidr)
		}
		for _, cidr := range c.V6 {
			fmt.Fprintf(&b, "set_real_ip_from %s;\n", cidr)
		}
		header := "X-Forwarded-For"
		if strings.Contains(c.Provider, "cloudflare") {
			header = "CF-Connecting-IP"
		}
		fmt.Fprintf(&b, "real_ip_header %s;\n", header)
	}
	return b.String()
}
