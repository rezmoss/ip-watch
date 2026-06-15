package engine

import (
	"context"
	"regexp"
	"strings"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// first resolvable name
func lookAny(tr transport.Transport, names ...string) (string, bool) {
	for _, name := range names {
		if path, err := tr.LookPath(name); err == nil && path != "" {
			return path, true
		}
	}
	return "", false
}

// run bin, extract version (re 1st group)
func versionVia(ctx context.Context, tr transport.Transport, bin string, re *regexp.Regexp, args ...string) string {
	res, err := tr.Run(ctx, bin, args...)
	if err != nil {
		return ""
	}
	if m := re.FindStringSubmatch(res.Stderr + res.Stdout); m != nil {
		return m[1]
	}
	return ""
}

// v4 then v6, one slice (order matters)
func allCIDRs(v4, v6 []string) []string {
	out := make([]string, 0, len(v4)+len(v6))
	out = append(out, v4...)
	out = append(out, v6...)
	return out
}

func joinCIDRs(cidrs []string) string { return strings.Join(cidrs, " ") }
