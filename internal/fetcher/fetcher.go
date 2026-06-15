// Package fetcher: per-provider CIDR lists + content hash.
package fetcher

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// CIDRs: v4/v6 ranges + content hash.
type CIDRs struct {
	Provider string
	V4       []string
	V6       []string
	Hash     string
}

// Fetcher: CIDR lists over HTTP.
type Fetcher struct {
	dataSource string
	client     *http.Client
	// dflt: bad CIDR fails closed; true: skip+log
	allowMalformed bool
}

// New: Fetcher for base URL; strict by dflt.
func New(dataSource string) *Fetcher {
	return &Fetcher{
		dataSource: dataSource,
		client:     &http.Client{Timeout: 30 * time.Second},
	}
}

// AllowMalformed: skip+log bad lines vs fail closed
func (f *Fetcher) AllowMalformed(v bool) *Fetcher {
	f.allowMalformed = v
	return f
}

// FetchMerged: merge providers (deduped, sorted); label "+"-joined
func (f *Fetcher) FetchMerged(ctx context.Context, providers []string) (*CIDRs, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers specified")
	}
	if len(providers) == 1 {
		return f.Fetch(ctx, providers[0])
	}
	v4set, v6set := map[string]struct{}{}, map[string]struct{}{}
	for _, p := range providers {
		c, err := f.Fetch(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", p, err)
		}
		for _, cidr := range c.V4 {
			v4set[cidr] = struct{}{}
		}
		for _, cidr := range c.V6 {
			v6set[cidr] = struct{}{}
		}
	}
	v4, v6 := sortedKeys(v4set), sortedKeys(v6set)
	label := strings.Join(providers, "+")
	return &CIDRs{Provider: label, V4: v4, V6: v6, Hash: hash(label, v4, v6)}, nil
}

// WithExtra: copy + merge extra CIDRs by family, rehash
func (c *CIDRs) WithExtra(extra []string) *CIDRs {
	v4set := map[string]struct{}{}
	v6set := map[string]struct{}{}
	for _, cidr := range c.V4 {
		v4set[cidr] = struct{}{}
	}
	for _, cidr := range c.V6 {
		v6set[cidr] = struct{}{}
	}
	for _, cidr := range extra {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if p.Addr().Is4() {
			v4set[cidr] = struct{}{}
		} else {
			v6set[cidr] = struct{}{}
		}
	}
	v4, v6 := sortedKeys(v4set), sortedKeys(v6set)
	return &CIDRs{Provider: c.Provider, V4: v4, V6: v6, Hash: hash(c.Provider, v4, v6)}
}

func sortedKeys(set map[string]struct{}) []string {
	return slices.Sorted(maps.Keys(set))
}

// Fetch: provider v4/v6 lists.
func (f *Fetcher) Fetch(ctx context.Context, provider string) (*CIDRs, error) {
	v4, err := f.fetchList(ctx, fmt.Sprintf("%s/%s/%s_ips_v4.txt", f.dataSource, provider, provider))
	if err != nil {
		return nil, fmt.Errorf("v4 list: %w", err)
	}
	v6, err := f.fetchList(ctx, fmt.Sprintf("%s/%s/%s_ips_v6.txt", f.dataSource, provider, provider))
	if err != nil {
		return nil, fmt.Errorf("v6 list: %w", err)
	}
	if len(v4) == 0 && len(v6) == 0 {
		return nil, fmt.Errorf("provider %q returned no CIDRs", provider)
	}
	return &CIDRs{Provider: provider, V4: v4, V6: v6, Hash: hash(provider, v4, v6)}, nil
}

func (f *Fetcher) fetchList(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// missing v6 file ok
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s for %s", resp.Status, url)
	}
	var out []string
	skipped := 0
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// reject bad CIDRs vs junk in rules
		if _, err := netip.ParsePrefix(line); err != nil {
			skipped++
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// fail closed: partial list -> bad rules; keep last-good
	if skipped > 0 {
		if !f.allowMalformed {
			return nil, fmt.Errorf("%s: %d malformed CIDR line(s); refusing partial data "+
				"(set allow_malformed_provider_data:true to skip them)", url, skipped)
		}
		log.Printf("fetcher: skipped %d malformed CIDR line(s) from %s", skipped, url)
	}
	slices.Sort(out)
	return out, nil
}

func hash(provider string, v4, v6 []string) string {
	h := sha256.New()
	fmt.Fprintln(h, provider)
	for _, c := range v4 {
		fmt.Fprintln(h, c)
	}
	fmt.Fprintln(h, "--")
	for _, c := range v6 {
		fmt.Fprintln(h, c)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
