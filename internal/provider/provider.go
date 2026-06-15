// Package provider: IP-provider catalog from summary.json.
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// Info: one provider's entry.
type Info struct {
	Name       string `json:"name"`
	IPv4CIDRs  int    `json:"ipv4_cidrs"`
	IPv6CIDRs  int    `json:"ipv6_cidrs"`
	TotalCIDRs int    `json:"total_cidrs"`
	Services   int    `json:"services"`
	Regions    int    `json:"regions"`
}

// Summary: upstream summary.json shape.
type Summary struct {
	Generated     string          `json:"generated"`
	ProviderCount int             `json:"provider_count"`
	Providers     map[string]Info `json:"providers"`
}

const cacheTTL = 10 * time.Minute

// Catalog: caches list per TTL; serves last-good on fail.
type Catalog struct {
	dataSource string
	client     *http.Client

	mu       sync.Mutex
	cached   []Info
	cachedAt time.Time
}

// New: Catalog for data source base URL.
func New(dataSource string) *Catalog {
	return &Catalog{
		dataSource: dataSource,
		client:     &http.Client{Timeout: 20 * time.Second},
	}
}

// List: sorted providers; cache/refresh/last-good.
func (c *Catalog) List(ctx context.Context) ([]Info, error) {
	c.mu.Lock()
	if c.cached != nil && time.Since(c.cachedAt) < cacheTTL {
		out := c.cached
		c.mu.Unlock()
		return out, nil
	}
	c.mu.Unlock()

	fresh, err := c.fetch(ctx)
	if err != nil {
		// upstream down: last-good
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.cached != nil {
			return c.cached, nil
		}
		return nil, err
	}

	c.mu.Lock()
	c.cached = fresh
	c.cachedAt = time.Now()
	c.mu.Unlock()
	return fresh, nil
}

// fetch: pull+parse summary.json.
func (c *Catalog) fetch(ctx context.Context) ([]Info, error) {
	url := c.dataSource + "/summary.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching summary.json: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("summary.json: unexpected status %s", resp.Status)
	}
	var s Summary
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, fmt.Errorf("decoding summary.json: %w", err)
	}
	out := make([]Info, 0, len(s.Providers))
	for name, info := range s.Providers {
		info.Name = name
		out = append(out, info)
	}
	slices.SortFunc(out, func(a, b Info) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
