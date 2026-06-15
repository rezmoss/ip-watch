package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

const sampleSummary = `{"provider_count":2,"providers":{
	"aws":{"ipv4_cidrs":10,"total_cidrs":12},
	"gcp":{"ipv4_cidrs":5,"total_cidrs":5}}}`

// caches in TTL (1 hit/2 calls); last-good on fail
func TestListCachesAndFallsBack(t *testing.T) {
	var hits atomic.Int32
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if fail.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(sampleSummary))
	}))
	defer srv.Close()

	c := New(srv.URL)

	got, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("first list: %v", err)
	}
	if len(got) != 2 || got[0].Name != "aws" {
		t.Fatalf("unexpected catalog: %+v", got)
	}

	// 2nd call in TTL: no extra hit
	if _, err := c.List(context.Background()); err != nil {
		t.Fatalf("cached list: %v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("upstream hits = %d, want 1 (second call cached)", n)
	}

	// failing refresh: last-good
	c.cachedAt = c.cachedAt.Add(-2 * cacheTTL)
	fail.Store(true)
	fb, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("fallback list should not error: %v", err)
	}
	if len(fb) != 2 {
		t.Errorf("fallback catalog = %d entries, want 2 (last good served)", len(fb))
	}
}

// no cache + fail -> error
func TestListErrorsWithoutCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := New(srv.URL).List(context.Background()); err == nil {
		t.Fatal("expected error when upstream fails and nothing is cached")
	}
}
