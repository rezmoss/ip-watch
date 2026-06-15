package fetcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubSource: serves CIDR files like data repo
func stubSource(t *testing.T, files map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range files {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchSingle(t *testing.T) {
	srv := stubSource(t, map[string]string{
		"/cloudflare/cloudflare_ips_v4.txt": "1.1.1.0/24\n2.2.2.0/24\n",
		"/cloudflare/cloudflare_ips_v6.txt": "2606:4700::/32\n",
	})
	c, err := New(srv.URL).Fetch(context.Background(), "cloudflare")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.V4) != 2 || len(c.V6) != 1 || c.Provider != "cloudflare" {
		t.Fatalf("unexpected result: %+v", c)
	}
}

func TestFetchMergedDedup(t *testing.T) {
	srv := stubSource(t, map[string]string{
		"/a/a_ips_v4.txt": "1.1.1.0/24\n9.9.9.0/24\n",
		"/a/a_ips_v6.txt": "2001:db8::/32\n",
		"/b/b_ips_v4.txt": "9.9.9.0/24\n3.3.3.0/24\n", // dup v4
		"/b/b_ips_v6.txt": "2001:db8::/32\n",          // dup v6
	})
	c, err := New(srv.URL).FetchMerged(context.Background(), []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.V4) != 3 {
		t.Fatalf("expected 3 deduped v4, got %d: %v", len(c.V4), c.V4)
	}
	if len(c.V6) != 1 {
		t.Fatalf("expected 1 deduped v6, got %d", len(c.V6))
	}
	if c.Provider != "a+b" {
		t.Fatalf("merged label = %q", c.Provider)
	}
	if !(c.V4[0] < c.V4[1] && c.V4[1] < c.V4[2]) {
		t.Fatalf("v4 not sorted: %v", c.V4)
	}
}

func TestFetchMissingV6IsOK(t *testing.T) {
	srv := stubSource(t, map[string]string{
		"/x/x_ips_v4.txt": "5.5.5.0/24\n# a comment\n\n",
	})
	c, err := New(srv.URL).Fetch(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.V4) != 1 || len(c.V6) != 0 {
		t.Fatalf("comment/blank filtering or v6-404 handling wrong: %+v", c)
	}
}

func TestFetchMalformedFailsClosedByDefault(t *testing.T) {
	srv := stubSource(t, map[string]string{
		"/x/x_ips_v4.txt": "5.5.5.0/24\nnot-a-cidr\n6.6.6.0/24\n",
	})
	_, err := New(srv.URL).Fetch(context.Background(), "x")
	if err == nil {
		t.Fatal("malformed upstream data should fail closed by default")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("error should mention malformed data: %v", err)
	}
}

func TestFetchMalformedSkippedWhenAllowed(t *testing.T) {
	srv := stubSource(t, map[string]string{
		"/x/x_ips_v4.txt": "5.5.5.0/24\nnot-a-cidr\n6.6.6.0/24\n",
	})
	c, err := New(srv.URL).AllowMalformed(true).Fetch(context.Background(), "x")
	if err != nil {
		t.Fatalf("AllowMalformed should skip bad lines: %v", err)
	}
	if len(c.V4) != 2 {
		t.Fatalf("expected 2 good v4 ranges, got %v", c.V4)
	}
}

func TestWithExtraMergesAndRehashes(t *testing.T) {
	base := &CIDRs{Provider: "cloudflare", V4: []string{"1.1.1.0/24"}, V6: []string{"2606:4700::/32"}, Hash: "h"}
	out := base.WithExtra([]string{"203.0.113.5/32", "2001:db8::/48", "garbage", "1.1.1.0/24"})
	if len(out.V4) != 2 { // deduped + new
		t.Fatalf("v4 = %v", out.V4)
	}
	if len(out.V6) != 2 {
		t.Fatalf("v6 = %v", out.V6)
	}
	if out.Hash == base.Hash {
		t.Fatal("hash should change when extra IPs are added")
	}
	if out.Provider != "cloudflare" {
		t.Fatalf("provider label changed: %q", out.Provider)
	}
}

func TestFetchHashChangesWithContent(t *testing.T) {
	a := &CIDRs{V4: []string{"1.1.1.0/24"}}
	h1 := hash("p", a.V4, nil)
	h2 := hash("p", []string{"1.1.1.0/24", "2.2.2.0/24"}, nil)
	if h1 == h2 || !strings.ContainsAny(h1, "0123456789abcdef") {
		t.Fatal("hash should differ with content and be hex")
	}
}
