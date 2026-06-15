package notify

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// dials test server, ignores req host; tests delivery w/ public hostname
func loopbackClient(addr string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
}

func TestPostDeliversPayload(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := loopbackClient(srv.Listener.Addr().String())
	err := post(context.Background(), client, "http://hooks.example.com/x", "hello", []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if got["text"] != "hello" {
		t.Fatalf("text = %v", got["text"])
	}
	if _, ok := got["results"]; !ok {
		t.Fatal("results missing")
	}
}

func TestPostEmptyWebhookNoop(t *testing.T) {
	if err := Post(context.Background(), "", "x", nil); err != nil {
		t.Fatalf("empty webhook should be a no-op, got %v", err)
	}
}

func TestPostNon2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	client := loopbackClient(srv.Listener.Addr().String())
	if err := post(context.Background(), client, "http://hooks.example.com/x", "x", nil); err == nil {
		t.Fatal("expected error on 500")
	}
}

// Post must refuse loopback: literal-IP + "localhost"
func TestPostBlocksLoopbackHostname(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	for _, u := range []string{srv.URL, "http://localhost/hook"} {
		if err := Post(context.Background(), u, "x", nil); err == nil {
			t.Errorf("Post(%q) should be blocked as loopback", u)
		}
	}
}

// must reject loopback/link-local resolved addrs (SSRF backstop)
func TestGuardedDialControlBlocksResolvedIPs(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:80", "169.254.169.254:80", "[::1]:443", "0.0.0.0:80"} {
		if err := guardedDialControl("tcp", addr, nil); err == nil {
			t.Errorf("guardedDialControl(%q) should be blocked", addr)
		}
	}
	for _, addr := range []string{"10.0.0.5:80", "93.184.216.34:443"} {
		if err := guardedDialControl("tcp", addr, nil); err != nil {
			t.Errorf("guardedDialControl(%q) should be allowed: %v", addr, err)
		}
	}
}

func TestValidateWebhook(t *testing.T) {
	ok := []string{"https://hooks.slack.com/services/x", "http://intranet.local/hook", "http://10.0.0.5/hook"}
	for _, u := range ok {
		if err := ValidateWebhook(u); err != nil {
			t.Errorf("ValidateWebhook(%q) should pass: %v", u, err)
		}
	}
	bad := []string{
		"ftp://example.com",             // scheme
		"file:///etc/passwd",            // scheme
		"http://127.0.0.1/x",            // loopback
		"http://[::1]/x",                // loopback v6
		"http://169.254.169.254/latest", // link-local
		"http://0.0.0.0/x",              // unspecified
		"notaurl",                       // no host
	}
	for _, u := range bad {
		if err := ValidateWebhook(u); err == nil {
			t.Errorf("ValidateWebhook(%q) should be rejected", u)
		}
	}
}
