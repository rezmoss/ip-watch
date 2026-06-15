package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rezmoss/ip-watch/internal/config"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.StateDir = dir
	srv := New(cfg, filepath.Join(dir, "config.json"), "testver")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestHealthz(t *testing.T) {
	ts := testServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" || body["version"] != "testver" {
		t.Fatalf("healthz body = %v", body)
	}
}

func TestTargetCRUD(t *testing.T) {
	ts := testServer(t)

	// PUT target
	body := `{"id":"web1","providers":["cloudflare"],"engine":"nginx"}`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/targets", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("put status %d: %s", resp.StatusCode, msg)
	}
	resp.Body.Close()

	// GET cfg w/ dflts (mode, transport)
	cfgResp, _ := http.Get(ts.URL + "/api/config")
	var cfg config.Config
	json.NewDecoder(cfgResp.Body).Decode(&cfg)
	cfgResp.Body.Close()
	if len(cfg.Targets) != 1 || cfg.Targets[0].Mode != "allow" || cfg.Targets[0].Transport != "local" {
		t.Fatalf("target defaults wrong: %+v", cfg.Targets)
	}

	// DELETE (keep=1 skips uninstall)
	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/targets/web1?keep=1", nil)
	delResp, _ := http.DefaultClient.Do(delReq)
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status %d", delResp.StatusCode)
	}
}

// an invalid config (repair mode) must block live apply, like the CLI does
func TestRepairModeBlocksApply(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.StateDir = dir
	cfg.UpdateHour = 99 // out of range -> Validate fails
	srv := New(cfg, filepath.Join(dir, "config.json"), "testver")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/api/apply", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("apply on invalid config should be 409, got %d", resp.StatusCode)
	}
}

func TestPutTargetValidation(t *testing.T) {
	ts := testServer(t)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/targets", strings.NewReader(`{"id":"x"}`))
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing provider should be 400, got %d", resp.StatusCode)
	}
}

func TestMetricsAndHistory(t *testing.T) {
	ts := testServer(t)
	resp, _ := http.Get(ts.URL + "/metrics")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "ipwatch_up 1") || !strings.Contains(string(body), `ipwatch_build_info{version="testver"}`) {
		t.Fatalf("metrics missing core series:\n%s", body)
	}

	hResp, _ := http.Get(ts.URL + "/api/history")
	var h map[string]any
	json.NewDecoder(hResp.Body).Decode(&h)
	hResp.Body.Close()
	if _, ok := h["recent"]; !ok {
		t.Fatal("history missing recent key")
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080": true, "localhost:8080": true, "[::1]:8080": true,
		":8080": false, "0.0.0.0:8080": false, "192.168.1.10:8080": false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestSameOriginGuard(t *testing.T) {
	ts := testServer(t)
	body := `{"id":"web1","providers":["cloudflare"],"engine":"nginx"}`

	// cross-origin write blocked
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/targets", strings.NewReader(body))
	req.Header.Set("Origin", "http://evil.example.com")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin PUT should be 403, got %d", resp.StatusCode)
	}

	// same-origin write ok
	req2, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/targets", strings.NewReader(body))
	req2.Header.Set("Origin", ts.URL)
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("same-origin PUT should be 200, got %d", resp2.StatusCode)
	}
}

func TestSettings(t *testing.T) {
	ts := testServer(t)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/settings", strings.NewReader(`{"notify":{"webhook":"http://x","always":true}}`))
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("settings status %d", resp.StatusCode)
	}
	cfgResp, _ := http.Get(ts.URL + "/api/config")
	var cfg config.Config
	json.NewDecoder(cfgResp.Body).Decode(&cfg)
	cfgResp.Body.Close()
	if cfg.Notify.Webhook != "http://x" || !cfg.Notify.Always {
		t.Fatalf("notify not saved: %+v", cfg.Notify)
	}
}
