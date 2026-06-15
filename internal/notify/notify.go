// Package notify posts run summaries to a webhook.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// blockedDest: block loopback/link-local/unspecified; private OK
func blockedDest(ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// ValidateWebhook: reject non-http(s)/hostless/blocked; SSRF guard at dial-time
func ValidateWebhook(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("webhook scheme must be http or https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("webhook URL has no host")
	}
	// localhost bypasses literal-IP check
	if host == "localhost" {
		return fmt.Errorf("webhook host %q not allowed (loopback)", host)
	}
	if ip, err := netip.ParseAddr(host); err == nil && blockedDest(ip) {
		return fmt.Errorf("webhook host %s not allowed (loopback/link-local)", host)
	}
	return nil
}

// post-DNS guard: block loopback/link-local (DNS rebinding) + redirects
func guardedDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("webhook: bad dial address %q: %w", address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("webhook: unresolved dial address %q", address)
	}
	if blockedDest(ip) {
		return fmt.Errorf("webhook: refusing to connect to %s (loopback/link-local)", ip)
	}
	return nil
}

// dials non-blocked dests, rechecks each redirect
var safeClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, Control: guardedDialControl}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("webhook: too many redirects")
		}
		return ValidateWebhook(req.URL.String())
	},
}

// Post: send to webhook; no-op if empty.
func Post(ctx context.Context, webhook, text string, results any) error {
	return post(ctx, safeClient, webhook, text, results)
}

func post(ctx context.Context, client *http.Client, webhook, text string, results any) error {
	if webhook == "" {
		return nil
	}
	if err := ValidateWebhook(webhook); err != nil {
		return err
	}
	payload := map[string]any{"text": text, "results": results}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling webhook payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("posting webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}
