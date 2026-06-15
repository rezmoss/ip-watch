package engine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/rezmoss/ip-watch/internal/transport"
)

// memTransport: in-mem for fail-injection; file ops hit map
type memTransport struct{ files map[string][]byte }

func newMem() *memTransport { return &memTransport{files: map[string][]byte{}} }

func (m *memTransport) Name() string { return "mem" }
func (m *memTransport) ReadFile(p string) ([]byte, error) {
	b, ok := m.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}
func (m *memTransport) WriteFile(p string, data []byte, _ os.FileMode) error {
	m.files[p] = append([]byte(nil), data...)
	return nil
}
func (m *memTransport) MkdirAll(string, os.FileMode) error { return nil }
func (m *memTransport) Remove(p string) error              { delete(m.files, p); return nil }
func (m *memTransport) Exists(p string) bool               { _, ok := m.files[p]; return ok }
func (m *memTransport) LookPath(n string) (string, error)  { return n, nil }
func (m *memTransport) Run(context.Context, string, ...string) (transport.Result, error) {
	return transport.Result{}, nil
}

func okValidate(context.Context, transport.Transport, string) (string, bool, error) {
	return "ok", true, nil
}

func TestApplyConfigRollsBackOnValidateFailure(t *testing.T) {
	tr := newMem()
	const orig = "server {\n}\n"
	tr.files["/etc/x.conf"] = []byte(orig)

	plan := configPlan{
		bin: "x", managedPath: "/etc/ip-watch/t.conf", managedData: []byte("rules\n"),
		confFile: "/etc/x.conf", reference: "include /etc/ip-watch/t.conf;",
		inject: func(conf []byte, _, ref, _ string) ([]byte, error) {
			return append(append([]byte(nil), conf...), []byte("\n"+ref)...), nil
		},
		validate: func(context.Context, transport.Transport, string) (string, bool, error) {
			return "syntax error", false, nil // injected fail
		},
		reload: func(context.Context, transport.Transport, string) (string, error) { return "", nil },
	}
	out := applyConfig(context.Background(), tr, Input{}, plan)
	if out.OK {
		t.Fatal("apply should fail when validate fails")
	}
	if string(tr.files["/etc/x.conf"]) != orig {
		t.Fatalf("config not byte-restored:\n%q", tr.files["/etc/x.conf"])
	}
	if _, ok := tr.files["/etc/ip-watch/t.conf"]; ok {
		t.Fatal("new managed file should be removed on rollback")
	}
}

func TestRemoveConfigRestoresOnReloadFailure(t *testing.T) {
	tr := newMem()
	const applied = "server {\n# >>> ip-watch:/m >>>\ninclude /m;\n# <<< ip-watch:/m <<<\n}\n"
	tr.files["/etc/x.conf"] = []byte(applied)
	tr.files["/m"] = []byte("rules\n")

	plan := configPlan{
		bin: "x", managedPath: "/m", confFile: "/etc/x.conf",
		validate: okValidate,
		reload: func(context.Context, transport.Transport, string) (string, error) {
			return "", errors.New("reload boom") // injected fail
		},
	}
	out := removeConfig(context.Background(), tr, plan)
	if out.OK {
		t.Fatal("remove should report failure when reload fails")
	}
	if !bytes.Contains(tr.files["/etc/x.conf"], []byte("include /m;")) {
		t.Fatalf("config not restored to applied state:\n%q", tr.files["/etc/x.conf"])
	}
	if _, ok := tr.files["/m"]; !ok {
		t.Fatal("managed file must not be deleted when reload fails (target stays manageable)")
	}
}

func TestRemoveConfigDeletesManagedOnSuccess(t *testing.T) {
	tr := newMem()
	tr.files["/etc/x.conf"] = []byte("server {\n# >>> ip-watch:/m >>>\ninclude /m;\n# <<< ip-watch:/m <<<\n}\n")
	tr.files["/m"] = []byte("rules\n")
	plan := configPlan{bin: "x", managedPath: "/m", confFile: "/etc/x.conf", validate: okValidate,
		reload: func(context.Context, transport.Transport, string) (string, error) { return "", nil }}
	out := removeConfig(context.Background(), tr, plan)
	if !out.OK {
		t.Fatalf("remove should succeed: %s", out.Message)
	}
	if _, ok := tr.files["/m"]; ok {
		t.Fatal("managed file should be deleted after successful reload")
	}
	if bytes.Contains(tr.files["/etc/x.conf"], []byte("include /m;")) {
		t.Fatal("include should be stripped")
	}
}

func TestNftablesAllowFailsClosedForEmptyFamily(t *testing.T) {
	// v4-only: v6 dropped (fail closed), not left open
	in := testInput("nftables", "allow")
	in.CIDRs.V6 = nil
	out := renderNftables(in)
	if !strings.Contains(out, "meta nfproto ipv6 ct state new drop") {
		t.Fatalf("v6 not failed closed in allow mode:\n%s", out)
	}
	if !strings.Contains(out, "ip saddr != @allowed_v4 drop") {
		t.Fatalf("v4 allow rule missing:\n%s", out)
	}
	// deny, no v6: emits nothing for v6
	deny := testInput("nftables", "deny")
	deny.CIDRs.V6 = nil
	if strings.Contains(renderNftables(deny), "nfproto ipv6") {
		t.Fatal("deny mode must not drop-all v6")
	}
}

func TestIPTablesAllowFailsClosedForEmptyFamily(t *testing.T) {
	in := testInput("iptables", "allow")
	in.CIDRs.V6 = nil
	out := renderIPTables(in)
	if !strings.Contains(out, "ip6tables -A IPWATCH_web1 -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j DROP") {
		t.Fatalf("v6 not failed closed (drop-all) in allow mode:\n%s", out)
	}
}
