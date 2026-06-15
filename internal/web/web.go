// Package web serves embedded SPA UI + JSON API.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rezmoss/ip-watch/internal/applier"
	"github.com/rezmoss/ip-watch/internal/config"
	"github.com/rezmoss/ip-watch/internal/docker"
	"github.com/rezmoss/ip-watch/internal/engine"
	"github.com/rezmoss/ip-watch/internal/history"
	"github.com/rezmoss/ip-watch/internal/notify"
	"github.com/rezmoss/ip-watch/internal/provider"
)

//go:embed static
var staticFS embed.FS

// Server: UI/API + cfg changes & manual applies.
type Server struct {
	cfg        *config.Config
	cfgPath    string
	version    string
	authUser   string
	authPass   string
	catalog    *provider.Catalog
	mu         sync.Mutex
	lastResult []applier.Result
}

// New: creds from env first, else cfg.
func New(cfg *config.Config, cfgPath, version string) *Server {
	user := firstNonEmpty(os.Getenv("IPWATCH_AUTH_USERNAME"), cfg.Auth.Username)
	pass := firstNonEmpty(os.Getenv("IPWATCH_AUTH_PASSWORD"), cfg.Auth.Password)
	return &Server{
		cfg:      cfg,
		cfgPath:  cfgPath,
		version:  version,
		authUser: user,
		authPass: pass,
		catalog:  provider.New(cfg.DataSource),
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	mux.HandleFunc("GET /api/providers", s.handleProviders)
	mux.HandleFunc("GET /api/config", s.handleGetConfig)
	mux.HandleFunc("PUT /api/targets", s.handlePutTarget)
	mux.HandleFunc("DELETE /api/targets/{id}", s.handleDeleteTarget)
	mux.HandleFunc("POST /api/targets/{id}/uninstall", s.handleUninstall)
	mux.HandleFunc("POST /api/apply", s.handleApply)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/docker/containers", s.handleDockerContainers)
	mux.HandleFunc("PUT /api/settings", s.handlePutSettings)
	mux.HandleFunc("POST /api/notify/test", s.handleNotifyTest)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/history", s.handleHistory)
	return s.withAuth(s.withSameOrigin(mux))
}

// withSameOrigin: block cross-origin writes (CSRF); no Origin passes.
func (s *Server) withSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				http.Error(w, "cross-origin request blocked", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isLoopbackAddr: addr binds loopback only.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch host {
	case "", "0.0.0.0", "::":
		return false
	case "localhost":
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsLoopback()
	}
	return false
}

// withAuth: Basic auth all routes but /healthz, if creds set.
func (s *Server) withAuth(next http.Handler) http.Handler {
	if s.authUser == "" || s.authPass == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(s.authUser)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(s.authPass)) == 1
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="ip-watch"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	store, err := history.Load(s.cfg.StateDir)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	// newest first
	recent := slices.Clone(store.Recent)
	slices.Reverse(recent)
	writeJSON(w, map[string]any{"recent": recent, "counters": store.Counters})
}

// handleMetrics: Prometheus metrics from history.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	store, err := history.Load(s.cfg.StateDir)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(RenderMetrics(store, s.version)))
}

// RenderMetrics: Prometheus text; shared by /metrics & CLI.
func RenderMetrics(store *history.Store, version string) string {
	var b strings.Builder
	b.WriteString("# HELP ipwatch_up 1 if ip-watch is running\n# TYPE ipwatch_up gauge\nipwatch_up 1\n")
	fmt.Fprintf(&b, "# HELP ipwatch_build_info Build info\n# TYPE ipwatch_build_info gauge\nipwatch_build_info{version=%q} 1\n", version)

	b.WriteString("# HELP ipwatch_target_applies_total Apply attempts per target\n# TYPE ipwatch_target_applies_total counter\n")
	for _, id := range sortedKeys(store.Counters) {
		fmt.Fprintf(&b, "ipwatch_target_applies_total{target=%q} %d\n", id, store.Counters[id].Applies)
	}
	b.WriteString("# HELP ipwatch_target_changes_total Applies that changed config per target\n# TYPE ipwatch_target_changes_total counter\n")
	for _, id := range sortedKeys(store.Counters) {
		fmt.Fprintf(&b, "ipwatch_target_changes_total{target=%q} %d\n", id, store.Counters[id].Changes)
	}
	b.WriteString("# HELP ipwatch_target_failures_total Failed applies per target\n# TYPE ipwatch_target_failures_total counter\n")
	for _, id := range sortedKeys(store.Counters) {
		fmt.Fprintf(&b, "ipwatch_target_failures_total{target=%q} %d\n", id, store.Counters[id].Failures)
	}
	b.WriteString("# HELP ipwatch_target_ranges Ranges applied at last success per target\n# TYPE ipwatch_target_ranges gauge\n")
	for _, id := range sortedKeys(store.Counters) {
		fmt.Fprintf(&b, "ipwatch_target_ranges{target=%q} %d\n", id, store.Counters[id].Ranges)
	}
	b.WriteString("# HELP ipwatch_target_last_success_timestamp_seconds Unix time of last successful apply\n# TYPE ipwatch_target_last_success_timestamp_seconds gauge\n")
	for _, id := range sortedKeys(store.Counters) {
		ts := int64(0)
		if t := store.Counters[id].LastSuccess; !t.IsZero() {
			ts = t.Unix()
		}
		fmt.Fprintf(&b, "ipwatch_target_last_success_timestamp_seconds{target=%q} %d\n", id, ts)
	}
	return b.String()
}

func sortedKeys(m map[string]history.Counter) []string {
	return slices.Sorted(maps.Keys(m))
}

// handleHealthz: liveness probe, unauthed so it works w/o creds.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	var targets int
	_ = applier.Guard(func() error { targets = len(s.cfg.Targets); return nil })
	writeJSON(w, map[string]any{
		"status":  "ok",
		"version": s.version,
		"targets": targets,
	})
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Notify config.NotifyOpts `json:"notify"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if in.Notify.Webhook != "" {
		if err := notify.ValidateWebhook(in.Notify.Webhook); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	err := applier.GuardConfig(s.cfg.StateDir, s.cfg.LockUnsafe, func() error {
		s.cfg.Notify = in.Notify
		return s.cfg.Save(s.cfgPath)
	})
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, in.Notify)
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	var webhook string
	_ = applier.Guard(func() error { webhook = s.cfg.Notify.Webhook; return nil })
	if webhook == "" {
		http.Error(w, "no webhook configured", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := notify.Post(ctx, webhook, "ip-watch test notification ✅", nil); err != nil {
		httpErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, map[string]string{"status": "sent"})
}

// UI picker container list; socket fixed (no user-chosen sockets)
func (s *Server) handleDockerContainers(w http.ResponseWriter, r *http.Request) {
	candidates, err := docker.Discover(r.Context(), "")
	if err != nil {
		httpErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, candidates)
}

func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	list, err := s.catalog.List(r.Context())
	if err != nil {
		httpErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, list)
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	var redacted config.Config
	_ = applier.Guard(func() error { redacted = *s.cfg; return nil })
	// never expose stored pass
	redacted.Auth.Password = ""
	writeJSON(w, &redacted)
}

func (s *Server) handlePutTarget(w http.ResponseWriter, r *http.Request) {
	var t config.Target
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if t.Engine == "" {
		t.Engine = "nginx"
	}
	if t.Transport == "" {
		t.Transport = "local"
	}
	if t.Mode == "" {
		t.Mode = "allow"
	}
	if err := t.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := engine.For(t.Engine); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if t.Transport == "docker" && t.Docker.Container == "" {
		http.Error(w, "docker transport requires docker.container", http.StatusBadRequest)
		return
	}
	err := applier.GuardConfig(s.cfg.StateDir, s.cfg.LockUnsafe, func() error {
		s.cfg.UpsertTarget(t)
		return s.cfg.Save(s.cfgPath)
	})
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, t)
}

// lookupTarget: target by id under apply gate.
func (s *Server) lookupTarget(id string) (config.Target, bool) {
	var t config.Target
	var ok bool
	_ = applier.Guard(func() error { t, ok = s.cfg.Target(id); return nil })
	return t, ok
}

// configValid: cfg validation err under gate; enforcement refuses if non-nil.
func (s *Server) configValid() error {
	return applier.Guard(func() error { return s.cfg.Validate() })
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	target, found := s.lookupTarget(id)
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// uninstall rules first; on fail keep target. ?keep=1 skips.
	var uninstall *applier.Result
	if r.URL.Query().Get("keep") != "1" {
		// live action; refuse on invalid cfg (?keep=1 stays for repair)
		if err := s.configValid(); err != nil {
			http.Error(w, "config invalid; refusing to uninstall rules for "+id+
				" — fix config, or delete w/ ?keep=1 to leave rules: "+err.Error(),
				http.StatusConflict)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		res := applier.New(s.cfg, false).Remove(ctx, target)
		uninstall = &res
		if !res.OK {
			w.WriteHeader(http.StatusConflict)
			writeJSON(w, map[string]any{
				"error":     "uninstall failed; target kept (use ?keep=1 to force-delete)",
				"uninstall": res,
			})
			return
		}
	}

	err := applier.GuardConfig(s.cfg.StateDir, s.cfg.LockUnsafe, func() error {
		s.cfg.RemoveTarget(id)
		return s.cfg.Save(s.cfgPath)
	})
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"deleted": id, "uninstall": uninstall})
}

// handleUninstall: drop applied rules, keep cfg entry.
func (s *Server) handleUninstall(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	target, found := s.lookupTarget(id)
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := s.configValid(); err != nil {
		http.Error(w, "config invalid; repair it before uninstalling: "+err.Error(), http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	writeJSON(w, applier.New(s.cfg, false).Remove(ctx, target))
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	if err := s.configValid(); err != nil {
		http.Error(w, "config invalid; repair it before applying: "+err.Error(), http.StatusConflict)
		return
	}
	dry := r.URL.Query().Get("dry") == "1"
	s.mu.Lock()
	app := applier.New(s.cfg, dry)
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	// UI apply always forces
	results := app.ApplyAll(ctx, true)

	if !dry {
		s.mu.Lock()
		s.lastResult = results
		s.mu.Unlock()
	}
	writeJSON(w, results)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, s.lastResult)
}

// ListenAndServe: serve, block until ctx cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	authEnabled := s.authUser != "" && s.authPass != ""
	if !isLoopbackAddr(s.cfg.Listen) && !authEnabled && !s.cfg.Insecure {
		return fmt.Errorf("refusing to bind non-loopback %q without auth: "+
			"set auth.username/password (or IPWATCH_AUTH_* env), bind 127.0.0.1, or set insecure:true",
			s.cfg.Listen)
	}
	if !isLoopbackAddr(s.cfg.Listen) && !authEnabled {
		log.Printf("web: WARNING serving on %s with no authentication (insecure mode)", s.cfg.Listen)
	}

	srv := &http.Server{Addr: s.cfg.Listen, Handler: s.Handler()}
	stop := context.AfterFunc(ctx, func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	})
	defer stop()
	log.Printf("web: listening on %s", s.cfg.Listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, err error) {
	http.Error(w, err.Error(), code)
}
