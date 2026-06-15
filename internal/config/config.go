// Package config: on-disk cfg + targets for apply.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// DefaultDataSource: raw base URL of provider IP data.
const DefaultDataSource = "https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main"

type Config struct {
	DataSource string `json:"data_source"`
	Listen     string `json:"listen"` // bind addr; loopback by dflt
	// non-loopback bind w/o auth; dflt off (no unauth root API)
	Insecure   bool   `json:"insecure,omitempty"`
	UpdateHour int    `json:"update_hour"` // local hour 0-23 for daily update
	StateDir   string `json:"state_dir"`
	// skip bad CIDR lines; dflt off = abort, keep last-good
	AllowMalformedProviderData bool `json:"allow_malformed_provider_data,omitempty"`
	// disable fail-closed lock; dflt off. true = best-effort
	LockUnsafe bool       `json:"lock_unsafe,omitempty"`
	Notify     NotifyOpts `json:"notify,omitempty"`
	Auth       AuthOpts   `json:"auth,omitempty"`
	Targets    []Target   `json:"targets"`
}

// AuthOpts: basic auth; may come from env to keep secrets out of file.
type AuthOpts struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type NotifyOpts struct {
	Webhook string `json:"webhook,omitempty"` // JSON POST; Slack/Mattermost/generic
	Always  bool   `json:"always,omitempty"`  // post even on no change
}

// Target: one (provider,mode,engine) on one enforcement point.
type Target struct {
	ID        string       `json:"id"`
	Provider  string       `json:"provider,omitempty"`  // single (legacy)
	Providers []string     `json:"providers,omitempty"` // merge ranges
	Mode      string       `json:"mode"`                // allow | deny
	Engine    string       `json:"engine"`              // nginx|caddy|apache|haproxy|nftables
	Transport string       `json:"transport"`           // local | docker
	Enabled   bool         `json:"enabled"`
	Config    ConfigOpts   `json:"config,omitempty"`
	Docker    DockerOpts   `json:"docker,omitempty"`
	Firewall  FirewallOpts `json:"firewall,omitempty"`
	// always-allow CIDRs in allow mode (anti-lockout)
	AdminAllowIPs []string `json:"admin_allow_ips,omitempty"`
}

// ConfigOpts: placement for config-file engines.
type ConfigOpts struct {
	File string `json:"file,omitempty"` // cfg file; empty = engine dflt
	// block to edit; empty = first
	Selector string `json:"selector,omitempty"`
	RealIP   bool   `json:"real_ip,omitempty"` // recover true client IP behind proxy
}

// DockerOpts: sibling ctr reached over Docker socket.
type DockerOpts struct {
	Container string `json:"container,omitempty"`
	Socket    string `json:"socket,omitempty"` // dflt docker.sock
}

type FirewallOpts struct {
	Ports []int `json:"ports,omitempty"` // TCP ports policed (dflt 80,443)
	// req to police mgmt port in allow mode — lockout guard
	AllowAdminPorts bool `json:"allow_admin_ports,omitempty"`
}

// EffectiveProviders: Providers, else legacy Provider.
func (t Target) EffectiveProviders() []string {
	if len(t.Providers) > 0 {
		return t.Providers
	}
	if t.Provider != "" {
		return []string{t.Provider}
	}
	return nil
}

func Default() *Config {
	return &Config{
		DataSource: DefaultDataSource,
		Listen:     "127.0.0.1:8080",
		UpdateHour: 3,
		StateDir:   "/var/lib/ip-watch",
		Targets:    []Target{},
	}
}

// Load reads cfg w/ dflts; if absent, writes dflt & returns it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		c := Default()
		if werr := c.Save(path); werr != nil {
			return nil, fmt.Errorf("writing default config: %w", werr)
		}
		c.applyEnv()
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	c := Default()
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	c.applyDefaults()
	c.applyEnv()
	return c, nil
}

// applyEnv overrides deploy settings w/o editing file.
func (c *Config) applyEnv() {
	if v := os.Getenv("IPWATCH_LISTEN"); v != "" {
		c.Listen = v
	}
	if os.Getenv("IPWATCH_INSECURE") == "1" {
		c.Insecure = true
	}
}

func (c *Config) applyDefaults() {
	d := Default()
	if c.DataSource == "" {
		c.DataSource = d.DataSource
	}
	if c.Listen == "" {
		c.Listen = d.Listen
	}
	if c.StateDir == "" {
		c.StateDir = d.StateDir
	}
	if c.Targets == nil {
		c.Targets = []Target{}
	}
}

// Save writes cfg atomically as 0600 (may hold secrets).
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// WriteFileAtomic writes temp then renames; no partial reads.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ipwatch-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("setting permissions on temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	return os.Rename(tmpName, path)
}

func (c *Config) Target(id string) (Target, bool) {
	for _, t := range c.Targets {
		if t.ID == id {
			return t, true
		}
	}
	return Target{}, false
}

func (c *Config) UpsertTarget(t Target) {
	for i := range c.Targets {
		if c.Targets[i].ID == t.ID {
			c.Targets[i] = t
			return
		}
	}
	c.Targets = append(c.Targets, t)
}

// RemoveTarget reports if it existed.
func (c *Config) RemoveTarget(id string) bool {
	for i := range c.Targets {
		if c.Targets[i].ID == id {
			c.Targets = append(c.Targets[:i], c.Targets[i+1:]...)
			return true
		}
	}
	return false
}
