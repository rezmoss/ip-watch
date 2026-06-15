package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
)

// Validate: cfg invariants + per-target Validate.
func (c *Config) Validate() error {
	if c.UpdateHour < 0 || c.UpdateHour > 23 {
		return fmt.Errorf("update_hour must be 0-23, got %d", c.UpdateHour)
	}
	if c.DataSource != "" {
		u, err := url.Parse(c.DataSource)
		if err != nil {
			return fmt.Errorf("data_source is not a valid URL: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("data_source must be an http(s) URL, got %q", c.DataSource)
		}
	}
	seen := map[string]bool{}
	for _, t := range c.Targets {
		if seen[t.ID] {
			return fmt.Errorf("duplicate target id %q", t.ID)
		}
		seen[t.ID] = true
		// unwrapped: Validate already prefixes id
		if err := t.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// mgmt ports that lock you out if allowed w/o override
var adminPorts = map[int]string{
	22: "SSH", 2222: "SSH", 3389: "RDP", 5900: "VNC",
	3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
	1433: "MSSQL", 9200: "Elasticsearch", 11211: "memcached",
}

// IDs -> paths/fw names/tags: safe charset; providers -> URL slugs.
var (
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$`)
	providerPattern = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
)

// Validate checks target user fields; engine/transport via registries.
func (t Target) Validate() error {
	if !idPattern.MatchString(t.ID) {
		return fmt.Errorf("invalid target id %q (letters, digits, _ or -, must start alphanumeric/_, max 63 chars)", t.ID)
	}
	if t.Mode != "allow" && t.Mode != "deny" {
		return fmt.Errorf("target %q: invalid mode %q (must be \"allow\" or \"deny\")", t.ID, t.Mode)
	}
	providers := t.EffectiveProviders()
	if len(providers) == 0 {
		return fmt.Errorf("target %q: at least one provider is required", t.ID)
	}
	for _, p := range providers {
		if !providerPattern.MatchString(p) {
			return fmt.Errorf("target %q: invalid provider name %q (lowercase letters, digits, _)", t.ID, p)
		}
	}
	if len(t.Firewall.Ports) > 64 {
		return fmt.Errorf("target %q: too many ports (max 64)", t.ID)
	}
	for _, port := range t.Firewall.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("target %q: invalid port %d (must be 1-65535)", t.ID, port)
		}
		if t.Mode != "allow" || t.Firewall.AllowAdminPorts {
			continue
		}
		if name, isAdmin := adminPorts[port]; isAdmin {
			return fmt.Errorf("target %q: port %d (%s) is a management port; "+
				"set firewall.allow_admin_ports=true to police it in allow mode", t.ID, port, name)
		}
	}
	for _, cidr := range t.AdminAllowIPs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("target %q: invalid admin_allow_ips entry %q (use CIDR like 203.0.113.5/32)", t.ID, cidr)
		}
	}
	return nil
}
