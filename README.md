<div align="center">

# ip-watch

**Keep cloud-provider IP ranges applied to your webserver and firewall, on a daily schedule with safe rollback.**

[![CI](https://github.com/rezmoss/ip-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/rezmoss/ip-watch/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/rezmoss/ip-watch?sort=semver)](https://github.com/rezmoss/ip-watch/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/rezmoss/ip-watch)](https://goreportcard.com/report/github.com/rezmoss/ip-watch)
[![Go version](https://img.shields.io/github/go-mod/go-version/rezmoss/ip-watch)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Fetch the latest IP ranges for **Cloudflare, AWS, Azure, Google Cloud** and [30+ more providers](#supported-providers),
wire **allow/deny** rules into **nginx, Caddy, Apache, HAProxy, nftables, iptables, or ufw**, validate the change
with the engine's own checker, reload, and **refresh every day**. One static **~7 MB** binary. No runtime dependencies.

</div>

```console
$ ip-watch add -id cf -provider cloudflare -engine nginx -selector example.com -apply
added target "cf" (allow, nginx, cloudflare)
[
  {
    "target_id": "cf",
    "provider": "cloudflare",
    "ok": true,
    "changed": true,
    "ranges": 22,
    "message": "applied 22 ranges; nginx -t passed; reloaded"
  }
]
```

> **Scenario:** you run nginx behind Cloudflare and want only Cloudflare to reach it.
> Pick `cloudflare` → `allow`. ip-watch detects nginx, wires the rules in, validates with `nginx -t`,
> reloads, and keeps the list fresh daily. If validation fails, ip-watch restores your config
> byte-for-byte and leaves the live service running.

<!-- To add a demo GIF later, record it with charmbracelet/vhs and drop it here:
     <p align="center"><img src="docs/demo.gif" alt="ip-watch applying Cloudflare ranges to nginx"></p> -->

---

## Contents

[Why](#why-ip-watch) ·
[Features](#features) ·
[Supported engines](#supported-engines) ·
[Providers](#supported-providers) ·
[Install](#install) ·
[Quick start](#quick-start) ·
[Recipes](#recipes) ·
[CLI](#command-line) ·
[Configuration](#configuration) ·
[How safe-apply works](#how-safe-apply-works) ·
[Operations](#operations) ·
[Security](#security--anti-lockout) ·
[Docker](#docker) ·
[Build](#build--test) ·
[FAQ](#faq)

---

## Why ip-watch

Cloud and CDN providers publish their IP ranges, and those lists change. Keeping a webserver or firewall
in sync is a chore you usually solve with a fragile cron job that `curl`s a list and rewrites a
config with no validation. One malformed line or a failed reload takes the site down.

ip-watch does the same job with guardrails:

- **It validates before it reloads.** Config engines run `nginx -t` / `caddy validate` / `apachectl -t` /
  `haproxy -c`; nftables loads atomically after a dry `nft -c`. A change that fails is rolled back, not shipped.
- **It is anti-lockout by design.** Firewall rules police only the ports you list (default 80/443), so SSH is
  never caught. Allow-mode whitelists refuse to start without an escape hatch, and you can pin your own IP.
- **It refreshes itself.** A built-in scheduler re-applies daily and skips targets whose ranges did not change.
- **It is one file.** A single static Go binary with an embedded web UI, a full CLI, `/healthz`, and Prometheus
  `/metrics`. No Python, no Node, no CDN at runtime.

It works whether your webserver runs **on the host** or **in a container** (it edits and reloads sibling
containers over the Docker socket, with no changes to the host).

## Features

| | |
|---|---|
| 🌐 **35 providers** | Cloudflare, AWS, Azure, GCP, Oracle, GitHub, Tor, AI crawlers, and [more](#supported-providers). Merge several into one rule set. |
| 🧩 **7 engines** | nginx, Caddy, Apache, HAProxy (config layer) plus nftables, iptables, ufw (firewall layer). |
| 🔁 **Allow or deny** | Whitelist a provider (only it may connect) or blocklist it (everyone but it). |
| 🛟 **Safe apply** | Validate with the engine's own checker, then reload. Roll back every touched file on failure. |
| ⏰ **Daily refresh** | Applies on start and daily at a configurable hour; skips targets whose ranges are unchanged. |
| 🐳 **Local + Docker** | Manage a host install or a sibling container over the daemon socket. Same engine, no host changes. |
| 🙈 **real-IP recovery** | Behind a proxy/CDN, recover the true client IP for logs and rate limits (all proxy engines). |
| 🔒 **Hardened by default** | Loopback bind, HTTP Basic auth, CSRF protection, refuses to expose an unauthenticated root API. |
| 📟 **CLI + Web UI** | A self-documenting CLI (stable JSON output) and an embedded Vue 3 + Tailwind UI. Use either. |
| 📈 **Observability** | `/healthz`, Prometheus `/metrics`, run history, and optional Slack/Mattermost/generic webhooks. |
| 📦 **Ships everywhere** | `.deb`, `.rpm`, `.apk`, tarball, `go install`, Docker image. 8 Linux architectures. |

## Supported engines

ip-watch enforces ranges at one of two layers. Pick whichever fits where your traffic is terminated.

| Engine | Layer | Validator before reload | Transactional | Rollback on failure | `real_ip` recovery |
|---|---|---|:--:|:--:|:--:|
| **nginx**    | Webserver       | `nginx -t`        | ✅ | ✅ every touched file | ✅ |
| **Caddy**    | Webserver       | `caddy validate`  | ✅ | ✅ every touched file | ✅ |
| **Apache**   | Webserver       | `apachectl -t`    | ✅ | ✅ every touched file | ✅ |
| **HAProxy**  | L4/L7 LB        | `haproxy -c`      | ✅ | ✅ every touched file | ✅ |
| **nftables** | Firewall        | `nft -c` (dry run)| ✅ atomic `nft -f` | n/a (all-or-nothing) | — |
| **iptables** | Firewall (ipset)| atomic set swap   | ⚠️ best-effort | re-run converges | — |
| **ufw**      | Firewall        | status precheck   | ⚠️ best-effort | re-run converges | — |

> **Safe-apply guarantees are not uniform.** The four **config engines** and **nftables** are
> transactional: a failed validation or reload restores the previous state and the live service keeps running
> a config that passes its own checker. **iptables/ufw** run idempotent scripts (re-running converges to the
> desired state) but have no atomic apply, so a mid-script failure can leave rules partially changed. Prefer
> **nftables** for large rule sets or strict atomicity.

The web UI (Vue 3 + Tailwind) and its libraries are **vendored and embedded** into the binary via `go:embed`.
No CDN, no Node build step, works offline.

## Supported providers

ip-watch pulls ranges from the open
[rezmoss/cloud-provider-ip-addresses](https://github.com/rezmoss/cloud-provider-ip-addresses) dataset.
Run `ip-watch providers` for the live list with CIDR counts. Currently **35 providers**:

| Category | Providers |
|---|---|
| **Cloud** | AWS · Azure · Google Cloud · Oracle · IBM Cloud · Alibaba · Tencent · DigitalOcean · Linode · Vultr · Hetzner · OVHcloud · Scaleway |
| **CDN / edge** | Cloudflare · Fastly |
| **SaaS / infra** | GitHub · Atlassian · Datadog · Zoom · Meta · Telegram · UptimeRobot · CircleCI · TeamCity |
| **Search & AI crawlers** | Googlebot · Bingbot · GPTBot · Amazonbot · Applebot · PerplexityBot · DuckDuckBot · Common Crawl |
| **Privacy / anonymity** | Tor · Mullvad · Apple Private Relay |

Combine providers in a single target (`-providers cloudflare,fastly`) and ip-watch merges and de-duplicates the CIDRs.

## Install

ip-watch is a Linux tool (it manages Linux webservers, firewalls, and systemd). Released for **amd64, arm64,
armv6, armv7, 386, riscv64, ppc64le, and s390x**. Pick whichever matches your distro; every method installs the
same `ip-watch` binary plus a systemd unit, and seeds a config with a **random admin password**.

**Quickest — one line (auto-detects arch, verifies checksum, installs the service):**

```sh
curl -fsSL https://raw.githubusercontent.com/rezmoss/ip-watch/main/install.sh | sudo sh
```

Re-run it anytime to **upgrade in place** (your config and admin password are kept). Pin a version with
`… | sudo sh -s -- v1.2.3`. Prefer your distro's package manager? Use one of the options below.

<details open>
<summary><b>Debian / Ubuntu (and derivatives: Mint, Pop!_OS, Kali, Raspbian)</b></summary>

```sh
# Grab the .deb for your arch from the latest release, then:
sudo dpkg -i ip-watch_*_amd64.deb        # arm64: ip-watch_*_arm64.deb
sudo systemctl status ip-watch
```
</details>

<details>
<summary><b>Fedora / RHEL / CentOS Stream / Rocky / AlmaLinux / openSUSE</b></summary>

```sh
sudo rpm -i ip-watch_*_amd64.rpm
# or, to pull deps: sudo dnf install ./ip-watch_*.x86_64.rpm
sudo systemctl status ip-watch
```
</details>

<details>
<summary><b>Alpine</b></summary>

```sh
sudo apk add --allow-untrusted ip-watch_*_amd64.apk
rc-service ip-watch status   # or: service ip-watch status
```
</details>

<details>
<summary><b>Arch / Manjaro</b></summary>

Use the generic binary tarball below or [build from source](#build--test). (An AUR package is planned.)
</details>

<details>
<summary><b>Any distro: binary tarball + systemd installer</b></summary>

```sh
# Download ip-watch_<version>_linux_x86_64.tar.gz from the latest release, then:
tar xzf ip-watch_*.tar.gz
sudo ./deploy/install.sh ./ip-watch     # installs to /usr/local/bin + systemd, prints the admin password
```
</details>

<details>
<summary><b>Go toolchain</b></summary>

```sh
go install github.com/rezmoss/ip-watch/cmd/ip-watch@latest
sudo "$(go env GOPATH)/bin/ip-watch" serve   # or wire up your own systemd unit
```
</details>

<details>
<summary><b>Nix (flakes)</b></summary>

```sh
nix run github:rezmoss/ip-watch -- help          # run without installing
nix profile install github:rezmoss/ip-watch      # install into your profile
```
Or add it as a flake input and use `inputs.ip-watch.packages.${system}.default`.
</details>

<details>
<summary><b>Docker (for managing sibling containers)</b></summary>

```sh
docker pull ghcr.io/rezmoss/ip-watch:latest        # or: docker.io/rezmoss/ip-watch:latest
```
See the [Docker](#docker) section for compose and the daemon-socket setup.
</details>

> **Not packaged for Snap/Flatpak by design.** ip-watch runs as root and edits host
> config (`/etc/nginx`, …), `systemctl`, and firewall rules — work that Snap/Flatpak
> sandboxes block. Use the `.deb`/`.rpm`, the apt/yum repo, or the installer instead
> (see [`deploy/snap/snapcraft.yaml`](deploy/snap/snapcraft.yaml) for the rationale).

After a package install, the service is already running on `127.0.0.1:8080` with a generated password. Find it with:

```sh
sudo grep -m1 password /etc/ip-watch/config.json
```

The UI binds **loopback** by default. To reach it from your laptop, SSH-tunnel (no need to expose anything):

```sh
ssh -L 8080:127.0.0.1:8080 user@your-server   # then open http://127.0.0.1:8080
```

> **Verify your download.** Each release ships `checksums.txt`:
> `sha256sum -c checksums.txt --ignore-missing`

## Quick start

Everything below runs from the CLI. (The web UI does the same things, if you prefer a form.)

```sh
# 1. What can ip-watch manage on this host?
ip-watch detect          # JSON: which engines are installed (+ binary path & version)
ip-watch providers       # which providers exist, with CIDR counts

# 2. Add a target and enforce it in one step.
ip-watch add -id cf -provider cloudflare -engine nginx -selector example.com -apply

# 3. Did it take effect?
ip-watch status          # per-target state + apply/change/failure counters

# 4. From now on it refreshes daily on its own. To re-assert manually:
ip-watch apply
```

`add` only writes config; nothing is enforced until `apply` (or `-apply` to do both). Preview any change without
writing or reloading using `ip-watch apply --dry`.

## Recipes

**Only Cloudflare may reach nginx** (the classic "lock the origin behind the CDN")

```sh
ip-watch add -id cf -provider cloudflare -engine nginx -selector example.com -real-ip -apply
```
`-real-ip` makes nginx trust `CF-Connecting-IP` so your logs and rate limits see the real visitor, not a
Cloudflare edge IP.

**Block every Tor exit node at the firewall**

```sh
ip-watch add -id no-tor -provider tor -mode deny -engine nftables -ports 80,443 -apply
```

**Block AI scrapers** (GPTBot, Amazonbot, PerplexityBot) on Apache

```sh
ip-watch add -id no-ai -providers gptbot,amazonbot,perplexitybot -mode deny -engine apache -apply
```

**Firewall: let only AWS + Cloudflare hit your web ports, and never lock yourself out**

```sh
ip-watch add -id edge -providers aws,cloudflare -mode allow -engine nftables \
    -ports 80,443 -admin-allow-ips 203.0.113.5/32 -apply
```

**Manage nginx running inside a container** (Docker transport, no host changes)

```sh
ip-watch docker-ls                                  # discover candidate containers
ip-watch add -id site -provider cloudflare -engine nginx \
    -transport docker -container my-nginx -apply
```

**Lock down ufw with a provider whitelist** (requires `ufw default deny incoming`)

```sh
ip-watch add -id ufw-cf -provider cloudflare -engine ufw -ports 80,443 -apply
```

## Command line

The CLI is self-documenting and built so a human or an automation/AI agent can enumerate and drive every
capability. `apply` and `detect` emit **stable JSON** for scripting.

```sh
ip-watch help                 # grouped list of every command
ip-watch help <command>       # usage, flags, and examples for one
ip-watch <command> -h         # same
```

| Group | Commands |
|---|---|
| **Run** | `serve` (web UI + daily scheduler; the default command) |
| **Targets** | `targets`, `add`, `rm` |
| **Apply & enforce** | `apply` (`--dry`, `-target`, `-skip-unchanged`), `remove` |
| **Inspect** | `detect`, `providers`, `config`, `status`, `history`, `metrics`, `docker-ls` |
| **Notifications** | `settings`, `notify-test` |
| **Meta** | `healthcheck`, `version`, `help` |

```sh
ip-watch apply --dry                 # preview: render + validate only, no writes/reload
ip-watch apply -target cf            # apply a single target
ip-watch remove cf                   # uninstall a target's rules, keep it in config
ip-watch rm cf                       # uninstall AND delete from config
ip-watch history -n 50               # recent apply events
ip-watch metrics | grep failures     # Prometheus text, no server needed
ip-watch settings -webhook https://hooks.slack.com/services/XXX   # then: notify-test
```

> Global flags (currently `-config <path>`, also via `$IPWATCH_CONFIG`) go **before** the command;
> command-specific flags go **after** it.

## Configuration

Config lives at `/etc/ip-watch/config.json` (auto-created on install). You can edit it directly, use the CLI
(`add`/`rm`/`settings`), or the web UI. They all write the same file under an advisory lock.

```json
{
  "data_source": "https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main",
  "listen": "127.0.0.1:8080",
  "update_hour": 3,
  "auth": { "username": "admin", "password": "change-me" },
  "notify": { "webhook": "https://hooks.slack.com/services/…", "always": false },
  "targets": [
    {
      "id": "web1",
      "providers": ["cloudflare", "fastly"],
      "mode": "allow",
      "engine": "nginx",
      "transport": "local",
      "enabled": true,
      "config": { "file": "", "selector": "example.com", "real_ip": true }
    },
    {
      "id": "fw",
      "providers": ["cloudflare"],
      "mode": "allow",
      "engine": "nftables",
      "transport": "local",
      "enabled": true,
      "admin_allow_ips": ["203.0.113.5/32"],
      "firewall": { "ports": [80, 443] }
    }
  ]
}
```

**Top-level keys**

| Key | Default | Meaning |
|---|---|---|
| `data_source` | the dataset repo | Base URL ip-watch fetches provider lists from. |
| `listen` | `127.0.0.1:8080` | Web UI / API bind address. |
| `update_hour` | `3` | Hour (0–23, **UTC**) of the daily refresh. |
| `auth` | none | `username` + `password` for HTTP Basic auth (required for non-loopback binds). |
| `notify` | none | `webhook` URL + `always` (notify even on no-change runs). |
| `allow_malformed_provider_data` | `false` | When `false`, one bad upstream CIDR aborts the apply (fail-closed, keeping last-good rules). |
| `lock_unsafe` | `false` | When `false`, edits abort if the cross-process lock can't be acquired. |

**Per-target keys**

| Key | Meaning |
|---|---|
| `id` | Unique id (letters, digits, `_`, `-`). |
| `providers` | One or more provider names; multiple are merged and de-duplicated. |
| `mode` | `allow` (whitelist) or `deny` (blocklist). |
| `engine` | `nginx` · `caddy` · `apache` · `haproxy` · `nftables` · `iptables` · `ufw`. |
| `transport` | `local` (native host) or `docker` (add `"docker": {"container": "name"}`). |
| `config.file` | Blank = auto-detect the engine's config; otherwise an explicit path. |
| `config.selector` | The block to edit (nginx `server_name` / Caddy site / Apache `VirtualHost` / HAProxy frontend). |
| `config.real_ip` | Recover the true client IP behind a proxy (nginx/caddy/apache/haproxy). |
| `firewall.ports` | TCP ports the firewall engines police (default `80, 443`). |
| `firewall.allow_admin_ports` | Permit policing management ports (22/3389/db…) in allow mode. |
| `admin_allow_ips` | CIDRs always permitted in allow mode (every engine). Add your own IP. |

**Environment overrides:** `IPWATCH_CONFIG` (config path), `IPWATCH_LISTEN`, `IPWATCH_AUTH_USERNAME`,
`IPWATCH_AUTH_PASSWORD`, `IPWATCH_INSECURE=1`.

> **Allow mode is a strict whitelist.** Traffic to the configured ports is dropped unless it matches a provider
> range or `admin_allow_ips`. Whitelisting a management port (22, 3389, database ports…) is rejected unless you
> set `firewall.allow_admin_ports: true`. For **ufw**, allow mode only enforces when the default incoming policy
> is `deny`; ip-watch refuses to apply otherwise. Only the listed ports are policed, so SSH and other services
> are untouched unless you add their ports.

## How safe-apply works

For a config engine, managed rules are written to their own file (for nginx, `/etc/nginx/ip-watch/<id>.conf`)
and pulled into your chosen block with an idempotent, clearly-marked `include`:

```nginx
server {
    # >>> ip-watch:/etc/nginx/ip-watch/web1.conf >>>
    include /etc/nginx/ip-watch/web1.conf;
    # <<< ip-watch:/etc/nginx/ip-watch/web1.conf <<<
    ...
}
```

Every apply follows the same state machine:

```
fetch CIDRs ─▶ render managed rules ─▶ inject the include (idempotent markers)
   ─▶ back up the target config
   ─▶ validate  ──fail──▶ restore backup, abort (live service never reloaded)
        │ pass
   ─▶ reload    ──fail──▶ restore backup, reload last-good, report
   ─▶ record content hash  (the daily run is a no-op when nothing changed)
```

Re-applies are idempotent: the prior managed block is stripped and rewritten, never duplicated.
`uninstall`/`rm` reverses it, removing the include and the managed file.

## Operations

- **Scheduler.** `serve` applies all enabled targets on startup, then daily at `update_hour` (UTC). The daily
  run compares a content fingerprint and **skips targets whose ranges did not change**, so a quiet day is cheap.
- **Health.** `GET /healthz` (always unauthenticated) for orchestration. The container image ships a
  `HEALTHCHECK` that calls the `healthcheck` subcommand, so no `curl`/`wget` is needed in the image.
- **Metrics.** `GET /metrics` exposes Prometheus counters (applies, changes, failures, ranges, last-success
  timestamp per target). `ip-watch metrics` prints the same text without a running server. Run history is at
  `GET /api/history` and in the UI.
- **Notifications.** Point `notify.webhook` at Slack, Mattermost, or any endpoint that accepts a JSON
  `{"text", "results"}` POST. `ip-watch notify-test` sends a probe. Outbound URLs are SSRF-guarded
  (no loopback/link-local).
- **Logs.** `journalctl -u ip-watch -f`.
- **systemd hardening.** The shipped unit runs with `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome`,
  `PrivateTmp`, a minimal capability set (`CAP_NET_ADMIN`, `CAP_NET_RAW`, …), and a tight `ReadWritePaths`
  allowlist scoped to the config dirs of the engines it manages.

## Security & anti-lockout

ip-watch runs as root (it edits webserver configs and firewall rules), so it is conservative by default:

- **Loopback bind + auth.** The UI binds `127.0.0.1:8080`. ip-watch **refuses to bind a non-loopback address
  without auth**. Set `auth` (or the env vars), or pass `insecure: true` / `IPWATCH_INSECURE=1` to override.
  Installers generate a random admin password; the container image requires `IPWATCH_AUTH_*`.
- **CSRF protection.** State-changing routes reject cross-origin requests.
- **Constant-time auth.** Basic-auth credentials are compared with `crypto/subtle`.
- **You cannot lock yourself out of SSH.** Firewall engines police only the configured ports (default 80/443).
  Allow-mode whitelists refuse management ports unless you opt in, and `admin_allow_ips` always passes, so you
  can pin your own address.
- **Fail-closed data handling.** A malformed upstream CIDR aborts the apply and keeps the last-good rules
  (override with `allow_malformed_provider_data: true`).

## Docker

The product is the binary; the container is a thin wrapper for managing **sibling containers** over the Docker
socket. To manage a host-installed webserver, run the binary natively.

```yaml
# docker-compose.yml
services:
  ip-watch:
    image: ghcr.io/rezmoss/ip-watch:latest
    ports: ["8080:8080"]
    environment:
      - IPWATCH_AUTH_USERNAME=admin
      - IPWATCH_AUTH_PASSWORD=${IPWATCH_AUTH_PASSWORD:?set a password}
    volumes:
      - ip-watch-data:/data
      - /var/run/docker.sock:/var/run/docker.sock   # only if you use the Docker transport
    restart: unless-stopped
volumes:
  ip-watch-data:
```

The image binds `0.0.0.0`, so it **requires** auth (compose fails fast without `IPWATCH_AUTH_PASSWORD`). The
Docker transport discovers a sibling webserver container, copies the managed include in over the archive API,
runs the engine's validator, and reloads via `docker exec`, all without touching the host.

## Build & test

Requires **Go 1.26+**. No CGO, no external modules.

```sh
make build          # static binary into ./ip-watch  (CGO_ENABLED=0, -trimpath, -s -w)
make test           # unit + httptest integration tests (go test -race ./...)
make e2e            # full Docker-based suite across all 7 engines (firewall tests need --privileged)
make snapshot       # build a complete local release into ./dist (no publish)
```

Or directly:

```sh
go test ./...
go build -ldflags "-s -w" -o ip-watch ./cmd/ip-watch
```

The end-to-end suite verifies apply → enforce → idempotent re-apply → uninstall for every engine, plus
multi-provider merge, the health endpoint, and the negative paths (validation rollback, ufw default-allow
refusal, invalid-config gating). CI runs format, vet, race tests, and e2e on every PR.

## FAQ

**Does this replace Cloudflare's own firewall / a WAF?**
No. It keeps your origin or firewall in sync with provider ranges. It pairs well with a CDN (lock the origin to
the CDN's IPs) but it is not a WAF.

**What happens if the provider list is briefly unreachable?**
The apply keeps your last-good rules. The provider catalog is cached and falls back to the previous good copy.

**Allow vs deny?**
`allow` is a whitelist (only the provider's ranges may reach the configured ports/block). `deny` is a blocklist
(everyone except that provider). Add `admin_allow_ips` in allow mode so a whitelist can't lock you out.

**nftables vs iptables vs ufw?**
Prefer **nftables**: it is transactional and handles large rule sets. **ufw** is impractical for providers with
thousands of CIDRs (one rule per range). **iptables** uses ipset for atomic swaps but the surrounding script is
best-effort.

**Can I run it without the web UI?**
Yes. Everything the UI does is on the CLI, with stable JSON for `apply`/`detect`. Bind loopback and ignore it,
or don't expose it at all.

## Contributing

Issues and pull requests are welcome. Run `make test` (and `make e2e` if Docker is available) before opening a
PR, and keep `gofmt`/`go vet` clean.

## License

[MIT](LICENSE) © Rez Moss
