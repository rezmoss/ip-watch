#!/bin/sh
# Install ip-watch as a native systemd service.
# Usage: sudo ./deploy/install.sh [path-to-ip-watch-binary]
set -eu

BIN="${1:-./ip-watch}"
PREFIX=/usr/local/bin
CONF_DIR=/etc/ip-watch
STATE_DIR=/var/lib/ip-watch
UNIT=/etc/systemd/system/ip-watch.service
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh must run as root (it writes /usr/local/bin and a systemd unit)" >&2
  exit 1
fi
if [ ! -f "$BIN" ]; then
  echo "binary not found: $BIN (pass the path as the first argument)" >&2
  exit 1
fi

echo "Installing binary -> $PREFIX/ip-watch"
install -m 0755 "$BIN" "$PREFIX/ip-watch"

mkdir -p "$STATE_DIR"
mkdir -p "$CONF_DIR"
chmod 0750 "$CONF_DIR"
if [ ! -f "$CONF_DIR/config.json" ]; then
  # Generate a random admin password so the UI isn't unauthenticated by default.
  PASS=$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | cut -c1-24)
  echo "Writing default config -> $CONF_DIR/config.json (loopback + auth)"
  cat > "$CONF_DIR/config.json" <<JSON
{
  "listen": "127.0.0.1:8080",
  "auth": { "username": "admin", "password": "$PASS" },
  "targets": []
}
JSON
  chmod 0600 "$CONF_DIR/config.json"
  echo
  echo "  Web UI login:  admin / $PASS"
  echo "  (stored in $CONF_DIR/config.json — change it there or via IPWATCH_AUTH_PASSWORD)"
  echo
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  echo "Installing systemd unit -> $UNIT"
  install -m 0644 "$HERE/ip-watch.service" "$UNIT"
  systemctl daemon-reload
  systemctl enable --now ip-watch.service
  echo
  echo "ip-watch is running. The UI binds loopback (127.0.0.1:8080) by default."
  echo "On this host:        http://127.0.0.1:8080"
  echo "From your machine:   ssh -L 8080:127.0.0.1:8080 $(whoami)@<this-host>  then open http://127.0.0.1:8080"
  echo "                     (or set a non-loopback \"listen\" + auth in the config to expose it directly)"
  echo "Edit config:         $CONF_DIR/config.json"
  echo "Logs:                journalctl -u ip-watch -f"
else
  # No systemd (container, WSL2 without systemd, chroot): install the unit file
  # for later, but don't try to start a service that can't run here.
  echo "Installing systemd unit -> $UNIT (not started — systemd not detected)"
  install -m 0644 "$HERE/ip-watch.service" "$UNIT"
  echo
  echo "Binary + config installed, but no init system was detected to run the service."
  echo "Start it manually:   ip-watch serve"
  echo "Edit config:         $CONF_DIR/config.json"
fi
