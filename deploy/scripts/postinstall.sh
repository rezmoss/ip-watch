#!/bin/sh
# nfpm post-install hook (.deb/.rpm/.apk). Mirrors deploy/install.sh: creates the
# config/state dirs, seeds a config with a random admin password on first install,
# and (re)starts the systemd service. Safe to run on upgrades — it never clobbers
# an existing config.
set -e

CONF_DIR=/etc/ip-watch
STATE_DIR=/var/lib/ip-watch

mkdir -p "$STATE_DIR"
mkdir -p "$CONF_DIR"
chmod 0750 "$CONF_DIR"

if [ ! -f "$CONF_DIR/config.json" ]; then
  # Generate a random admin password so the UI isn't unauthenticated by default.
  PASS=$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | cut -c1-24)
  cat > "$CONF_DIR/config.json" <<JSON
{
  "listen": "127.0.0.1:8080",
  "auth": { "username": "admin", "password": "$PASS" },
  "targets": []
}
JSON
  chmod 0600 "$CONF_DIR/config.json"
  echo
  echo "  ip-watch web UI login:  admin / $PASS"
  echo "  (stored in $CONF_DIR/config.json — change it there or via IPWATCH_AUTH_PASSWORD)"
  echo "  The UI binds 127.0.0.1:8080. From your machine:"
  echo "    ssh -L 8080:127.0.0.1:8080 <user>@<this-host>  then open http://127.0.0.1:8080"
  echo
fi

# Enable + start under systemd when available (skipped in containers / non-systemd).
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  systemctl enable ip-watch.service || true
  systemctl restart ip-watch.service || true
fi

exit 0
