#!/bin/sh
# nfpm post-remove hook. Reload systemd so the removed unit is forgotten. We keep
# /etc/ip-watch and /var/lib/ip-watch (config + state) on purge so an accidental
# remove/reinstall doesn't lose targets; delete them manually to wipe everything.
set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi

exit 0
