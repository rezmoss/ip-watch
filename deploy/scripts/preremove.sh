#!/bin/sh
# nfpm pre-remove hook. Stop + disable the service before the binary is removed.
# On upgrades the package manager re-runs postinstall afterwards, which restarts it.
set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl stop ip-watch.service || true
  systemctl disable ip-watch.service || true
fi

exit 0
