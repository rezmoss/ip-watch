#!/bin/sh
# ip-watch universal installer.
#
#   curl -fsSL https://raw.githubusercontent.com/rezmoss/ip-watch/main/install.sh | sudo sh
#   curl -fsSL https://raw.githubusercontent.com/rezmoss/ip-watch/main/install.sh | sudo sh -s -- v1.2.3
#
# Detects your architecture, downloads the matching release tarball, verifies its
# SHA-256 against checksums.txt, then installs the binary + systemd unit via the
# bundled deploy/install.sh. Re-run anytime to upgrade in place (config + admin
# password are preserved). Linux only — for containers use ghcr.io/rezmoss/ip-watch.
#
# Knobs (env):
#   IPWATCH_VERSION=v1.2.3   pin a version (default: latest release)
set -eu

REPO="rezmoss/ip-watch"

err() { echo "ip-watch-install: $*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || err "ip-watch is Linux-only (detected $(uname -s)). For containers use: docker pull ghcr.io/$REPO"
command -v tar >/dev/null 2>&1 || err "missing required tool: tar"

# Download helpers — prefer curl, fall back to wget.
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1"; }            # to stdout
  download() { curl -fsSL -o "$1" "$2"; } # to file
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO- "$1"; }
  download() { wget -qO "$1" "$2"; }
else
  err "need curl or wget to download releases"
fi

# Map `uname -m` to the arch suffix GoReleaser uses in the archive name.
machine=$(uname -m)
case "$machine" in
  x86_64 | amd64) ARCH=x86_64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  armv7l) ARCH=armv7 ;;
  armv6l) ARCH=armv6 ;;
  i386 | i686) ARCH=i386 ;;
  ppc64le) ARCH=ppc64le ;;
  riscv64) ARCH=riscv64 ;;
  s390x) ARCH=s390x ;;
  *) err "unsupported architecture: $machine" ;;
esac

# Version: CLI arg ($1) > $IPWATCH_VERSION > latest GitHub release.
VERSION="${1:-${IPWATCH_VERSION:-latest}}"
if [ "$VERSION" = "latest" ]; then
  VERSION=$(fetch "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4)
  [ -n "$VERSION" ] || err "could not determine the latest version (set IPWATCH_VERSION=vX.Y.Z)"
fi
VER_NUM=${VERSION#v}

TARBALL="ip-watch_${VER_NUM}_linux_${ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "Downloading $TARBALL ($VERSION)…"
download "$TMP/$TARBALL" "$BASE/$TARBALL" || err "download failed: $BASE/$TARBALL"
download "$TMP/checksums.txt" "$BASE/checksums.txt" || err "could not download checksums.txt"

echo "Verifying checksum…"
(
  cd "$TMP"
  line=$(grep " ${TARBALL}\$" checksums.txt) || err "no checksum entry for $TARBALL"
  if command -v sha256sum >/dev/null 2>&1; then
    echo "$line" | sha256sum -c -
  elif command -v shasum >/dev/null 2>&1; then
    echo "$line" | shasum -a 256 -c -
  else
    err "need sha256sum or shasum to verify the download"
  fi
) || err "CHECKSUM MISMATCH — refusing to install"

tar -xzf "$TMP/$TARBALL" -C "$TMP"
[ -f "$TMP/ip-watch" ] || err "archive did not contain the ip-watch binary"

# Stop a running instance so the binary can be swapped on upgrade. The bundled
# deploy/install.sh re-enables and starts it (and keeps any existing config).
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  if systemctl is-active --quiet ip-watch.service 2>/dev/null; then
    echo "Stopping running ip-watch for upgrade…"
    systemctl stop ip-watch.service || true
  fi
fi

echo "Installing…"
sh "$TMP/deploy/install.sh" "$TMP/ip-watch"
