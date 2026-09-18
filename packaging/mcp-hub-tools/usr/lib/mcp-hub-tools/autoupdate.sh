#!/bin/bash
# mcp-hub-tools-autoupdate.sh — checks GitHub Releases for a newer version
# of this package and installs it if found. Run periodically by
# mcp-hub-tools-autoupdate.timer (disabled by default -- see postinst's
# printed instructions, or /usr/share/doc/mcp-hub-tools/README, for how
# to enable it).
#
# Deliberately simple (curl + dpkg, no apt repo / signing infrastructure)
# -- setting up and maintaining a signed apt repository is a real,
# ongoing operational commitment (key rotation, repo hosting, etc.) that
# doesn't fit this project's scale. This trades that off against a
# narrower, honest guarantee: releases are fetched over HTTPS from
# GitHub (so the CHANNEL is authenticated) and the download is verified
# against the SHA256 checksum GitHub publishes alongside the release
# asset, but the .deb itself is NOT GPG-signed, so this does not protect
# against a compromised GitHub account or repo publishing a malicious
# release -- same trust model as `curl | bash`-style installers common
# for small projects, made explicit rather than implied.
set -euo pipefail

REPO="mienkek13-netizen/server-mcp-claude"
PACKAGE_NAME="mcp-hub-tools"
GITHUB_API_BASE="${GITHUB_API_BASE:-https://api.github.com}"  # overridable for tests
CURRENT_VERSION="$(dpkg-query -W -f='${Version}' "$PACKAGE_NAME" 2>/dev/null || echo "0")"
LOG_TAG="mcp-hub-tools-autoupdate"

log() { logger -t "$LOG_TAG" "$1" 2>/dev/null || echo "[$LOG_TAG] $1"; }

log "checking for updates (current version: $CURRENT_VERSION)"

RELEASE_JSON="$(curl -fsSL --max-time 15 "${GITHUB_API_BASE}/repos/${REPO}/releases/latest")" || {
  log "failed to reach GitHub Releases API — skipping this run"
  exit 0  # a network blip is not a failure worth alerting on for a periodic timer
}

LATEST_TAG="$(echo "$RELEASE_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name",""))')"
LATEST_VERSION="${LATEST_TAG#v}"  # tags are like v1.2.3; dpkg versions don't have the leading v

if [ -z "$LATEST_VERSION" ]; then
  log "could not determine latest version from release JSON — skipping"
  exit 0
fi

if ! dpkg --compare-versions "$LATEST_VERSION" gt "$CURRENT_VERSION"; then
  log "already up to date ($CURRENT_VERSION >= $LATEST_VERSION)"
  exit 0
fi

log "newer version available: $LATEST_VERSION (current: $CURRENT_VERSION)"

ASSET_URL="$(echo "$RELEASE_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for a in data.get('assets', []):
    if a['name'].endswith('.deb') and 'mcp-hub-tools' in a['name']:
        print(a['browser_download_url'])
        break
")"
CHECKSUM_URL="$(echo "$RELEASE_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for a in data.get('assets', []):
    if a['name'].endswith('.deb.sha256'):
        print(a['browser_download_url'])
        break
")"

if [ -z "$ASSET_URL" ]; then
  log "release $LATEST_TAG has no mcp-hub-tools .deb asset — skipping"
  exit 0
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

DEB_PATH="$TMPDIR/mcp-hub-tools.deb"
curl -fsSL --max-time 60 -o "$DEB_PATH" "$ASSET_URL"

if [ -n "$CHECKSUM_URL" ]; then
  curl -fsSL --max-time 15 -o "$TMPDIR/checksum.sha256" "$CHECKSUM_URL"
  EXPECTED="$(awk '{print $1}' "$TMPDIR/checksum.sha256")"
  ACTUAL="$(sha256sum "$DEB_PATH" | awk '{print $1}')"
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    log "CHECKSUM MISMATCH — expected $EXPECTED, got $ACTUAL. Refusing to install. This could mean a corrupted download OR a tampered release; not treating it as the former by default."
    exit 1
  fi
  log "checksum verified"
else
  log "WARNING: no .deb.sha256 asset found for this release — installing without checksum verification"
fi

log "installing $LATEST_VERSION"
dpkg -i "$DEB_PATH" || {
  log "dpkg -i failed — attempting apt-get install -f to resolve dependencies, then retrying"
  apt-get install -f -y || true
  dpkg -i "$DEB_PATH"
}

log "updated to $LATEST_VERSION"
