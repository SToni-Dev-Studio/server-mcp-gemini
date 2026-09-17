#!/bin/bash
# build-deb.sh — assembles and builds the mcp-hub-tools .deb package.
#
# Usage:
#   ./build-deb.sh [version]
#
# version defaults to "0.0.0-dev" for local testing; release.yml passes
# the actual release tag (stripped of its leading 'v') when building for
# a real release.
#
# This copies the CURRENT scripts/hub-cli.py, scripts/hub-diagnostics.py,
# and pc-tunnel@.service from the repo root into the package tree before
# building, rather than relying on whatever's already sitting in
# packaging/mcp-hub-tools/ (which may be stale) -- so the package always
# reflects the actual current source, not a snapshot someone forgot to
# refresh.
set -euo pipefail

VERSION="${1:-0.0.0-dev}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_DIR="$SCRIPT_DIR/mcp-hub-tools"
BUILD_DIR="$SCRIPT_DIR/build/mcp-hub-tools"

echo "Building mcp-hub-tools version $VERSION"

rm -rf "$BUILD_DIR"
mkdir -p "$(dirname "$BUILD_DIR")"
cp -r "$PKG_DIR" "$BUILD_DIR"

# Refresh the bundled sources from the actual repo root.
cp "$REPO_ROOT/scripts/hub-cli.py" "$BUILD_DIR/usr/lib/mcp-hub-tools/hub-cli.py"
cp "$REPO_ROOT/scripts/hub-diagnostics.py" "$BUILD_DIR/usr/lib/mcp-hub-tools/hub-diagnostics.py"
cp "$REPO_ROOT/pc-tunnel@.service" "$BUILD_DIR/lib/systemd/system/pc-tunnel@.service"
chmod 755 "$BUILD_DIR/usr/lib/mcp-hub-tools/hub-cli.py"
chmod 755 "$BUILD_DIR/usr/lib/mcp-hub-tools/hub-diagnostics.py"

# Substitute the version into control (Debian requires a real version
# string, not a placeholder).
sed -i "s/^Version: __VERSION__/Version: $VERSION/" "$BUILD_DIR/DEBIAN/control"

# Debian packages need correct ownership recorded in the .deb regardless
# of the building user's own uid/gid -- dpkg-deb's --root-owner-group
# flag (used below) handles this without needing the build itself to
# run as root or under fakeroot, so no explicit chown step is needed
# here (an earlier version of this script did one; removed since it'd
# fail on a non-root CI runner for no real benefit over the flag).

OUT_DEB="$SCRIPT_DIR/mcp-hub-tools_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$BUILD_DIR" "$OUT_DEB"

echo "Built: $OUT_DEB"
sha256sum "$OUT_DEB" | awk '{print $1}' > "$OUT_DEB.sha256"
echo "Checksum: $OUT_DEB.sha256"

dpkg-deb --info "$OUT_DEB"
echo ""
echo "Contents:"
dpkg-deb --contents "$OUT_DEB"
