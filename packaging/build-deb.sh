#!/bin/bash
# build-deb.sh — assembles and builds the mcp-hub-tools Proposal v2 .deb package.
set -euo pipefail

VERSION="${1:-0.2.0-v2-gemini}"
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
cp "$REPO_ROOT/scripts/hub-monitor.py" "$BUILD_DIR/usr/lib/mcp-hub-tools/hub-monitor.py"
cp "$REPO_ROOT/pc-tunnel@.service" "$BUILD_DIR/lib/systemd/system/pc-tunnel@.service"
cp "$REPO_ROOT/mcp-hub-monitor.service" "$BUILD_DIR/lib/systemd/system/mcp-hub-monitor.service"

chmod 755 "$BUILD_DIR/usr/lib/mcp-hub-tools/hub-cli.py"
chmod 755 "$BUILD_DIR/usr/lib/mcp-hub-tools/hub-diagnostics.py"
chmod 755 "$BUILD_DIR/usr/lib/mcp-hub-tools/hub-monitor.py"

# Symlink hub-monitor executable
mkdir -p "$BUILD_DIR/usr/bin"
ln -sf ../lib/mcp-hub-tools/hub-monitor.py "$BUILD_DIR/usr/bin/hub-monitor"

# Substitute version
sed -i "s/^Version: .*/Version: $VERSION/" "$BUILD_DIR/DEBIAN/control"

OUT_DEB="$SCRIPT_DIR/mcp-hub-tools_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$BUILD_DIR" "$OUT_DEB"

echo "Built: $OUT_DEB"
sha256sum "$OUT_DEB" | awk '{print $1}' > "$OUT_DEB.sha256"
echo "Checksum: $OUT_DEB.sha256"

dpkg-deb --info "$OUT_DEB"
echo ""
echo "Contents:"
dpkg-deb --contents "$OUT_DEB"
