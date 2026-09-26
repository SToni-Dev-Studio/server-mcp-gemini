#!/bin/bash
set -e

VERSION="${1:-0.3.0}"
REPO="SToni-Dev-Studio/server-mcp-gemini"
BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"
DEB_NAME="mcp-hub-tools_${VERSION}_all.deb"

echo "======================================"
echo " mcp-hub-tools v${VERSION} installer"
echo "======================================"
echo ""

# Download .deb
echo "Downloading ${DEB_NAME}..."
curl -fsSL "${BASE_URL}/${DEB_NAME}" -o "/tmp/${DEB_NAME}"

# Install
echo "Installing..."
sudo dpkg -i "/tmp/${DEB_NAME}"
sudo apt-get install -f -y 2>/dev/null || true

# Prompt for config
echo ""
echo "Configuration:"
read -p "  MCP Server URL (e.g. https://server-mcp-gemini.onrender.com): " MCP_URL
read -s -p "  MCP Password: " MCP_PASSWORD
echo ""
read -p "  Linux server Tailscale hostname/IP: " SERVER_HOST
read -p "  Linux server SSH user [sepisotoni]: " SERVER_USER
SERVER_USER="${SERVER_USER:-sepisotoni}"

# Write config
sudo mkdir -p /etc/mcp-hub-tools
printf "MCP_SERVER_URL=%s\nMCP_PASSWORD=%s\nSERVER_HOST=%s\nSERVER_USER=%s\n" \
    "$MCP_URL" "$MCP_PASSWORD" "$SERVER_HOST" "$SERVER_USER" \
    | sudo tee /etc/mcp-hub-tools/config.env > /dev/null
sudo chmod 600 /etc/mcp-hub-tools/config.env

# Enable services
sudo systemctl daemon-reload
sudo systemctl enable --now hub-monitor.service 2>/dev/null || true
sudo systemctl enable --now hub-poll.timer      2>/dev/null || true

echo ""
echo "Done! mcp-hub-tools v${VERSION} installed."
echo ""
echo "Commands:"
echo "  hub-cli --help"
echo "  hub-diagnostics --help"
echo "  hub-monitor status"
echo "  hub-monitor events"
