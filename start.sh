#!/bin/bash
set -e

# Install and connect Tailscale if auth key is provided
if [ -n "$TAILSCALE_AUTH_KEY" ]; then
    echo "Setting up Tailscale..."
    # Install tailscale
    curl -fsSL https://tailscale.com/install.sh | sh 2>/dev/null || true
    # Start tailscaled in background
    tailscaled --tun=userspace-networking --socks5-server=localhost:1055 &
    sleep 3
    # Connect to tailnet
    tailscale up --authkey="$TAILSCALE_AUTH_KEY" --hostname=render-mcp --accept-routes 2>/dev/null || true
    echo "Tailscale connected: $(tailscale ip 2>/dev/null || echo 'pending')"
fi

# Write SSH key to file if provided
if [ -n "$SSH_PRIVATE_KEY" ]; then
    mkdir -p /tmp
    echo "$SSH_PRIVATE_KEY" > /tmp/render_mcp_key
    chmod 600 /tmp/render_mcp_key
    echo "SSH key written."
fi

# Start the MCP server
exec node dist/server.cjs
