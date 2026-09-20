#!/bin/bash
set -e

if [ -n "$TAILSCALE_AUTH_KEY" ]; then
    echo "Setting up Tailscale..."
    tailscaled --tun=userspace-networking --socks5-server=localhost:1055 &
    sleep 3
    tailscale up --authkey="${TAILSCALE_AUTH_KEY}" --hostname=render-mcp --accept-routes 2>/dev/null || true
    echo "Tailscale connected: $(tailscale ip 2>/dev/null || echo 'pending')"
fi

if [ -n "$SSH_PRIVATE_KEY" ]; then
    mkdir -p /tmp
    echo "$SSH_PRIVATE_KEY" > /tmp/render_mcp_key
    chmod 600 /tmp/render_mcp_key
    echo "SSH key written."
fi

exec python server.py

