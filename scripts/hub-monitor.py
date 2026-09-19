#!/usr/bin/env python3
"""
hub-monitor.py — Linux Hub auto-discovery registration listener + 5-minute poller (Proposal v2)

Features:
1. Auto-Registration Listener: Listens on port 7840 for PC registration announcements.
2. Registry Store: Maintains /var/lib/hub-monitor/registry.json (id, name, lan_ip, port, last_registered).
3. 5-Minute Poller: Periodically polls each registered PC's /status over LAN.
4. Retry Logic: On missed poll, retries 3 times at 3-second intervals before marking offline.
5. Event Push: Appends transition events to /var/lib/hub-monitor/events.jsonl and POSTs to cloud server.
"""

import argparse
import json
import os
import sys
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

REGISTRY_DIR = os.environ.get("HUB_MONITOR_DIR", "/var/lib/hub-monitor")
REGISTRY_FILE = os.path.join(REGISTRY_DIR, "registry.json")
EVENTS_FILE = os.path.join(REGISTRY_DIR, "events.jsonl")

# In-memory state
_registry = {}
_pc_states = {}  # name -> "online" | "offline"
_lock = threading.Lock()


def get_effective_registry_dir():
    global REGISTRY_DIR, REGISTRY_FILE, EVENTS_FILE
    target = REGISTRY_DIR
    try:
        os.makedirs(target, exist_ok=True)
        return target
    except PermissionError:
        user_dir = os.path.expanduser("~/.local/share/hub-monitor")
        os.makedirs(user_dir, exist_ok=True)
        REGISTRY_DIR = user_dir
        REGISTRY_FILE = os.path.join(REGISTRY_DIR, "registry.json")
        EVENTS_FILE = os.path.join(REGISTRY_DIR, "events.jsonl")
        return user_dir


def load_registry():
    global _registry
    eff_dir = get_effective_registry_dir()
    if os.path.exists(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, "r") as f:
                _registry = json.load(f)
        except Exception:
            _registry = {}


def save_registry():
    get_effective_registry_dir()
    with open(REGISTRY_FILE + ".tmp", "w") as f:
        json.dump(_registry, f, indent=2)
    os.replace(REGISTRY_FILE + ".tmp", REGISTRY_FILE)


def log_and_push_event(machine_name, event, data):
    get_effective_registry_dir()
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    event_entry = {
        "timestamp": now_iso,
        "machine_name": machine_name,
        "event": event,
        "data": data,
    }
    # Append to local jsonl
    with open(EVENTS_FILE, "a") as f:
        f.write(json.dumps(event_entry) + "\n")

    # Push to cloud server if configured
    cloud_url = os.environ.get("CLOUD_SERVER_URL", "https://server-mcp-gemini.fly.dev").rstrip("/") + "/events/pc_status"
    bearer_token = os.environ.get("MCP_SERVER_PASSWORD", os.environ.get("ADMIN_PASSWORD", "gemini_mcp_secret_2026"))
    try:
        payload = json.dumps({
            "machine_name": machine_name,
            "event": event,
            "lan_ip": data.get("lan_ip", ""),
            "port": data.get("port", 0),
            "timestamp": now_iso,
        }).encode("utf-8")
        req = urllib.request.Request(cloud_url, data=payload, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer_token}",
        })
        urllib.request.urlopen(req, timeout=5)
        print(f"[Hub Monitor] Event '{event}' for '{machine_name}' pushed to cloud server.")
    except Exception as e:
        print(f"[Hub Monitor] Cloud push failed for '{machine_name}': {e}")


class RegistrationHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path in ("/register", "/announce"):
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            try:
                data = json.loads(body.decode("utf-8"))
            except Exception:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid JSON"}')
                return

            name = data.get("machine_name") or data.get("machine_id") or "pc-unknown"
            lan_ip = data.get("lan_ip") or self.client_address[0]
            port = int(data.get("port", 7842))
            secret = data.get("secret", "")

            with _lock:
                was_known = name in _registry
                prev_state = _pc_states.get(name, "offline")
                _registry[name] = {
                    "id": data.get("machine_id"),
                    "name": name,
                    "lan_ip": lan_ip,
                    "port": port,
                    "secret": secret,
                    "last_registered": time.time(),
                    "status": "online",
                }
                save_registry()
                _pc_states[name] = "online"

                if prev_state != "online":
                    log_and_push_event(name, "online", _registry[name])

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "registered", "name": name}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def poll_pcs_once():
    """Polls registered PCs every 5 minutes with 3-retry 3s grace period."""
    with _lock:
        target_pcs = dict(_registry)

    for name, info in target_pcs.items():
        lan_ip = info.get("lan_ip", "127.0.0.1")
        port = info.get("port", 7842)
        url = f"http://{lan_ip}:{port}/status"

        is_online = False
        # Try initial poll + 3 retries at 3s intervals
        for attempt in range(4):
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status == 200:
                        is_online = True
                        break
            except Exception:
                if attempt < 3:
                    time.sleep(3)

        with _lock:
            prev_state = _pc_states.get(name, "unknown")
            new_state = "online" if is_online else "offline"
            _pc_states[name] = new_state
            if name in _registry:
                _registry[name]["status"] = new_state
                _registry[name]["last_polled"] = time.time()
                save_registry()

            if prev_state != new_state:
                log_and_push_event(name, new_state, _registry.get(name, {}))


def poller_loop(interval_sec=300):
    while True:
        poll_pcs_once()
        time.sleep(interval_sec)


def main():
    parser = argparse.ArgumentParser(description="Proposal v2 Hub Auto-Discovery Listener & Poller")
    parser.add_argument("--port", type=int, default=7840, help="Listen port for PC announcements (default 7840)")
    parser.add_argument("--once", action="store_true", help="Run one poll pass and exit")
    args = parser.parse_args()

    load_registry()

    if args.once:
        poll_pcs_once()
        print(json.dumps(_registry, indent=2))
        return

    # Start polling thread
    t = threading.Thread(target=poller_loop, daemon=True)
    t.start()

    server = HTTPServer(("0.0.0.0", args.port), RegistrationHandler)
    print(f"[Hub Monitor v2] Listening for PC announcements on port {args.port}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
