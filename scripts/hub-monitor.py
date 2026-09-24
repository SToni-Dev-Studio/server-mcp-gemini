#!/usr/bin/env python3
"""
hub-monitor.py — PC registration listener + poller + event log

Per coordination/proposals/pc-autodiscovery-2026-09-18-v2.md:

  1. Listens on LAN for PC self-registration announcements (HTTP POST /register)
  2. Maintains registry at /var/lib/hub-monitor/registry.json
  3. Polls every 5 minutes; retries 3x at 3s intervals before marking offline
  4. Logs online/offline events to /var/lib/hub-monitor/events.jsonl
  5. Pushes events to Render MCP server (wakes it from free-tier sleep)

Usage:
  hub-monitor serve   — start registration listener (runs as systemd service)
  hub-monitor poll    — run one poll cycle (called by systemd timer)
  hub-monitor status  — print current registry to stdout
  hub-monitor events  — print recent events
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread

# ---------------------------------------------------------------------------
# Paths + config
# ---------------------------------------------------------------------------
STATE_DIR = Path(os.environ.get("HUB_MONITOR_STATE_DIR", "/var/lib/hub-monitor"))
REGISTRY_FILE = STATE_DIR / "registry.json"
EVENTS_FILE = STATE_DIR / "events.jsonl"
CONFIG_FILE = Path(os.environ.get("HUB_CLI_CONFIG_PATH", "/etc/hub-cli/config.json"))

LISTEN_HOST = os.environ.get("HUB_MONITOR_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("HUB_MONITOR_PORT", "7700"))

POLL_TIMEOUT = int(os.environ.get("HUB_MONITOR_POLL_TIMEOUT", "5"))   # seconds per PC
RETRY_COUNT  = int(os.environ.get("HUB_MONITOR_RETRY_COUNT", "3"))
RETRY_DELAY  = int(os.environ.get("HUB_MONITOR_RETRY_DELAY", "3"))    # seconds between retries

ORGANISER_SECRET = os.environ.get("ORGANISER_SECRET", "")
MCP_SERVER_URL   = os.environ.get("MCP_SERVER_URL", "")
MCP_PASSWORD     = os.environ.get("MCP_PASSWORD", "")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
def _load_registry() -> dict:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if REGISTRY_FILE.exists():
        try:
            return json.loads(REGISTRY_FILE.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def _save_registry(reg: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    REGISTRY_FILE.write_text(json.dumps(reg, indent=2))


def _log_event(pc_name: str, event: str, extra: dict = None) -> None:
    """Append an event line to events.jsonl."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    entry = {"ts": _now_iso(), "pc": pc_name, "event": event, **(extra or {})}
    with open(EVENTS_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[event] {entry}", flush=True)


def _push_event_to_render(entry: dict) -> None:
    """POST event to Render MCP server to wake it and update its cache."""
    if not MCP_SERVER_URL or not MCP_PASSWORD:
        return
    url = MCP_SERVER_URL.rstrip("/") + "/pc-event"
    payload = json.dumps(entry).encode()
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MCP_PASSWORD}",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[render-push] {resp.status} OK", flush=True)
    except Exception as e:
        print(f"[render-push] failed (non-fatal): {e}", flush=True)


# ---------------------------------------------------------------------------
# Poll logic
# ---------------------------------------------------------------------------
def _poll_pc(pc: dict) -> bool:
    """Return True if PC is reachable. Retries RETRY_COUNT times."""
    url = f"http://{pc['lan_ip']}:{pc['port']}/status"
    for attempt in range(RETRY_COUNT):
        try:
            req = urllib.request.Request(url, headers={"X-Organiser-Secret": ORGANISER_SECRET})
            with urllib.request.urlopen(req, timeout=POLL_TIMEOUT) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        if attempt < RETRY_COUNT - 1:
            time.sleep(RETRY_DELAY)
    return False


def cmd_poll(_args) -> None:
    """Run one full poll cycle — called by systemd timer every 5 minutes."""
    reg = _load_registry()
    if not reg:
        print("[poll] No PCs registered yet.", flush=True)
        return

    changed = []
    for name, pc in reg.items():
        was_online = pc.get("online", False)
        is_online  = _poll_pc(pc)

        pc["online"]    = is_online
        pc["last_poll"] = _now_iso()
        if is_online:
            pc["last_seen"] = _now_iso()

        if is_online != was_online:
            event = "online" if is_online else "offline"
            extra = {"version": pc.get("version", "unknown")}
            _log_event(name, event, extra)
            entry = {"ts": _now_iso(), "pc": name, "event": event, **extra}
            changed.append(entry)

        status = "✅" if is_online else "❌"
        print(f"[poll] {status} {name} ({pc['lan_ip']}:{pc['port']})", flush=True)

    _save_registry(reg)

    # Push all changed events to Render
    for entry in changed:
        _push_event_to_render(entry)


# ---------------------------------------------------------------------------
# Registration HTTP listener
# ---------------------------------------------------------------------------
class RegistrationHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):  # suppress default access log spam
        pass

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok", "ts": _now_iso()})
        elif self.path == "/registry":
            self._respond(200, _load_registry())
        elif self.path == "/events":
            lines = []
            if EVENTS_FILE.exists():
                raw = EVENTS_FILE.read_text().strip().splitlines()
                lines = [json.loads(l) for l in raw[-50:]]  # last 50 events
            self._respond(200, {"events": lines})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/register":
            self._respond(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON"})
            return

        # Auth check — shared ORGANISER_SECRET
        token = data.get("token", "") or self.headers.get("X-Organiser-Secret", "")
        if ORGANISER_SECRET and token != ORGANISER_SECRET:
            self._respond(403, {"error": "unauthorized"})
            return

        required = {"machine_id", "machine_name", "lan_ip", "port"}
        if not required.issubset(data.keys()):
            self._respond(400, {"error": f"missing fields: {required - data.keys()}"})
            return

        name = data["machine_name"]
        reg  = _load_registry()

        was_online = reg.get(name, {}).get("online", False)

        reg[name] = {
            "machine_id":      data["machine_id"],
            "machine_name":    name,
            "lan_ip":          data["lan_ip"],
            "port":            int(data["port"]),
            "version":         data.get("version", "unknown"),
            "platform":        data.get("platform", "windows"),
            "online":          True,
            "last_registered": _now_iso(),
            "last_seen":       _now_iso(),
            "last_poll":       None,
        }
        _save_registry(reg)

        # Fire online event if this is a new registration or comeback
        if not was_online:
            _log_event(name, "online", {"version": data.get("version", "unknown")})
            _push_event_to_render({
                "ts": _now_iso(), "pc": name, "event": "online",
                "version": data.get("version", "unknown"),
            })

        print(f"[register] ✅ {name} @ {data['lan_ip']}:{data['port']}", flush=True)
        self._respond(200, {"status": "registered", "name": name})

    def _respond(self, code: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def cmd_serve(_args) -> None:
    """Start the registration listener."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[serve] hub-monitor listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), RegistrationHandler)
    server.serve_forever()


# ---------------------------------------------------------------------------
# Status / events CLI commands
# ---------------------------------------------------------------------------
def cmd_status(_args) -> None:
    reg = _load_registry()
    if not reg:
        print("No PCs registered.")
        return
    online  = sum(1 for p in reg.values() if p.get("online"))
    offline = len(reg) - online
    print(f"PC Registry ({len(reg)} known, {online} online, {offline} offline):")
    for name, pc in reg.items():
        icon     = "✅" if pc.get("online") else "❌"
        seen     = pc.get("last_seen", "never")
        version  = pc.get("version", "?")
        print(f"  {icon} {name:<20} v{version:<12} last_seen={seen}  {pc['lan_ip']}:{pc['port']}")


def cmd_events(args) -> None:
    if not EVENTS_FILE.exists():
        print("No events yet.")
        return
    lines = EVENTS_FILE.read_text().strip().splitlines()
    limit = getattr(args, "limit", 20)
    for line in lines[-limit:]:
        try:
            e = json.loads(line)
            icon = "🟢" if e.get("event") == "online" else "🔴"
            print(f"  {icon} [{e['ts']}] {e['pc']} → {e['event']}")
        except Exception:
            print(f"  {line}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="hub-monitor — PC registration + polling")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("serve",  help="Start registration HTTP listener")
    sub.add_parser("poll",   help="Run one poll cycle (called by systemd timer)")
    sub.add_parser("status", help="Show current PC registry")
    ev = sub.add_parser("events", help="Show recent events")
    ev.add_argument("--limit", type=int, default=20)

    args = parser.parse_args()
    cmds = {
        "serve":  cmd_serve,
        "poll":   cmd_poll,
        "status": cmd_status,
        "events": cmd_events,
    }
    if args.cmd not in cmds:
        parser.print_help()
        sys.exit(1)
    cmds[args.cmd](args)


if __name__ == "__main__":
    main()
