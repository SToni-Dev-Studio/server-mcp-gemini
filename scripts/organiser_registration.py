# ---------------------------------------------------------------------------
# PC Self-Registration — paste into organiser-agent.py startup
# This runs once at startup + every 4 hours to re-announce to hub-monitor
# ---------------------------------------------------------------------------

import json
import os
import platform
import socket
import threading
import time
import urllib.request
import uuid
from pathlib import Path

# Config from env or fallback
HUB_MONITOR_URL    = os.environ.get("HUB_MONITOR_URL", "http://stoni-room-serve.local:7700")
ORGANISER_SECRET   = os.environ.get("ORGANISER_SECRET", "")
ORGANISER_PORT     = int(os.environ.get("ORGANISER_PORT", "7800"))
MACHINE_ID_FILE    = Path(os.environ.get("MACHINE_ID_FILE", r"C:\ProgramData\mcp-hub-tools\machine_id"))
VERSION            = "0.3.0"
RE_REGISTER_EVERY  = 4 * 3600  # re-announce every 4 hours


def _get_machine_id() -> str:
    """Stable per-machine UUID stored on disk."""
    MACHINE_ID_FILE.parent.mkdir(parents=True, exist_ok=True)
    if MACHINE_ID_FILE.exists():
        return MACHINE_ID_FILE.read_text().strip()
    mid = str(uuid.uuid4())
    MACHINE_ID_FILE.write_text(mid)
    return mid


def _get_lan_ip() -> str:
    """Get primary LAN IP (not loopback)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _register_with_hub() -> bool:
    """POST registration payload to hub-monitor. Returns True on success."""
    payload = json.dumps({
        "machine_id":   _get_machine_id(),
        "machine_name": platform.node(),
        "lan_ip":       _get_lan_ip(),
        "port":         ORGANISER_PORT,
        "version":      VERSION,
        "platform":     f"windows/{platform.version()}",
        "token":        ORGANISER_SECRET,
    }).encode()

    url = HUB_MONITOR_URL.rstrip("/") + "/register"
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Organiser-Secret": ORGANISER_SECRET,
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            print(f"[register] ✅ Registered as '{body.get('name')}' with hub-monitor", flush=True)
            return True
    except Exception as e:
        print(f"[register] ⚠️  Could not reach hub-monitor at {url}: {e}", flush=True)
        return False


def _registration_loop():
    """Background thread — register on startup then re-announce periodically."""
    # Try immediately, retry up to 3x with backoff if hub isn't ready yet
    for attempt in range(3):
        if _register_with_hub():
            break
        time.sleep(30 * (attempt + 1))

    # Re-announce every 4 hours (handles IP changes, hub restarts)
    while True:
        time.sleep(RE_REGISTER_EVERY)
        _register_with_hub()


def start_registration_background():
    """Call this from organiser-agent startup."""
    t = threading.Thread(target=_registration_loop, daemon=True)
    t.start()
    print("[register] Registration thread started", flush=True)
