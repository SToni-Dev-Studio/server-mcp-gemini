#!/usr/bin/env python3
"""
Hub PC Registration Listener & Poller (Proposal pc-autodiscovery-v2)
=====================================================================
Runs on the Linux hub. Listens on HTTP port 7845 for PC auto-registrations,
maintains /var/lib/hub-monitor/pc_registry.json, polls registered PCs every
5 minutes over the LAN, logs state changes to pc_events.jsonl, and exposes
the active PC registry for server.py.
"""

import asyncio
import json
import os
import time
from typing import Dict, Any
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
import httpx

REGISTRY_FILE = os.environ.get("PC_REGISTRY_FILE", "/tmp/pc_registry.json")
EVENTS_FILE = os.environ.get("PC_EVENTS_FILE", "/tmp/pc_events.jsonl")
PORT = int(os.environ.get("HUB_REG_PORT", "7845"))

_registry: Dict[str, Dict[str, Any]] = {}


def load_registry():
    global _registry
    if os.path.exists(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, "r") as f:
                _registry = json.load(f)
        except Exception:
            _registry = {}


def save_registry():
    try:
        os.makedirs(os.path.dirname(os.path.abspath(REGISTRY_FILE)), exist_ok=True)
        with open(REGISTRY_FILE + ".tmp", "w") as f:
            json.dump(_registry, f, indent=2)
        os.replace(REGISTRY_FILE + ".tmp", REGISTRY_FILE)
    except Exception as e:
        print(f"Error saving PC registry: {e}")


def log_event(machine_name: str, event_type: str, details: dict):
    try:
        os.makedirs(os.path.dirname(os.path.abspath(EVENTS_FILE)), exist_ok=True)
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "machine_name": machine_name,
            "event": event_type,
            "details": details,
        }
        with open(EVENTS_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"Error logging PC event: {e}")


async def handle_register(request: Request) -> JSONResponse:
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    machine_name = data.get("machine_name", "").strip() or "unknown"
    machine_id = data.get("machine_id", "")
    port = data.get("port", 7842)
    secret = data.get("secret", "")
    version = data.get("version", "")
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Deduplicate: remove any old entry with matching machine_id or machine_name
    to_delete = []
    for k, v in _registry.items():
        if (machine_id and v.get("machine_id") == machine_id) or k == machine_name:
            to_delete.append(k)
    for k in to_delete:
        _registry.pop(k, None)

    _registry[machine_name] = {
        "machine_id": machine_id,
        "machine_name": machine_name,
        "lan_ip": client_ip,
        "port": port,
        "secret": secret,
        "version": version,
        "last_registered": time.time(),
        "status": "online",
    }
    save_registry()
    log_event(machine_name, "online", {"lan_ip": client_ip, "port": port})

    return JSONResponse(
        {"status": "registered", "machine_name": machine_name, "lan_ip": client_ip}
    )


async def handle_list_pcs(request: Request) -> JSONResponse:
    include_offline = request.query_params.get("include_offline", "false").lower() in (
        "true",
        "1",
        "yes",
    )
    now = time.time()
    result = []
    for pc in list(_registry.values()):
        # Prune offline entries older than 24 hours
        if pc.get("status") == "offline" and (
            now - pc.get("last_registered", 0) > 86400
        ):
            _registry.pop(pc.get("machine_name"), None)
            continue
        if include_offline or pc.get("status") == "online":
            result.append(pc)
    save_registry()
    return JSONResponse({"pcs": result})


async def poll_pcs_loop():
    """Polls registered PCs every 5 minutes (retry 3x @ 3s on miss)."""
    while True:
        await asyncio.sleep(300)
        for name, pc in list(_registry.items()):
            ip = pc.get("lan_ip")
            port = pc.get("port", 7842)
            url = f"http://{ip}:{port}/status"
            headers = {}
            if pc.get("secret"):
                headers["x-organiser-secret"] = pc["secret"]

            success = False
            for attempt in range(3):
                try:
                    async with httpx.AsyncClient(timeout=3) as client:
                        r = await client.get(url, headers=headers)
                    if r.status_code == 200:
                        success = True
                        break
                except Exception:
                    pass
                if attempt < 2:
                    await asyncio.sleep(3)

            old_status = pc.get("status", "unknown")
            new_status = "online" if success else "offline"
            if old_status != new_status:
                pc["status"] = new_status
                save_registry()
                log_event(name, new_status, {"lan_ip": ip, "port": port})


app = Starlette(
    routes=[
        Route("/register", handle_register, methods=["POST"]),
        Route("/pcs", handle_list_pcs, methods=["GET"]),
    ]
)

if __name__ == "__main__":
    import uvicorn

    load_registry()
    loop = asyncio.get_event_loop()
    loop.create_task(poll_pcs_loop())
    uvicorn.run(app, host="0.0.0.0", port=PORT)
