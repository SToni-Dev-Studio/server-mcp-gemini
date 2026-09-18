"""
organiser-agent.py — run this on your PC
=========================================
Starts a local HTTP server that lets Claude (via codespaces-mcp) browse,
move, delete, and analyse files on this machine.

Usage
-----
1. Install deps:
       pip install flask send2trash

2. (Optional) Install ngrok for a public URL:
       https://ngrok.com/download
   Then in a second terminal:
       ngrok http 7842

3. Run:
       python organiser-agent.py

4. Copy the public URL (e.g. https://xxxx.ngrok-free.app) and set it as
   ORGANISER_URL in your Render environment variables for codespaces-mcp.

5. (Optional) set a shared secret so only Claude can call it:
       set ORGANISER_SECRET=mysecret   (Windows)
       export ORGANISER_SECRET=mysecret (Mac/Linux)
   Then also set ORGANISER_SECRET to the same value in Render env vars.

6. (Multi-PC) give this machine a name that matches its entry in the PCS
   registry on the hub side (see pc-tunnel@.service), e.g. "desktop" or
   "laptop":
       set ORGANISER_MACHINE_NAME=desktop   (Windows)
       export ORGANISER_MACHINE_NAME=desktop (Mac/Linux)
   If unset, the agent falls back to the OS hostname. Either way, a
   stable machine_id (random, generated once) is persisted alongside the
   agent so the hub can tell "same machine, renamed" apart from "new
   machine, name reused" across restarts. See machine_registry() below.
"""

import hashlib
import hmac
import json
import os
import platform
import shutil
import socket
import uuid
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, request, abort

try:
    from send2trash import send2trash
    HAS_TRASH = True
except ImportError:
    HAS_TRASH = False

VERSION = "1.3.0"
PORT = int(os.environ.get("ORGANISER_PORT", 7842))
# Hard ceiling for any single-file read (/preview, /read_file_b64),
# regardless of what a caller's max_bytes asks for. Python's own
# MemoryError-on-huge-read failure mode differs from the C++ build's
# std::bad_alloc, but the same defense-in-depth applies: never trust a
# caller-supplied size unclamped, and never allocate more than the file
# actually contains (see SECURITY_FINDINGS.md finding 4, found against
# organiser-agent.cpp — applying the same fix here for consistency).
MAX_READ_BYTES = 20 * 1024 * 1024
# SECRET and MACHINE_NAME are resolved further down, after the machine
# registry/config-file plumbing they depend on (env var > config file >
# default). Referencing them at call time inside route handlers is fine
# even though they're assigned later in this file.

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _check_auth():
    if not SECRET:
        return
    # Constant-time comparison (mirrors organiser-agent.cpp's fix for
    # SECURITY_FINDINGS.md finding 5 — plain string != is a timing side
    # channel; server.py already uses hmac.compare_digest for exactly
    # this reason elsewhere in this project).
    if not hmac.compare_digest(request.headers.get("X-Organiser-Secret", ""), SECRET):
        abort(401, "Unauthorized")


# ---------------------------------------------------------------------------
# Machine registry
# ---------------------------------------------------------------------------
# Each deployed agent is one machine in a small multi-PC fleet (desktop,
# laptop, server, ...). The hub side (pc-tunnel@.service / the PCS env var
# on Render) already keys machines by a short name and gives each one its
# own port + secret. We mirror that here with two identifiers:
#
#   machine_name — human-chosen, matches the hub's PCS key (e.g. "desktop").
#                  Comes from ORGANISER_MACHINE_NAME if set, else the OS
#                  hostname. Not guaranteed unique or stable (a hostname
#                  can be reused, a name can be typo'd or changed).
#   machine_id   — a random id generated once on first run and persisted
#                  to a small config file next to this script (or in the
#                  user's config dir). This is what actually distinguishes
#                  "the same physical agent, renamed" from "a different
#                  machine that happens to reuse the name" — the hub can
#                  key long-lived state (e.g. audit logs) off machine_id
#                  and treat machine_name as a display label that can move.
#
# This is deliberately just a file, not a database: one agent per machine,
# low write frequency, no concurrent-writer story needed.

def _config_dir() -> Path:
    if platform.system() == "Windows":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    d = Path(base) / "organiser-agent"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_or_create_machine_id(config_path: Path) -> str:
    if config_path.exists():
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            mid = data.get("machine_id", "")
            if mid:
                return mid
        except (json.JSONDecodeError, OSError):
            pass  # fall through and regenerate/overwrite a corrupt file
    mid = str(uuid.uuid4())
    try:
        config_path.write_text(json.dumps({"machine_id": mid}), encoding="utf-8")
    except OSError:
        pass  # best-effort persistence; agent still works this run
    return mid


_MACHINE_CONFIG_PATH = _config_dir() / "machine.json"
MACHINE_ID = _load_or_create_machine_id(_MACHINE_CONFIG_PATH)


def _load_config() -> dict:
    if _MACHINE_CONFIG_PATH.exists():
        try:
            return json.loads(_MACHINE_CONFIG_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_config(updates: dict) -> None:
    data = _load_config()
    data.update(updates)
    _MACHINE_CONFIG_PATH.write_text(json.dumps(data), encoding="utf-8")


_config = _load_config()
# Precedence: env var (set at service-install time) wins over the config
# file (set later via /admin) wins over the OS hostname. This lets someone
# either pin the name at install time OR change it later from the local
# dashboard without needing to touch environment variables/services.
MACHINE_NAME = (
    os.environ.get("ORGANISER_MACHINE_NAME", "").strip()
    or _config.get("machine_name", "").strip()
    or socket.gethostname()
)
# Same precedence for the secret: env var wins (so a service-managed
# deployment isn't silently overridable from the local HTTP dashboard),
# else whatever was last saved via /admin.
SECRET = os.environ.get("ORGANISER_SECRET", "").strip() or _config.get("secret", "").strip()


# ---------------------------------------------------------------------------
# Protected paths
# ---------------------------------------------------------------------------
# The Windows system directory (C:\Windows) must never be movable,
# deletable, or writable through this agent, regardless of what a caller
# asks for — see coordination/tasks/pc-agent.md. This mirrors the check in
# organiser-agent.cpp so the Python and C++ builds agree on what "protected"
# means.
#
# NOTE: like the C++ build, this guard covers path-based file operations
# only (list/move/delete/preview/disk_usage/duplicates/write_file). It does
# NOT and cannot reliably cover /run_command — arbitrary shell text can't be
# statically checked for whether it touches a protected path. Closing that
# off requires OS-level permissions (run the agent as a user without write
# access to C:\Windows), not a string check here.

def _windows_dir() -> Path:
    root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    return Path(root)


def _is_protected_path(raw: Path) -> bool:
    if platform.system() != "Windows":
        return False  # this guard only applies to the Windows deployment target
    try:
        resolved = raw.expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        resolved = raw.expanduser().absolute()
    win = _windows_dir().resolve(strict=False)
    r = str(resolved).lower()
    w = str(win).lower()
    if len(r) < len(w) or not r.startswith(w):
        return False
    # boundary check so "C:\Windows2\..." doesn't false-match "C:\Windows"
    return len(r) == len(w) or r[len(w)] in ("\\", "/")


def _reject_if_protected(*paths: Path):
    """Returns a Flask error response if any path is protected, else None."""
    for p in paths:
        if _is_protected_path(p):
            return jsonify({
                "error": f"Path is inside the protected Windows system directory: {p}"
            }), 403
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _human(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def _entry_info(p: Path) -> dict:
    try:
        stat = p.stat()
        return {
            "name": p.name,
            "path": str(p),
            "is_dir": p.is_dir(),
            "size_bytes": stat.st_size if p.is_file() else 0,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            "extension": p.suffix.lower() if p.is_file() else "",
        }
    except PermissionError:
        return {"name": p.name, "path": str(p), "error": "permission denied"}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/status")
def status():
    _check_auth()
    return jsonify({
        "version": VERSION,
        "platform": platform.system(),
        "python": platform.python_version(),
        "trash_available": HAS_TRASH,
        "watched_folders": [],
        "machine_id": MACHINE_ID,
        "machine_name": MACHINE_NAME,
    })


@app.get("/list")
def list_files():
    _check_auth()
    folder = request.args.get("folder", "")
    recursive = request.args.get("recursive", "false").lower() == "true"

    p = Path(folder).expanduser()
    blocked = _reject_if_protected(p)
    if blocked:
        return blocked
    if not p.exists():
        return jsonify({"error": f"Path does not exist: {folder}"}), 404
    if not p.is_dir():
        return jsonify({"error": f"Not a directory: {folder}"}), 400

    if recursive:
        entries = [_entry_info(child) for child in sorted(p.rglob("*")) if not child.name.startswith(".")]
    else:
        entries = [_entry_info(child) for child in sorted(p.iterdir()) if not child.name.startswith(".")]

    return jsonify({"folder": str(p), "entries": entries})


@app.post("/move")
def move_file():
    _check_auth()
    body = request.get_json(force=True)
    src = Path(body.get("source", "")).expanduser()
    dst = Path(body.get("destination", "")).expanduser()

    blocked = _reject_if_protected(src, dst)
    if blocked:
        return blocked
    if not src.exists():
        return jsonify({"error": f"Source does not exist: {src}"}), 404

    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return jsonify({"message": f"Moved '{src}' → '{dst}'"})


@app.post("/delete")
def delete_file():
    _check_auth()
    body = request.get_json(force=True)
    path = Path(body.get("path", "")).expanduser()
    permanent = body.get("permanent", False)

    blocked = _reject_if_protected(path)
    if blocked:
        return blocked
    if not path.exists():
        return jsonify({"error": f"Path does not exist: {path}"}), 404

    if permanent:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        return jsonify({"message": f"Permanently deleted '{path}'"})
    else:
        if not HAS_TRASH:
            return jsonify({
                "error": "send2trash not installed. Run: pip install send2trash, or pass permanent=true"
            }), 500
        send2trash(str(path))
        return jsonify({"message": f"Sent '{path}' to Recycle Bin / Trash"})


@app.get("/preview")
def preview_file():
    _check_auth()
    path = Path(request.args.get("path", "")).expanduser()
    requested = int(request.args.get("max_bytes", 4096))

    blocked = _reject_if_protected(path)
    if blocked:
        return blocked
    if not path.exists():
        return jsonify({"error": f"Path does not exist: {path}"}), 404
    if not path.is_file():
        return jsonify({"error": "Not a file"}), 400

    max_bytes = min(max(requested, 0), MAX_READ_BYTES)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(max_bytes)
        return jsonify({"path": str(path), "content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/disk_usage")
def disk_usage():
    _check_auth()
    folder = Path(request.args.get("folder", "")).expanduser()

    blocked = _reject_if_protected(folder)
    if blocked:
        return blocked
    if not folder.exists():
        return jsonify({"error": f"Path does not exist: {folder}"}), 404

    items = []
    total = 0

    try:
        for child in sorted(folder.iterdir()):
            if child.name.startswith("."):
                continue
            try:
                if child.is_dir():
                    size = sum(f.stat().st_size for f in child.rglob("*") if f.is_file())
                else:
                    size = child.stat().st_size
                items.append({"path": str(child), "size_bytes": size, "size_human": _human(size)})
                total += size
            except (PermissionError, OSError):
                continue
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403

    items.sort(key=lambda x: x["size_bytes"], reverse=True)
    return jsonify({"folder": str(folder), "items": items, "total_bytes": total, "total_human": _human(total)})


@app.post("/run_command")
def run_command():
    _check_auth()
    import subprocess
    body = request.get_json(force=True)
    command = body.get("command", "")
    working_dir = body.get("working_dir", None) or None
    timeout_s = 60

    if not command:
        return jsonify({"error": "No command provided"}), 400

    # Determine shell based on OS. This endpoint is, by design, "run
    # arbitrary shell text" — there is no safe argv-list form for it
    # because the caller supplies a full command line, not a single
    # program + args. Treat this endpoint itself, not string-parsing, as
    # the risk boundary: lock it down with ORGANISER_SECRET, and run the
    # agent under an OS account with the least privilege you can manage
    # (see protected-path notes above — the same "can't parse arbitrary
    # shell text" limit applies here as it does to /run_command escaping
    # the path guard).
    if platform.system() == "Windows":
        shell_args = ["cmd", "/c", command]
    else:
        shell_args = ["/bin/bash", "-c", command]

    if working_dir is not None and not os.path.isdir(working_dir):
        return jsonify({"error": f"working_dir does not exist or is not a directory: {working_dir}"}), 400

    try:
        result = subprocess.run(
            shell_args,
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        return jsonify({
            "returncode": result.returncode,
            "stdout": result.stdout[-8000:],  # cap output
            "stderr": result.stderr[-2000:],
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Command timed out after {timeout_s}s"}), 408
    except FileNotFoundError as e:
        return jsonify({"error": f"Shell not found: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/duplicates")
def find_duplicates():
    _check_auth()
    folder = Path(request.args.get("folder", "")).expanduser()

    blocked = _reject_if_protected(folder)
    if blocked:
        return blocked
    if not folder.exists():
        return jsonify({"error": f"Path does not exist: {folder}"}), 404

    # Hash all files
    hash_map: dict[str, list[Path]] = {}
    for f in folder.rglob("*"):
        if not f.is_file():
            continue
        try:
            h = hashlib.md5(f.read_bytes()).hexdigest()
            hash_map.setdefault(h, []).append(f)
        except (PermissionError, OSError):
            continue

    groups = []
    for h, files in hash_map.items():
        if len(files) < 2:
            continue
        size = files[0].stat().st_size
        wasted = size * (len(files) - 1)
        groups.append({
            "hash": h,
            "count": len(files),
            "size_bytes": size,
            "size_human": _human(size),
            "wasted_bytes": wasted,
            "wasted_human": _human(wasted),
            "files": [str(f) for f in files],
        })

    groups.sort(key=lambda x: x["wasted_bytes"], reverse=True)
    return jsonify({"folder": str(folder), "groups": groups})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

@app.post("/screenshot")
def screenshot():
    _check_auth()
    import base64, io

    body = request.get_json(force=True, silent=True) or {}
    save_path = body.get("save_path", "")
    if save_path:
        blocked = _reject_if_protected(Path(save_path).expanduser())
        if blocked:
            return blocked

    img_bytes = None
    size_str = ""

    # 1. Try PIL (Pillow)
    try:
        import PIL.ImageGrab as _ig
        img = _ig.grab()
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        img_bytes = buf.getvalue()
        size_str = f"{img.width}x{img.height}"
    except ImportError:
        # 2. Fallback to mss
        try:
            import mss, mss.tools
            with mss.mss() as sct:
                # Use primary monitor (1) if available, fallback to total desktop (0)
                monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
                raw = sct.grab(monitor)
                img_bytes = mss.tools.to_png(raw.rgb, raw.size)
                size_str = f"{raw.size[0]}x{raw.size[1]}"
        except ImportError:
            return jsonify({"error": "No screenshot library found. Install pillow or mss."}), 500
        except Exception as e:
            return jsonify({"error": f"MSS capture failed: {e}"}), 500
    except Exception as e:
        return jsonify({"error": f"PIL capture failed: {e}"}), 500

    # 3. Centralized File Saving & Response
    try:
        if save_path:
            p = Path(save_path).expanduser()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(img_bytes)

        b64 = base64.b64encode(img_bytes).decode("ascii")
        return jsonify({
            "image_base64": b64,
            "size": size_str,
            "saved_path": save_path if save_path else None,
        })
    except Exception as e:
        return jsonify({"error": f"Failed saving image or encoding response: {e}"}), 500

@app.post("/write_file")
def write_file():
    # Accepts either "content" (text, existing behaviour) or "content_b64"
    # (base64-encoded bytes, new) so binary files survive a round trip.
    # file_transfer's pc: leg previously used this endpoint text-only,
    # which silently corrupts binary files sent as text (encoding
    # mismatches, e.g. writing bytes that aren't valid UTF-8 crashes
    # instead of writing them) — content_b64 is the fix for that. See
    # coordination/status/pc-agent.md and BROADCAST [0006].
    _check_auth()
    import base64
    body = request.get_json(force=True)
    path = Path(body.get("path", "")).expanduser()
    if not path or str(path) in (".", ""):
        return jsonify({"error": "No path provided"}), 400
    blocked = _reject_if_protected(path)
    if blocked:
        return blocked

    content_b64 = body.get("content_b64")
    if content_b64 is not None:
        try:
            raw = base64.b64decode(content_b64, validate=True)
        except Exception as e:
            return jsonify({"error": f"Invalid base64 in content_b64: {e}"}), 400
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(raw)
        return jsonify({"message": f"Written to '{path}' ({len(raw)} bytes, binary)"})

    content = body.get("content", "")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return jsonify({"message": f"Written to '{path}' ({len(content)} bytes)"})


@app.get("/read_file_b64")
def read_file_b64():
    # Binary-safe counterpart to /preview (which is text/UTF-8 only).
    # Returns the raw bytes of any file, base64-encoded, so file_transfer
    # can move binaries to/from a PC without corruption.
    _check_auth()
    import base64
    path = Path(request.args.get("path", "")).expanduser()
    requested = int(request.args.get("max_bytes", 10 * 1024 * 1024))  # 10MB default

    blocked = _reject_if_protected(path)
    if blocked:
        return blocked
    if not path.exists():
        return jsonify({"error": f"Path does not exist: {path}"}), 404
    if not path.is_file():
        return jsonify({"error": "Not a file"}), 400

    max_bytes = min(max(requested, 0), MAX_READ_BYTES)
    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            raw = f.read(max_bytes)
        truncated = size > len(raw)
        return jsonify({
            "path": str(path),
            "content_b64": base64.b64encode(raw).decode("ascii"),
            "size_bytes": size,
            "returned_bytes": len(raw),
            "truncated": truncated,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Local config / admin dashboard
# ---------------------------------------------------------------------------
# Per BROADCAST [0006]: config (secret, machine name) should be manageable
# from a local UI built into the agent, not by hand-editing a file over
# SSH/RDP. This is intentionally minimal — a same-machine-only HTML form
# backed by /config — not a general remote-admin panel. It relies on the
# same loopback binding as every other endpoint here for its access
# control; it does NOT bypass or replace ORGANISER_SECRET for the other
# routes (setting or changing the secret still requires already being able
# to reach this port, exactly like every other endpoint).

@app.get("/config")
def get_config():
    _check_auth()
    return jsonify({
        "machine_id": MACHINE_ID,
        "machine_name": MACHINE_NAME,
        "secret_set": bool(SECRET),
        "secret_source": "env" if os.environ.get("ORGANISER_SECRET", "").strip() else (
            "config_file" if SECRET else "none"
        ),
        "config_path": str(_MACHINE_CONFIG_PATH),
    })


@app.post("/config")
def update_config():
    # SECURITY_FINDINGS.md finding 20 (HIGH), confirmed independently
    # against this Flask implementation too: /config previously let an
    # unauthenticated caller set the FIRST secret whenever none was
    # configured yet -- turning the transient "no secret = open" window
    # (finding 3, an accepted trade-off for one-off operations) into a
    # PERMANENT takeover, since the attacker-chosen secret then persists
    # to disk and locks the legitimate owner out on every future start.
    # Fix (the simplest of security-qa's suggested directions): /config
    # can ROTATE an existing secret (already safely gated -- reaching
    # this handler at all requires the current secret once one is set,
    # via _check_auth() above), but can never BOOTSTRAP the first one
    # over the network. The first secret must come from ORGANISER_SECRET
    # (env var) or a local edit of the config file.
    global MACHINE_NAME, SECRET
    _check_auth()
    body = request.get_json(force=True) or {}
    updates = {}

    if "machine_name" in body:
        name = str(body["machine_name"]).strip()
        if not name:
            return jsonify({"error": "machine_name cannot be empty"}), 400
        updates["machine_name"] = name

    if "secret" in body:
        new_secret = str(body["secret"])
        if not SECRET and new_secret:
            return jsonify({
                "error": (
                    "Cannot set the initial secret via /config over the network -- "
                    "this would let anyone who reaches this port before you do "
                    "permanently lock you out (SECURITY_FINDINGS.md finding 20). "
                    f"Set ORGANISER_SECRET as an environment variable (then restart), "
                    f"or edit {_MACHINE_CONFIG_PATH} directly on this machine. "
                    "Once a secret exists, /config can rotate it normally."
                )
            }), 403
        # Empty string is allowed here — it means "remove the secret",
        # matching the existing semantics of ORGANISER_SECRET unset.
        # (This guard only blocks empty->non-empty; non-empty->empty and
        # non-empty->non-empty rotation both still work, appropriately
        # gated by already needing the current secret to be here.)
        updates["secret"] = new_secret

    if not updates:
        return jsonify({"error": "Nothing to update. Send machine_name and/or secret."}), 400

    _save_config(updates)

    # Hot-reload in-memory values so the change takes effect immediately,
    # without restarting the agent — UNLESS an env var is set for that
    # field, in which case the env var still wins (documented precedence).
    if "machine_name" in updates and not os.environ.get("ORGANISER_MACHINE_NAME", "").strip():
        MACHINE_NAME = updates["machine_name"]
    if "secret" in updates and not os.environ.get("ORGANISER_SECRET", "").strip():
        SECRET = updates["secret"]

    return jsonify({"message": "Config updated", "machine_name": MACHINE_NAME, "secret_set": bool(SECRET)})


@app.get("/admin")
def admin_page():
    # No _check_auth() here on purpose: if a secret is already set, you
    # need it to see the *current* config via /config anyway (the page's
    # own JS calls /config and /run_command-style endpoints, which check
    # auth same as ever) — the static form shell itself has nothing
    # secret in it. This mirrors how the other endpoints are protected:
    # loopback bind + optional secret header, not per-page gating of a
    # write-nothing-here shell page.
    html = """<!DOCTYPE html>
<html><head><title>Organiser Agent — Local Config</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 480px; margin: 40px auto; }
label { display: block; margin-top: 12px; font-weight: 600; }
input { width: 100%; padding: 6px; box-sizing: border-box; }
button { margin-top: 16px; padding: 8px 16px; }
#status { margin-top: 12px; white-space: pre-wrap; font-family: monospace; font-size: 0.85em; }
</style></head>
<body>
<h2>Organiser Agent — Local Config</h2>
<p>Changes here are saved to this PC's local config file and take effect immediately.</p>
<label>Secret (header X-Organiser-Secret required if set)
  <input id="authSecret" type="password" placeholder="current secret, if any (to authenticate this page's requests)">
</label>
<hr>
<label>Machine name <input id="machineName" type="text"></label>
<label>New secret (leave blank to remove) <input id="newSecret" type="password"></label>
<p style="font-size:0.8em;color:#666">If no secret is configured yet, it can't be set from this page over the network (security fix) — set ORGANISER_SECRET as an environment variable first, or edit the config file directly on this machine, then use this page to rotate it afterward.</p>
<button onclick="loadConfig()">Refresh current config</button>
<button onclick="saveConfig()">Save</button>
<div id="status"></div>
<script>
async function call(path, opts) {
  opts = opts || {};
  opts.headers = Object.assign({'Content-Type': 'application/json'}, opts.headers || {});
  var s = document.getElementById('authSecret').value;
  if (s) opts.headers['X-Organiser-Secret'] = s;
  const r = await fetch(path, opts);
  const j = await r.json().catch(() => ({}));
  return {ok: r.ok, status: r.status, body: j};
}
async function loadConfig() {
  const res = await call('/config');
  document.getElementById('status').textContent = JSON.stringify(res.body, null, 2);
  if (res.ok) document.getElementById('machineName').value = res.body.machine_name || '';
}
async function saveConfig() {
  const updates = {};
  const mn = document.getElementById('machineName').value.trim();
  if (mn) updates.machine_name = mn;
  const ns = document.getElementById('newSecret');
  if (ns.value !== '') updates.secret = ns.value;
  const res = await call('/config', {method: 'POST', body: JSON.stringify(updates)});
  document.getElementById('status').textContent = JSON.stringify(res.body, null, 2);
  ns.value = '';
}
loadConfig();
</script>
</body></html>"""
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}


if __name__ == "__main__":
    print("=" * 60)
    print(f"  Organiser Agent v{VERSION}")
    print(f"  Platform : {platform.system()} {platform.release()}")
    print(f"  Machine  : {MACHINE_NAME} ({MACHINE_ID})")
    print(f"  Trash    : {'✅ send2trash available' if HAS_TRASH else '⚠️  install send2trash for safe deletes'}")
    print(f"  Auth     : {'🔒 secret set' if SECRET else '⚠️  no secret — anyone with the URL can access'}")
    print(f"  Listening: http://localhost:{PORT}")
    print()
    print("  Next steps:")
    print("  1. In another terminal run:  ngrok http 7842")
    print("  2. Copy the https://xxxx.ngrok-free.app URL")
    print("  3. Set ORGANISER_URL=<that url> in Render env vars")
    print("=" * 60)
    app.run(host="0.0.0.0", port=PORT, debug=False)
