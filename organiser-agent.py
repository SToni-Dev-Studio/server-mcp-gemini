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
"""

import hashlib
import os
import platform
import shutil
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, request, abort

try:
    from send2trash import send2trash
    HAS_TRASH = True
except ImportError:
    HAS_TRASH = False

VERSION = "1.0.0"
PORT = int(os.environ.get("ORGANISER_PORT", 7842))
SECRET = os.environ.get("ORGANISER_SECRET", "").strip()

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _check_auth():
    if not SECRET:
        return
    if request.headers.get("X-Organiser-Secret", "") != SECRET:
        abort(401, "Unauthorized")


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
# Routes & Embedded Dashboard
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Organiser Agent — Local Dashboard</title>
<style>
  :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8; --accent: #38bdf8; --border: #334155; --success: #22c55e; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 24px; line-height: 1.5; }
  .container { max-width: 900px; margin: 0 auto; }
  header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
  h1 { font-size: 1.5rem; font-weight: 700; color: var(--accent); }
  .badge { background: #064e3b; color: var(--success); padding: 4px 10px; border-radius: 999px; font-size: 0.85rem; font-weight: 600; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 18px; }
  .card h2 { font-size: 1.1rem; margin-bottom: 12px; color: var(--accent); }
  label { display: block; font-size: 0.85rem; color: var(--muted); margin-bottom: 6px; }
  input, button { width: 100%; padding: 10px 12px; border-radius: 6px; border: 1px solid var(--border); background: #0b1120; color: var(--text); font-size: 0.95rem; margin-bottom: 12px; }
  button { background: #0284c7; border: none; font-weight: 600; cursor: pointer; color: #fff; }
  button:hover { background: #0369a1; }
  pre { background: #0b1120; padding: 12px; border-radius: 6px; border: 1px solid var(--border); overflow-x: auto; font-size: 0.85rem; color: #cbd5e1; max-height: 240px; }
  .msg { padding: 10px; border-radius: 6px; margin-bottom: 12px; display: none; font-size: 0.9rem; }
  .msg.ok { background: #064e3b; color: #86efac; display: block; }
  .msg.err { background: #7f1d1d; color: #fca5a5; display: block; }
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>Organiser Agent Dashboard</h1>
      <p style="color:var(--muted); font-size:0.85rem;">Built-in Executive & Secrets Controller</p>
    </div>
    <div class="badge">● Online</div>
  </header>
  <div class="grid">
    <div class="card">
      <h2>Local Agent Status</h2>
      <p><strong>Platform:</strong> <span id="st-plat">...</span></p>
      <p><strong>Version:</strong> <span id="st-ver">...</span></p>
      <p><strong>Auth:</strong> <span id="st-auth">...</span></p>
      <button style="margin-top:12px;" onclick="fetchStatus()">Refresh Status</button>
    </div>
    <div class="card">
      <h2>Control Secrets</h2>
      <div id="sec-msg" class="msg"></div>
      <label for="new-sec">ORGANISER_SECRET:</label>
      <input type="password" id="new-sec" placeholder="Enter new secret key...">
      <button onclick="updateSecret()">Update Secret</button>
    </div>
  </div>
  <div class="card" style="margin-bottom:24px;">
    <h2>Quick Directory Browser</h2>
    <div style="display:flex; gap:8px;">
      <input type="text" id="dir-path" placeholder="C:\\ or /home..." style="margin-bottom:0;">
      <button style="width:120px; margin-bottom:0;" onclick="browseDir()">Browse</button>
    </div>
    <pre id="dir-output" style="margin-top:12px;">Enter a path above and click Browse to view files.</pre>
  </div>
</div>
<script>
async function fetchStatus() {
  try {
    const res = await fetch('/status');
    const d = await res.json();
    document.getElementById('st-plat').textContent = d.platform || 'Unknown';
    document.getElementById('st-ver').textContent = d.version || 'Unknown';
    document.getElementById('st-auth').textContent = d.has_secret ? 'Secret Active' : 'Open (No Secret)';
  } catch(e) { document.getElementById('st-plat').textContent = 'Error'; }
}
async function updateSecret() {
  const sec = document.getElementById('new-sec').value.trim();
  const msg = document.getElementById('sec-msg');
  if(!sec) { msg.className='msg err'; msg.textContent='Secret cannot be empty'; return; }
  try {
    const res = await fetch('/set_secret', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ secret: sec })
    });
    const d = await res.json();
    if(res.ok) {
      msg.className='msg ok';
      msg.textContent=d.message || 'Secret updated!';
      document.getElementById('new-sec').value='';
      fetchStatus();
    } else {
      msg.className='msg err';
      msg.textContent=d.error || 'Failed';
    }
  } catch(e) { msg.className='msg err'; msg.textContent=String(e); }
}
async function browseDir() {
  const p = document.getElementById('dir-path').value.trim();
  if(!p) return;
  const out = document.getElementById('dir-output');
  out.textContent = 'Loading...';
  try {
    const res = await fetch('/list?folder=' + encodeURIComponent(p));
    const d = await res.json();
    out.textContent = JSON.stringify(d, null, 2);
  } catch(e) { out.textContent = 'Error: ' + e; }
}
fetchStatus();
</script>
</body>
</html>"""

@app.get("/")
@app.get("/dashboard")
def dashboard():
    return DASHBOARD_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}

@app.post("/set_secret")
def set_secret():
    data = request.get_json(silent=True) or {}
    sec = data.get("secret", "").strip()
    if not sec:
        return jsonify({"error": "Secret cannot be empty"}), 400
    global SECRET
    SECRET = sec
    with open(".secrets", "w", encoding="utf-8") as f:
        f.write(f"ORGANISER_SECRET={sec}\n")
    return jsonify({"success": True, "message": "Secret updated successfully"})

@app.get("/status")
def status():
    return jsonify({
        "version": VERSION,
        "platform": platform.system(),
        "python": platform.python_version(),
        "trash_available": HAS_TRASH,
        "has_secret": bool(SECRET),
        "watched_folders": [],
    })


@app.get("/list")
def list_files():
    _check_auth()
    folder = request.args.get("folder", "")
    recursive = request.args.get("recursive", "false").lower() == "true"

    p = Path(folder).expanduser()
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
    max_bytes = int(request.args.get("max_bytes", 4096))

    if not path.exists():
        return jsonify({"error": f"Path does not exist: {path}"}), 404
    if not path.is_file():
        return jsonify({"error": "Not a file"}), 400

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
    import subprocess, sys
    body = request.get_json(force=True)
    command = body.get("command", "")
    working_dir = body.get("working_dir", None) or None

    if not command:
        return jsonify({"error": "No command provided"}), 400

    # Determine shell based on OS
    if platform.system() == "Windows":
        shell_args = ["cmd", "/c", command]
    else:
        shell_args = ["/bin/bash", "-c", command]

    try:
        result = subprocess.run(
            shell_args,
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return jsonify({
            "returncode": result.returncode,
            "stdout": result.stdout[-8000:],  # cap output
            "stderr": result.stderr[-2000:],
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out after 60s"}), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/duplicates")
def find_duplicates():
    _check_auth()
    folder = Path(request.args.get("folder", "")).expanduser()

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
    for files in hash_map.values():
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
    body = request.get_json(force=True) or {}
    save_path = body.get("save_path", "")
    try:
        import PIL.ImageGrab as _ig
        img = _ig.grab()
    except ImportError:
        try:
            import mss, mss.tools
            with mss.mss() as sct:
                raw = sct.grab(sct.monitors[0])
                img_bytes = mss.tools.to_png(raw.rgb, raw.size)
                b64 = base64.b64encode(img_bytes).decode()
                if save_path:
                    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
                    with open(save_path, "wb") as f:
                        f.write(img_bytes)
                return jsonify({
                    "image_base64": b64,
                    "size": f"{raw.size[0]}x{raw.size[1]}",
                    "saved_path": save_path if save_path else None,
                })
        except ImportError:
            return jsonify({"error": "No screenshot library found. Run: pip install Pillow or pip install mss"}), 500

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    img_bytes = buf.getvalue()
    b64 = base64.b64encode(img_bytes).decode()
    if save_path:
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(img_bytes)
    return jsonify({
        "image_base64": b64,
        "size": f"{img.width}x{img.height}",
        "saved_path": save_path if save_path else None,
    })


@app.post("/write_file")
def write_file():
    _check_auth()
    body = request.get_json(force=True)
    path = Path(body.get("path", "")).expanduser()
    content = body.get("content", "")
    if not path:
        return jsonify({"error": "No path provided"}), 400
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return jsonify({"message": f"Written to '{path}' ({len(content)} bytes)"})


if __name__ == "__main__":
    print("=" * 60)
    print(f"  Organiser Agent v{VERSION}")
    print(f"  Platform : {platform.system()} {platform.release()}")
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
