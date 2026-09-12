# Build & Setup Guide — organiser-agent C++ + Multi-PC + Admin Dashboard

See `ARCHITECTURE.md` first if you haven't — it covers the auth model,
request routing, and known limitations this guide assumes. See
`SKILL.md` for the full tool reference once this is running.

## 1. Build on Windows (MSVC)

Open **Developer Command Prompt for VS** (search in Start menu):

```cmd
cd C:\Users\Sepiso Toni\Documents\organiser-agent
cl /EHsc /O2 /std:c++17 organiser-agent.cpp /Fe:organiser-agent.exe
```

That produces `organiser-agent.exe` (~500 KB, zero dependencies, ~2 MB RAM idle).
Links gdi32.lib/user32.lib automatically via `#pragma comment` in the source
— no extra `/link` flags needed, whether built here or by CI.

**No Python, no pip, no Flask, no ngrok.**

Do this once per PC you want Claude to reach (see §4 for multi-PC).

> **Build `organiser-agent.cpp`, not `organiser-agent.py`.** The Python
> file is a legacy reference implementation — it has no path-traversal
> protection and its own comments describe an older ngrok-based
> deployment model that doesn't match §4/§6 below. See `ARCHITECTURE.md`
> for the full comparison. Don't run it as a production agent.

Don't want to build it yourself? A prebuilt `organiser-agent.exe` is
published on every push to `main` and on every tagged release — see
"Getting a prebuilt build" below, or use the installer script in
`scripts/install-organiser-agent.ps1` (§1b) to fetch, verify, and
install it in one step.

---

## 1a. Install into Program Files

Building requires no special rights, but placing the exe in `Program Files`
does — copy it over from an **elevated** (Run as Administrator) Command Prompt:

```cmd
mkdir "C:\Program Files\OrganiserAgent"
copy organiser-agent.exe "C:\Program Files\OrganiserAgent\organiser-agent.exe"
```

Everything below refers to `C:\Program Files\OrganiserAgent\organiser-agent.exe`.
Launching it afterwards does **not** need elevation — only this copy step does.

---

## 1b. Or: use the installer script (recommended)

`scripts/install-organiser-agent.ps1` does §1/§1a/§3 in one step: it
downloads the latest (or a specific tagged) `organiser-agent.exe` from
this repo's GitHub Releases, verifies its SHA-256 checksum against the
release's published `.sha256` file, installs it to
`C:\Program Files\OrganiserAgent\`, preserves your existing
`ORGANISER_SECRET`/`ORGANISER_PORT` if you're upgrading rather than
installing fresh, registers/refreshes the Scheduled Task from §3, and
verifies the agent actually responds on `/status` afterward.

```powershell
# Run in an elevated PowerShell prompt:
irm https://raw.githubusercontent.com/<owner>/<repo>/main/scripts/install-organiser-agent.ps1 | iex

# Or, having downloaded the script:
.\install-organiser-agent.ps1 -Secret "your_secret_here" -Port 7842
```

See the script's own header comment for the full flag list (`-Version`
to pin a specific release tag instead of "latest", `-Uninstall`, etc).
If you'd rather do each step by hand (or the installer fails and you
need to see why), §1–§3 below are the manual equivalent.

---

## 2. Set the secret and port (each PC needs its own)

Pick a port for this PC (7842 for the first one, 7843 for a second, etc.)
and a secret — these get matched up in the `PCS` registry later. **The
secret you set here and the `secret` you put in that PC's `PCS` entry on
the Render side must match exactly — nothing else enforces the pairing**
(see "Known limitations" in `ARCHITECTURE.md`).

```cmd
set ORGANISER_SECRET=<a_secret_just_for_this_pc>
set ORGANISER_PORT=7842
organiser-agent.exe
```

Or create a `.env.bat` that you double-click to start it manually:
```bat
@echo off
set ORGANISER_SECRET=your_secret_here
set ORGANISER_PORT=7842
organiser-agent.exe
```

---

## 3. Windows Task Scheduler (auto-start at logon, hidden)

Run this once in an **admin** PowerShell (adjust the secret/port for this PC):

```powershell
$trigger = New-ScheduledTaskTrigger -AtLogOn

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit 0 `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

$principal = New-ScheduledTaskPrincipal `
    -UserId "Sepiso Toni" `
    -LogonType Interactive `
    -RunLevel Limited

$env_action = New-ScheduledTaskAction `
    -Execute "cmd.exe" `
    -Argument '/c "set ORGANISER_SECRET=your_secret_here && set ORGANISER_PORT=7842 && C:\Program Files\OrganiserAgent\organiser-agent.exe"'

Register-ScheduledTask `
    -TaskName "OrganiserAgent" `
    -Action $env_action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Force
```

To verify it's running:
```powershell
Get-ScheduledTask -TaskName "OrganiserAgent" | Select State
```

(The installer script in §1b does this step for you and keeps the task
name/secret/port in sync on upgrade.)

---

## 4. Linux server — one SSH tunnel per PC (no ngrok, multi-PC ready)

The tunnel unit is templated (`pc-tunnel@.service`) — one instance per PC,
each with its own name, IP, and port. Adding a second PC later is just
another `.conf` file and another `systemctl enable --now`.

```bash
# 1. Find the PC's LAN IP (run on that PC):
ipconfig | findstr "IPv4"
# e.g. 192.168.1.50

# 2. Make sure the server can SSH to that PC without a password:
ssh-copy-id sepisotoni@192.168.1.50

# 3. Copy the templated unit (once — covers every PC):
sudo cp pc-tunnel@.service /etc/systemd/system/

# 4. Create a small config file for THIS PC (pick a unique name, e.g. "desktop"):
sudo mkdir -p /etc/pc-tunnel
sudo tee /etc/pc-tunnel/desktop.conf <<'EOF'
PC_IP=192.168.1.50
PORT=7842
EOF

# 5. Enable and start THIS instance:
sudo systemctl daemon-reload
sudo systemctl enable --now pc-tunnel@desktop

# 6. Check:
sudo systemctl status pc-tunnel@desktop
# Should show: active (running)

# 7. Test from the server itself (the tunnel is loopback-only — 127.0.0.1,
#    not 0.0.0.0 — since Render only ever reaches it by SSHing in here first):
curl http://127.0.0.1:7842/status
# Should return JSON with version and platform
```

**Adding a second PC** ("laptop", say): repeat steps 1–2 and 4–7 with a
different name (`laptop`), a different port (`7843`), and its own secret
in step 2 of §2 above. No changes to the systemd unit itself — that's
the point of the templated `@.service`.

---

## 5. Render environment variables

In Render dashboard → your `codespaces-mcp` service → Environment
(or from the admin dashboard at `/admin` — see §7):

```
PCS = {"desktop": {"port": 7842, "secret": "your_secret_here"}}
```

Add more PCs as more `{"name": {"port": ..., "secret": ...}}` entries in
that same JSON object. `port` must match the PC's `.conf` file on the
server; `secret` must match that PC's `ORGANISER_SECRET`.

(Single-PC legacy setups: `ORGANISER_PORT` / `ORGANISER_SECRET` still work
as a fallback if `PCS` isn't set at all — but `PCS` is the supported path
going forward, especially once you have more than one PC.)

Other env vars worth setting at the same time — see `.secrets.example`
for the complete list with descriptions:
```
MCP_SERVER_PASSWORD   — required in production; the server refuses all
                        /mcp requests if this is unset on a public host
ADMIN_PASSWORD        — for the /admin dashboard (falls back to
                        MCP_SERVER_PASSWORD if you don't set this)
RENDER_API_KEY        — lets /admin manage this service's own env vars
                        and trigger redeploys (get one from Render →
                        Account Settings → API Keys)
RENDER_SERVICE_ID     — optional; defaults to this service's real ID
                        already
```

Render is the documented/supported deployment target — see
`ARCHITECTURE.md` for the current Fly.io status (present in the repo,
not confirmed maintained).

---

## 6. Traffic Flow (no ngrok, any number of PCs)

```
Claude (claude.ai)
    │ HTTPS
    ▼
Render (codespaces-mcp)
    │ SSH via Tailscale  (tailscale ssh — same channel for every
    │                     server_* tool AND every pc_* tool)
    ▼
stoni-room-serve (Linux)
    │ curl http://127.0.0.1:<that PC's port>/...
    ▼
pc-tunnel@<name>.service (loopback-only forward)
    ▼
organiser-agent.exe on that PC
```

No PC is ever publicly reachable, and Render never opens a raw connection
to any PC or even to the server's public/Tailscale IP for this traffic —
only the one already-authenticated `tailscale ssh` channel is used, for
everything. Only the Linux server needs to be reachable (via Tailscale).
Full detail (including exactly how a request is packaged for that SSH
channel) is in `ARCHITECTURE.md`.

---

## 7. Admin dashboard — configure everything from a browser

Visit `https://<your-render-app>.onrender.com/admin`.

- Log in with `ADMIN_PASSWORD` (or `MCP_SERVER_PASSWORD` if you didn't set one).
- **Render settings**: view/update this service's env vars (`PCS`,
  `MCP_SERVER_PASSWORD`, tokens, anything), then click **Trigger redeploy**
  for changes to take effect (Render doesn't auto-deploy env var changes).
- **Linux server**: run one-off commands directly from the page.
- **Diagnostics**: click **Run all tests** to check every GitHub token,
  the Codespaces API, the Linux server, and every configured PC's
  organiser-agent in one pass — pass/fail/skip with a reason for each.

The same diagnostics are available from chat too, as the `run_diagnostics`
tool — useful right after changing any config.

---

## 8. Verify end-to-end

From Claude, run `pc_list_configured` to see registered PCs, then
`pc_organiser_status` (optionally with a `pc` name) — it should return:
```
✅ 'desktop' reachable via stoni-room-serve → loopback:7842
Version : 2.0.0-cpp
Platform: Windows
```

Or just run `run_diagnostics` for a full pass/fail sweep of everything at once.

---

## Getting a prebuilt organiser-agent.exe

Every push to `main` that touches `organiser-agent.cpp` publishes
`organiser-agent.exe` to a rolling `latest` GitHub Release (see
`.github/workflows/build-organiser-agent.yml`). Every tagged release
(`vX.Y.Z`) additionally publishes it — alongside a checksum file and
`server.py`/docs — as part of that version (see
`.github/workflows/release.yml`). Either way:

```
https://github.com/<owner>/<repo>/releases/latest/download/organiser-agent.exe
https://github.com/<owner>/<repo>/releases/latest/download/organiser-agent.exe.sha256
```

`scripts/install-organiser-agent.ps1` (§1b) fetches and verifies this
for you; grab it manually only if you have a reason to skip the
installer.

---

## Known limitations

See `ARCHITECTURE.md`'s "Known limitations" section for the full,
current list (PC secret pairing isn't enforced, `*_run_command` tools
are intentionally close to unrestricted, no CI test/lint step for
`server.py` yet, Fly vs Render status, etc.) — kept in one place instead
of duplicated here so it doesn't drift.
