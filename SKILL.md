---
name: custom-mcp
description: >
  Use this skill whenever the user wants to interact with their personal
  infrastructure via the Github-MCP connector. Covers: PC file management
  (Windows, one or more machines), Linux home server commands/services/logs,
  GitHub Codespaces lifecycle, Plex media server, file transfers between
  all of them, and a browser-based admin dashboard for Render/server config.
  Trigger on phrases like: "check my server", "sort my downloads", "list
  files on my PC", "run a command on the server", "what's downloading",
  "queue anime", "open a codespace", "move files", "screenshot my screen",
  "check disk space", "what services are running", "search Plex",
  "transfer a file", "test everything", "run diagnostics". Always consult
  this skill when Github-MCP tools are available and the request involves
  the user's personal machines.
---

# Custom-MCP Skill

This MCP server (`codespaces-mcp`, deployed on Render) bridges Claude to
personal infrastructure via a single HTTPS endpoint: one or more Windows
PCs, a Linux home server, GitHub Codespaces, and Plex. ~50 tools across
6 groups, plus a browser admin dashboard. Always pick the most specific tool.

---

## Architecture

```
Claude (claude.ai)
      │  HTTPS /mcp
      ▼
Render (codespaces-mcp — Python/FastMCP)
      │
      ├── GitHub API  ──────────────────► GitHub Codespaces (gh CLI over SSH)
      │
      ├── SSH (Tailscale)  ────────────► Linux home server  (stoni-room-serve)
      │         (tailscale ssh — one authenticated channel, reused for
      │          every server_* tool AND every pc_* tool)
      │                                       │
      │                                       ├── curl 127.0.0.1:<port A> ──► PC "desktop"
      │                                       ├── curl 127.0.0.1:<port B> ──► PC "laptop"
      │                                       └── ...one loopback tunnel per configured PC
      │
      ├── Plex HTTP API  ──────────────► Plex Media Server (192.168.101.105:32400)
      │
      └── Render API  ──────────────────► this service's own env vars / redeploys
                                            (via the /admin dashboard)
```

**Key facts:**
- Server is `stoni-room-serve` (Ubuntu, always-on, Tailscale IP)
- Render never opens a raw connection to any PC, or even to the server's
  public IP for PC traffic — everything folds into the one `tailscale ssh`
  channel. Every server-side PC tunnel is loopback-only (127.0.0.1).
- Multiple PCs are configured via the `PCS` env var (a JSON registry);
  every `pc_*`/`transfer__*_pc` tool takes an optional `pc` parameter
  (default `"default"`) to pick which one.
- GitHub has three token slots: primary, secondary, tertiary, with
  automatic fallback on 401/403.
- A browser admin dashboard at `/admin` can update this service's Render
  env vars, trigger redeploys, run server commands, and run the full
  diagnostics sweep — without going through Claude at all.

---

## Group 1 — PC Tools (Windows, one or more machines)

Requires `organiser-agent.exe` running on each PC (C++ build, ~2 MB RAM idle).
Every tool below takes an optional `pc: str = "default"` — omit it for a
single-PC setup, or pass a name (see `pc_list_configured`) for a specific machine.

| Tool | What it does |
|------|-------------|
| `pc_list_configured()` | List every PC in the `PCS` registry (name + port). |
| `pc_organiser_status(pc?)` | Ping a PC's agent. Run first if PC tools fail. |
| `pc_list_files(folder, recursive?, pc?)` | List files. Start here before moving/deleting. |
| `pc_move_file(source, destination, pc?)` | Move or rename. Creates parent dirs. |
| `pc_delete_file(path, permanent?, pc?)` | Recycle Bin by default; `permanent=true` to skip. |
| `pc_read_file_preview(path, max_bytes?, pc?)` | Peek at a text file before acting on it. |
| `pc_disk_usage(folder, pc?)` | Space breakdown, sorted largest-first. |
| `pc_find_duplicates(folder, pc?)` | Find identical files by content hash. |
| `pc_run_command(command, working_dir?, pc?)` | Run PowerShell/cmd. Output capped at 8 KB. |
| `pc__screenshot(save_path?, pc?)` | Capture screen → base64 PNG for Claude to view. |

**PC paths always use Windows format:** `C:\Users\Sepiso Toni\Downloads\`

### File Organisation Rules

| Destination | What goes there |
|-------------|----------------|
| `Downloads\` | Temporary only — nothing lives here permanently |
| `Documents\UmbrellaOS\` | All UmbrellaOS project files |
| `Documents\Chess companion\` | ChessPulse project |
| `Documents\Moon-Assistant\` | Moon Assistant project |
| `Downloads\Minecraft\` | Minecraft jars, mods, APKs |
| `Downloads\Installers\` | Setup executables not yet installed |
| `Downloads\ISOs\` | Disk images |
| `Downloads\Docs\` | PDFs, chat logs, handoffs |
| `Downloads\Media\` | Videos, images, WhatsApp files |
| `Downloads\Dev\` | Scripts, benchmark files |
| `Downloads\Backups\` | Config backups, recovery keys |

---

## Group 2 — Linux Server Tools

SSH via Tailscale. Server: `stoni-room-serve` (Ubuntu, always-on).

| Tool | What it does |
|------|-------------|
| `server_status` | All services + disk + RAM overview. **Start here.** |
| `server_run_command(command)` | Run any shell command over SSH. |
| `server_list_files(path, recursive?)` | Browse filesystem. |
| `server_read_file(path, tail?, head?)` | Read file; `tail=50` for logs. |
| `server_write_file(path, content)` | Write/overwrite a file (base64 transfer). |
| `server_move_file(source, destination)` | Move or rename. |
| `server_delete_file(path)` | Delete a single file (not directory). |
| `server_disk_usage(path?)` | Disk breakdown. Default: `/` |
| `server_process_list` | Top CPU/RAM processes. |
| `server_service_control(service, action)` | systemd: start/stop/restart/status/enable/disable |
| `server_tail_log(log_path, lines?)` | Tail any log. |
| `server_cron_list` | All cron jobs (user + root + system). |
| `server_network_info` | Interfaces, open ports, active connections. |
| `server_docker_status` | Docker containers + images. |
| `server_find_duplicates(path)` | Duplicates by content hash. |
| `server_download_anime(anime_name, quality?)` | Search + queue via Sonarr. |
| `server_download_status` | qBittorrent queue + pipeline log. |
| `server_pipeline_log` | Full Plex download pipeline log (last 50 lines). |

**Server paths use Linux format:** `/mnt/ssd/`, `/home/sepisotoni/`, `/var/log/`

**Blocked commands** (server_run_command will reject): `rm -rf /`, `mkfs`,
`dd if=`, `> /dev/sda`, `shutdown now`, `halt` — this is a footgun-prevention
nicety, not a real security boundary; the tool intentionally runs arbitrary
commands. Every path/service/message value passed to this group is
shell-quoted (`shlex.quote`) before being sent over SSH, so paths or commit
messages containing apostrophes/quotes are handled safely.

### Key Service Names
| Service | Port |
|---------|------|
| `plexmediaserver` | 32400 |
| `sonarr` | 8989 |
| `jackett` | 9117 |
| `qbittorrent` | 8080 |
| `plex-watch` | — |

### Key Server Paths
| Path | Contents |
|------|----------|
| `/mnt/ssd/plex/downloads/` | Active downloads |
| `/media/plex/anime/library/` | Finished anime |
| `/var/log/plex-download.log` | Pipeline log |
| `/var/lib/sonarr/config.xml` | Sonarr API key |

---

## Group 3 — Plex Media Server

Plex runs on the Linux server at `192.168.101.105:32400`.

| Tool | What it does |
|------|-------------|
| `plex_get_status` | Version + active sessions. |
| `plex_get_libraries` | All libraries with their keys. |
| `plex_search(query, media_type?)` | Search by name. Returns up to 10 results. |
| `plex_get_recently_added(count?)` | Recently added items. Default: 10. |
| `plex_scan_library(library_key?)` | Trigger scan. Default: all. |

---

## Group 4 — GitHub Codespaces

| Tool | What it does |
|------|-------------|
| `list_codespaces` | All codespaces + state (Running/Shutdown/Available). |
| `create_codespace(repo_full_name, branch?, machine_type?)` | Create new codespace — pass a bigger `machine_type` for heavy/AI workloads, then use `exec_command` to install whatever's needed (Ollama, etc.). |
| `exec_command(codespace_name, command, timeout?)` | SSH into codespace + run command. Auto-wakes. |
| `list_workspace_files(codespace_name, path?)` | File tree (maxdepth 2, hides dotfiles). |
| `read_codespace_file(codespace_name, file_path)` | Read a file (uses `cat`). |
| `write_codespace_file(codespace_name, content, file_path)` | Write via base64. |
| `get_git_status(codespace_name)` | `git status --short -b` output. |
| `create_git_commit_and_push(codespace_name, commit_message, branch?, repo_path?)` | Stage all tracked, commit, push. |
| `stop_codespace(codespace_name)` | Stop to save credits. |
| `set_machine_type(codespace_name, machine_type)` | Resize machine (properly sent as PATCH). |
| `list_forwarded_ports(codespace_name)` | Forwarded ports + dev server URLs. |
| `rebuild_codespace(codespace_name)` | Full devcontainer rebuild. |

There's no separate "launch an AI codespace" tool — `create_codespace` with
a bigger `machine_type` plus `exec_command` to install Ollama does the same
thing without a redundant tool to maintain.

### Known Codespaces

| Codespace Name | Repo | Machine |
|----------------|------|---------|
| `sturdy-tribble-r49xx959q7wxhwg5` | sepisotoni/UmbrellaOS | 4c/16GB/32GB |
| `sturdy-adventure-r76jwp9xwqr25696` | sepisotoni/Minecraft | 4c/16GB/32GB |
| `turbo-tribble-5g699676j4wxcv4rv` | openclaw/openclaw | 2c/8GB/32GB |
| `solid-adventure-pjv66v5v5x75h79j` | sepisotoni/Moon-assistant | 2c/8GB/32GB |
| `bug-free-waffle-5g699676j47w34j99` | sepisotoni/codespaces-mcp | 2c/8GB/32GB |
| `fictional-memory-q7rxxr5rj769f99xq` | sepisotoni/codespaces-mcp | 2c/8GB/32GB |

Codespaces can expire/reset their registration after periods of inactivity —
if `exec_command` 404s on a known name, try the other codespaces-mcp
codespace, or `create_codespace` a fresh one.

**Machine type strings:** `standardLinux32Gb` (16 GB RAM), `premiumLinux` (32 GB RAM)

**Important:** Codespaces start as Shutdown. `exec_command` auto-wakes them.
First command after wake may take **30–60 seconds** — this is normal, retry
if it times out.

### GitHub Token Accounts

| Account | Used for |
|---------|---------|
| `primary` | Default for most operations |
| `secondary` | Fallback on billing/auth errors |
| `tertiary` | Reserved for heavy/AI workloads |

Auto-fallback chain: primary → secondary → tertiary on 401/403.
`check_account_status` reports which are valid and which GitHub user each
authenticates as (useful since primary/secondary can be different accounts).

---

## Group 5 — File Transfers

| Tool | Direction | Notes |
|------|-----------|-------|
| `transfer__pc_to_sandbox(remote_path, local_save_path, pc?)` | PC → Claude sandbox | Text files only; binary unsupported |
| `transfer__sandbox_to_pc(local_path, remote_dest_path, pc?)` | Sandbox → PC | UTF-8 text |
| `transfer__sandbox_to_codespace(local_path, codespace_name, remote_path)` | Sandbox → Codespace | Via base64 or exec fallback |
| `transfer__server_to_sandbox(remote_path, local_save_path)` | Linux server → Sandbox | Via SSH cat |
| `transfer__sandbox_to_server(local_path, remote_dest_path)` | Sandbox → Linux server | Via base64 SSH write |

**Sandbox paths:** `/home/claude/` (Linux format)
**PC paths:** `C:\Users\Sepiso Toni\...` (Windows format)

**PC ↔ Server two-hop pattern:**
- PC → Server: `transfer__pc_to_sandbox` then `transfer__sandbox_to_server`
- Server → PC: `transfer__server_to_sandbox` then `transfer__sandbox_to_pc`

---

## Group 6 — Diagnostics & Admin

| Tool | What it does |
|------|-------------|
| `run_diagnostics()` | Tests every configured subsystem in one pass: each GitHub token, Codespaces API, Plex, the Linux server, every configured PC's organiser-agent, and the Render API. Reports pass/fail/skip with a reason for each. |

The same sweep is available as a **Run all tests** button on the browser
admin dashboard at `/admin` (see below) — run it right after changing any
config to confirm nothing broke.

### Admin dashboard (`/admin`)

A password-gated (separate cookie login, not the MCP bearer token) browser
page on the deployed service, for configuring things without going through
Claude at all:
- View/update this service's own Render env vars (`PCS`,
  `MCP_SERVER_PASSWORD`, tokens, anything) and trigger a redeploy —
  updates go through Render's single-variable endpoint, never the
  bulk-replace one, so they can't accidentally wipe unlisted vars.
- Run one-off commands on the Linux server.
- Run the full diagnostics sweep.

Needs `ADMIN_PASSWORD` set (falls back to `MCP_SERVER_PASSWORD` if not),
and `RENDER_API_KEY` for the Render-management features specifically
(server commands and diagnostics work without it).

---

## Common Workflows

### Sort / Organise Downloads
```
1. pc_list_files("C:\Users\Sepiso Toni\Downloads")
2. Categorise each file by extension and name using the table above
3. pc_move_file(source, destination) for each file
4. pc_delete_file for junk: files ending in (1), .zip.txt, __pycache__, old logs
```

### Check Server Health
```
1. server_status            — services, disk, RAM at a glance
2. server_tail_log(...)     — drill into any failing service log
3. server_service_control   — restart if needed
```

### Queue Anime Download
```
1. server_download_status   — see what's already running
2. server_download_anime("show name") — search Sonarr + queue
```

### Work on a Codespace Project
```
1. list_codespaces                      — find the right one
2. exec_command(name, "git status")     — auto-wakes
3. write_codespace_file(...)            — make changes
4. create_git_commit_and_push(...)      — commit & push
5. stop_codespace(name)                 — save credits when done
```

### Screenshot / What's on Screen
```
1. pc__screenshot() — Claude receives base64 PNG and can describe/analyse it
   (pass pc="laptop" etc. for a specific machine if more than one is configured)
```

### Run a Script on the Server
```
# One-off:
server_run_command("python3 /home/sepisotoni/script.py")

# Persistent (survives disconnect):
transfer__sandbox_to_server("/home/claude/script.py", "/home/sepisotoni/script.py")
server_run_command("nohup python3 /home/sepisotoni/script.py > /tmp/out.log 2>&1 &")
```

### After changing any config
```
1. run_diagnostics() — or the admin dashboard's "Run all tests" button
2. Fix whatever shows fail; skip is fine if that subsystem isn't configured
```

---

## Error Reference

| Error | Cause | Fix |
|-------|-------|-----|
| PC tool error / empty response | organiser-agent not running, or its tunnel is down | `pc_organiser_status(pc)` for a checklist; ask user to check Task Scheduler on that PC and `systemctl status pc-tunnel@<name>` on the server |
| `Unknown PC 'x'` | `pc` name not in the `PCS` registry | `pc_list_configured()` to see valid names |
| Server SSH timeout | Server offline or Tailscale down | `server_run_command("tailscale status")` first, or `run_diagnostics()` |
| Codespace first-command timeout | Codespace waking up | Retry once after 30s |
| Codespace 404 on a known name | Codespace registration expired/stale | Try the other codespaces-mcp codespace, or `create_codespace` a fresh one |
| `Invalid Host header` on `/mcp` | `MCP_ALLOWED_HOST` not set in Render | Set to the Render external hostname (no https://) |
| `/mcp` returns 503 "misconfigured" | `MCP_SERVER_PASSWORD` unset on a public deployment | Set it — the server fails closed rather than serving unauthenticated on the public internet |
| GitHub 401/403 | Token expired or wrong scope | Auto-fallback tries secondary/tertiary; `check_account_status` shows which; otherwise refresh PAT |
| Plex tools empty | `PLEX_TOKEN` not set | Add to Render env vars |
| Admin dashboard "not configured" on Render panel | `RENDER_API_KEY`/`RENDER_SERVICE_ID` not set | Add `RENDER_API_KEY`; `RENDER_SERVICE_ID` defaults to this service already |

---

## Deployment Reference (Render)

### Required Environment Variables
| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | Primary GitHub PAT (Codespaces scope) |
| `GITHUB_TOKEN_SECONDARY` | Secondary PAT (fallback) |
| `GITHUB_TOKEN_TERTIARY` | Tertiary PAT (heavy/AI workloads) |
| `MCP_SERVER_PASSWORD` | Bearer token for Claude connector auth — **required** once this is on a public host; the server fails closed without it |
| `ADMIN_PASSWORD` | Password for the `/admin` dashboard (falls back to `MCP_SERVER_PASSWORD` if unset) |
| `RENDER_API_KEY` | Lets `/admin` manage this service's env vars + trigger redeploys |
| `RENDER_SERVICE_ID` | Optional — defaults to `srv-da11cupt0dsc73aq2qq0` (this service) |
| `TAILSCALE_AUTH_KEY` | Tailscale ephemeral key for server SSH |
| `SSH_PRIVATE_KEY` | Private key for SSH to `stoni-room-serve` |
| `SERVER_HOST` | Tailscale IP of `stoni-room-serve` |
| `SERVER_USER` | `sepisotoni` |
| `PCS` | JSON registry of PCs, e.g. `{"desktop": {"port": 7842, "secret": "..."}}` — see §Group 1 |
| `PLEX_URL` | `http://192.168.101.105:32400` |
| `PLEX_TOKEN` | Plex auth token |
| `MCP_ALLOWED_HOST` | Render external hostname (auto-detected on Render) |

Legacy single-PC fallback (used only if `PCS` isn't set at all):
`ORGANISER_PORT` (default 7842), `ORGANISER_SECRET`.

### MCP Endpoint
`https://<render-app>.onrender.com/mcp`

### Health Check
`GET https://<render-app>.onrender.com/healthz` → `{"status": "ok"}`

### Status Page
`GET https://<render-app>.onrender.com/` → JSON with auth/admin/Plex/server/PC/token config status

### Admin Dashboard
`https://<render-app>.onrender.com/admin` → browser UI, see Group 6 above

---

## organiser-agent (PC) — C++ Build

The PC-side agent is a **pure C++ HTTP server**, no external framework.
Idle RAM: ~2 MB. CPU: 0%. The old Python/Flask equivalent used ~50 MB idle.

### Endpoints
| Method | Path | What it does |
|--------|------|-------------|
| GET | `/status` | Version, platform, agent health |
| GET | `/list?folder=&recursive=` | List files in a directory |
| POST | `/move` | Move/rename a file (cross-drive fallback included) |
| POST | `/delete` | Delete (Recycle Bin or permanent) |
| GET | `/preview?path=&max_bytes=` | Read first N bytes of a file (binary-safe) |
| GET | `/disk_usage?folder=` | Disk usage breakdown |
| POST | `/run_command` | Execute shell command |
| GET | `/duplicates?folder=` | Find duplicate files by content hash |
| POST | `/screenshot` | Capture screen → base64 image |
| POST | `/write_file` | Write content to a file |

Auth: `X-Organiser-Secret` header (must match that PC's entry in `PCS`).
Binds to loopback only — never listens on a LAN-reachable address; the
server's `pc-tunnel@<name>.service` is what forwards to it, itself also
loopback-only on the server side.

Blocks any file-touching endpoint from resolving inside the real Windows
system directory (queried via `GetWindowsDirectoryA`, not hardcoded, so
it's correct even if Windows is on a different drive). `/run_command` is
NOT covered by this guard — there's no reliable way to parse arbitrary
shell text to know whether it'll touch the system directory, so a command
sent through that endpoint has full reach by design.

### Running on PC
```
# Windows — Task Scheduler (run at logon, hidden):
"C:\Program Files\OrganiserAgent\organiser-agent.exe"

# Or manually:
set ORGANISER_SECRET=<this PC's secret>
set ORGANISER_PORT=<this PC's port>
organiser-agent.exe
```

### How traffic reaches it (no ngrok, any number of PCs)
```
Render (server.py)
  └─► tailscale ssh → stoni-room-serve
        └─► curl http://127.0.0.1:<this PC's port>/...
              └─► pc-tunnel@<name>.service (loopback-only forward)
                    └─► organiser-agent.exe on that PC
```

Set up the tunnel as a systemd template unit on the Linux server — see
`pc-tunnel@.service` in this repo and `BUILD_AND_SETUP.md` §4 for the
full per-PC setup (one `.conf` file + one `systemctl enable --now` per PC).
