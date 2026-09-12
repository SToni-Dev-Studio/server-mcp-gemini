# Architecture

What this actually is, how the pieces talk to each other, and where the
edges are. For "how do I set this up," see `BUILD_AND_SETUP.md`. For the
full tool-by-tool reference, see `SKILL.md`.

## What this is

A single remote MCP server (`server.py`, Python/FastMCP, deployed on
Render) that gives Claude ~45 narrow tools across five areas instead of
one broad "do anything" tool:

1. GitHub Codespaces lifecycle (create/stop/rebuild/resize, exec a
   command inside one, read/write files, git status/commit/push).
2. A Linux home server, reached over `tailscale ssh` (services, files,
   logs, cron, docker, disk, network, a Sonarr/qBittorrent download
   pipeline).
3. One or more Windows PCs, each running a companion agent
   (`organiser-agent`), reached through the Linux server.
4. A single generic `file_transfer` tool moving bytes between any two of
   the above (plus this server's own sandbox), in any direction.
5. Diagnostics + a password-gated browser admin dashboard at `/admin`
   for configuring the deployment itself without going through Claude.

> Plex support (all `plex_*` tools, `PLEX_URL`/`PLEX_TOKEN`, the Plex
> diagnostics/service checks) has been removed entirely and is not
> coming back. If you see a Plex reference anywhere else in this repo,
> it's stale — flag it.

## Request flow

```
Claude (claude.ai)
      │  HTTPS  Authorization: Bearer <MCP_SERVER_PASSWORD>
      ▼
Render — server.py (Python/FastMCP)
      │
      ├─ GitHub API ──────────────► GitHub Codespaces (gh CLI over SSH)
      │
      ├─ tailscale ssh ───────────► Linux home server
      │   (ONE authenticated channel, reused for every server_* tool
      │    AND every pc_* tool — see "PC routing" below)
      │        │
      │        ├─ curl 127.0.0.1:<port A> ──► PC "desktop"
      │        ├─ curl 127.0.0.1:<port B> ──► PC "laptop"
      │        └─ ...one loopback tunnel per configured PC
      │
      └─ Render API ──────────────► this service's own env vars / redeploys
                                     (only used by /admin)
```

`file_transfer` doesn't add a new channel — it reads from one of
sandbox/server/pc/codespace and writes to another using the same
mechanisms above (local disk, the SSH channel, or the GitHub API),
transporting the bytes as base64 internally so binary data survives.

## Auth layers (three, independent)

| Layer | Protects | Mechanism |
|---|---|---|
| MCP endpoint | `/mcp` (every tool call) | `MCP_SERVER_PASSWORD` compared constant-time against the `Authorization: Bearer` header. **Fails closed**: if unset on a detected public deployment (Render/Fly host present), every request is rejected rather than allowed through. Not required for a bare local run with no host env vars. |
| Admin dashboard | `/admin` and its `/admin/api/*` endpoints | Separate cookie-based login (`ADMIN_PASSWORD`, falls back to `MCP_SERVER_PASSWORD`). Stateless HMAC-signed `<expiry>.<signature>` cookie — no session store. If neither `ADMIN_COOKIE_SECRET` nor `ADMIN_PASSWORD` is set, the server generates a random per-process secret and **verification is gated the same way login is** — i.e. disabled, not "protected by an unknown random string" (a real regression test, `tests/test_admin_cookie_auth.py`, guards against a past bug where a hardcoded fallback secret let anyone forge a session). |
| PC organiser-agent | Each `pc_*` tool call and `file_transfer`'s `pc:` leg | `X-Organiser-Secret` header, sent by `server.py` from that PC's entry in the `PCS` registry, checked by the agent against its own `ORGANISER_SECRET` env var. **Nothing enforces that the two actually match** beyond you setting them to the same value on both sides — see "Known limitations." |

GitHub API calls have their own layer: three optional token slots
(`GITHUB_TOKEN`, `_SECONDARY`, `_TERTIARY`) with automatic fallback to
the next one on a 401/403.

## PC routing, in detail

Render never opens a connection to a PC, or even to the Linux server's
public/Tailscale IP for PC traffic. Every `pc_*` call (and `file_transfer`
whenever a `pc:` address is involved) folds into the *same* `tailscale
ssh` exec channel used for every `server_*` tool:

```
Render (server.py: _organiser_ssh_request)
    │ tailscale ssh <user>@<server>  "<base64 python blob> | python3 -"
    ▼
Linux server
    │ that inline python script does: urllib → http://127.0.0.1:<PC's port>/...
    ▼
pc-tunnel@<name>.service   (systemd template, one instance per PC,
    │                       an SSH port-forward, loopback-only on
    │                       both ends — see pc-tunnel@.service)
    ▼
organiser-agent(.exe) on that PC   (binds 127.0.0.1 only)
```

The request/response body itself is shipped as a base64-encoded Python
source blob rather than a hand-built curl command line — this sidesteps
shell-quoting entirely for arbitrary path/content characters (Windows
paths with spaces or backslashes, apostrophes, etc.), rather than
relying on quoting being correct everywhere.

Multiple PCs are configured via the `PCS` env var (a JSON object: name →
`{"port": ..., "secret": ...}`); every `pc_*` tool takes an optional
`pc: str = "default"`, and `file_transfer` addresses a PC as
`pc:<name>:<path>`. If `PCS` is unset, the server falls back to a single
implicit `"default"` PC built from the legacy
`ORGANISER_PORT`/`ORGANISER_SECRET` env vars.

## `file_transfer`: one tool, four endpoint kinds

Replaced five narrower `transfer__*` tools (`pc_to_sandbox`,
`sandbox_to_pc`, `sandbox_to_codespace`, `server_to_sandbox`,
`sandbox_to_server`), which covered only 5 of the ~10 meaningful
directed pairs and read local files in **text mode** — silently
corrupting any binary file. `file_transfer(source, destination)` moves
bytes between any two of: `sandbox:<path>`, `server:<path>`,
`pc:<name>:<path>`, `codespace:<name>[@account]:<path>` — in either
direction, any pairing, transported as base64 so binary data survives.
Capped at 15 MB per transfer. See `SKILL.md`'s Group 4 for the full
address-format reference and examples.

**Current limitation:** the `pc:` leg still goes through
organiser-agent's `/preview`/`/write_file` endpoints, which are
text-only — a binary file with a PC as either end fails cleanly rather
than corrupting, but can't complete. This is tracked as PC-agent work
(a base64-safe endpoint pair) in `coordination/tasks/pc-agent.md`.

## organiser-agent: two implementations, one is current

| | `organiser-agent.py` | `organiser-agent.cpp` |
|---|---|---|
| Status | Legacy reference implementation | **The one actually deployed/documented** |
| Runtime | Python + Flask + send2trash | Zero-dependency C++ (winsock2 on Windows) |
| Idle footprint | ~50 MB RAM | ~2 MB RAM, 0% CPU |
| Windows system-dir protection on file ops | **None** | Yes — every file-touching endpoint (`/list`, `/move`, `/delete`, `/preview`, `/disk_usage`, `/write_file`) rejects paths inside the real Windows directory (queried via `GetWindowsDirectoryA`, not hardcoded) |
| `/run_command` protection | N/A (no protection anywhere) | **Deliberately unprotected** — there's no reliable way to string-parse arbitrary shell/PowerShell text to know if it'll touch a protected path, so this endpoint has full reach by design |
| Deployment model described in its own header comment | ngrok + `ORGANISER_URL` (**stale** — doesn't match how traffic actually reaches it, see "PC routing" above) | Task Scheduler + the tailscale-ssh-tunnel model (accurate) |
| Machine identity | None | None — `/status` returns version/platform, not a name (see `coordination/tasks/pc-agent.md`) |
| File transfer safety | N/A | `/preview` and `/write_file` are text-only today — the reason for `file_transfer`'s PC-side limitation above |

**If you're setting up a new PC, build and run `organiser-agent.cpp`**
(or use `scripts/install-organiser-agent.ps1`, which fetches a prebuilt
release). `organiser-agent.py` is kept in the repo as a reference/
prototype; its own setup instructions describe a different,
no-longer-used deployment model and it lacks the path protections the
C++ build has. Don't run it as your production agent.

## Deployment target: Render (documented/supported); Fly: present, unconfirmed

Everything actually wired up — the `/admin` dashboard's Render API
calls, the hardcoded default `RENDER_SERVICE_ID`, every setup doc — is
Render-specific. `fly.toml` and the generic `Dockerfile` are present in
the repo and would plausibly work on Fly (`server.py` auto-detects
`FLY_APP_NAME` for `MCP_ALLOWED_HOST` the same way it does
`RENDER_EXTERNAL_HOSTNAME`), but nothing in this docs pass could confirm
a Fly deployment is actually live or maintained. Treat Render as the
supported path until `coordination/status/hub-cicd.md` says otherwise.

## Known limitations

- **organiser-agent.py lacks path protection.** Covered above — don't
  run it in production.
- **`file_transfer`'s PC leg is text-only.** Covered above.
- **PC secret pairing isn't enforced.** The `PCS` registry's `secret`
  for a given PC name must be manually kept in sync with that PC's own
  `ORGANISER_SECRET`. Nothing on either side verifies the pairing is
  correct beyond the header check itself — set them to matching values
  when you provision a PC, and there's no drift-detection if one side
  changes later. `run_diagnostics` will report a 401/timeout if they've
  drifted, but won't tell you *why*.
- **No PC identity/registration handshake.** An agent doesn't know its
  own configured name; it's implicit in which tunnel/port you're
  routing through. `coordination/tasks/pc-agent.md` covers giving each
  agent build awareness of its own name, plus moving the PC-side
  config (secret, name, allowed paths) into the agent itself instead of
  external env vars/scheduled-task args.
- **`/run_command` (both agent builds, and `server_run_command`) is
  intentionally close to unrestricted.** `server_run_command`'s blocklist
  is explicitly documented in-code as "a footgun-prevention nicety, not
  a real security boundary." Treat every `*_run_command` tool as
  equivalent to a real shell on that machine.
- **`write_codespace_file` doesn't verify its own write.** It always
  reports success even if the target directory doesn't exist yet (the
  underlying command has no `mkdir -p` and the tool doesn't check the
  exec result). Create the parent directory first if it might be new.
- **`create_git_commit_and_push` only stages already-tracked files**
  (`git add -u`) — brand-new untracked files need an explicit `git add`
  first.
- **No CI test/lint step for `server.py` yet.** Only
  `tests/test_admin_cookie_auth.py` and `tests/test_file_transfer.py`
  exist today. See `coordination/status/hub-cicd.md` for whether a real
  CI workflow has landed.
- **Fly vs Render** — see above.
- **No rate limiting** on the MCP bearer-token check beyond the
  constant-time comparison itself; a very determined attacker with
  network access could still attempt many guesses over time.
- **Admin dashboard is single-admin by design** — one shared password,
  one HMAC secret, no per-user accounts. Fine for personal
  infrastructure, not intended for multiple distinct admins.

## Where things live (quick map)

| File | Role |
|---|---|
| `server.py` | The MCP server — every tool definition, the admin dashboard, all auth |
| `organiser-agent.cpp` | Windows PC agent — build and run this one |
| `organiser-agent.py` | Legacy reference implementation — do not deploy |
| `pc-tunnel@.service` | systemd template, one instance per configured PC |
| `scripts/install-organiser-agent.ps1` | Fetches, verifies, and installs a release build of the PC agent |
| `Dockerfile`, `start.sh` | Container build/entrypoint for server.py |
| `fly.toml` | Fly.io config (see "Deployment target" above) |
| `.secrets.example` | Full list of every optional/required env var, for local runs |
| `tests/` | `test_admin_cookie_auth.py` (plain script), `test_file_transfer.py` (pytest, uses fixtures — run with `pytest`, not `python <file>`) |
| `coordination/` | Multi-agent build coordination — not part of the shipped product |
