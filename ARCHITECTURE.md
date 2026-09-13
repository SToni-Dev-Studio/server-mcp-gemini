# Architecture

What this actually is, how the pieces talk to each other, and where the
edges are. For "how do I set this up," see `BUILD_AND_SETUP.md`. For the
full tool-by-tool reference, see `SKILL.md`.

## What this is

A single remote MCP server (`server.py`, Python/FastMCP, deployed on
Render) that gives Claude 43 narrow tools across five areas instead of
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
- **`file_transfer`'s PC leg is text-only.** Covered above. (The underlying binary-safe agent endpoints now exist on `agent/pc-agent`, pending merge + server.py wiring — see "Pending: agent/pc-agent's fixes" below.)
- **PC secret pairing isn't enforced.** The `PCS` registry's `secret`
  for a given PC name must be manually kept in sync with that PC's own
  `ORGANISER_SECRET`. Nothing on either side verifies the pairing is
  correct beyond the header check itself — set them to matching values
  when you provision a PC, and there's no drift-detection if one side
  changes later. `run_diagnostics` will report a 401/timeout if they've
  drifted, but won't tell you *why*.
- **No PC identity/registration handshake.** An agent doesn't know its
  own configured name; it's implicit in which tunnel/port you're
  routing through. Addressed on `agent/pc-agent` (machine_id/
  machine_name via `/status`), pending merge — see "Pending:
  agent/pc-agent's fixes" below.
- **`/run_command` (both agent builds, and `server_run_command`) is
  intentionally close to unrestricted.** `server_run_command`'s blocklist
  is explicitly documented in-code as "a footgun-prevention nicety, not
  a real security boundary." Treat every `*_run_command` tool as
  equivalent to a real shell on that machine. This is a deliberate design
  choice, not a bug — but see the next item for a *specific, confirmed*
  vulnerability in how one of its arguments is handled, which is a bug.
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

## Confirmed security findings (agent/security-qa)

`agent/security-qa`'s findings are now merged to `main` — see
`SECURITY_FINDINGS.md` at repo root for full detail, severities, and
suggested fixes, and `coordination/status/security-qa.md` for how each
was verified. Summarizing the confirmed, actionable ones here so they
aren't easy to miss:

- **Command injection via `working_dir` in organiser-agent's
  `/run_command`** (separate from, and worse than, the "intentionally
  unrestricted by design" point above — this is an argument-handling
  bug, not a design choice). Confirmed exploitable on Linux; the
  equivalent Windows path is suspected but **unverified** (no Windows
  test target was available for that pass).
- **`/preview`'s `max_bytes` is unbounded and pre-allocates before
  checking the real file size**, causing a crash-the-process DoS —
  confirmed, and it **chains straight through server.py**:
  `pc_read_file_preview`'s `max_bytes` parameter is forwarded with no
  clamping, so this is reachable from an ordinary MCP tool call, not
  just from talking to the agent directly.
- **organiser-agent's secret comparison isn't constant-time**, unlike
  `server.py`'s `hmac.compare_digest` everywhere else in this project —
  a timing side-channel on the PC-agent secret specifically.
- **Oversized request bodies to organiser-agent (>~64KB) are silently
  truncated and still report success** — confirmed by sending a 200KB
  body and getting a corrupted 65,333-byte file back with an HTTP 200.
  This is a silent-data-corruption bug, not just a size-limit gap.
- **`pc-tunnel@.service` uses `StrictHostKeyChecking=no`** — a low-severity
  LAN MITM exposure.
- **`file_transfer` has two silent-fallback footguns**: an empty PC name
  silently resolves to `"default"` instead of erroring, and an unknown
  `@account` suffix silently falls back to `"auto"` instead of erroring.
  Neither corrupts anything, but both can mask a typo as if it worked.
- **`file_transfer`'s read side has no upfront size cap** — the write
  side enforces the 15 MB limit documented above, but an oversized
  *source* is fully read and base64-decoded before being rejected,
  rather than being rejected up front.

Also worth knowing, as reassurance rather than a limitation: security-qa
independently **verified** (not just re-asserted) this doc's claim that
a binary file with a PC as either end of `file_transfer` fails cleanly
rather than corrupting — they traced the actual mechanism (organiser-agent's
raw binary response is invalid UTF-8, which the Linux-server hop's strict
decode step catches and turns into a clean error before it ever reaches
`server.py`). They also ran full adversarial fuzzing against the real MCP
JSON-RPC wire protocol (malformed envelopes, wrong-type tool arguments,
oversized/null-byte/unicode input) with no crashes or leaked internals,
and confirmed a leaked session ID alone doesn't bypass the bearer-token
check. One usability-only finding from that pass: the DNS-rebinding
`allowed_hosts` check has no port wildcard, so a Host header with a port
gets rejected even with the correct password — breaks routine local
testing (fails closed, not a security bug, but worth knowing if `/mcp`
seems to reject valid local requests).

## Pending: agent/pc-agent's fixes (landed on their branch, not yet merged to main)

`agent/pc-agent` has pushed 4 commits addressing several of the gaps
above, tested against a compiled Linux build (see
`coordination/status/pc-agent.md` on that branch for full test detail —
33 new tests, one explicit `expectedFailure` for a POSIX-vs-Windows
path-semantics artifact that can only be confirmed on real Windows).
**None of this is on `main` yet** — everything below is what will
change once it's merged, not current behavior:

- **Machine identity**: `/status` on both agent builds now returns a
  persistent `machine_id`/`machine_name`, addressing "No PC
  identity/registration handshake" above. `server.py`'s `PCS` registry
  remains the source of truth for hub-side routing — this doesn't
  replace it, it just lets the agent know its own name too.
- **Binary-safe file transfer endpoints**: a new `/read_file_b64` (GET)
  and a `content_b64` field on `/write_file` (POST), verified
  byte-identical round-trip in testing. **This does not yet fix
  `file_transfer`'s PC-side text-only limitation on its own** — that
  wiring lives in `server.py` (calling these new endpoints instead of
  `/preview`/`/write_file`'s old text-only form), which is outside both
  pc-agent's and this docs pass's scope. Until someone wires it,
  `file_transfer` still can't move binary data to/from a PC even after
  this merges.
- **A local `/config` + `/admin` dashboard on the agent itself**,
  letting `machine_name`/`secret` be set without hand-editing env vars
  or the Scheduled Task — hot-reloads without a restart. An
  environment-variable secret still wins over a config-file one if both
  are present.
- **`organiser-agent.py` now has the same protected-path guard
  `organiser-agent.cpp` already had** — the "legacy build has no path
  protection" gap in the comparison table above no longer applies once
  this merges (it remains true of the version on `main` today).
- **A real, verified bug fix**: `organiser-agent.cpp`'s `/run_command`
  had no timeout at all (`popen()` blocks until the child exits,
  indefinitely) — confirmed by actually hanging a `sleep 90` against a
  60s deadline and watching the process group get killed via `ps aux`.
  Fixed for the POSIX path; the equivalent Windows fix (Job Objects) is
  code-reviewed but **not compiled or run** — no Windows toolchain was
  available to verify it.
- On the "PC secret pairing isn't enforced" point above: pc-agent looked
  into this specifically and concluded there's no *architectural*
  ambiguity to resolve (one agent process is one physical machine with
  exactly one secret, so there's no "which PC's secret" question for the
  agent side to answer) — worth knowing as context, though it doesn't
  change the operational fact that nothing double-checks the two sides
  were typed identically when you provision a PC.

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
