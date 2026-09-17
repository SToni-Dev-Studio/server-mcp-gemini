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
Capped at 15 MB per transfer, **including PC transfers** — that cap
used to be lowered to 40 KB for the `pc:` leg specifically as a
workaround for a bug in organiser-agent.cpp (see finding 7 below); that
bug is now genuinely fixed, and the cap was restored to match the
general 15 MB limit. See `SKILL.md`'s Group 4 for the full
address-format reference and examples.

## organiser-agent: two implementations, now at genuine feature + safety parity

Both builds (`organiser-agent.py` v1.2.0+, `organiser-agent.cpp`
v2.1.0-cpp+) have: protected-path checks, machine identity
(`machine_id`/`machine_name`), binary-safe transfer (`/read_file_b64`,
`content_b64` on `/write_file`), an in-agent `/config`+`/admin`
dashboard, a real `/run_command` timeout with process-tree cleanup, and
(as of the latest `agent/pc-agent` merge) every SECURITY_FINDINGS.md
issue that applied to them fixed except finding 3 (see below, a
documented design choice) and finding 2 (Windows injection — the
architectural fix is in place, but unverified by actual execution, no
Windows box available anywhere in this project). The only remaining
practical difference is resource footprint:

| | `organiser-agent.py` | `organiser-agent.cpp` |
|---|---|---|
| Runtime | Python + Flask (+ optional `send2trash`) | Zero-dependency C++ (winsock2 on Windows) |
| Idle footprint | ~50 MB RAM | ~2 MB RAM, 0% CPU |
| Everything in SECURITY_FINDINGS.md that applies to this file | Fixed (mostly never applicable — see below) | Fixed |
| Deployment model described in its own header comment | Still **stale** — describes ngrok + `ORGANISER_URL`, not the tailscale-ssh-tunnel model actually used (see "PC routing" above). Nobody's fixed this doc comment yet, unlike everything else | Accurate |

Worth knowing even though it no longer changes which one is "safe to
run": the Python build's `subprocess.run(..., cwd=working_dir,
timeout=60)` was *architecturally* never vulnerable to findings 1/2 in
the first place (a real function argument, never shell text), and
Flask/Werkzeug's own request handling meant finding 7's raw-socket
buffer bug never applied to it either — not a fix so much as a
different implementation approach that happened to sidestep two whole
bug classes.

**Pick based on footprint or convenience** — C++ if ~2 MB idle/0% CPU
matters, Python if you'd rather not set up an MSVC toolchain.
`scripts/install-organiser-agent.ps1` (`BUILD_AND_SETUP.md` §1b)
fetches the C++ build specifically; there's no equivalent installer for
the Python build yet.

## Deployment target: Render (confirmed)

Render is the confirmed, supported, actually-deployed target —
resolved by `agent/hub-cicd` (see `render.yaml` at repo root and
`coordination/status/hub-cicd.md`). Everything actually wired up — the
`/admin` dashboard's Render API calls, the hardcoded default
`RENDER_SERVICE_ID` (matching the real live service), every setup doc —
is Render-specific. `fly.toml` is kept in the repo (not deleted — a
bigger, less reversible call than documenting its status) but is now
explicitly marked in its own header comment as unconfirmed/likely-legacy:
`server.py` would plausibly still work on Fly (it auto-detects
`FLY_APP_NAME` the same way it does `RENDER_EXTERNAL_HOSTNAME`), but
nothing in this project's history confirms a Fly deployment is actually
live, tested, or maintained.

## Known limitations

- **`/run_command` (both agent builds, and `server_run_command`) is
  intentionally close to unrestricted by design.** `server_run_command`'s
  blocklist is explicitly documented in-code as "a footgun-prevention
  nicety, not a real security boundary." Treat every `*_run_command`
  tool as equivalent to a real shell on that machine. (This is a design
  choice, not a bug — the *bug* this used to be paired with, the
  `working_dir` shell injection, is fixed; see "Security findings.")
- **No secret configured on an agent means its auth check is skipped
  entirely**, not fail-closed (SECURITY_FINDINGS.md finding 3) — the
  one finding pc-agent deliberately left as-is rather than "fixing":
  it's explicitly documented behavior (prints `"Auth: NO SECRET
  (open)"` at startup), and mitigated by the tunnel being loopback-only
  by design. Worth knowing if you ever run an agent without setting
  `ORGANISER_SECRET`, not something anyone's actively planning to change.
- **PC secret pairing isn't enforced.** The `PCS` registry's `secret`
  for a given PC name must be manually kept in sync with that PC's own
  `ORGANISER_SECRET`. Nothing on either side verifies the pairing beyond
  the header check itself. (`agent/pc-agent` looked into whether this
  needs fixing and concluded there's no *architectural* ambiguity for
  the agent side to resolve — one process is one physical machine with
  one secret — which is fair, but doesn't change that nothing catches a
  typo across the two sides at provisioning time.)
- **`file_transfer`'s read side has no upfront size cap** (finding 8) —
  an oversized *source* is fully read (and, for `server:`/`codespace:`
  kinds, base64-decoded) before the size limit is checked, rather than
  checked incrementally or upfront.
- **`create_git_commit_and_push` only stages already-tracked files**
  (`git add -u`) — brand-new untracked files need an explicit `git add`
  first.
- **DNS-rebinding host check has no port wildcard** (finding 15) — a
  request with a port in its `Host` header (`127.0.0.1:18010`, which is
  how virtually every local/self-hosted setup looks) gets rejected even
  with a correct password. Fails *closed* (not a vulnerability), but
  will confuse anyone testing this locally — see `SECURITY_FINDINGS.md`
  finding 15 before "fixing" this by weakening the DNS-rebinding check
  itself, which would be a real regression.
- **No rate limiting** on the MCP bearer-token check (or the admin
  dashboard's login) beyond the constant-time comparison itself.
- **Admin dashboard is single-admin by design**, and shares its secret
  with the MCP bearer token unless `ADMIN_PASSWORD`/`ADMIN_COOKIE_SECRET`
  are set separately — by design, not a bug (finding 11).
- **No CI test/lint step for `server.py` yet** — the tests exist (116:
  115 passing + 1 expected-fail, across 8 files under `tests/`, verified
  locally with `pytest tests/` as of this writing — needs
  `requirements-test.txt` + `pytest.ini`, see below) but nothing runs
  them automatically on push/PR yet. `agent/hub-cicd` is active (their
  first commit resolved the Fly-vs-Render question above) but hasn't
  landed CI itself yet — check `coordination/status/hub-cicd.md` for
  current state.

## Security findings (agent/security-qa + agent/pc-agent) — current status

Full detail, severities, and fix history for all 17 numbered findings
are in `SECURITY_FINDINGS.md` at repo root. Independently re-verified
directly against the actual current code for this pass (not just read
from commit messages or trusted from either subagent's own report):

| # | Finding | Status (independently verified) |
|---|---|---|
| 1 | `working_dir` shell injection (Linux) | **Fixed** — `chdir()` in a forked child, no shell string; verified in `organiser-agent.cpp` |
| 2 | Same, Windows (hypothesized) | **Architecturally fixed** — verified `cwd` is passed via `CreateProcessA`'s `lpCurrentDirectory` parameter, never concatenated into the command string — but still unverified *by execution*, no Windows box available |
| 3 | No secret = auth skipped entirely | Open by design — see "Known limitations" |
| 4 | `/preview` `max_bytes` unbounded, chains through server.py | **Fixed, both halves** — verified `h_preview` now clamps to a hard ceiling AND the real file size before allocating; `server.py`'s `pc_read_file_preview` also clamps before forwarding |
| 5 | Secret comparison not constant-time | **Fixed** — verified a `constant_time_equal()` function now exists and is used in `organiser-agent.cpp`; `organiser-agent.py` uses `hmac.compare_digest` |
| 6 | `StrictHostKeyChecking=no` | **Fixed** — verified `pc-tunnel@.service` now uses `StrictHostKeyChecking=yes` + a per-PC `UserKnownHostsFile` |
| 7 | Oversized body silently truncated (64KB buffer) | **Fixed** — verified `organiser-agent.cpp`'s `handle_conn` now reads headers first, checks `Content-Length` against a real ceiling, and reads exactly that many bytes in a loop rather than stopping at a fixed buffer. `server.py`'s PC-transfer cap was restored from its 40KB workaround back to the general 15MB limit accordingly |
| 8 | `file_transfer` read side, no upfront cap | Open |
| 9 | Malformed address / unknown account silently degrades | **Fixed** — verified directly in `server.py` (`_get_token`, address parsing) |
| 10 | Admin-cookie forgery (original bug) | Already fixed before this pass; re-verified |
| 11 | Shared secret across MCP/admin boundaries | By design, not a bug |
| 12 | Shell-injection sweep of server.py | No issues found |
| 13 | PC binary transfer failure mode | Verified true (moot now for size reasons too — finding 7's fix means large binary PC transfers now actually succeed rather than needing the clean-failure path as often, though the failure-mode guarantee itself is unchanged) |
| 14 | Query-string parser doesn't URL-decode | Behavioral quirk, not a vulnerability |
| 15 | DNS-rebinding host check has no port wildcard | Open, fails closed (not a vulnerability, but confusing) |
| 16 | Session ID alone doesn't bypass bearer-token check | Confirmed secure |
| 17 | MCP wire-protocol fuzzing | No issues found |

**Net effect: of the findings that represented real bugs (not design
choices or already-secure behavior), only #8 (low-medium, `file_transfer`
read-side cap) and #15 (usability, fails closed) remain open.** Finding
3 is a deliberate, documented design choice, not an oversight. Finding 2
is architecturally addressed but formally unverified for lack of a
Windows test target — the one genuine gap in this project's testing
coverage, called out consistently by every subagent that touched it
rather than glossed over.

## Where things live (quick map)

| File | Role |
|---|---|
| `server.py` | The MCP server — every tool definition, the admin dashboard, all auth |
| `organiser-agent.cpp` | Windows PC agent, C++ build — lower footprint, see comparison above |
| `organiser-agent.py` | Windows PC agent, Python build — same safety features, higher footprint, see comparison above |
| `pc-tunnel@.service` | systemd template, one instance per configured PC |
| `scripts/install-organiser-agent.ps1` | Fetches, verifies, and installs a release build of the PC agent |
| `Dockerfile`, `start.sh` | Container build/entrypoint for server.py |
| `render.yaml` | Render Blueprint — documents the full env var surface for a working deployment; the live service predates this file |
| `fly.toml` | Present but unconfirmed/likely-legacy — see "Deployment target" above |
| `.secrets.example` | Full list of every optional/required env var, for local runs |
| `SECURITY_FINDINGS.md` | Full detail on all 17 security findings and their fix status |
| `tests/` | 8 files, 116 tests (115 pass + 1 expected-fail), run with `pytest tests/` |
| `pytest.ini`, `requirements-test.txt` | Test-only deps (pytest, pytest-asyncio, flask, send2trash) + the asyncio-mode config every `@pytest.mark.asyncio` test needs. Without `pytest.ini`, several tests fail with a misleading error instead of a clean pass; without `flask`, `tests/test_organiser_agent.py` fails to even *collect*, aborting the whole run |
| `coordination/` | Multi-agent build coordination — not part of the shipped product |
