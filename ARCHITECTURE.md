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

**Update: the `pc:` leg is now binary-safe**, wired to
organiser-agent's `/read_file_b64` and `/write_file`'s `content_b64`
field (landed on `agent/pc-agent`, wired up in `server.py` directly by
the lead). It's currently capped at 40,000 raw bytes for PC transfers
specifically (`_PC_TRANSFER_SAFE_MAX_BYTES` in `server.py`) — well under
the 15 MB general cap — as a defensive workaround for a still-open bug
in organiser-agent.cpp (SECURITY_FINDINGS.md finding 7: its raw socket
read loop silently truncates request bodies over ~64 KB rather than
reading the full declared `Content-Length`). The cap can go back up
toward 15 MB once that's fixed for real (a `Content-Length`-aware read
loop, not a bigger fixed buffer).

## organiser-agent: two implementations, now at rough feature parity

Both builds gained protected-path checks, machine identity
(`machine_id`/`machine_name`), binary-safe transfer (`/read_file_b64`,
`content_b64` on `/write_file`), and an in-agent `/config`+`/admin`
dashboard in the same pass (`agent/pc-agent`, merged to `main`). This
used to be a "use the C++ one, the Python one is unsafe" situation —
**it no longer is.** Current differences:

| | `organiser-agent.py` (v1.2.0) | `organiser-agent.cpp` (v2.1.0-cpp) |
|---|---|---|
| Runtime | Python + Flask (+ optional `send2trash`) | Zero-dependency C++ (winsock2 on Windows) |
| Idle footprint | ~50 MB RAM | ~2 MB RAM, 0% CPU |
| Windows system-dir protection | Yes (`_is_protected_path`) | Yes (`reject_if_protected`) |
| Machine identity, binary transfer, `/config`+`/admin` | Yes | Yes |
| `working_dir` shell injection (SECURITY_FINDINGS.md finding 1) | **Never applicable** — uses `subprocess.run(..., cwd=working_dir, timeout=60)`, a real argument, never shell text | **Fixed** — the timeout fix (below) restructured this to `chdir()` in a forked child instead of a `"cd X && Y"` shell string, closing the injection as a side effect |
| `/run_command` timeout enforcement | Always had it (`subprocess.run`'s built-in `timeout=`) | **Fixed** — `popen()` used to block forever; now fork/exec + poll + process-group `SIGKILL` on deadline (POSIX, verified live); the Windows path (Job Objects) is code-reviewed only, not compiled/run |
| `/preview`/`h_preview` allocates before checking real file size (finding 4) | Not applicable (`f.read(max_bytes)` in Python doesn't pre-allocate the same way) | **Still open** — `server.py`'s `pc_read_file_preview` clamps to 2 MB before forwarding (defense in depth, fixed), but the agent's own allocate-then-check order is unfixed |
| Secret comparison constant-time | No (`!=`) | No (`!=`) — same gap, both builds, per finding 5 |
| Raw request body size handling | Flask/Werkzeug handles this properly | **Still open** (finding 7) — fixed `char buf[65536]`, silently truncates anything larger with an HTTP 200. This is why `file_transfer`'s `pc:` leg is capped at 40 KB, not the full 15 MB, above |
| Deployment model described in its own header comment | Still **stale** — describes ngrok + `ORGANISER_URL`, not the tailscale-ssh-tunnel model actually used (see "PC routing" above) — nobody's fixed this doc comment yet | Accurate |

**Practical takeaway:** either build is safe to run today; pick based on
resource footprint (C++ if you want ~2 MB idle / 0% CPU) or convenience
(Python if you'd rather not set up an MSVC toolchain). If you care about
the specific still-open bugs above (finding 4's agent-side half, finding
5, finding 7), the Python build sidesteps two of the three for free by
virtue of using Flask instead of hand-rolled socket handling — worth
knowing, not necessarily a reason to switch if C++'s footprint matters
more to you. `scripts/install-organiser-agent.ps1` (§1b in
`BUILD_AND_SETUP.md`) fetches the C++ build specifically; there's no
equivalent installer for the Python build yet.

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

> `write_codespace_file` used to always report success even when its
> target directory didn't exist yet — fixed in commit `7dc1695`. Not
> listed below anymore since it's no longer true.

- **`pc-tunnel@.service` still uses `StrictHostKeyChecking=no`**
  (SECURITY_FINDINGS.md finding 6) — a real, if LAN-local, MITM
  exposure. A fix (pin the host key via `ssh-keyscan` + `known_hosts`)
  exists on `agent/pc-agent`'s branch but **is not yet merged to
  `main`** — check `coordination/status/pc-agent.md` or the file itself
  before assuming this is closed.
- **Secret comparison isn't constant-time, in both agent builds**
  (finding 5) — plain `!=`/`hdr != g_secret`, unlike `server.py`'s
  `hmac.compare_digest` everywhere else in this project. Practical risk
  is low (the port is loopback-only; an attacker needs to already be
  running code on the PC to reach it), but it's a real, cost-nothing-
  to-fix gap.
- **organiser-agent's `/preview` still allocates before checking the
  real file size** (finding 4's agent-side half) — `server.py`'s
  `pc_read_file_preview` clamps to 2 MB before forwarding (fixed,
  defense in depth), but the agent itself will still try to allocate
  whatever `max_bytes` a direct HTTP request specifies before checking
  it against the actual file size.
- **organiser-agent.cpp's raw request-body reads still silently
  truncate past ~64 KB** (finding 7) — a fixed `char buf[65536]` that
  stops filling once full regardless of the declared `Content-Length`,
  reporting HTTP 200 with truncated data rather than an error. This is
  why `file_transfer`'s `pc:` leg (see above) is capped at 40 KB rather
  than the general 15 MB. Doesn't affect the Python build (Flask/
  Werkzeug handles this correctly).
- **No secret configured on an agent means its auth check is skipped
  entirely**, not fail-closed (finding 3) — documented behavior (it
  prints `"Auth: NO SECRET (open)"` at startup), mitigated by the
  loopback-only tunnel, but worth knowing if you ever run an agent
  without setting `ORGANISER_SECRET`.
- **PC secret pairing isn't enforced.** The `PCS` registry's `secret`
  for a given PC name must be manually kept in sync with that PC's own
  `ORGANISER_SECRET`. Nothing on either side verifies the pairing is
  correct beyond the header check itself. (`agent/pc-agent` looked into
  whether this needs fixing and concluded there's no *architectural*
  ambiguity for the agent side to resolve — one process is one physical
  machine with one secret — which is fair, but doesn't change that nothing
  catches a typo across the two sides at provisioning time.)
- **`file_transfer`'s read side has no upfront size cap** (finding 8) —
  the write side enforces its size limit before writing, but an
  oversized *source* is fully read (and, for `server:`/`codespace:`
  kinds, base64-decoded) before being rejected, rather than checked
  incrementally or upfront.
- **`/run_command` (both agent builds, and `server_run_command`) is
  intentionally close to unrestricted by design** — `server_run_command`'s
  blocklist is explicitly documented in-code as "a footgun-prevention
  nicety, not a real security boundary." Treat every `*_run_command`
  tool as equivalent to a real shell on that machine. (The `working_dir`
  *injection* bug this used to be paired with — a bug, not a design
  choice — is fixed; see "Security findings" below.)
- **`create_git_commit_and_push` only stages already-tracked files**
  (`git add -u`) — brand-new untracked files need an explicit `git add`
  first.
- **No CI test/lint step for `server.py` yet** — the tests exist (115:
  114 passing + 1 expected-fail, across 8 files under `tests/`, verified
  locally with `pytest tests/` as of this writing — needs both
  `requirements-test.txt` and `pytest.ini`, see below) but nothing runs
  them automatically on push/PR. `.github/workflows/release.yml` runs
  them as part of a tagged release, which is a different thing. See
  `coordination/status/hub-cicd.md` for whether a real CI workflow has
  landed — as of this writing, `agent/hub-cicd` has no commits at all.
- **Fly vs Render** — see above; still unconfirmed, still pending
  hub-cicd.
- **No rate limiting** on the MCP bearer-token check (or the admin
  dashboard's login) beyond the constant-time comparison itself.
- **Admin dashboard is single-admin by design**, and shares its secret
  with the MCP bearer token unless `ADMIN_PASSWORD`/`ADMIN_COOKIE_SECRET`
  are set separately — by design, not a bug, but worth knowing (finding 11).
- **DNS-rebinding host check has no port wildcard** (finding 15) — a
  request with a port in its `Host` header (`127.0.0.1:18010`, which is
  how virtually every local/self-hosted setup looks) gets rejected even
  with a correct password. Fails *closed* (not a vulnerability), but
  will confuse anyone testing this locally — see `SECURITY_FINDINGS.md`
  finding 15 before "fixing" this by weakening the DNS-rebinding check
  itself, which would be a real regression.

## Security findings (agent/security-qa) — current status

Full detail, severities, and suggested fixes for all 17 numbered
findings are in `SECURITY_FINDINGS.md` at repo root (merged to `main`).
Several of the ones covered as prose above are also formal findings
there; this is a compressed pointer table so nothing gets missed,
independently verified against the actual code as of this writing (not
just read from commit messages):

| # | Finding | Status (verified against current `main`) |
|---|---|---|
| 1 | `working_dir` shell injection (Linux) | **Fixed** — verified directly in `organiser-agent.cpp` (`chdir()` in a forked child, no shell string) |
| 2 | Same, Windows (hypothesized) | Unverified — no Windows box to test the `CreateProcess` path |
| 3 | No secret = auth skipped entirely | Open, documented, mitigated by loopback binding |
| 4 | `/preview` `max_bytes` unbounded, chains through server.py | **Partially fixed** — server.py clamps to 2MB; agent-side allocate-before-check still open, verified directly in code |
| 5 | Secret comparison not constant-time | Open — verified directly, both agent builds |
| 6 | `StrictHostKeyChecking=no` | **Fix exists but not merged** — verified the actual file on `main` still has `StrictHostKeyChecking=no`; the fix is real but only on `agent/pc-agent`'s branch |
| 7 | Oversized body silently truncated (64KB buffer) | Open — verified; `server.py` added a 40KB defensive cap on the `pc:` `file_transfer` leg as a workaround, not a fix |
| 8 | `file_transfer` read side, no upfront cap | Open |
| 9 | Malformed address / unknown account silently degrades | **Fixed** — verified directly in `server.py` (`_get_token`, `_parse_location`) |
| 10 | Admin-cookie forgery (original bug) | Already fixed before this pass; re-verified |
| 11 | Shared secret across MCP/admin boundaries | By design, not a bug |
| 12 | Shell-injection sweep of server.py | No issues found |
| 13 | PC binary transfer failure mode | Verified true (and slightly stronger than originally claimed) |
| 14 | Query-string parser doesn't URL-decode | Behavioral quirk, not a vulnerability |
| 15 | DNS-rebinding host check has no port wildcard | Open, fails closed (not a vulnerability, but confusing) |
| 16 | Session ID alone doesn't bypass bearer-token check | Confirmed secure |
| 17 | MCP wire-protocol fuzzing | No issues found |

## Where things live (quick map)

| File | Role |
|---|---|
| `server.py` | The MCP server — every tool definition, the admin dashboard, all auth |
| `organiser-agent.cpp` | Windows PC agent, C++ build — lower footprint, see comparison above |
| `organiser-agent.py` | Windows PC agent, Python build — same safety features, higher footprint, see comparison above |
| `pc-tunnel@.service` | systemd template, one instance per configured PC |
| `scripts/install-organiser-agent.ps1` | Fetches, verifies, and installs a release build of the PC agent |
| `Dockerfile`, `start.sh` | Container build/entrypoint for server.py |
| `fly.toml` | Fly.io config (see "Deployment target" above) |
| `.secrets.example` | Full list of every optional/required env var, for local runs |
| `tests/` | 8 files, 115 tests (114 pass + 1 expected-fail), run with `pytest tests/` |
| `pytest.ini`, `requirements-test.txt` | Test-only deps (pytest, pytest-asyncio, flask, send2trash) + the asyncio-mode config every `@pytest.mark.asyncio` test needs. Without `pytest.ini`, several tests fail with a misleading error instead of a clean pass; without `flask` in particular, `tests/test_organiser_agent.py` fails to even *collect*, aborting the whole run |
| `coordination/` | Multi-agent build coordination — not part of the shipped product |
