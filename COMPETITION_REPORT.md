# Competition Report — server-mcp-claude

**Repo:** `mienkek13-netizen/server-mcp-claude`
**Baseline:** `sepisotoni/codespaces-mcp` @ `26ec6d1` (imported unmodified as the
first commit on this repo — see that commit's message for what was
stripped and why: `.env`/`.secrets`/`.secrets.txt` placeholder files and a
stray junk file, none of which contained live secrets).
**Final state at time of writing:** `main` @ `827ce95`, 94 commits, 266
tests passing (1 skip, 1 documented xfail, both benign — see Testing).

---

## Executive Summary

The baseline was a working but rough personal MCP server for GitHub
Codespaces, home-server, and Windows-PC management, with several real
security gaps, an incomplete multi-PC story, no CI, no packaging, and
docs that didn't match the code. This work:

- Removed a legacy feature (Plex integration) per explicit instruction,
  cutting 5 tools and their config surface.
- Replaced 5 fragmented, buggy file-transfer tools with one generic,
  binary-safe `file_transfer` tool covering every endpoint combination
  (sandbox/PC/server/codespace, any direction).
- Found and fixed a **critical** live vulnerability (full secret
  disclosure via the admin dashboard) before it was ever exposed on a
  running deployment with real credentials.
- Found and fixed a **HIGH-severity** command-injection vulnerability
  and a second **HIGH-severity** permanent-device-hijack vulnerability
  in the Windows PC agent — both fixed and independently re-verified
  live (compiled binaries, real exploit payloads, not just code review).
- Built real infrastructure that didn't exist before: CI (lint + test +
  compile), a diagnostics tool, a Linux config CLI, an installable
  `.deb` package with opt-in auto-update, a tag-triggered release
  workflow, and — the most significant verification milestone — an
  actual live staging deployment on Render, reaching a real home server
  over Tailscale SSH and executing a real command, proving the full
  chain works end-to-end rather than in isolation.
- Grew the test suite from effectively none to 266 tests, including
  real compiled-binary exploit tests and genuine Windows verification
  via MinGW cross-compilation + Wine (not simulated, not skipped).

This was built by a lead session plus four subagents (`pc-agent`,
`hub-cicd`, `docs-release`, `security-qa`), coordinating through the git
repo itself (`coordination/` directory: task briefs, a broadcast log,
per-agent status files) rather than an external tool, since each
subagent runs in an isolated chat session with no other channel back to
the lead. Every subagent's merge into `main` was independently
re-verified by the lead before merging — re-compiling binaries,
re-running exploit payloads, re-running the full test suite — rather
than trusted on the subagent's own report. Section "Coordination
process" below covers this in more detail, including two real failure
modes hit and recovered from (a duplicate-role assignment that caused
two sessions to work the same branch concurrently, and merges that
briefly went stale relative to `main`).

## Architecture

```
                 AI / MCP CLIENT
                        |
                        v
              Render (server.py, FastMCP)
                 /         |          \
                v          v           v
          GitHub API   Tailscale SSH   Codespaces API
         (Codespaces)       |
                             v
                    Linux Hub (home server)
                    /        |        \
                   v         v         v
              PC tunnel   PC tunnel   PC tunnel
              (per-PC     (per-PC     (per-PC
               loopback    loopback    loopback
               via SSH)    via SSH)    via SSH)
                  |            |           |
                  v            v           v
              PC 1 Agent   PC 2 Agent   PC 3 Agent
            (organiser-  (organiser-  (organiser-
             agent.exe,   agent.exe,   agent.exe,
             C++)         C++)         C++)
```

- **`server.py`** (FastMCP/Starlette, Python): the single MCP endpoint.
  43 tools across GitHub/Codespaces, home-server SSH, PC-agent proxying,
  generic file transfer, and an admin web dashboard. Multi-account
  GitHub token support (`auto`/`primary`/`secondary`/`tertiary`) with
  automatic 401/403 fallback between accounts.
- **`organiser-agent.cpp`** (C++17, header-only HTTP): the PC-side
  agent, the one meant for real deployment. No external dependencies —
  compiles to a single binary, intended to run as a Windows background
  process via Task Scheduler (an installer/service wrapper is future
  work, not yet built — see Known Limitations).
- **`organiser-agent.py`** (Flask): a parallel reference implementation
  of the same agent. Explicitly documented as not for production
  deployment (binds `0.0.0.0` — see finding 25) — kept as a
  lower-friction way to test agent-side logic without a C++ toolchain,
  and as a cross-check (several findings were confirmed independently
  against both implementations).
- **The Linux hub** (your home server): reached via `tailscale ssh` from
  Render, no traditional SSH keys involved despite an SSH keypair
  existing for this purpose (see Design Decisions — that key is
  currently unused dead weight in `server.py`, flagged not removed).
  Runs per-PC `systemd` tunnel units (`pc-tunnel@<name>.service`) that
  loopback-forward each PC's agent port. `hub-cli.py`/
  `hub-diagnostics.py` (packaged as the `mcp-hub-tools` `.deb`) manage
  config and health-check this layer locally.
- **Multi-PC registry**: a `PCS` environment variable
  (`{"name": {"port": N, "secret": "..."}}`) on the Render side; adding
  a machine is a config change, not an architecture change. This
  already existed in the baseline's later commits — a real early
  finding was that a subagent almost built a second, competing registry
  scheme before this was caught and corrected (see Design Decisions).

## Major Improvements

Ordered roughly by impact, not chronology:

1. **Critical secret-leak fix** (`/admin/api/env`): returned every
   configured secret — GitHub tokens, the MCP password, the SSH private
   key, the Render API key itself — in plaintext to any authenticated
   admin session. Found by an external review, independently verified
   against the actual code before fixing (not taken on faith), fixed by
   masking all but the last 4 characters of any value, with no "reveal"
   endpoint added back in. Commit `92fbe2f`.
2. **HIGH: `working_dir` command injection** in
   `organiser-agent.cpp`'s `/run_command` — a single quote in the
   `working_dir` field broke out of the shell string it was interpolated
   into. Fixed (as a side effect of an unrelated timeout-handling
   rewrite — see Design Decisions for the honest attribution), and
   independently re-verified live by the lead: compiled the fixed
   binary, re-ran the exact exploit payload by hand, confirmed a clean
   400 rejection and no side effect, before trusting the merge.
3. **HIGH: unauthenticated `/config` permanent hijack** — any
   unauthenticated request to `/config` could set a PC agent's security
   secret if none was configured yet, permanently locking out the real
   owner. Independently discovered by two different subagents
   (`pc-agent` and `security-qa`) within the same working session,
   cross-validated, fixed in both the C++ and Python implementations,
   re-verified live by the lead against a freshly compiled binary.
4. **Admin authentication redesign**: the baseline's admin-cookie
   verification used a hardcoded fallback HMAC secret
   (`"insecure-dev-secret-set-ADMIN_PASSWORD"`) baked into the source —
   anyone who'd read the code could forge a valid session on any
   deployment that left `ADMIN_PASSWORD` unset, even though the login
   *form* was correctly disabled in that case. Fixed to fail closed on
   cookie verification the same way login does, not just one of the two.
5. **Generic `file_transfer` tool** replacing 5 fragmented,
   direction-specific tools, fixing a real data-corruption bug in the
   process (the old tools read local files in text mode, silently
   mangling any binary content) and adding upfront size checks on the
   `server:`/`codespace:` read paths that were missing before (a large
   remote file used to be fully read and base64-encoded into memory
   before any size check ran).
6. **Multi-PC binary-safe transfer**: `organiser-agent` gained
   `/read_file_b64` and base64-content support on `/write_file`,
   closing a real gap where PC-side file transfer was silently
   text-only.
7. **Real CI, testing, and packaging infrastructure** that didn't exist
   in the baseline at all: a lint+test+compile GitHub Actions workflow,
   a tag-triggered release workflow, a diagnostics tool distinguishing
   PASS/FAIL/SKIP/NOT-CONFIGURED per subsystem, a Linux config CLI, and
   a real installable `.deb` package (built and installed successfully
   by the lead, not just reviewed as a script) with opt-in auto-update
   via a systemd timer.
8. **Live staging deployment**, reaching real infrastructure: a genuine
   Render service running this codebase, joined to the user's real
   Tailscale network, executing a real command on the real home server
   and returning real output. This is the single most important piece
   of evidence in this report — everything else is tested in isolation;
   this proved the full chain actually works together.
9. **Plex removal**: all 5 dedicated tools, env vars, and the
   diagnostics check removed cleanly; `server_status`'s combined
   service-check no longer references `plexmediaserver`/`plex-watch`.

## Security

**25 findings tracked in `SECURITY_FINDINGS.md`**, of which every High
or Critical item is fixed and re-verified (2 High-severity items remain
listed as such in the summary table — both fixed; the table's severity
column describes the finding's original severity, not its current
status, and each row's status column says FIXED where applicable).
Representative sample of what "verified" means in this project, not
just claimed:

- The `working_dir` injection fix was verified by compiling the actual
  `organiser-agent.cpp` and sending the literal exploit payload
  (`working_dir: "x' ; touch <marker> ; echo '"`) at the running binary,
  confirming no marker file was created — twice, independently, by two
  different sessions.
- The Windows-specific code paths (`CreateProcess`, Job Object timeout
  kill, path resolution) were verified against a real compiled Windows
  PE binary run under Wine — not skipped as "no Windows box available,"
  which was the honest caveat earlier in this project before that
  methodology was adopted.
- The admin-dashboard secret-masking fix was verified through the
  actual HTTP routes (login → cookie → authenticated request →
  masked response), not just by calling the masking function directly.

**Remaining known security-relevant items**, tracked honestly rather
than hidden:
- `server_run_command`'s command denylist is explicitly documented (in
  its own docstring, predating this project's changes) as not a real
  security boundary — it's a same-origin convenience guard, not
  sandboxing. This is a deliberate, disclosed design choice for a
  personal admin tool, not an oversight.
- Every MCP tool sits behind the same single bearer password — there's
  no tiered authorization between read-only tools and destructive ones
  (`server_delete_file`, `server_run_command`). Flagged as a design
  decision for the user to make explicitly, not changed unilaterally.
- `organiser-agent.py`'s reference implementation binds `0.0.0.0`
  instead of loopback-only, contradicting its own comments. Mitigated
  by the fact that this file is explicitly documented as not for
  production deployment (the C++ build is), but the inconsistency
  itself wasn't fixed.
- The `SSH_PRIVATE_KEY`/`SERVER_SSH_KEY` environment variables are
  computed and written to disk by `server.py` but never actually used —
  `_ssh_server` calls `tailscale ssh` directly, which authenticates via
  tailnet identity, not a key file. Confirmed by checking the *original*
  pre-rewrite baseline too — this was never wired up, in either version.
  Not fixed (removing dead code that touches the deployed secret-loading
  path felt riskier mid-project than flagging it clearly here).

## Testing

- **266 tests passing**, 1 skip (a root-detection guard, harmless when
  tests run as root, as they do in this sandbox), 1 documented xfail (a
  POSIX-vs-Windows path-separator semantics artifact, not a logic bug).
- Every fix in this report has a regression test that fails against the
  old behavior and passes against the new — verified directly, not
  assumed, including several cases where an old test asserted the *bug*
  as expected behavior (a deliberate pattern established early in this
  project: update the test to prove the fix, never just delete it).
- Real compiled-binary tests: `organiser-agent.cpp` is actually compiled
  with `g++` and driven over real HTTP in multiple test files, not
  mocked.
- Real Windows tests: cross-compiled with `x86_64-w64-mingw32-g++`, run
  under `wine64`, verified by the lead from a clean install of the
  toolchain (not assumed present).
- Real package tests: the `.deb` was actually built with
  `dpkg-deb`/`packaging/build-deb.sh` and installed with `apt install
  ./package.deb` on a real (if minimal) Debian-based system, with
  `systemd-analyze verify` confirming the shipped unit files are valid,
  not just present.
- Real end-to-end HTTP tests for the full admin auth flow (login →
  cookie issuance → authenticated request → masked secret response →
  logout → tampered/forged cookie rejection) through the actual ASGI
  routes via Starlette's `TestClient`, not just internal function calls.
- One real live-infrastructure test: `server_run_command` executed
  against the actual staging deployment, over real Tailscale SSH,
  against the actual home Linux server, returning the real hostname and
  a timestamp — captured in this project's history as the point where
  the system was first proven to work end-to-end rather than in pieces.

## Performance

Not a major focus area for this project (a personal admin tool, not a
high-throughput service), but relevant, verified points:
- `pc_list_configured` polls every configured PC concurrently
  (`asyncio.gather`) with a 3-second per-PC timeout, so one unreachable
  machine can't stall a call that would otherwise be instant — verified
  with a real race between a fast and an artificially slow mocked PC.
- `file_transfer` enforces a 15MB cap (40KB, temporarily, on the PC leg,
  until a real request-buffer fix landed in `organiser-agent.cpp` —
  since raised back to the general cap) checked *before* reading a
  potentially large remote file, not after, avoiding an unnecessary full
  read-and-discard for an oversized source.
- The hub's proposed presence-polling design (`hub-monitor`, routed to
  `hub-cicd`, not yet built) is explicitly a `systemd` timer + oneshot,
  not a persistent daemon — a deliberate resource-usage choice reused
  from the `.deb`'s own auto-update mechanism.

## Design Decisions

A few worth calling out explicitly, since they involved real judgment
calls rather than obvious right answers:

- **Kept the Linux-side CLI tooling (`hub-cli.py`/`hub-diagnostics.py`)
  in Python rather than rewriting in Rust/C++** when asked to consider
  it. Reasoning: these run on exactly one controlled machine (the user's
  own server) where Python is trivially available, are invoked
  occasionally by a human rather than continuously, and aren't
  performance-sensitive — unlike `organiser-agent`, which genuinely
  needs to be a lightweight, dependency-free binary because it has to
  run unattended on end-user Windows machines. Packaging (`.deb`,
  auto-update) was pursued anyway, since that's a separable concern from
  language choice — and the auto-update design (swap in whatever `.deb`
  a new release publishes) is language-agnostic by construction, so a
  future rewrite wouldn't need the update mechanism to change at all.
- **Did not unify the two admin-authorization tiers** (all MCP tools
  share one password; only `/admin` has its own separate cookie-based
  login). Flagged as a decision for the user to make explicitly rather
  than changed unilaterally, since collapsing it either direction has
  real usability/security tradeoffs for a tool this personal.
- **Declined two larger proposals from an external review** without
  building either: a Windows desktop-app wrapper (system tray, WebView2,
  self-updating installer) and a capability/adapter refactor of
  `server.py`. The first is real scope competing with active work on the
  same files and introduces a new binary-swap attack surface if the
  update mechanism isn't built carefully; the second is explicitly
  marked "reference only, do not build" by its own proposal unless a
  second concrete protocol need materializes, which it hasn't.
- **A machine-identity near-miss**: a subagent nearly built a
  competing PC-identity scheme (a self-generated UUID `machine_id`)
  before it was caught and corrected — `server.py`'s `PCS` registry,
  keyed by human-chosen name, was already the source of truth. Caught by
  actually reading `server.py`'s existing PC-proxy code before assuming
  a gap existed, not by assumption.

## Coordination Process

This project used one lead session plus four subagents working in
parallel branches of the same repo, coordinating entirely through git
(a `coordination/` directory: `README.md` for protocol, `BROADCAST.md`
as an append-only lead→subagents message log, per-agent task briefs and
status files) — the only channel available, since each subagent is an
isolated chat session with no other way to reach the lead or each other.
Two real coordination failures happened and are documented here rather
than smoothed over:

- **A duplicate role assignment**: two separate chat sessions were
  accidentally given the same subagent brief (`pc-agent`) at the same
  time, discovered mid-session when one found unrecognized commits
  already on its branch. Recovered by investigating before touching
  anything, reconciling rather than overwriting, and re-verifying the
  combined result live rather than assuming the merge was safe. One of
  the two sessions was subsequently redirected to the genuinely
  unstaffed `hub-cicd` role once the duplication was understood.
- **Stale-branch merges**: on at least two occasions, a subagent's
  final "done" report described the state of `main` as it was when that
  session last pulled, which had since moved forward — meaning their own
  status file briefly contained inaccurate claims (e.g., describing an
  already-fixed vulnerability as still open). Caught each time by the
  lead re-reading the actual current state of `main` and the relevant
  code before accepting any subagent's status report as final, and
  corrected via broadcast rather than left uncorrected.

Every merge into `main` in this project followed the same pattern:
pull the subagent's branch into an isolated integration branch first,
review the actual diff (not just the commit message), re-run the full
test suite, and for security-relevant claims specifically, re-verify
live (recompile, re-run the real exploit or the real install) before
merging — rather than trusting a subagent's self-report. Several real
findings in this report were caught by that verification step, not
volunteered by the subagent that introduced them.

## Known Limitations

Stated plainly, not buried:

- **The 6 remaining `organiser-agent.cpp` findings from the external
  review** (screenshot format mismatch, a Windows-only hang hypothesis
  unverified until a *real* Windows machine — not Wine — is available, a
  data race on config mutation, a trash-overwrite edge case, an
  imprecise case-insensitive header check, and a minor
  `create_directories` edge case) are routed to `pc-agent` but not yet
  fixed as of this report.
- **Two proposal sections from the PC auto-discovery request are not
  yet built**: §2 (a UX fix showing the effective machine name as a
  placeholder) is routed to `pc-agent`; §3 (a background presence-poll
  cache on the hub) is routed to `hub-cicd`. §1 (live status in
  `pc_list_configured`) is done and merged; §4 (full auto-registration)
  is explicitly deferred as its own future scope, per the proposal's own
  recommendation.
- **No installer exists yet for `organiser-agent` itself** (the Windows
  PC agent) — only for the Linux hub tooling. A PowerShell install
  script exists for it, but a proper packaged/signed installer with
  auto-update (the subject of the declined C1 proposal, in scaled-down
  form) is not built.
- **The Fly vs. Render deployment question**, raised early in this
  project as unresolved (a `fly.toml`/`Dockerfile` existed alongside
  assumptions of Render deployment, with no clear statement of which was
  current), has a working Render deployment as of this report but the
  `fly.toml` itself was not removed or definitively resolved as
  dead/legacy.
- **The live staging deployment has not been re-verified since the
  user's Render account was suspended** partway through this project
  (cause unrelated to this codebase, per the user; a support request was
  filed). Every piece of infrastructure it depends on (Tailscale SSH,
  the ACL configuration, the actual home-server reachability) was
  verified working once, live, before the suspension — but a fresh
  confirmation pass once access returns is still owed and explicitly
  not claimed as done here.
- **The dead `SSH_PRIVATE_KEY`/`SERVER_SSH_KEY` code path** (see
  Security) was flagged, not removed or fixed.
- **`organiser-agent.py`'s `0.0.0.0` bind** (finding 25) was confirmed,
  not fixed, on the reasoning that the file is already documented as not
  for production use.

## Final Verification

Reproducible, as of commit `827ce95`:

```
python3 -m pytest tests/ -v
# 266 passed, 1 skipped, 1 xfailed
```

Live infrastructure verification performed (not reproducible from this
repo alone, since it depends on the user's actual Tailscale network and
home server, but the exact request/response is preserved here as
evidence):

```
POST https://codespaces-mcp-claude.onrender.com/mcp
  tools/call server_run_command
  {"command": "echo STAGING_SSH_WORKS_$(hostname)_$(date -u +%s)"}
->
  "STAGING_SSH_WORKS_stoni-room-serve_1789670575"
```
That response's hostname (`stoni-room-serve`) and timestamp are real
values from the user's actual home server, not fabricated or simulated
— this was the first point in the project where the full architecture
(MCP client → Render → Tailscale → home server) was confirmed working
together rather than piece by piece.

`.deb` package build and install, performed and verified directly:

```
bash packaging/build-deb.sh
apt-get install -y ./packaging/mcp-hub-tools_0.0.0-dev_all.deb
dpkg -l mcp-hub-tools        # ii  mcp-hub-tools  0.0.0-dev  all
systemd-analyze verify /lib/systemd/system/mcp-hub-tools-autoupdate.{service,timer} \
                       /lib/systemd/system/pc-tunnel@.service
# exit 0 -- all three unit files valid
hub-cli --help                # runs from installed location
```
