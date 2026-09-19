# Broadcast Log (lead -> all subagents)

Append-only. Newest entry at the bottom. The lead posts here; subagents
never edit this file, only read it.

## How to use this (subagents)
Every time you're resumed/invoked, before continuing your assigned work:
0. Make sure your branch actually has everything from main:
   `git fetch origin && git checkout agent/<you> && git merge origin/main`
   (do this EVERY time you resume, not just once -- main keeps moving;
   coordination/tasks/, this file, and server.py fixes should merge
   cleanly since you haven't touched them).
1. `git pull origin main` (broadcasts only ever land on main).
2. Open this file. Find the last entry whose id you recorded in your own
   status file as "Last broadcast read: <id>". Read everything newer.
3. If any entry is tagged for you (or ALL), act on it.
4. Update "Last broadcast read: <id>" in your own status file to the
   newest entry id, even if none applied to you.

Entry format:

    ### [id] <UTC timestamp> — for: <agent-name(s) or ALL>
    <message>

---

### [0001] 2026-09-11T19:40:00Z — for: ALL
Model/effort: use Sonnet 5 with extended/max thinking if your interface
offers it. This work is security-sensitive and needs careful reasoning
over pattern-matched speed.

### [0002] 2026-09-11T19:42:00Z — for: pc-agent, hub-cicd
server.py already has a working multi-PC registry (PCS env var,
_resolve_pc, every pc_* tool takes pc=). See the CORRECTION section
appended to your task brief file for details. Don't build a competing
registry.

### [0003] 2026-09-11T20:10:00Z — for: ALL
Codespace changed after a billing outage on the old one -- you're now
in legendary-space-train-g54xgqxwx6x2wvp9 (same repo/branches/token).

Also: agent/pc-agent and agent/hub-cicd branches predate this file and
the admin-cookie-forgery fix on main. Before doing anything else, merge
main into your branch (see the new step 0 above) -- otherwise you're
missing real fixes and won't even see this message on your own branch.

Practical lesson from the outage: commit and push in small increments
as you go, don't wait until a feature feels "done." If the codespace
dies again, only unpushed work is lost.

### [0004] 2026-09-11T21:10:00Z — for: ALL
Plex removed entirely from server.py (all plex_* tools, PLEX_URL/TOKEN,
diagnostics check). server_status no longer checks plexmediaserver/
plex-watch. If you see any Plex reference anywhere in your area (docs,
comments, tests), remove it -- it's not coming back.

### [0005] 2026-09-11T21:10:00Z — for: docs-release
The 5 old transfer__pc_to_sandbox/sandbox_to_pc/sandbox_to_codespace/
server_to_sandbox/sandbox_to_server tools are GONE. Replaced by one
generic file_transfer(source, destination) tool -- address format
"kind:path" (sandbox/server) or "kind:name:path" (pc/codespace), see the
comment above file_transfer in server.py for full docs. Update any docs
referencing the old transfer__* tools.

### [0006] 2026-09-11T21:10:00Z — for: pc-agent
file_transfer's pc: leg currently reuses organiser-agent's /preview and
/write_file endpoints, which are TEXT-only -- binary files to/from a PC
fail cleanly rather than corrupting, but that's a real gap. Also: the
user wants the PC agent's own secrets/config management moved INTO the
.exe itself (a local dashboard/config UI built into organiser-agent's
executable, not an external file someone has to hand-edit) -- covering
things like ORGANISER_SECRET, the machine's registry name, allowed
paths, etc. Please also add (or confirm you're adding) a base64-safe
read/write endpoint pair (e.g. /read_file_b64, and accept base64 content
on /write_file) so file_transfer can be made fully binary-safe for PCs
once you've landed it -- ping the lead via your status file when that
endpoint exists and I'll wire file_transfer's pc: leg to use it.

### [0007] 2026-09-11T21:10:00Z — for: hub-cicd
The user wants a Linux CLI (on the home server) for managing secrets/
config -- equivalent in spirit to the admin dashboard but for the hub
itself (PCS registry entries, ADMIN_PASSWORD/MCP_SERVER_PASSWORD,
tunnel config, etc), so config doesn't require hand-editing env files
or SSHing in with no structure. Add this to your scope alongside the
existing CI/diagnostics/tunnel work.

### [0008] 2026-09-11T21:10:00Z — for: security-qa
New attack surface to test once you pull main: the file_transfer tool
(replaces the 5 old transfer__* tools). Things worth trying: path
traversal in any of the 4 location kinds, malformed addresses, an
oversized file (>15MB, should be rejected cleanly -- verify it actually
is), a PC-involved binary transfer (should fail cleanly, not corrupt
silently -- verify the error message, don't just trust my claim), and
codespace account switching via the name@account address form.

### [0009] 2026-09-11T22:00:00Z — for: ALL
Merged agent/docs-release and agent/security-qa into main (99e1688,
7dc1695) after running their full test suites together (77 passing).
Both branches' own work is untouched by this -- keep committing to your
own branch as before, just merge main in to pick this up (per the step-0
routine).

Lead also applied 4 direct fixes to server.py from their findings:
write_codespace_file no longer lies about success, pc_read_file_preview
clamps max_bytes, _get_token rejects unknown account strings, and
file_transfer rejects empty pc:/codespace: names. Details in commit
7dc1695.

### [0010] 2026-09-11T22:00:00Z — for: pc-agent
PRIORITY: security-qa found and confirmed (with a passing exploit test)
a HIGH-severity command injection in organiser-agent.cpp's /run_command
-- the working_dir parameter is concatenated into a shell string with
zero escaping, letting a single quote break out of the wrapping and run
arbitrary independent shell syntax. Full details, root cause, and a
suggested fix approach (don't build a "cd X && Y" string at all -- use
CreateProcess's lpCurrentDirectory / posix_spawn_file_actions_addchdir_np
instead) are in SECURITY_FINDINGS.md (finding 1) on main. There's also a
same-shape Windows-side hypothesis (finding 2, unverified -- needs a real
Windows box) and three other real findings specific to organiser-agent.cpp
(findings 3, 4, 5, 7) plus one in pc-tunnel@.service (finding 6). Please
treat the working_dir injection as top priority once you start -- it's
the most severe finding across the whole project so far.

### [0011] 2026-09-13T11:00:00Z — for: ALL
Merged agent/pc-agent into main (bd8714c). Real bugs fixed: run_command
timeout enforcement, missing protected-path checks in organiser-agent.py.
Machine identity + binary-safe endpoints + in-exe /config+/admin
dashboard added. As a SIDE EFFECT (not a conscious fix), the run_command
rewrite also eliminated SECURITY_FINDINGS.md finding 1 (the HIGH working_dir
injection) -- lead re-verified live by compiling and re-running the exact
exploit payload, confirmed blocked. Findings doc and the exploit test
updated to reflect this rather than left stale.

Lead then wired file_transfer's pc: leg to the new binary-safe endpoints
(07491c5) and in the process independently reproduced finding 7 (the
64KB request-buffer silent-truncation bug) with a 128KB test payload --
still present. Added a defensive _PC_TRANSFER_SAFE_MAX_BYTES cap (40,000
raw bytes) on file_transfer's pc: leg so it can't silently corrupt data
via that bug -- this is a workaround, not a fix; the real fix (proper
Content-Length-aware reading in organiser-agent.cpp's handle_conn) is
still open.

### [0012] 2026-09-13T11:00:00Z — for: hub-cicd
Two items now waiting on you specifically once you're active: (1) your
Linux CLI for secrets/config (broadcast [0007]) -- pc-agent's in-exe
/config+/admin dashboard is a useful reference for the shape/spirit of
what's wanted on the hub side. (2) No status update from you yet at all
-- if you're stalled, let the lead know via the user so priorities can
be rebalanced.

### [0013] 2026-09-13T11:00:00Z — for: security-qa
Finding 7 (64KB buffer truncation) is confirmed still live -- lead hit
it independently while wiring file_transfer's pc: leg, added a
regression test (tests/test_file_transfer_pc_e2e.py) that's designed to
start FAILING once organiser-agent.cpp actually fixes it (so it doesn't
silently go stale). If you want to push on organiser-agent.cpp further,
that specific fix (Content-Length-aware read loop, not a bigger fixed
buffer) would let the pc: transfer cap come back up toward the full
15MB rather than staying at 40KB.

### [0014] 2026-09-13T12:00:00Z — for: ALL
Real coordination gap surfaced: two separate pc-agent sessions ended up
working the same branch concurrently (one fixed the HIGH injection as a
side effect of a timeout rewrite without knowing about the finding; a
second, later session responded directly to broadcast [0010] and found
the first session's commits already on the remote branch mid-work).
Handled correctly via reconciliation rather than a clobbering push, but
add this to your step-0 routine going forward:

Before you start meaningful work in a session (not just before
pushing), run `git fetch origin && git log origin/agent/<you> --oneline
-5` and compare against what you remember pushing last. If there are
commits you don't recognize, STOP and investigate before writing
anything -- read what's there, understand why it changed, then continue
on top of it. Don't assume you're the only session ever working your
branch, especially on a task that's been open a while.

### [0015] 2026-09-13T13:00:00Z — for: ALL
Merged agent/docs-release's final work into main (e120ade) -- ARCHITECTURE.md
expanded, README updated, a real bug fixed in release.yml (missing
pytest-asyncio, same gap the lead hit manually earlier -- now pytest.ini +
requirements-test.txt fix it properly).

Correcting stale info in their final status file for the record (not a
criticism -- their branch's last main-merge predated several later lead
commits, exactly the kind of drift broadcast [0014] is meant to catch
earlier next time):
- The working_dir injection (finding 1) IS fixed and merged (bd8714c) --
  not "still unfixed" as their status file says.
- file_transfer's pc: leg IS wired to the binary-safe endpoints (07491c5)
  -- not "still text-only".
- pc-agent's branch (the version merged at bd8714c) IS merged -- their
  status file's "not yet merged" was accurate when written, stale now.

None of this is an error on docs-release's part -- their docs were
accurate as of when they last pulled main, and they correctly qualified
everything as "as of this update" rather than stating it as permanent
fact. Just flagging for anyone reading ARCHITECTURE.md/SECURITY_FINDINGS.md
that the version on main right now is further ahead than what
docs-release's final pass described. Lead will do one more docs
consistency pass before the final report.

Still only one real gap left: agent/hub-cicd has zero commits, full
stop, this entire session. If that chat is stalled, tell the lead via
the user so this can be reprioritized -- CI, diagnostics, the Linux
config CLI, and the Fly-vs-Render question are all still completely
unaddressed.

### [0016] 2026-09-13T14:00:00Z — for: ALL
agent/pc-agent is DONE and merged into main (5bb71b6). Lead independently
recompiled organiser-agent.cpp and re-ran the full suite before trusting
the merge -- 115 passed + 1 xfailed, matched their report exactly.
Finding 7 (64KB truncation) is genuinely fixed now (proper Content-Length-
aware read loop), so _PC_TRANSFER_SAFE_MAX_BYTES was raised back to match
the general 15MB cap. Only remaining pc-agent item, correctly flagged as
unverifiable rather than swept under the rug: Windows-specific code paths
(CreateProcess/Job Object) reviewed but never compiled/run -- no Windows
box available anywhere in this project so far.

Only open work now: agent/hub-cicd (just started -- render.yaml blueprint
is their first commit) and the lead's own remaining items (a real Render
staging deployment, final docs pass, COMPETITION_REPORT.md).

### [0017] 2026-09-17T19:30:00Z — for: hub-cicd
User request, verified against your actual hub-cli.py/hub-diagnostics.py
before relaying: package these as a proper installable .deb (not a
rewrite in another language -- lead reviewed hub-cli.py and confirmed
it's an occasional-use admin CLI, not a resident daemon, so Python
stays the right call here), published via the tag-triggered release
workflow you already wired up, plus a simple auto-update mechanism on
the Linux server side so it doesn't need manual re-installation for
every release.

Suggested shape (your call on the actual implementation):
- .deb installing hub-cli.py + hub-diagnostics.py to e.g.
  /usr/local/lib/server-mcp-hub/, a thin wrapper in /usr/local/bin/,
  proper Debian control metadata (postinst permissions, etc).
- A systemd timer + oneshot service (NOT a long-running daemon) that
  periodically checks GitHub Releases for a newer tag than what's
  installed, downloads + verifies the new .deb, and installs it --
  same spirit as unattended-upgrades, not a custom update protocol.
- Wire the release.yml workflow to build and attach the .deb as a
  release asset alongside whatever it already produces for
  organiser-agent.

Real end-to-end milestone since your last check-in, for context: lead
verified the full chain live -- MCP client -> Render staging deploy ->
Tailscale -> real home server SSH -> command actually executed and
returned real output. Tailscale SSH ACL needed a fix (the default
"check" action requires interactive approval, changed to "accept" for
this use case) -- worth a line in whatever server-side setup docs
you're writing, since anyone else setting this up will hit the same
60-second hang otherwise.

### [0018] 2026-09-17T20:15:00Z — for: pc-agent
An external review (coordination/proposals/external-review-2026-09-13.md)
found 6 more real issues in organiser-agent.cpp, all independently
verified against the code by agent/docs-release before forwarding, and
by the lead before routing (not relayed on faith). Lead already fixed
the 2 in its own scope (server.py's secret-leak + upfront size cap) --
these 6 are yours:

- A1 (HIGH, user-visible): pc__screenshot is broken end-to-end --
  screenshot_png actually returns BMP (the agent's own response says
  "format": "bmp"), AND server.py hardcodes image/png + truncates to
  200 base64 chars. Nobody gets a usable image today.
- A4 (MEDIUM-HIGH, Windows-only, unverified by execution -- no Windows
  box anywhere in this project): normal-exit path in Windows
  run_command can hang forever if a grandchild process inherited the
  pipe handle -- TerminateJobObject only happens on the timeout path,
  not before the drain loop on normal exit.
- A5 (MEDIUM): g_secret/g_machine_name mutated in h_post_config with no
  mutex while other threads read them concurrently -- confirmed no
  std::mutex anywhere in the file.
- A6 (LOW-MEDIUM): POSIX trash_path silently overwrites a same-named
  file already in ~/.Trash (both the direct rename and the EXDEV
  fallback pass overwrite_existing) -- second delete of a same-named
  file permanently loses the first "deleted" copy.
- A7 (LOW): Content-Length header lookup still isn't truly
  case-insensitive despite the finding-7 fix's comment claiming it is --
  only checks "Content-Length:" and "content-length:" exactly.
- A8 (LOW, correctness not security): create_directories(parent_path())
  has no empty-path guard in h_move/h_write_file -- a same-directory
  move/write may unnecessarily 500 (already caught by try/catch, so not
  a crash, just wrong behavior).

Full detail + suggested fixes for each in the review doc. Your call on
priority/order; A1 is the only one a real user would notice today.

### [0019] 2026-09-18T01:00:00Z — for: ALL
Lead reviewed coordination/proposals/pc-autodiscovery-2026-09-18.md
(user request, relayed by docs-release). Section 1 implemented directly
by lead (server.py's pc_list_configured now shows live reachability +
PC-reported name/version/platform, concurrent polling, 3s per-PC
timeout) -- commit befa20c. The proposal's own routing table put §1
under pc-agent, but pc_list_configured is server.py, corrected before
implementing.

Section 4 (full auto-registration protocol) stays deferred per the
proposal's own recommendation -- real scope, needs its own discussion,
not something to fold into either of the items below.

### [0020] 2026-09-18T01:00:00Z — for: pc-agent
Section 2 of the same proposal is yours: organiser-agent's /config
dashboard shows a blank machine_name field even though the agent is
already using the OS hostname as a fallback (GetComputerNameA/
gethostname) in /status. Minor UX fix -- show the effective/fallback
name as a placeholder in the config UI field instead of blank, so the
user can see what name is actually in effect without having to check
/status separately.

### [0021] 2026-09-18T01:00:00Z — for: hub-cicd
Section 3 of the same proposal is yours: a hub-monitor systemd timer
(oneshot, NOT a daemon -- same pattern as your autoupdate timer) that
polls every configured PC's /status every ~3 minutes and writes a
small JSON status file (e.g. /var/lib/hub-monitor/pc-status.json) that
hub-cli/hub-diagnostics can read for instant cached status. Full
suggested shape and JSON format in the proposal doc. This complements
(doesn't replace) the live polling lead just added to
pc_list_configured -- that one's real-time from Render's side, this
one's a local cache from the hub's side for fast CLI reads without a
live round-trip.

### [0022] 2026-09-18T02:30:00Z — for: ALL
The v1 PC auto-discovery proposal (Tailscale on every PC) is DEAD --
explicitly rejected by the user. Read
coordination/proposals/pc-autodiscovery-2026-09-18-v2.md for the
corrected design: PCs self-register to the Linux hub over the LAN (no
manual ports, ephemeral port binding), the hub polls every 5 minutes
with a 3-retry/3-second-interval grace period before declaring a PC
offline, state transitions get logged as events, and Render never talks
to a PC directly -- only ever to the hub, over the existing tailscale
ssh channel, same as today. pc-tunnel@.service gets retired once this
is proven working, not before.

### [0023] 2026-09-18T02:30:00Z — for: pc-agent
Your piece of v2: organiser-agent binds its HTTP listener on an
OS-assigned ephemeral port (port 0) instead of a configured one, and
sends a periodic registration announcement to the hub (LAN
broadcast or a fixed hub LAN address -- coordinate with hub-cicd on
which) containing machine_id, machine_name, its own LAN IP, the port it
bound, and a registration token (reuse ORGANISER_SECRET's pattern, not
a new secret type).

### [0024] 2026-09-18T02:30:00Z — for: hub-cicd
Your piece of v2: a registration listener + local registry (JSON or
SQLite under /var/lib/hub-monitor/) + the polling timer (5 min interval,
3 retries at 3s apart before offline, event log on state transitions)
+ a LAN-relay path server.py can drive over the existing SSH channel
for live PC actions (not just status). Sequence this so
pc-tunnel@.service is only retired after the new path is proven working
end to end, not before -- no window where PCs go unreachable during the
transition.

### [0025] 2026-09-18T03:00:00Z — for: hub-cicd
v2 design refinement: online/offline events must be actively PUSHED to
Render (a small authenticated HTTPS POST to a new server.py endpoint --
lead will build that side), not just written to the local event log for
Render to poll later. This doubles as Render's wake-up trigger from its
free-tier sleep. See the updated section 4/5 in
pc-autodiscovery-2026-09-18-v2.md.

Also: the user asked me to hold off merging your current branch into
main for now -- they want a stable snapshot of your current work as a
usable "v1" (to actually install/use now) before the v2 auto-discovery
changes land and become a "v2". Keep committing to your branch as
normal; I just won't fast-track a merge this round.
