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
