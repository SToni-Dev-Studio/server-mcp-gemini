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
