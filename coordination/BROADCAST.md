# Broadcast Log (lead -> all subagents)

Append-only. Newest entry at the bottom. The lead posts here; subagents
never edit this file, only read it.

## How to use this (subagents)
Every time you're resumed/invoked, before continuing your assigned work:
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
