# Status: docs-release
Updated: 2026-09-18T11:00:00Z
Branch: agent/docs-release
State: ACTIVE
Last broadcast read: 0018

## ⚠️ FOR LEAD — new user feature request, needs your sign-off

Filed in `coordination/proposals/pc-autodiscovery-2026-09-18.md`.
Summary of what the user wants:

- **Auto-registration**: PCs should appear automatically when they
  come online, no manual config editing
- **No manual ports**: user doesn't want to think about port numbers
  at all — proposal recommends putting PCs on the Tailnet (Tailscale
  already runs on the Linux server, natural extension) to eliminate
  port-forward tunnels entirely
- **5-minute polling** with a 3-retry / 3-second-interval grace period
  before declaring a PC offline (not instant miss = offline)
- **Online/offline events** logged when status changes, visible via
  a tool like `pc_events`
- `pc_list_configured` should show **live reachability + the PC's own
  Windows hostname** (already in `/status` as `machine_name`, just not
  surfaced in the list tool today)

The proposal has 4 open questions that need your answers before anyone
starts building — most importantly: **is Tailscale on Windows PCs an
acceptable dependency?** That gates the whole no-ports design.

Not starting any of this myself — it's pc-agent + hub-cicd territory,
and it's a real scope decision, not a docs task.

## This session's doc work (separate from the proposal)

- Fixed 7 stale "text-only PC leg" references in SKILL.md (it's been
  binary-safe since agent/pc-agent merged)
- Added security-qa findings 24 + 25 to ARCHITECTURE.md (Python agent
  /preview silently corrupts binary files; Python agent binds 0.0.0.0
  not loopback)
- Reconciled ARCHITECTURE.md/README.md against all merged fixes
- Filed and verified the external AI review handoff
  (coordination/proposals/external-review-2026-09-13.md)

## Deployment readiness (as of this update)

Close but not quite shipped:
- Core server (server.py on Render): deployable, verified live end-to-end
- pc__screenshot: still broken (wrong mime + 200-char truncation)
- hub-cicd: no .deb packaging yet
- security-qa findings 24/25: unmerged
- Windows code paths in organiser-agent.cpp: reviewed but never
  run on actual Windows

## Tests
203 passed, 1 skipped, 1 xfailed — last full run against main this session.

## Blockers
None on my own docs work. Everything above is routing/flagging for you.
