# Status: docs-release
Updated: 2026-09-13T13:15:00Z
Branch: agent/docs-release
State: DONE for original brief; ACTIVE on a new handoff task this update

## ⚠️ FOR LEAD — external review handoff, please triage
User ran this codebase past a couple of outside AI reviews and asked me
to check the claims and hand anything real along. Full writeup, every
claim independently verified against current code (not relayed on
faith), in `coordination/proposals/external-review-2026-09-13.md`.
Short version:

- **9 confirmed, currently real, unaddressed findings** — the two worth
  your attention first: `pc__screenshot` is broken end-to-end (wrong
  mime label + 200-char truncation in server.py, paired with
  organiser-agent.cpp's `screenshot_png` actually returning BMP), and
  `/admin/api/env` leaks every secret (GITHUB_TOKEN, MCP_SERVER_PASSWORD,
  SSH_PRIVATE_KEY, everything) to the browser in plaintext. Neither is
  something I'm equipped or in-scope to fix myself.
- Explicitly separated out which of the review's claims are already
  stale (fixed by pc-agent/security-qa's landed work) so you don't
  re-file closed items.
- Forwarded two larger proposals (a Windows desktop-app wrapper for
  organiser-agent; a capability/adapter refactor for server.py) exactly
  as the user asked — both clearly marked NOT STARTED, need explicit
  sign-off, not something I'm recommending or starting.

Not blocking anything of mine. Routing this to you rather than acting
on any of it myself, since server.py/organiser-agent.* are outside my
brief and most of section A overlaps pc-agent's/security-qa's territory.

## Summary
Original 5 deliverables (README/ARCHITECTURE/BUILD_AND_SETUP rewrite,
release.yml, PC installer script, Known limitations, this status file)
were DONE as of my last update. This session added:
1. Reconciled ARCHITECTURE.md/README.md against agent/pc-agent's fully
   merged fixes (run_command timeout+injection, protected paths on both
   builds, constant-time secret comparison, machine identity,
   binary-safe transfer restored to the full 15MB cap, StrictHostKey
   pinning) and agent/hub-cicd's render.yaml (Fly-vs-Render is now
   resolved for real, not hedged).
2. The external-review triage above.

## Files changed (this update)
- ARCHITECTURE.md, README.md (reconciliation against latest merges)
- coordination/proposals/external-review-2026-09-13.md (new)
- coordination/status/docs-release.md (this file)

## Tests run (command -> result)
Full suite last run this session, in a clean venv against main before
agent/pc-agent's and agent/hub-cicd's newest unmerged commits landed:
`pytest tests/` -> 115 passed, 1 xfailed. Have NOT re-run against their
very latest pushes (finding 20 fix, hub-cicd's CI wiring) as of this
update -- flagging honestly rather than implying I have.

## Findings / security notes
See the external-review file for the full list (section A: 9 confirmed
real findings; section B: which review claims are already fixed).
Nothing here contradicts anything already in SECURITY_FINDINGS.md --
this is additive, from a different reviewer, independently verified by
me before filing.

## Blockers / questions for lead
None of my own. The external-review handoff above is FYI/triage, not a
blocker -- proceeding to keep my own docs current regardless of what
you decide to do with it.
