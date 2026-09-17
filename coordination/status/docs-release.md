# Status: docs-release
Updated: 2026-09-18T10:30:00Z
Branch: agent/docs-release
State: ACTIVE (ongoing maintenance — original brief done, keeping docs current as main moves)
Last broadcast read: 0018

## Summary
Original 5 deliverables are done and merged. This session: pulled main
(picked up massive merge — 22 files, 2481 insertions from pc-agent,
hub-cicd, lead fixes, security-qa's test files). Found and fixed real
stale content in SKILL.md. Also answered the "is this ready to deploy?"
question the user asked (answer: close but not yet — see below).

## Deployment readiness assessment (as of this update)

**The core server (server.py on Render) IS in a deployable state:**
- Lead has verified the full chain live end-to-end (MCP client →
  Render staging → Tailscale → real home server → real command executed)
- All HIGH/MEDIUM security findings fixed or meaningfully mitigated
- 203 tests passing in a clean venv, 1 xfailed (expected), 1 skipped

**Still open before calling it "shipped":**
- `pc__screenshot` is broken end-to-end (wrong mime + 200-char truncation
  in server.py, plus organiser-agent's function returns BMP not PNG) —
  routed to pc-agent via broadcast [0018], not fixed yet
- `hub-cicd` has no .deb packaging or auto-update mechanism yet (broadcast
  [0017] asked for this) — hub-cli.py exists but isn't packaged/installable
- `agent/security-qa` has 5 unmerged commits with 2 new findings (24: Flask
  organiser-agent /preview silently corrupts binary files; 25: it binds
  0.0.0.0 not loopback) — not yet merged to main
- Lead's COMPETITION_REPORT.md doesn't exist yet
- Windows code paths in organiser-agent.cpp (CreateProcess/Job Object)
  reviewed but never compiled/run on actual Windows — genuinely unverifiable
  with no Windows box anywhere in this project

**Lead responded to the external review handoff:** yes, thoroughly —
directly fixed A2 (env masking, with regression test) and A10 (read-side
cap), routed A1/A4/A5/A6/A7/A8 to pc-agent via broadcast [0018].

## Files changed this session
- SKILL.md: 7 stale "text-only PC leg" references fixed; /screenshot
  annotated as broken; /read_file_b64 added to endpoint table;
  /write_file content_b64 documented
- ARCHITECTURE.md: security-qa findings 24 + 25 added; organiser-agent.py
  binding comparison row corrected (0.0.0.0 vs 127.0.0.1)
- coordination/status/docs-release.md: this file

## Tests run
203 passed, 1 skipped, 1 xfailed — full suite in clean venv against
current main (includes all security-qa test files now on main, hub-cli
tests, hub-diagnostics tests, etc).

## Blockers / open items
- pc__screenshot fix is pc-agent's, not mine
- .deb packaging is hub-cicd's, not mine
- security-qa's findings 24/25 are in my docs but their branch hasn't
  merged — I'll update once it does
- No blockers on my own docs work
