# Task Brief: Linux Hub, Tunnels, Render/CI, Testing, Diagnostics
Branch: agent/hub-cicd
Status file: coordination/status/hub-cicd.md

## Scope
pc-tunnel@.service, fly.toml, Dockerfile, start.sh,
.github/workflows/build-organiser-agent.yml, plus new files: a CI
workflow, a pytest test suite, a diagnostics tool, Render deployment
docs/config.

## Context
Intended architecture: AI/MCP client -> Render (server.py) -> Linux hub
-> per-PC tunnels -> PC agents. Baseline has one systemd template
(pc-tunnel@.service, tailscale-ssh based), a Dockerfile/fly.toml (Fly,
not Render — check whether Render deployment is actually documented and
working, or just assumed), and one build workflow for the C++ agent,
with no visible test workflow.

## Known baseline gaps to verify and address
- No CI test/lint step for server.py (Python) — only a build workflow
  for organiser-agent.cpp.
- No diagnostics tool reporting PASS/FAIL/SKIPPED/NOT_CONFIGURED per
  subsystem (GitHub auth, Plex, server SSH, PC tunnel reachability,
  Render config). Build one.
- pc-tunnel@.service is templated for one PC per systemd instance —
  confirm it cleanly supports N machines via instance names
  (pc-tunnel@<machine>.service) and propose/implement a machine registry
  format. Coordinate the machine-ID scheme with agent/pc-agent via
  status files.
- Confirm reconnection/health behavior if a tunnel drops, or whether it
  silently goes stale.
- Real tests for: MCP tool input validation, auth with password
  present/absent/wrong, server_run_command safety boundaries, and the
  admin dashboard auth path in server.py (read the actual auth section,
  roughly lines 170-230 and 1330-1440, before writing these — don't
  guess at its behavior).

## Deliverables
1. Working CI (lint + test) GitHub Actions workflow.
2. pytest suite testing real behavior, not just import success.
3. Diagnostics tool/script with honest PASS/FAIL/SKIPPED/NOT_CONFIGURED
   output.
4. Render deployment doc matching what's actually true (flag if Fly vs
   Render is inconsistent in the baseline).
5. coordination/status/hub-cicd.md: what changed, what you tested,
   what's unverified.

## Out of scope
Don't touch organiser-agent.py/.cpp internals or server.py's MCP tool
definitions. Note concerns in your status file instead.
