# Task Brief: Windows PC Agent + Multi-PC Registry
Branch: agent/pc-agent
Status file: coordination/status/pc-agent.md

## Scope
organiser-agent.py, organiser-agent.cpp, pc-tunnel@.service, plus any new
files you need (machine registry config, Windows service wrapper, etc).

## Context
This is the Windows-side agent the hub/MCP server talks to for PC
management: command execution, file ops (move/delete/preview), disk
usage, duplicate detection, screenshots, health/status.

## Known baseline issues to verify and address
- shutil.move / shutil.rmtree in organiser-agent.py (~line 136, ~152)
  with no visible path-traversal or protected-path checks. Confirm and
  fix — Windows system-critical paths must not be movable/deletable via
  this agent. Don't hardcode C:\Windows; use proper Windows path/env
  APIs.
- subprocess.run with a timeout (~line 233) — check argument
  construction for injection risk (list args vs shell string), verify
  the timeout is actually enforced and errors handled cleanly.
- No visible machine identity/registry concept. Design a small registry
  (config file + unique machine ID) so this agent can be one of several
  (desktop/laptop/server) instead of a single hardcoded target. Check
  coordination/status/hub-cicd.md for the tunnel-side machine-ID scheme
  before finalizing yours so the two sides agree; if it's not posted
  yet, propose one in your own status file.
- Treat command execution and path-based file operations as SEPARATE
  risk surfaces — a path allowlist for file ops does not make arbitrary
  command execution safe, and vice versa.

## Deliverables
1. Working, tested changes on branch agent/pc-agent.
2. Real tests for: path traversal attempts, protected-path rejection,
   command timeout behavior, malformed input, duplicate detection,
   screenshot failure handling.
3. coordination/status/pc-agent.md: what changed, what you tested, what
   remains weak/unverified.

## Out of scope
Don't touch server.py or Render/CI/tunnel-service files. Note concerns
in your status file instead.
