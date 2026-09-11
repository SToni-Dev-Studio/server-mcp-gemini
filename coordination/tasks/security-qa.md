# Task Brief: Adversarial Security Testing (Red Team)
Branch: agent/security-qa
Status file: coordination/status/security-qa.md

## Scope
No feature code changes unless something is so broken it needs an
immediate fix (note it either way in your status file — the lead
decides whether to merge a fix or just track the finding). Your output
is primarily: attack attempts, findings, and test cases proving them
(or disproving your own hypothesis — a documented attempt that failed
is still useful evidence, don't only report successful attacks).

## Targets
Attack whatever exists on `main` right now, and re-attack again once
agent/pc-agent, agent/hub-cicd, and agent/docs-release have pushed real
work (pull periodically, don't just test once at the start).

Areas to actually attempt, not just reason about abstractly:
- server.py MCP tools taking paths/commands: server_read_file,
  server_write_file, server_move_file, server_delete_file,
  server_run_command, exec_command (codespace SSH path),
  read_codespace_file, write_codespace_file. Try path traversal
  (../../, absolute paths, symlink tricks), shell metacharacters in
  arguments, oversized input, null bytes, unicode tricks.
- Auth: MCP_SERVER_PASSWORD bearer check (timing, malformed headers,
  case sensitivity, empty vs missing), admin cookie handling (already
  one real fix landed on main for a hardcoded-secret forgery bug --
  verify that fix actually holds, then look for anything similar
  elsewhere, e.g. other places a secret might have a guessable
  fallback).
- Concurrency: fire concurrent requests at state-changing tools (env
  var writes, file writes) and check for races.
- Malformed/adversarial MCP tool arguments: wrong types, missing
  required fields, extremely long strings, injection-shaped strings in
  every string parameter you can find across all tools in server.py.
- Once pc-agent lands: attempt the same categories against the Windows
  agent's exposed operations.
- Once hub-cicd lands: attempt tunnel/auth bypass against whatever
  hub-to-PC design they build.

## Deliverables
1. A written findings log (new file: SECURITY_FINDINGS.md on your
   branch) -- each finding with: what you tried, exact command/input,
   actual observed result, severity, whether it's exploitable or was
   already mitigated.
2. Automated regression tests for anything you find that's real
   (pytest, added to tests/), so it can't silently regress later.
3. coordination/status/security-qa.md summarizing what you tested, what
   you found, what's still unverified/untested.

## Rules
- Never fabricate a finding. If an attack attempt fails, say so plainly
  rather than omitting it or implying success.
- Don't attack anything outside this repo/codespace (no scanning real
  infrastructure, no touching sepisotoni's live Render/server/PC).
- Don't touch mienkek13-netizen/server-mcp-gpt or server-mcp-gemini.
