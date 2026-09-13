# Status: docs-release
Updated: 2026-09-13T10:30:00Z
Branch: agent/docs-release
State: IN_PROGRESS

## Summary
All 5 deliverables have a landed first version (11 commits total).
This session: merged main twice more (per the "merge every resume"
protocol) and reacted both times. First merge brought in
security-qa's work landing on main for real (SECURITY_FINDINGS.md,
their status file, 4 new test files) — updated my "pending merge"
framing to reflect that. Second pull revealed agent/pc-agent now has 4
real commits (still unmerged to main) with machine identity,
binary-safe agent endpoints, a local config dashboard, and a real
verified run_command timeout fix — added a clearly-hedged "pending,
not yet merged" section for that too, plus cross-links from the two
"Known limitations" bullets it directly affects. Did not touch any
non-doc file on either of their branches; only read them.

## Files changed (on agent/docs-release, cumulative)
- README.md (rewrite + Known limitations highlights, incl. security-qa findings)
- ARCHITECTURE.md (new; now includes Confirmed security findings +
  Pending pc-agent fixes sections)
- BUILD_AND_SETUP.md (cross-links, installer section, private-repo fix)
- SKILL.md (Plex removed, file_transfer added, tool-count fix)
- .secrets.example (rewrite, Plex vars removed)
- .github/workflows/release.yml (new)
- scripts/install-organiser-agent.ps1 (new)
- coordination/status/docs-release.md (this file)

## Tests run (command -> result)
- python tests/test_admin_cookie_auth.py -> pass
- pytest tests/ -v -> 8 passed (test_file_transfer.py; this was before
  security-qa's extra test files merged into main — haven't re-run the
  now-larger suite myself, their own status file reports it passing
  independently, not re-verified by me this round)
- python -c "import ast; ast.parse(open('server.py').read())" -> parses cleanly
- python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" -> valid YAML
- PowerShell parser check on install-organiser-agent.ps1 -> no syntax errors

## Findings / security notes
- security-qa's findings (working_dir injection in organiser-agent,
  unbounded max_bytes DoS via pc_read_file_preview, non-constant-time
  agent secret comparison, silent oversized-body truncation,
  StrictHostKeyChecking=no, two file_transfer silent-fallback
  footguns, uncapped file_transfer read side) are folded into
  ARCHITECTURE.md's "Confirmed security findings" section, now
  correctly described as merged to main (not pending, as I had it
  before this update).
- pc-agent's landed-but-unmerged fixes (machine identity,
  /read_file_b64 + content_b64, /config+/admin dashboard,
  organiser-agent.py protected-path guard, run_command timeout fix)
  are folded in as a clearly-labeled pending section. Important nuance
  I made sure to capture accurately: the new binary-safe agent
  endpoints exist, but file_transfer itself isn't wired to use them
  yet (that's a server.py change, outside pc-agent's and my own
  scope) — so file_transfer's PC-leg text-only limitation is still
  literally true today even once pc-agent's branch merges, until
  someone does that wiring.
- Windows-only code paths in pc-agent's work (Job Object timeout-kill,
  Windows path-traversal semantics) are explicitly unverified by
  execution per their own status file — carried that caveat through
  rather than presenting it as confirmed.
- Fly vs Render: unchanged, still pending hub-cicd (still zero commits
  beyond main).

## Blockers / questions for lead
- Nothing blocking. agent/hub-cicd still has zero commits beyond main.
- Once agent/pc-agent and agent/security-qa's test suites are actually
  merged to main together with any server.py changes, I should re-run
  the full test suite myself rather than relying on their self-reports
  — noting this as my own next check, not asking anyone to do it for
  me.
