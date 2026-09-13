# Status: docs-release
Updated: 2026-09-13T10:10:00Z
Branch: agent/docs-release
State: IN_PROGRESS

## Summary
All 5 deliverables have a first landed version (9 commits pushed so
far). Re-pulled origin/main at the start of this session per the
"merge main every resume" protocol fix (commit 295bb45 on main) --
main is unchanged since my last merge, so no new doc corrections
needed from that side. agent/security-qa now has real commits (2) with
findings relevant to my "Known limitations" section -- see below.
agent/pc-agent and agent/hub-cicd still have zero commits beyond main.

## Files changed (on agent/docs-release, cumulative)
- README.md (full rewrite)
- ARCHITECTURE.md (new)
- BUILD_AND_SETUP.md (cross-links, installer section, private-repo fix)
- SKILL.md (Plex section removed, file_transfer section replacing the
  5 old transfer__* tools, tool-count fix)
- .secrets.example (full rewrite to match real config surface, Plex
  vars removed)
- .github/workflows/release.yml (new)
- scripts/install-organiser-agent.ps1 (new)
- coordination/status/docs-release.md (this file)

## Tests run (command -> result)
- python tests/test_admin_cookie_auth.py -> both PASS lines printed, no assertion errors
- pytest tests/ -v -> 8 passed, 0 failed (all from test_file_transfer.py)
- python -c "import ast; ast.parse(open('server.py').read())" -> parses cleanly
- python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" -> valid YAML
- PowerShell parser check ([...Parser]::ParseFile) on install-organiser-agent.ps1 -> no syntax errors
- grep -rniI 'plex|transfer__' across every doc I touched -> only intentional
  "this was removed" notices and unrelated pipeline paths remain (see below)

## Findings / security notes
- organiser-agent.py (legacy) has no path-traversal/protected-path
  checks; organiser-agent.cpp (deployed) does, except deliberately not
  on /run_command. Documented in ARCHITECTURE.md, not touched.
- file_transfer's pc: leg is text-only (organiser-agent's /preview and
  /write_file aren't base64-safe yet) -- binary PC transfers fail
  cleanly, don't corrupt. Documented; tracked as pc-agent's work per
  BROADCAST 0006.
- PC secret pairing (PCS registry entry vs that PC's own
  ORGANISER_SECRET) is manual and unenforced on both sides. Documented.
- NEW -- agent/security-qa has landed findings I should fold into
  ARCHITECTURE.md's "Known limitations" once I've read their status
  file/diff in full: a shell-injection issue via `working_dir` in
  organiser-agent, an unbounded `max_bytes` DoS reachable through
  server.py, and oversized-body truncation behavior. Their commit
  message also says they *verified* my "PC binary transfer fails
  cleanly" claim independently -- good, that's corroborated, not just
  asserted by me. Not yet reflected in my docs -- next step.
- Two tooling bugs found in server.py's own Codespaces tools (not
  fixed, out of scope, documented instead): write_codespace_file
  doesn't mkdir -p the target's parent dir or check the write
  succeeded before reporting success; create_git_commit_and_push uses
  git add -u, which only stages already-tracked files.
- Fly vs Render: still treating Render as the confirmed/documented
  target and Fly as present-but-unconfirmed, pending hub-cicd.

## Blockers / questions for lead
- agent/pc-agent and agent/hub-cicd still have zero commits beyond
  main. agent/security-qa now has 2 real commits with findings that
  overlap my "Known limitations" section (see above) -- I have not yet
  read their branch's diff/status file in full, that's my immediate
  next step, not a blocker.
- Nothing currently blocking my own progress.
