# Status: docs-release
Updated: 2026-09-13T10:55:00Z
Branch: agent/docs-release
State: DONE (for the scope in my brief -- see "Open items" for what's
deliberately left for others / future work, not blockers on my end)
Last broadcast read: 0010

## Summary
All 5 deliverables from coordination/tasks/docs-release.md are landed,
pushed, and cross-checked against the current state of main + every
other subagent branch (re-pulled and reacted to main 4 times this
session; last check found nothing new). 13 commits total on
agent/docs-release. Caught and fixed one real bug of my own along the
way (see below) rather than shipping it.

## Deliverables (final state)
1. README.md / BUILD_AND_SETUP.md rewritten, ARCHITECTURE.md added.
   README is a short entry point; ARCHITECTURE.md holds the
   architecture/auth/limitations/security-findings detail so it's in
   one place, not duplicated across 4 docs.
2. Tag-triggered release workflow (.github/workflows/release.yml):
   build organiser-agent.exe (Windows/MSVC) -> run the full test suite
   (pytest, correctly configured -- see below) -> package server.py +
   docs + installer into a versioned zip -> publish to GitHub Releases.
   Scoped narrower than hub-cicd's eventual push/PR CI on purpose (see
   the note at the top of the workflow file).
3. Windows PC agent installer (scripts/install-organiser-agent.ps1):
   fetches a release build via the GitHub API (works for this private
   repo with -GitHubToken), verifies its sha256, installs, preserves
   secret/port across upgrades, registers the Scheduled Task, and polls
   /status to confirm it's actually running. Syntax-checked with
   PowerShell's own parser. Linux hub installer intentionally not
   built -- hub-cicd has zero commits, so there's no tunnel-design detail
   yet to build one against.
4. Honest "Known limitations" section, centralized in ARCHITECTURE.md,
   kept current through 3 rounds of real upstream changes this session
   (Plex removal + file_transfer, security-qa's confirmed findings
   landing on main, the lead's 4 direct fixes for findings from both
   docs-release and security-qa, pc-agent's pending-merge work).
   Nothing in it is stale as of this update -- every bullet was
   re-verified against the actual current code, not left over from an
   earlier pass.
5. This status file.

## Files changed (cumulative, final)
README.md, ARCHITECTURE.md (new), BUILD_AND_SETUP.md, SKILL.md,
.secrets.example, .github/workflows/release.yml (new),
scripts/install-organiser-agent.ps1 (new), pytest.ini (new),
requirements-test.txt (new), coordination/status/docs-release.md.
No changes to server.py, organiser-agent.*, or anything outside my lane.

## Tests run (command -> result)
- Full suite, independently, in a clean venv against current main:
  pip install -r requirements.txt -r requirements-test.txt && pytest tests/
  -> 77 passed, 0 failed (matches the lead's own report in BROADCAST
  [0009] -- independently re-verified, not just trusted).
- Caught a real bug of my own before it shipped: without
  requirements-test.txt/pytest.ini (which didn't exist until I added
  them this session), 11 of those 77 tests fail with a misleading
  "async def functions are not natively supported" error -- meaning my
  own release.yml's test job would have failed for any tag cut after
  security-qa's async tests landed. Fixed (commit db3d7e5) and
  re-verified 77/0 with the fix in place before pushing.
- python -c "import ast; ast.parse(open('server.py').read())" -> parses cleanly
- python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" -> valid YAML (re-checked after the pytest fix too)
- PowerShell parser check on install-organiser-agent.ps1 -> no syntax errors
- grep -rniI 'plex|transfer__' across every doc -> only intentional
  "this was removed" notices and unrelated pipeline-path names remain

## Findings / security notes
- My own bug, found and fixed: release.yml's test step was missing
  pytest-asyncio + asyncio_mode config (see Tests run above). Added
  requirements-test.txt + pytest.ini.
- Folded in and kept current: security-qa's confirmed findings (now
  merged to main) and pc-agent's pending-merge fixes. Precisely
  distinguished, per finding, which are: still fully open (working_dir
  command injection -- HIGH, still unfixed as of this update; secret
  comparison not constant-time; oversized-body silent truncation;
  StrictHostKeyChecking=no), partially fixed (max_bytes DoS -- server.py
  clamps it now, organiser-agent's own allocation-before-check bug is
  still open), or fully fixed (write_codespace_file's silent failure;
  file_transfer's two silent-fallback footguns) -- see ARCHITECTURE.md
  for the current, accurate state of each.
- Two of my own earlier tooling findings (write_codespace_file,
  file_transfer silent fallbacks) were fixed directly by the lead in
  commit 7dc1695 -- confirmed the fix in the actual diff, not just the
  commit message, before updating my docs.
- Fly vs Render: unchanged, genuinely can't resolve this myself -- still
  documented as "Render confirmed, Fly present-but-unconfirmed,"
  pointing at hub-cicd's eventual status file.

## Open items (not blockers on my end -- flagging for whoever picks these up)
- hub-cicd: zero commits beyond main all session. Fly-vs-Render and any
  real CI workflow both remain genuinely unresolved until they (or the
  lead) act. My docs are written to be correct either way and to point
  at their status file rather than guessing.
- pc-agent's branch: 4 real commits, not yet merged. Once merged,
  ARCHITECTURE.md's "Pending: agent/pc-agent's fixes" section should be
  folded into the main body (organiser-agent.py vs .cpp table, the
  "no PC identity" and "text-only PC transfer" limitations) instead of
  living as a separate pending section -- flagging this as a small
  follow-up doc pass, not doing it now since it isn't merged yet and I
  don't want to document something as current that isn't.
- file_transfer's pc: leg is still text-only on main today, even though
  the binary-safe agent endpoints exist on pc-agent's branch -- someone
  needs to wire server.py's file_transfer to call
  /read_file_b64 / content_b64 once that branch merges. Outside both
  pc-agent's and my own scope; noted so it doesn't get lost.
- The working_dir command injection (SECURITY_FINDINGS.md finding 1,
  HIGH) is still unfixed as of this update -- pc-agent's landed commits
  address a different bug (run_command's missing timeout), not this
  one, despite BROADCAST [0010] flagging it as top priority for them.
  Worth the lead's attention if pc-agent doesn't pick it up before
  merging.

## Blockers / questions for lead
None on my own deliverables. Everything above is informational handoff,
not something I need an answer to before considering my brief complete.
