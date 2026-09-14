# Status: pc-agent
Updated: 2026-09-13T16:34:20Z
Branch: agent/pc-agent
State: DONE (brief + broadcast [0006] + all priority security findings from [0010]/[0011]/[0013]; see Blockers for the one thing genuinely out of my hands)
Last broadcast read: 0015

## Summary
Round 1: fixed a real, verified bug in organiser-agent.cpp (run_command
had no enforced timeout), added a protected-path guard to
organiser-agent.py (had none at all), added machine identity exposed via
/status (broadcast [0002]), and added /read_file_b64 + content_b64 on
/write_file plus a /config + /admin local dashboard to both builds
(broadcast [0006]). Merged into main at bd8714c.

Round 2: treated the HIGH-severity working_dir injection as top priority
per broadcast [0010]; verified it was ALREADY closed as a side effect of
round 1's run_command rewrite (proved with security-qa's exact exploit
plus a stricter test of my own). Fixed three more organiser-agent.cpp
findings (4, 5, 7) and one infra finding (6). Pushed after lead had
already merged round 1 into main -- so lead's independent rediscovery of
finding 7 (broadcast [0011]/[0013]) was correct at the time, just ahead
of this fix reaching main.

Round 3 (this update): read broadcasts [0011]-[0015] in full, ran the
new step-0 check (git fetch + compare origin/agent/pc-agent against what
I remembered pushing -- clean, no surprise commits from another
session). Merged origin/main (resolving 2 real conflicts -- both sides
had independently reached the same conclusions on finding 1, reconciled
into one version). Properly fixed the mcp-SDK dependency mismatch I'd
previously given up on (installed the exact pinned mcp==1.29.0 from
requirements.txt) so I could finally run the FULL test suite, not just
my own subset. Re-verified finding 7's fix end-to-end against lead's own
regression test using the exact 128,000-byte payload that caught the bug
originally -- confirmed it holds. Raised server.py's
_PC_TRANSFER_SAFE_MAX_BYTES workaround back to the full 15MB now that
it's no longer needed, and updated the e2e test file per its own
embedded instructions (invert, don't delete).

## Files changed (round 3, on top of rounds 1-2)
- server.py -- raised _PC_TRANSFER_SAFE_MAX_BYTES to match
  _FILE_TRANSFER_MAX_BYTES (15MB), updated now-stale comments/error
  message
- tests/test_file_transfer_pc_e2e.py -- inverted
  test_organiser_agent_still_has_the_64kb_truncation_bug into
  test_organiser_agent_no_longer_has_the_64kb_truncation_bug (per its
  own instruction); fixed test_pc_transfer_rejects_payload_over_the_safe_cap,
  which broke because raising the pc-specific cap to equal the general
  cap makes the general check fire first (rewrote to check the actual
  safety property, not a specific error-message wording)
- SECURITY_FINDINGS.md -- finding 7 marked fully fixed and end-to-end
  verified, with the merge-timing explanation documented

Commits (agent/pc-agent, all pushed, HEAD is 038dd96):
- 86caa29, 734213f, f742298, 6f5d451, 0e9d39d -- round 2 (see prior
  status entries, still on this branch, unchanged)
- d6e12bc -- merge origin/main (resolved conflicts in
  SECURITY_FINDINGS.md, tests/test_organiser_agent_security.py)
- 038dd96 -- finding 7 end-to-end closure (this round)

## Tests run (command -> result)
- `python3 -m pytest tests/ -v` (FULL SUITE, all 116 tests, all test
  files including ones I couldn't previously collect) -> **115 passed,
  1 xfailed**. Fixed the blocker myself this round: previous sessions'
  attempts to install `mcp` pulled in an incompatible v2.x API
  (FastMCP renamed); installing the exact `mcp==1.29.0` pinned in
  requirements.txt resolved it cleanly. This is the first time I've
  run the actual complete suite rather than a subset.
- `python3 -m pytest tests/test_file_transfer_pc_e2e.py -v` (lead's own
  finding-7 regression suite) -> all 5 pass, INCLUDING the inverted
  truncation-bug test using the exact 128,000-byte payload that
  originally caught the bug -- confirmed byte-identical on disk now
  (was 48,981 of 128,000 bytes before the fix).
- `g++ -std=c++17 -O2 -Wall -o <bin> organiser-agent.cpp -lpthread`
  -> compiles clean.

## Findings / security notes
- The "finding 7 rediscovery" flagged in broadcast [0011]/[0013] was a
  merge-timing artifact, not a real regression or a flaw in my fix.
  Confirmed via git history: `86caa29` (my finding-7 fix) was pushed to
  `agent/pc-agent` AFTER lead had already merged an earlier state of
  this branch into `main` at `bd8714c`. Lead's rediscovery, using a
  128,000-byte payload against that pre-fix `main` state, was entirely
  correct at the time -- it just predated the actual fix. I verified
  this explanation by checking `git merge-base --is-ancestor 86caa29
  origin/main` (returned false at the time) rather than assuming either
  side's report was wrong.
- Both my branch and main independently arrived at the same fix and the
  same conclusion for finding 1 while working in parallel (my own
  verification vs. lead's live re-verification, per broadcast [0011]) --
  a nice cross-validation, reconciled into one merged writeup rather
  than picking one side arbitrarily.
- Raising `_PC_TRANSFER_SAFE_MAX_BYTES` to equal `_FILE_TRANSFER_MAX_BYTES`
  made the pc-specific size check in `server.py`'s `_location_write_bytes`
  effectively dead code at that exact threshold (the general check earlier
  in the function now always fires first). Left the pc-specific check in
  place rather than removing it -- it's harmless, self-documenting, and
  becomes live again if either constant is ever changed independently of
  the other -- but rewrote the test that exercised it to check the
  actual safety property (oversized pc: writes are still rejected,
  never silently corrupted) instead of a specific error-message wording
  that was really an implementation detail of which code path caught it.
- Followed the new step-0 routine from broadcast [0014] this session:
  checked `origin/agent/pc-agent` against what I remembered pushing
  before starting work, and again before the final push. Both checks
  came back clean (no unrecognized commits) -- the incident described in
  [0014] doesn't appear to have recurred here.

## Blockers / questions for lead
- **Finding 2 (Windows-side injection) still cannot be verified by
  execution** -- no Windows toolchain available to pc-agent in this
  environment either. The fix should close it by the same logic as the
  POSIX side (CreateProcess's lpCurrentDirectory instead of any shell
  string), but "should" isn't "verified." If anyone gets access to a
  real Windows box, this plus the CreateProcess/Job Object timeout-kill
  path are the two things most worth a real smoke test before this goes
  into production.
- No other blockers. Brief + broadcast [0006] + every priority security
  finding from [0010]/[0011]/[0013] are done, tested end-to-end against
  the actual regression tests that caught them (not just my own), and
  pushed. Full 116-test suite passes on this branch.
