# Status: pc-agent
Updated: 2026-09-13T15:54:26Z
Branch: agent/pc-agent
State: DONE (brief + broadcast [0006] + priority security fixes from [0010]; see Blockers for the one thing genuinely out of my hands)
Last broadcast read: 0010

## Summary
Round 1 (earlier commits): fixed a real, verified bug in organiser-agent.cpp
(run_command had no enforced timeout), added a protected-path guard to
organiser-agent.py (had none at all), added machine identity
(machine_id/machine_name) exposed via /status per broadcast [0002]
correction (NOT a competing registry — server.py's PCS registry is still
the source of truth), and added /read_file_b64 + content_b64 on
/write_file plus a /config + /admin local dashboard to both builds, per
broadcast [0006].

Round 2 (this update): merged origin/main (picked up security-qa's full
pass and SECURITY_FINDINGS.md) and treated the HIGH-severity working_dir
injection as top priority per broadcast [0010]. Verified it was ALREADY
closed as a side effect of round 1's run_command rewrite — proved this
rather than assumed it, using security-qa's own exact exploit payload
plus a stricter test of my own. Then fixed three more organiser-agent.cpp
findings (4, 5, 7) and one infra finding (6), applied defense-in-depth
equivalents to organiser-agent.py where applicable, and updated
SECURITY_FINDINGS.md + security-qa's own test file in place (per that
file's explicit instruction) to reflect the fixes rather than leaving
stale "confirmed exploitable" language next to code that no longer is.

## Files changed (this update, on top of round 1)
- organiser-agent.cpp — max_bytes clamping (finding 4), constant-time
  secret comparison (finding 5), growable/validated request body reading
  (finding 7)
- organiser-agent.py — max_bytes clamping + hmac.compare_digest, for
  consistency with the cpp fixes
- pc-tunnel@.service — StrictHostKeyChecking=yes + per-PC known_hosts
  pinning (finding 6)
- SECURITY_FINDINGS.md — status updates on findings 1,2,3,4,5,6,7 with
  commit references
- tests/test_organiser_agent_security.py — two tests updated in place to
  assert fixed behavior (not deleted — matches that file's own
  instruction for exactly this situation), one new stricter test added

Commits (agent/pc-agent, all pushed):
- 86caa29 — cpp: findings 1/2 verification + fixes for 4, 5, 7
- 734213f — organiser-agent.py: defense-in-depth for findings 4, 5
- f742298 — pc-tunnel@.service: finding 6 fix
- 6f5d451 — SECURITY_FINDINGS.md + test file updates
(Round 1 commits: 377d3e9, 59cf209, b25bf52, 7507362 — see prior status,
still on this branch, unchanged.)

## Tests run (command -> result)
- `g++ -std=c++17 -O2 -Wall -o <bin> organiser-agent.cpp -lpthread`
  -> compiles clean, no warnings.
- `python3 -m pytest tests/test_organiser_agent.py tests/test_organiser_agent_security.py -v`
  -> 38 passed, 1 xfailed (the same documented Linux-path-semantics xfail
     from round 1). Includes the UPDATED security-qa tests now asserting
     fixed behavior, plus my new companion test.
- Full `tests/` could not be fully collected in this sandbox:
  test_admin_cookie_auth.py, test_file_transfer.py,
  test_file_transfer_extra.py, test_lead_fixes_round2.py,
  test_mcp_protocol_fuzzing.py all fail to import due to an mcp-SDK
  version mismatch pulling in server.py (`ModuleNotFoundError` chain
  inside the installed `mcp` package's own internals even after pinning
  `mcp<2`). This is a pre-existing environment/dependency gap unrelated
  to anything on this branch — none of those files import
  organiser-agent.py/.cpp, and I did not touch server.py. Flagging
  honestly rather than claiming those suites pass when I couldn't
  actually run them here.

Live, real HTTP verification against the compiled binary (not mocked):

- **Finding 1/2 (working_dir injection) — re-verified as fixed, not
  assumed fixed:**
  - Reproduced security-qa's exact payload
    (`working_dir="x' ; touch <marker> ; echo '"`) against my compiled
    binary -> now a clean 400 ("not a valid directory"), marker file
    NOT created.
  - Stricter test: created a REAL directory whose actual name contains
    `'; touch ...; echo '`, pointed working_dir at it, ran `pwd` as the
    command -> returncode 0, stdout is exactly that directory's real
    path, no injection, no marker file. Proves the chdir()/CreateProcess
    mechanism itself is safe, not just that the precheck rejected an
    invalid-looking string.
- **Finding 4 (unbounded max_bytes):** `max_bytes=10000000000` against
  an 11-byte file now returns 200 with the correct clamped content
  ("hello world") instead of crashing; confirmed process still responds
  to /status afterward.
- **Finding 5 (constant-time compare):** functional correctness
  preserved — correct secret 200s, wrong secret (same and different
  length) both 401, missing header 401s. (True timing-safety isn't
  provable from a functional test; the comparison shape now matches
  hmac.compare_digest's approach, which is what the finding asked for.)
- **Finding 7 (oversized body truncation):** a 300,000-byte write_file
  body previously would have silently truncated around 64KB with a
  false "success" — now arrives complete and correct (300000 bytes
  confirmed via a fresh read of the written file). A 26MB body (over
  the new 25MB hard ceiling) gets a clean 413 with no attempt to read it
  into memory at all; process confirmed alive and responsive
  immediately after.

## Findings / security notes
- Treated the working_dir injection (broadcast [0010]'s stated top
  priority) as top priority as instructed — but the correct finding
  here is that it required verification, not a new fix: round 1's
  run_command rewrite (done for the timeout bug, before security-qa's
  pass even existed) already eliminated the shell-string-building this
  bug depended on. I did not assume this from reading my own old diff —
  I compiled the current committed code and ran security-qa's literal
  exploit against it, then went further with an independent, stricter
  test of my own construction.
- Finding 4 is now fully closed, both sides — confirmed by reading
  actual code on both, not by assuming from the broadcast. The
  organiser-agent.cpp/.py side is fixed and verified by me. The
  server.py side (`pc_read_file_preview`) was separately fixed by lead
  in commit `7dc1695` (already merged into this branch) — I read the
  actual clamp against `_PC_PREVIEW_MAX_BYTES_CEILING` in server.py to
  confirm this rather than taking broadcast [0009]'s summary at face
  value.
- Finding 3 (no-secret-means-open) was deliberately NOT changed.
  Enforcing a mandatory secret would be a behavior/default change that
  could break existing deployments relying on today's easy-setup
  default — that's a product decision for the lead, not something a
  QA-findings bugfix pass should flip silently. Documented this
  reasoning directly in SECURITY_FINDINGS.md rather than either
  silently fixing or silently ignoring it.
- Finding 6 (pc-tunnel@.service) sits in territory hub-cicd also has
  scope over per broadcast [0007] (tunnel config). Fixed it since it was
  explicitly listed as part of my review scope in broadcast [0010], kept
  the change small and additive (one flag + a new per-PC known_hosts
  path, nothing existing removed) specifically to minimize collision
  risk if hub-cicd is also working in this file.
- Updated security-qa's own test file rather than leaving it stale.
  Followed the exact instruction embedded in the original tests'
  docstrings ("if this starts failing because the bug was fixed, please
  update SECURITY_FINDINGS.md to mark it remediated instead of just
  deleting this test") — updated both the doc and the tests in place,
  preserved the original historical documentation of what was found in
  comments, added one new test rather than just weakening assertions.

## Blockers / questions for lead
- **Finding 2 (Windows-side injection) still cannot be verified by
  execution** — no Windows toolchain available to pc-agent in this
  environment either. The fix should close it by the same logic as the
  POSIX side (CreateProcess's lpCurrentDirectory instead of any shell
  string), but "should" isn't "verified," and I want to be honest about
  that rather than claim a clean bill of health I can't back up. If
  anyone gets access to a real Windows box, this plus the earlier-flagged
  CreateProcess/Job Object timeout-kill path are the two things most
  worth a real smoke test before this goes into production.
- No other blockers. Brief + broadcast [0006] + the priority security
  fixes from [0010] are done, tested to the extent this environment
  allows, and pushed. Finding 4 is fully closed on both sides (no
  handoff needed there after all — see Findings section above).
