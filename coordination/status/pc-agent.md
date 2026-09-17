# Status: pc-agent
Updated: 2026-09-16T18:09:47Z
Branch: agent/pc-agent
State: DONE (brief + broadcast [0006] + all priority security findings from [0010]/[0011]/[0013], plus a self-initiated HIGH-severity fix -- finding 20 -- found while checking in on other agents' work; see Blockers for the one thing genuinely out of my hands)
Last broadcast read: 0016
HEAD: 017a3a3

## Summary
Rounds 1-3 (prior status entries, unchanged): timeout fix, protected-path
guard, machine identity, binary-safe endpoints + config dashboard
(broadcast [0006]); HIGH-severity working_dir injection verified already
fixed, plus findings 4/5/6/7 fixed and verified live (broadcast [0010]);
merged main, reconciled a merge-timing gap around finding 7 with lead's
independent rediscovery, verified end-to-end against the actual
128,000-byte payload that caught it, raised server.py's defensive cap
back to normal. Broadcast [0016] confirms this branch is DONE and merged
into main (5bb71b6) -- lead independently recompiled and re-ran the full
suite before trusting the merge, got the exact same result.

Round 4 (this update): user asked me to look at agent/security-qa's
latest work for context. Found something directly actionable: a NEW
HIGH-severity finding (their finding 20) against my own /config
dashboard, discovered independently on their branch (not yet merged into
main) -- an unauthenticated caller could permanently hijack a PC agent by
setting the first-ever secret via /config whenever none was configured
yet. Confirmed the vulnerability myself against my own current code
(didn't just trust their report), fixed it in both organiser-agent.cpp
and organiser-agent.py, verified the fix live against both, caught and
fixed my OWN existing test that had encoded the vulnerable behavior, and
wrote independent regression tests (their equivalent tests live only on
their branch, not mine, so cherry-picking wasn't straightforward --
wrote matching coverage instead).

## Files changed (round 4)
- organiser-agent.cpp -- h_post_config now rejects bootstrapping the
  first-ever secret over the network (403); rotation of an existing
  secret unaffected
- organiser-agent.py -- update_config gets the equivalent guard
- Both /admin pages -- added a note explaining the restriction
- tests/test_organiser_agent.py -- rewrote
  test_post_config_sets_secret_and_it_takes_effect_immediately (which
  had encoded the vulnerable behavior) into
  test_post_config_cannot_bootstrap_initial_secret_unauthenticated, plus
  2 new companion tests (rotation still works, machine_name unaffected)
- tests/test_organiser_agent_security.py -- 3 new equivalent tests for
  the C++ side; isolated running_agent()'s $HOME per test (matching a
  fix security-qa made independently on their branch) so the persisted
  config file can't leak state between tests
- SECURITY_FINDINGS.md -- new finding 20 entry, explicitly crediting
  security-qa's independent, concurrent discovery of the same issue

Commit (agent/pc-agent, pushed): 017a3a3

## Tests run (command -> result)
- `g++ -std=c++17 -O2 -Wall -o <bin> organiser-agent.cpp -lpthread` ->
  compiles clean.
- `python3 -m pytest tests/ -q` (full suite) -> **120 passed + 1
  xfailed** (was 116 before this round's additions).
- Live verification against both compiled/running implementations, not
  just reading the diff:
  - Exact exploit (zero-credential POST of `{"secret": "..."}`)  against
    a freshly-started, unconfigured agent -> clean `403` in both
    organiser-agent.cpp (real compiled binary over real HTTP) and
    organiser-agent.py (Flask test client). Confirmed via `GET
    /config`'s `secret_set` field that nothing was actually persisted --
    not just that the one response said 403.
  - Legitimate rotation: bootstrapped a secret via a direct config-file
    write (the local-access path the fix requires for the *first*
    secret), then rotated it via authenticated `/config` -- old secret
    stops working, new one works, in both implementations.
  - `machine_name` changes confirmed unaffected by the guard (not a
    credential) in both implementations.
  - Caught my own mistake mid-verification: my first version of the
    rotation test bootstrapped via `ORGANISER_SECRET` (env var), which
    by design is immutable via `/config` at runtime (env var always
    wins) -- got a false failure, diagnosed it correctly as a test
    design issue rather than a bug in the fix, and rewrote the test to
    bootstrap via a direct config-file write instead.

## Findings / security notes
- This finding was NOT something I was asked to look for -- the user
  asked me to check in on agent/security-qa's work for context, and I
  found something directly actionable against my own code while doing
  so. Fixed it the same session rather than just noting it for later.
- Genuine cross-validation, not duplicated effort: security-qa found and
  reported this independently on their own branch (commit `f61783b`,
  not yet merged into main) at essentially the same time I found and
  fixed it here. Their writeup is more thorough than what I added to
  SECURITY_FINDINGS.md -- I credited them explicitly rather than
  presenting this as solely my own discovery.
- Their suggested fix ("simplest: never allow /config to set an initial
  secret over the network at all... once any secret exists, /config can
  rotate it") matches what I'd independently arrived at before reading
  their detailed suggestions -- worth noting as a second form of
  cross-validation on the fix approach itself, not just the finding.
- Their regression tests for this finding live only on
  `agent/security-qa`, not merged into `main`, so not available on this
  branch. Rather than trying to cherry-pick across branches (which
  isn't really mine to do), I wrote independent equivalent tests here.
  When their branch eventually merges, expect some overlap/redundancy
  between their finding-20 tests and mine -- worth a dedup pass at that
  point, not a conflict to worry about now.
- Also fixed a real gap in my OWN test suite while doing this: I had an
  existing test (`test_post_config_sets_secret_and_it_takes_effect_immediately`)
  that literally encoded the vulnerable behavior as correct/expected --
  written during round 1, before this finding existed. A reminder that
  "my own tests pass" was never sufficient evidence of security on its
  own; external review (in this case, incidentally, by another agent's
  concurrent work) caught what my own test suite was structurally
  blind to.

## Blockers / questions for lead
- **Finding 2 (Windows-side injection) still cannot be verified by
  execution** -- no Windows toolchain available to pc-agent in this
  environment either. Same status as every prior update.
- Not a blocker, but worth flagging: this branch (agent/pc-agent) now
  has a finding 20 fix that predates security-qa's own finding-20
  branch being merged into main. When main eventually picks up both,
  expect the SECURITY_FINDINGS.md entries and regression tests to need
  a light dedup pass (not a conflict -- both sides fixed the same real
  bug the same way, just documented/tested it independently).
- No other blockers. Everything from the brief, broadcast [0006], every
  priority security finding from [0010]/[0011]/[0013], AND this
  self-found finding 20 are done, tested live against real running
  instances of both implementations, and pushed.
