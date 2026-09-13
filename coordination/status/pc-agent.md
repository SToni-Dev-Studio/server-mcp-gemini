# Status: pc-agent
Updated: 2026-09-13T10:03:57Z
Branch: agent/pc-agent
State: DONE (for the scope in my brief + broadcast [0006]; see Blockers for what's genuinely unverified)
Last broadcast read: 0008

## Summary
Fixed a real, verified bug in organiser-agent.cpp (run_command had no
enforced timeout — popen()-based, would hang forever). Added a
protected-path guard to organiser-agent.py (it had none at all —
shutil.move/rmtree took any path, unlike the .cpp build which already
had this). Added machine identity (machine_id/machine_name) exposed via
/status per broadcast [0002] correction — NOT a competing registry;
server.py's PCS registry is still the source of truth for hub-side PC
config. Per broadcast [0006]: added /read_file_b64 + content_b64
support on /write_file (binary-safe file transfer) and a /config +
/admin local dashboard (secret/machine_name management without
hand-editing files) to both organiser-agent.py and organiser-agent.cpp.

Pinging lead directly: /read_file_b64 (GET, query params path/max_bytes,
returns {content_b64, size_bytes, returned_bytes, truncated}) and
/write_file's new content_b64 body field are ready in both builds —
file_transfer's pc: leg can be wired to them.

## Files changed
- organiser-agent.py — protected-path guard, machine registry, /config,
  /admin, /read_file_b64, content_b64 on /write_file
- organiser-agent.cpp — run_command timeout fix (real bug), machine
  registry, /config, /admin, /read_file_b64, content_b64 on /write_file
- tests/test_organiser_agent.py — new, 33 tests

Commits (agent/pc-agent, all pushed):
- 377d3e9 — organiser-agent.py changes
- 59cf209 — organiser-agent.cpp changes
- b25bf52 — tests

## Tests run (command -> result)
All run for real, in this environment (Linux sandbox — see Blockers for
what that does and doesn't prove):

- `python3 -m unittest tests.test_organiser_agent -v`
  -> 33 tests, 32 pass + 1 expectedFailure (see below). Run from repo
     root with `HOME` pointed at a scratch dir so config-file tests
     don't touch a real user profile.
  Covers: protected-path logic + Flask routes (move/delete/write_file/
  list all correctly 403 inside C:\Windows, forward-slash-form path
  traversal collapses correctly), machine_id persists across a reload
  and survives a corrupted config file, run_command timeout/malformed
  input/nonzero-exit handling via the actual Flask test client, binary
  round-trip through content_b64 write + read_file_b64 read (a
  256-distinct-byte-value blob, verified byte-identical both ways),
  invalid-base64 rejected cleanly (400, no file written), /config
  hot-reloads machine_name and secret without restart, and env-var
  secret still wins over an attempted config-file override.
  One test (`test_path_traversal_attempt_still_caught`) is marked
  `@unittest.expectedFailure` with an inline explanation: on Linux,
  pathlib.PosixPath never normalizes '/' vs '\' the way WindowsPath
  does on real Windows, so a backslash-form traversal check across
  separator styles can only be fully confirmed on an actual Windows
  host. Confirmed by hand that this is a POSIX-path-semantics artifact,
  not a logic bug, by comparing resolve() output for both forms
  directly (see commit message / earlier session for the exact repro).

- `g++ -std=c++17 -O2 -Wall -o organiser-agent organiser-agent.cpp -lpthread`
  -> compiles clean (one expected unused-function warning for
     b64_encode, which is only referenced from the #if IS_WIN screenshot
     path).

- Manual, real HTTP tests against the compiled Linux binary (not
  mocked — actual curl requests to a running instance):
  - /status returns machine_id/machine_name.
  - run_command: quick command returns fast; nonzero exit reported
    correctly; missing command -> 400; bad working_dir -> 400.
  - **Timeout, the important one**: `sleep 90` against the 60s deadline
    -> returned `{"error":"Command timed out after 60s"}` at exactly
    60s elapsed (measured). Confirmed via `ps aux` 35s later that the
    killed process was gone (not just abandoned).
  - **Process-group kill**: `sleep 90 & wait` (a backgrounded
    grandchild) — confirmed via `ps aux` while running that both the
    `bash -c` wrapper AND the grandchild `sleep 90` existed, then
    confirmed both gone after the timeout fired. This is exactly the
    case the old popen()-based code would have leaked.
  - content_b64 write_file + read_file_b64: wrote a 1024-byte blob
    covering all 256 byte values via content_b64, verified the on-disk
    file was byte-identical to the input, then read it back via
    read_file_b64 and verified that was also byte-identical. Malformed
    base64 -> 400, no file written. Nonexistent path -> 404. max_bytes
    truncation flagged correctly (truncated: true, returned_bytes
    matches the cap).
  - /config + /admin: set secret via /config -> /status immediately
    started requiring it (no restart) -> correct secret succeeds,
    wrong one 401s. /admin loads fine with no secret header even after
    a secret is set (page shell exempted, /config calls it makes are
    still checked). Empty machine_name rejected (400). Env-var secret
    confirmed to still win when a config-file secret is also POSTed.

## Findings / security notes
- **Real bug, fixed**: organiser-agent.cpp's run_command had no timeout
  enforcement at all (popen() blocks until the child exits, full stop).
  A hung or malicious long-running command would tie up a connection
  thread indefinitely. Fixed with fork/exec + poll + process-group
  SIGKILL on deadline (POSIX) and CreateProcess + Job Object (Windows,
  reviewed only, not compiled — flagging honestly, not claiming it
  works).
- **Real gap, fixed**: organiser-agent.py had NO protected-path checks
  anywhere — every file op could touch C:\Windows. organiser-agent.cpp
  already had this; now both agree.
- Investigated whether the single global ORGANISER_SECRET is a gap
  given the hub's per-PC secrets in PCS — it isn't: each organiser-agent
  process IS one physical machine with exactly one secret matching its
  own PCS entry, so there's no "which PC's secret" ambiguity for the
  agent side to resolve. Documenting this reasoning rather than
  building something to solve a non-problem.
- /run_command's shell-execution nature is an unavoidable, separate
  risk surface from the path guard — documented clearly in-code on both
  builds (it accepts a full command line, not an argv list, so there's
  no static way to tell whether it touches a protected path). Mitigated
  by ORGANISER_SECRET + recommending least-privilege OS accounts, not by
  a string check.
- No Plex references anywhere in this file's area (verified via grep
  per broadcast [0004] — there weren't any to begin with).

## Blockers / questions for lead
- **Windows-only code paths are unverified by execution**: the C++
  run_command's CreateProcess/Job Object path, and both builds'
  Windows-specific protected-path resolution (GetWindowsDirectoryA /
  SystemRoot-based), are code-reviewed carefully but never compiled or
  run — no Windows toolchain in this environment. If anyone has a
  Windows box, worth a real smoke test before this goes into
  production, especially the Job Object timeout-kill path.
- No blockers on my actual scope — brief + broadcast [0006] items are
  done, tested to the extent this environment allows, and pushed.
