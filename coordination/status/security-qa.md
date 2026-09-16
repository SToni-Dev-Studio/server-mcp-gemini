# security-qa status

Last broadcast read: 0015

## ⚠️ URGENT FOR LEAD — recommend broadcasting: HIGH-severity finding 20
Unauthenticated `/config` POST can PERMANENTLY hijack a PC agent, confirmed
independently in BOTH organiser-agent.cpp and organiser-agent.py (Flask).
Worse than the already-known finding 3: not "anyone can run one command
during the exposure window", but "anyone can set their own secret,
persisted to disk, surviving restart, with no network recovery path for
the legitimate owner." Design-level gap replicated into two codebases.
Full details, confirmed mechanism, and suggested fix directions in
SECURITY_FINDINGS.md finding 20 and in the dated update further down this
file. I'm not editing BROADCAST.md myself (it's lead-only per its own
header), but given severity and that pc-agent may still be iterating on
this feature, flagging here as prominently as I can for you to relay.

## Done
- Re-verified the admin-cookie-forgery fix (b28ab02) independently; still
  holds. Searched for the same bug shape elsewhere in server.py — found
  none there, but found a close analog in organiser-agent.cpp (see below).
- Full pass over organiser-agent.cpp (compiled and dynamically tested as a
  native Linux binary — it's written to be cross-platform for exactly this
  reason). Found and confirmed exploitable:
  - **HIGH: command injection via `working_dir` in `/run_command`**
    (unescaped single-quote breakout on Linux; Windows path looks equally
    exploitable via `"`/`&` but I have no Windows box to confirm — flagged
    as unverified, not claimed).
  - No-secret-configured leaves every endpoint open (documented behavior,
    same bug shape as the admin-cookie issue, mitigated by loopback-only
    binding).
  - `/preview`'s `max_bytes` is unbounded and pre-allocates before
    checking the real file size → std::bad_alloc DoS (confirmed, process
    survives on Linux, Windows behavior unverified). **This chains
    directly through server.py**: `pc_read_file_preview`'s `max_bytes`
    param is forwarded with zero clamping — an MCP client can trigger this
    on a real PC with one tool call.
  - Secret comparison isn't constant-time (vs. server.py's correct
    `hmac.compare_digest` everywhere).
  - Oversized request bodies (>~64KB) are silently truncated with a
    reported "success" — confirmed by actually POSTing 200KB and getting
    back a corrupted 65,333-byte file with HTTP 200.
  - `pc-tunnel@.service` uses `StrictHostKeyChecking=no` (LAN MITM risk,
    low severity).
- Systematic sweep of every shell-command-building f-string in server.py:
  all properly escaped (`_q()`/shlex.quote or allowlist). Dynamically
  fuzzed with quote/backtick/$()/&&/newline payloads against
  server_read_file/move_file/write_file — no injection. **No findings** —
  this is a real, positive result, not a skipped check.
- Broadcast [0008] (file_transfer): tested path traversal (n/a — no
  sandboxing exists anywhere in this codebase by design, confirmed via a
  local-file-read test), malformed addresses (found two low-severity
  silent-fallback gaps: empty PC name → silently uses "default"; unknown
  account string → silently uses "auto" instead of erroring), oversized
  file (15MB cap enforced on write for every kind, but read side has no
  upfront cap — confirmed a >15MB "remote" source gets fully read+decoded
  before rejection), PC-involved binary transfer (**verified end-to-end
  against a real compiled organiser-agent that the "fails cleanly, doesn't
  corrupt" claim is TRUE** — traced the exact mechanism: organiser-agent's
  raw response is invalid UTF-8 for real binary content, the Linux-server
  Python hop's strict decode() catches that and turns it into a clean
  error before it ever reaches server.py), and codespace account switching
  (works correctly for valid accounts; unknown account silently falls back
  to "auto", noted above).
- Wrote 50 passing regression tests across three new files
  (`tests/test_organiser_agent_security.py`,
  `tests/test_server_auth_and_injection.py`,
  `tests/test_file_transfer_extra.py`) plus re-ran the existing
  `tests/test_admin_cookie_auth.py` and `tests/test_file_transfer.py`
  unchanged. Full writeup with severities and suggested fixes in
  `SECURITY_FINDINGS.md` at repo root.

## Still to do
- Windows-only code paths in organiser-agent.cpp (working_dir injection
  variant, is_protected_path canonicalization bypass tricks, max_bytes
  allocator behavior) — need a real Windows target, flagged clearly as
  unverified rather than guessed at.
- Concurrency/race testing against real state-changing remote operations
  (actual file writes on the live Linux server, actual Render env-var
  edits) — requires live infra, out of scope for this sandbox-only pass.
  Reviewed server.py for in-process shared-state races and found none,
  but that's not the same as testing the real thing.
- ~~Malformed/adversarial MCP tool arguments sent through the *real* MCP
  JSON-RPC protocol layer~~ -- DONE this session, see the update below.
- Revisit once pc-agent lands the in-exe secrets dashboard and base64
  read/write endpoints (broadcast [0006]) — the binary-transfer clean-
  failure behavior documented here may change once those land; the
  regression tests should catch that if it does.

## Notes for the lead
- Environment was flaky twice during this run: a codespace billing outage
  (switched to legendary-space-train-g54xgqxwx6x2wvp9 per your message),
  then the GitHub-MCP connector itself became unreliable mid-session, so I
  moved all actual work to a local bash sandbox and only use git-over-
  HTTPS now (clone/fetch/push), no more codespace SSH dependency for my
  own testing. All findings in SECURITY_FINDINGS.md were produced this
  way — compiled/run entirely locally, nothing touched real infra.

## Update: MCP wire-protocol fuzzing (this session)
Drove a real server.py subprocess with the actual MCP JSON-RPC wire
protocol (both the official mcp SDK client for a legit baseline, and raw
hand-crafted httpx requests for the adversarial cases) -- not just calling
the underlying Python functions directly.

- Found (documented as finding 15, low severity, fails CLOSED not open):
  the DNS-rebinding `allowed_hosts` list has no port wildcard, so any
  request with a port in its Host header gets 421'd, even with the
  correct password. Breaks routine local/self-hosted testing. Real risk
  is someone "fixing" this by weakening/disabling the DNS-rebinding
  check entirely -- flagged clearly so that doesn't happen by accident.
- Verified (finding 16, positive): a stolen/leaked session ID does NOT
  work without the bearer token -- auth middleware runs on every request,
  not just at session creation. Tried to break this specifically; it
  held.
- Full envelope + tool-argument fuzzing (finding 17): malformed JSON-RPC,
  every wrong-type combination for tool args, oversized strings, null
  bytes, unicode, unknown tools, missing/extra fields -- all handled
  cleanly by the SDK's Pydantic validation, no crashes, no leaked
  internals, no 500s anywhere. Clean, thorough, negative result.
- 16 new regression tests in tests/test_mcp_protocol_fuzzing.py. Full
  suite is now 66 passing tests across 6 test files.

This closes out the "malformed/adversarial MCP tool arguments...at the
wire protocol level" item from the previous "still to do" list.


## Update: closed remaining brief gaps + caught a new bug in the lead's own fix
- Systematic fuzz sweep across ALL 43 tools' string parameters (not just a
  hand-picked sample) -- discovered dynamically via tools/list at run
  time, 19 adversarial payloads each, network fully mocked. 1420 calls in
  the full engagement run, 0 findings. Locked in as
  tests/test_all_tools_fuzz_sweep.py (trimmed payload set for CI speed).
- Actually fired concurrent requests at state-changing tools (not just
  reasoned about them, per the brief's explicit ask): 25-30 truly
  concurrent async server_write_file calls with unique per-call markers
  and an artificial mock delay to force interleaving -- zero
  cross-contamination. Also fired 20 concurrent writes to the SAME path
  -- no crashes/hangs/exceptions. Confirmed _admin_api_env_set PUTs each
  key independently (no read-modify-write pattern), so there's no local
  lost-update race to find in that code. tests/test_concurrency.py.
- Filled in dynamic injection-resistance proof for the remaining
  brief-named tools I'd only statically reviewed before:
  server_delete_file, read_codespace_file, write_codespace_file, and
  exec_command's codespace_name (confirmed it's argv-based, not shell --
  can't be locally injected regardless of content).
- Independently re-verified all 4 fixes the lead applied in 7dc1695
  (from earlier docs-release/security-qa findings) rather than trusting
  their own passing tests alone -- checked edge cases their tests didn't
  cover (name@account combinations, exception surfacing through the real
  wire protocol). All 4 hold up.
- **New finding while doing that verification** (finding 18): the
  `mkdir -p $(dirname {_q(path)})` pattern in three write paths
  (write_codespace_file, file_transfer's server:/codespace: writes) has
  an unquoted command substitution, so it word-splits on any path with a
  space in a directory component -- verified by actually running the
  real constructed command in a real shell; it creates two wrong garbage
  directories and the write fails. Not a security hole (fails cleanly,
  the existing "OK"/"__WRITE_OK__" checks catch it), but a real
  reliability bug on a completely ordinary input. This pattern predates
  the lead's fix (already in file_transfer) -- I missed it in my first
  pass and only caught it while double-checking the fix commit. Suggested
  fix verified to work: quote the substitution,
  `mkdir -p "$(dirname {_q(path)})"`.
- Full suite: 110 passing tests across 8 files.

## Next
- pc-agent has landed real commits (6f5d451) -- per the brief, this is
  now the priority: attempt the same attack categories against whatever
  they built. Haven't looked yet as of this status update.
- Still open: Windows-only organiser-agent.cpp paths (no Windows box),
  races against real remote infra (out of scope).


## Update: pc-agent landed -- re-verified their fixes, found a new HIGH finding in their new feature
- Re-verified finding 1 (working_dir injection) is genuinely fixed:
  rebuilt organiser-agent.cpp from main, re-ran the EXACT original
  exploit payload -- now cleanly rejected (400, honest error message),
  no marker file created, legitimate working_dir use still works
  correctly. Fix uses fork()+chdir()+execl() (POSIX) / lpCurrentDirectory
  (Windows) -- working_dir is never shell text anymore, closed at the
  root. Independently re-verified the lead's own re-verification, not
  just trusted it.
- Confirmed the reject_if_protected() Windows-directory guard is now
  applied consistently across every file-mutating handler (list, move,
  delete, preview, disk_usage, screenshot, write_file, read_file_b64) --
  good coverage improvement. Still can't dynamically test the actual
  Windows canonicalization logic itself (compiled out on non-Windows,
  no Windows box available) -- stays flagged as unverified, not assumed
  safe.
- **NEW finding (20, HIGH severity)**: pc-agent's new /config dashboard
  (both organiser-agent.cpp AND the separate Flask organiser-agent.py --
  confirmed independently in both) lets an UNAUTHENTICATED caller
  PERMANENTLY hijack the machine when no secret is configured yet --
  not just "run one command during the exposure window" (finding 3),
  but "set your own secret, persisted to disk, survives restart, locks
  the legitimate owner out with no network recovery path." Verified
  end-to-end against a real compiled C++ binary and against the real
  Flask app via its test client. This is a design-level gap (the same
  "no secret = no check" logic, originally reasonable for one-off
  file/command ops, applied to a fundamentally different credential-
  rotation endpoint) independently replicated into two separate
  codebases -- flagging clearly so fixing one doesn't leave the other
  exposed the same way. Full writeup + suggested fix directions (a real
  product decision, not mine to make) in SECURITY_FINDINGS.md finding 20.
  Posted as a broadcast given the severity and that it affects live
  work pc-agent may still be iterating on.
- Small housekeeping: added flask>=3.0 to requirements-test.txt (needed
  to even collect tests/test_organiser_agent.py -- was causing a hard
  collection error for anyone running the full suite fresh).
- Full suite: 153 passing + 1 xfailed (the finding-7 buffer-truncation
  regression test, correctly xfailed since that fix is still open on
  pc-agent's side per broadcast [0013]) across 10 test files.


## Update: major methodology upgrade -- real Windows verification via MinGW + Wine
Installed g++-mingw-w64-x86-64 and wine64 (both from Ubuntu's own repos)
and cross-compiled the real organiser-agent.cpp into a genuine Windows
PE32+ binary, run under Wine (real Win32 API emulation, not guesswork).
Confirmed it genuinely exercises the Windows code path (its own /status
reports "platform":"Windows", a compile-time branch Wine can't fake).

This closes three specific "static analysis only, needs Windows" gaps
with real confirmed results:
- The EXACT traversal case (forward-slash path resolving back into
  C:\windows) that tests/test_organiser_agent.py's own Flask-side test
  honestly marks @unittest.expectedFailure on Linux, with a correct
  explanation of why Linux can't demonstrate it -- I independently
  confirmed their hypothesis was right: it IS caught on real Windows
  path semantics.
- Finding 21 (working_dir fix) re-confirmed under real CreateProcess
  behavior, including the double-quote+& injection shape hypothesized
  but never confirmed for the cmd.exe path. Used a real marker-file
  side-effect check (not a naive string match, which would false-positive
  against the legitimate rejection message echoing the payload back).
- Finding 4's max_bytes bad_alloc DoS re-confirmed on a real Windows
  process (with an honest MinGW-vs-MSVC caveat on the allocator
  specifics, though the qualitative "throws, doesn't crash" result is a
  C++ language guarantee independent of that).

Stated the caveat plainly: MinGW-compiled + Wine-emulated, not a genuine
MSVC/real-hardware Windows box. Strong proxy for filesystem/path/process
behavior; less certain for allocator internals specifically. Not
claiming total Windows coverage -- screenshot/GDI path and NTFS-specific
quirks (8.3 names, \\?\ prefixes) remain unverified hypotheses.

6 new tests in tests/test_organiser_agent_windows_via_wine.py, skip
cleanly if the two packages aren't installed (not a hard CI dependency).

Full suite: 159 passing + 1 xfailed across 11 test files.

## Next
- Haven't yet done the same systematic injection/concurrency sweep
  against the Flask organiser-agent.py that I did for the C++ version --
  only checked auth/config/working_dir on it so far.
- Should verify finding 7's workaround (_PC_TRANSFER_SAFE_MAX_BYTES,
  per broadcast [0013]) rather than trusting the broadcast description.
- User has offered codespace (real network) + a Render test deployment
  for higher-fidelity verification of finding 15 (DNS-rebinding host
  header behavior) in real production -- haven't used that yet, this
  Windows work took priority given it closed three long-standing gaps.


## Update: re-verified findings 4, 5, 7 as genuinely fixed (didn't blindly update tests)
After merging pc-agent's finished branch, two of my own tests failed:
the Flask secret-comparison test (asserted the OLD vulnerable != check)
and the Windows-via-Wine max_bytes test (expected a 500/bad_alloc). Read
the actual diffs before touching either test:

- Finding 4 (max_bytes DoS): genuinely fixed with a proper fs::file_size()
  check before allocating, not just a raised ceiling. Re-verified on
  BOTH Linux and real Windows (via the Wine setup) -- a 10GB request
  against a tiny file now correctly returns the real content, no crash,
  no error.
- Finding 5 (non-constant-time compare): genuinely fixed in BOTH
  organiser-agent.cpp (new constant_time_equal() helper) and
  organiser-agent.py (switched to hmac.compare_digest) -- found and
  applied independently in each. Re-verified end-to-end in both, not
  just grepped for the right function name.
- Finding 7 (body truncation): genuinely fixed with a proper
  Content-Length-aware growable-buffer read loop that upfront-rejects
  absurd declared sizes before allocating. Confirmed server.py's
  _PC_TRANSFER_SAFE_MAX_BYTES workaround was correctly raised back to
  the general 15MB cap by reading the current file directly.

Updated my own two stale tests to verify the FIXES specifically (not
just "doesn't fail the old way anymore"), added a proper dynamic
end-to-end check to the Flask secret test (source-text grep alone isn't
enough per my own standard), and cross-referenced my Wine-based
Windows confirmation directly into pc-agent's own expectedFailure test
docstring in test_organiser_agent.py, since it's the exact case that
test documents as unverifiable on Linux.

Full suite: 161 passing + 1 xfailed (unchanged -- the one remaining
xfail is exactly the Linux-can't-test-Windows-path-normalization case,
now cross-referenced to my independent confirmation rather than left
as a dangling unresolved question).

## Next
- Still haven't done the systematic injection/concurrency sweep against
  organiser-agent.py (Flask) that I did for the C++ version -- only
  checked auth/config/working_dir/secret-comparison on it so far.
- User's offer to use the codespace + a Render test deployment for
  finding 15 (DNS-rebinding host header in real production) still
  stands, unused so far -- the Windows work and this re-verification
  round took priority.
