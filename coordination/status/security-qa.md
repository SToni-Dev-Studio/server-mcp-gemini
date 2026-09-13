# security-qa status

Last broadcast read: 0008

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
