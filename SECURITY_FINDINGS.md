# Security QA Findings — server-mcp-claude

Author: security-qa subagent. All findings below were dynamically verified
against real, compiled code running in an isolated sandbox (this codespace/
bash sandbox) — never against sepisotoni's live Render deployment, home
Linux server, PC, or Plex instance. Where I could not verify something
dynamically (Windows-only code paths, real multi-instance/live-infra
races), I say so explicitly rather than presenting it as confirmed.

Regression tests for every dynamically-confirmed finding live in
`tests/test_organiser_agent_security.py`, `tests/test_server_auth_and_injection.py`,
and `tests/test_file_transfer_extra.py`. All 50 tests pass as of this
writing (`python3 -m pytest tests/ -v`).

---

## Summary table

| # | Finding | Component | Severity | Status |
|---|---|---|---|---|
| 1 | `working_dir` shell injection (Linux, single-quote breakout) | organiser-agent.cpp | **High** | **FIXED** by agent/pc-agent's run_command rewrite (fork+chdir+execl, no shell string interpolation) -- lead re-verified live, see COMPETITION_REPORT.md |
| 2 | `working_dir` shell injection (Windows, hypothesized) | organiser-agent.cpp | High (unverified) | Static analysis only — needs a real Windows box |
| 3 | No-secret-configured = auth check skipped entirely | organiser-agent.cpp | High (conditional) | Confirmed |
| 4 | `/preview` `max_bytes` unbounded → memory-exhaustion DoS | organiser-agent.cpp + server.py | Medium-High | Confirmed, chained end-to-end |
| 5 | Secret comparison not constant-time | organiser-agent.cpp | Low | Confirmed by code + design comparison |
| 6 | SSH tunnel `StrictHostKeyChecking=no` | pc-tunnel@.service | Low | Confirmed by inspection |
| 7 | Oversized request body silently truncated | organiser-agent.cpp | Medium | Confirmed |
| 8 | `file_transfer` read-side has no upfront size cap | server.py | Low-Medium | Confirmed |
| 9 | `pc::` / typo'd account silently degrade instead of erroring | server.py | Low | Confirmed |
| 10 | Admin-cookie forgery (original bug) | server.py | — | **Already fixed on main**, fix independently re-verified |
| 11 | Shared secret across MCP-bearer and admin-cookie boundaries | server.py | Info | By design, noted for awareness |
| 12 | Shell-injection sweep of server.py's command-building code | server.py | — | **No injection found** — positive finding |
| 13 | PC binary transfer failure mode | server.py + organiser-agent.cpp | — | **Claim verified true** — fails cleanly, does not corrupt |
| 14 | Query-string parser does not URL-decode | organiser-agent.cpp | Info | Behavioral quirk, not a vulnerability |
| 15 | DNS-rebinding `allowed_hosts` has no port wildcard — breaks local/self-hosted access | server.py | Low (availability, fails closed) | Confirmed |
| 16 | Session ID alone (no bearer token) is rejected — auth runs per-request | server.py | — | **Confirmed secure** — positive finding |
| 17 | MCP wire-protocol fuzzing (malformed JSON-RPC, wrong tool-arg types, oversized/null-byte/unicode args) | server.py + mcp SDK | — | **No issues found** — thorough fuzzing, clean result |
| 18 | `mkdir -p $(dirname ...)` word-splits on paths with spaces — write fails, creates wrong garbage dirs | server.py (3 call sites) | Low-Medium (reliability, not access) | Confirmed, fix verified |
| 19 | Independent re-verification of lead's 4 fixes (commit 7dc1695) | server.py | — | **All 4 confirmed sound** |
| 20 | Unauthenticated `/config` POST can PERMANENTLY hijack a PC agent (both implementations) | organiser-agent.cpp + organiser-agent.py | **High** | Confirmed, both implementations, design-level |
| 21 | `working_dir` injection re-verified fixed (pc-agent's rewrite) | organiser-agent.cpp | — | **Confirmed fixed**, exploit closed, legit use unaffected |
| 22 | Windows-specific claims re-verified against a REAL Windows binary (cross-compiled, run under Wine) | organiser-agent.cpp | — | **Methodology upgrade** — several "unverified, needs Windows" items now confirmed |

---

## 1 & 2. Command injection via `working_dir` in `/run_command`

**Confirmed exploitable on Linux.** organiser-agent.cpp builds the shell
command for `/run_command` like this (paraphrased):

```
full_cmd = "cd \"" + cwd + "\" && " + cmd
full_cmd = "/bin/bash -c '" + full_cmd + "' 2>&1"
```

`cmd` (the actual arbitrary command) is *meant* to be arbitrary — that's the
tool's job. But `cwd` (`working_dir`) is not documented or expected to be
anything other than a plain directory path, and it receives **zero
escaping**. A single quote in `working_dir` breaks out of the outer
`/bin/bash -c '...'` wrapper, and everything between that quote and the
next one is parsed as new, independent shell syntax by the process that
invokes `popen()`.

Live proof (`tests/test_organiser_agent_security.py::test_working_dir_command_injection`):
sending `command="echo should_not_matter"` with
`working_dir="x' ; touch <marker> ; echo '"` creates the marker file even
though the "command" field never executes as intended. Full trace of why,
with the real captured output, is in that test's docstring.

**Why this matters beyond "the tool is already arbitrary-exec by design":**
`working_dir` is a second, independent injection point. If anyone ever adds
validation/allowlisting to the `command` field in the future (a reasonable
thing to want for an AI-driven tool), this bypasses it completely, since
`working_dir` requires no interaction with `command` at all to achieve
code execution.

**Windows path (`organiser-agent.cpp`, `#else` branch) — NOT dynamically
verified, code-reviewed only:**

```
full_cmd = "cd /d \"" + cwd + "\" && " + cmd;
full_cmd = "cmd /c " + full_cmd + " 2>&1";
```

No outer single-quote wrapping exists on Windows at all. A `working_dir`
containing `"` followed by `&`, `|`, or `&&` would very plausibly achieve
the same class of injection via `cmd.exe`'s own metacharacters. I could not
build/run the Windows code path in this sandbox (no Windows target
available, and I was told not to touch the real PC), so **this is a
hypothesis from reading the code, not a confirmed finding** — please
verify on a real Windows box before treating it as closed either way.

**Suggested fix (not applied — QA scope, not fix scope):** don't build a
`cd X && Y` string at all. Use the platform's native "run in a specific
directory" primitive (`CreateProcess`'s `lpCurrentDirectory` on Windows,
`posix_spawn_file_actions_addchdir_np` / just `chdir()` in a forked child
before `execve` on POSIX) so `working_dir` is never shell text in the
first place.

## 3. No-secret-configured means the auth check silently does nothing

```cpp
if (!g_secret.empty()) {
    ... check X-Organiser-Secret ...
}
```

If `ORGANISER_SECRET` is unset, this entire block is skipped — every
endpoint, including `/run_command`, `/write_file`, `/delete`, `/move`, is
open to anyone who can reach the port, no credential needed at all.

This is the *same shape* of bug as the admin-cookie-forgery issue already
fixed on `main` (b28ab02) — an auth mechanism that quietly no-ops when
unconfigured, rather than failing closed. The difference: here it's
explicitly documented behavior (`main()` prints `"Auth : NO SECRET
(open)"` at startup), not a hidden bug, and it's mitigated by the tunnel
being loopback-only by design (confirmed — see finding 6's neighboring
code, `INADDR_LOOPBACK` binding, and the `pc-tunnel@.service`'s
`-L 127.0.0.1:port:localhost:port` forwarding). So the practical exposure
is "any process already running on the PC, as any user" rather than
"anyone on the network." Still worth a second look given how severe the
combination with finding 1 is: on a PC where `ORGANISER_SECRET` was never
set, *any* local process (a compromised browser extension, a
different-user malware sample, etc.) gets instant, unauthenticated, full
command execution as the account running organiser-agent.

## 4. `/preview`'s `max_bytes` — unbounded, pre-allocated, chains through server.py

organiser-agent.cpp's `h_preview`:

```cpp
size_t max_bytes = ... std::stoull(req.query.at("max_bytes")) : 4096;
...
std::string content(max_bytes, '\0');   // <-- allocated BEFORE checking file size
f.read(&content[0], max_bytes);
content.resize((size_t)f.gcount());
```

Live-tested: requesting `max_bytes=10000000000` (10 GB) against a 1 KB
file causes an immediate `std::bad_alloc`. On this Linux build it's caught
cleanly by the route dispatcher (`HTTP 500`, process survives —
confirmed, see
`tests/test_organiser_agent_security.py::test_oversized_max_bytes_does_not_crash_process`).
**Not verified on Windows** — allocator/overcommit behavior for a
multi-GB request differs by platform, and I don't have a Windows target to
test against; the failure mode there could plausibly be worse (e.g. an
OS-level OOM kill instead of a caught C++ exception) — flagging as
unverified rather than assuming either way.

**The more concerning part: this is directly reachable from an MCP tool
with zero clamping.** `server.py`'s `pc_read_file_preview(path, max_bytes=4096, pc=...)`
passes the caller-supplied `max_bytes` straight through to
`_org_get("/preview", {"path": path, "max_bytes": max_bytes}, ...)` with no
upper-bound check anywhere in `server.py`. Confirmed via
`tests/test_file_transfer_extra.py::test_pc_read_file_preview_max_bytes_is_not_clamped`.
So: any MCP client holding the one shared bearer token can call
`pc_read_file_preview(path="<any real file>", max_bytes=99999999999)` and
directly trigger the organiser-agent allocation bug on a real PC — no
`working_dir` trick or separate exploit needed, just an unclamped integer
parameter passed three layers deep.

(By contrast, `file_transfer`'s own internal use of `/preview` always
passes the fixed `_FILE_TRANSFER_MAX_BYTES` constant — that path is safe.
It's specifically the directly-exposed `pc_read_file_preview` tool that's
unclamped.)

**Suggested fix:** clamp `max_bytes` server-side in `server.py` (e.g. to
`_FILE_TRANSFER_MAX_BYTES` or similar) before forwarding, *and*
independently cap it in organiser-agent.cpp itself (defense in depth —
`server.py` isn't the only possible caller), and check the requested size
against `fs::file_size(p)` before allocating rather than trusting the
caller's `max_bytes`.

## 5. Secret comparison is not constant-time

```cpp
if (hdr != g_secret) { ... 401 ... }
```

Plain `std::string operator!=`, which typically short-circuits on the
first differing byte — a timing side channel. Contrast with `server.py`,
which correctly uses `hmac.compare_digest` for both the MCP bearer-token
check and the admin-cookie signature check. Practical exploitability is
low here specifically *because* the port is loopback-only (an attacker
needs to already be running code on the PC to reach it at all, at which
point they have other options), but it's a real gap relative to the
standard the rest of this project holds itself to, and costs nothing to
fix (`std::equal` with a constant-time comparator, or just don't roll your
own — most platforms have a `timingsafe_bcmp`-equivalent).

## 6. SSH tunnel: `StrictHostKeyChecking=no`

`pc-tunnel@.service` connects from the Linux server to each PC with
`StrictHostKeyChecking=no` and no host-key pinning. This is a real (if
LAN-local, requires-network-position) MITM risk: anything that can spoof
a PC's LAN address (ARP spoofing, DNS tricks if the PC is addressed by
name, a rogue DHCP lease, etc.) could impersonate the PC and have the
server tunnel traffic to it instead, without any warning. Given `BatchMode=yes`
is already set (so it's not relying on interactive host-key-trust
prompts anyway), pinning the known host key
(`StrictHostKeyChecking=yes` + a pre-populated `known_hosts`, or
`ssh-keyscan` at PC-registration time) would close this with no
operational downside.

## 7. Oversized request bodies are silently truncated

organiser-agent.cpp's `handle_conn` reads into a fixed `char buf[65536]`
and stops once the buffer is full, *regardless* of whether the declared
`Content-Length` was actually satisfied. Confirmed live: POSTing a 200 KB
`write_file` body resulted in the file being silently written with
exactly 65,333 bytes (the truncated amount) and the server reporting
`HTTP 200` success with no indication that anything was cut off. This is
a genuine data-integrity risk — any legitimate large write (a config file,
a downloaded script) larger than ~64 KB gets silently corrupted with a
success response.

**Suggested fix:** either raise the buffer to accommodate the documented
15 MB `file_transfer` cap plus JSON/base64 overhead, switch to a growable
buffer, or (better) explicitly check `total bytes read == Content-Length`
before processing and return a clear 4xx if they don't match.

## 8. `file_transfer` read side has no upfront size limit

The 15 MB cap in `_location_write_bytes` is checked *after* the full
source has already been read into memory (and, for `server:`/`codespace:`
kinds, base64-decoded, meaning the wire transfer and decode work already
happened before the cap ever fires). Confirmed via
`tests/test_file_transfer_extra.py::test_read_side_has_no_upfront_size_limit_for_server_kind`.
Low-to-medium severity since the caller triggering this already holds the
shared admin-level bearer token, but it's a real gap: a very large or
unexpectedly-huge remote source file will be fully read (and for
server/codespace, base64-inflated ~33%) into `server.py`'s process memory
before being rejected, rather than being size-checked incrementally or
upfront.

## 9. Malformed addresses silently degrade instead of erroring

Two related, low-severity gaps in `file_transfer` address parsing:

- `"pc::/some/path"`-shaped locations (empty PC name) parse successfully
  with `name=""`, which downstream code turns into `pc="default"` via
  `name or "default"` — a typo'd/blank PC name silently targets the
  default PC instead of raising a clear "malformed address" error.
- `_get_token()` only special-cases `"primary"`/`"secondary"`/`"tertiary"`;
  any other `account` string (e.g. a typo in a `name@account` codespace
  address) silently falls through to the same behavior as `"auto"`. It
  does not grant *escalated* access — it still only picks from the
  already-configured tokens — but a caller who named one specific account
  and mistyped it gets silently redirected to a *different* configured
  account instead of an error.

Both confirmed via `tests/test_file_transfer_extra.py`. Neither is
exploitable for privilege escalation; both are "surprising silent
fallback instead of a clear error" correctness gaps worth tightening.

## 10. Admin-cookie forgery fix — independently re-verified

The fix in `b28ab02` (`_ADMIN_AUTH_CONFIGURED` gate that makes
`_admin_cookie_valid` always return `False` when neither `ADMIN_PASSWORD`
nor `ADMIN_COOKIE_SECRET` is set, closing the old hardcoded-fallback-secret
forgery hole) was re-run and re-verified independently in this sandbox —
still holds (`tests/test_admin_cookie_auth.py`, both cases pass). Looked
for the same *shape* of bug elsewhere in `server.py` (any secret with a
guessable/hardcoded fallback) and found none — the only other fallback
chain is `ADMIN_PASSWORD` → `MCP_SERVER_PASSWORD` → (nothing, stays empty),
and `ADMIN_COOKIE_SECRET` → `ADMIN_PASSWORD` → `secrets.token_hex(32)`
(a strong random value, not a guessable default). See finding 3 for the
closest analog found *outside* server.py (organiser-agent.cpp's
no-secret-means-no-check pattern).

## 11. Shared secret across two trust boundaries (by design, noted for awareness)

`ADMIN_PASSWORD` falls back to `MCP_SERVER_PASSWORD` when unset. This means
the same secret that authenticates the MCP bearer-token layer (used by AI
clients) also authenticates the human-facing `/admin` dashboard (which can
edit Render env vars, trigger redeploys, and run commands on the Linux
server via `/admin/api/server/run`). If the MCP bearer token is ever
exposed somewhere the admin password wouldn't otherwise be (logged by an
MCP client, pasted into a less-trusted automation, etc.), that exposure
also grants the admin dashboard. This is very plausibly an intentional
simplification (one secret to manage) rather than an oversight, so I'm
noting it as an awareness item rather than a "finding" needing a fix —
but it's worth knowing that these two surfaces aren't independently
revocable unless `ADMIN_PASSWORD`/`ADMIN_COOKIE_SECRET` are explicitly set
separately from `MCP_SERVER_PASSWORD`. No rate-limiting exists on either
`/admin/login` or the MCP bearer check, for what it's worth — brute-forcing
either is only bounded by network latency.

## 12. Systematic shell-injection sweep of server.py — no issues found

Every `f"..."` string in `server.py` that builds a command for
`_ssh_server` / `exec_command` was enumerated and checked (grep for the
construction sites, then manual review of each). Every user-controlled
variable is either wrapped in `_q()` (`shlex.quote`) or, in the one case
where it isn't (`server_service_control`'s `action`), validated against a
hardcoded allowlist *before* being embedded unquoted. Dynamically
confirmed with adversarial payloads (unescaped single/double quotes,
`$()`, backticks, `&&`, embedded newlines, pipes) against
`server_read_file`, `server_move_file`, and `server_write_file` — every
payload survived intact as a single shell-safe token, never breaking out
(`tests/test_server_auth_and_injection.py`). Notably, the code even has a
comment (`server.py` around line 218) explicitly calling out the exact bug
class found in organiser-agent.cpp's `working_dir` ("an apostrophe...
breaks out of the surrounding quotes... several of these run with sudo"),
so this appears to be a deliberate, applied defense rather than luck.

## 13. PC binary transfer failure mode — claim verified, not just trusted

Broadcast [0008] asked me not to just trust the claim that PC-involved
binary transfers "fail cleanly, not silently corrupt." I verified this
end-to-end rather than assuming it:

1. Compiled real organiser-agent.cpp, hit its real `/preview` endpoint
   with a genuinely binary 1 KB file (`bytes(range(256)) * 4`).
2. Confirmed the raw HTTP response body is itself invalid UTF-8 (organiser
   -agent's hand-rolled `Json::escape` does not escape or reject bytes
   ≥ 0x80 — it copies them straight through).
3. Traced `server.py`'s actual transport path: it does *not* talk HTTP to
   the PC directly — `_organiser_ssh_request` ships a small Python script
   to the *Linux server* over SSH, which does the real `urlopen()` +
   `r.read().decode()` (strict UTF-8) *on the server*, wrapped in a broad
   `except Exception` that turns any decode failure into a clean
   `{"error": "..."}` JSON string.
4. Replayed that exact, real, captured failure shape through `server.py`'s
   own `file_transfer` (`tests/test_file_transfer_extra.py::test_pc_binary_read_fails_cleanly_not_corrupted`)
   and confirmed it surfaces as a clean `"Read failed: ..."` message, never
   as truncated/corrupted `content`.
5. Separately confirmed the write-side half of the safety net
   (`_location_write_bytes` for `pc:` destinations checks
   `data.decode("utf-8")` and raises a clean error *before* ever calling
   organiser-agent) — this half lives entirely in `server.py`, not
   organiser-agent.

**Conclusion: the claim holds, and is actually slightly stronger than
advertised.** Because UTF-8 is a lossless round-trip for any *valid* UTF-8
byte sequence, the real guarantee isn't just "fails instead of corrupting"
— it's "either transfers correctly (if the content happens to be valid
UTF-8) or fails with a clear error (if not) — there is no code path here
that silently drops/replaces bytes." In practice, real binary formats
(images, executables, archives) contain invalid UTF-8 byte sequences
almost universally, so the clean-failure path is what will actually fire
for real binary files.

## 14. organiser-agent's query-string parser does not URL-decode

`parse_qs` splits on `&`/`=` and stores values raw — it never
percent-decodes. Not a vulnerability by itself, but a real behavioral
quirk: a well-behaved HTTP client that percent-encodes special characters
in a query value (spaces, `#`, non-ASCII filenames) will have the *raw
percent-encoded text* stored and used as the literal path, not the
decoded value. Cost me some debugging time during this engagement (my
first `/preview` test against a binary file used `curl
--data-urlencode` and got a "path does not exist" error until I switched
to sending the raw, unencoded path) — documenting it here so nobody else
loses time to the same thing, and so anyone building a client against
this API knows not to URL-encode query values.

---

## Things I looked at and did NOT find problems with

- **Malformed/adversarial MCP tool arguments at the real wire-protocol
  level** — done, see finding 17. Both the JSON-RPC envelope layer and
  the tool-argument layer were fuzzed against a real running instance,
  not just the underlying Python functions.
- **Concurrency / race conditions on state-changing tools:** reviewed
  `server.py` for shared *in-process* mutable state that could race under
  concurrent `asyncio` requests (the auth middleware reads env vars fresh
  per-request with no caching; the admin-cookie secret is either
  deterministic — derived from `ADMIN_PASSWORD` — or, when unconfigured,
  irrelevant because login is disabled entirely, so no multi-instance
  secret-mismatch scenario exists either). Found no significant shared
  mutable state. **I did not attempt races against real state-changing
  remote operations** (concurrent real file writes on the actual Linux
  server, concurrent real Render env-var edits) since that requires live
  infrastructure, which is out of scope for this engagement. This should
  be revisited against a real staging target in a follow-up pass — noting
  the gap honestly rather than claiming a clean bill of health I can't
  back up.
- **Path traversal via `..` in file_transfer / organiser-agent /
  server_* tools:** there is no sandboxed root directory anywhere in this
  codebase for any of these admin tools (by design — see the "sandbox
  kind can read arbitrary local files" test) — so "traversal" in the
  classic escape-the-jail sense doesn't really apply; there's no jail to
  escape. The real control point is the single shared bearer
  token/organiser secret, already covered above.
- **is_protected_path's Windows-directory guard:** compiled out entirely
  (`return false;`) on non-Windows builds, so I could not dynamically
  test the actual Windows canonicalization logic
  (`fs::weakly_canonical` + prefix match) against known bypass tricks
  (8.3 short names, `\\?\` prefixes, trailing dots/spaces, UNC paths). Flagging
  as **needs a real Windows target to verify**, not claiming it's broken
  or claiming it's safe.


## 15. DNS-rebinding `allowed_hosts` has no port wildcard

```python
_transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["localhost", "127.0.0.1"] + ([_allowed_host] if _allowed_host else []),
    allowed_origins=["*"],
)
```

The MCP SDK's `TransportSecurityMiddleware._validate_host` only accepts an
**exact** match against `allowed_hosts`, or an entry ending in `":*"` as a
port wildcard. None of the entries here end in `:*`. Confirmed live: a
request to `/mcp` with `Host: 127.0.0.1:18010` (i.e., anything sent to a
non-default port, which is what virtually every local/self-hosted/Docker
deployment looks like) is rejected with `421 Misdirected Request` —
*even with a fully correct bearer token* — while the exact same request
with `Host: localhost` (bare, no port) succeeds.

**This is not a vulnerability** — it fails *closed*, more restrictively
than presumably intended, which is the opposite direction of a security
hole. But it's worth fixing and worth documenting clearly, for two
reasons: (1) it will confuse and block anyone trying to run/test this
server locally or self-hosted behind anything other than Render's exact
default-port HTTPS setup, and the confusing `421` error gives no hint
that the fix is "match your Host header" — the natural instinct if you
hit this is to work around it by *weakening* the check
(`enable_dns_rebinding_protection=False` or `allowed_hosts=["*"]`-
equivalent), which **would** be a real regression; (2) it's exactly the
kind of gap this engagement exists to surface before someone "fixes" it
the wrong way under time pressure.

**Suggested fix:** add port-wildcard entries for the loopback cases —
`"localhost:*"` and `"127.0.0.1:*"` — which the SDK already explicitly
supports for this purpose. Leave the explicit `_allowed_host` production
entry as an exact match (correct, since Render's edge forwards the bare
external hostname).

Confirmed via `tests/test_mcp_protocol_fuzzing.py::test_host_header_with_port_is_rejected_by_dns_rebinding_check`
and its `_accepted` counterpart.

## 16. Session ID alone, without the bearer token, is correctly rejected

Verified a specific defense-in-depth property by trying to break it: after
establishing a real, valid MCP session (real `initialize` handshake, real
`Mcp-Session-Id`), I replayed that exact session ID from a *second,
independent client that never sent the `Authorization` header at all*.

**Result: `401 Unauthorized: Invalid or missing server password.`**

This confirms `PasswordAuthMiddleware` runs on *every* request to `/mcp`,
not just at session-creation time — so a session ID leaking on its own
(via a proxy log, a referrer header, a misconfigured logging integration,
etc., all realistic ways a session ID specifically — as opposed to an
`Authorization` header — might end up somewhere it shouldn't) does not by
itself grant access. This is exactly the property you'd want and it holds.
Locked in as a regression test:
`tests/test_mcp_protocol_fuzzing.py::test_stolen_session_id_without_bearer_token_is_rejected`.

I also checked a forged/nonexistent session ID (with a valid bearer
token) — cleanly rejected with `404 Session not found`, no crash, no
information leakage about valid session ID shapes.

## 17. Full wire-protocol fuzzing of `/mcp` — no issues found

Rather than only calling `server.py`'s Python functions directly (which
tests the tool logic but skips the actual JSON-RPC/MCP transport layer
entirely), I drove a real `server.py` subprocess over a real socket with
the actual MCP wire protocol — both with the official `mcp` SDK client
(for a legitimate baseline handshake) and with raw, hand-crafted
JSON-RPC bodies via `httpx` (for the adversarial cases), to see what
happens *before* input ever reaches a tool function.

**Envelope-level fuzzing** (missing/wrong `jsonrpc` field, missing/wrong-
typed `method`, missing `id`, `id: null`, `params` as a string/null,
extra unexpected top-level fields, batch-style JSON arrays, empty body,
non-JSON body, truncated JSON, wrong `Content-Type`, missing `Accept`
header): every single case produced a clean, well-formed 4xx with a
proper JSON-RPC error code (`-32700` parse error, `-32602` invalid
params, `-32600` bad request) or an appropriate HTTP status
(`406 Not Acceptable` for a missing `Accept` header, `400` for a bad
`Content-Type`). **No 500s, no stack traces, no crashes.** This is the
`mcp` SDK's own Pydantic-based message validation doing its job — a nice
contrast with organiser-agent.cpp's hand-rolled JSON parser (see finding
14), which has no equivalent structural validation.

**Tool-argument-level fuzzing** (once past the envelope, with a real
session): missing required arguments, wrong types in every direction
(int/null/list/dict/bool where a string was expected; string/float where
an int was expected), an unknown tool name, an empty tool name, a
path-traversal-shaped tool name, extra unexpected arguments, a 2 MB
string argument, an embedded null byte, and unicode/emoji content — every
case was caught and returned as a clean `isError: true` tool result with
a specific, non-crashing Pydantic validation message (or, for the null
byte, Python's own `ValueError: embedded null byte`, also caught
cleanly). The server remained fully responsive after every single fuzzed
request (verified with a follow-up real call each time). **No type-
confusion bugs, no unhandled exceptions, no leaked internals beyond the
tool/field names the caller already supplied themselves.**

**Conclusion: this is a clean, thoroughly-tested result, not a skipped
check.** 16 of the fuzz cases are now locked in as regression tests in
`tests/test_mcp_protocol_fuzzing.py`.


## 18. `mkdir -p $(dirname ...)` word-splits on paths containing spaces

Three call sites build a write command like this:

```python
cmd = f"mkdir -p $(dirname {_q(path)}) && echo {_q(encoded)} | base64 -d > {_q(path)} && echo OK"
```

`{_q(path)}` (the argument *to* `dirname`) is correctly shell-quoted. But
the **command substitution itself, `$(dirname ...)`, is not** — its
*output* (the directory name `dirname` computes) is substituted back into
the command unquoted, so it undergoes normal shell word-splitting. Any
path with a space in a directory component — a completely ordinary input,
not an exotic attack string (`"My Files/notes.txt"`, `"Program Files
(x86)/..."`, anything a real user might name a folder) — breaks this.

**Verified by executing the real, actual command `server.py` constructs**
(not a hand-reproduction) in a real shell, in an isolated temp directory:

```
$ mkdir -p $(dirname '/tmp/.../my dir/file.txt') && ... 
bash: line 1: /tmp/.../my dir/file.txt: No such file or directory
```

`dirname`'s output (`/tmp/.../my dir`) gets word-split into two arguments,
so `mkdir -p` creates **two wrong directories** (`.../my` and a
*relative* `dir` in whatever the shell's current working directory
happens to be) instead of the one intended directory. The subsequent
`>` redirect then fails because the real parent directory was never
created.

**Not a security vulnerability** — no silent corruption occurs, because
all three call sites already check for an explicit success marker
(`"OK"` / `"__WRITE_OK__"`) in the result and raise/report a clean
failure when it's missing (two of these checks predate this finding;
the third — `write_codespace_file`'s — was *added* by the lead's fix in
7dc1695 for an unrelated reason, and happens to also catch this cleanly
as a nice side effect). But it's a real reliability bug that will fail
on an entirely mundane input, and leaves stray, oddly-named directories
behind as debris.

**Affected:** `write_codespace_file`, and `file_transfer`'s `server:` and
`codespace:` write paths (`_location_write_bytes`). **Not affected:**
`file_transfer`'s `sandbox:` write path, which correctly uses
`pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)` instead of
a shell one-liner.

**Note on provenance:** this pattern already existed in `file_transfer`'s
`server:`/`codespace:` write paths *before* the lead's fix commit — I
missed it in my own first pass (I was focused on the *quoting*
correctness of `_q()`'s output, not on the *unquoted command
substitution* wrapping it). The lead's fix for `write_codespace_file`
replicated the same pre-existing pattern into a third location. Flagging
this plainly rather than implying I caught it the first time around.

**Suggested fix, verified to work:** quote the command substitution —
`mkdir -p "$(dirname {_q(path)})"` (just add `"..."` around `$(...)`).
Confirmed this resolves it cleanly: same real command, same real shell,
now succeeds and creates exactly the one intended directory.

Regression tests (which execute the real, actual constructed command,
not a reproduction) in
`tests/test_server_auth_and_injection.py::test_write_codespace_file_mkdir_breaks_on_path_with_space`
and `::test_file_transfer_server_write_mkdir_breaks_on_path_with_space`.

## 19. Independent re-verification of the lead's 4 fixes (commit 7dc1695)

Per my own rule of never trusting a claim without checking it myself
(the same standard I'd want applied to my own findings), I read the full
diff and independently re-verified each of the 4 fixes the lead applied
from earlier docs-release/security-qa findings, rather than just
trusting that their own accompanying tests (`test_lead_fixes_round2.py`,
which do pass) were sufficient:

1. **`write_codespace_file` success-checking** — sound. Also directly
   surfaces finding 18 above as a clean failure instead of a false
   "success", which is a nice side benefit.
2. **`pc_read_file_preview` 2 MB clamp** — verified this genuinely closes
   the demonstrated DoS: the worst case is now a bounded 2 MB allocation
   (harmless) instead of an attacker-chosen unbounded one. Not a
   substitute for the real fix in organiser-agent.cpp itself (correctly
   scoped to pc-agent), but effective defense in depth as advertised.
3. **`_get_token` rejects unknown accounts** — checked both call sites
   (`exec_command`, `_gh_request_with_fallback`) and confirmed the new
   `ValueError` surfaces cleanly through the real MCP wire protocol as a
   normal `isError: true` tool result (tested live: `list_codespaces`
   with a bogus account returns a clean error message, no 500, no
   traceback) — not just that the unit test around the raw function
   passes.
4. **Empty pc:/codespace: name rejection** — hand-checked the `name@account`
   edge cases the lead's own tests didn't explicitly enumerate (empty
   name with a real account present — `"codespace:@tertiary:/x"` — empty
   account with a real name present, and both empty) — all handled
   correctly by the `name.split("@", 1)[0]` check.

**Conclusion: all 4 fixes hold up under independent re-verification.**
No regressions found in this round of double-checking.


## 20. Unauthenticated `/config` POST can PERMANENTLY hijack a PC agent — both implementations

pc-agent added an in-exe local config dashboard (per broadcast [0006]) to
both `organiser-agent.cpp` and the separate, parallel `organiser-agent.py`
(Flask) implementation, so the machine name and secret can be managed from
a browser instead of hand-editing a file over SSH/RDP. Both implementations
share the same auth pattern:

```cpp
// C++
if (!g_secret.empty() && req.path != "/admin") { /* check X-Organiser-Secret */ }
```
```python
# Flask
def _check_auth():
    if not SECRET:
        return
    if request.headers.get("X-Organiser-Secret", "") != SECRET:
        abort(401, "Unauthorized")
```

This is the same "no secret configured → check is skipped entirely"
pattern as finding 3 — but finding 3 was about one-off operations
(`/run_command`, file read/write) during an exposure *window*. **`/config`
turns that same window into a permanent takeover**, because it lets the
caller — including one with zero credentials, during that window — *set
a brand-new secret*, which is persisted to disk and survives a restart.

**Confirmed dynamically, end-to-end, against BOTH implementations
independently** (real compiled C++ binary over real HTTP;
Flask's own test client for the Python version):

1. No secret configured → `/status` (and everything else) is open, as
   documented.
2. An attacker with **zero credentials** — no header, nothing — POSTs
   `{"secret": "attacker-chosen-secret"}` to `/config`. **Succeeds
   (`200 OK`)** in both implementations.
3. The legitimate owner, presenting exactly the same "no credentials"
   they always had (since none were ever configured), now gets a clean
   `401` on *every* endpoint, including `/config` itself.
4. The attacker's chosen secret works.
5. There is **no network-based recovery path** — the owner's only way
   back in is local/physical access to edit or delete the persisted
   config file directly.

**This is a meaningfully worse variant than finding 3**, not just a
duplicate of it: finding 3 describes a transient exposure ("anyone
nearby can run a command while this is unconfigured"); finding 20 is a
**ratchet** — a single moment of exposure converts into **permanent,
exclusive attacker control**, because the takeover is written to disk
and reloaded on every future start (unless `ORGANISER_SECRET` is set via
environment variable, which always takes precedence over the file and
is the one deployment mode this doesn't affect).

**Concrete persistence detail confirmed:** the config file lives at a
fixed, well-known, per-OS-user path — `$HOME/.config/organiser-agent/machine.json`
on Linux/Mac (`$XDG_CONFIG_HOME` if set), `%APPDATA%\organiser-agent\machine.json`
on Windows — and stores the secret in **plaintext JSON**:
```json
{"machine_id":"...","machine_name":"","secret":"attacker-chosen-secret-12345"}
```
Plaintext local storage of a locally-scoped secret is standard practice
and not itself a separate finding, but it's included here for anyone
doing incident response: this is exactly where to look, and exactly
what to expect to find.

**This is a design-level gap, not a one-off coding mistake** — it was
independently written into two completely separate codebases (C++ and
Python/Flask) by the same reasonable "no secret configured → stay
open" logic applied uniformly to a *new* endpoint that has a
fundamentally different risk profile (rotating/setting credentials)
than the *existing* endpoints that logic was originally designed for
(one-off file/command operations). That's worth calling out clearly
since fixing one implementation without recognizing the pattern would
very plausibly leave the other one — or any future third
implementation — exposed the same way.

**Suggested fix directions** (a genuine product decision, not mine to
make unilaterally — flagging trade-offs rather than prescribing one):
- Simplest: never allow `/config` to *set an initial* secret over the
  network at all. Require the first secret to come from the environment
  variable or a local file edit; once *any* secret exists, `/config` can
  be used to *rotate* it (still gated behind the existing secret, so this
  doesn't regress the no-secret-configured case into "can never be
  configured remotely at all" for legitimate first-time setup — it just
  means first-time setup needs one local step).
- Alternative: auto-generate a strong random secret on first run if none
  is configured (print it once, to the console/log), rather than leaving
  a wide-open "anyone can claim this" window at all.
- Weakest but cheapest: time-box the unconfigured window (e.g., only
  accept a `/config` secret-set within N seconds of process start), which
  reduces but does not eliminate the race against a legitimate first-time
  setup.

Regression tests:
`tests/test_organiser_agent_security.py::test_unauthenticated_config_post_can_permanently_hijack_the_machine`
(C++) and
`tests/test_organiser_agent_flask_security.py::test_unauthenticated_config_post_can_hijack_flask_agent_too`
(Flask) — both designed to start failing (not silently pass) if either
implementation's behavior changes, per the standing convention in this
file.

## 21. `working_dir` command injection (finding 1) — re-verified fixed

pc-agent rewrote `run_command` in `organiser-agent.cpp` (as a side effect
of a `run_command` timeout fix, not a conscious response to this specific
finding — see their commit message) to use `fork()` + `chdir()` +
`execl()` on POSIX and `CreateProcess`'s native `lpCurrentDirectory`
parameter on Windows, instead of building a `cd "<dir>" && <cmd>` shell
string. This means `working_dir` is **never shell text at all anymore**
on either platform, closing the injection at the root rather than adding
escaping to the old approach. An explicit `fs::is_directory()` (or
equivalent) check also now rejects anything that isn't a real, existing
directory before it's used at all.

**Re-verified independently** (not just by reading the diff or trusting
the lead's own re-verification, which they also did separately and noted
in `COMPETITION_REPORT.md`): rebuilt the exact current `organiser-agent.cpp`
from `main` for Linux, and re-ran the **exact same payload** that
originally worked (`working_dir: "x' ; touch <marker> ; echo '"`):

- Now rejected cleanly with `400` and a specific, honest error
  (`"working_dir does not exist or is not a directory: x' ; touch ..."`)
  — the payload is correctly treated as a literal (non-existent)
  directory name, never as shell syntax.
- No marker file created.
- **Legitimate use still works**: a real directory as `working_dir`
  correctly changes the command's working directory (`ls -la` inside a
  test directory listed exactly that directory's contents).
- Process remained stable throughout.

**Conclusion: this fix is complete and correctly implemented on both
platforms** (Windows re-checked via code review only, consistent with
every other Windows-specific claim in this document — I don't have a
Windows target to run it on, but the `lpCurrentDirectory` approach is the
correct native primitive and structurally can't reintroduce the same bug
class the way string concatenation could).


## 22. Methodology upgrade: real Windows verification via cross-compilation + Wine

Every Windows-specific claim in this document up to this point was
explicitly caveated as "static analysis only — I don't have a Windows
target, so this is a hypothesis from reading the code, not a confirmed
finding." That caveat is now substantially narrower.

**What I did:** installed `g++-mingw-w64-x86-64` and `wine64` (both from
Ubuntu's own package repos — `apt-get install`, no untrusted third-party
sources), cross-compiled the *exact current* `organiser-agent.cpp` from
`main` into a real Windows PE32+ executable, and ran it under Wine —
which emulates the real Win32 API surface (path canonicalization,
`CreateProcess`, the registry-free parts of the filesystem API, etc.).
Confirmed the binary genuinely exercises the Windows code path (its own
`/status` response reports `"platform":"Windows"`, which is a compile-time
`#if IS_WIN` branch, not something Wine could fake).

**Caveat, stated plainly and not glossed over:** this is MinGW-compiled,
not MSVC-compiled — a real Windows deployment likely uses MSVC. Wine
emulates genuine Win32 API behavior, so *filesystem/path/process-creation*
findings below are a strong proxy for real Windows. The C++
runtime/allocator internals (MinGW's libstdc++ vs. MSVC's STL) could
differ somewhat, so the one allocator-specific result (the `max_bytes`
finding) is reported with that narrower caveat — the *qualitative*
result (an exception is thrown and caught, not a crash) is a
language-level C++ guarantee that doesn't depend on which standard
library implementation is in use, so it very likely holds regardless,
but isn't claimed as a byte-for-byte match to an MSVC build.

**Results — three previously-unverified items now confirmed:**

1. **The exact traversal case pc-agent's own test honestly flagged as
   unverifiable.** `tests/test_organiser_agent.py`'s Flask-side
   equivalent test (`test_path_traversal_attempt_still_caught`) is
   marked `@unittest.expectedFailure` on Linux, with a detailed and
   *correct* explanation: `pathlib.PosixPath` never normalizes `/` vs
   `\` the way `pathlib.WindowsPath` does on real Windows, so a
   forward-slash traversal payload can't be shown to converge with a
   backslash-form protected path on a Linux sandbox. **I independently
   confirmed their hypothesis was right**: against the real (Wine-
   emulated) Windows path semantics, `C:/windows/system32/../../windows/system32`
   *is* correctly caught and rejected (`403`, "Path is inside the
   protected Windows system directory"). This closes finding-adjacent
   uncertainty for both the C++ and (by extension, since it was already
   confirmed via mocking on the Python side) Flask implementations'
   protected-path guards.
2. **Finding 21 (working_dir fix) re-confirmed under real Windows
   `CreateProcess` behavior**, including the specific double-quote +
   `&` injection shape hypothesized (never confirmed) in finding 2's
   original write-up for the `cmd.exe` code path. Used a real
   marker-file side effect (not a naive string match against the
   rejection message, which legitimately echoes the attempted path
   back and would otherwise cause a false positive) — no marker file
   was created; the payload was correctly rejected as a non-existent
   directory. Legitimate `working_dir` use was separately confirmed
   to still work correctly (`dir` listed the real directory's contents).
3. **Finding 4's `max_bytes` allocation failure re-confirmed on a real
   Windows process** (with the MinGW/MSVC caveat above): a 10 GB
   request against a 5-byte file threw a caught exception (`500`,
   `std::bad_alloc`), the process survived, and remained responsive
   immediately afterward.

Also re-confirmed the basic protected-path guard correctness on real
Windows (case-insensitivity, no false-positive on a sibling directory
like `C:\windows2`) — all consistent with what static review and the
Flask-side mocked tests already suggested, now with a real Windows
binary backing it up.

**What's still genuinely unverified, honestly:** the screenshot/GDI
code path (compiles fine cross-platform but wasn't exercised — Wine's
virtual display setup is a bigger lift than was worth it for this
pass), and anything that depends on real Windows-specific filesystem
quirks Wine doesn't fully emulate (8.3 short names, `\\?\` extended-length
prefixes, NTFS alternate data streams). Those remain flagged as
hypotheses, not findings, exactly as before — this upgrade closes three
specific, previously-flagged gaps; it doesn't claim total Windows
coverage.

**Regression tests** (skip cleanly if `g++-mingw-w64-x86-64`/`wine`
aren't installed, so this doesn't become a hard CI dependency):
`tests/test_organiser_agent_windows_via_wine.py`, 6 tests, all passing
in this environment after installing the two packages above.
