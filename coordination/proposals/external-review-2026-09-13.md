# External review, consolidated + independently verified — 2026-09-13

The user ran this codebase past a couple of other AI reviews outside
this coordination process and asked me to check the claims and hand
anything real to the lead. Every finding below marked "Confirmed" was
checked directly against the current code on `main` by me this
session — not just relayed from the review text. Where a claim turned
out to already be fixed by `agent/pc-agent` or `agent/security-qa`'s
landed-but-unmerged work, I've said so explicitly rather than re-filing
it as new.

I haven't fixed anything here myself — `server.py`/`organiser-agent.*`
are out of my brief's scope, and several of these overlap
`security-qa`'s and `pc-agent`'s territory. This is a triage list for
you to route, not a pull request.

## A. Confirmed real, currently unaddressed

### A1 — `pc__screenshot` is broken end-to-end (HIGH, user-visible)
Two independent bugs that compound:
- `organiser-agent.cpp`'s function is literally named `screenshot_png`
  but returns BMP bytes — its own response honestly says
  `"format": "bmp"` (line ~1074), so the mismatch is confirmed in the
  agent's own output, not just the function name.
- `server.py`'s `pc__screenshot` (line ~999) hardcodes
  `f"data:image/png;base64,{b64[:200]}..."` — wrong mime type on top of
  the agent's real bug, **and** truncates to the first 200 base64
  characters. The caller never receives a usable image; this tool does
  not work today.

Suggested fix (not mine to implement): rename the C++ function honestly
(`screenshot_bmp` or ship a real PNG encoder), and have `server.py`
return the correct mime type plus the full payload — or better, return
`saved_path` and let the caller fetch deliberately, since a full 1080p
BMP as base64 is multi-MB and will blow through the MCP context window
if returned inline by default.

### A2 — `/admin/api/env` returns every secret in plaintext (HIGH)
`_admin_api_env_get` (server.py ~1582) returns
`{"key": ..., "value": i["envVar"]["value"]}` for every env var,
verbatim — `GITHUB_TOKEN`, `MCP_SERVER_PASSWORD`, `SSH_PRIVATE_KEY`,
`RENDER_API_KEY`, `ORGANISER_SECRET`, everything. Any admin-cookie leak
(XSS, screenshot, shared screen, browser extension) is a full
credential compromise, not just a dashboard compromise. Confirmed
still exactly as described — nobody's touched this function.

Suggested fix: mask values (last 4 chars visible, or a whitelist of
safe-to-show keys), with a separate logged "reveal" action for when the
real value is genuinely needed.

### A3 — `list_forwarded_ports` almost certainly doesn't work (MEDIUM)
`server.py` (~line 535): `exec_command(codespace_name, "gh codespace
ports -c <name>", ...)` — this SSHes *into* the codespace and asks it
to list its own forwarded ports via `gh`, which requires `gh` installed
and authenticated *inside* the codespace. Confirmed as written; I
didn't have a live codespace with `gh` configured internally to confirm
what it actually returns, but the shape of the bug (querying the wrong
side) is unambiguous from the code alone.

### A4 — Windows `run_command`'s normal-exit path can hang forever (MEDIUM-HIGH, Windows-only)
Verified directly in `organiser-agent.cpp`'s Windows `run_command`
(~line 260-315): on the **timeout** path, `TerminateJobObject` runs
*before* the drain loop — correct. On the **normal exit** path, the
code goes `WaitForSingleObject(pi.hProcess, ...)` (waits for the direct
child only) → straight into the `ReadFile` drain loop → `CloseHandle(hJob)`
only at the very end. If the direct child spawned a grandchild that
inherited the pipe's write handle and is still running when the direct
child exits, the pipe never signals EOF and `ReadFile` blocks with no
timeout. The POSIX path doesn't have this problem (process-group kill
fires on timeout before any drain); this is specifically the Windows
normal-exit path. Unverified by actual execution (would need a real
Windows box and a command that spawns a detached grandchild), but the
code-path logic is unambiguous.

Suggested fix: close/terminate the job object before draining, not after
— same ordering fix already applied to the timeout path.

### A5 — Data races on `g_secret`/`g_machine_name` (MEDIUM, Windows+Linux)
Confirmed: no `std::mutex` anywhere in `organiser-agent.cpp` (grepped
the whole file). `h_post_config` mutates `g_secret`/`g_machine_name`
(lines ~1195, ~1204) while other request-handling threads read them
(`h_status`, the auth check in `handle_conn`). `std::string` isn't
atomic — this is genuine UB under concurrent access, not just a style
nit. Rare in practice (config writes are infrequent) but real.

### A6 — POSIX trash overwrites same-named files (LOW-MEDIUM)
Confirmed in `trash_path` (~line 213): `fs::rename(p, trash / p.filename())`
silently overwrites an existing file of the same name in `~/.Trash`.
Worth noting: the fallback path added for cross-filesystem renames
(copy+remove, for when `rename()` hits EXDEV) explicitly passes
`fs::copy_options::overwrite_existing` — so this is a *deliberate*
current behavior on both code paths, not an oversight in one spot. The
Windows path (`SHFileOperationW`) handles collisions via the shell;
POSIX doesn't. A second delete of a same-named file is a silent
permanent loss of the first "deleted" copy — the opposite of what
Recycle-Bin-style deletion is supposed to guarantee.

### A7 — `Content-Length` header lookup still isn't truly case-insensitive (LOW)
This is a partial-fix nuance worth flagging precisely rather than
either "still broken" or "fixed": the finding-7 rewrite (the proper
Content-Length-aware read loop, genuinely fixed per security-qa's
re-verification) added a comment claiming case-tolerance, but the
actual lookup (~line 1328) only checks for exactly `"Content-Length:"`
and `"content-length:"` — a request with `CONTENT-LENGTH:` or
`Content-Length:` (mixed case) still misses both checks. Low practical
risk (every real client uses canonical casing) but the comment
over-promises relative to what the code does.

### A8 — `create_directories(parent_path())` on a bare filename (LOW, correctness not security)
Confirmed in both `h_move`/`h_write_file`'s binary and text branches
(~lines 879, 1100, 1112): no guard for an empty `parent_path()`. These
calls are already wrapped in `try/catch` returning a clean 500 rather
than crashing, so this isn't a crash/security issue — but a legitimate
same-directory `pc_move_file("a.txt", "b.txt")` or
`pc_write_file("out.txt", ...)` may unnecessarily 500 depending on how
the underlying stdlib handles `create_directories("")`. Cheap guard:
`if (!p.parent_path().empty()) fs::create_directories(p.parent_path());`.

### A9 — Admin dashboard: no rate limiting, no `secure` cookie flag (MEDIUM)
Both confirmed directly in `server.py`'s `_admin_login`/cookie code:
- No throttling or lockout on repeated `/admin/login` attempts — just
  `hmac.compare_digest`, which stops timing attacks, not brute force.
- `resp.set_cookie(..., httponly=True, samesite="lax")` — no
  `secure=True`. Free to add on Render/Fly (always HTTPS in practice);
  closes the "cookie sent over a mis-typed `http://` URL" hole.

### A10 — `file_transfer` read side still has no upfront size cap
Not new — this is `SECURITY_FINDINGS.md` finding 8, already tracked and
still open. Mentioning it here only because both external reviews
raised it independently and I want the cross-reference on record: a
`file_transfer("server:/mnt/ssd/huge.iso", "sandbox:/tmp/x")` on an
oversized source reads (and, for `server:`/`codespace:` kinds,
base64-decodes) the *entire* source before the size check runs,
risking an OOM rather than a clean rejection. The `pc:` leg is already
capped upstream via `max_bytes`; server/codespace legs aren't.

## B. Claims that are already fixed — don't re-file these

Both external reviews were working from an earlier snapshot of the
code. These specific claims are **no longer true** as of the current
`main` + `agent/pc-agent`'s (unmerged but real) work — confirmed
directly in code, not just taken on faith from status files:

- "Secret comparison isn't constant-time" — fixed in both agent builds
  (`constant_time_equal()` in `.cpp`, `hmac.compare_digest` in `.py`).
- "`StrictHostKeyChecking=no`" — fixed; `pc-tunnel@.service` now uses
  `StrictHostKeyChecking=yes` + a per-PC `UserKnownHostsFile`.
- "`run_command` has no timeout" / "`working_dir` shell injection" —
  both fixed; POSIX uses `chdir()` in a forked child, Windows passes
  `cwd` via `CreateProcess`'s `lpCurrentDirectory`, neither concatenates
  it into shell text anymore. (Windows path re-verified by
  `agent/security-qa` via a real MinGW cross-compile + Wine run — as
  close to genuine Windows execution as anyone's gotten on this
  project so far.)
- "`/preview`'s `max_bytes` unbounded" — fixed on both the agent side
  (checks real file size before allocating) and the server.py side
  (defense-in-depth clamp).
- "64KB request body truncation" — genuinely fixed with a proper
  `Content-Length`-aware read loop (see A7 above for the one remaining
  nuance in that fix).
- **`/config` unauthenticated hijack (a HIGH finding neither external
  review caught, for what it's worth)** — this one *was* real and
  serious (unauthenticated first-time `/config` POST could permanently
  claim a PC agent with no recovery path), found independently by both
  `security-qa` and `pc-agent` at nearly the same time, and is now
  fixed in both `organiser-agent.cpp` and `organiser-agent.py`. Worth
  knowing the in-house review process caught something the external
  ones missed.

## C. Proposals — not started, need your (or the user's) sign-off before any subagent picks these up

These aren't bugs — they're two substantial proposals from the external
review. I'm forwarding them as-is because the user asked me to, not
because I'm recommending either be started. Both are explicitly scoped
by their own authors as future/optional work, and both would be a real
allocation decision (whose branch, how much time, whether it's worth
it at all) rather than something to just start on.

### C1 — Desktop application wrapper for organiser-agent (Windows)
Converts the PC agent from a console app + Task Scheduler + browser
config page into a system-tray app with a native WebView2-hosted
dashboard, an Inno Setup installer, and a self-updating binary with
3-version rollback. Also bundles 4 small independent bug fixes
(screenshot mislabeling — same as A1 above; a `std::cout` data race in
logging; a non-atomic updater swap; the bare-filename
`create_directories` bug — same as A8 above) as "cheap to fix while
touching the same files."

This is a genuinely large scope change (new UI layer, an installer
toolchain, an auto-update mechanism with its own attack surface —
binary swap + signature/hash verification needs to be gotten right or
it's a new vulnerability class, not just a UX improvement). The
proposal's own resource budget and risk table are reasonable and
specific enough to act on if this gets a green light, but I'd want
explicit confirmation this is actually wanted before anyone starts —
it's a multi-day effort, not a bug-fix-sized task, and it touches the
exact same files three subagents (`pc-agent`, `security-qa`, me) are
all currently working in.

### C2 — Capability/adapter refactor (explicitly "reference only, do not build" per its own author)
Restructure `server.py` so capabilities (codespaces, server admin, PC
files, transfer, diagnostics) are decoupled from the MCP transport,
with pluggable adapters (MCP, REST, CLI, etc.) reading from a shared
registry. The proposal is explicit that this shouldn't be built without
a second concrete protocol use case actually materializing — I'm
including it only because the user asked me to hand along "the ideas,"
not because it's actionable right now. No action needed unless that
changes.

## D. Documentation reconciliation (this doc, i.e. mine)

The external review also flagged that `ARCHITECTURE.md` had drifted —
several "still open" items were actually already fixed, and a
"Pending: agent/pc-agent's fixes" section described merged work in
future tense. That critique was accurate against the version it saw.
I've since rewritten the affected sections against current `main` (the
same verification pass that produced section A/B above) — see the
commit landing alongside this file. Nothing further needed here unless
new drift shows up.
