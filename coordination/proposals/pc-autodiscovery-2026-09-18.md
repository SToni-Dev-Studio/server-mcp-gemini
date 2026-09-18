# Proposal: PC auto-discovery, presence polling, and a live PC status dashboard

**From:** docs-release agent, relaying a user request  
**To:** lead (for routing to pc-agent and/or hub-cicd as appropriate)  
**Date:** 2026-09-18  
**Status:** Draft — needs lead sign-off before anyone starts building

---

## What the user asked for

> "auto-detect for every PC so the PC gets an ID as well with a name
> of the PC since Windows names PCs, and maybe something like a status
> thing — basic tools — so that if there is a tool like 'pc list' you
> can always see what PCs are there and what not, and the Linux server
> must auto-detect the PCs, it can poll every few minutes or so in
> order to check if it's still reachable and what not"

Short version: **make `pc_list_configured` show live reachability
status, not just what's in the PCS registry**, and **reduce the
manual work of adding a PC by auto-detecting its name from Windows
itself**.

---

## What already exists (don't rebuild these)

Checked directly against current `main` before writing this:

- `organiser-agent` (both builds) already exposes a `/status` endpoint
  returning `version`, `platform`, `machine_id` (a UUID generated once
  and persisted to a config file), and `machine_name` (set via
  `/config`'s `machine_name` field, falling back to the OS hostname via
  `GetComputerNameA` / `gethostname`). **The Windows hostname is already
  available today** — `machine_name` in a `/status` response is the
  PC's own name.

- `pc_list_configured` already lists every entry in the `PCS` registry
  (name + port; secret never shown).

- `pc_organiser_status(pc)` already pings one PC's agent and returns
  its version, platform, and reachability status.

- `run_diagnostics()` already checks every configured PC's agent in one
  pass, but it's a one-shot MCP tool call, not a persistent background
  poll.

- `hub-cli pc list` (in `scripts/hub-cli.py`, not yet packaged as .deb)
  lists PCs from the server-side tunnel config, not from the Render-side
  `PCS` registry — these can drift.

The gap is: **none of this is automatic or live**. You find out a PC is
down when a tool call fails, not proactively. Adding a PC still requires
manually syncing the PCS registry in Render with the tunnel config on the
server. And the PC's own name isn't shown in `pc_list_configured` because
that only reads the local registry, not the live `/status` endpoint.

---

## Proposed changes

### 1. Enrich `pc_list_configured` with live data (server.py)

Change `pc_list_configured` to call `/status` on each configured PC
concurrently (with a short timeout, e.g. 3 seconds), and return a
combined view:

```
PC Registry (2 configured, 2 reachable):

desktop  port=7842  ✅ reachable  name="SEPISO-DESKTOP"  v2.1.0-cpp  Windows
laptop   port=7843  ⚠️ unreachable (timeout after 3s)
```

- **Reachable:** shows the name the PC reports for itself (`machine_name`
  from `/status` — already the Windows hostname by default), version,
  and platform.
- **Unreachable:** shows the last-known status if cached (see §3), or
  just "unreachable" with the error.
- Concurrent calls so a 2-PC registry doesn't take 6 seconds if one is
  down.

This is a small change to one existing tool. No new tools needed.

### 2. Auto-populate `machine_name` from Windows hostname on first run (organiser-agent, both builds)

Already done — the agent falls back to `GetComputerNameA` / `gethostname`
if `machine_name` isn't explicitly configured. The only thing missing is
**surfacing this in the UI clearly** so the user knows that's what's
happening. Currently the `/config` dashboard just shows an empty
`machine_name` field if it hasn't been set, even though the agent is
already using the OS hostname as the fallback in `/status`. Minor UX fix:
show the effective name (i.e. the fallback value) as a placeholder in the
config field, not a blank.

### 3. Background reachability cache on the Linux server (hub-cli or a new hub-monitor service)

The Linux server already runs the SSH tunnels to each PC. It's the right
place to poll, because it's always on and it's the hub that all traffic
flows through anyway.

**Suggested shape:**

A simple systemd timer + oneshot service (not a daemon — same pattern as
the proposed .deb auto-updater in broadcast [0017]):

```
hub-monitor.service   — oneshot: polls every configured PC's /status once
hub-monitor.timer     — runs hub-monitor.service every 3 minutes
```

What it does each run:
1. Reads `/etc/pc-tunnel/*.conf` to find configured PCs (name + port).
2. `curl -sf --max-time 5 http://127.0.0.1:<port>/status` for each.
3. Writes results to a small JSON file, e.g.
   `/var/lib/hub-monitor/pc-status.json`:
   ```json
   {
     "updated": "2026-09-18T10:30:00Z",
     "pcs": {
       "desktop": {"reachable": true, "name": "SEPISO-DESKTOP",
                   "version": "2.1.0-cpp", "last_seen": "2026-09-18T10:30:00Z"},
       "laptop":  {"reachable": false, "last_seen": "2026-09-18T09:15:00Z",
                   "error": "connection refused"}
     }
   }
   ```
4. Exits. No persistent process, no socket, no daemon to crash.

`hub-cli pc list` and `hub-diagnostics` can then read this file for
instant status (no live poll needed for a CLI invocation), and `server.py`
can SSH-cat it as part of `pc_list_configured` for cached reachability
without waiting for a live poll on every MCP tool call.

The timer interval (3 minutes suggested) means you find out about a PC
going offline within 3 minutes, not only when you next run a tool against
it.

### 4. Auto-detect new PCs (stretch goal — probably scope for a separate pass)

The user mentioned "the Linux server must auto-detect the PCs." Fully
automatic discovery (no config at all) is hard without a discovery
protocol — the server doesn't know what IP a new PC might be at. But a
**semi-automatic flow** is achievable:

When the PC agent starts up for the first time, it could POST a
registration ping to a known endpoint on the server (e.g. the hub-cli's
HTTP interface, or a small dedicated endpoint). The server would then:
1. Show a pending-approval entry in `hub-cli pc list`.
2. Let the user approve it with `hub-cli pc approve <name>`, which writes
   the `.conf` file and enables the tunnel service.

This needs a shared secret for the registration step (otherwise any
machine on the LAN could register itself) and a way for the PC to know
the server's address — both solvable, but not trivially. **Recommend
deferring this to a separate proposal** unless the user specifically wants
it now. The §1–3 changes above give most of the value (live status,
Windows hostname auto-populated, background polling) without requiring a
new registration protocol.

---

## What this is NOT proposing

- Any change to how PCs are *routed* (the `PCS` registry + tunnel model
  stays exactly as-is — this is purely about visibility and monitoring).
- A new persistent daemon (§3 is a timer + oneshot, not a long-running
  process).
- Breaking any existing tool signatures (§1 is backward-compatible —
  `pc_list_configured` still works, it just returns more information).

---

## Suggested routing

| Item | Who |
|---|---|
| §1 — enrich `pc_list_configured` | pc-agent (touches server.py's PC tool area) |
| §2 — UX fix for machine_name placeholder | pc-agent (touches organiser-agent config dashboard) |
| §3 — hub-monitor systemd timer | hub-cicd (systemd units + hub-cli integration is their territory) |
| §4 — auto-registration (if approved) | new scope, new discussion |

Lead to decide whether to act on any of this, route it, or park it.

---

## One thing to verify before starting §1

`pc_list_configured` calling `/status` on every PC concurrently is only
safe if the timeout is short and failures are caught cleanly — a PC that's
down shouldn't make the whole tool call hang. Recommend
`asyncio.gather(*[...], return_exceptions=True)` with a 3-second
per-PC timeout, same pattern already used in `_run_diagnostics`.
