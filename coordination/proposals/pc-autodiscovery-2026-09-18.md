# Proposal: PC auto-discovery, presence polling, and live status
**From:** docs-release agent, relaying a user request  
**To:** lead (for routing to pc-agent and/or hub-cicd)  
**Date:** 2026-09-18 (revised same day based on user feedback)  
**Status:** Draft — needs lead sign-off before anyone starts

---

## What the user wants (revised)

- **Every 5 minutes** polling (not 3 — no need to hammer PCs)
- **Retry on a missed poll** — if a poll fails, retry 2–3 times at
  ~3-second intervals before declaring the PC offline (not instant
  offline on first miss)
- **Events** when a PC goes offline or comes back online — not just a
  status file, an actual logged event
- **No manual port configuration** — shouldn't need to think about
  ports at all
- **Auto-registration is the priority** — PCs should appear
  automatically, not require hand-editing config files

---

## The port question — two realistic options

The current architecture uses SSH port-forwards with explicit port
numbers because the PC agent binds a local port and the server tunnels
to it. The user wants to drop this. Two real alternatives:

### Option A — Put PCs directly on the Tailnet (recommended)

Install Tailscale on each Windows PC. The PC agent then binds its HTTP
server to the Tailscale interface IP (or loopback, reachable via
Tailscale exit node), and `server.py` reaches it directly via
`tailscale ssh` to the PC, not via a tunnel through the Linux server.

```
Render → tailscale ssh sepisotoni@SEPISO-DESKTOP → organiser-agent
```

- **No ports to configure** — Tailscale handles addressing. The agent
  can use any fixed internal port (say, always 7842) because the
  Tailscale network is isolated anyway — no exposure, no collision risk
  between PCs on different machines.
- **No `pc-tunnel@.service` units needed** — the Linux server is no
  longer the routing hub for PC traffic, just for `server_*` tools.
- **Auto-registration becomes trivial** — when a PC joins the Tailnet,
  `server.py` can discover it via the Tailscale API (list devices →
  filter by tag or name pattern → try `/status`).
- **Tradeoff:** every PC needs Tailscale installed. For a personal setup
  this is fine (Tailscale is free for personal use, ~5 MB, dead simple
  to install). The PC agent would need a small change to bind on the
  right interface.

### Option B — Keep the tunnel model, drop manual port config

Keep the current SSH-tunnel architecture but auto-assign ports:
- The hub-monitor assigns each PC a port from a pool (e.g. 7842, 7843,
  7844...) based on a hash of its `machine_id` or registration order.
- The PC agent advertises "I want port X" in its registration ping;
  the server accepts or assigns one.

This is more complex than Option A and still has ports under the hood —
just hidden from the user. Option A is cleaner.

**Recommendation: Option A (Tailscale on PCs).** The project already
uses Tailscale for the Linux server; extending it to PCs is a natural
fit and eliminates the whole port-management problem for real rather
than papering over it.

---

## Full revised design (assuming Option A — Tailscale on PCs)

### PC agent changes

1. **Tailscale-aware binding** — the agent binds to `0.0.0.0` (or
   specifically the Tailscale interface) on a fixed internal port
   (always 7842, or configurable but with a sane default). Since
   Tailscale is the network boundary, binding wider than loopback is
   safe within the tailnet.

2. **Registration on startup** — when the agent starts, it sends a
   registration ping to a known endpoint on the Linux server (or
   directly to `server.py` via a Tailscale-reachable URL, TBD). The
   ping includes:
   - `machine_id` (already exists — persisted UUID)
   - `machine_name` (already exists — Windows hostname fallback)
   - `tailscale_ip` (the PC's Tailscale IP, readable from
     `tailscale ip -4` or the Tailscale local API)
   - `version`, `platform`

3. **Registration auth** — a shared registration token (set in the
   agent's config, same as `ORGANISER_SECRET` today) so random machines
   can't self-register. Or, simpler: only accept registrations from
   IPs already on the Tailnet (Tailscale handles that boundary).

### Server-side changes (`server.py`)

1. **PC registry becomes dynamic** — instead of (or alongside) the
   static `PCS` env var, `server.py` maintains a small in-memory
   registry of known PCs, populated from a JSON file written by
   hub-monitor. Fallback to `PCS` for anyone who wants static config.

2. **`pc_list_configured` shows live status** — calls each PC's
   `/status` concurrently (3-second timeout, `asyncio.gather` with
   `return_exceptions=True`) and shows:
   ```
   PC Registry (2 known, 1 online, 1 offline):
   SEPISO-DESKTOP  ✅ online   v2.1.0-cpp  last_seen=just now
   SEPISO-LAPTOP   ⚠️ offline  last_seen=14 minutes ago
   ```

3. **New `pc_events` tool** (or folded into diagnostics) — returns
   recent online/offline events from the hub-monitor event log.

### Hub-side changes (hub-cli / hub-monitor)

1. **hub-monitor systemd timer** — polls every **5 minutes** (not 3).
   On each poll:
   - Pings each known PC's `/status` via Tailscale (direct HTTP, no
     SSH hop needed once PCs are on the tailnet).
   - If a poll **fails**: retries **3 times at 3-second intervals**
     before marking as offline.
   - If status **changes** (online→offline or offline→online): appends
     an event to `/var/lib/hub-monitor/events.jsonl`:
     ```json
     {"ts": "2026-09-18T10:35:00Z", "pc": "SEPISO-DESKTOP", "event": "offline", "last_version": "2.1.0-cpp"}
     {"ts": "2026-09-18T11:02:00Z", "pc": "SEPISO-DESKTOP", "event": "online",  "version": "2.1.0-cpp"}
     ```
   - Updates `/var/lib/hub-monitor/pc-status.json` with current state.

2. **Registration endpoint** — a small HTTP endpoint (or a special
   path on hub-cli if it grows an HTTP mode, or just a webhook that
   writes to a pending-registrations file that hub-monitor picks up).
   When a PC registers:
   - Writes to `/var/lib/hub-monitor/pending.json` if not already known.
   - On next `hub-cli pc list`, shows pending PCs with an "approve?"
     prompt.
   - `hub-cli pc approve SEPISO-DESKTOP` moves it to the active
     registry, writes its Tailscale IP + name to the status file, and
     optionally pushes the updated `PCS` to Render via the API so
     `server.py` picks it up.
   - Fires an `"online"` event.

3. **`hub-cli pc list`** reads from `pc-status.json` for instant output
   (no live poll on CLI invocation — that's the timer's job).

4. **`hub-cli pc remove <name>`** — marks a PC as removed, fires an
   `"offline"` event.

---

## What this removes entirely

- `pc-tunnel@.service` and its `.conf` files per PC — no longer needed
  once PCs are on the Tailnet and `server.py` reaches them directly.
- Manual port assignment — gone.
- Manual `PCS` env var editing — optional fallback only; normal flow is
  auto-registration.
- The `StrictHostKeyChecking` / `ssh-keyscan` setup step — Tailscale
  handles identity; no host key pinning needed for the PC leg.

---

## What stays the same

- The Linux server's role for `server_*` tools (Tailscale SSH to the
  hub for all server-side operations) — unchanged.
- `organiser-agent`'s HTTP API (`/status`, `/list`, `/move`, etc.) —
  unchanged, just reachable differently.
- The `PCS` env var as a static fallback for anyone who wants it —
  unchanged.
- `machine_id` and `machine_name` in `/status` — already there,
  already works.

---

## Open questions for the lead

1. **Tailscale on PCs: acceptable dependency?** It's free for personal
   use and ~5 MB, but it's a real new dependency for every Windows PC.
   If the answer is no, Option B (auto-assigned ports, same tunnel
   model) is the fallback — more complex but no new software needed.

2. **Registration auth model**: shared token (same as `ORGANISER_SECRET`
   today, just repurposed) or Tailscale-network-membership-as-auth
   (simpler: only devices on the tailnet can even reach the registration
   endpoint, so no extra token needed)? The second option is cleaner
   but requires Tailscale on PCs.

3. **`server.py` reaching PCs directly vs. via the hub**: with Tailscale
   on PCs, `server.py` on Render *could* reach each PC directly if
   Render's server is also on the tailnet, but it currently isn't (only
   the Linux server has Tailscale). The easier path is: `server.py`
   still SSHes to the Linux server, and the Linux server curls the PC's
   Tailscale IP directly — keeping Render out of the tailnet but
   eliminating the port-forward tunnel. Worth confirming this is the
   intended shape.

4. **Scope split**: this touches pc-agent (agent-side changes), hub-cicd
   (hub-monitor, hub-cli), and server.py (dynamic registry, new tools).
   Should this be a single coordinated feature branch or three
   coordinated branches? Given the coordination gap that surfaced in
   broadcast [0014], probably worth a single feature branch with one
   owner, or at minimum an explicit handoff protocol.

---

## Priority order if approved

1. Tailscale-on-PCs decision (gates everything else)
2. Hub-monitor timer + event log (observable immediately once PCs are on tailnet)
3. `pc_list_configured` enriched with live status
4. Auto-registration + approval flow
5. `pc_events` tool in `server.py`
6. Retire `pc-tunnel@.service` (once everything else is working)
