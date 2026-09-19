# Proposal v2: PC auto-registration + hub-side polling (corrects v1)

**From:** lead, drafting the user's own words directly, correcting a
misread in the first draft (coordination/proposals/pc-autodiscovery-2026-09-18.md)
**Status:** Approved by the user in principle for this shape. Still
needs implementation — routing at the bottom.

## What v1 got wrong

v1 proposed installing Tailscale on every Windows PC and having
`server.py` (on Render) reach each PC more directly. **The user
explicitly rejected this**: PCs are supposed to stay LAN-local behind
the Linux hub, not gain their own network identity. Quoting directly:

> "having to download tailscale on every pc would be annoying as
> [...] it's supposed to all go through the linux server"

v1 also invented a 5-minute-with-Tailscale polling scheme and an
auto-registration flow keyed off Tailscale's device list. Neither of
those match what was actually asked for. This version replaces v1
entirely for the parts it got wrong; the accurate parts of v1 (live
status in a `pc list`-style view, concurrent polling, no persistent
daemon) carry over.

## What the user actually wants, in their own words

> "auto-detect for every PC so the PC gets an ID as well with a name of
> the PC since windows names PCs... something like a status thing...
> basic tools so that if there is a tool like 'pc list' you can always
> see what PCs are there... the linux server must auto-detect the PCs,
> it can poll every few minutes or so to check if it's still
> reachable... why not every 5 mins, I don't really want my PC getting
> crazy pings... if a poll is missed it will send a few more in 3
> second interval[s] and if those don't reach it can declare the PC as
> offline... when it goes offline or one comes online it's posted as an
> event... I don't want to have to manually set ports... isn't there a
> different system you can use?? ... the auto-registration is supposed
> to be to the linux server, where it auto-registers with the linux
> server"

Plus, separately: Render should be allowed to sleep/wake on its normal
free-tier schedule — only the Linux hub needs to be up 24/7 with
Tailscale connected, since it's the thing doing the polling.

## The design

### Why no ports, no Tailscale-on-PCs, no tunnel units

PCs already sit on the same LAN as the Linux hub. That means the hub
can just talk to a PC's LAN IP directly over plain HTTP — no Tailscale
needed on the PC (Tailscale is for reaching the hub itself from
outside the LAN, i.e. from Render; PCs never need to be reachable from
outside the LAN, only from the hub that's already on it). This also
means `pc-tunnel@.service` (the current per-PC SSH-tunnel systemd
template) can be retired entirely — it exists to solve a problem
(Render reaching a PC through the hub) that a hub-side LAN relay solves
more simply, with less to configure and less to break.

### Agent-side: self-registration, no configured port

1. On startup, `organiser-agent` binds an HTTP listener on an
   OS-assigned ephemeral port (port 0 → let the OS pick a free one) —
   the user never types a port number anywhere.
2. It then sends a registration announcement to a small, always-on
   listener on the Linux hub (LAN broadcast, or a fixed well-known hub
   LAN IP:port if broadcast proves unreliable — hub-cicd's call which
   is more robust for this network) containing: `machine_id`
   (persisted UUID, already exists), `machine_name` (Windows hostname
   fallback, already exists), its own LAN IP, the port it just bound,
   and a shared registration token (reusing the existing
   `ORGANISER_SECRET` concept — not a new secret type) so a random LAN
   device can't register itself.
3. Re-announces periodically (e.g. every few minutes, or on any
   restart) so the hub's registry self-heals if the PC's IP or port
   ever changes (DHCP lease renewal, agent restart) without a human
   touching anything.

### Hub-side: registry + poller + relay

1. A small always-on registration listener (part of `hub-monitor` or a
   thin sibling service — hub-cicd's call) receives PC announcements
   and maintains a local registry (name → {id, lan_ip, port,
   last_registered}), e.g. a JSON file or small SQLite DB under
   `/var/lib/hub-monitor/`.
2. A `systemd` timer (oneshot, not a daemon — same pattern as the
   `.deb`'s auto-updater) polls every registered PC's `/status`
   directly over the LAN, on the interval the user asked for: **every
   5 minutes**, not more aggressive.
3. On a missed poll: retry up to 2-3 more times at **3-second
   intervals** before marking the PC offline — not instant-offline on
   one miss.
4. On any online→offline or offline→online transition: append a
   timestamped line to an event log (e.g.
   `/var/lib/hub-monitor/events.jsonl`), AND actively push the event to
   Render (a small authenticated POST to a new `server.py` endpoint,
   not just something Render has to poll for). This has a second
   purpose beyond just notifying Render promptly: the incoming request
   itself is what wakes Render up from its free-tier sleep, so Render's
   own cached PC list gets updated proactively instead of only when a
   user happens to make an unrelated call while Render is already awake
   (user-requested refinement, 2026-09-18).
5. `server.py` (on Render), when it needs live PC status or wants to
   run something on a PC, reaches the hub the same way it already
   does — `tailscale ssh` — and either reads the cached registry/status
   file, or (for an actual action, e.g. `pc_run_command`) asks the hub
   to relay a local LAN HTTP call to the target PC and pass the result
   back. No new channel between Render and PCs is needed for actions;
   the existing Render↔hub Tailscale SSH link carries everything, same
   as it does for `server_*` tools today. The one new channel is the
   event push in step 4 above — hub-to-Render, over plain HTTPS (not
   SSH, since it's a one-way notification, not a command relay), using
   the same MCP bearer password the hub already has no reason not to
   hold (it already holds far more sensitive secrets than that).

### Render sleep/wake

No change needed — Render's existing free-tier auto-sleep/wake behavior
is unaffected by any of this, since it only ever talks to the hub
on-demand per MCP tool call, exactly as it does now. Only the hub needs
to be a persistent, always-on Tailscale node, which it already is.

### What this removes

- `pc-tunnel@.service` and its per-PC `.conf` files.
- Any manual port configuration, anywhere, for PCs.
- `pc-tunnel@.service`'s `StrictHostKeyChecking`/`ssh-keyscan` setup
  step (nothing SSHes to a PC directly anymore).

### What stays the same

- Render only ever reaches the hub via `tailscale ssh` — never a PC
  directly. This was already the architecture's intent from the start
  of this whole project ("PCs should preferably remain private behind
  the LAN/Tailscale/network layer") — this proposal fulfills that more
  completely than the current tunnel-based setup does, not less.
- `organiser-agent`'s HTTP API itself (`/status`, `/run_command`,
  `/move`, etc.) — unchanged, just reached differently (LAN-direct from
  the hub instead of through a port-forward tunnel).
- `machine_id`/`machine_name` — already exist, just get used as the
  registration key instead of a config-file port number.

## Suggested routing

| Piece | Who |
|---|---|
| Ephemeral-port binding + registration announce (agent-side) | pc-agent |
| Registration listener + registry + poller + retry logic + event log (hub-side) | hub-cicd |
| Relay mechanism for live PC actions through the hub (server.py side) | lead |
| Retire `pc-tunnel@.service` once the above is working | hub-cicd, last step, not first |

Sequencing matters here: don't retire the tunnel units until the
registration+relay path is proven working, so there's no window where
PCs are unreachable either way.
