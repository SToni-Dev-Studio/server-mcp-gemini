# codespaces-mcp

A remote MCP server that gives Claude 43 narrow, purpose-built tools —
instead of one broad "do anything" tool — for managing personal
infrastructure: GitHub Codespaces, a Linux home server, and one or more
Windows PCs, all through a single HTTPS endpoint. Includes a
password-gated browser admin dashboard for configuring the deployment
itself.

Read next:
- **`ARCHITECTURE.md`** — how the pieces fit together, auth model, known
  limitations. Start here if you're modifying anything.
- **`BUILD_AND_SETUP.md`** — step-by-step setup: building the PC agent,
  the Linux tunnel, Render env vars, verifying it end-to-end.
- **`SKILL.md`** — full tool-by-tool reference (what Claude reads to use
  this server well).

## What it does, briefly

| Area | Example tools |
|---|---|
| GitHub Codespaces | `list_codespaces`, `exec_command`, `create_git_commit_and_push` |
| Linux home server | `server_status`, `server_run_command`, `server_tail_log` |
| Windows PC(s) | `pc_list_files`, `pc_move_file`, `pc__screenshot` |
| File transfer | `file_transfer` — any endpoint to any other (sandbox/server/pc/codespace) |
| Diagnostics / admin | `run_diagnostics`, browser dashboard at `/admin` |

See `SKILL.md` for the complete list with parameters.

## Quick start

```bash
git clone <this repo>
cd server-mcp-claude
pip install -r requirements.txt
cp .secrets.example .secrets   # fill in whichever sections you need —
                                # every subsystem is independently optional
python server.py                # reads PORT from .secrets, defaults to 8000
```

That gets `server.py` running locally with no auth required (no host
env vars detected = local dev mode). Point an MCP client at
`http://localhost:8000/mcp`.

For an actual deployment (Render) reachable by Claude, plus the Windows
PC agent and Linux tunnel setup, follow **`BUILD_AND_SETUP.md`** from
the top — there's no shortcut version, since the PC/server pieces each
need their own machine-side setup.

## Auth model

Three independent layers — see `ARCHITECTURE.md` for the full picture:

1. **MCP endpoint** (`/mcp`): `MCP_SERVER_PASSWORD`, sent as
   `Authorization: Bearer <token>`. Required once this is reachable from
   the public internet — the server refuses every request rather than
   serving unauthenticated if this is unset on a detected public host
   (Render/Fly).
2. **Admin dashboard** (`/admin`): separate cookie-based login,
   `ADMIN_PASSWORD` (falls back to `MCP_SERVER_PASSWORD` if unset).
3. **Each PC's organiser-agent**: `X-Organiser-Secret` header, matched
   per-PC via the `PCS` registry.

GitHub API access uses up to three PATs (`GITHUB_TOKEN`,
`_SECONDARY`, `_TERTIARY`) with automatic fallback on 401/403.

## Deploy it

Render is the documented, supported target — see `BUILD_AND_SETUP.md`
§5 for the full env var list. A `Dockerfile` and `fly.toml` are also
present; Fly.io would plausibly work (the server auto-detects
`FLY_APP_NAME`) but isn't confirmed maintained — see `ARCHITECTURE.md`.

```bash
docker build -t codespaces-mcp .
docker run -p 8000:8000 --env-file .secrets codespaces-mcp
```

Don't bake `.secrets` into the image — pass it at container run time
(`--env-file`), or use your platform's own secrets UI for a real
deployment.

## Connect it to Claude

1. **Customize > Connectors > + > Add custom connector**
2. Name it, URL: `https://<your-deployed-host>/mcp`
3. Under **Request headers**: `Authorization: Bearer <MCP_SERVER_PASSWORD>`
4. Set per-tool permission levels under the connector's settings — at
   minimum, set every `*_run_command` tool to **Needs approval** (see
   "Known limitations" in `ARCHITECTURE.md` for why).

## Known limitations

The full, honest list lives in **`ARCHITECTURE.md`**. Highlights:

- `organiser-agent.py` (the Python build) has no path-traversal/
  protected-path checks. Use `organiser-agent.cpp` for anything real.
- `*_run_command` tools (PC and Linux server both) are intentionally
  close to unrestricted shell access — treat their permission level
  accordingly.
- `file_transfer` can't yet move a binary file to/from a PC (fails
  cleanly rather than corrupting — organiser-agent's file API is
  text-only today).
- No CI test/lint pipeline for `server.py` yet.

## Local testing

```bash
pip install -r requirements.txt
cp .secrets.example .secrets
python server.py
```

Run the existing tests:

```bash
python tests/test_admin_cookie_auth.py   # plain script, run directly
pip install pytest && pytest tests/      # runs everything, including
                                          # the fixture-based file_transfer tests
```
