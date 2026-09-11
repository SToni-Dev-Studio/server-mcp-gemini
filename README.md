# GitHub Codespaces MCP Server

A small remote MCP server exposing four narrow tools for GitHub
Codespaces, instead of one broad "do anything" tool:

| Tool | What it does | Suggested permission |
|---|---|---|
| `list_codespaces` | Lists your codespaces, their repo, and state | Always allow (read-only) |
| `create_codespace` | Creates a codespace from a repo | Needs approval |
| `stop_codespace` | Stops a running codespace | Needs approval |
| `exec_command` | Runs a shell command inside a codespace | Needs approval (strongly recommended) |

## Why this fixes the original problem

Claude's own sandboxed environment couldn't complete the Codespaces
tunnel negotiation needed for `gh codespace ssh`. This server runs
as its own independent service — wherever *you* deploy it — so it
isn't subject to that sandbox's network restrictions. Claude just
calls it over MCP like any other connector.

## Auth model

The server does **not** hardcode any token. It reads your GitHub PAT
from the incoming request's `Authorization: Bearer <token>` header
(or `X-GitHub-Token` as a fallback). When you add this as a Custom
Connector in Claude, you'll paste the token into Claude's own
"Request headers" field — Claude stores it securely and attaches it
to every call. The token never sits in chat text again.

**Use a fine-grained PAT scoped only to Codespaces**, ideally on a
single repo, not your whole account. Revoke and re-issue it if you
ever suspect it's leaked.

## Required: set your deployed hostname

The SDK blocks any request whose `Host` header isn't `localhost` by
default (DNS-rebinding protection). The server now auto-detects this
on Render (`RENDER_EXTERNAL_HOSTNAME`) and Fly.io (`FLY_APP_NAME`), so
on those two platforms it should just work with zero config. On any
other host, or to override the auto-detected value, set it manually
(no `https://`, no path):

```bash
# Render: Dashboard > your service > Environment
# Fly:
fly secrets set MCP_ALLOWED_HOST=your-app.fly.dev
```

Without this on an unrecognized platform, every request to `/mcp`
returns `Invalid Host header`. Visit `https://your-host/` after
deploying — it now returns a small JSON status page (instead of a
confusing 404) that tells you whether an allowed host was detected.

## Troubleshooting: everything 404s

If your logs show every request hitting `/`, `/register`, or
`/.well-known/...` and **none hitting `/mcp`**, the connector URL in
Claude is wrong. The MCP endpoint is at `/mcp`, not the bare domain:

- ✅ `https://your-app.example.com/mcp`
- ❌ `https://your-app.example.com`

A GET to the bare `/` now returns a JSON hint instead of a 404, and
`/healthz` is available for platform health checks that expect 200 at
a fixed path.

## Deploy it

Any host that can run a Docker container and give you a public
HTTPS URL works — Railway, Fly.io, Render, a small VPS, etc.

Example with Railway (arbitrary choice, others work the same way):

```bash
# from this folder
railway init
railway up
```

Or manually with Docker anywhere:

```bash
docker build -t codespaces-mcp .
docker run -p 8000:8000 -e PORT=8000 codespaces-mcp
```

Put a reverse proxy / the platform's built-in HTTPS in front of it
so you get a `https://your-app.example.com/mcp` URL.

## Connect it to Claude

1. In Claude: **Customize > Connectors > + > Add custom connector**
2. Name it (e.g. "GitHub Codespaces")
3. URL: `https://your-app.example.com/mcp`
4. Under **Request headers**, add:
   - Name: `Authorization`
   - Value: `Bearer <your fine-grained PAT>`
5. Save, then go set each tool's permission level (Always allow /
   Needs approval) under the connector's settings — set `exec_command`
   to **Needs approval**.

## Config via .secrets

All settings can go in one `.secrets` file instead of hunting through a
platform's dashboard each time:

```bash
cp .secrets.example .secrets
# then fill in GITHUB_TOKEN (and MCP_ALLOWED_HOST if not on Render/Fly)
```

`.secrets` is gitignored -- it holds a live token, never commit it.
`load_dotenv()` only fills in vars that aren't already set, so real
platform env vars (Render/Fly dashboard secrets) always win over
`.secrets` -- safe to leave the file in place everywhere, including prod,
without it ever overriding a real secret.

For Docker, don't bake `.secrets` into the image (it'd ship your token
inside the image layers). Pass it at run time instead:

```bash
docker run -p 8000:8000 --env-file .secrets codespaces-mcp
```

Render and Fly both have their own secrets UI -- set values there for
deployed environments, and reserve `.secrets` for local runs.

## Local testing

```bash
pip install -r requirements.txt
cp .secrets.example .secrets   # fill in GITHUB_TOKEN
python server.py       # reads PORT from .secrets, defaults to 8000
```

Then point a local MCP client (or curl, per the MCP Streamable HTTP
spec) at `http://localhost:8000/mcp`.

## Security notes

- `exec_command` can run arbitrary shell commands with whatever
  permissions the codespace's default user has. Treat it like giving
  someone a terminal — because that's what it is. Keep it on "Needs
  approval."
- Don't expose this server without the header-auth requirement, or
  anyone with the URL could act as whoever's token is configured.
- Consider scoping the PAT to a single repo if the bot only needs
  one.
