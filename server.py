"""
GitHub Codespaces MCP Server
-----------------------------
Exposes narrow, named tools for managing and executing commands in
GitHub Codespaces, the user's Linux home server, one or more Windows
PCs (via organiser-agent) — with multi-account GitHub
fallback, password protection, and a browser-based admin dashboard.

Auth:
    - MCP Server Auth: Validates `MCP_SERVER_PASSWORD` against incoming
      Authorization header (set via 'OAuth Client Secret' in Claude).
      Compared in constant time. If unset while running on a public
      host (RENDER_EXTERNAL_HOSTNAME/MCP_ALLOWED_HOST present), the
      server fails CLOSED rather than silently allowing every request.
    - GitHub Auth: Uses primary `GITHUB_TOKEN`, secondary
      `GITHUB_TOKEN_SECONDARY`, and tertiary `GITHUB_TOKEN_TERTIARY`
      with automatic failover on billing/auth errors.
    - Admin dashboard Auth: Separate cookie-based login, gated by
      `ADMIN_PASSWORD` (falls back to `MCP_SERVER_PASSWORD` if unset).

PC organiser-agent routing:
    Render never talks to a PC directly. Every pc_* tool call goes
    Render -> ordinary SSH -> Linux server -> loopback tunnel -> PC.
    See the "PC File Organiser Tools" section below for the full
    diagram. Multiple PCs are supported via the `PCS` env var (JSON
    registry) and a `pc` parameter on every pc_*/transfer__*_pc tool.


Server Management:
    Set SERVER_HOST, SERVER_USER, and optionally SERVER_SSH_PORT; authenticate
    with SSH_PRIVATE_KEY (raw key text) or SERVER_SSH_KEY (path).

Admin dashboard (configure everything from a browser):
    Visit /admin on this service's URL. Requires RENDER_API_KEY (and
    optionally RENDER_SERVICE_ID, which defaults to this service) to
    manage Render env vars and trigger redeploys from the page.

Run locally:
    export PORT=8000
    python server.py
"""

import asyncio
import base64
import hashlib
import hmac
import secrets
import html as _html
import json
import os
import shlex
import shutil
import time
import urllib.parse

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from mcp.server.streamable_http import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

load_dotenv()

GITHUB_API = "https://api.github.com"
RENDER_API = "https://api.render.com/v1"


SERVER_HOST = os.environ.get("SERVER_HOST", "192.168.101.105")
SERVER_USER = os.environ.get("SERVER_USER", "sepisotoni")
SERVER_SSH_PORT = int(os.environ.get("SERVER_SSH_PORT") or "22")
SERVER_SSH_KEY = os.path.expanduser(os.environ.get("SERVER_SSH_KEY", "~/.ssh/id_rsa"))

# This service's own Render identity — used by the admin dashboard to manage
# itself by default. Override RENDER_SERVICE_ID if you rename/fork the service.
RENDER_API_KEY = os.environ.get("RENDER_API_KEY", "").strip()
RENDER_SERVICE_ID = os.environ.get(
    "RENDER_SERVICE_ID", "srv-da11cupt0dsc73aq2qq0"
).strip()

# If SSH_PRIVATE_KEY env var is set (raw key text), write it to a temp file
_SSH_PRIVATE_KEY_CONTENT = os.environ.get("SSH_PRIVATE_KEY", "")
_SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", "/tmp/render_mcp_key")
if _SSH_PRIVATE_KEY_CONTENT:
    import stat as _stat

    os.makedirs(os.path.dirname(_SSH_KEY_PATH), exist_ok=True)
    with open(_SSH_KEY_PATH, "w") as _kf:
        _kf.write(_SSH_PRIVATE_KEY_CONTENT.strip() + "\n")
    os.chmod(_SSH_KEY_PATH, _stat.S_IRUSR | _stat.S_IWUSR)
    SERVER_SSH_KEY = _SSH_KEY_PATH


# ---------------------------------------------------------------------------
# PC Registry (multi-PC support)
# ---------------------------------------------------------------------------
#
# Configure via the PCS env var — a JSON object mapping a short name to
# {"port": <local tunnel port on the server>, "secret": <ORGANISER_SECRET
# for that PC's agent>}. Each PC gets its own pc-tunnel@<name>.service
# instance on the Linux server, forwarding a distinct loopback port to
# that PC. Example:
#
#   PCS={"desktop": {"port": 7842, "secret": "abc"}, "laptop": {"port": 7843, "secret": "xyz"}}
#
# If PCS is not set, falls back to a single "default" PC built from the
# legacy ORGANISER_PORT / ORGANISER_SECRET env vars (port 7842 if unset).
# Every pc_* / transfer__*_pc tool takes an optional `pc` parameter
# (default "default") to pick which one it talks to.

_PCS_RAW = os.environ.get("PCS", "").strip()
_PC_REGISTRY: dict = {}
if _PCS_RAW:
    try:
        _PC_REGISTRY = json.loads(_PCS_RAW)
    except json.JSONDecodeError:
        print(
            "WARNING: PCS env var is not valid JSON — ignoring it, falling back to single-PC mode."
        )

if not _PC_REGISTRY:
    _PC_REGISTRY = {
        "default": {
            "port": int(os.environ.get("ORGANISER_PORT", "7842")),
            "secret": os.environ.get("ORGANISER_SECRET", ""),
        }
    }


def _resolve_pc(pc: str) -> dict:
    if pc not in _PC_REGISTRY:
        available = ", ".join(sorted(_PC_REGISTRY.keys())) or "(none configured)"
        raise RuntimeError(f"Unknown PC '{pc}'. Configured PCs: {available}")
    return _PC_REGISTRY[pc]


# ---------------------------------------------------------------------------
# Host Detection & Security Settings
# ---------------------------------------------------------------------------


def _detect_allowed_host() -> str:
    explicit = os.environ.get("MCP_ALLOWED_HOST", "").strip()
    if explicit:
        return explicit
    render_host = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "").strip()
    if render_host:
        return render_host
    fly_app = os.environ.get("FLY_APP_NAME", "").strip()
    if fly_app:
        return f"{fly_app}.fly.dev"
    return ""


_allowed_host = _detect_allowed_host()
_is_public_deployment = bool(_allowed_host)
if not _allowed_host:
    print("WARNING: no MCP_ALLOWED_HOST detected. Remote requests to /mcp will fail.")
else:
    print(f"MCP allowed host: {_allowed_host}")

_transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["localhost", "127.0.0.1"]
    + ([_allowed_host] if _allowed_host else []),
    allowed_origins=["*"],
)

mcp = FastMCP("github-codespaces", transport_security=_transport_security)


# ---------------------------------------------------------------------------
# Authentication Middleware
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# OAuth 2.1 State, Token Persistence & Helpers
# ---------------------------------------------------------------------------

_OAUTH_CODES: dict = {}  # code -> {client_id, redirect_uri, code_challenge, code_challenge_method, expires_at}
_OAUTH_CLIENTS: dict = {}  # client_id -> {client_secret, redirect_uris}
_OAUTH_TOKENS_FILE = os.environ.get("OAUTH_TOKENS_FILE", "/tmp/oauth_tokens.json")


def _load_oauth_data():
    tokens = set()
    refresh_tokens = {}
    if os.path.exists(_OAUTH_TOKENS_FILE):
        try:
            with open(_OAUTH_TOKENS_FILE, "r") as f:
                data = json.load(f)
                tokens = set(data.get("tokens", []))
                refresh_tokens = dict(data.get("refresh_tokens", {}))
        except Exception:
            pass
    return tokens, refresh_tokens


_OAUTH_TOKENS, _OAUTH_REFRESH_TOKENS = _load_oauth_data()


def _save_oauth_data():
    try:
        os.makedirs(os.path.dirname(_OAUTH_TOKENS_FILE), exist_ok=True)
        with open(_OAUTH_TOKENS_FILE + ".tmp", "w") as f:
            json.dump(
                {
                    "tokens": list(_OAUTH_TOKENS),
                    "refresh_tokens": _OAUTH_REFRESH_TOKENS,
                },
                f,
            )
        os.replace(_OAUTH_TOKENS_FILE + ".tmp", _OAUTH_TOKENS_FILE)
    except Exception as e:
        print(f"Warning: Failed to save OAuth tokens: {e}")


def _generate_oauth_token() -> str:
    ts = str(int(time.time()))
    secret = os.environ.get("MCP_SERVER_PASSWORD", "gemini_mcp_secret_2026")
    sig = hmac.new(
        secret.encode("utf-8"), ts.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:32]
    return f"mcp_oauth_{ts}_{sig}"


def _generate_refresh_token() -> str:
    ts = str(int(time.time()))
    secret = os.environ.get("MCP_SERVER_PASSWORD", "gemini_mcp_secret_2026")
    sig = hmac.new(
        secret.encode("utf-8"), ts.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:32]
    return f"mcp_refresh_{ts}_{sig}"


def _is_valid_token(token: str) -> bool:
    if not token:
        return False
    token = token.strip("\"'")
    expected_password = os.environ.get("MCP_SERVER_PASSWORD", "").strip()
    if expected_password and hmac.compare_digest(token, expected_password):
        return True
    if ADMIN_PASSWORD and hmac.compare_digest(token, ADMIN_PASSWORD):
        return True
    if token in _OAUTH_TOKENS:
        return True
    # Stateless HMAC signature validation for OAuth tokens (access & refresh)
    if token.startswith("mcp_oauth_") or token.startswith("mcp_refresh_"):
        parts = token.split("_")
        if len(parts) >= 4:
            ts = parts[2]
            sig = parts[3]
            secret = os.environ.get("MCP_SERVER_PASSWORD", "gemini_mcp_secret_2026")
            expected_sig = hmac.new(
                secret.encode("utf-8"), ts.encode("utf-8"), hashlib.sha256
            ).hexdigest()[:32]
            if hmac.compare_digest(sig, expected_sig):
                return True
    return False


class PasswordAuthMiddleware(BaseHTTPMiddleware):
    """
    Protects the MCP endpoint with a shared-secret bearer token or OAuth token.
    Exempts /, /healthz, /admin, and /oauth routes.
    """

    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)
        path = request.url.path
        if (
            path
            in (
                "/",
                "/healthz",
                "/.well-known/oauth-authorization-server",
                "/.well-known/oauth-protected-resource",
            )
            or path.startswith("/admin")
            or path.startswith("/oauth")
        ):
            return await call_next(request)

        expected_password = os.environ.get("MCP_SERVER_PASSWORD", "").strip()

        if not expected_password and not _OAUTH_TOKENS:
            if _is_public_deployment:
                return JSONResponse(
                    {
                        "error": "Server misconfigured: MCP_SERVER_PASSWORD is not set on a public deployment."
                    },
                    status_code=503,
                )
            return await call_next(request)

        # 1. Check Authorization header (case-insensitive "Bearer" prefix)
        auth_header = request.headers.get("authorization", "").strip()
        token = ""
        if auth_header:
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
            else:
                token = auth_header

        # 2. Fallback to query parameters (ChatGPT, EventSource, SSE)
        if not token:
            token = (
                request.query_params.get("access_token")
                or request.query_params.get("token")
                or request.query_params.get("auth")
                or request.query_params.get("api_key")
                or ""
            ).strip()

        # 3. Fallback to custom HTTP headers
        if not token:
            token = (
                request.headers.get("x-access-token")
                or request.headers.get("x-api-key")
                or request.headers.get("x-mcp-token")
                or ""
            ).strip()

        if not _is_valid_token(token):
            host = _allowed_host or request.headers.get(
                "host", "server-mcp-gemini.fly.dev"
            )
            base_url = f"https://{host}" if not host.startswith("http") else host
            metadata_url = f"{base_url}/.well-known/oauth-authorization-server"
            protected_res_url = f"{base_url}/.well-known/oauth-protected-resource"
            return JSONResponse(
                {"error": "Unauthorized: Invalid or missing bearer token."},
                status_code=401,
                headers={
                    "WWW-Authenticate": f'Bearer realm="mcp", error="invalid_token", resource_metadata="{protected_res_url}"'
                },
            )
        return await call_next(request)


# ---------------------------------------------------------------------------
# Shell-Quoting Helper
# ---------------------------------------------------------------------------
#
# Every function below that builds a command string for `_ssh_server` or
# the codespace `exec_command` SSH path uses shlex.quote() on any
# user-supplied value. Without it, a path/message containing a single
# quote (e.g. a commit message like "fix user's login bug", or a Windows
# folder with an apostrophe) breaks out of the surrounding quotes and the
# remainder gets interpreted as shell syntax — a real injection risk, not
# just a correctness bug, since several of these run with sudo.


def _q(value) -> str:
    """shlex.quote, coercing non-strings first (e.g. int line counts)."""
    return shlex.quote(str(value))


# ---------------------------------------------------------------------------
# Token Resolution & Fallback Helpers
# ---------------------------------------------------------------------------

_VALID_ACCOUNTS = {"auto", "primary", "secondary", "tertiary"}


def _get_token(account: str = "auto") -> tuple[str, str]:
    """Returns (token, account_name) — supports primary, secondary, tertiary."""
    # A typo'd/unrecognized account string used to fall through silently
    # to the same behavior as "auto" (security-qa finding 9) -- a caller
    # who named one specific account and mistyped it got silently
    # redirected to a different configured account instead of an error.
    # Not a privilege-escalation issue (still only picks from already-
    # configured tokens) but a real correctness/surprise gap.
    if account not in _VALID_ACCOUNTS:
        raise ValueError(
            f"Unknown account '{account}' -- expected one of {sorted(_VALID_ACCOUNTS)}"
        )

    primary = os.environ.get("GITHUB_TOKEN", "").strip()
    secondary = os.environ.get("GITHUB_TOKEN_SECONDARY", "").strip()
    tertiary = os.environ.get("GITHUB_TOKEN_TERTIARY", "").strip()

    if account == "secondary":
        if not secondary:
            raise RuntimeError("GITHUB_TOKEN_SECONDARY is not configured.")
        return secondary, "secondary"

    if account == "tertiary":
        if not tertiary:
            raise RuntimeError("GITHUB_TOKEN_TERTIARY is not configured.")
        return tertiary, "tertiary"

    if account == "primary":
        if not primary:
            raise RuntimeError("GITHUB_TOKEN is not configured.")
        return primary, "primary"

    # auto: try primary → secondary → tertiary
    if primary:
        return primary, "primary"
    if secondary:
        return secondary, "secondary"
    if tertiary:
        return tertiary, "tertiary"

    raise RuntimeError("No GitHub tokens configured in environment.")


def _gh_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def _gh_request_with_fallback(
    method: str, path: str, json_body: dict | None = None, account: str = "auto"
) -> dict:
    """
    Executes an HTTP request against the GitHub API with automatic
    fallback through all tokens on 401/403.

    Supports GET/POST/PATCH/DELETE properly — a previous version of this
    function only distinguished GET vs "everything else routes through
    POST", which meant set_machine_type (a PATCH) was silently sent as a
    POST and would have been rejected by GitHub's API.
    """
    token, used_account = _get_token(account)
    method = method.upper()

    async def _do(tok: str) -> httpx.Response:
        async with httpx.AsyncClient() as client:
            kwargs = {"headers": _gh_headers(tok), "timeout": 60}
            if json_body is not None and method in ("POST", "PATCH", "PUT"):
                kwargs["json"] = json_body
            return await client.request(method, f"{GITHUB_API}{path}", **kwargs)

    resp = await _do(token)

    if resp.status_code in (401, 403) and account == "auto":
        for fallback_account, env_name in [
            ("secondary", "GITHUB_TOKEN_SECONDARY"),
            ("tertiary", "GITHUB_TOKEN_TERTIARY"),
        ]:
            fallback_token = os.environ.get(env_name, "").strip()
            if fallback_token and fallback_token != token:
                print(
                    f"Token failed with HTTP {resp.status_code}. Trying {fallback_account}..."
                )
                resp = await _do(fallback_token)
                if resp.status_code not in (401, 403):
                    break

    resp.raise_for_status()
    return resp.json() if resp.content else {}



# ---------------------------------------------------------------------------
# SSH Helper for Linux Server
# ---------------------------------------------------------------------------


async def _ssh_server(command: str, timeout: int = 60) -> str:
    """
    Run a command on the home Linux server over key-authenticated SSH.
    """

    async def _run(cmd_list: list, t: int) -> tuple[int, str]:
        """Run a subprocess, return (returncode, output)."""
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=t)
            out = (stdout.decode(errors="replace") + stderr.decode(errors="replace")).strip()
            return proc.returncode, out
        except asyncio.TimeoutError:
            if proc:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return -1, f"timed out after {t}s"
        except Exception as e:
            return -2, str(e)

    key_args = (
        ["-i", SERVER_SSH_KEY]
        if (SERVER_SSH_KEY and os.path.exists(SERVER_SSH_KEY))
        else []
    )

    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout=8",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=2",
        "-p", str(SERVER_SSH_PORT),
    ] + key_args + [f"{SERVER_USER}@{SERVER_HOST}", command]

    rc, output = await _run(ssh_cmd, timeout)
    target = f"{SERVER_USER}@{SERVER_HOST}:{SERVER_SSH_PORT}"
    if rc == 0:
        return output or f"(exited {rc}, no output)"
    if rc == -1:
        return f"SSH to {target} failed: {output}"
    return f"SSH to {target} exited with status {rc}: {output or 'no output'}"


# ---------------------------------------------------------------------------
# Codespace Lifecycle Tools
# ---------------------------------------------------------------------------








# ---------------------------------------------------------------------------
# Shell Execution & File I/O Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def exec_command(
    codespace_name: str, command: str, timeout_seconds: int = 60, account: str = "auto"
) -> str:
    """Run a single shell command inside a codespace asynchronously via SSH. Auto-starts stopped codespaces if needed."""
    if not shutil.which("gh"):
        raise RuntimeError("The 'gh' CLI is not installed on this server.")

    token, used_account = _get_token(account)

    async def _run_ssh(tok: str):
        env = os.environ.copy()
        env["GH_TOKEN"] = tok
        proc = await asyncio.create_subprocess_exec(
            "gh",
            "codespace",
            "ssh",
            "--codespace",
            codespace_name,
            "--",
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_seconds
            )
            return proc.returncode, (stdout.decode() + stderr.decode()).strip()
        except asyncio.TimeoutError:
            proc.kill()
            raise TimeoutError(f"Command timed out after {timeout_seconds} seconds.")

    returncode, output = await _run_ssh(token)

    # If execution failed due to stopped/shutdown state or missing connection, auto-start and retry
    out_lower = output.lower()
    is_stopped_err = any(
        k in out_lower
        for k in (
            "not found",
            "stopped",
            "shutdown",
            "failed to connect",
            "404",
            "unavailable",
            "offline",
            "connect",
        )
    )

    if returncode != 0 and is_stopped_err:
        print(
            f"Codespace '{codespace_name}' appears to be shut down. Attempting auto-start..."
        )
        start_result = await start_codespace(codespace_name, account=account)
        print(f"Auto-start result: {start_result}")
        if "Available" in start_result or "running" in start_result:
            returncode, output = await _run_ssh(token)

    if returncode != 0 and account == "auto" and used_account == "primary":
        secondary_token = os.environ.get("GITHUB_TOKEN_SECONDARY", "").strip()
        if secondary_token and (
            "auth" in output.lower()
            or "denied" in output.lower()
            or "billing" in output.lower()
        ):
            print("SSH execution failed on primary. Retrying with secondary...")
            returncode, output = await _run_ssh(secondary_token)

    return output or f"(command exited {returncode}, no output)"





# ---------------------------------------------------------------------------
# Git & Port Management Tools
# ---------------------------------------------------------------------------





# ---------------------------------------------------------------------------
# Server Management Tools
# ---------------------------------------------------------------------------



@mcp.tool()
async def server_run_command(command: str) -> str:
    """
    Run a shell command on the home Linux server over SSH.
    Good for anything read-only or administrative.

    Note: the blocklist below is a footgun-prevention nicety, not a real
    security boundary (trivially bypassable — this tool intentionally runs
    arbitrary commands, that's its purpose). Avoid wiping disks.
    """
    blocked = ["rm -rf /", "mkfs", "dd if=", "> /dev/sda", "shutdown now", "halt"]
    for b in blocked:
        if b in command:
            return f"Blocked: '{b}' is not allowed."
    return await _ssh_server(command)













# ---------------------------------------------------------------------------
# PC File Organiser Tools
# ---------------------------------------------------------------------------
#
# These tools let Claude browse, move, delete, and analyse files on the
# user's Windows PC(s), each running the companion organiser-agent
# (C++ build).
#
# Routing — everything goes through the Linux home server, nothing talks
# to a PC directly:
#
#   Render (this process)
#       │  ordinary SSH (same channel _ssh_server() uses for every
#       │                other server_* tool — one exec call)
#       ▼
#   stoni-room-serve (Linux)
#       │  curl http://127.0.0.1:<pc's port>/...  (loopback only —
#       │  pc-tunnel@<name>.service forwards this to that PC via its
#       │  own outbound SSH connection)
#       ▼
#   organiser-agent.exe on the target PC
#
# Render never opens a raw TCP connection to any PC. PC requests are
# proxied through the Linux server's loopback-only tunnels over SSH.
#
# Multi-PC: configure the PCS env var (see "PC Registry" above). Every
# tool below takes `pc: str = "default"` to pick which machine it talks to.
# ---------------------------------------------------------------------------


async def _organiser_ssh_request(
    method: str,
    path: str,
    pc: str = "default",
    params: dict | None = None,
    body: dict | None = None,
    timeout: int = 30,
) -> str:
    """
    Executes one HTTP request against a PC's organiser-agent by having the
    Linux server curl its own loopback tunnel for that PC, via the
    existing SSH exec channel. Returns raw response text
    (expected to be JSON).

    The whole request is shipped as a base64-encoded Python source blob
    (`echo <b64> | base64 -d | python3 -`) — the same base64-transfer
    convention used elsewhere in this file — so arbitrary path/content
    characters (spaces, backslashes, quotes in Windows paths) never touch
    a shell quoting layer at all.
    """
    entry = _resolve_pc(pc)
    base = f"http://127.0.0.1:{entry['port']}"
    envelope = {
        "method": method,
        "path": path,
        "params": params or {},
        "body": body,
        "secret": entry.get("secret", ""),
        "base": base,
    }
    env_b64 = base64.b64encode(json.dumps(envelope).encode("utf-8")).decode("ascii")

    py_source = f"""
import urllib.request as u, urllib.parse as p, json, base64
e = json.loads(base64.b64decode("{env_b64}").decode())
url = e["base"] + e["path"]
if e["params"]:
    url += "?" + p.urlencode(e["params"])
headers = {{"Content-Type": "application/json"}}
if e["secret"]:
    headers["X-Organiser-Secret"] = e["secret"]
data = json.dumps(e["body"]).encode() if e["body"] is not None else None
req = u.Request(url, data=data, headers=headers, method=e["method"])
try:
    with u.urlopen(req, timeout=25) as r:
        print(r.read().decode())
except u.HTTPError as ex:
    print(json.dumps({{"error": ex.read().decode(), "status_code": ex.code}}))
except Exception as ex:
    print(json.dumps({{"error": str(ex)}}))
"""
    src_b64 = base64.b64encode(py_source.encode("utf-8")).decode("ascii")
    cmd = f"echo {src_b64} | base64 -d | python3 -"
    return await _ssh_server(cmd, timeout=timeout)


def _parse_organiser_response(raw: str) -> dict:
    raw = (raw or "").strip()
    if not raw:
        raise RuntimeError(
            "Empty response reaching the organiser-agent via the server. "
            "Check: is pc-tunnel@<name>.service running on the Linux server, "
            "and is organiser-agent.exe running on that PC?"
        )
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(
            f"Non-JSON response from organiser-agent (via server): {raw[:300]}"
        )


async def _org_get(path: str, params: dict | None = None, pc: str = "default") -> dict:
    raw = await _organiser_ssh_request("GET", path, pc=pc, params=params)
    return _parse_organiser_response(raw)


async def _org_post(path: str, body: dict, pc: str = "default") -> dict:
    raw = await _organiser_ssh_request("POST", path, pc=pc, body=body)
    return _parse_organiser_response(raw)










@mcp.tool()
async def pc_run_command(
    command: str, working_dir: str = "", pc: str = "default"
) -> str:
    """
    Run a shell command on a PC. Works on Windows (cmd/PowerShell) and
    Mac/Linux (bash). Avoid destructive commands; prefer pc_delete_file
    for deletions.
    """
    body: dict = {"command": command}
    if working_dir:
        body["working_dir"] = working_dir
    data = await _org_post("/run_command", body, pc=pc)
    output = data.get("stdout", "") + data.get("stderr", "")
    rc = data.get("returncode", 0)
    return f"[exit {rc}]\n{output}" if output else f"[exit {rc}] (no output)"




# ---------------------------------------------------------------------------
# File Transfer (sandbox <-> PC <-> server <-> codespace, any combination)
# ---------------------------------------------------------------------------
#
# Replaces the earlier transfer__pc_to_sandbox / transfer__sandbox_to_pc /
# transfer__sandbox_to_codespace / transfer__server_to_sandbox /
# transfer__sandbox_to_server tools. Those covered only 5 of the ~10
# meaningful directed pairs (no pc<->server, pc<->codespace,
# server<->codespace, codespace<->codespace, or pc<->pc), and read local
# files in TEXT mode (open(..., "r", encoding="utf-8", errors="replace")),
# which silently corrupts any binary file (images, zips, .exe, etc).
#
# This tool moves bytes between ANY two endpoints, transported internally
# as base64 so binary data survives intact.
#
# Address format for `source` / `destination` (a single string each):
#   sandbox:<path>                          -- this server process's own local disk
#   server:<path>                           -- the home Linux server, via SSH
#   pc:<pc_name>:<path>                     -- a Windows PC, via organiser-agent
#                                               (pc_name from the PCS registry,
#                                               e.g. "desktop"; Windows paths
#                                               like C:\\Users\\me\\f.txt are fine --
#                                               only the first two colons are
#                                               used as separators)
#   codespace:<name>:<path>                 -- a GitHub Codespace, default account
#   codespace:<name>@<account>:<path>       -- explicit account (auto/secondary/tertiary)
#
# Examples:
#   file_transfer("pc:desktop:C:\\Users\\me\\report.pdf", "server:/home/user/report.pdf")
#   file_transfer("codespace:my-space:/workspace/out.zip", "sandbox:/tmp/out.zip")
#   file_transfer("sandbox:/tmp/build.tar", "codespace:my-space@tertiary:/workspace/build.tar")
#
# Known limitation (not this tool's bug, an upstream one): PC-side read/write
# still goes through organiser-agent's /preview and /write_file endpoints,
# which are currently TEXT-only. Binary transfers where a PC is the source
# or destination will fail with a clear error until organiser-agent exposes
# base64-safe file read/write endpoints. Every other pair (sandbox, server,
# codespace, in any combination) is fully binary-safe today.

_FILE_TRANSFER_MAX_BYTES = 15 * 1024 * 1024  # 15 MB, pre-base64

# organiser-agent.cpp's handle_conn previously read HTTP requests into a
# fixed 65536-byte buffer and silently truncated anything larger --
# reporting HTTP 200 success on the truncated write regardless
# (SECURITY_FINDINGS.md finding 7, confirmed independently by lead while
# wiring this up: a 128,000-byte test payload silently landed on disk as
# 48,981 bytes). pc-agent fixed this with a proper Content-Length-aware
# growable read loop (agent/pc-agent commit 86caa29, merged into main) --
# verified by re-running the exact 128,000-byte payload that originally
# exposed the bug: it now arrives complete (128,000 of 128,000 bytes) and
# an oversized (>25MB) body is cleanly rejected with 413 rather than
# silently truncated. See tests/test_file_transfer_pc_e2e.py's
# test_organiser_agent_no_longer_has_the_64kb_truncation_bug.
# The pc: leg's cap can now match the general _FILE_TRANSFER_MAX_BYTES
# cap rather than staying artificially low.
_PC_TRANSFER_SAFE_MAX_BYTES = _FILE_TRANSFER_MAX_BYTES  # raw bytes, pre-base64 -- matches the general cap now that finding 7 is fixed


def _parse_location(loc: str) -> tuple[str, str, str]:
    """Returns (kind, name_or_account_str, path). name_or_account_str is
    "" for sandbox/server, "<pc_name>" for pc, "<name>[@<account>]" for
    codespace."""
    if ":" not in loc:
        raise ValueError(
            f"Malformed location '{loc}' -- expected 'kind:path' or 'kind:name:path'"
        )
    kind, rest = loc.split(":", 1)
    kind = kind.strip().lower()
    if kind in ("sandbox", "server"):
        return kind, "", rest
    if kind in ("pc", "codespace"):
        if ":" not in rest:
            raise ValueError(
                f"Malformed '{kind}:' location '{loc}' -- expected '{kind}:name:path'"
            )
        name, path = rest.split(":", 1)
        # An empty name (e.g. "pc::/some/path") used to silently fall
        # back to the default PC / auto account downstream instead of
        # raising -- reject it here instead (security-qa finding 9).
        name_check = name.split("@", 1)[0] if kind == "codespace" else name
        if not name_check:
            raise ValueError(
                f"Malformed '{kind}:' location '{loc}' -- empty name before the path"
            )
        return kind, name, path
    raise ValueError(
        f"Unknown location kind '{kind}' -- expected sandbox, server, pc, or codespace"
    )


async def _location_read_bytes(loc: str) -> bytes:
    kind, name, path = _parse_location(loc)

    if kind == "sandbox":
        with open(path, "rb") as f:
            return f.read()

    if kind == "server":
        # Check size BEFORE reading+base64-encoding the whole thing --
        # without this, a huge source file gets fully read, encoded, and
        # streamed back over SSH before the size check in file_transfer()
        # ever runs, risking an OOM on this process rather than a clean
        # upfront rejection (external review A10 / SECURITY_FINDINGS.md
        # finding 8's other half -- the pc: leg was already capped
        # upstream via max_bytes, server:/codespace: weren't).
        size_str = (await _ssh_server(f"stat -c%s {_q(path)} 2>&1")).strip()
        try:
            size = int(size_str)
        except ValueError:
            raise ValueError(
                f"Could not stat '{path}' on server (got: {size_str[:200]!r})"
            )
        if size > _FILE_TRANSFER_MAX_BYTES:
            raise ValueError(
                f"'{path}' on server is {size} bytes, over the {_FILE_TRANSFER_MAX_BYTES} "
                f"byte file_transfer limit -- rejected before reading, not after."
            )
        b64 = await _ssh_server(f"base64 -w0 {_q(path)} 2>&1")
        try:
            return base64.b64decode(b64, validate=False)
        except Exception:
            raise ValueError(
                f"Could not read '{path}' from server as a file (got: {b64[:200]!r})"
            )

    if kind == "pc":
        # Binary-safe as of agent/pc-agent's /read_file_b64 endpoint
        # (see coordination/status/pc-agent.md, broadcast [0006]) --
        # this used to go through /preview, which is text/UTF-8 only
        # and silently failed on any binary file.
        data = await _org_get(
            "/read_file_b64",
            {"path": path, "max_bytes": _FILE_TRANSFER_MAX_BYTES},
            pc=name or "default",
        )
        content_b64 = data.get("content_b64")
        if content_b64 is None:
            raise ValueError(
                f"Could not read '{path}' from pc:{name} -- {data.get('error', 'unknown error')}"
            )
        try:
            return base64.b64decode(content_b64, validate=True)
        except Exception as e:
            raise ValueError(f"pc:{name} returned invalid base64 for '{path}': {e}")

    if kind == "codespace":
        cs_name, _, account = name.partition("@")
        account = account or "auto"
        # Same upfront-size-check reasoning as the server: kind above.
        size_str = (
            await exec_command(cs_name, f"stat -c%s {_q(path)} 2>&1", account=account)
        ).strip()
        try:
            size = int(size_str)
        except ValueError:
            raise ValueError(
                f"Could not stat '{path}' on codespace:{cs_name} (got: {size_str[:200]!r})"
            )
        if size > _FILE_TRANSFER_MAX_BYTES:
            raise ValueError(
                f"'{path}' on codespace:{cs_name} is {size} bytes, over the "
                f"{_FILE_TRANSFER_MAX_BYTES} byte file_transfer limit -- rejected "
                f"before reading, not after."
            )
        b64_cmd = f"base64 -w0 {_q(path)} 2>&1"
        result = await exec_command(cs_name, b64_cmd, account=account)
        try:
            return base64.b64decode(result.strip(), validate=False)
        except Exception:
            raise ValueError(
                f"Could not read '{path}' from codespace:{cs_name} (got: {result[:200]!r})"
            )

    raise AssertionError("unreachable")  # _parse_location already validated kind


async def _location_write_bytes(loc: str, data: bytes) -> str:
    kind, name, path = _parse_location(loc)

    if len(data) > _FILE_TRANSFER_MAX_BYTES:
        raise ValueError(
            f"File is {len(data)} bytes, over the {_FILE_TRANSFER_MAX_BYTES} byte "
            f"limit for file_transfer. Use a location-specific tool for large files."
        )

    if kind == "sandbox":
        import pathlib

        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        return f"sandbox:{path} ({len(data)} bytes)"

    if kind == "server":
        encoded = base64.b64encode(data).decode()
        result = await _ssh_server(
            f"mkdir -p $(dirname {_q(path)}) && echo {_q(encoded)} | base64 -d > {_q(path)} && echo OK"
        )
        if "OK" not in result:
            raise ValueError(f"Write to server:'{path}' failed: {result}")
        return f"server:{path} ({len(data)} bytes)"

    if kind == "pc":
        # Binary-safe as of agent/pc-agent's content_b64 support on
        # /write_file (see coordination/status/pc-agent.md, broadcast
        # [0006]) -- always sent as base64 now, text or binary alike, so
        # there's no encoding-mismatch failure mode to special-case here.
        # Cap now matches _FILE_TRANSFER_MAX_BYTES -- see the comment on
        # _PC_TRANSFER_SAFE_MAX_BYTES above (finding 7 is fixed; this
        # check just keeps the pc: leg consistent with every other kind
        # rather than being load-bearing for safety anymore).
        if len(data) > _PC_TRANSFER_SAFE_MAX_BYTES:
            raise ValueError(
                f"File is {len(data)} bytes -- pc: transfers are capped at "
                f"{_PC_TRANSFER_SAFE_MAX_BYTES} bytes."
            )
        encoded = base64.b64encode(data).decode("ascii")
        result = await _org_post(
            "/write_file", {"path": path, "content_b64": encoded}, pc=name or "default"
        )
        if result.get("error"):
            raise ValueError(f"Write to pc:{name}:'{path}' failed: {result['error']}")
        return f"pc:{name}:{path} ({len(data)} bytes)"

    if kind == "codespace":
        cs_name, _, account = name.partition("@")
        account = account or "auto"
        encoded = base64.b64encode(data).decode()
        cmd = f"mkdir -p $(dirname {_q(path)}) && echo {_q(encoded)} | base64 -d > {_q(path)} && echo OK"
        result = await exec_command(cs_name, cmd, account=account)
        if "OK" not in result:
            raise ValueError(f"Write to codespace:{cs_name}:'{path}' failed: {result}")
        return f"codespace:{cs_name}:{path} ({len(data)} bytes)"

    raise AssertionError("unreachable")




# ===========================================================================
# CONSOLIDATED TOOLS (40 → 15)
# ===========================================================================

# ===========================================================================
# CONSOLIDATED MCP TOOLS
# 40 tools → 14 tools
# ===========================================================================

# ---------------------------------------------------------------------------
# 1. github_account_status  (was: check_account_status)
# ---------------------------------------------------------------------------
@mcp.tool()
async def github_account_status() -> str:
    """Check validity and user identities for all configured GitHub tokens (primary, secondary, tertiary)."""
    results = []
    tokens_to_check = [
        ("primary", os.environ.get("GITHUB_TOKEN", "").strip()),
        ("secondary", os.environ.get("GITHUB_TOKEN_SECONDARY", "").strip()),
        ("tertiary", os.environ.get("GITHUB_TOKEN_TERTIARY", "").strip()),
    ]
    async with httpx.AsyncClient() as client:
        for label, token in tokens_to_check:
            if not token:
                results.append(f"• **{label.capitalize()} Token**: Not configured.")
                continue
            try:
                resp = await client.get(f"{GITHUB_API}/user", headers=_gh_headers(token), timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    login = data.get("login", "unknown")
                    name = data.get("name") or login
                    scopes = resp.headers.get("X-OAuth-Scopes", "unknown")
                    results.append(f"• **{label.capitalize()} Token**: ✅ Active (User: `{login}` / {name}, scopes: {scopes})")
                else:
                    results.append(f"• **{label.capitalize()} Token**: ❌ Invalid/Expired (HTTP {resp.status_code})")
            except Exception as e:
                results.append(f"• **{label.capitalize()} Token**: ⚠️ Error ({type(e).__name__})")
    return "\n".join(results)


# ---------------------------------------------------------------------------
# 2. codespace_manage  (was: list/create/start/stop/rebuild/set_machine_type)
# ---------------------------------------------------------------------------
@mcp.tool()
async def codespace_manage(
    action: str,
    codespace_name: str = "",
    repo_full_name: str = "",
    branch: str = "main",
    machine_type: str = "",
    account: str = "auto",
) -> str:
    """
    Manage GitHub Codespaces lifecycle.
    action: list | create | start | stop | rebuild | set_machine
      list        — show all codespaces (name, repo, state, machine)
      create      — requires repo_full_name; optional branch, machine_type
      start       — requires codespace_name; polls until Available
      stop        — requires codespace_name
      rebuild     — requires codespace_name
      set_machine — requires codespace_name + machine_type (e.g. standardLinux32Gb)
    """
    if action == "list":
        data = await _gh_request_with_fallback("GET", "/user/codespaces", account=account)
        lines = []
        for cs in data.get("codespaces", []):
            lines.append(
                f"- {cs['name']} | {cs['repository']['full_name']} | "
                f"{cs['state']} | {cs['machine']['display_name']}"
            )
        return "\n".join(lines) if lines else "No codespaces found."

    elif action == "create":
        if not repo_full_name:
            return "Error: repo_full_name required for action=create"
        body: dict = {"ref": branch}
        if machine_type:
            body["machine"] = machine_type
        data = await _gh_request_with_fallback(
            "POST", f"/repos/{repo_full_name}/codespaces", json_body=body, account=account
        )
        return f"Created '{data.get('name')}' (state: {data.get('state')})"

    elif action == "start":
        if not codespace_name:
            return "Error: codespace_name required for action=start"
        try:
            data = await _gh_request_with_fallback(
                "POST", f"/user/codespaces/{codespace_name}/start", account=account
            )
            state = data.get("state", "starting")
        except Exception as e:
            return f"Failed to start '{codespace_name}': {e}"
        if state in ("Available", "Running"):
            return f"'{codespace_name}' is already running."
        for _ in range(15):
            await asyncio.sleep(2)
            try:
                info = await _gh_request_with_fallback(
                    "GET", f"/user/codespaces/{codespace_name}", account=account
                )
                if info.get("state", "") in ("Available", "Running"):
                    return f"'{codespace_name}' started and is now Available."
            except Exception:
                pass
        return f"Start requested for '{codespace_name}'. Last state: {state}."

    elif action == "stop":
        if not codespace_name:
            return "Error: codespace_name required for action=stop"
        await _gh_request_with_fallback(
            "POST", f"/user/codespaces/{codespace_name}/stop", account=account
        )
        return f"Stop requested for '{codespace_name}'."

    elif action == "rebuild":
        if not codespace_name:
            return "Error: codespace_name required for action=rebuild"
        data = await _gh_request_with_fallback(
            "POST", f"/user/codespaces/{codespace_name}/rebuild", account=account
        )
        return f"Rebuild initiated for '{codespace_name}'. State: {data.get('state', 'queued')}"

    elif action == "set_machine":
        if not codespace_name or not machine_type:
            return "Error: codespace_name and machine_type required for action=set_machine"
        await _gh_request_with_fallback(
            "PATCH", f"/user/codespaces/{codespace_name}",
            json_body={"machine": machine_type}, account=account,
        )
        return f"Machine updated to '{machine_type}' for '{codespace_name}'."

    else:
        return f"Unknown action '{action}'. Valid: list, create, start, stop, rebuild, set_machine"



# ---------------------------------------------------------------------------
# 4. codespace_files  (was: read_codespace_file + write_codespace_file + list_workspace_files)
# ---------------------------------------------------------------------------
@mcp.tool()
async def codespace_files(
    action: str,
    codespace_name: str = "",
    file_path: str = "",
    content: str = "",
    account: str = "auto",
) -> str:
    """
    Read, write, or list files inside a GitHub Codespace.
    action: read | write | list
      read  — requires codespace_name + file_path
      write — requires codespace_name + file_path + content
      list  — requires codespace_name; file_path is optional directory (default '.')
    """
    if action == "read":
        if not codespace_name or not file_path:
            return "Error: codespace_name and file_path required"
        result = await _cs_exec(codespace_name, f"cat {_q(file_path)}", account=account)
        return result

    elif action == "write":
        if not codespace_name or not file_path or content is None:
            return "Error: codespace_name, file_path and content required"
        encoded = base64.b64encode(content.encode()).decode()
        cmd = f"echo {encoded} | base64 -d > {_q(file_path)} && echo 'Written OK'"
        return await _cs_exec(codespace_name, cmd, account=account)

    elif action == "list":
        if not codespace_name:
            return "Error: codespace_name required"
        path = file_path or "."
        cmd = f"find {_q(path)} -maxdepth 2 -printf '%M %s\\t%p\\n' 2>/dev/null | head -100"
        return await _cs_exec(codespace_name, cmd, account=account)

    else:
        return f"Unknown action '{action}'. Valid: read, write, list"


# ---------------------------------------------------------------------------
# 5. codespace_git  (was: get_git_status + create_git_commit_and_push + list_forwarded_ports)
# ---------------------------------------------------------------------------
@mcp.tool()
async def codespace_git(
    action: str,
    codespace_name: str = "",
    commit_message: str = "",
    branch: str = "",
    repo_path: str = ".",
    account: str = "auto",
) -> str:
    """
    Git and port operations inside a GitHub Codespace.
    action: status | commit | ports
      status — show git status + branch (requires codespace_name)
      commit — stage all, commit, push (requires codespace_name + commit_message)
      ports  — list forwarded ports / dev server URLs (requires codespace_name)
    """
    if action == "status":
        if not codespace_name:
            return "Error: codespace_name required"
        cmd = f"cd {_q(repo_path)} && git status --short && echo '---' && git branch --show-current"
        return await _cs_exec(codespace_name, cmd, account=account)

    elif action == "commit":
        if not codespace_name or not commit_message:
            return "Error: codespace_name and commit_message required"
        branch_arg = f"&& git push origin {_q(branch)}" if branch else "&& git push"
        cmd = (
            f"cd {_q(repo_path)} && git add -A "
            f"&& git commit -m {_q(commit_message)} "
            f"{branch_arg} 2>&1"
        )
        return await _cs_exec(codespace_name, cmd, account=account)

    elif action == "ports":
        if not codespace_name:
            return "Error: codespace_name required"
        data = await _gh_request_with_fallback(
            "GET", f"/user/codespaces/{codespace_name}/ports", account=account
        )
        ports = data.get("ports", [])
        if not ports:
            return "No forwarded ports."
        lines = []
        for p in ports:
            lines.append(
                f"- Port {p.get('port_number')}: {p.get('label','?')} | "
                f"{p.get('visibility','?')} | {p.get('browser_url','no URL')}"
            )
        return "\n".join(lines)

    else:
        return f"Unknown action '{action}'. Valid: status, commit, ports"


# ---------------------------------------------------------------------------
# 6. server_info  (was: server_status + server_network_info + server_docker_status + server_cron_list)
# ---------------------------------------------------------------------------
@mcp.tool()
async def server_info(
    section: str = "all",
    disk_detail: bool = False,
    disk_path: str = "/",
    processes: bool = False,
) -> str:
    """
    Get an overview of the home Linux server.
    section: all | status | network | docker | cron  (default: all)
      status  — disk + RAM; disk_detail=True adds du breakdown; processes=True adds top procs
      network — interfaces, open ports, active connections
      docker  — Docker container list and status
      cron    — all cron jobs (user + root)
    """
    parts = []

    if section in ("all", "status"):
        cmd = "df -h / 2>/dev/null && echo '---' && free -h | grep Mem"
        if processes:
            cmd += " && echo '---' && ps aux --sort=-%cpu | head -10"
        result = await _ssh_server(cmd)
        if disk_detail:
            du = await _ssh_server(
                f"du -h --max-depth=2 {_q(disk_path)} 2>/dev/null | sort -rh | head -30"
            )
            result += f"\n\nDisk breakdown ({disk_path}):\n{du}"
        parts.append(f"**Status:**\n{result}")

    if section in ("all", "network"):
        result = await _ssh_server(
            "ip -br addr && echo '---' && ss -tlnp 2>/dev/null | head -20"
        )
        parts.append(f"**Network:**\n{result}")

    if section in ("all", "docker"):
        result = await _ssh_server(
            "docker ps -a 2>/dev/null || echo 'Docker not running or not installed'"
        )
        parts.append(f"**Docker:**\n{result}")

    if section in ("all", "cron"):
        result = await _ssh_server(
            "crontab -l 2>/dev/null || true ; sudo -n crontab -l -u root 2>/dev/null || true"
        )
        parts.append(f"**Cron:**\n{result}")

    if not parts:
        return f"Unknown section '{section}'. Use: all, status, network, docker, cron"
    return "\n\n".join(parts)




# ---------------------------------------------------------------------------
# 8. server_files  (was: server_list_files + server_read_file + server_write_file
#                        + server_move_file + server_delete_file + server_find_duplicates)
# ---------------------------------------------------------------------------
@mcp.tool()
async def server_files(
    action: str,
    path: str = "",
    destination: str = "",
    content: str = "",
    recursive: bool = False,
    tail: int = 0,
    head: int = 0,
) -> str:
    """
    Manage files on the home Linux server.
    action: list | read | write | move | delete | duplicates
      list       — list files at path; recursive=True walks subdirs (depth 3)
      read       — read file; tail=N last N lines, head=N first N lines
      write      — write content to path (overwrites)
      move       — move/rename path to destination
      delete     — delete file at path
      duplicates — scan folder for duplicate files by content hash
    """
    if not path:
        return "Error: path is required for all actions"

    if action == "list":
        depth = "" if not recursive else " -maxdepth 3"
        cmd = f"find {_q(path)}{depth} -printf '%M %s\\t%p\\n' 2>/dev/null | head -200"
        return await _ssh_server(cmd)

    elif action == "read":
        if tail:
            return await _ssh_server(f"tail -n {tail} {_q(path)}")
        elif head:
            return await _ssh_server(f"head -n {head} {_q(path)}")
        else:
            return await _ssh_server(f"cat {_q(path)} 2>/dev/null | head -300")

    elif action == "write":
        if content is None:
            return "Error: content is required for action=write"
        encoded = base64.b64encode(content.encode()).decode()
        cmd = f"echo {encoded} | base64 -d | sudo -n tee {_q(path)} > /dev/null && echo 'Written OK'"
        return await _ssh_server(cmd)

    elif action == "move":
        if not destination:
            return "Error: destination is required for action=move"
        return await _ssh_server(f"sudo -n mv {_q(path)} {_q(destination)} && echo 'Moved OK'")

    elif action == "delete":
        return await _ssh_server(f"sudo -n rm {_q(path)} && echo 'Deleted OK'")

    elif action == "duplicates":
        cmd = (
            f"find {_q(path)} -type f -print0 2>/dev/null | "
            "xargs -0 md5sum 2>/dev/null | sort | uniq -w32 -D"
        )
        result = await _ssh_server(cmd)
        return result or "No duplicates found."

    else:
        return f"Unknown action '{action}'. Valid: list, read, write, move, delete, duplicates"


# ---------------------------------------------------------------------------
# 9. server_service  (was: server_service_control + server_tail_log)
# ---------------------------------------------------------------------------
@mcp.tool()
async def server_service(
    action: str,
    service: str = "",
    log_path: str = "/var/log/syslog",
    lines: int = 50,
) -> str:
    """
    Control systemd services and read logs on the home Linux server.
    action: start | stop | restart | status | enable | disable | logs
      start/stop/restart/enable/disable — requires service name
      status — full systemctl status for service
      logs   — tail log_path (default /var/log/syslog); lines=N controls count
    """
    if action in ("start", "stop", "restart", "enable", "disable"):
        if not service:
            return f"Error: service name required for action={action}"
        return await _ssh_server(
            f"sudo -n systemctl {action} {_q(service)} && echo '{action} OK'"
        )
    elif action == "status":
        if not service:
            return "Error: service name required for action=status"
        return await _ssh_server(
            f"sudo -n systemctl status {_q(service)} --no-pager -l 2>&1"
        )
    elif action == "logs":
        return await _ssh_server(f"sudo -n tail -n {lines} {_q(log_path)} 2>&1")
    else:
        return f"Unknown action '{action}'. Valid: start, stop, restart, status, enable, disable, logs"


# ---------------------------------------------------------------------------
# 10. pc_info  (was: pc_list + pc_list_configured + pc_organiser_status)
# ---------------------------------------------------------------------------
@mcp.tool()
async def pc_info(
    action: str = "list",
    pc: str = "default",
    include_offline: bool = False,
) -> str:
    """
    Get info about connected Windows PCs via the organiser-agent.
    action: list | configured | status
      list       — auto-discovered online PCs (include_offline=True to see offline too)
      configured — all PCs in the registry with live reachability status
      status     — check organiser-agent health on a specific pc (default: 'default')
    """
    if action == "list":
        pcs = await _pc_list(include_offline=include_offline)
        if not pcs:
            return "No PCs discovered."
        lines = []
        for p in pcs:
            status = "🟢 online" if p.get("online") else "🔴 offline"
            lines.append(f"- {p.get('name','?')} | {status} | {p.get('ip','?')}")
        return "\n".join(lines)

    elif action == "configured":
        pcs = await _pc_list_configured()
        if not pcs:
            return "No PCs configured."
        lines = []
        for p in pcs:
            reachable = "✅" if p.get("reachable") else "❌"
            lines.append(
                f"- {p.get('name','?')} {reachable} | "
                f"v{p.get('version','?')} | {p.get('platform','?')} | {p.get('ip','?')}"
            )
        return "\n".join(lines)

    elif action == "status":
        result = await _pc_organiser_status(pc=pc)
        return result

    else:
        return f"Unknown action '{action}'. Valid: list, configured, status"


# ---------------------------------------------------------------------------
# 11. pc_files  (was: pc_list_files + pc_move_file + pc_delete_file
#                     + pc_read_file_preview + pc_disk_usage + pc_find_duplicates)
# ---------------------------------------------------------------------------
@mcp.tool()
async def pc_files(
    action: str,
    path: str = "",
    destination: str = "",
    pc: str = "default",
    recursive: bool = False,
    max_bytes: int = 4096,
) -> str:
    """
    Manage files on a Windows PC via organiser-agent.
    action: list | read | move | delete | disk | duplicates
      list       — list files/folders at path (recursive=True for subdirs)
      read       — read first max_bytes of a text file at path
      move       — move/rename path to destination
      delete     — send file to Recycle Bin (safe)
      disk       — disk usage breakdown for folder at path, sorted largest-first
      duplicates — find duplicate files by content hash under path
    """
    if not path and action not in ("disk",):
        return "Error: path is required"

    if action == "list":
        return await _pc_list_files(folder=path, pc=pc, recursive=recursive)
    elif action == "read":
        return await _pc_read_file_preview(path=path, pc=pc, max_bytes=max_bytes)
    elif action == "move":
        if not destination:
            return "Error: destination required for action=move"
        return await _pc_move_file(source=path, destination=destination, pc=pc)
    elif action == "delete":
        return await _pc_delete_file(path=path, pc=pc, permanent=False)
    elif action == "disk":
        folder = path or "C:\\"
        return await _pc_disk_usage(folder=folder, pc=pc)
    elif action == "duplicates":
        return await _pc_find_duplicates(folder=path, pc=pc)
    else:
        return f"Unknown action '{action}'. Valid: list, read, move, delete, disk, duplicates"



# ---------------------------------------------------------------------------
# 13. pc_screenshot  (was: pc__screenshot — renamed, kept separate for clarity)
# ---------------------------------------------------------------------------
@mcp.tool()
async def pc_screenshot(
    pc: str = "default",
    save_path: str = "",
) -> str:
    """
    Capture a screenshot of a PC's screen.
    Returns base64-encoded image data for viewing/analysis.
    save_path — optional path on the PC to also save the file.
    """
    return await _pc__screenshot(pc=pc, save_path=save_path)


@mcp.tool()
async def file_transfer(source: str, destination: str) -> str:
    """
    Move a file between any two endpoints -- this sandbox, a PC, the Linux
    server, or a GitHub Codespace -- in any direction/combination (pc to
    server, codespace to codespace, pc to pc via the hub, etc).

    Address format: "<kind>:<path>" for sandbox/server, "<kind>:<name>:<path>"
    for pc/codespace (codespace also accepts "<name>@<account>:<path>").
    See the comment above this tool in server.py for full examples.

    Binary-safe (images, zips, executables) for every pair, including a
    PC as either endpoint, via organiser-agent's base64 file API.

    Capped at 15 MB per transfer.
    """
    try:
        data = await _location_read_bytes(source)
    except ValueError as e:
        return f"Read failed: {e}"
    except Exception as e:
        return f"Read failed ({type(e).__name__}): {e}"

    try:
        result = await _location_write_bytes(destination, data)
    except ValueError as e:
        return f"Write failed: {e}"
    except Exception as e:
        return f"Write failed ({type(e).__name__}): {e}"

    return f"Transferred {source} -> {result}"


# ---------------------------------------------------------------------------
# Diagnostics — test every configured subsystem
# ---------------------------------------------------------------------------


async def _run_diagnostics() -> dict:
    """
    Runs a lightweight health check for every subsystem this server can
    talk to, and returns a structured report. Backs both the
    run_diagnostics MCP tool and the admin dashboard's "Run All Tests".
    """
    checks = []

    async def _check(name: str, coro):
        try:
            detail = await coro
            checks.append({"name": name, "status": "pass", "detail": detail})
        except Exception as e:
            checks.append({"name": name, "status": "fail", "detail": str(e)})

    # GitHub tokens
    for label, env_name in [
        ("GitHub primary", "GITHUB_TOKEN"),
        ("GitHub secondary", "GITHUB_TOKEN_SECONDARY"),
        ("GitHub tertiary", "GITHUB_TOKEN_TERTIARY"),
    ]:
        token = os.environ.get(env_name, "").strip()
        if not token:
            checks.append({"name": label, "status": "skip", "detail": "not configured"})
            continue

        async def _do(tok=token):
            async with httpx.AsyncClient() as client:
                r = await client.get(
                    f"{GITHUB_API}/user", headers=_gh_headers(tok), timeout=10
                )
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            return f"authenticated as {r.json().get('login', '?')}"

        await _check(label, _do())

    # Codespaces API
    async def _codespaces():
        data = await _gh_request_with_fallback("GET", "/user/codespaces")
        return f"{len(data.get('codespaces', []))} codespace(s) visible"

    await _check("Codespaces API", _codespaces())

    # Linux server
    async def _server():
        out = await _ssh_server("echo alive", timeout=15)
        if "alive" not in out:
            raise RuntimeError(out[:200] or "no response")
        return f"{SERVER_USER}@{SERVER_HOST} reachable"

    await _check("Linux server", _server())

    # Each configured PC
    for pc_name in sorted(_PC_REGISTRY.keys()):

        async def _pc(name=pc_name):
            data = await _org_get("/status", pc=name)
            return f"{data.get('platform', '?')} v{data.get('version', '?')}"

        await _check(f"PC '{pc_name}'", _pc())

    # Render API (needed for the admin settings panel)
    if RENDER_API_KEY and RENDER_SERVICE_ID:

        async def _render():
            async with httpx.AsyncClient() as client:
                r = await client.get(
                    f"{RENDER_API}/services/{RENDER_SERVICE_ID}",
                    headers=_render_headers(),
                    timeout=10,
                )
            r.raise_for_status()
            return r.json().get("name", "?")

        await _check("Render API", _render())
    else:
        checks.append(
            {
                "name": "Render API",
                "status": "skip",
                "detail": "RENDER_API_KEY/RENDER_SERVICE_ID not configured",
            }
        )

    passed = sum(1 for c in checks if c["status"] == "pass")
    failed = sum(1 for c in checks if c["status"] == "fail")
    skipped = sum(1 for c in checks if c["status"] == "skip")
    return {
        "checks": checks,
        "summary": f"{passed} passed, {failed} failed, {skipped} skipped",
    }


@mcp.tool()
async def run_diagnostics() -> str:
    """
    Test every configured subsystem (GitHub tokens, Codespaces API,
    Linux server, each configured PC's organiser-agent, Render API) and
    report pass/fail/skip for each. Use this to verify the whole stack
    after making config changes.
    """
    report = await _run_diagnostics()
    icon = {"pass": "✅", "fail": "❌", "skip": "⏭️"}
    lines = [f"**Diagnostics — {report['summary']}**\n"]
    for c in report["checks"]:
        lines.append(f"{icon.get(c['status'], '?')} {c['name']}: {c['detail']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Admin Dashboard — configure everything from a browser
# ---------------------------------------------------------------------------
#
# Separate cookie-based login (NOT the MCP bearer-token auth above, since
# a plain browser navigation can't set an Authorization header). Gated by
# ADMIN_PASSWORD (falls back to MCP_SERVER_PASSWORD if unset). The cookie
# is a stateless HMAC-signed "<expiry>.<signature>" pair — no session
# store needed for a single-admin personal dashboard.

ADMIN_PASSWORD = (
    os.environ.get("ADMIN_PASSWORD", "").strip()
    or os.environ.get("MCP_SERVER_PASSWORD", "").strip()
)

# SECURITY: no hardcoded fallback secret. A static in-source string here
# would let anyone who has read this file forge a valid admin cookie
# (compute hmac(known_secret, expiry)) even though the login *form* is
# disabled when ADMIN_PASSWORD is unset -- verification must be gated
# the same way login is, or "disabled login" is theater.
#
# If no real secret is configured, generate one per-process instead. It
# won't validate any cookie forged against a guessable string, and it
# won't survive a restart (which is fine -- with no real secret configured
# there should be no durable admin session anyway).
_ADMIN_COOKIE_SECRET = (
    os.environ.get("ADMIN_COOKIE_SECRET", "").strip()
    or ADMIN_PASSWORD
    or secrets.token_hex(32)
)
_ADMIN_AUTH_CONFIGURED = bool(
    os.environ.get("ADMIN_COOKIE_SECRET", "").strip() or ADMIN_PASSWORD
)
_ADMIN_SESSION_TTL = 60 * 60 * 12  # 12 hours
_ADMIN_COOKIE_NAME = "admin_session"


def _render_headers() -> dict:
    return {
        "Authorization": f"Bearer {RENDER_API_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _admin_sign(payload: str) -> str:
    return hmac.new(
        _ADMIN_COOKIE_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()


def _admin_make_cookie() -> str:
    expiry = str(int(time.time()) + _ADMIN_SESSION_TTL)
    return f"{expiry}.{_admin_sign(expiry)}"


def _admin_cookie_valid(cookie_value: str | None) -> bool:
    if not _ADMIN_AUTH_CONFIGURED:
        return False
    if not cookie_value or "." not in cookie_value:
        return False
    expiry_s, sig = cookie_value.split(".", 1)
    try:
        if time.time() > int(expiry_s):
            return False
    except ValueError:
        return False
    return hmac.compare_digest(sig, _admin_sign(expiry_s))


def _admin_authed(request: Request) -> bool:
    return _admin_cookie_valid(request.cookies.get(_ADMIN_COOKIE_NAME))


_ADMIN_PAGE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>codespaces-mcp admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: dark; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #0d1117; color: #e6edf3;
         max-width: 900px; margin: 0 auto; padding: 24px 16px; line-height: 1.5; }
  h1 { font-size: 1.3rem; }
  h2 { font-size: 1.05rem; border-bottom: 1px solid #30363d; padding-bottom: 6px; margin-top: 2rem; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  input, textarea, button, select { font-family: inherit; font-size: 0.9rem; }
  input[type=text], input[type=password] { background: #0d1117; border: 1px solid #30363d; color: #e6edf3;
         border-radius: 6px; padding: 8px 10px; width: 100%; box-sizing: border-box; }
  button { background: #238636; border: none; color: white; border-radius: 6px; padding: 8px 14px;
         cursor: pointer; margin-top: 8px; }
  button:hover { background: #2ea043; }
  button.secondary { background: #30363d; }
  button.secondary:hover { background: #3f4652; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  td, th { text-align: left; padding: 6px 8px; border-bottom: 1px solid #21262d; }
  .pass { color: #3fb950; } .fail { color: #f85149; } .skip { color: #8b949e; }
  pre { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 10px;
        overflow-x: auto; white-space: pre-wrap; word-break: break-word; font-size: 0.82rem; }
  .row { display: flex; gap: 8px; }
  .row > * { flex: 1; }
  .muted { color: #8b949e; font-size: 0.85rem; }
</style>
</head>
<body>
__BODY__
</body>
</html>
"""

_ADMIN_LOGIN_BODY = """
<h1>codespaces-mcp admin</h1>
<div class="card">
  <form method="POST" action="/admin/login">
    <label class="muted">Admin password</label>
    <input type="password" name="password" autofocus>
    <button type="submit">Log in</button>
  </form>
  __ERROR__
</div>
"""

_ADMIN_DASHBOARD_BODY = """
<h1>codespaces-mcp admin</h1>
<p class="muted">Signed in. <a href="/admin/logout" style="color:#58a6ff;">Log out</a></p>

<h2>Render settings</h2>
<div class="card">
  <p class="muted">Service: <code>__SERVICE_ID__</code></p>
  <div id="env-table">Loading…</div>
  <div class="row" style="margin-top:12px;">
    <input type="text" id="env-key" placeholder="KEY (e.g. MCP_SERVER_PASSWORD)">
    <input type="text" id="env-value" placeholder="value">
  </div>
  <button onclick="setEnvVar()">Save variable</button>
  <button class="secondary" onclick="triggerDeploy()">Trigger redeploy</button>
  <pre id="env-result"></pre>
</div>

<h2>Linux server</h2>
<div class="card">
  <input type="text" id="server-cmd" placeholder="command to run on stoni-room-serve">
  <button onclick="runServerCmd()">Run</button>
  <pre id="server-result"></pre>
</div>

<h2>Diagnostics</h2>
<div class="card">
  <button onclick="runDiagnostics()">Run all tests</button>
  <div id="diag-result"></div>
</div>

<script>
function esc(s) {
  const d = document.createElement("div");
  d.innerText = String(s ?? "");
  return d.innerHTML;
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (r.status === 401) { window.location = "/admin"; return null; }
  return r.json();
}

async function loadEnv() {
  const data = await api("/admin/api/env");
  if (!data) return;
  if (data.error) { document.getElementById("env-table").innerText = data.error; return; }
  let rows = data.vars.map(v =>
    `<tr><td>${esc(v.key)}</td><td>${esc(v.value)}</td></tr>`
  ).join("");
  document.getElementById("env-table").innerHTML =
    `<table><tr><th>Key</th><th>Value</th></tr>${rows}</table>`;
}

async function setEnvVar() {
  const key = document.getElementById("env-key").value.trim();
  const value = document.getElementById("env-value").value;
  if (!key) return;
  const data = await api("/admin/api/env", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({key, value})
  });
  document.getElementById("env-result").innerText = JSON.stringify(data, null, 2);
  loadEnv();
}

async function triggerDeploy() {
  const data = await api("/admin/api/deploy", {method: "POST"});
  document.getElementById("env-result").innerText = JSON.stringify(data, null, 2);
}

async function runServerCmd() {
  const command = document.getElementById("server-cmd").value;
  const data = await api("/admin/api/server/run", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({command})
  });
  document.getElementById("server-result").innerText = data.output ?? JSON.stringify(data, null, 2);
}

async function runDiagnostics() {
  document.getElementById("diag-result").innerText = "Running…";
  const data = await api("/admin/api/diagnostics");
  if (!data) return;
  let rows = data.checks.map(c =>
    `<tr><td class="${esc(c.status)}">${esc(c.status)}</td><td>${esc(c.name)}</td><td>${esc(c.detail)}</td></tr>`
  ).join("");
  document.getElementById("diag-result").innerHTML =
    `<p class="muted">${esc(data.summary)}</p><table><tr><th>Status</th><th>Check</th><th>Detail</th></tr>${rows}</table>`;
}

loadEnv();
</script>
"""


async def _admin_page(request: Request) -> HTMLResponse:
    if not _admin_authed(request):
        body = _ADMIN_LOGIN_BODY.replace("__ERROR__", "")
        return HTMLResponse(_ADMIN_PAGE_TEMPLATE.replace("__BODY__", body))
    body = _ADMIN_DASHBOARD_BODY.replace(
        "__SERVICE_ID__", _html.escape(RENDER_SERVICE_ID)
    )
    return HTMLResponse(_ADMIN_PAGE_TEMPLATE.replace("__BODY__", body))


_ADMIN_LOGIN_ATTEMPTS: dict[str, list[float]] = {}


async def _admin_login(request: Request) -> RedirectResponse | HTMLResponse:
    form = await request.form()
    password = str(form.get("password", ""))
    client_ip = request.client.host if request.client else "unknown"

    # Rate limiting: max 5 failed attempts per IP within 60s
    now = time.time()
    attempts = [t for t in _ADMIN_LOGIN_ATTEMPTS.get(client_ip, []) if now - t < 60]
    _ADMIN_LOGIN_ATTEMPTS[client_ip] = attempts
    if len(attempts) >= 5:
        body = _ADMIN_LOGIN_BODY.replace(
            "__ERROR__",
            "<p style='color:#f85149'>Too many failed login attempts. Please wait 1 minute.</p>",
        )
        return HTMLResponse(
            _ADMIN_PAGE_TEMPLATE.replace("__BODY__", body), status_code=429
        )

    if not ADMIN_PASSWORD:
        body = _ADMIN_LOGIN_BODY.replace(
            "__ERROR__",
            "<p style='color:#f85149'>ADMIN_PASSWORD is not set — admin login is disabled.</p>",
        )
        return HTMLResponse(
            _ADMIN_PAGE_TEMPLATE.replace("__BODY__", body), status_code=503
        )
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        _ADMIN_LOGIN_ATTEMPTS.setdefault(client_ip, []).append(now)
        body = _ADMIN_LOGIN_BODY.replace(
            "__ERROR__", "<p style='color:#f85149'>Wrong password.</p>"
        )
        return HTMLResponse(
            _ADMIN_PAGE_TEMPLATE.replace("__BODY__", body), status_code=401
        )
    _ADMIN_LOGIN_ATTEMPTS.pop(client_ip, None)
    resp = RedirectResponse(url="/admin", status_code=303)
    resp.set_cookie(
        _ADMIN_COOKIE_NAME,
        _admin_make_cookie(),
        max_age=_ADMIN_SESSION_TTL,
        httponly=True,
        samesite="lax",
        secure=True,
        # secure=True: Render/Fly serve HTTPS exclusively in practice, so this
        # closes the "cookie sent over a mis-typed http:// URL" hole with zero
        # downside (external review A9, confirmed and fixed).
    )
    return resp


async def _admin_logout(request: Request) -> RedirectResponse:
    resp = RedirectResponse(url="/admin", status_code=303)
    resp.delete_cookie(_ADMIN_COOKIE_NAME)
    return resp


def _require_admin(request: Request) -> JSONResponse | None:
    if not _admin_authed(request):
        return JSONResponse({"error": "Not authenticated."}, status_code=401)
    return None


def _mask_secret_value(value: str) -> str:
    """Mask an env var value for display: keep the last 4 characters
    visible (enough to confirm 'is this the value I think it is' /
    detect a stale value without exposing anything usable), mask the
    rest. Values of 4 chars or fewer are fully masked.

    SECURITY: this endpoint used to return every env var's value in
    full plaintext -- GITHUB_TOKEN, MCP_SERVER_PASSWORD, SSH_PRIVATE_KEY,
    RENDER_API_KEY, everything -- to any authenticated admin session.
    That turns any admin-cookie leak (XSS, a shared screen, a browser
    extension, a screenshot) into a full credential compromise instead
    of just dashboard access. Confirmed by external review, verified
    against the actual code, fixed here rather than re-filed as a
    duplicate finding. There is deliberately no "reveal full value"
    endpoint added alongside this -- if a real value is genuinely
    needed, get it from Render's own dashboard, which has its own
    audit trail for that action.
    """
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


FLY_API = "https://api.fly.io/graphql"
FLY_API_TOKEN = os.environ.get("FLY_API_TOKEN", "").strip()
FLY_APP_NAME = os.environ.get("FLY_APP_NAME", "server-mcp-gemini").strip()


def _fly_headers() -> dict:
    return {
        "Authorization": f"Bearer {FLY_API_TOKEN}",
        "Content-Type": "application/json",
    }


async def _admin_api_env_get(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied

    # 1. Fly.io API support
    if FLY_API_TOKEN and FLY_APP_NAME:
        query = """
        query($appName: String!) {
          app(name: $appName) {
            secrets {
              name
              digest
            }
          }
        }
        """
        try:
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    FLY_API,
                    headers=_fly_headers(),
                    json={"query": query, "variables": {"appName": FLY_APP_NAME}},
                    timeout=15,
                )
            r.raise_for_status()
            data = r.json()
            secrets_list = data.get("data", {}).get("app", {}).get("secrets", [])
            env_vars = [{"key": s["name"], "value": "********"} for s in secrets_list]
            env_vars.sort(key=lambda v: v["key"])
            return JSONResponse({"vars": env_vars, "platform": "fly.io"})
        except httpx.HTTPError as e:
            return JSONResponse({"error": f"Fly.io API error: {e}"}, status_code=502)

    # 2. Render API fallback
    if RENDER_API_KEY and RENDER_SERVICE_ID:
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(
                    f"{RENDER_API}/services/{RENDER_SERVICE_ID}/env-vars",
                    headers=_render_headers(),
                    timeout=15,
                )
            r.raise_for_status()
            items = r.json()
            env_vars = [
                {
                    "key": i["envVar"]["key"],
                    "value": _mask_secret_value(i["envVar"]["value"]),
                }
                for i in items
            ]
            env_vars.sort(key=lambda v: v["key"])
            return JSONResponse({"vars": env_vars, "platform": "render"})
        except httpx.HTTPError as e:
            return JSONResponse({"error": f"Render API error: {e}"}, status_code=502)

    return JSONResponse(
        {
            "error": "Neither FLY_API_TOKEN nor RENDER_API_KEY is configured on this deployment."
        }
    )


async def _admin_api_env_set(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied

    body = await request.json()
    key = str(body.get("key", "")).strip()
    value = str(body.get("value", ""))
    if not key:
        return JSONResponse({"error": "Missing 'key'."}, status_code=400)

    # 1. Fly.io API support
    if FLY_API_TOKEN and FLY_APP_NAME:
        mutation = """
        mutation($appId: String!, $secrets: [SecretInput!]!) {
          setSecrets(input: {appId: $appId, secrets: $secrets}) {
            app {
              name
            }
          }
        }
        """
        try:
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    FLY_API,
                    headers=_fly_headers(),
                    json={
                        "query": mutation,
                        "variables": {
                            "appId": FLY_APP_NAME,
                            "secrets": [{"key": key, "value": value}],
                        },
                    },
                    timeout=15,
                )
            r.raise_for_status()
            return JSONResponse(
                {
                    "ok": True,
                    "note": f"Saved secret '{key}' to Fly.io app '{FLY_APP_NAME}'.",
                }
            )
        except httpx.HTTPError as e:
            return JSONResponse({"error": f"Fly.io API error: {e}"}, status_code=502)

    # 2. Render API fallback
    if RENDER_API_KEY and RENDER_SERVICE_ID:
        try:
            async with httpx.AsyncClient() as client:
                r = await client.put(
                    f"{RENDER_API}/services/{RENDER_SERVICE_ID}/env-vars/{key}",
                    headers=_render_headers(),
                    json={"value": value},
                    timeout=15,
                )
            r.raise_for_status()
            return JSONResponse(
                {
                    "ok": True,
                    "note": "Saved. Click 'Trigger redeploy' for it to take effect.",
                }
            )
        except httpx.HTTPError as e:
            return JSONResponse({"error": f"Render API error: {e}"}, status_code=502)

    return JSONResponse(
        {
            "error": "Neither FLY_API_TOKEN nor RENDER_API_KEY is configured on this deployment."
        },
        status_code=400,
    )


async def _admin_api_deploy(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied

    # 1. Fly.io API support
    if FLY_API_TOKEN and FLY_APP_NAME:
        mutation = """
        mutation($appId: String!) {
          restartApp(input: {appId: $appId}) {
            app {
              name
            }
          }
        }
        """
        try:
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    FLY_API,
                    headers=_fly_headers(),
                    json={"query": mutation, "variables": {"appId": FLY_APP_NAME}},
                    timeout=15,
                )
            r.raise_for_status()
            return JSONResponse(
                {
                    "ok": True,
                    "deploy": r.json(),
                    "note": f"Restart triggered for Fly app '{FLY_APP_NAME}'.",
                }
            )
        except httpx.HTTPError as e:
            return JSONResponse({"error": f"Fly.io API error: {e}"}, status_code=502)

    # 2. Render API fallback
    if RENDER_API_KEY and RENDER_SERVICE_ID:
        try:
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    f"{RENDER_API}/services/{RENDER_SERVICE_ID}/deploys",
                    headers=_render_headers(),
                    json={"clearCache": "do_not_clear"},
                    timeout=15,
                )
            r.raise_for_status()
            return JSONResponse({"ok": True, "deploy": r.json()})
        except httpx.HTTPError as e:
            return JSONResponse({"error": f"Render API error: {e}"}, status_code=502)

    return JSONResponse(
        {
            "error": "Neither FLY_API_TOKEN nor RENDER_API_KEY is configured on this deployment."
        },
        status_code=400,
    )


async def _admin_api_server_run(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied
    body = await request.json()
    command = str(body.get("command", "")).strip()
    if not command:
        return JSONResponse({"error": "Missing 'command'."}, status_code=400)
    output = await _ssh_server(command, timeout=30)
    return JSONResponse({"output": output})


async def _admin_api_diagnostics(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied
    report = await _run_diagnostics()
    return JSONResponse(report)


async def _admin_api_fleet(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied
    pcs = []
    # Merge static registry and dynamic discovery
    all_names = sorted(
        set(list(_PC_REGISTRY.keys()) + list(_PC_V2_DYNAMIC_REGISTRY.keys()))
    )
    for name in all_names:
        cfg = _PC_REGISTRY.get(name, {})
        dyn = _PC_V2_DYNAMIC_REGISTRY.get(name, {})
        port = cfg.get("port") or dyn.get("port")
        lan_ip = cfg.get("lan_ip") or dyn.get("lan_ip", "127.0.0.1")
        status = "offline"
        details = {}
        try:
            res = await asyncio.wait_for(_org_get("/status", pc=name), timeout=2.0)
            status = "online"
            details = res
        except Exception as e:
            details = {"error": str(e)}
        pcs.append(
            {
                "name": name,
                "port": port,
                "status": status,
                "machine_name": details.get("machine_name", dyn.get("name", name)),
                "machine_id": details.get("machine_id", dyn.get("id", "?")),
                "version": details.get("version", "?"),
                "platform": details.get("platform", "windows"),
                "lan_ip": lan_ip,
                "last_event": dyn.get("event", "unknown"),
            }
        )
    return JSONResponse({"fleet": pcs})


async def _admin_api_pc_screenshot(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied
    body = await request.json()
    pc = body.get("pc", "default")
    try:
        res = await _org_post("/screenshot", body, pc=pc)
        return JSONResponse(res)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def _admin_api_pc_cmd(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied
    body = await request.json()
    pc = body.get("pc", "default")
    cmd = body.get("command", "")
    try:
        res = await _org_post("/run_command", {"command": cmd}, pc=pc)
        return JSONResponse(res)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def _admin_api_pc_disk(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied
    pc = request.query_params.get("pc", "default")
    try:
        res = await _org_get("/disk_usage", pc=pc)
        return JSONResponse(res)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def _admin_api_codespaces(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        return JSONResponse({"codespaces": [], "error": "No GITHUB_TOKEN configured"})
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{GITHUB_API}/user/codespaces",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                },
                timeout=10,
            )
            r.raise_for_status()
            data = r.json()
            return JSONResponse({"codespaces": data.get("codespaces", [])})
    except Exception as e:
        return JSONResponse({"codespaces": [], "error": str(e)})


async def _admin_api_server_overview(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied
    cmd = "uptime; echo '---'; free -h; echo '---'; df -h /; echo '---'; systemctl is-active mcp-hub-monitor pc-tunnel@* 2>&1"
    output = await _ssh_server(cmd, timeout=10)
    return JSONResponse({"output": output})


async def _admin_api_server_service(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied
    body = await request.json()
    service = body.get("service", "")
    action = body.get("action", "status")
    if not service:
        return JSONResponse({"error": "Service required"}, status_code=400)
    cmd = f"sudo systemctl {action} {_q(service)}"
    output = await _ssh_server(cmd, timeout=15)
    return JSONResponse({"output": output, "service": service, "action": action})


async def _admin_api_transfer(request: Request) -> JSONResponse:
    if (denied := _require_admin(request)) is not None:
        return denied
    body = await request.json()
    src = body.get("src")
    dest = body.get("dest")
    if not src or not dest:
        return JSONResponse({"error": "Missing src or dest"}, status_code=400)
    try:
        data = await _location_read_bytes(src)
        result = await _location_write_bytes(dest, data)
        return JSONResponse({"ok": True, "result": result, "bytes": len(data)})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


# ---------------------------------------------------------------------------
# Proposal v2 Event Push Endpoint
# ---------------------------------------------------------------------------

_PC_V2_DYNAMIC_REGISTRY: dict = {}


async def _events_pc_status(request: Request) -> JSONResponse:
    expected_token = os.environ.get("MCP_SERVER_PASSWORD") or ADMIN_PASSWORD
    if expected_token:
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer ") or auth_header[7:] != expected_token:
            return JSONResponse({"error": "Unauthorized"}, status_code=401)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    name = data.get("machine_name") or data.get("machine_id") or "unknown"
    event_status = data.get("event", "online")
    _PC_V2_DYNAMIC_REGISTRY[name] = {
        "id": data.get("machine_id"),
        "name": name,
        "event": event_status,
        "lan_ip": data.get("lan_ip", ""),
        "port": data.get("port", 0),
        "timestamp": data.get("timestamp", ""),
        "last_updated": time.time(),
    }
    if data.get("port") and event_status == "online":
        _PC_REGISTRY[name] = {
            "port": int(data["port"]),
            "secret": data.get("secret", os.environ.get("ORGANISER_SECRET", "")),
            "lan_ip": data.get("lan_ip", "127.0.0.1"),
        }
    return JSONResponse({"status": "received", "pc": name, "event": event_status})


# ---------------------------------------------------------------------------
# OAuth 2.1 Web Authorization Flow Endpoints
# ---------------------------------------------------------------------------


async def _oauth_metadata(request: Request) -> JSONResponse:
    host = _allowed_host or request.headers.get("host", "server-mcp-gemini.fly.dev")
    base_url = f"https://{host}" if not host.startswith("http") else host
    return JSONResponse(
        {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/oauth/authorize",
            "token_endpoint": f"{base_url}/oauth/token",
            "registration_endpoint": f"{base_url}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "scopes_supported": ["mcp"],
        }
    )


async def _oauth_protected_resource(request: Request) -> JSONResponse:
    host = _allowed_host or request.headers.get("host", "server-mcp-gemini.fly.dev")
    base_url = f"https://{host}" if not host.startswith("http") else host
    return JSONResponse(
        {
            "resource": base_url,
            "authorization_servers": [base_url],
            "scopes_supported": ["mcp"],
            "bearer_methods_supported": ["header", "query"],
        }
    )


async def _oauth_register(request: Request) -> JSONResponse:
    try:
        data = await request.json()
    except Exception:
        data = {}
    client_id = f"client_{secrets.token_hex(8)}"
    client_secret = f"secret_{secrets.token_hex(16)}"
    redirect_uris = data.get(
        "redirect_uris", ["https://claude.ai/api/mcp/auth_callback"]
    )
    client_name = data.get("client_name") or data.get("client_name", "Client App")
    _OAUTH_CLIENTS[client_id] = {
        "client_name": client_name,
        "client_secret": client_secret,
        "redirect_uris": redirect_uris,
    }
    return JSONResponse(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
        status_code=201,
    )


async def _oauth_authorize_get(request: Request) -> HTMLResponse:
    params = request.query_params
    client_id = _html.escape(params.get("client_id", ""))
    redirect_uri = _html.escape(
        params.get("redirect_uri", "https://claude.ai/api/mcp/auth_callback")
    )
    state = _html.escape(params.get("state", ""))
    code_challenge = _html.escape(params.get("code_challenge", ""))
    code_challenge_method = _html.escape(params.get("code_challenge_method", "plain"))

    # Dynamically determine client display name
    raw_client_name = params.get("client_name", "")
    if not raw_client_name and client_id in _OAUTH_CLIENTS:
        raw_client_name = _OAUTH_CLIENTS[client_id].get("client_name", "")
    if not raw_client_name:
        if "chatgpt" in redirect_uri.lower() or "openai" in redirect_uri.lower():
            raw_client_name = "ChatGPT"
        elif "claude" in redirect_uri.lower():
            raw_client_name = "Claude Web"
        else:
            raw_client_name = client_id if client_id else "Client App"
    client_display_name = _html.escape(raw_client_name)

    error_html = ""
    if params.get("error"):
        error_html = '<div style="color: #ef4444; background: #451a1a; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; border: 1px solid #7f1d1d;">Invalid password. Please try again.</div>'

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorize {client_display_name} MCP Server</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; display: flex; justify-content: center; align-items: center; min-height: 80vh; }}
        .card {{ background: #1e293b; border-radius: 12px; padding: 2.5rem; max-width: 450px; width: 100%; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }}
        h1 {{ color: #38bdf8; margin-top: 0; font-size: 1.5rem; text-align: center; }}
        p {{ color: #94a3b8; font-size: 0.95rem; text-align: center; line-height: 1.5; }}
        label {{ font-weight: 600; color: #cbd5e1; font-size: 0.9rem; margin-bottom: 0.5rem; display: block; }}
        input[type="password"] {{ width: 100%; padding: 0.75rem; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font-size: 1rem; margin-bottom: 1.25rem; box-sizing: border-box; }}
        input[type="password"]:focus {{ outline: none; border-color: #38bdf8; }}
        button {{ width: 100%; background: #0284c7; color: white; border: none; padding: 0.8rem; border-radius: 6px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.2s; }}
        button:hover {{ background: #0369a1; }}
        .badge {{ background: #0369a1; color: #e0f2fe; font-size: 0.8rem; padding: 0.2rem 0.5rem; border-radius: 4px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Authorize Connector</h1>
        <p>An application <span class="badge">{client_display_name}</span> is requesting access to your <strong>Gemini MCP Server</strong>.</p>
        {error_html}
        <form method="POST" action="/oauth/authorize">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="state" value="{state}">
            <input type="hidden" name="code_challenge" value="{code_challenge}">
            <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
            
            <label for="password">Enter MCP Server Password:</label>
            <input type="password" id="password" name="password" required autofocus placeholder="Enter password...">
            
            <button type="submit">Authorize & Return to Claude</button>
        </form>
    </div>
</body>
</html>"""
    return HTMLResponse(html_content)


async def _oauth_authorize_post(request: Request) -> Response:
    form = await request.form()
    password = str(form.get("password", "")).strip()
    client_id = str(form.get("client_id", ""))
    redirect_uri = str(
        form.get("redirect_uri", "https://claude.ai/api/mcp/auth_callback")
    )
    state = str(form.get("state", ""))
    code_challenge = str(form.get("code_challenge", ""))
    code_challenge_method = str(form.get("code_challenge_method", "plain"))

    expected_password = os.environ.get("MCP_SERVER_PASSWORD", "").strip()
    is_valid = False
    if expected_password and hmac.compare_digest(password, expected_password):
        is_valid = True
    elif ADMIN_PASSWORD and hmac.compare_digest(password, ADMIN_PASSWORD):
        is_valid = True

    if not is_valid:
        params = f"?client_id={urllib.parse.quote(client_id)}&redirect_uri={urllib.parse.quote(redirect_uri)}&state={urllib.parse.quote(state)}&code_challenge={urllib.parse.quote(code_challenge)}&code_challenge_method={urllib.parse.quote(code_challenge_method)}&error=1"
        return RedirectResponse(url=f"/oauth/authorize{params}", status_code=302)

    code = f"code_{secrets.token_hex(16)}"
    _OAUTH_CODES[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": time.time() + 600,
    }

    target = f"{redirect_uri}?code={urllib.parse.quote(code)}"
    if state:
        target += f"&state={urllib.parse.quote(state)}"
    return RedirectResponse(url=target, status_code=302)


async def _oauth_token(request: Request) -> JSONResponse:
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            data = await request.json()
        except Exception:
            data = {}
    else:
        form = await request.form()
        data = dict(form)

    grant_type = data.get("grant_type", "authorization_code")
    code = data.get("code", "")
    refresh_token = data.get("refresh_token", "")
    code_verifier = data.get("code_verifier", "")

    if grant_type == "refresh_token":
        new_access_token = _generate_oauth_token()
        new_refresh_token = _generate_refresh_token()
        _OAUTH_TOKENS.add(new_access_token)
        if refresh_token:
            _OAUTH_REFRESH_TOKENS[refresh_token] = new_access_token
        _save_oauth_data()
        return JSONResponse(
            {
                "access_token": new_access_token,
                "token_type": "Bearer",
                "expires_in": 315360000,
                "refresh_token": new_refresh_token,
                "scope": "mcp",
            }
        )

    if grant_type != "authorization_code" or not code or code not in _OAUTH_CODES:
        return JSONResponse(
            {
                "error": "invalid_grant",
                "error_description": "Invalid or expired authorization code",
            },
            status_code=400,
        )

    code_info = _OAUTH_CODES.pop(code)
    if time.time() > code_info["expires_at"]:
        return JSONResponse(
            {
                "error": "invalid_grant",
                "error_description": "Authorization code expired",
            },
            status_code=400,
        )

    code_challenge = code_info.get("code_challenge")
    method = code_info.get("code_challenge_method", "plain")
    if code_challenge and code_verifier:
        if method == "S256":
            hashed = hashlib.sha256(code_verifier.encode("utf-8")).digest()
            computed = base64.urlsafe_b64encode(hashed).decode("utf-8").rstrip("=")
            if not hmac.compare_digest(computed, code_challenge.rstrip("=")):
                return JSONResponse(
                    {
                        "error": "invalid_grant",
                        "error_description": "PKCE code_verifier check failed",
                    },
                    status_code=400,
                )
        else:
            if not hmac.compare_digest(code_verifier, code_challenge):
                return JSONResponse(
                    {
                        "error": "invalid_grant",
                        "error_description": "PKCE code_verifier check failed",
                    },
                    status_code=400,
                )

    access_token = _generate_oauth_token()
    new_refresh_token = _generate_refresh_token()
    _OAUTH_TOKENS.add(access_token)
    _OAUTH_REFRESH_TOKENS[new_refresh_token] = access_token
    _save_oauth_data()

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 315360000,
            "refresh_token": new_refresh_token,
            "scope": "mcp",
        }
    )


# ---------------------------------------------------------------------------
# Server Entrypoint & Routes
# ---------------------------------------------------------------------------

app = mcp.streamable_http_app()
app.add_middleware(PasswordAuthMiddleware)


async def _root(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "service": "github-codespaces MCP server",
            "message": "MCP endpoint is at /mcp — admin dashboard at /admin",
            "mcp_endpoint": "/mcp",
            "admin_endpoint": "/admin",
            "allowed_host_configured": bool(_allowed_host),
            "auth_enabled": bool(os.environ.get("MCP_SERVER_PASSWORD")),
            "admin_enabled": bool(ADMIN_PASSWORD),
            "render_admin_configured": bool(RENDER_API_KEY),
            "server_configured": bool(SERVER_HOST),
            "pcs_configured": sorted(_PC_REGISTRY.keys()),
            "v2_dynamic_pcs": list(_PC_V2_DYNAMIC_REGISTRY.keys()),
            "accounts": {
                "primary": bool(os.environ.get("GITHUB_TOKEN")),
                "secondary": bool(os.environ.get("GITHUB_TOKEN_SECONDARY")),
                "tertiary": bool(os.environ.get("GITHUB_TOKEN_TERTIARY")),
            },
        }
    )


async def _health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


app.router.routes.insert(0, Route("/", _root, methods=["GET", "POST", "HEAD"]))
app.router.routes.insert(1, Route("/healthz", _health, methods=["GET", "HEAD"]))
app.router.routes.insert(2, Route("/admin", _admin_page, methods=["GET"]))
app.router.routes.insert(3, Route("/admin/login", _admin_login, methods=["POST"]))
app.router.routes.insert(4, Route("/admin/logout", _admin_logout, methods=["GET"]))
app.router.routes.insert(
    5, Route("/admin/api/env", _admin_api_env_get, methods=["GET"])
)
app.router.routes.insert(
    6, Route("/admin/api/env", _admin_api_env_set, methods=["POST"])
)
app.router.routes.insert(
    7, Route("/admin/api/deploy", _admin_api_deploy, methods=["POST"])
)
app.router.routes.insert(
    8, Route("/admin/api/server/run", _admin_api_server_run, methods=["POST"])
)
app.router.routes.insert(
    9, Route("/admin/api/diagnostics", _admin_api_diagnostics, methods=["GET"])
)
app.router.routes.insert(
    10, Route("/admin/api/fleet", _admin_api_fleet, methods=["GET"])
)
app.router.routes.insert(
    11, Route("/admin/api/pc/screenshot", _admin_api_pc_screenshot, methods=["POST"])
)
app.router.routes.insert(
    12, Route("/admin/api/pc/cmd", _admin_api_pc_cmd, methods=["POST"])
)
app.router.routes.insert(
    13, Route("/admin/api/pc/disk", _admin_api_pc_disk, methods=["GET"])
)
app.router.routes.insert(
    14, Route("/admin/api/codespaces", _admin_api_codespaces, methods=["GET"])
)
app.router.routes.insert(
    15, Route("/admin/api/server/overview", _admin_api_server_overview, methods=["GET"])
)
app.router.routes.insert(
    16, Route("/admin/api/server/service", _admin_api_server_service, methods=["POST"])
)
app.router.routes.insert(
    17, Route("/admin/api/transfer", _admin_api_transfer, methods=["POST"])
)
app.router.routes.insert(
    18, Route("/events/pc_status", _events_pc_status, methods=["POST"])
)
app.router.routes.insert(
    19,
    Route("/.well-known/oauth-authorization-server", _oauth_metadata, methods=["GET"]),
)
app.router.routes.insert(
    20,
    Route(
        "/.well-known/oauth-protected-resource",
        _oauth_protected_resource,
        methods=["GET"],
    ),
)
app.router.routes.insert(
    21, Route("/oauth/register", _oauth_register, methods=["POST"])
)
app.router.routes.insert(
    22, Route("/oauth/authorize", _oauth_authorize_get, methods=["GET"])
)
app.router.routes.insert(
    23, Route("/oauth/authorize", _oauth_authorize_post, methods=["POST"])
)
app.router.routes.insert(24, Route("/oauth/token", _oauth_token, methods=["POST"]))


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
