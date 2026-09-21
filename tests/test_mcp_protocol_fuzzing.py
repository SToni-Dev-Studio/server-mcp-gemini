"""
Wire-protocol-level fuzzing of the real MCP JSON-RPC endpoint (/mcp),
driven against a real server.py subprocess over a real (loopback-only)
TCP socket -- same pattern as test_organiser_agent_security.py. No real
infra touched.

Findings locked in here:
  - The DNS-rebinding `allowed_hosts` list has no port wildcard, so any
    request whose Host header includes an explicit port is rejected with
    421 -- confirmed this breaks routine localhost testing (not a
    vulnerability; it's a fail-CLOSED availability bug, the opposite
    direction of a security hole, but worth locking in since a bad "fix"
    for it -- disabling DNS-rebinding protection entirely -- would be a
    real regression).
  - A valid Mcp-Session-Id replayed WITHOUT the Authorization bearer token
    is rejected (401) -- confirms PasswordAuthMiddleware runs on every
    request, not just at session creation. This is a real defense-in-depth
    property worth protecting from regression.
  - Malformed JSON-RPC envelopes and malformed tool arguments (wrong
    types, missing fields, oversized strings, null bytes, unicode) are all
    handled cleanly by the SDK/Pydantic validation layer -- no crashes, no
    leaked internals, always a well-formed JSON-RPC error.
"""

import json
import os
import re
import socket
import subprocess
import sys
import time

import httpx
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


RUNNER_TEMPLATE = """
import os, sys
os.environ["MCP_SERVER_PASSWORD"] = "test-password-123"
for k in ("RENDER_EXTERNAL_HOSTNAME", "MCP_ALLOWED_HOST", "FLY_APP_NAME"):
    os.environ.pop(k, None)
os.environ["PORT"] = "__PORT__"
sys.path.insert(0, "__REPO_ROOT__")
import server
import uvicorn
uvicorn.run(server.app, host="127.0.0.1", port=__PORT__, log_level="warning")
"""


@pytest.fixture
def app_client(tmp_path):
    """Runs the real server.py as a real subprocess (real uvicorn, real TCP
    socket) rather than an in-process ASGI transport -- simpler and more
    representative of the real deployment."""
    port = _free_port()
    runner = tmp_path / "run_server.py"
    script = RUNNER_TEMPLATE.replace("__PORT__", str(port)).replace(
        "__REPO_ROOT__", REPO_ROOT
    )
    runner.write_text(script)
    proc = subprocess.Popen(
        [sys.executable, str(runner)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base_url = f"http://127.0.0.1:{port}"
    client = httpx.Client(base_url=base_url, timeout=10)
    try:
        for _ in range(50):
            try:
                client.get("/healthz")
                break
            except httpx.ConnectError:
                if proc.poll() is not None:
                    out = proc.stdout.read().decode(errors="replace")
                    pytest.fail(f"server.py exited early:\n{out}")
                time.sleep(0.1)
        else:
            pytest.fail("server.py never came up")
        yield client
    finally:
        client.close()
        proc.kill()
        proc.wait(timeout=5)


HEADERS_BASE = {
    "Authorization": "Bearer test-password-123",
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _extract_json(text):
    m = re.search(r"data: (\{.*\})", text)
    if m:
        return json.loads(m.group(1))
    try:
        return json.loads(text)
    except Exception:
        return None


def test_host_header_with_port_is_rejected_by_dns_rebinding_check(app_client):
    """Documents a real availability gap (not a vulnerability -- fails
    CLOSED, more restrictive than intended): allowed_hosts=["localhost",
    "127.0.0.1"] has no ":*" port-wildcard entry, so ANY request whose
    Host header includes an explicit port -- which is standard for
    virtually any non-default-port local/self-hosted deployment -- gets
    rejected with 421, even with a fully correct bearer token."""
    headers = dict(HEADERS_BASE)
    headers["Host"] = "localhost:8000"  # what a real local client would send
    r = app_client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "x", "version": "1"},
            },
        },
    )
    assert r.status_code == 421, (
        "if this now passes, the port-wildcard gap was fixed -- update "
        "SECURITY_FINDINGS.md to mark it resolved rather than deleting "
        "this test"
    )


def test_bare_host_header_without_port_is_accepted(app_client):
    headers = dict(HEADERS_BASE)
    headers["Host"] = "localhost"
    r = app_client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "x", "version": "1"},
            },
        },
    )
    assert r.status_code == 200


def _init_session(app_client):
    headers = dict(HEADERS_BASE)
    headers["Host"] = "localhost"
    r = app_client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "x", "version": "1"},
            },
        },
    )
    sid = r.headers.get("Mcp-Session-Id")
    app_client.post(
        "/mcp",
        headers={**headers, "Mcp-Session-Id": sid},
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    return sid


def test_stolen_session_id_without_bearer_token_is_rejected(app_client):
    """The security-critical case: a Mcp-Session-Id leaked or intercepted
    separately from the bearer token (e.g. via logs, a referrer header,
    proxy logs) must NOT be usable on its own. Confirms the auth
    middleware runs on every request, not just at session creation."""
    sid = _init_session(app_client)
    assert sid

    headers_no_auth = {k: v for k, v in HEADERS_BASE.items() if k != "Authorization"}
    headers_no_auth["Host"] = "localhost"
    headers_no_auth["Mcp-Session-Id"] = sid
    r = app_client.post(
        "/mcp",
        headers=headers_no_auth,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "server_status", "arguments": {}},
        },
    )
    assert r.status_code == 401, (
        "a valid session id must never grant access without the bearer "
        "token -- if this regresses, session hijacking via a leaked "
        "session id (without the password) becomes possible"
    )


def test_forged_session_id_is_cleanly_rejected(app_client):
    headers = dict(HEADERS_BASE)
    headers["Host"] = "localhost"
    headers["Mcp-Session-Id"] = "totally-made-up-session-id"
    r = app_client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "server_status", "arguments": {}},
        },
    )
    assert r.status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b'{"jsonrpc":"2.0","id":1,"method":"initialize"',  # truncated
        b'[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}]',  # array not object
    ],
)
def test_malformed_envelopes_never_500_or_leak_traceback(app_client, body):
    headers = dict(HEADERS_BASE)
    headers["Host"] = "localhost"
    r = app_client.post("/mcp", headers=headers, content=body)
    assert r.status_code != 500, f"malformed envelope caused a 500: {r.text[:300]}"
    assert "Traceback" not in r.text
    assert r.status_code == 400


@pytest.mark.parametrize(
    "bad_args,expect_field",
    [
        ({}, "path"),  # missing required arg
        ({"path": 12345}, "path"),  # wrong type: int for str
        ({"path": None}, "path"),  # wrong type: null for str
        ({"path": ["a", "b"]}, "path"),  # wrong type: list for str
        ({"path": {"x": 1}}, "path"),  # wrong type: dict for str
        ({"path": True}, "path"),  # wrong type: bool for str
    ],
)
def test_tool_call_type_validation_never_crashes(app_client, bad_args, expect_field):
    """Pydantic-based argument validation must reject every wrong type
    cleanly, as a tool-result error, never as an unhandled exception."""
    sid = _init_session(app_client)
    headers = dict(HEADERS_BASE)
    headers["Host"] = "localhost"
    headers["Mcp-Session-Id"] = sid
    r = app_client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "server_read_file", "arguments": bad_args},
        },
    )
    assert r.status_code == 200
    parsed = _extract_json(r.text)
    assert parsed is not None
    text = json.dumps(parsed)
    assert "Traceback" not in text
    assert expect_field in text


def test_embedded_null_byte_in_argument_is_caught_cleanly(app_client):
    sid = _init_session(app_client)
    headers = dict(HEADERS_BASE)
    headers["Host"] = "localhost"
    headers["Mcp-Session-Id"] = sid
    r = app_client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "server_read_file",
                "arguments": {"path": "/tmp/foo\x00bar"},
            },
        },
    )
    assert r.status_code == 200
    parsed = _extract_json(r.text)
    text = json.dumps(parsed)
    assert "Traceback" not in text
    assert parsed["result"]["isError"] is True


def test_oversized_string_argument_does_not_crash_server(app_client):
    sid = _init_session(app_client)
    headers = dict(HEADERS_BASE)
    headers["Host"] = "localhost"
    headers["Mcp-Session-Id"] = sid
    r = app_client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "server_read_file",
                "arguments": {"path": "A" * 2_000_000},
            },
        },
    )
    assert r.status_code == 200
    r2 = app_client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "server_status", "arguments": {}},
        },
    )
    assert r2.status_code == 200
