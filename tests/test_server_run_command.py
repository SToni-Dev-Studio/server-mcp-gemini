"""
Tests for server_run_command's safety boundaries -- called out explicitly
in coordination/tasks/hub-cicd.md as untested ("Real tests for: ...
server_run_command safety boundaries"). No other test file in this repo
exercises this tool directly.

Reads server.py's actual implementation first (as the brief insists):

    @mcp.tool()
    async def server_run_command(command: str) -> str:
        '''
        Run a shell command on the home Linux server over SSH.
        Note: the blocklist below is a footgun-prevention nicety, not a
        real security boundary (trivially bypassable -- this tool
        intentionally runs arbitrary commands, that's its purpose).
        '''
        blocked = ["rm -rf /", "mkfs", "dd if=", "> /dev/sda", "shutdown now", "halt"]
        for b in blocked:
            if b in command:
                return f"Blocked: '{b}' is not allowed."
        return await _ssh_server(command)

So the actual, honest safety boundary here is: (1) a plain substring
denylist that only catches the LITERAL patterns, nothing normalized or
regex'd, and the tool's own docstring says this is intentional -- these
tests verify that's true (the denylist catches exactly what it claims to
and nothing more), NOT that the denylist is a real security control (it
isn't, and pretending otherwise in a test would misrepresent the code).
The real security boundary for this tool is the same one gating every
other tool: the bearer-token auth on /mcp, already covered by
tests/test_server_auth_and_injection.py.
"""

import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fresh_server(env_overrides: dict):
    for k in [
        "MCP_SERVER_PASSWORD",
        "ADMIN_PASSWORD",
        "ADMIN_COOKIE_SECRET",
        "RENDER_EXTERNAL_HOSTNAME",
        "MCP_ALLOWED_HOST",
        "FLY_APP_NAME",
        "PORT",
    ]:
        os.environ.pop(k, None)
    os.environ.update(env_overrides)
    if "server" in sys.modules:
        importlib.reload(sys.modules["server"])
    else:
        import server  # noqa
    return sys.modules["server"]


@pytest.fixture
def srv_with_captured_ssh():
    srv = _fresh_server({"PORT": "18000"})
    captured = []

    async def fake_ssh_server(cmd, timeout=30):
        captured.append(cmd)
        return "MOCKED_OUTPUT"

    srv._ssh_server = fake_ssh_server
    return srv, captured


EXACT_BLOCKED_PATTERNS = [
    "rm -rf /",
    "mkfs",
    "dd if=",
    "> /dev/sda",
    "shutdown now",
    "halt",
]


@pytest.mark.parametrize("pattern", EXACT_BLOCKED_PATTERNS)
@pytest.mark.asyncio
async def test_exact_blocked_pattern_is_blocked(srv_with_captured_ssh, pattern):
    srv, captured = srv_with_captured_ssh
    result = await srv.server_run_command(pattern)
    assert result == f"Blocked: '{pattern}' is not allowed."
    assert captured == [], "a blocked command must never reach _ssh_server"


@pytest.mark.parametrize("pattern", EXACT_BLOCKED_PATTERNS)
@pytest.mark.asyncio
async def test_blocked_pattern_still_blocked_when_embedded_in_a_longer_command(
    srv_with_captured_ssh, pattern
):
    """The denylist is a substring check, so it should catch the pattern
    anywhere in a longer command line, not just as the whole command."""
    srv, captured = srv_with_captured_ssh
    result = await srv.server_run_command(f"echo start && {pattern} && echo end")
    assert result.startswith("Blocked:")
    assert captured == []


@pytest.mark.asyncio
async def test_ordinary_safe_command_passes_through_unmodified(srv_with_captured_ssh):
    srv, captured = srv_with_captured_ssh
    result = await srv.server_run_command("ls -la /home")
    assert result == "MOCKED_OUTPUT"
    assert captured == ["ls -la /home"], (
        "command must reach _ssh_server verbatim -- no extra escaping/wrapping here (that's _ssh_server's job)"
    )


# ---------------------------------------------------------------------------
# The denylist is DOCUMENTED as trivially bypassable, not a security
# boundary -- these tests confirm that's actually true of the current
# implementation (a plain `in` substring check), so if someone tightens it
# later without updating the docstring, this file makes that drift visible
# rather than silently stale.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_denylist_bypassed_by_extra_whitespace(srv_with_captured_ssh):
    srv, captured = srv_with_captured_ssh
    # Two spaces instead of one -- "rm -rf /" (one space) is the literal
    # denylist entry, "rm  -rf /" doesn't contain that exact substring.
    result = await srv.server_run_command("rm  -rf /")
    assert result == "MOCKED_OUTPUT", (
        "confirms the denylist is a literal substring match, easily varied around -- matches its own docstring's honesty about this"
    )
    assert captured == ["rm  -rf /"]


@pytest.mark.asyncio
async def test_denylist_bypassed_by_wrapping_in_sudo(srv_with_captured_ssh):
    srv, captured = srv_with_captured_ssh
    result = await srv.server_run_command("sudo rm -rf /")
    # "rm -rf /" IS a substring of "sudo rm -rf /", so this SHOULD still
    # be caught -- included as a sanity check that substring matching
    # does at least catch this common variant, unlike the whitespace case
    # above.
    assert result.startswith("Blocked:")


@pytest.mark.asyncio
async def test_denylist_bypassed_by_different_target_path(srv_with_captured_ssh):
    srv, captured = srv_with_captured_ssh
    # "dd if=" is blocked, but nothing stops writing to a different device
    # or file via a totally different dd invocation shape that doesn't
    # contain that literal substring, e.g. using bs=/of= ordering tricks
    # is unnecessary -- the destructive part here doesn't even need "if=":
    result = await srv.server_run_command("dd of=/dev/sda bs=1M count=100 </dev/zero")
    assert result == "MOCKED_OUTPUT", (
        "no 'if=' or '> /dev/sda' substring present, so this destructive dd invocation is NOT caught -- confirms the denylist is footgun-prevention only, as documented, not a real boundary"
    )
    assert captured == ["dd of=/dev/sda bs=1M count=100 </dev/zero"]


@pytest.mark.asyncio
async def test_command_containing_shell_metacharacters_passed_through_verbatim(
    srv_with_captured_ssh,
):
    """This tool's entire purpose is running arbitrary shell commands over
    SSH -- unlike organiser-agent.cpp's working_dir bug (a DIFFERENT
    parameter being unsafely concatenated INTO a shell string), `command`
    here IS the shell string by design. So metacharacters passing through
    verbatim to _ssh_server is correct, expected behavior, not a
    vulnerability -- this test documents that distinction rather than
    flagging it as a finding."""
    srv, captured = srv_with_captured_ssh
    cmd = "echo hi; cat /etc/passwd | grep root && echo done"
    result = await srv.server_run_command(cmd)
    assert result == "MOCKED_OUTPUT"
    assert captured == [cmd]
