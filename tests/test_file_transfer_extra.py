"""
Extra file_transfer + related security tests, written in response to
BROADCAST [0008]: path traversal in the 4 location kinds, malformed
addresses, oversized files, PC binary-transfer failure mode (verified,
not just trusted), and codespace account switching.

No real infrastructure touched: _ssh_server / exec_command / _org_get /
_org_post are monkeypatched. Real organiser-agent behavior for the binary
case was captured separately against a real compiled instance (see
SECURITY_FINDINGS.md and test_organiser_agent_security.py) and is
replayed here verbatim to test server.py's handling of it end-to-end.
"""

import asyncio
import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.pop("MCP_SERVER_PASSWORD", None)
os.environ.setdefault("PORT", "8000")

import server as srv


# ---------------------------------------------------------------------------
# Malformed addresses (extends the basic set already in test_file_transfer.py)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "loc,expect_valid",
    [
        ("", False),
        (":", False),  # kind="" -> unknown kind -> ValueError
        ("pc:", False),  # no second colon -> ValueError
        (
            "pc::",
            False,
        ),  # FIXED (was True): empty pc name now rejected by lead, see below
        ("codespace:", False),
        ("unknown-kind:/x", False),
        ("SANDBOX:/x", True),  # kind is lowercased -- valid by design, not a bug
    ],
)
def test_various_malformed_or_edge_addresses(loc, expect_valid):
    if not expect_valid:
        with pytest.raises(ValueError):
            srv._parse_location(loc)
        return
    kind, name, path = srv._parse_location(loc)
    if loc == "SANDBOX:/x":
        assert kind == "sandbox" and path == "/x"


def test_pc_location_with_empty_name_now_raises():
    """FIXED (was: silently fell back to the default PC). Originally
    documented a real gap -- 'pc::C:\\path' parsed with name="", and
    downstream code did `pc=name or "default"`, so a malformed/typo'd
    empty PC name was silently treated as the "default" PC instead of
    raising. Lead added an explicit check in _parse_location; a blank
    name is now a clear ValueError at parse time instead of a silent
    redirect to a possibly-wrong machine."""
    with pytest.raises(ValueError, match="empty name"):
        srv._parse_location("pc::C:\\Users\\me\\file.txt")


def test_codespace_unknown_account_now_raises(monkeypatch):
    """FIXED (was: silently fell through to auto's behavior). Originally
    documented a real gap -- _get_token() only special-cased
    'primary'/'secondary'/'tertiary', so any other string (typo or
    garbage) silently used a DIFFERENT token than the one the caller
    named instead of erroring. Lead added an explicit allowlist check;
    an unrecognized account is now a clear ValueError."""
    monkeypatch.setenv("GITHUB_TOKEN", "primary-tok")
    monkeypatch.setenv("GITHUB_TOKEN_SECONDARY", "secondary-tok")
    with pytest.raises(ValueError, match="this-is-not-a-real-account"):
        srv._get_token("this-is-not-a-real-account")


# ---------------------------------------------------------------------------
# Oversized files: verify the 15MB cap holds for every destination kind,
# AND document that the READ side has no size limit (server:/codespace:
# will fully read+base64-decode an arbitrarily large remote file into
# memory before the write-side check ever rejects it).
# ---------------------------------------------------------------------------


def test_size_limit_enforced_for_server_destination(monkeypatch):
    async def fake_ssh_server(cmd, timeout=30):
        return "OK"

    monkeypatch.setattr(srv, "_ssh_server", fake_ssh_server)
    data = b"x" * (srv._FILE_TRANSFER_MAX_BYTES + 1)
    with pytest.raises(ValueError, match="over the"):
        asyncio.run(srv._location_write_bytes("server:/tmp/x", data))


def test_size_limit_enforced_for_codespace_destination(monkeypatch):
    async def fake_exec_command(
        codespace_name, cmd, timeout_seconds=60, account="auto"
    ):
        return "OK"

    monkeypatch.setattr(srv, "exec_command", fake_exec_command)
    data = b"x" * (srv._FILE_TRANSFER_MAX_BYTES + 1)
    with pytest.raises(ValueError, match="over the"):
        asyncio.run(srv._location_write_bytes("codespace:myspace:/tmp/x", data))


def test_read_side_now_has_upfront_size_limit_for_server_kind(monkeypatch):
    """FIXED (external review A10, was: no upfront size check). Used to
    document that _location_read_bytes for 'server:' would happily
    decode an oversized base64 blob fully into memory before the 15MB
    cap was ever checked, on the WRITE side, after the full read already
    happened. Lead added a `stat -c%s` check before ever running the
    base64 read -- see test_server_read_rejects_oversized_file_before_reading
    for the direct proof the base64 command is never even issued."""

    async def fake_ssh_server(cmd, timeout=60):
        if "stat -c%s" in cmd:
            return str(srv._FILE_TRANSFER_MAX_BYTES + 5_000_000)
        pytest.fail("base64 read should never be reached for an oversized file")

    monkeypatch.setattr(srv, "_ssh_server", fake_ssh_server)
    try:
        asyncio.run(srv._location_read_bytes("server:/tmp/huge-remote-file"))
        assert False, "should have raised ValueError"
    except ValueError as e:
        assert "over the" in str(e)


# ---------------------------------------------------------------------------
# Sandbox kind: no path confinement, by design (consistent with every
# other admin tool in this server) -- but worth demonstrating concretely,
# since file_transfer makes local-file read/write more discoverable than
# the 5 old narrowly-named transfer__* tools it replaces.
# ---------------------------------------------------------------------------


def test_sandbox_kind_can_read_arbitrary_local_files(tmp_path, monkeypatch):
    """Not a NEW vulnerability introduced by file_transfer (the old
    transfer__sandbox_to_* / transfer__*_to_sandbox tools already exposed
    this same local-filesystem reach) -- but file_transfer consolidates
    it into one obviously-discoverable generic tool. Demonstrated here
    with a synthetic 'sensitive-looking' file rather than a real secret."""
    fake_secret_file = tmp_path / "pretend_env_file"
    fake_secret_file.write_text("FAKE_TOKEN=not-a-real-secret-just-a-test-value\n")
    data = asyncio.run(srv._location_read_bytes(f"sandbox:{fake_secret_file}"))
    assert b"FAKE_TOKEN" in data


# ---------------------------------------------------------------------------
# PC binary transfer: VERIFY (not just trust) that it fails cleanly.
# This replays the EXACT wrapper shape that a real compiled organiser-agent
# + the Linux-server python hop produces for genuinely binary content
# (captured live against a real build -- see SECURITY_FINDINGS.md).
# ---------------------------------------------------------------------------


def test_pc_binary_read_fails_cleanly_not_corrupted(monkeypatch):
    """Real organiser-agent, when asked to /preview a file containing
    invalid-UTF-8 bytes, produces a raw HTTP response body that is
    itself invalid UTF-8 (confirmed live: see
    test_organiser_agent_security.py::test_preview_of_binary_file_returns_invalid_utf8_over_the_wire).
    The Linux-server-side python hop in _organiser_ssh_request does
    `r.read().decode()` with strict UTF-8, which raises UnicodeDecodeError
    on that response and is caught by its own broad `except Exception`,
    turning it into a clean {"error": "...decode error..."} JSON payload
    -- which is what actually reaches server.py. This test replays that
    exact, real, captured shape and confirms file_transfer surfaces it as
    a clean 'Read failed', never as truncated/corrupted 'content'."""
    simulated_linux_hop_output = '{"error": "\'utf-8\' codec can\'t decode byte 0x80 in position 340: invalid start byte"}'

    async def fake_ssh_server(cmd, timeout=30):
        return simulated_linux_hop_output

    monkeypatch.setattr(srv, "_ssh_server", fake_ssh_server)
    result = asyncio.run(
        srv.file_transfer(
            "pc:default:C:\\some\\binary.exe", "sandbox:/tmp/wont-be-written"
        )
    )
    assert result.startswith("Read failed")
    assert "invalid start byte" in result or "decode" in result.lower()


def test_pc_binary_write_now_succeeds_via_base64(monkeypatch, tmp_path):
    """UPDATED (was: rejected binary writes to a pc: destination as a
    UTF-8-decode failure). agent/pc-agent added content_b64 support to
    organiser-agent's /write_file (broadcast [0006]), and the lead wired
    file_transfer's pc: leg to send content_b64 unconditionally instead
    of trying content= as UTF-8 text first -- binary writes to a PC now
    succeed instead of being rejected."""
    received = {}

    async def fake_org_post(path, body, pc="default"):
        received["path"] = path
        received["body"] = body
        return {"message": "ok"}

    monkeypatch.setattr(srv, "_org_post", fake_org_post)
    binary_data = bytes(range(256)) * 4
    result = asyncio.run(_write_helper(srv, binary_data))
    assert "pc:default" in result
    assert received["path"] == "/write_file"
    assert "content_b64" in received["body"]
    assert "content" not in received["body"]


async def _write_helper(srv, data):
    try:
        return await srv._location_write_bytes("pc:default:C:\\dest.bin", data)
    except ValueError as e:
        return str(e)


# ---------------------------------------------------------------------------
# pc_read_file_preview: max_bytes passes through to organiser-agent with
# NO clamping -- chains directly into the confirmed organiser-agent
# std::bad_alloc DoS (test_organiser_agent_security.py). This test proves
# the pass-through on the server.py side (the other half of that chain).
# ---------------------------------------------------------------------------


def test_pc_read_file_preview_max_bytes_now_clamped(monkeypatch):
    """FIXED (was: passed through uncapped). Originally documented that
    server.py forwarded caller-supplied max_bytes straight to
    organiser-agent with no upper bound, chaining into the confirmed
    std::bad_alloc DoS in organiser-agent.cpp's h_preview (see
    SECURITY_FINDINGS.md finding 4). Lead added a ceiling clamp in
    server.py as the server-side half of the fix; the real fix (a bounds
    check inside organiser-agent.cpp itself) is pc-agent's scope."""
    captured = {}

    async def fake_org_get(path, params=None, pc="default"):
        captured["params"] = params
        return {"content": "irrelevant"}

    monkeypatch.setattr(srv, "_org_get", fake_org_get)
    asyncio.run(
        srv.pc_read_file_preview("C:\\some\\file.txt", max_bytes=10_000_000_000)
    )
    assert captured["params"]["max_bytes"] == srv._PC_PREVIEW_MAX_BYTES_CEILING


def test_server_read_rejects_oversized_file_before_reading(monkeypatch):
    """External review A10: server:/codespace: reads used to base64 the
    WHOLE file before any size check ran. Now stats first and rejects
    upfront."""
    calls = []

    async def fake_ssh_server(cmd, timeout=60):
        calls.append(cmd)
        if "stat -c%s" in cmd:
            return str(srv._FILE_TRANSFER_MAX_BYTES + 1)
        pytest.fail("should never reach the base64 read after a failed size check")

    monkeypatch.setattr(srv, "_ssh_server", fake_ssh_server)
    try:
        asyncio.run(srv._location_read_bytes("server:/mnt/ssd/huge.iso"))
        assert False, "should have raised"
    except ValueError as e:
        assert "over the" in str(e)
    assert any("stat -c%s" in c for c in calls)
    assert not any("base64 -w0" in c for c in calls), (
        "read the file despite the size check failing"
    )


def test_server_read_allows_file_within_cap(monkeypatch):
    async def fake_ssh_server(cmd, timeout=60):
        if "stat -c%s" in cmd:
            return "5"
        if "base64 -w0" in cmd:
            return base64.b64encode(b"hello").decode()
        pytest.fail(f"unexpected command: {cmd}")

    monkeypatch.setattr(srv, "_ssh_server", fake_ssh_server)
    result = asyncio.run(srv._location_read_bytes("server:/tmp/small.txt"))
    assert result == b"hello"


def test_codespace_read_rejects_oversized_file_before_reading(monkeypatch):
    calls = []

    async def fake_exec_command(cs_name, cmd, account="auto", timeout_seconds=60):
        calls.append(cmd)
        if "stat -c%s" in cmd:
            return str(srv._FILE_TRANSFER_MAX_BYTES + 1)
        pytest.fail("should never reach the base64 read after a failed size check")

    monkeypatch.setattr(srv, "exec_command", fake_exec_command)
    try:
        asyncio.run(srv._location_read_bytes("codespace:my-space:/workspace/huge.bin"))
        assert False, "should have raised"
    except ValueError as e:
        assert "over the" in str(e)
    assert not any("base64 -w0" in c for c in calls)


def test_pc_list_configured_shows_live_status(monkeypatch):
    """pc-autodiscovery proposal section 1: pc_list_configured now polls
    each PC live instead of just echoing the static registry."""
    monkeypatch.setattr(
        srv,
        "_PC_REGISTRY",
        {
            "desktop": {"port": 7842},
            "laptop": {"port": 7843},
        },
    )

    async def fake_org_get(path, params=None, pc="default"):
        if pc == "desktop":
            return {
                "machine_name": "SEPISO-DESKTOP",
                "version": "2.1.0-cpp",
                "platform": "Windows",
            }
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(srv, "_org_get", fake_org_get)
    result = asyncio.run(srv.pc_list_configured())

    assert "2 configured, 1 reachable" in result
    assert "SEPISO-DESKTOP" in result
    assert "\u2705" in result  # desktop reachable
    assert "laptop" in result and "unreachable" in result


def test_pc_list_configured_a_slow_pc_does_not_block_others(monkeypatch):
    """One PC timing out must not make the whole call wait for it --
    proposal explicitly calls for asyncio.gather with per-PC timeout."""
    monkeypatch.setattr(
        srv,
        "_PC_REGISTRY",
        {
            "fast": {"port": 1},
            "slow": {"port": 2},
        },
    )

    async def fake_org_get(path, params=None, pc="default"):
        if pc == "slow":
            await asyncio.sleep(
                10
            )  # would fail the test's own timeout if actually awaited fully
        return {"machine_name": pc, "version": "1.0", "platform": "Linux"}

    monkeypatch.setattr(srv, "_org_get", fake_org_get)

    async def run_with_timeout():
        return await asyncio.wait_for(srv.pc_list_configured(), timeout=5.0)

    result = asyncio.run(run_with_timeout())
    assert "fast" in result
    assert "slow" in result
    assert (
        "unreachable" in result
    )  # the 3s per-PC timeout fired before the outer 5s test timeout


def test_pc_list_configured_empty_registry_unchanged(monkeypatch):
    """The 'no PCs configured at all' case is unchanged by this feature --
    still a plain message, no polling attempted."""
    monkeypatch.setattr(srv, "_PC_REGISTRY", {})
    result = asyncio.run(srv.pc_list_configured())
    assert result == "No PCs configured."
