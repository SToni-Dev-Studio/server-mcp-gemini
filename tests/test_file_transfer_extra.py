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
import importlib
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

@pytest.mark.parametrize("loc,expect_valid", [
    ("", False),
    (":", False),                  # kind="" -> unknown kind -> ValueError
    ("pc:", False),                # no second colon -> ValueError
    ("pc::", True),                # DOES parse: kind="pc", name="", path="" (see finding below)
    ("codespace:", False),
    ("unknown-kind:/x", False),
    ("SANDBOX:/x", True),          # kind is lowercased -- valid by design, not a bug
])
def test_various_malformed_or_edge_addresses(loc, expect_valid):
    if not expect_valid:
        with pytest.raises(ValueError):
            srv._parse_location(loc)
        return
    kind, name, path = srv._parse_location(loc)
    if loc == "SANDBOX:/x":
        assert kind == "sandbox" and path == "/x"
    elif loc == "pc::":
        # FINDING (low severity): _parse_location happily accepts "pc::"
        # as kind="pc", name="", path="" -- an entirely empty path -- with
        # no validation that path is non-empty. It only surfaces as an
        # error much further downstream (organiser-agent's own "Missing
        # 'path'" 400), with a much less clear message than a proper
        # "malformed location" would give at the point of parsing.
        assert kind == "pc" and name == "" and path == ""


def test_pc_location_with_empty_name_silently_falls_back_to_default():
    """Documents a real (low-severity) gap: 'pc::C:\\path' parses with
    name="" , and downstream code does `pc=name or "default"` -- so a
    malformed/typo'd empty PC name is silently treated as the "default"
    PC rather than raising a clear error. Not a privilege issue (still
    requires the one shared bearer token), but a caller who meant to
    target a specific PC and fat-fingered the address gets silently
    redirected to a different machine instead of an error."""
    kind, name, path = srv._parse_location("pc::C:\\Users\\me\\file.txt")
    assert kind == "pc"
    assert name == ""  # falls back to "default" downstream, not rejected here


def test_codespace_unknown_account_silently_falls_back_to_auto(monkeypatch):
    """Documents a real (low-severity) gap: _get_token() only special-cases
    'primary'/'secondary'/'tertiary'; any other account string (typo, or
    garbage) falls through to the same branch as 'auto' instead of being
    rejected. It does not grant escalated access (still picks from the
    same configured tokens via the auto order), but a typo'd account
    silently uses a DIFFERENT token than the one the caller named,
    instead of erroring."""
    monkeypatch.setenv("GITHUB_TOKEN", "primary-tok")
    monkeypatch.setenv("GITHUB_TOKEN_SECONDARY", "secondary-tok")
    token, used = srv._get_token("this-is-not-a-real-account")
    assert used == "primary"  # silently == auto, not an error


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
    async def fake_exec_command(codespace_name, cmd, timeout_seconds=60, account="auto"):
        return "OK"
    monkeypatch.setattr(srv, "exec_command", fake_exec_command)
    data = b"x" * (srv._FILE_TRANSFER_MAX_BYTES + 1)
    with pytest.raises(ValueError, match="over the"):
        asyncio.run(srv._location_write_bytes("codespace:myspace:/tmp/x", data))


def test_read_side_has_no_upfront_size_limit_for_server_kind(monkeypatch, tmp_path):
    """Confirms (via code path, not just reading the source) that
    _location_read_bytes for 'server:' will happily decode an
    oversized base64 blob fully into memory -- the 15MB cap is only
    ever enforced on the WRITE side, after the full read already
    happened. This means a huge remote source file gets fully
    read+decoded (and, for server:/codespace:, base64-inflated ~33%)
    before file_transfer ever rejects it -- a real (if minor,
    self-inflicted-by-the-same-caller) resource-exhaustion gap."""
    huge = b"A" * (srv._FILE_TRANSFER_MAX_BYTES + 5_000_000)  # ~20MB, over cap
    huge_b64 = base64.b64encode(huge).decode()

    async def fake_ssh_server(cmd, timeout=30):
        return huge_b64

    monkeypatch.setattr(srv, "_ssh_server", fake_ssh_server)
    result = asyncio.run(srv._location_read_bytes("server:/tmp/huge-remote-file"))
    # the read itself succeeds and returns the full oversized payload --
    # proving no size check happened during the read.
    assert len(result) == len(huge)


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
    simulated_linux_hop_output = (
        '{"error": "\'utf-8\' codec can\'t decode byte 0x80 in position 340: invalid start byte"}'
    )

    async def fake_ssh_server(cmd, timeout=30):
        return simulated_linux_hop_output

    monkeypatch.setattr(srv, "_ssh_server", fake_ssh_server)
    result = asyncio.run(srv.file_transfer("pc:default:C:\\some\\binary.exe", "sandbox:/tmp/wont-be-written"))
    assert result.startswith("Read failed")
    assert "invalid start byte" in result or "decode" in result.lower()


def test_pc_binary_write_fails_cleanly_not_corrupted(monkeypatch, tmp_path):
    """Writing binary data TO a pc: destination: server.py itself checks
    (before ever calling organiser-agent) whether the payload can be
    UTF-8 decoded, and raises a clean error if not -- this half of the
    safety net lives entirely in server.py, not organiser-agent."""
    async def fake_org_post(path, body, pc="default"):
        pytest.fail("should never reach the PC -- must fail before the network call")

    monkeypatch.setattr(srv, "_org_post", fake_org_post)
    binary_data = bytes(range(256)) * 4
    result = asyncio.run(_write_helper(srv, binary_data))
    assert "text-only" in result.lower() or "binary" in result.lower()


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

def test_pc_read_file_preview_max_bytes_is_not_clamped(monkeypatch):
    captured = {}

    async def fake_org_get(path, params=None, pc="default"):
        captured["params"] = params
        return {"content": "irrelevant"}

    monkeypatch.setattr(srv, "_org_get", fake_org_get)
    asyncio.run(srv.pc_read_file_preview("C:\\some\\file.txt", max_bytes=10_000_000_000))
    assert captured["params"]["max_bytes"] == 10_000_000_000, (
        "server.py does not clamp max_bytes before forwarding to "
        "organiser-agent -- chains into the confirmed std::bad_alloc DoS "
        "in organiser-agent.cpp's h_preview (see SECURITY_FINDINGS.md)"
    )
