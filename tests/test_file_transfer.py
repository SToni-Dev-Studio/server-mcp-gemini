"""
Tests for the generic file_transfer tool (replaces the old
transfer__pc_to_sandbox / sandbox_to_pc / sandbox_to_codespace /
server_to_sandbox / sandbox_to_server tools).

The sandbox<->sandbox tests below run anywhere (no live infra needed) and
are the ones that caught the real bug: the old tools read local files in
TEXT mode, silently corrupting binary content. These tests fail loudly if
that regresses.

The pc:/server:/codespace: legs need real infra (organiser-agent, SSH
access, a live codespace) to test end-to-end and are NOT exercised here --
security-qa / hub-cicd / pc-agent should run those against the actual
staging environment once available, using the same _parse_location /
_location_read_bytes / _location_write_bytes functions directly if a full
mocked httpx/asyncssh harness isn't set up yet.
"""
import os
import sys
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.pop("MCP_SERVER_PASSWORD", None)
os.environ.setdefault("PORT", "8000")

import server as srv


def test_parse_location_all_kinds():
    assert srv._parse_location("sandbox:/tmp/a.txt") == ("sandbox", "", "/tmp/a.txt")
    assert srv._parse_location("server:/etc/hosts") == ("server", "", "/etc/hosts")
    assert srv._parse_location("pc:desktop:C:\\Users\\me\\file.txt") == (
        "pc", "desktop", "C:\\Users\\me\\file.txt"
    )
    assert srv._parse_location("codespace:my-space:/workspace/x") == (
        "codespace", "my-space", "/workspace/x"
    )
    assert srv._parse_location("codespace:my-space@tertiary:/workspace/x") == (
        "codespace", "my-space@tertiary", "/workspace/x"
    )


def test_parse_location_rejects_unknown_kind():
    try:
        srv._parse_location("dropbox:/x")
        assert False, "should have raised ValueError"
    except ValueError:
        pass


def test_parse_location_rejects_malformed():
    try:
        srv._parse_location("no-colon-at-all")
        assert False, "should have raised ValueError"
    except ValueError:
        pass
    try:
        srv._parse_location("pc:missing-path-separator")
        assert False, "should have raised ValueError"
    except ValueError:
        pass


def test_sandbox_to_sandbox_binary_roundtrip(tmp_path):
    src = tmp_path / "source.bin"
    dst = tmp_path / "dest.bin"
    binary_content = bytes(range(256)) * 1000  # every byte value, non-UTF8-safe
    src.write_bytes(binary_content)

    result = asyncio.run(srv.file_transfer(f"sandbox:{src}", f"sandbox:{dst}"))
    assert "Transferred" in result, result
    assert dst.read_bytes() == binary_content, "binary data was corrupted in transfer"


def test_sandbox_to_sandbox_creates_parent_dirs(tmp_path):
    src = tmp_path / "source.txt"
    src.write_bytes(b"hello")
    dst = tmp_path / "nested" / "dir" / "dest.txt"

    result = asyncio.run(srv.file_transfer(f"sandbox:{src}", f"sandbox:{dst}"))
    assert "Transferred" in result, result
    assert dst.read_bytes() == b"hello"


def test_size_limit_enforced(tmp_path):
    src = tmp_path / "huge.bin"
    src.write_bytes(b"x" * (srv._FILE_TRANSFER_MAX_BYTES + 1))
    dst = tmp_path / "huge_dest.bin"

    result = asyncio.run(srv.file_transfer(f"sandbox:{src}", f"sandbox:{dst}"))
    assert "Write failed" in result and "over the" in result, result
    assert not dst.exists(), "oversized file should not have been partially written"


def test_missing_source_gives_clean_error(tmp_path):
    result = asyncio.run(
        srv.file_transfer(f"sandbox:{tmp_path}/does_not_exist.bin", f"sandbox:{tmp_path}/dest.bin")
    )
    assert result.startswith("Read failed"), result


def test_malformed_address_gives_clean_error():
    result = asyncio.run(srv.file_transfer("not-a-valid-address", "sandbox:/tmp/x"))
    assert result.startswith("Read failed"), result
