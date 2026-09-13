"""
Regression tests for four fixes made in response to findings from
agent/docs-release and agent/security-qa:

1. write_codespace_file used to always report success regardless of the
   actual outcome (docs-release finding, hit while writing docs).
2. pc_read_file_preview passed caller-supplied max_bytes straight through
   with no upper bound, enabling the organiser-agent unbounded-allocation
   DoS to be triggered from a single MCP tool call (security-qa finding 4).
3. _get_token silently treated any unrecognized account string the same
   as "auto" instead of erroring (security-qa finding 9).
4. file_transfer's pc:/codespace: address parsing accepted an empty name
   and let it silently degrade to a default downstream (security-qa
   finding 9).
"""
import os
import sys
import asyncio
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("PORT", "8000")

import server as srv


def test_write_codespace_file_reports_real_failure():
    with patch.object(srv, "exec_command", new=AsyncMock(return_value="bash: cannot create: Permission denied")):
        result = asyncio.run(srv.write_codespace_file("some-space", "/readonly/x.txt", "hello"))
    assert result.startswith("Write failed"), result


def test_write_codespace_file_reports_real_success():
    with patch.object(srv, "exec_command", new=AsyncMock(return_value="__WRITE_OK__")):
        result = asyncio.run(srv.write_codespace_file("some-space", "/tmp/x.txt", "hello"))
    assert result.startswith("Successfully wrote"), result


def test_write_codespace_file_mkdir_p_included_in_command():
    mock = AsyncMock(return_value="__WRITE_OK__")
    with patch.object(srv, "exec_command", new=mock):
        asyncio.run(srv.write_codespace_file("some-space", "/new/nested/dir/x.txt", "hello"))
    sent_cmd = mock.call_args.args[1]
    assert "mkdir -p" in sent_cmd


def test_pc_read_file_preview_clamps_huge_max_bytes():
    captured = {}

    async def fake_org_get(path, params=None, pc="default"):
        captured["max_bytes"] = params["max_bytes"]
        return {"content": "ok"}

    with patch.object(srv, "_org_get", new=fake_org_get):
        asyncio.run(srv.pc_read_file_preview("C:\\x.txt", max_bytes=10_000_000_000, pc="desktop"))
    assert captured["max_bytes"] == srv._PC_PREVIEW_MAX_BYTES_CEILING


def test_pc_read_file_preview_handles_zero_or_negative():
    captured = {}

    async def fake_org_get(path, params=None, pc="default"):
        captured["max_bytes"] = params["max_bytes"]
        return {"content": "ok"}

    with patch.object(srv, "_org_get", new=fake_org_get):
        asyncio.run(srv.pc_read_file_preview("x.txt", max_bytes=-5, pc="desktop"))
    assert captured["max_bytes"] == 4096


def test_pc_read_file_preview_passes_through_reasonable_value():
    captured = {}

    async def fake_org_get(path, params=None, pc="default"):
        captured["max_bytes"] = params["max_bytes"]
        return {"content": "ok"}

    with patch.object(srv, "_org_get", new=fake_org_get):
        asyncio.run(srv.pc_read_file_preview("x.txt", max_bytes=8192, pc="desktop"))
    assert captured["max_bytes"] == 8192


def test_get_token_rejects_unknown_account():
    try:
        srv._get_token("teritary")  # typo
        assert False, "should have raised"
    except ValueError as e:
        assert "teritary" in str(e)


def test_get_token_still_accepts_valid_accounts(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok-primary")
    tok, acct = srv._get_token("auto")
    assert acct == "primary"
    tok, acct = srv._get_token("primary")
    assert acct == "primary"


def test_file_transfer_rejects_empty_pc_name():
    try:
        srv._parse_location("pc::/some/path")
        assert False, "should have raised"
    except ValueError as e:
        assert "empty name" in str(e)


def test_file_transfer_rejects_empty_codespace_name():
    try:
        srv._parse_location("codespace::/some/path")
        assert False, "should have raised"
    except ValueError as e:
        assert "empty name" in str(e)


def test_file_transfer_still_accepts_valid_pc_and_codespace_addresses():
    assert srv._parse_location("pc:desktop:/x") == ("pc", "desktop", "/x")
    assert srv._parse_location("codespace:my-space:/x") == ("codespace", "my-space", "/x")
    assert srv._parse_location("codespace:my-space@tertiary:/x") == ("codespace", "my-space@tertiary", "/x")
