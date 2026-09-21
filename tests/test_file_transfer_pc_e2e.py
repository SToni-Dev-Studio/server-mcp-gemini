"""
Two-layer verification of file_transfer's pc: leg, split honestly by what
can actually be tested from this environment:

1. test_organiser_agent_binary_endpoints_binary_roundtrip -- REAL HTTP
   against a compiled, running organiser-agent binary, proving
   /read_file_b64 and /write_file's content_b64 field genuinely work as
   a binary-safe pair. This is real, not mocked.

2. test_server_file_transfer_calls_binary_safe_endpoints -- mocked at the
   _org_get/_org_post layer, proving server.py's file_transfer pc: leg
   calls /read_file_b64 and /write_file(content_b64) with correctly
   shaped requests. This is NOT a full end-to-end test.

What's genuinely NOT tested here, and can't be from this sandbox:
file_transfer's pc: leg actually routes through _organiser_ssh_request,
which SSHes to the real home Linux hub, which then reaches the PC over
an SSH-tunneled loopback port -- there's no real hub or tunnel reachable
from this environment to exercise that full path. hub-cicd or security-qa
should run a true end-to-end pc: transfer against real staging
infrastructure once available; this file proves both halves work
correctly in isolation, not that the full chain between them does.
"""

import os
import sys
import shutil
import socket
import subprocess
import time
import contextlib
import asyncio
import base64
import urllib.request
import urllib.error
import json

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("PORT", "8000")

import server as srv

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CPP_SRC = os.path.join(REPO_ROOT, "organiser-agent.cpp")

pytestmark = pytest.mark.skipif(shutil.which("g++") is None, reason="g++ not available")


@pytest.fixture(scope="module")
def agent_binary(tmp_path_factory):
    out = str(tmp_path_factory.mktemp("bin") / "organiser-agent-e2e")
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-o", out, CPP_SRC, "-lpthread"],
        check=True,
        capture_output=True,
    )
    return out


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextlib.contextmanager
def running_agent(binary_path):
    port = _free_port()
    env = dict(os.environ)
    env["ORGANISER_PORT"] = str(port)
    env["ORGANISER_SECRET"] = ""
    proc = subprocess.Popen(
        [binary_path], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{base}/status", timeout=0.5)
                break
            except Exception:
                time.sleep(0.1)
        else:
            proc.kill()
            raise RuntimeError("agent never came up")
        yield base
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_organiser_agent_binary_endpoints_binary_roundtrip_SMALL_PAYLOAD(
    agent_binary, tmp_path
):
    """REAL HTTP against a real running binary. Confirms every one of 256
    distinct byte values survives a round trip through content_b64 /
    read_file_b64.

    NOTE: an earlier version of this test used a 128,000-byte payload and
    caught finding 7 independently -- the write silently succeeded
    (HTTP 200) but only wrote 48,981 of 128,000 bytes. That's now fixed
    (see test_organiser_agent_no_longer_has_the_64kb_truncation_bug
    below) -- this test's payload size no longer matters for correctness,
    kept modest just because it doesn't need to be large to prove the
    byte-range round-trips correctly.
    """
    with running_agent(agent_binary) as base:
        target = str(tmp_path / "roundtrip.bin")
        binary_content = (
            bytes(range(256)) * 100
        )  # 25,600 bytes -- comfortably under the 64KB buffer
        encoded = base64.b64encode(binary_content).decode("ascii")

        req = urllib.request.Request(
            f"{base}/write_file",
            data=json.dumps({"path": target, "content_b64": encoded}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200

        with urllib.request.urlopen(
            f"{base}/read_file_b64?path={target}", timeout=5
        ) as resp:
            body = json.loads(resp.read())
        readback = base64.b64decode(body["content_b64"])
        assert readback == binary_content, (
            "binary content corrupted by the agent's own endpoints"
        )
        assert body["truncated"] is False


def test_organiser_agent_no_longer_has_the_64kb_truncation_bug(agent_binary, tmp_path):
    """FIXED by pc-agent (agent/pc-agent commit 86caa29, merged into main):
    finding 7 (SECURITY_FINDINGS.md) -- organiser-agent.cpp's handle_conn
    used a fixed 65536-byte buffer and silently stopped reading once full,
    regardless of the declared Content-Length, reporting HTTP 200
    "success" on the truncated write. Replaced with a growable read that
    keeps reading until the declared Content-Length is actually satisfied
    (or cleanly rejects with 413 if it's over a 25MB hard ceiling, or 400
    if the connection drops early) -- never silently short.

    This test originally proved the bug with this exact 128,000-byte
    payload (silently landed as 48,981 bytes). Per its own original
    instruction ("if this starts failing because organiser-agent.cpp got
    a proper Content-Length-aware read loop, that's GOOD -- raise
    _PC_TRANSFER_SAFE_MAX_BYTES back toward _FILE_TRANSFER_MAX_BYTES in
    server.py and update this test rather than just deleting it") --
    inverted to confirm the fix holds, and _PC_TRANSFER_SAFE_MAX_BYTES
    has been raised to match _FILE_TRANSFER_MAX_BYTES (15MB) since the
    underlying reason for the lower cap no longer applies.
    """
    with running_agent(agent_binary) as base:
        target = str(tmp_path / "oversized.bin")
        binary_content = (
            bytes(range(256)) * 500
        )  # 128,000 bytes -- the exact payload that originally caught this bug
        encoded = base64.b64encode(binary_content).decode("ascii")

        req = urllib.request.Request(
            f"{base}/write_file",
            data=json.dumps({"path": target, "content_b64": encoded}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200

        with open(target, "rb") as f:
            on_disk = f.read()
        assert on_disk == binary_content, (
            "REGRESSION: finding 7 (silent request-body truncation) is "
            "back -- organiser-agent wrote fewer bytes than were sent. "
            "If this starts failing, lower _PC_TRANSFER_SAFE_MAX_BYTES "
            "in server.py back down and re-open SECURITY_FINDINGS.md "
            "finding 7 as unfixed."
        )


def test_server_file_transfer_calls_binary_safe_endpoints(monkeypatch, tmp_path):
    """Mocked at _org_get/_org_post: proves file_transfer's pc: leg calls
    the NEW binary-safe endpoints with correctly shaped requests, not the
    old text-only /preview / content= pair."""
    calls = {}

    async def fake_org_get(path, params=None, pc="default"):
        calls["get_path"] = path
        calls["get_params"] = params
        return {"content_b64": base64.b64encode(b"\x00\x01\xff hello").decode("ascii")}

    async def fake_org_post(path, body=None, pc="default"):
        calls["post_path"] = path
        calls["post_body"] = body
        return {"message": "ok"}

    monkeypatch.setattr(srv, "_org_get", fake_org_get)
    monkeypatch.setattr(srv, "_org_post", fake_org_post)

    # read side
    data = asyncio.run(srv._location_read_bytes("pc:desktop:C:\\some\\file.bin"))
    assert calls["get_path"] == "/read_file_b64"
    assert data == b"\x00\x01\xff hello"

    # write side
    asyncio.run(
        srv._location_write_bytes("pc:desktop:C:\\some\\dest.bin", b"\x02\x03binary")
    )
    assert calls["post_path"] == "/write_file"
    assert "content_b64" in calls["post_body"]
    assert "content" not in calls["post_body"], (
        "should send content_b64, not the old text content field"
    )
    assert base64.b64decode(calls["post_body"]["content_b64"]) == b"\x02\x03binary"


def test_pc_transfer_rejects_payload_over_the_safe_cap(monkeypatch):
    """Proves an oversized pc: write is rejected before it ever reaches
    the agent, with a clear message, rather than silently corrupting.

    Note: now that _PC_TRANSFER_SAFE_MAX_BYTES == _FILE_TRANSFER_MAX_BYTES
    (finding 7 is fixed, so the pc:-specific lower cap is no longer
    needed -- see the comment on _PC_TRANSFER_SAFE_MAX_BYTES in
    server.py), the general _location_write_bytes size check at the top
    of the function fires first for any payload over the cap, before
    kind-specific logic is even reached. This test checks the safety
    property that actually matters (oversized pc: writes are rejected,
    never silently truncated) rather than which specific code path or
    exact wording produces the rejection -- that's an implementation
    detail that correctly changed once finding 7 was fixed.
    """
    called = {"post": False}

    async def fake_org_post(path, body=None, pc="default"):
        called["post"] = True
        return {"message": "should never get here"}

    monkeypatch.setattr(srv, "_org_post", fake_org_post)

    oversized = b"x" * (srv._PC_TRANSFER_SAFE_MAX_BYTES + 1)
    try:
        asyncio.run(srv._location_write_bytes("pc:desktop:/tmp/x.bin", oversized))
        assert False, "should have raised ValueError"
    except ValueError as e:
        assert str(srv._PC_TRANSFER_SAFE_MAX_BYTES) in str(e) or str(
            srv._FILE_TRANSFER_MAX_BYTES
        ) in str(e)
    assert called["post"] is False, "should reject before ever calling the agent"


def test_pc_transfer_accepts_payload_within_the_safe_cap(monkeypatch):
    async def fake_org_post(path, body=None, pc="default"):
        return {"message": "ok"}

    monkeypatch.setattr(srv, "_org_post", fake_org_post)

    ok_size = srv._PC_TRANSFER_SAFE_MAX_BYTES  # exactly at the cap, inclusive
    result = asyncio.run(
        srv._location_write_bytes("pc:desktop:/tmp/x.bin", b"x" * ok_size)
    )
    assert "pc:desktop" in result
