import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server


class FakeProcess:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout.encode()
        self.stderr = stderr.encode()

    async def communicate(self):
        return self.stdout, self.stderr


@pytest.mark.asyncio
async def test_ssh_server_uses_configured_regular_ssh(monkeypatch):
    calls = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        calls.append(args)
        return FakeProcess(0, stdout="server output")

    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(server, "SERVER_HOST", "server.example.test")
    monkeypatch.setattr(server, "SERVER_USER", "deploy")
    monkeypatch.setattr(server, "SERVER_SSH_PORT", 2222)
    monkeypatch.setattr(server, "SERVER_SSH_KEY", "")

    result = await server._ssh_server("id")

    assert result == "server output"
    assert len(calls) == 1
    assert calls[0][0] == "ssh"
    assert calls[0][calls[0].index("-p") + 1] == "2222"
    assert calls[0][-2:] == ("deploy@server.example.test", "id")


@pytest.mark.asyncio
async def test_ssh_server_reports_connection_failure_without_fallback(monkeypatch):
    calls = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        calls.append(args)
        return FakeProcess(255, stderr="ssh: connect to host failed: Connection timed out")

    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(server, "SERVER_HOST", "server.example.test")
    monkeypatch.setattr(server, "SERVER_USER", "deploy")
    monkeypatch.setattr(server, "SERVER_SSH_PORT", 22)
    monkeypatch.setattr(server, "SERVER_SSH_KEY", "")

    result = await server._ssh_server("id")

    assert result == (
        "SSH to deploy@server.example.test:22 exited with status 255: "
        "ssh: connect to host failed: Connection timed out"
    )
    assert len(calls) == 1
    assert calls[0][0] == "ssh"
