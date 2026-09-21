"""
Concurrency testing, per the task brief: "fire concurrent requests at
state-changing tools (env var writes, file writes) and check for races."

Two things are verified here:
1. server.py's own in-process handling of concurrent tool calls never
   cross-contaminates data between calls (classic shared-mutable-state
   bug class) -- proven by firing genuinely concurrent async calls with
   per-call unique markers and an artificial mock delay to encourage
   interleaving, then checking each response only ever contains its own
   call's data.
2. The admin env-var-set endpoint (_admin_api_env_set) PUTs each key
   independently to Render's per-key API rather than doing a
   read-modify-write of the whole list -- so there is no local
   "lost update" race to find in server.py's own code (verified by
   reading the implementation; the actual conflict-resolution for two
   concurrent writes to the SAME key happens entirely on Render's side,
   which is real infrastructure out of scope for this engagement).

What this does NOT cover (documented, not silently skipped): races
against a REAL remote filesystem or REAL Render API (e.g. does the
Linux server's actual `cat >` redirect handle two truly-simultaneous SSH
sessions correctly) -- that needs live infrastructure, which is out of
scope for this sandbox-only engagement. See SECURITY_FINDINGS.md and
coordination/status/security-qa.md for that caveat stated plainly.
"""

import asyncio
import base64
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fresh_server():
    for k in [
        "MCP_SERVER_PASSWORD",
        "RENDER_EXTERNAL_HOSTNAME",
        "MCP_ALLOWED_HOST",
        "FLY_APP_NAME",
        "PORT",
    ]:
        os.environ.pop(k, None)
    os.environ["PORT"] = "18000"
    if "server" in sys.modules:
        importlib.reload(sys.modules["server"])
    else:
        import server  # noqa
    return sys.modules["server"]


@pytest.mark.asyncio
async def test_concurrent_writes_to_different_paths_never_cross_contaminate():
    srv = _fresh_server()
    call_log = []

    async def slow_echo_ssh_server(command, timeout=60):
        # artificial delay to force real interleaving between coroutines,
        # exactly the condition that would expose a shared-mutable-state
        # bug if server.py's tool functions used any (they use only
        # local variables per call, which is what this test confirms).
        await asyncio.sleep(0.05)
        call_log.append(command)
        return command

    srv._ssh_server = slow_echo_ssh_server

    N = 25

    async def do_write(i):
        marker = f"UNIQUE_MARKER_{i:04d}"
        path = f"/tmp/concurrency-test-{i:04d}.txt"
        result = await srv.server_write_file(path, marker)
        return i, marker, path, result

    results = await asyncio.gather(*[do_write(i) for i in range(N)])

    assert len(call_log) == N

    for i, marker, path, result in results:
        expected_b64 = base64.b64encode(marker.encode()).decode()
        assert expected_b64 in result, (
            f"call {i}'s own content missing from its own result"
        )
        assert path in result, f"call {i}'s own path missing from its own result"
        for j in range(N):
            if j == i:
                continue
            other_marker = f"UNIQUE_MARKER_{j:04d}"
            other_b64 = base64.b64encode(other_marker.encode()).decode()
            assert other_b64 not in result, (
                f"CROSS-CONTAMINATION: call {i}'s result contains call {j}'s "
                f"content -- shared mutable state bug in concurrent tool dispatch"
            )


@pytest.mark.asyncio
async def test_concurrent_writes_to_the_same_path_do_not_crash_or_hang():
    """Confirms server.py itself handles N truly-concurrent calls to the
    identical path/tool without exceptions, deadlocks, or corruption of
    its OWN process state. Which write "wins" on a real remote filesystem
    is a property of the remote SSH/filesystem layer, not this code, and
    is out of scope (real infrastructure)."""
    srv = _fresh_server()

    async def slow_ssh_server(command, timeout=60):
        await asyncio.sleep(0.02)
        return command

    srv._ssh_server = slow_ssh_server

    same_path = "/tmp/same-path-race.txt"

    async def do_write(i):
        return await srv.server_write_file(same_path, f"writer_{i}")

    results = await asyncio.wait_for(
        asyncio.gather(*[do_write(i) for i in range(20)], return_exceptions=True),
        timeout=10,
    )
    exceptions = [r for r in results if isinstance(r, Exception)]
    assert not exceptions, f"concurrent same-path writes raised: {exceptions}"
    assert len(results) == 20


def test_admin_env_set_writes_each_key_independently_not_read_modify_write():
    """Reads _admin_api_env_set's source to confirm it PUTs a single key
    to Render's per-key endpoint, rather than fetching the whole env-var
    list, mutating it, and PUTting the whole thing back. A
    read-modify-write pattern would be vulnerable to lost updates under
    concurrent edits to different keys; a per-key PUT is not."""
    import inspect

    srv = _fresh_server()
    source = inspect.getsource(srv._admin_api_env_set)
    assert "env-vars/{key}" in source, (
        "if this assertion starts failing because the implementation "
        "changed to a bulk read-modify-write pattern, that IS a new "
        "finding worth adding to SECURITY_FINDINGS.md, not just fixing "
        "this test"
    )
    assert "client.get" not in source, (
        "env-set should not need to read the existing list before writing a single key"
    )
