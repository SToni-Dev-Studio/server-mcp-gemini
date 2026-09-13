"""
Security regression tests for organiser-agent.cpp (the Windows PC agent).

These build the agent as a native Linux binary (it's written to be
cross-platform for exactly this reason -- see the top-of-file comment in
organiser-agent.cpp) and drive it over real HTTP on a loopback port. No
real infrastructure is touched: everything here is a subprocess owned by
the test, on 127.0.0.1, torn down at the end of each test.

Skips cleanly (does not fail) if g++ isn't available in the environment.

Findings this file locks in as regressions (see SECURITY_FINDINGS.md for
full writeup, severity, and remediation suggestions):
  - working_dir command injection (single-quote breakout on the Linux
    /bin/bash -c wrapping) -- CONFIRMED exploitable.
  - No-secret-configured means the auth check is skipped entirely.
  - /preview's max_bytes is attacker-controlled with no upper bound and
    is used to pre-allocate a buffer before checking the real file size.
  - Secret comparison is not constant-time (plain std::string !=).
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import contextlib
import urllib.request
import urllib.error

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CPP_SRC = os.path.join(REPO_ROOT, "organiser-agent.cpp")

pytestmark = pytest.mark.skipif(shutil.which("g++") is None, reason="g++ not available")


@pytest.fixture(scope="module")
def agent_binary(tmp_path_factory):
    build_dir = tmp_path_factory.mktemp("organiser-build")
    binary = str(build_dir / "organiser-agent")
    r = subprocess.run(
        ["g++", "-std=c++17", "-O0", "-o", binary, CPP_SRC, "-lpthread"],
        capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        pytest.fail(f"organiser-agent.cpp failed to compile:\n{r.stderr[-4000:]}")
    return binary


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextlib.contextmanager
def running_agent(binary, secret=None, extra_env=None):
    port = _free_port()
    env = os.environ.copy()
    env.pop("ORGANISER_SECRET", None)
    env["ORGANISER_PORT"] = str(port)
    if secret is not None:
        env["ORGANISER_SECRET"] = secret
    if extra_env:
        env.update(extra_env)
    proc = subprocess.Popen(binary, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{base}/status", timeout=0.5)
                break
            except urllib.error.HTTPError:
                # Any real HTTP response (even 401, when a secret is
                # configured) means the server is up and listening.
                break
            except Exception:
                if proc.poll() is not None:
                    out = proc.stdout.read().decode(errors="replace")
                    pytest.fail(f"organiser-agent exited early:\n{out}")
                time.sleep(0.1)
        else:
            pytest.fail("organiser-agent never came up on /status")
        yield base, proc
    finally:
        proc.kill()
        proc.wait(timeout=5)


def _get(base, path, headers=None):
    req = urllib.request.Request(base + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _post(base, path, body: dict, headers=None):
    data = json.dumps(body).encode()
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(base + path, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_no_secret_configured_leaves_endpoints_open(agent_binary):
    """CONFIRMED: if ORGANISER_SECRET is unset, the auth check is skipped
    entirely (organiser-agent.cpp line ~837: `if (!g_secret.empty())`)."""
    with running_agent(agent_binary, secret=None) as (base, _):
        status, body = _get(base, "/status")
        assert status == 200
        # no X-Organiser-Secret header sent at all, and it still works
        status, body = _post(base, "/run_command", {"command": "echo open_by_default"})
        assert status == 200
        assert b"open_by_default" in body


def test_secret_gate_works_when_configured(agent_binary):
    with running_agent(agent_binary, secret="s3cr3t-test") as (base, _):
        status, _ = _get(base, "/status")
        assert status == 401, "missing secret header should be rejected"
        status, _ = _get(base, "/status", headers={"X-Organiser-Secret": "wrong"})
        assert status == 401, "wrong secret should be rejected"
        status, _ = _get(base, "/status", headers={"X-Organiser-Secret": "s3cr3t-test"})
        assert status == 200, "correct secret should be accepted"


def test_working_dir_command_injection(agent_binary, tmp_path):
    """CONFIRMED EXPLOITABLE: the `working_dir` field is embedded into a
    shell string as `cd "<working_dir>" && <command>` and then wrapped in
    `/bin/bash -c '...'` with NO escaping of single quotes in
    `working_dir`. A single quote breaks out of that wrapper entirely and
    the remainder of working_dir is interpreted as new shell syntax --
    independent of, and regardless of, whatever `command` contains.

    This test proves it by injecting a `touch` via working_dir while
    `command` is an inert echo, and checking the marker file exists.
    """
    marker = tmp_path / "PWNED_VIA_WORKING_DIR"
    assert not marker.exists()
    payload_working_dir = f"x' ; touch {marker} ; echo '"
    with running_agent(agent_binary, secret=None) as (base, _):
        status, body = _post(
            base, "/run_command",
            {"command": "echo should_not_matter", "working_dir": payload_working_dir},
        )
        assert status == 200
    assert marker.exists(), (
        "working_dir shell-injection did not fire -- if this starts "
        "failing because the bug was fixed, please update "
        "SECURITY_FINDINGS.md to mark it remediated instead of just "
        "deleting this test."
    )


def test_oversized_max_bytes_does_not_crash_process(agent_binary, tmp_path):
    """/preview's max_bytes is attacker-controlled with no upper bound and
    is used to pre-allocate a std::string of that size BEFORE the actual
    file size is known. A absurd value (10 GB) against a tiny file causes
    a std::bad_alloc -- confirmed caught cleanly (HTTP 500) on this Linux
    build, process survives. Windows allocator/OOM behavior under real
    memory pressure has NOT been verified (needs a real Windows target)."""
    small_file = tmp_path / "small.bin"
    small_file.write_bytes(b"hello world")
    with running_agent(agent_binary, secret=None) as (base, proc):
        status, body = _get(base, f"/preview?path={small_file}&max_bytes=10000000000")
        assert status == 500
        assert b"bad_alloc" in body or b"error" in body
        # process must still be alive and responsive afterwards
        status2, _ = _get(base, "/status")
        assert status2 == 200, "process did not survive the oversized max_bytes request"


def test_preview_of_binary_file_returns_invalid_utf8_over_the_wire(agent_binary, tmp_path):
    """Documents (does not "fix") a real quirk: h_preview's JSON escaping
    (Json::escape) does not escape or reject bytes >= 0x80, so raw
    non-UTF-8 bytes are copied straight into the JSON response body. This
    is precisely why PC<->binary file_transfer legs must fail cleanly
    rather than silently corrupt -- see
    test_file_transfer_extra.py::test_pc_binary_read_fails_cleanly_not_corrupted
    for the server.py-side verification of that safety net."""
    binfile = tmp_path / "bin.dat"
    binfile.write_bytes(bytes(range(256)) * 4)
    with running_agent(agent_binary, secret=None) as (base, _):
        status, body = _get(base, f"/preview?path={binfile}&max_bytes=4096")
        assert status == 200
        with pytest.raises(UnicodeDecodeError):
            body.decode("utf-8")
