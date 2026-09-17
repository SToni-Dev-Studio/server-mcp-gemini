"""
Security regression tests for organiser-agent.py (the Flask-based
alternative PC agent implementation -- a separate, parallel codebase from
organiser-agent.cpp, for users who prefer `pip install flask` over
compiling C++).

Uses Flask's own test client (no real network, no real infra) with an
isolated $HOME per test so the persisted machine.json config file never
leaks state between tests or into whatever real $HOME this sandbox has.
"""
import importlib.util
import os
import shutil
import sys
import tempfile

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def flask_app(monkeypatch):
    isolated_home = tempfile.mkdtemp(prefix="flask-organiser-test-home-")
    monkeypatch.setenv("HOME", isolated_home)
    monkeypatch.setenv("XDG_CONFIG_HOME", os.path.join(isolated_home, ".config"))
    monkeypatch.delenv("ORGANISER_SECRET", raising=False)
    monkeypatch.delenv("ORGANISER_MACHINE_NAME", raising=False)

    spec = importlib.util.spec_from_file_location(
        f"organiser_agent_flask_{id(monkeypatch)}",
        os.path.join(REPO_ROOT, "organiser-agent.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.app.test_client()


def test_unauthenticated_config_post_can_no_longer_hijack_flask_agent(flask_app):
    """FIXED (was: succeeded, HIGH severity). Same finding (20) as
    organiser-agent.cpp -- was a design-level gap in the "/config with no
    auth when unconfigured" pattern, independently replicated into both
    implementations, and fixed in both by pc-agent (organiser-agent.py's
    update_config gets the same bootstrap guard as the C++ h_post_config)."""
    client = flask_app

    r = client.get("/status")
    assert r.status_code == 200

    r = client.post("/config", json={"secret": "attacker-flask-secret"})
    assert r.status_code == 403, (
        f"REGRESSION: got {r.status_code}, expected 403 -- if this now "
        f"succeeds again, the finding-20 fix was reverted or bypassed "
        f"in the Flask implementation."
    )

    r = client.get("/status")
    assert r.status_code == 200  # never locked out -- nothing was set

    r = client.get("/status", headers={"X-Organiser-Secret": "attacker-flask-secret"})
    assert r.status_code == 200  # still open baseline, not "secret accepted"


def test_flask_config_endpoint_never_leaks_secret_value(flask_app):
    client = flask_app
    client.post("/config", json={"secret": "s3cr3t-should-not-leak"})
    r = client.get("/config", headers={"X-Organiser-Secret": "s3cr3t-should-not-leak"})
    assert r.status_code == 200
    assert "s3cr3t-should-not-leak" not in r.get_data(as_text=True)


def test_flask_working_dir_is_never_shell_text(flask_app, tmp_path):
    """Confirms the Flask implementation does NOT have the C++ version's
    (now-fixed) working_dir shell-injection bug -- it never had it in the
    first place, since subprocess.run(cwd=...) handles the directory
    change via the OS directly, never via shell string concatenation."""
    client = flask_app
    marker = tmp_path / "PWNED_FLASK_WORKING_DIR"
    payload_working_dir = f"x' ; touch {marker} ; echo '"
    r = client.post("/run_command", json={
        "command": "echo should_not_matter", "working_dir": payload_working_dir,
    })
    assert r.status_code == 400  # not a real directory -> clean rejection
    assert not marker.exists()


def test_flask_secret_comparison_is_constant_time_FIXED():
    """FIXED (previously finding 5's Flask-side analog): _check_auth now
    uses hmac.compare_digest instead of a plain `!=` comparison, matching
    the pattern server.py already used."""
    src = open(os.path.join(REPO_ROOT, "organiser-agent.py")).read()
    assert "hmac.compare_digest" in src, (
        "if this now fails, the constant-time fix was reverted or "
        "reworded -- re-verify end-to-end before re-flagging finding 5 "
        "as open again"
    )
    assert 'request.headers.get("X-Organiser-Secret", "") != SECRET' not in src


def test_flask_secret_comparison_fix_works_end_to_end(monkeypatch):
    """Dynamic end-to-end proof, not just a source-text check: with a
    real secret configured, wrong/missing credentials are rejected and
    the correct one is accepted."""
    isolated_home = tempfile.mkdtemp(prefix="flask-organiser-secret-test-")
    monkeypatch.setenv("HOME", isolated_home)
    monkeypatch.setenv("XDG_CONFIG_HOME", os.path.join(isolated_home, ".config"))
    monkeypatch.setenv("ORGANISER_SECRET", "test-secret-end-to-end-verify")
    monkeypatch.delenv("ORGANISER_MACHINE_NAME", raising=False)

    spec = importlib.util.spec_from_file_location(
        "organiser_agent_flask_secret_e2e",
        os.path.join(REPO_ROOT, "organiser-agent.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    client = mod.app.test_client()

    assert client.get("/status", headers={"X-Organiser-Secret": "wrong"}).status_code == 401
    assert client.get("/status").status_code == 401  # no header at all
    assert client.get(
        "/status", headers={"X-Organiser-Secret": "test-secret-end-to-end-verify"}
    ).status_code == 200


def test_preview_of_binary_file_is_SILENTLY_CORRUPTED_not_a_clean_failure(flask_app, tmp_path):
    """NEW finding (24): unlike organiser-agent.cpp's /preview (whose
    raw-byte passthrough happens to produce invalid UTF-8 for real
    binary content, which a downstream strict-decode hop then turns
    into a clean error -- see finding 13), organiser-agent.py's
    /preview opens the file with errors="replace":

        with open(path, "r", encoding="utf-8", errors="replace") as f:

    This means invalid UTF-8 bytes are silently replaced with U+FFFD
    *before* the JSON response is ever serialized -- so the raw HTTP
    response bytes are themselves ALREADY valid UTF-8. Nothing
    downstream (including the exact safety net that saves the C++
    version) can detect anything went wrong, because nothing did, from
    a "was this valid UTF-8" point of view -- data was just silently
    altered. HTTP 200, no error, no truncated/corrupted flag -- just
    wrong content that looks plausible.

    This matters because pc_read_file_preview (the MCP tool that calls
    this endpoint) has no enforcement that the target is actually a
    text file -- its docstring says "text file" but an AI agent
    "peeking" at an unknown file, which is exactly this tool's stated
    use case, will routinely hit binary files by accident. Contrast
    with /read_file_b64 (this file's OWN binary-safe endpoint,
    correctly implemented) and file_transfer's pc: leg (which correctly
    uses /read_file_b64, not /preview, for exactly this reason)."""
    client = flask_app
    binfile = tmp_path / "binary_test.bin"
    binfile.write_bytes(bytes(range(256)) * 4)

    r = client.get(f"/preview?path={binfile}&max_bytes=4096")
    assert r.status_code == 200, (
        "if this now returns an error instead, the endpoint may have "
        "been changed to detect/reject binary content -- update "
        "SECURITY_FINDINGS.md finding 24 to mark it resolved rather "
        "than just adjusting this test"
    )
    content = r.get_json()["content"]
    assert "\ufffd" in content, "expected silent replacement-character corruption"

    raw_response_bytes = r.get_data()
    # the crux of the finding: the WIRE bytes are already valid UTF-8,
    # so no strict-decode safety net anywhere downstream can catch this.
    raw_response_bytes.decode("utf-8")  # must not raise


def test_flask_agent_binds_all_interfaces_not_loopback_only():
    """NEW finding (25, HIGH — but see severity caveat in
    SECURITY_FINDINGS.md re: this file's "legacy, do not deploy"
    status): organiser-agent.cpp deliberately binds INADDR_LOOPBACK
    (127.0.0.1) with an explicit comment explaining why -- the whole
    SSH-tunnel security model depends on this agent being unreachable
    except through that tunnel. organiser-agent.py instead calls:

        app.run(host="0.0.0.0", port=PORT, debug=False)

    -- binding to EVERY network interface. Confirmed by actually
    starting the real Flask dev server as a subprocess: its own startup
    banner reports "Running on all addresses (0.0.0.0)" and lists a
    real non-loopback address (whatever this host's actual interface
    is) as directly reachable, alongside 127.0.0.1.

    This directly CONTRADICTS the access-control model this same file's
    own comments describe in two separate places (near /config and
    /admin): "It relies on the same loopback binding as every other
    endpoint here for its access control" and "This mirrors how the
    other endpoints are protected: loopback bind + optional secret
    header." Those comments describe a security property the code does
    not actually have.

    Combined with finding 3 (no secret configured = fully open) and
    finding 20 (unauthenticated /config can permanently hijack), this
    turns "needs local code execution on the machine" into "needs only
    network reachability to the machine" for anyone during either
    exposure window -- and the file's OWN documented deployment method
    (its startup banner tells you to run `ngrok http <port>` and
    publish the resulting URL) would extend that reachability to the
    public internet.

    Confirmed by starting the real subprocess and reading its own
    stdout, not just grepping the source (a source grep alone wouldn't
    prove Flask actually acts on the host="0.0.0.0" argument the way
    the comments assume it doesn't)."""
    import subprocess
    import time as _time

    isolated_home = tempfile.mkdtemp(prefix="flask-bind-check-")
    port = 0
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    env = dict(os.environ)
    env["HOME"] = isolated_home
    env["XDG_CONFIG_HOME"] = os.path.join(isolated_home, ".config")
    env["ORGANISER_PORT"] = str(port)
    env.pop("ORGANISER_SECRET", None)

    proc = subprocess.Popen(
        ["python3", os.path.join(REPO_ROOT, "organiser-agent.py")],
        cwd=REPO_ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        banner = ""
        deadline = _time.time() + 5
        while _time.time() < deadline:
            line = proc.stdout.readline()
            banner += line
            if "Running on all addresses" in banner or "Running on http" in banner and "127.0.0.1" not in line and line.strip():
                pass
            if proc.poll() is not None:
                break
            if "Press CTRL+C to quit" in banner:
                break
        assert "Running on all addresses (0.0.0.0)" in banner, (
            f"if this now says something else (e.g. binding to "
            f"127.0.0.1 only), the binding was fixed -- update "
            f"SECURITY_FINDINGS.md finding 25 to mark it resolved "
            f"rather than adjusting this test. Actual banner:\n{banner}"
        )
    finally:
        proc.kill()
        proc.wait(timeout=5)
        shutil.rmtree(isolated_home, ignore_errors=True)


def test_flask_agent_comments_claim_loopback_binding_that_does_not_exist():
    """Documents the specific mismatch between this file's own stated
    security model and its actual code, as a standing regression check
    on the comments themselves -- if someone "fixes" the bind address
    without updating these comments (or vice versa), this test should
    catch the drift either way."""
    src = open(os.path.join(REPO_ROOT, "organiser-agent.py")).read()
    assert "loopback binding" in src or "loopback bind" in src, (
        "the comments asserting a loopback-binding security model seem "
        "to have been removed -- if that's because the bind address "
        "was also fixed to match, great, update SECURITY_FINDINGS.md "
        "finding 25 accordingly"
    )
    assert 'host="0.0.0.0"' in src, (
        "if this fails because the bind address was changed to "
        "127.0.0.1, the comments' claim is now TRUE -- update "
        "SECURITY_FINDINGS.md finding 25 to mark it resolved"
    )
