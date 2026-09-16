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


def test_unauthenticated_config_post_can_hijack_flask_agent_too(flask_app):
    """Same finding (20) as organiser-agent.cpp, confirmed independently
    against the SEPARATE Flask implementation: this is a design-level gap
    in the "/config with no auth when unconfigured" pattern, not a
    one-off coding mistake in a single file -- it was independently
    replicated into both implementations."""
    client = flask_app

    r = client.get("/status")
    assert r.status_code == 200

    r = client.post("/config", json={"secret": "attacker-flask-secret"})
    assert r.status_code == 200

    r = client.get("/status")
    assert r.status_code == 401, (
        "if this now passes, the hijack was mitigated in the Flask "
        "implementation -- update SECURITY_FINDINGS.md finding 20 "
        "accordingly (note whether the C++ side was fixed too)"
    )

    r = client.get("/status", headers={"X-Organiser-Secret": "attacker-flask-secret"})
    assert r.status_code == 200


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
