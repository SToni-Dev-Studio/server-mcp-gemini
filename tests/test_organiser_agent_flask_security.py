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


def test_flask_secret_comparison_documented_as_non_constant_time():
    """Documents (does not fix): _check_auth() uses a plain `!=` string
    comparison for the secret, same category of timing side-channel as
    the C++ version's `hdr != g_secret` (finding 5). Practical
    exploitability is low (loopback-only), same caveat as before."""
    import inspect
    spec = importlib.util.spec_from_file_location(
        "organiser_agent_flask_src_check",
        os.path.join(REPO_ROOT, "organiser-agent.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    # don't exec_module here (would start reading real env/config) --
    # just read the source text for this specific check.
    src = open(os.path.join(REPO_ROOT, "organiser-agent.py")).read()
    assert 'request.headers.get("X-Organiser-Secret", "") != SECRET' in src, (
        "if this assertion fails because the comparison was changed to "
        "something constant-time (e.g. hmac.compare_digest), that's a "
        "genuine improvement -- update SECURITY_FINDINGS.md finding 5's "
        "coverage note rather than just fixing this test"
    )
