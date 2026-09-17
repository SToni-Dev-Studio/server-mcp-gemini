"""
Tests for scripts/hub-cli.py.

Runs the script as a real subprocess (not importlib-loaded and called
in-process) for most of these, since the whole point of a CLI is its
argument parsing + process exit codes + stdout/stderr contract, and that
can only be genuinely verified by actually invoking it as a process, the
same way a sysadmin or a systemd unit would. Isolated from the real
system via HUB_CLI_PC_TUNNEL_DIR / HUB_CLI_CONFIG_PATH / HUB_CLI_RENDER_API
env var overrides (all three added to hub-cli.py specifically so this is
possible without needing to touch real /etc paths or the real Render API
in a test run).

The render subcommands are tested against tests/_fake_render_api.py, a
real (if minimal) local HTTP server -- not a mocked urllib.request.Request
call -- so these tests catch real bugs in URL construction, header
formatting, and JSON body shape, not just "was some function called".
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import _fake_render_api  # noqa: E402

SCRIPT = Path(__file__).parent.parent / "scripts" / "hub-cli.py"


def run_cli(args, env_overrides=None, cwd=None):
    env = dict(os.environ)
    env.update(env_overrides or {})
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], env=env, capture_output=True, text=True, timeout=15
    )


@pytest.fixture
def isolated_env(tmp_path):
    return {
        "HUB_CLI_PC_TUNNEL_DIR": str(tmp_path / "pc-tunnel"),
        "HUB_CLI_CONFIG_PATH": str(tmp_path / "hub-cli-config.json"),
        # See hub-cli.py's _require_root() -- CI runners aren't root, and
        # neither is every dev machine, so root-gated subcommands need
        # this to be testable at all. NEVER set this outside tests.
        "HUB_CLI_SKIP_ROOT_CHECK": "1",
    }


def test_root_is_actually_enforced_without_the_test_bypass(tmp_path):
    """The inverse of isolated_env's bypass -- confirms _require_root()
    really does gate these commands when HUB_CLI_SKIP_ROOT_CHECK isn't
    set, by explicitly clearing it and any real root-equivalent state
    this process might have. If this test can't be made to fail root's
    check (e.g. the test runner itself is actually root), it's skipped
    rather than giving a false pass -- asserting behavior this process
    is incapable of triggering would be meaningless, not a real
    verification."""
    if os.geteuid() == 0:
        pytest.skip("this test process is itself root, so _require_root() cannot be exercised as non-root here")
    env = {
        "HUB_CLI_PC_TUNNEL_DIR": str(tmp_path / "pc-tunnel"),
        "HUB_CLI_CONFIG_PATH": str(tmp_path / "hub-cli-config.json"),
    }
    env.pop("HUB_CLI_SKIP_ROOT_CHECK", None)
    r = run_cli(["pc", "add", "desktop", "192.168.1.50"], env)
    assert r.returncode != 0
    assert "needs root" in r.stderr


# ---------------------------------------------------------------------------
# pc list / add / remove -- real subprocess, real filesystem (isolated tmp_path)
# ---------------------------------------------------------------------------

def test_pc_list_empty(isolated_env):
    r = run_cli(["pc", "list"], isolated_env)
    assert r.returncode == 0
    assert "No PCs configured" in r.stdout


def test_pc_add_writes_conf_file(isolated_env, tmp_path):
    r = run_cli(["pc", "add", "desktop", "192.168.1.50", "--port", "7842"], isolated_env)
    assert "Wrote" in r.stdout
    conf = tmp_path / "pc-tunnel" / "desktop.conf"
    assert conf.exists()
    content = conf.read_text()
    assert "PC_IP=192.168.1.50" in content
    assert "PORT=7842" in content


def test_pc_add_default_port_is_7842(isolated_env, tmp_path):
    run_cli(["pc", "add", "laptop", "10.0.0.5"], isolated_env)
    content = (tmp_path / "pc-tunnel" / "laptop.conf").read_text()
    assert "PORT=7842" in content


def test_pc_add_refuses_to_overwrite_without_force(isolated_env, tmp_path):
    run_cli(["pc", "add", "desktop", "192.168.1.50"], isolated_env)
    r = run_cli(["pc", "add", "desktop", "10.10.10.10"], isolated_env)
    assert r.returncode != 0
    assert "already exists" in r.stderr
    # original value preserved, not silently overwritten
    assert "192.168.1.50" in (tmp_path / "pc-tunnel" / "desktop.conf").read_text()


def test_pc_add_force_does_overwrite(isolated_env, tmp_path):
    run_cli(["pc", "add", "desktop", "192.168.1.50"], isolated_env)
    run_cli(["pc", "add", "desktop", "10.10.10.10", "--force"], isolated_env)
    assert "10.10.10.10" in (tmp_path / "pc-tunnel" / "desktop.conf").read_text()


def test_pc_list_shows_added_pc(isolated_env):
    run_cli(["pc", "add", "desktop", "192.168.1.50", "--port", "9999"], isolated_env)
    r = run_cli(["pc", "list"], isolated_env)
    assert "desktop" in r.stdout
    assert "192.168.1.50" in r.stdout
    assert "9999" in r.stdout
    assert "pinned=NO" in r.stdout  # no known_hosts.d/desktop yet


def test_pc_remove_deletes_conf_and_pin(isolated_env, tmp_path):
    run_cli(["pc", "add", "desktop", "192.168.1.50"], isolated_env)
    known_hosts_dir = tmp_path / "pc-tunnel" / "known_hosts.d"
    known_hosts_dir.mkdir()
    (known_hosts_dir / "desktop").write_text("fake pinned key\n")

    r = run_cli(["pc", "remove", "desktop"], isolated_env)
    assert r.returncode == 0
    assert not (tmp_path / "pc-tunnel" / "desktop.conf").exists()
    assert not (known_hosts_dir / "desktop").exists()


def test_pc_remove_nonexistent_pc_fails_cleanly(isolated_env):
    r = run_cli(["pc", "remove", "ghost"], isolated_env)
    assert r.returncode != 0
    assert "no such PC" in r.stderr


def test_pc_pin_nonexistent_pc_fails_cleanly(isolated_env):
    r = run_cli(["pc", "pin", "ghost"], isolated_env)
    assert r.returncode != 0
    assert "no such PC" in r.stderr


def test_pc_pin_unreachable_ip_fails_cleanly(isolated_env):
    run_cli(["pc", "add", "unreachable", "192.0.2.1"], isolated_env)  # TEST-NET-1, guaranteed unroutable
    r = run_cli(["pc", "pin", "unreachable"], isolated_env)
    assert r.returncode != 0
    assert "ssh-keyscan" in r.stderr


# ---------------------------------------------------------------------------
# config show / set-render-credentials -- real subprocess, real filesystem
# ---------------------------------------------------------------------------

def test_config_show_before_any_setup(isolated_env):
    r = run_cli(["config", "show"], isolated_env)
    assert r.returncode == 0
    assert "NOT set" in r.stdout


def test_config_set_render_credentials_persists_with_0600(isolated_env, tmp_path):
    r = run_cli(
        ["config", "set-render-credentials", "--api-key", "secret123", "--service-id", "srv-abc"],
        isolated_env,
    )
    assert r.returncode == 0
    cfg_path = tmp_path / "hub-cli-config.json"
    assert cfg_path.exists()
    assert oct(cfg_path.stat().st_mode)[-3:] == "600"
    data = json.loads(cfg_path.read_text())
    assert data["render_api_key"] == "secret123"
    assert data["render_service_id"] == "srv-abc"


def test_config_show_never_prints_the_actual_secret_value(isolated_env):
    run_cli(["config", "set-render-credentials", "--api-key", "supersecretvalue123"], isolated_env)
    r = run_cli(["config", "show"], isolated_env)
    assert "supersecretvalue123" not in r.stdout
    assert "set" in r.stdout  # just confirms presence, not the value


# ---------------------------------------------------------------------------
# render get/set/deploy -- real subprocess, real local HTTP server (not mocked)
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_render_server():
    server = _fake_render_api.start(port=18091)
    time.sleep(0.2)
    yield server
    server.shutdown()


@pytest.fixture
def render_env(isolated_env):
    return {
        **isolated_env,
        "HUB_CLI_RENDER_API": "http://127.0.0.1:18091",
        "RENDER_API_KEY": "test-key-abc",
        "RENDER_SERVICE_ID": "srv-test",
    }


def test_render_get_existing_key(fake_render_server, render_env):
    r = run_cli(["render", "get", "MCP_SERVER_PASSWORD"], render_env)
    assert r.returncode == 0
    assert r.stdout.strip() == "supersecret"
    method, path, auth, _ = _fake_render_api.received[-1]
    assert method == "GET"
    assert path == "/services/srv-test/env-vars"
    assert auth == "Bearer test-key-abc"


def test_render_get_missing_key(fake_render_server, render_env):
    r = run_cli(["render", "get", "NO_SUCH_KEY"], render_env)
    assert r.returncode != 0
    assert "no such env var" in r.stderr


def test_render_set_sends_correct_put(fake_render_server, render_env):
    r = run_cli(["render", "set", "ADMIN_PASSWORD", "newvalue"], render_env)
    assert r.returncode == 0
    method, path, auth, body = _fake_render_api.received[-1]
    assert method == "PUT"
    assert path == "/services/srv-test/env-vars/ADMIN_PASSWORD"
    assert body == {"value": "newvalue"}
    assert auth == "Bearer test-key-abc"


def test_render_set_does_not_auto_deploy(fake_render_server, render_env):
    """Matches /admin's own behavior deliberately -- a bad value
    shouldn't auto-propagate to production."""
    run_cli(["render", "set", "ADMIN_PASSWORD", "newvalue"], render_env)
    methods = [m for m, *_ in _fake_render_api.received]
    assert "POST" not in methods  # no deploy call triggered


def test_render_deploy_sends_correct_post(fake_render_server, render_env):
    r = run_cli(["render", "deploy"], render_env)
    assert r.returncode == 0
    method, path, auth, body = _fake_render_api.received[-1]
    assert method == "POST"
    assert path == "/services/srv-test/deploys"
    assert body == {"clearCache": "do_not_clear"}


def test_render_get_without_credentials_fails_cleanly(isolated_env):
    env = {**isolated_env, "HUB_CLI_RENDER_API": "http://127.0.0.1:1"}
    env.pop("RENDER_API_KEY", None)
    env.pop("RENDER_SERVICE_ID", None)
    r = run_cli(["render", "get", "SOMEKEY"], env)
    assert r.returncode != 0
    assert "credentials not configured" in r.stderr


def test_render_credentials_can_come_from_saved_config_not_just_env(fake_render_server, isolated_env):
    # Save credentials via `config set-render-credentials` first, then
    # confirm `render get` picks them up WITHOUT any RENDER_API_KEY /
    # RENDER_SERVICE_ID env vars set -- this is the whole point of
    # config set-render-credentials existing (so you don't have to pass
    # secrets as env vars / CLI args every single invocation).
    env = {**isolated_env, "HUB_CLI_RENDER_API": "http://127.0.0.1:18091"}
    run_cli(["config", "set-render-credentials", "--api-key", "test-key-abc", "--service-id", "srv-test"], env)
    r = run_cli(["render", "get", "MCP_SERVER_PASSWORD"], env)
    assert r.returncode == 0
    assert r.stdout.strip() == "supersecret"


# ---------------------------------------------------------------------------
# argument parsing sanity
# ---------------------------------------------------------------------------

def test_no_subcommand_fails_with_usage(isolated_env):
    r = run_cli([], isolated_env)
    assert r.returncode != 0


def test_help_text_runs_without_crashing():
    r = run_cli(["--help"])
    assert r.returncode == 0
    assert "hub-cli" in r.stdout
