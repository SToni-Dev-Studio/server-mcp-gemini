"""
Tests for scripts/hub-diagnostics.py.

Two kinds of coverage here, and they're not the same thing:

1. Genuinely real: check_port_listening (real sockets), check_disk_space
   (real filesystem), discover_pcs / check_pc_tunnel_config_dir (real
   temp files on disk) -- these run the actual code path with no
   stubbing at all.

2. Decision-logic tests with a stubbed `run` callable: check_systemd_available,
   check_tunnel_service, check_tailscale, check_ssh_reachable take `run`
   as a parameter specifically so a test can hand them a fake
   subprocess.CompletedProcess without needing a real systemd bus, real
   Tailscale install, or a real reachable SSH host -- none of which exist
   in a CI runner or this sandbox. This tests "does the script correctly
   classify PASS vs FAIL vs SKIPPED given a known systemctl/ssh output",
   which is the actual bug-prone part (see hub-diagnostics.py's comment
   on check_systemd_available for a real bug this exact kind of test
   would have caught immediately instead of only being noticed by
   manually running the script against this sandbox).
"""

import importlib.util
import socket
import subprocess
import sys
from pathlib import Path

import pytest

_SPEC_PATH = Path(__file__).parent.parent / "scripts" / "hub-diagnostics.py"
spec = importlib.util.spec_from_file_location("hub_diagnostics", _SPEC_PATH)
hd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hd)


def fake_run(returncode=0, stdout="", stderr="", captured_cmds=None):
    """Returns a `run(cmd, timeout=...)` callable that ignores its
    arguments and always returns a fixed CompletedProcess -- stands in for
    hub-diagnostics.py's `_run` in tests. If captured_cmds (a list) is
    passed, every cmd this is called with is appended to it, so a test
    can assert on the EXACT command built (e.g. which ssh flags were
    chosen), not just the final PASS/FAIL classification."""

    def _f(cmd, timeout=5):
        if captured_cmds is not None:
            captured_cmds.append(cmd)
        return subprocess.CompletedProcess(
            cmd, returncode=returncode, stdout=stdout, stderr=stderr
        )

    return _f


@pytest.fixture(autouse=True)
def _assume_tools_installed(monkeypatch):
    """Most decision-logic tests below are about how this script
    interprets a command's OUTPUT (active/inactive/offline/JSON), not
    about whether systemctl/ssh/tailscale happen to be installed on
    whatever machine runs the test suite -- that would make the suite
    flaky depending on the CI image. Default shutil.which to "yes,
    installed" for every tool so those tests are deterministic; the
    specific NOT_CONFIGURED/"not installed" tests override this back to
    None explicitly, which is the actual thing they're testing."""
    real_which = hd.shutil.which

    def _which(name):
        if name in ("systemctl", "ssh", "tailscale"):
            return f"/usr/bin/{name}"
        return real_which(name)

    monkeypatch.setattr(hd.shutil, "which", _which)


# ---------------------------------------------------------------------------
# Real (unstubbed) checks
# ---------------------------------------------------------------------------


def test_port_listening_pass_against_a_real_local_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))  # let the OS pick a free port
    port = srv.getsockname()[1]
    srv.listen(1)
    try:
        result = hd.check_port_listening("test", str(port))
        assert result["status"] == hd.PASS
    finally:
        srv.close()


def test_port_listening_fail_when_nothing_is_there():
    # Port 1 is a real, always-invalid target to connect to as a non-root
    # process (privileged range, nothing listens there in a sandbox).
    result = hd.check_port_listening("test", "1")
    assert result["status"] == hd.FAIL


def test_port_listening_not_configured_when_port_missing():
    result = hd.check_port_listening("test", "")
    assert result["status"] == hd.NOT_CONFIGURED


def test_port_listening_fail_on_non_numeric_port():
    result = hd.check_port_listening("test", "not-a-number")
    assert result["status"] == hd.FAIL


def test_disk_space_real_check_returns_pass_or_fail():
    result = hd.check_disk_space("/")
    assert result["status"] in (hd.PASS, hd.FAIL)
    assert "%" in result["detail"]


def test_discover_pcs_parses_real_conf_files(tmp_path):
    (tmp_path / "desktop.conf").write_text("PC_IP=192.168.1.50\nPORT=7842\n")
    (tmp_path / "laptop.conf").write_text("PORT=7843\nPC_IP=192.168.1.51\n")
    pcs = hd.discover_pcs(tmp_path)
    assert sorted(pcs) == [
        ("desktop", "192.168.1.50", "7842"),
        ("laptop", "192.168.1.51", "7843"),
    ]


def test_discover_pcs_empty_dir_returns_empty_list(tmp_path):
    assert hd.discover_pcs(tmp_path) == []


def test_discover_pcs_missing_dir_returns_empty_list_not_crash(tmp_path):
    assert hd.discover_pcs(tmp_path / "does_not_exist") == []


def test_check_pc_tunnel_config_dir_not_configured_when_missing(tmp_path):
    result = hd.check_pc_tunnel_config_dir(tmp_path / "missing")
    assert result["status"] == hd.NOT_CONFIGURED


def test_check_pc_tunnel_config_dir_pass_with_valid_configs(tmp_path):
    (tmp_path / "desktop.conf").write_text("PC_IP=192.168.1.50\nPORT=7842\n")
    result = hd.check_pc_tunnel_config_dir(tmp_path)
    assert result["status"] == hd.PASS
    assert "desktop" in result["detail"]


def test_check_pc_tunnel_config_dir_fail_on_malformed_conf(tmp_path):
    (tmp_path / "desktop.conf").write_text("PC_IP=192.168.1.50\n")  # missing PORT
    result = hd.check_pc_tunnel_config_dir(tmp_path)
    assert result["status"] == hd.FAIL
    assert "desktop" in result["detail"]


# ---------------------------------------------------------------------------
# Stubbed subprocess (`run=`) decision-logic tests
# ---------------------------------------------------------------------------


def test_systemd_available_pass_when_running():
    result = hd.check_systemd_available(run=fake_run(returncode=0, stdout="running\n"))
    assert result["status"] == hd.PASS


def test_systemd_available_pass_when_degraded():
    # "degraded" means some unrelated unit failed, not that systemd itself
    # is unusable -- our checks are still meaningful. This is the exact
    # distinction the real bug (found by manually testing against this
    # sandbox) got wrong for "offline".
    result = hd.check_systemd_available(run=fake_run(returncode=1, stdout="degraded\n"))
    assert result["status"] == hd.PASS


def test_systemd_available_skipped_when_offline():
    # Regression test for the real bug found while testing this script:
    # "offline" used to fall through to a hardcoded PASS.
    result = hd.check_systemd_available(run=fake_run(returncode=1, stdout="offline\n"))
    assert result["status"] == hd.SKIPPED


def test_systemd_available_skipped_when_unknown():
    result = hd.check_systemd_available(run=fake_run(returncode=1, stdout="unknown\n"))
    assert result["status"] == hd.SKIPPED


def test_systemd_available_skipped_on_bus_connect_failure():
    result = hd.check_systemd_available(
        run=fake_run(
            returncode=1, stdout="", stderr="Failed to connect to bus: Host is down\n"
        )
    )
    assert result["status"] == hd.SKIPPED


def test_tunnel_service_pass_when_active():
    result = hd.check_tunnel_service(
        "desktop", run=fake_run(returncode=0, stdout="active\n")
    )
    assert result["status"] == hd.PASS


@pytest.mark.parametrize("state", ["inactive", "failed", "activating", "deactivating"])
def test_tunnel_service_fail_for_known_bad_states(state):
    result = hd.check_tunnel_service(
        "desktop", run=fake_run(returncode=3, stdout=f"{state}\n")
    )
    assert result["status"] == hd.FAIL
    assert state in result["detail"]


def test_tunnel_service_skipped_on_unparseable_output():
    result = hd.check_tunnel_service(
        "desktop",
        run=fake_run(
            returncode=1, stdout="", stderr="Failed to connect to bus: Host is down\n"
        ),
    )
    assert result["status"] == hd.SKIPPED


def test_tailscale_pass_when_backend_running(monkeypatch):
    monkeypatch.setattr(hd.shutil, "which", lambda name: "/usr/bin/tailscale")
    result = hd.check_tailscale(
        run=fake_run(returncode=0, stdout='{"BackendState": "Running"}')
    )
    assert result["status"] == hd.PASS


def test_tailscale_fail_when_backend_stopped(monkeypatch):
    monkeypatch.setattr(hd.shutil, "which", lambda name: "/usr/bin/tailscale")
    result = hd.check_tailscale(
        run=fake_run(returncode=0, stdout='{"BackendState": "Stopped"}')
    )
    assert result["status"] == hd.FAIL


def test_tailscale_fail_on_bad_json(monkeypatch):
    monkeypatch.setattr(hd.shutil, "which", lambda name: "/usr/bin/tailscale")
    result = hd.check_tailscale(run=fake_run(returncode=0, stdout="not json"))
    assert result["status"] == hd.FAIL


def test_tailscale_not_configured_when_not_installed(monkeypatch):
    monkeypatch.setattr(hd.shutil, "which", lambda name: None)
    result = hd.check_tailscale(
        run=fake_run(returncode=0, stdout='{"BackendState": "Running"}')
    )
    assert result["status"] == hd.NOT_CONFIGURED


def test_ssh_reachable_pass():
    result = hd.check_ssh_reachable(
        "desktop", "192.168.1.50", "alice", run=fake_run(returncode=0, stdout="")
    )
    assert result["status"] == hd.PASS


def test_ssh_reachable_fail():
    result = hd.check_ssh_reachable(
        "desktop",
        "192.168.1.50",
        "alice",
        run=fake_run(returncode=255, stderr="Permission denied (publickey).\n"),
    )
    assert result["status"] == hd.FAIL
    assert "Permission denied" in result["detail"]


def test_ssh_reachable_not_configured_without_ip():
    result = hd.check_ssh_reachable("desktop", "", "alice")
    assert result["status"] == hd.NOT_CONFIGURED


def test_ssh_reachable_uses_accept_new_when_no_pinned_known_hosts(tmp_path):
    """When a PC hasn't been through the pinning step yet (see
    pc-tunnel@.service setup step 4), the check should fall back to
    accept-new rather than requiring a pin that doesn't exist -- and
    should say so plainly in the detail on success, since 'reachable but
    unpinned' is a meaningfully different, worth-knowing state from
    'reachable and verified against a pinned key'."""
    captured = []
    result = hd.check_ssh_reachable(
        "desktop",
        "192.168.1.50",
        "alice",
        run=fake_run(returncode=0, captured_cmds=captured),
        known_hosts_dir=tmp_path / "known_hosts.d",  # deliberately doesn't exist
    )
    assert result["status"] == hd.PASS
    assert "NOT pinned yet" in result["detail"]
    cmd = captured[0]
    assert "accept-new" in " ".join(cmd)
    assert "UserKnownHostsFile" not in " ".join(cmd)


def test_ssh_reachable_uses_pinned_known_hosts_when_available(tmp_path):
    """The real tunnel (pc-tunnel@.service) uses StrictHostKeyChecking=yes
    against a per-PC pinned known_hosts file -- this check should use the
    exact same verification, not a looser one, so it can actually catch
    a real problem (see the mismatch test below) rather than just
    confirming the port is open."""
    known_hosts_dir = tmp_path / "known_hosts.d"
    known_hosts_dir.mkdir()
    pinned_file = known_hosts_dir / "desktop"
    pinned_file.write_text("192.168.1.50 ssh-ed25519 AAAA...\n")

    captured = []
    result = hd.check_ssh_reachable(
        "desktop",
        "192.168.1.50",
        "alice",
        run=fake_run(returncode=0, captured_cmds=captured),
        known_hosts_dir=known_hosts_dir,
    )
    assert result["status"] == hd.PASS
    assert "verified against pinned known_hosts" in result["detail"]
    cmd = " ".join(captured[0])
    assert "StrictHostKeyChecking=yes" in cmd
    assert f"UserKnownHostsFile={pinned_file}" in cmd
    assert "accept-new" not in cmd


def test_ssh_reachable_flags_host_key_mismatch_distinctly(tmp_path):
    """A pinned host key that no longer matches (MITM, or the PC's SSH
    host keys were regenerated and nobody re-pinned them) is a much more
    alarming failure than 'connection timed out' -- this should be
    surfaced distinctly, not buried in generic ssh stderr text."""
    known_hosts_dir = tmp_path / "known_hosts.d"
    known_hosts_dir.mkdir()
    (known_hosts_dir / "desktop").write_text("192.168.1.50 ssh-ed25519 AAAA...\n")

    result = hd.check_ssh_reachable(
        "desktop",
        "192.168.1.50",
        "alice",
        run=fake_run(
            returncode=255,
            stderr="@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n"
            "Host key verification failed.\n",
        ),
        known_hosts_dir=known_hosts_dir,
    )
    assert result["status"] == hd.FAIL
    assert "HOST KEY MISMATCH" in result["detail"]


# ---------------------------------------------------------------------------
# End-to-end: run_all() with a real temp conf dir + stubbed subprocess
# ---------------------------------------------------------------------------


def test_run_all_end_to_end_with_stubbed_success(tmp_path):
    (tmp_path / "desktop.conf").write_text("PC_IP=127.0.0.1\nPORT=17999\n")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 17999))
    srv.listen(1)
    try:
        checks = hd.run_all(
            tmp_path, ssh_user="alice", run=fake_run(returncode=0, stdout="active\n")
        )
        by_name = {c["name"]: c for c in checks}
        assert by_name["PC tunnel config directory"]["status"] == hd.PASS
        assert (
            by_name["tunnel service (pc-tunnel@desktop.service)"]["status"] == hd.PASS
        )
        assert by_name["port listening (desktop)"]["status"] == hd.PASS
    finally:
        srv.close()


def test_run_all_no_pcs_configured_is_clean_not_a_crash(tmp_path):
    checks = hd.run_all(tmp_path / "missing", ssh_user="alice", run=fake_run())
    assert any(c["status"] == hd.NOT_CONFIGURED for c in checks)
    assert not any(
        c["status"] == hd.FAIL for c in checks if "PC tunnel config" in c["name"]
    )


def test_main_exits_nonzero_on_failure(tmp_path, monkeypatch, capsys):
    (tmp_path / "desktop.conf").write_text(
        "PC_IP=127.0.0.1\nPORT=1\n"
    )  # port 1: guaranteed not listening
    monkeypatch.setattr(
        sys, "argv", ["hub-diagnostics.py", "--conf-dir", str(tmp_path), "--json"]
    )
    with pytest.raises(SystemExit) as exc_info:
        hd.main()
    assert exc_info.value.code == 1
    out = capsys.readouterr().out
    assert '"fail"' in out


def test_main_exits_zero_when_nothing_configured(tmp_path, monkeypatch):
    # Opt out of the autouse "assume tools installed" fixture here: this
    # test is specifically about the genuinely-nothing-configured,
    # nothing-installed path (tailscale really isn't on this sandbox),
    # so faking tool presence while still calling the REAL subprocess
    # runner (main() doesn't take an injected `run=`) would make
    # check_tailscale try to actually exec a nonexistent binary and
    # report FAIL for the wrong reason -- caught by running this exact
    # test and seeing it fail with "No such file or directory: 'tailscale'"
    # instead of the NOT_CONFIGURED this test is meant to verify.
    monkeypatch.setattr(hd.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        sys,
        "argv",
        ["hub-diagnostics.py", "--conf-dir", str(tmp_path / "missing"), "--json"],
    )
    with pytest.raises(SystemExit) as exc_info:
        hd.main()
    assert exc_info.value.code == 0
