#!/usr/bin/env python3
"""
hub-diagnostics.py — local health check for the Linux hub server.

Complements (does NOT duplicate) server.py's `run_diagnostics` MCP tool:
that one checks reachability FROM Render's side, over the whole chain
(Render -> SSH -> hub -> tunnel -> PC). It can tell you "PC 'desktop'
unreachable" but not WHY -- is the systemd unit down? Is the port not
listening? Those questions can only be answered by running something ON
the hub, which is what this script is for.

Usage:
    python3 hub-diagnostics.py            # human-readable table
    python3 hub-diagnostics.py --json     # machine-readable, for cron/monitoring

Exit code: 0 if every check is PASS/SKIPPED/NOT_CONFIGURED, 1 if any
check is FAIL (so this is usable directly as a cron/systemd-timer health
check, not just an interactive tool).

Every check is a small, independently-callable function taking its
external commands (subprocess runner, etc.) as parameters where it
matters for testing -- see tests/test_hub_diagnostics.py, which stubs
`systemctl`/`ss`/`ssh` on PATH to test the actual decision logic
(active/inactive/not-found/timeout -> PASS/FAIL/SKIPPED) without a real
systemd bus or real PCs. That's a deliberate, documented trade-off: this
script's presence-detection and status-PARSING is genuinely tested; the
actual "is systemd reachable at all" question can only be answered on a
real Linux host with an init system, which a sandboxed dev container
generally is not (no PID 1 / no D-Bus session) -- see
coordination/status/hub-cicd.md for exactly what was and wasn't run
against live infrastructure.
"""

import argparse
import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path

PASS, FAIL, SKIPPED, NOT_CONFIGURED = "PASS", "FAIL", "SKIPPED", "NOT_CONFIGURED"

PC_TUNNEL_CONF_DIR = Path("/etc/pc-tunnel")


def _run(cmd, timeout=5):
    """Thin wrapper around subprocess so tests can monkeypatch this one
    function instead of every individual subprocess.run call."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return subprocess.CompletedProcess(cmd, returncode=-1, stdout="", stderr=str(e))


def check_result(name, status, detail=""):
    return {"name": name, "status": status, "detail": detail}


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def discover_pcs(conf_dir: Path = PC_TUNNEL_CONF_DIR) -> list:
    """Returns [(name, pc_ip, port), ...] parsed from /etc/pc-tunnel/<name>.conf
    files -- the same convention pc-tunnel@.service's EnvironmentFile uses,
    so "which PCs are configured" has exactly one source of truth shared
    between the systemd side and this diagnostic, rather than a second
    registry someone has to keep in sync by hand."""
    pcs = []
    if not conf_dir.is_dir():
        return pcs
    for conf_file in sorted(conf_dir.glob("*.conf")):
        name = conf_file.stem
        pc_ip, port = None, None
        try:
            for line in conf_file.read_text().splitlines():
                line = line.strip()
                if line.startswith("PC_IP="):
                    pc_ip = line.split("=", 1)[1].strip()
                elif line.startswith("PORT="):
                    port = line.split("=", 1)[1].strip()
        except OSError:
            continue
        pcs.append((name, pc_ip, port))
    return pcs


def check_pc_tunnel_config_dir(conf_dir: Path = PC_TUNNEL_CONF_DIR) -> dict:
    if not conf_dir.is_dir():
        return check_result(
            "PC tunnel config directory",
            NOT_CONFIGURED,
            f"{conf_dir} does not exist yet -- no PCs configured (this is expected on a fresh install)",
        )
    pcs = discover_pcs(conf_dir)
    if not pcs:
        return check_result(
            "PC tunnel config directory",
            NOT_CONFIGURED,
            f"{conf_dir} exists but has no *.conf files",
        )
    malformed = [name for name, ip, port in pcs if not ip or not port]
    if malformed:
        return check_result(
            "PC tunnel config directory",
            FAIL,
            f"{len(malformed)} malformed conf file(s) missing PC_IP or PORT: {', '.join(malformed)}",
        )
    return check_result(
        "PC tunnel config directory",
        PASS,
        f"{len(pcs)} PC(s) configured: {', '.join(n for n, _, _ in pcs)}",
    )


def check_systemd_available(run=_run) -> dict:
    if not shutil.which("systemctl"):
        return check_result(
            "systemd available", SKIPPED, "systemctl not on PATH (not a systemd host)"
        )
    r = run(["systemctl", "is-system-running"])
    state = (r.stdout or "").strip()
    # Per systemd's own documented values for `is-system-running`: "offline"
    # means the manager/bus isn't actually running at all (a container
    # without a real init process, exactly this sandbox's situation --
    # confirmed by hand: `systemctl is-system-running` here prints
    # "offline" with exit code 1, NOT a connection-refused error, so the
    # original "-1 or 'Failed to connect to bus'" check below never
    # caught it and silently fell through to PASS -- a real bug caught by
    # actually running this against the sandbox instead of assuming).
    # "unknown" similarly means no usable answer. Every other documented
    # state (running/degraded/maintenance/stopping/initializing/starting)
    # means a real manager IS there and can be queried, even if the
    # overall system health isn't "running" cleanly (e.g. "degraded" just
    # means some unrelated unit failed, not that OUR checks are useless).
    if (
        r.returncode == -1
        or "Failed to connect to bus" in (r.stderr or "")
        or state in ("offline", "unknown", "")
    ):
        return check_result(
            "systemd available",
            SKIPPED,
            f"no usable systemd manager (state: {state or 'no output'})",
        )
    return check_result("systemd available", PASS, state)


def check_tunnel_service(name: str, run=_run) -> dict:
    unit = f"pc-tunnel@{name}.service"
    if not shutil.which("systemctl"):
        return check_result(
            f"tunnel service ({unit})", SKIPPED, "systemctl not available"
        )
    r = run(["systemctl", "is-active", unit])
    state = (r.stdout or "").strip() or (r.stderr or "").strip().replace("\n", " ")
    if state == "active":
        return check_result(f"tunnel service ({unit})", PASS, "active")
    if state in ("inactive", "failed", "activating", "deactivating"):
        return check_result(f"tunnel service ({unit})", FAIL, f"state: {state}")
    # "unknown" / connection error / anything else we don't recognize
    return check_result(
        f"tunnel service ({unit})",
        SKIPPED,
        f"could not determine state ({state or 'no output'})",
    )


def check_port_listening(name: str, port: str) -> dict:
    if not port:
        return check_result(
            f"port listening ({name})", NOT_CONFIGURED, "no PORT in conf file"
        )
    try:
        port_i = int(port)
    except ValueError:
        return check_result(
            f"port listening ({name})", FAIL, f"PORT is not a number: {port!r}"
        )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        result = sock.connect_ex(("127.0.0.1", port_i))
        if result == 0:
            return check_result(
                f"port listening ({name})",
                PASS,
                f"127.0.0.1:{port_i} accepting connections",
            )
        return check_result(
            f"port listening ({name})",
            FAIL,
            f"127.0.0.1:{port_i} not accepting connections",
        )
    finally:
        sock.close()


def check_ssh_reachable(
    name: str,
    pc_ip: str,
    ssh_user: str,
    run=_run,
    known_hosts_dir: Path = Path("/etc/pc-tunnel/known_hosts.d"),
) -> dict:
    if not pc_ip:
        return check_result(f"SSH to {name}", NOT_CONFIGURED, "no PC_IP in conf file")
    if not shutil.which("ssh"):
        return check_result(f"SSH to {name}", SKIPPED, "ssh not on PATH")

    # Use the SAME host-key verification the real tunnel uses (see
    # pc-tunnel@.service's setup step 4 / SECURITY_FINDINGS.md finding 6:
    # StrictHostKeyChecking=yes against a per-PC pinned known_hosts file,
    # populated once via ssh-keyscan) rather than a looser accept-new
    # check -- that way this diagnostic can actually catch "the pinned
    # key doesn't match anymore" (a real MITM, or the PC's SSH host keys
    # were regenerated and nobody re-pinned them), which is exactly the
    # kind of failure a "just check the port is reachable" test would
    # silently miss. Falls back to accept-new only if the PC hasn't been
    # through the pinning step yet (e.g. mid-setup) -- that's a real,
    # different state worth distinguishing, not something to paper over.
    known_hosts_file = known_hosts_dir / name
    if known_hosts_file.exists():
        host_key_opts = [
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={known_hosts_file}",
        ]
        pinned = True
    else:
        host_key_opts = ["-o", "StrictHostKeyChecking=accept-new"]
        pinned = False

    r = run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            *host_key_opts,
            f"{ssh_user}@{pc_ip}",
            "true",
        ],
        timeout=8,
    )
    if r.returncode == 0:
        note = (
            "key verified against pinned known_hosts"
            if pinned
            else "NOT pinned yet (see pc-tunnel@.service setup step 4)"
        )
        return check_result(
            f"SSH to {name}",
            PASS,
            f"{ssh_user}@{pc_ip} reachable, key auth working ({note})",
        )
    detail = (r.stderr or "ssh failed").strip()[:200]
    if pinned and (
        "REMOTE HOST IDENTIFICATION HAS CHANGED" in detail
        or "Host key verification failed" in detail
    ):
        detail = f"HOST KEY MISMATCH against pinned known_hosts -- {detail}"
    return check_result(f"SSH to {name}", FAIL, detail)


def check_disk_space(path="/", warn_pct=90) -> dict:
    try:
        usage = shutil.disk_usage(path)
    except OSError as e:
        return check_result("Disk space", FAIL, str(e))
    pct_used = usage.used / usage.total * 100
    detail = f"{pct_used:.1f}% used ({usage.free // (1024**3)}GB free of {usage.total // (1024**3)}GB)"
    return check_result("Disk space", FAIL if pct_used >= warn_pct else PASS, detail)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_all(
    conf_dir: Path = PC_TUNNEL_CONF_DIR, ssh_user: str = "sepisotoni", run=_run
) -> list:
    checks = [
        check_systemd_available(run),
        check_pc_tunnel_config_dir(conf_dir),
        check_disk_space(),
    ]

    pcs = discover_pcs(conf_dir)
    for name, pc_ip, port in pcs:
        checks.append(check_tunnel_service(name, run))
        checks.append(check_port_listening(name, port))
        checks.append(check_ssh_reachable(name, pc_ip, ssh_user, run))

    return checks


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--json", action="store_true", help="machine-readable JSON output")
    ap.add_argument(
        "--conf-dir",
        default=str(PC_TUNNEL_CONF_DIR),
        help="pc-tunnel conf directory (default: /etc/pc-tunnel)",
    )
    ap.add_argument(
        "--ssh-user",
        default="sepisotoni",
        help="user to test SSH reachability as (default: sepisotoni)",
    )
    args = ap.parse_args()

    checks = run_all(Path(args.conf_dir), args.ssh_user)
    failed = [c for c in checks if c["status"] == FAIL]

    if args.json:
        print(
            json.dumps(
                {
                    "checks": checks,
                    "summary": {
                        "pass": sum(1 for c in checks if c["status"] == PASS),
                        "fail": len(failed),
                        "skipped": sum(1 for c in checks if c["status"] == SKIPPED),
                        "not_configured": sum(
                            1 for c in checks if c["status"] == NOT_CONFIGURED
                        ),
                    },
                },
                indent=2,
            )
        )
    else:
        width = max((len(c["name"]) for c in checks), default=20)
        for c in checks:
            print(f"[{c['status']:>14}] {c['name']:<{width}}  {c['detail']}")
        print()
        print(
            f"{sum(1 for c in checks if c['status'] == PASS)} passed, {len(failed)} failed, "
            f"{sum(1 for c in checks if c['status'] == SKIPPED)} skipped, "
            f"{sum(1 for c in checks if c['status'] == NOT_CONFIGURED)} not configured"
        )

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
