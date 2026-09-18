"""
Tests for packaging/mcp-hub-tools/usr/lib/mcp-hub-tools/autoupdate.sh.

Runs the real script as a subprocess against a real local HTTP server
(tests/_fake_github_releases_api.py) standing in for GitHub's Releases
API (via the GITHUB_API_BASE env var override added to the script
specifically for this). `dpkg`/`apt-get` are stubbed via a fake
executable placed first on PATH -- these tests verify autoupdate.sh's
own decision logic (version comparison, checksum verification, when it
does vs. doesn't attempt an install), not dpkg itself, and actually
running dpkg -i as part of a test suite would be invasive (real package
state changes) for no real benefit over confirming "the script would
have run dpkg -i here" via the stub's captured invocation log.

The full real install/remove/purge lifecycle (dpkg -i / dpkg -r / dpkg -P
against the actual built .deb) WAS verified for real, once, manually --
see coordination/status/hub-cicd.md for that transcript. It's not
re-run here as an automated test because doing so on every CI run would
mutate the CI runner's real package database, which is a bigger blast
radius than a lint/test job should have.
"""
import hashlib
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import _fake_github_releases_api  # noqa: E402

SCRIPT = (
    Path(__file__).parent.parent
    / "packaging" / "mcp-hub-tools" / "usr" / "lib" / "mcp-hub-tools" / "autoupdate.sh"
)


@pytest.fixture
def fake_dpkg_bin(tmp_path):
    """A fake `dpkg` on PATH that just logs its invocation to a file
    instead of touching real package state. Also provides a fake
    `dpkg-query` (used to determine the CURRENTLY installed version) and
    a fake `apt-get` (used as a fallback if dpkg -i fails) -- these are
    real, separate executables, not python mocks, since autoupdate.sh
    shells out to them by name and doesn't take an injectable command
    runner the way the Python scripts in this repo do."""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    log_file = tmp_path / "dpkg_calls.log"

    (bin_dir / "dpkg").write_text(f"""#!/bin/bash
if [ "$1" = "--compare-versions" ]; then
    # Delegate real version comparisons to the REAL dpkg (found via the
    # rest of PATH, which this fake bin dir is prepended to, not
    # replacing) -- this stub only needs to intercept the actual
    # install call (dpkg -i), not reimplement Debian version-comparison
    # semantics. An earlier version of this stub unconditionally
    # returned exit 0 for every dpkg invocation, which made
    # --compare-versions always report "yes, newer" regardless of the
    # actual versions being compared -- caught by running this exact
    # test and seeing it fail on the "already up to date" case.
    exec /usr/bin/dpkg "$@"
fi
echo "dpkg $*" >> {log_file}
exit 0
""")
    (bin_dir / "dpkg-query").write_text("""#!/bin/bash
# Simulates: currently-installed version is 1.0.0
echo "1.0.0"
exit 0
""")
    (bin_dir / "apt-get").write_text(f"""#!/bin/bash
echo "apt-get $*" >> {log_file}
exit 0
""")
    for f in ("dpkg", "dpkg-query", "apt-get"):
        p = bin_dir / f
        p.chmod(p.stat().st_mode | stat.S_IEXEC)

    return bin_dir, log_file


def run_autoupdate(fake_dpkg_bin, github_api_base, extra_env=None):
    bin_dir, log_file = fake_dpkg_bin
    env = dict(os.environ)
    # Fake bin dir first, but keep the real PATH after it so bash,
    # curl, sha256sum, python3, logger, etc. are all still found --
    # only dpkg/dpkg-query/apt-get resolve to the fakes.
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    env["GITHUB_API_BASE"] = github_api_base
    env.update(extra_env or {})
    result = subprocess.run(
        ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=20
    )
    calls = log_file.read_text().splitlines() if log_file.exists() else []
    return result, calls


def test_already_up_to_date_skips_install(fake_dpkg_bin):
    # fake dpkg-query reports 1.0.0 installed; release tag v1.0.0 (same
    # version) should NOT trigger an install.
    _fake_github_releases_api.start(tag_name="v1.0.0", port=18093)
    time.sleep(0.2)
    result, calls = run_autoupdate(fake_dpkg_bin, "http://127.0.0.1:18093")
    assert result.returncode == 0
    assert not any("dpkg -i" in c for c in calls)


def test_newer_version_with_valid_checksum_installs(fake_dpkg_bin):
    deb_content = b"fake deb package bytes for testing"
    server = _fake_github_releases_api.start(tag_name="v2.0.0", deb_content=deb_content, port=18094)
    time.sleep(0.2)
    try:
        result, calls = run_autoupdate(fake_dpkg_bin, "http://127.0.0.1:18094")
        assert result.returncode == 0, result.stderr
        assert any("dpkg -i" in c for c in calls), f"expected a dpkg -i call, got: {calls}"
    finally:
        server.shutdown()


def test_checksum_mismatch_refuses_to_install(fake_dpkg_bin):
    """Serves a .deb whose bytes do NOT match the published checksum --
    simulating a corrupted download or a tampered release -- and
    confirms the script refuses to install rather than proceeding
    anyway."""
    real_content = b"the actual deb bytes"
    wrong_hash_content = b"completely different bytes"
    assert hashlib.sha256(real_content).hexdigest() != hashlib.sha256(wrong_hash_content).hexdigest()

    import http.server
    import json as _json
    import threading

    class MismatchHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.endswith("/releases/latest"):
                body = _json.dumps({
                    "tag_name": "v2.0.0",
                    "assets": [
                        {"name": "mcp-hub-tools_2.0.0_all.deb", "browser_download_url": "http://127.0.0.1:18096/deb"},
                        {"name": "mcp-hub-tools_2.0.0_all.deb.sha256", "browser_download_url": "http://127.0.0.1:18096/sum"},
                    ],
                }).encode()
            elif self.path == "/deb":
                body = real_content
            elif self.path == "/sum":
                # Deliberately the checksum of DIFFERENT bytes than what
                # /deb actually serves -- the mismatch under test.
                body = f"{hashlib.sha256(wrong_hash_content).hexdigest()}  x.deb\n".encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.HTTPServer(("127.0.0.1", 18096), MismatchHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    try:
        result, calls = run_autoupdate(fake_dpkg_bin, "http://127.0.0.1:18096")
        assert result.returncode != 0
        assert not any("dpkg -i" in c for c in calls), "must NOT install on checksum mismatch"
    finally:
        srv.shutdown()


def test_no_deb_asset_in_release_skips_gracefully(fake_dpkg_bin):
    server = _fake_github_releases_api.start(tag_name="v2.0.0", include_deb_asset=False, port=18097)
    time.sleep(0.2)
    try:
        result, calls = run_autoupdate(fake_dpkg_bin, "http://127.0.0.1:18097")
        assert result.returncode == 0
        assert not any("dpkg -i" in c for c in calls)
    finally:
        server.shutdown()


def test_github_unreachable_fails_gracefully_not_loudly(fake_dpkg_bin):
    # Port 1: guaranteed nothing listening, connection refused quickly.
    result, calls = run_autoupdate(fake_dpkg_bin, "http://127.0.0.1:1")
    assert result.returncode == 0, "a network blip on a periodic timer shouldn't be treated as a hard failure"
    assert calls == []
