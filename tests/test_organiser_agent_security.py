"""
Security regression tests for organiser-agent.cpp (the Windows PC agent).

These build the agent as a native Linux binary (it's written to be
cross-platform for exactly this reason -- see the top-of-file comment in
organiser-agent.cpp) and drive it over real HTTP on a loopback port. No
real infrastructure is touched: everything here is a subprocess owned by
the test, on 127.0.0.1, torn down at the end of each test.

Skips cleanly (does not fail) if g++ isn't available in the environment.

Findings this file locks in as regressions (see SECURITY_FINDINGS.md for
full writeup, severity, and remediation suggestions) -- all FIXED as of
this branch, tests inverted to confirm the fixes hold rather than
deleted (per this file's own established convention):
  - working_dir command injection (single-quote breakout on the Linux
    /bin/bash -c wrapping) -- FIXED (run_command rewrite, no longer
    builds a shell string from working_dir at all).
  - No-secret-configured means most auth checks are skipped entirely --
    left as documented, accepted behavior for one-off operations
    (finding 3), but /config specifically can no longer use that window
    to PERMANENTLY set a secret (finding 20, see below).
  - /preview's max_bytes is attacker-controlled -- FIXED, clamped to a
    hard ceiling and to the real file size before allocating.
  - Secret comparison is not constant-time -- FIXED
    (constant_time_equal(), matching hmac.compare_digest's approach).
  - /config could be used by an unauthenticated caller to permanently
    hijack the agent by setting the first-ever secret -- FIXED: /config
    can rotate an existing secret but can never bootstrap the first one
    over the network.
"""
import json
import os
import shutil
import socket
import subprocess
import tempfile
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
    """IMPORTANT: organiser-agent persists machine identity/secret to a
    fixed, per-OS-user path ($HOME/.config/organiser-agent/machine.json
    on Linux -- see SECURITY_FINDINGS.md finding 20). Every invocation
    here gets its own isolated $HOME so tests never leak state into each
    other or into whatever real $HOME this sandbox happens to have."""
    port = _free_port()
    isolated_home = tempfile.mkdtemp(prefix="organiser-agent-test-home-")
    env = os.environ.copy()
    env.pop("ORGANISER_SECRET", None)
    env["ORGANISER_PORT"] = str(port)
    env["HOME"] = isolated_home
    env["XDG_CONFIG_HOME"] = os.path.join(isolated_home, ".config")
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
        shutil.rmtree(isolated_home, ignore_errors=True)


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
    """REMEDIATED by pc-agent (see SECURITY_FINDINGS.md finding 1/2 status
    and coordination/status/pc-agent.md) -- this test originally proved
    the vulnerability by injecting a `touch` via `working_dir` while
    `command` was an inert echo, then asserting the marker file existed.

    Originally: `working_dir` was embedded into a shell string as
    `cd "<working_dir>" && <command>`, wrapped in `/bin/bash -c '...'`,
    with NO escaping of single quotes. A single quote broke out of that
    wrapper and the remainder of working_dir was interpreted as new
    shell syntax, independent of `command`.

    Now: run_command no longer builds that string at all. The POSIX path
    validates working_dir with fs::is_directory() and then chdir()s a
    forked child directly before exec; the Windows path passes it as
    CreateProcess's lpCurrentDirectory parameter. Neither ever treats
    working_dir as shell text.

    Verified independently twice, not just by reading the diff: pc-agent
    compiled this exact organiser-agent.cpp and re-ran this exact exploit
    payload by hand against the running binary; lead did the same
    separately before updating this test (see COMPETITION_REPORT.md for
    that verification).

    Per the original docstring's own instruction ("if this starts
    failing because the bug was fixed, please update SECURITY_FINDINGS.md
    to mark it remediated instead of just deleting this test") -- kept
    as a permanent regression test, inverted to confirm the fix holds:
    the exact same payload must now be REJECTED (working_dir isn't a
    real directory) and must NOT create the marker file.
    """
    marker = tmp_path / "PWNED_VIA_WORKING_DIR"
    assert not marker.exists()
    payload_working_dir = f"x' ; touch {marker} ; echo '"
    with running_agent(agent_binary, secret=None) as (base, _):
        status, body = _post(
            base, "/run_command",
            {"command": "echo should_not_matter", "working_dir": payload_working_dir},
        )
        # Fixed behavior: this isn't a real directory, so it's now a
        # clean 400 -- not a 200 that silently ran the injected shell
        # syntax.
        assert status == 400, f"expected clean 400 rejection, got {status}: {body!r}"
    assert not marker.exists(), (
        "REGRESSION: the working_dir shell-injection is back -- the "
        "marker file was created, meaning working_dir is being "
        "shell-interpreted again instead of passed as a real chdir "
        "target/lpCurrentDirectory. This is a HIGH-severity finding if "
        "it starts failing again; see SECURITY_FINDINGS.md finding 1."
    )


def test_working_dir_injection_via_real_directory_with_malicious_name(agent_binary, tmp_path):
    """Stricter companion to the test above: proves the underlying
    chdir()/CreateProcess mechanism is safe, not just that the
    is_directory() precheck happens to reject payloads that aren't real
    paths. Creates an ACTUAL directory whose name contains shell
    metacharacters and confirms changing into it via /run_command's pwd
    does not trigger injection."""
    marker = tmp_path / "PWNED2"
    weird_dir = tmp_path / "weird'; touch marker_should_not_appear; echo '"
    weird_dir.mkdir()
    assert not marker.exists()
    with running_agent(agent_binary, secret=None) as (base, _):
        status, body = _post(
            base, "/run_command",
            {"command": "pwd", "working_dir": str(weird_dir)},
        )
        assert status == 200
        result = json.loads(body)
        assert result["returncode"] == 0
        # pwd's output should be exactly the weird directory path --
        # proving chdir() changed into it literally, not that any part
        # of the name was interpreted as shell syntax.
        assert result["stdout"].strip() == str(weird_dir)
    assert not marker.exists()


def test_oversized_max_bytes_no_longer_crashes_or_leaks_memory(agent_binary, tmp_path):
    """REMEDIATED by pc-agent (see SECURITY_FINDINGS.md finding 4 status).
    max_bytes is now clamped to MAX_READ_BYTES (20MB) and additionally
    capped to the real file size before any allocation happens. Inverted
    from the original crash-proving test to confirm: (a) no more
    std::bad_alloc/500, (b) the response is still correct (returns the
    actual small file's content, not silently wrong data), (c) the
    process survives and stays responsive."""
    small_file = tmp_path / "small.bin"
    small_file.write_bytes(b"hello world")
    with running_agent(agent_binary, secret=None) as (base, proc):
        status, body = _get(base, f"/preview?path={small_file}&max_bytes=10000000000")
        assert status == 200, f"expected clean 200 with clamped read, got {status}: {body}"
        result = json.loads(body)
        assert result["content"] == "hello world"
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


def test_unauthenticated_config_post_cannot_bootstrap_the_initial_secret(agent_binary):
    """SECURITY_FINDINGS.md finding 20 (HIGH), fixed. Originally: when no
    ORGANISER_SECRET was configured, POST /config let ANY unauthenticated
    caller set a brand-new secret -- persisted to disk, surviving a
    restart, permanently locking out the legitimate owner with no
    network recovery path. A meaningfully worse variant of finding 3
    (a transient exposure window) turned into a permanent, exclusive
    takeover.

    Fix: /config can no longer bootstrap the FIRST secret over the
    network at all -- only rotate an existing one (already safely gated,
    since reaching /config at all requires the current secret once one
    exists). The first secret must come from ORGANISER_SECRET (env var)
    or a local edit of the config file.

    This test proves the exploit chain is broken at every step: the
    attacker's POST is rejected, the legitimate owner keeps their
    (pre-existing, always-open) access, and the attacker's chosen
    "secret" grants nothing because it was never actually set."""
    with running_agent(agent_binary, secret=None) as (base, _):
        status, _ = _get(base, "/status")
        assert status == 200  # documented-open baseline (finding 3)

        status, body = _post(base, "/config", {"secret": "attacker-chosen-secret"})
        assert status == 403, f"expected clean 403 rejection, got {status}: {body!r}"

        # Confirm nothing was actually persisted -- not just that this
        # one response said 403.
        status, body = _get(base, "/config")
        assert status == 200
        assert json.loads(body)["secret_set"] is False, (
            "REGRESSION: finding 20 is back -- a secret was set via /config "
            "with zero credentials. This is a HIGH-severity finding if it "
            "starts failing again."
        )


def test_legitimate_secret_rotation_still_works_once_a_secret_exists(agent_binary):
    """Companion to the fix above: confirms the fix doesn't overreach --
    once a secret exists, /config can still rotate it normally, gated by
    already knowing the current secret.

    Bootstraps the initial secret via a local config-file edit (one of
    the two ways the finding-20 fix now allows), NOT via ORGANISER_SECRET
    -- an env-var-sourced secret is intentionally immutable via /config
    at runtime (env var always wins, by design, so a service-managed
    deployment isn't silently overridable from the local dashboard);
    using it here would test that immutability instead of rotation."""
    isolated_home = tempfile.mkdtemp(prefix="organiser-agent-test-home-")
    config_dir = os.path.join(isolated_home, ".config", "organiser-agent")
    os.makedirs(config_dir, exist_ok=True)
    with open(os.path.join(config_dir, "machine.json"), "w") as f:
        json.dump({"machine_id": "test-rotation", "secret": "file-bootstrapped-secret"}, f)

    port = _free_port()
    env = os.environ.copy()
    env.pop("ORGANISER_SECRET", None)
    env["ORGANISER_PORT"] = str(port)
    env["HOME"] = isolated_home
    env["XDG_CONFIG_HOME"] = os.path.join(isolated_home, ".config")
    proc = subprocess.Popen(agent_binary, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{base}/status", timeout=0.5)
            except urllib.error.HTTPError:
                pass
            except Exception:
                if proc.poll() is not None:
                    pytest.fail(f"organiser-agent exited early:\n{proc.stdout.read().decode(errors='replace')}")
                time.sleep(0.1)
                continue
            break
        else:
            pytest.fail("organiser-agent never came up")

        status, _ = _get(base, "/status", headers={"X-Organiser-Secret": "file-bootstrapped-secret"})
        assert status == 200, "file-bootstrapped secret should be active"

        status, body = _post(
            base, "/config", {"secret": "rotated-secret"},
            headers={"X-Organiser-Secret": "file-bootstrapped-secret"},
        )
        assert status == 200, f"legitimate rotation should succeed, got {status}: {body!r}"

        status, _ = _get(base, "/status", headers={"X-Organiser-Secret": "file-bootstrapped-secret"})
        assert status == 401, "old secret should no longer work after rotation"

        status, _ = _get(base, "/status", headers={"X-Organiser-Secret": "rotated-secret"})
        assert status == 200, "new secret should work after rotation"
    finally:
        proc.kill()
        proc.wait(timeout=5)
        shutil.rmtree(isolated_home, ignore_errors=True)


def test_machine_name_change_unaffected_by_the_secret_bootstrap_guard(agent_binary):
    """Confirms the finding-20 fix is scoped precisely to the SECRET
    field -- machine_name is not security-sensitive (it's a display
    label, not a credential) and must remain settable even with no
    secret configured yet."""
    with running_agent(agent_binary, secret=None) as (base, _):
        status, body = _post(base, "/config", {"machine_name": "my-desktop"})
        assert status == 200, f"machine_name change should not be blocked, got {status}: {body!r}"
        assert json.loads(body)["machine_name"] == "my-desktop"
def test_unauthenticated_config_post_can_no_longer_hijack_the_machine(agent_binary):
    """FIXED (was: succeeded, HIGH severity). This is security-qa's
    original exploit test from before pc-agent's fix landed -- it used
    to assert the hijack SUCCEEDED (status == 200, followed by the
    legitimate owner getting locked out). Now proves the opposite: the
    same zero-credential bootstrap attempt is rejected outright, nobody
    gets locked out, and the "attacker's" chosen secret is never
    accepted anywhere -- because it was never set in the first place.

    See test_unauthenticated_config_post_cannot_bootstrap_the_initial_secret
    above for the lead's/pc-agent's version of this same proof, written
    independently before this branch's history was reconciled -- kept
    both rather than deduplicating, since they're independent
    confirmations of the same fix from two different sessions."""
    with running_agent(agent_binary, secret=None) as (base, _):
        # confirm the open baseline (still true, and still the
        # documented, accepted, separate finding 3 -- this fix is
        # narrower than "require auth for everything")
        status, _ = _get(base, "/status")
        assert status == 200

        # attacker, holding no credentials at all, tries to set their
        # own secret -- must be rejected, not accepted
        status, body = _post(base, "/config", {"secret": "attacker-chosen-secret"})
        assert status == 403, (
            f"REGRESSION: got {status}, expected 403 -- if this now "
            f"returns 200 again, the finding-20 fix was reverted or "
            f"bypassed. Body: {body!r}"
        )

        # the legitimate owner is NOT locked out -- nothing was ever set
        status, _ = _get(base, "/status")
        assert status == 200

        # the attacker's chosen secret was never persisted, so it
        # doesn't work anywhere
        status, _ = _get(base, "/status", headers={"X-Organiser-Secret": "attacker-chosen-secret"})
        assert status == 200  # still open baseline, not "secret accepted"


def test_config_endpoint_never_leaks_the_actual_secret_value(agent_binary):
    """Positive check: GET /config must report whether a secret is set
    and where it came from, but never the secret's actual value."""
    with running_agent(agent_binary, secret="s3cr3t-value-should-not-leak") as (base, _):
        status, body = _get(base, "/config", headers={"X-Organiser-Secret": "s3cr3t-value-should-not-leak"})
        assert status == 200
        assert b"s3cr3t-value-should-not-leak" not in body
        assert b"secret_set" in body
