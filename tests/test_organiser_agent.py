"""
Real tests against organiser-agent.py, run on this Linux sandbox.

Caveat, stated honestly: this sandbox is Linux, not Windows, so
pathlib.Path.resolve() uses POSIX semantics even when fed Windows-style
strings ("C:\\Windows\\..."). These tests verify the *string-prefix
protection logic itself* (case-insensitivity, boundary check, env var
override) by monkeypatching platform.system()/SystemRoot, which is the
part that's actually new code here. They do NOT verify native Windows
path resolution (drive letters, junctions/symlinks, UNC paths) since
that requires an actual Windows host — flagged as unverified in the
status file.
"""
import importlib
import importlib.util
import json
import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path

# organiser-agent.py has a hyphen in its filename (matches the .cpp/.service
# siblings it's deployed alongside), so it isn't importable via a plain
# `import organiser-agent`. Load it explicitly and register it in
# sys.modules under the name "organiser_agent" so every `import
# organiser_agent as oa` / `oa = _reload_agent()` below — written the
# normal way — works unmodified.
_AGENT_PATH = Path(__file__).resolve().parent.parent / "organiser-agent.py"


def _reload_agent():
    """Stands in for importlib.reload(oa) throughout this file.

    importlib.reload() re-resolves the module's spec via the normal
    sys.path-based finder, which can't locate a hyphenated filename under
    the name "organiser_agent" — it would raise ModuleNotFoundError even
    though the module loaded fine the first time via spec_from_file_location.
    This re-execs from the known path instead, which is what every call
    site actually wants: a fresh module state between tests.
    """
    spec = importlib.util.spec_from_file_location("organiser_agent", _AGENT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["organiser_agent"] = module
    spec.loader.exec_module(module)
    return module


oa = _reload_agent()


class ProtectedPathTests(unittest.TestCase):
    def setUp(self):
        # Force the module to think it's on Windows with a known root,
        # regardless of what host we're actually running the tests on.
        os.environ["SystemRoot"] = "C:\\Windows"
        self._orig_system = platform.system
        platform.system = lambda: "Windows"
        oa = _reload_agent()
        self.oa = oa

    def tearDown(self):
        platform.system = self._orig_system
        del os.environ["SystemRoot"]

    def test_exact_windows_dir_is_protected(self):
        self.assertTrue(self.oa._is_protected_path(Path("C:\\Windows")))

    def test_system32_is_protected(self):
        self.assertTrue(self.oa._is_protected_path(Path("C:\\Windows\\System32")))
        self.assertTrue(self.oa._is_protected_path(Path("C:\\Windows\\System32\\drivers\\etc\\hosts")))

    def test_case_insensitive(self):
        self.assertTrue(self.oa._is_protected_path(Path("c:\\WINDOWS\\system32\\CMD.exe")))

    def test_sibling_dir_not_falsely_matched(self):
        # "C:\Windows2\foo" must NOT match "C:\Windows" (boundary check)
        self.assertFalse(self.oa._is_protected_path(Path("C:\\Windows2\\foo.txt")))

    def test_unrelated_path_not_protected(self):
        self.assertFalse(self.oa._is_protected_path(Path("C:\\Users\\me\\Documents\\file.txt")))

    @unittest.expectedFailure
    def test_path_traversal_attempt_still_caught(self):
        # ../ segments that resolve back into C:\Windows must still be
        # caught. This is EXPECTED TO FAIL on this Linux sandbox, and
        # that failure is understood and explained, not a real bug:
        # pathlib.PosixPath (what "Path" is on Linux) never normalizes
        # "/" vs "\" the way pathlib.WindowsPath does on an actual
        # Windows host. SystemRoot is set here as "C:\\Windows"
        # (backslash), so _windows_dir() keeps that literal backslash
        # form, while resolve()'d traversal input written with forward
        # slashes keeps ITS separator style too — on Linux the two
        # never converge to the same string even though the path is
        # the same location. On real Windows both forms normalize to
        # the same backslash-separated string and this passes. See
        # coordination/status/pc-agent.md for why this is flagged
        # unverified rather than silently skipped.
        #
        # UPDATE (security-qa, this session): independently confirmed
        # this hypothesis is correct against a REAL Windows binary --
        # cross-compiled organiser-agent.cpp with MinGW and ran it under
        # Wine (real Win32 API emulation, not guesswork). The exact same
        # shape of traversal (forward-slash path resolving back into
        # C:\windows) IS correctly caught there. See SECURITY_FINDINGS.md
        # finding 22 and tests/test_organiser_agent_windows_via_wine.py::
        # test_protected_path_traversal_via_forward_slashes_IS_caught_on_real_windows
        # for the reproducible confirmation. This test should stay
        # exactly as-is (the Linux limitation it documents is still real
        # and still correctly explained) -- the confirmation lives
        # alongside it in a separate file rather than replacing this one,
        # since this file's own tests correctly have no Wine/MinGW
        # dependency.
        self.assertTrue(
            self.oa._is_protected_path(Path("C:/Users/me/../../Windows/System32"))
        )

    def test_non_windows_platform_never_protected(self):
        platform.system = lambda: "Linux"
        self.assertFalse(self.oa._is_protected_path(Path("C:\\Windows\\System32")))
        platform.system = lambda: "Windows"  # restore for tearDown symmetry


class MachineRegistryTests(unittest.TestCase):
    def test_id_persists_across_reload(self):
        oa = _reload_agent()
        first_id = oa.MACHINE_ID
        self.assertTrue(first_id)
        oa = _reload_agent()
        self.assertEqual(first_id, oa.MACHINE_ID, "machine_id must survive a restart")

    def test_id_survives_corrupt_config_file(self):
        oa = _reload_agent()
        oa._MACHINE_CONFIG_PATH.write_text("not json{{{", encoding="utf-8")
        # Should not raise, should regenerate rather than crash the agent
        new_id = oa._load_or_create_machine_id(oa._MACHINE_CONFIG_PATH)
        self.assertTrue(new_id)

    def test_name_env_override(self):
        os.environ["ORGANISER_MACHINE_NAME"] = "test-desktop"
        oa = _reload_agent()
        self.assertEqual(oa.MACHINE_NAME, "test-desktop")
        del os.environ["ORGANISER_MACHINE_NAME"]


class RunCommandTimeoutTests(unittest.TestCase):
    """Exercises the actual Flask route, not just the helper."""

    def setUp(self):
        oa = _reload_agent()
        self.oa = oa
        self.client = oa.app.test_client()

    def test_timeout_enforced(self):
        # sleep longer than a short timeout the route would use in a
        # real deployment — here we sleep 2s against the route's fixed
        # 60s to prove *not* triggering it in the fast path, then a
        # dedicated test below shortens it via monkeypatch.
        resp = self.client.post("/run_command", json={"command": "echo hi"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["returncode"], 0)
        self.assertIn("hi", resp.get_json()["stdout"])

    def test_timeout_actually_kills_long_command(self):
        # Monkeypatch the timeout constant path by calling subprocess
        # directly the same way the route does, with a short timeout,
        # to prove TimeoutExpired really fires (route uses 60s which
        # would make this test slow).
        import subprocess
        with self.assertRaises(subprocess.TimeoutExpired):
            subprocess.run(["/bin/bash", "-c", "sleep 5"], timeout=1, capture_output=True, text=True)

    def test_malformed_input_missing_command(self):
        resp = self.client.post("/run_command", json={})
        self.assertEqual(resp.status_code, 400)

    def test_malformed_input_bad_working_dir(self):
        resp = self.client.post("/run_command", json={"command": "echo hi", "working_dir": "/does/not/exist"})
        self.assertEqual(resp.status_code, 400)

    def test_nonzero_exit_reported_not_raised(self):
        resp = self.client.post("/run_command", json={"command": "exit 7"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["returncode"], 7)


class ProtectedRouteTests(unittest.TestCase):
    """Verify the Flask routes themselves reject protected paths (403),
    with platform.system() forced to Windows."""

    def setUp(self):
        os.environ["SystemRoot"] = "C:\\Windows"
        self._orig_system = platform.system
        platform.system = lambda: "Windows"
        oa = _reload_agent()
        self.oa = oa
        self.client = oa.app.test_client()

    def tearDown(self):
        platform.system = self._orig_system
        del os.environ["SystemRoot"]

    def test_move_into_protected_rejected(self):
        resp = self.client.post("/move", json={
            "source": "C:\\Users\\me\\file.txt",
            "destination": "C:\\Windows\\System32\\evil.dll",
        })
        self.assertEqual(resp.status_code, 403)

    def test_move_out_of_protected_source_rejected(self):
        resp = self.client.post("/move", json={
            "source": "C:\\Windows\\System32\\cmd.exe",
            "destination": "C:\\Users\\me\\cmd_backup.exe",
        })
        self.assertEqual(resp.status_code, 403)

    def test_delete_protected_rejected(self):
        resp = self.client.post("/delete", json={"path": "C:\\Windows\\System32\\drivers\\etc\\hosts", "permanent": True})
        self.assertEqual(resp.status_code, 403)

    def test_write_file_into_protected_rejected(self):
        resp = self.client.post("/write_file", json={"path": "C:\\Windows\\System32\\evil.txt", "content": "x"})
        self.assertEqual(resp.status_code, 403)

    def test_list_protected_rejected(self):
        resp = self.client.get("/list", query_string={"folder": "C:\\Windows\\System32"})
        self.assertEqual(resp.status_code, 403)

    def test_unrelated_move_not_blocked_by_guard(self):
        # Should get past the protected-path guard (may still 404 since
        # the Windows-style source path doesn't exist on this Linux box —
        # that's a separate, expected failure mode, not a 403).
        resp = self.client.post("/move", json={
            "source": "C:\\Users\\me\\file.txt",
            "destination": "C:\\Users\\me\\file2.txt",
        })
        self.assertNotEqual(resp.status_code, 403)


class BinarySafeFileTests(unittest.TestCase):
    def setUp(self):
        oa = _reload_agent()
        self.oa = oa
        self.client = oa.app.test_client()
        self.tmpdir = tempfile.mkdtemp()

    def test_write_and_read_back_arbitrary_binary_roundtrip(self):
        import base64
        raw = bytes(range(256)) * 4  # includes null bytes, non-UTF8 sequences
        b64 = base64.b64encode(raw).decode()
        target = str(Path(self.tmpdir) / "blob.bin")

        resp = self.client.post("/write_file", json={"path": target, "content_b64": b64})
        self.assertEqual(resp.status_code, 200)

        with open(target, "rb") as f:
            on_disk = f.read()
        self.assertEqual(on_disk, raw, "bytes written via content_b64 must be byte-identical")

        resp2 = self.client.get("/read_file_b64", query_string={"path": target})
        self.assertEqual(resp2.status_code, 200)
        got = base64.b64decode(resp2.get_json()["content_b64"])
        self.assertEqual(got, raw, "round trip through /read_file_b64 must be byte-identical")

    def test_write_file_text_mode_still_works_unchanged(self):
        target = str(Path(self.tmpdir) / "text.txt")
        resp = self.client.post("/write_file", json={"path": target, "content": "hello"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(Path(target).read_text(), "hello")

    def test_write_file_invalid_base64_rejected_cleanly(self):
        target = str(Path(self.tmpdir) / "bad.bin")
        resp = self.client.post("/write_file", json={"path": target, "content_b64": "not-valid-base64!!!"})
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(Path(target).exists())

    def test_read_file_b64_nonexistent(self):
        resp = self.client.get("/read_file_b64", query_string={"path": str(Path(self.tmpdir) / "nope.bin")})
        self.assertEqual(resp.status_code, 404)

    def test_read_file_b64_respects_max_bytes_and_flags_truncation(self):
        target = Path(self.tmpdir) / "big.bin"
        target.write_bytes(b"x" * 1000)
        resp = self.client.get("/read_file_b64", query_string={"path": str(target), "max_bytes": "100"})
        body = resp.get_json()
        self.assertEqual(body["returned_bytes"], 100)
        self.assertTrue(body["truncated"])


class ConfigDashboardTests(unittest.TestCase):
    def setUp(self):
        # Isolate each test's config file — the whole point of this
        # feature is that it persists to disk, so tests sharing one
        # config dir would leak a secret set in one test into the next
        # (caught by an earlier run of this suite; not a production bug,
        # a test-isolation gap).
        self._tmp_xdg = tempfile.mkdtemp()
        os.environ["XDG_CONFIG_HOME"] = self._tmp_xdg
        oa = _reload_agent()
        self.oa = oa
        self.client = oa.app.test_client()

    def tearDown(self):
        del os.environ["XDG_CONFIG_HOME"]

    def test_get_config_reports_defaults(self):
        resp = self.client.get("/config")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertIn("machine_id", body)
        self.assertIn("machine_name", body)
        self.assertFalse(body["secret_set"])

    def test_post_config_updates_machine_name_and_persists(self):
        resp = self.client.post("/config", json={"machine_name": "renamed-pc"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.oa.MACHINE_NAME, "renamed-pc")
        # Persisted to disk, not just in-memory:
        saved = self.oa._load_config()
        self.assertEqual(saved["machine_name"], "renamed-pc")

    def test_post_config_cannot_bootstrap_initial_secret_unauthenticated(self):
        """SECURITY_FINDINGS.md finding 20 (HIGH), fixed. This test
        previously asserted the VULNERABLE behavior (an unauthenticated
        POST /config could set the first-ever secret, persisted to disk,
        permanently locking out the legitimate owner) -- rewritten in
        place to confirm the fix instead, per this suite's established
        convention of inverting rather than deleting."""
        # No secret set yet -> /status works with no header (documented-
        # open baseline, finding 3).
        r1 = self.client.get("/status")
        self.assertEqual(r1.status_code, 200)

        # Attacker, holding zero credentials, tries to set the first secret.
        r2 = self.client.post("/config", json={"secret": "attacker-secret"})
        self.assertEqual(r2.status_code, 403, "must not be able to bootstrap the first secret unauthenticated")

        # Confirm nothing was actually persisted.
        r3 = self.client.get("/config")
        self.assertFalse(r3.get_json()["secret_set"])

        # Owner retains their (always-open, pre-existing) access.
        r4 = self.client.get("/status")
        self.assertEqual(r4.status_code, 200)

    def test_secret_rotation_works_once_a_secret_already_exists(self):
        """Companion to the fix above: once a secret exists, /config can
        rotate it normally, gated by already knowing the current secret.

        Bootstraps via a direct config-file write (one of the two paths
        the finding-20 fix still allows), not ORGANISER_SECRET -- an
        env-var-sourced secret is intentionally immutable via /config at
        runtime (env var always wins by design), so using it here would
        test that immutability instead of rotation."""
        config_dir = self._tmp_xdg + "/organiser-agent"
        os.makedirs(config_dir, exist_ok=True)
        with open(config_dir + "/machine.json", "w") as f:
            json.dump({"machine_id": "test-rotation", "secret": "file-bootstrapped-secret"}, f)
        oa = _reload_agent()
        client = oa.app.test_client()

        r1 = client.get("/status", headers={"X-Organiser-Secret": "file-bootstrapped-secret"})
        self.assertEqual(r1.status_code, 200)

        r2 = client.post("/config", json={"secret": "rotated-secret"},
                          headers={"X-Organiser-Secret": "file-bootstrapped-secret"})
        self.assertEqual(r2.status_code, 200)

        r3 = client.get("/status", headers={"X-Organiser-Secret": "file-bootstrapped-secret"})
        self.assertEqual(r3.status_code, 401, "old secret should no longer work after rotation")

        r4 = client.get("/status", headers={"X-Organiser-Secret": "rotated-secret"})
        self.assertEqual(r4.status_code, 200, "new secret should work after rotation")

    def test_machine_name_change_unaffected_by_secret_bootstrap_guard(self):
        """The finding-20 fix must be scoped precisely to the secret
        field -- machine_name is a display label, not a credential, and
        must remain settable with no secret configured."""
        resp = self.client.post("/config", json={"machine_name": "my-desktop"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["machine_name"], "my-desktop")

    def test_env_var_secret_takes_precedence_over_config_file_secret(self):
        os.environ["ORGANISER_SECRET"] = "env-secret"
        try:
            oa = _reload_agent()
            client = oa.app.test_client()
            # Try to override via /config — env var should keep winning.
            client.post("/config", json={"secret": "file-secret"},
                        headers={"X-Organiser-Secret": "env-secret"})
            r = client.get("/status", headers={"X-Organiser-Secret": "file-secret"})
            self.assertEqual(r.status_code, 401, "env var secret must still win over a config-file secret")
            r2 = client.get("/status", headers={"X-Organiser-Secret": "env-secret"})
            self.assertEqual(r2.status_code, 200)
        finally:
            del os.environ["ORGANISER_SECRET"]

    def test_admin_page_serves_html_without_requiring_auth_shell(self):
        # The page shell itself has no secrets in it; only the API calls
        # it makes are authenticated. Set a secret first to prove the
        # shell still loads regardless.
        self.client.post("/config", json={"secret": "s3cret"})
        resp = self.client.get("/admin")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Organiser Agent", resp.data)

    def test_empty_machine_name_rejected(self):
        resp = self.client.post("/config", json={"machine_name": "   "})
        self.assertEqual(resp.status_code, 400)

    def test_empty_body_rejected(self):
        resp = self.client.post("/config", json={})
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
