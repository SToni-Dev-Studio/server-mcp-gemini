"""
Dynamic verification of organiser-agent.cpp's WINDOWS-SPECIFIC code paths,
using a real cross-compiled Windows PE32+ binary run under Wine -- not
just static code review.

This closes several gaps that were previously flagged as "static
analysis only, needs a real Windows target" throughout SECURITY_FINDINGS.md:
  - is_protected_path's canonicalization, INCLUDING the specific
    forward-slash-vs-backslash traversal normalization case that
    tests/test_organiser_agent.py's Flask-side equivalent test honestly
    marked @unittest.expectedFailure on Linux with a detailed explanation
    of why it can't be verified there. Confirmed here: on real Windows
    path semantics (via Wine, which emulates the actual Win32 API/
    filesystem calls a genuine Windows host would make), the traversal
    IS correctly caught.
  - The working_dir fix (finding 21) under real CreateProcess/
    lpCurrentDirectory behavior, including the double-quote+ampersand
    injection shape hypothesized (but not confirmed) in the original
    finding 2 write-up for the Windows cmd.exe code path.
  - The max_bytes fix (finding 4) under a real Windows process: since
    the merge, organiser-agent.cpp now clamps max_bytes to a hard
    ceiling AND to the real file size (checked via fs::file_size before
    ever allocating), so this no longer even reaches an allocation
    failure -- it just returns the correct, real file content. Re-
    verified that end-to-end on real Windows (this was written when
    the bug was still open and confirmed a caught bad_alloc; updated
    after the fix landed to confirm the fix itself, not just that it
    stopped crashing).

CAVEAT, stated plainly: this cross-compiles with MinGW-w64 and runs
under Wine, not a genuine Windows install with MSVC. Wine emulates the
real Win32 API surface (path canonicalization, CreateProcess, etc.), so
filesystem/path/process-creation findings here are a strong proxy for
real Windows behavior. The C++ runtime specifics (MinGW's libstdc++ vs
MSVC's STL) could differ somewhat for anything allocator-internals-
specific, though the max_bytes finding above no longer depends on that
distinction now that it's fixed at the file-size-check level rather
than relying on catching an allocation failure.

Skips cleanly (does not fail) if the MinGW cross-compiler or Wine aren't
available in the environment -- both were installed for this engagement
via `apt-get install g++-mingw-w64-x86-64 wine64` (both come from
Ubuntu's own package repos, no untrusted third-party sources).
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CPP_SRC = os.path.join(REPO_ROOT, "organiser-agent.cpp")

MINGW = shutil.which("x86_64-w64-mingw32-g++")
WINE = shutil.which("wine")

pytestmark = pytest.mark.skipif(
    MINGW is None or WINE is None,
    reason="needs x86_64-w64-mingw32-g++ and wine (apt-get install g++-mingw-w64-x86-64 wine64)",
)


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def windows_binary(tmp_path_factory):
    build_dir = tmp_path_factory.mktemp("organiser-build-windows")
    exe = str(build_dir / "organiser-agent.exe")
    r = subprocess.run(
        [MINGW, "-std=c++17", "-O0", "-static", "-o", exe, CPP_SRC, "-lws2_32", "-lgdi32"],
        capture_output=True, text=True, timeout=180,
    )
    if r.returncode != 0:
        pytest.fail(f"organiser-agent.cpp failed to cross-compile for Windows:\n{r.stderr[-4000:]}")
    return exe


@pytest.fixture(scope="module")
def wine_prefix(tmp_path_factory):
    prefix = str(tmp_path_factory.mktemp("wineprefix"))
    env = dict(os.environ, WINEPREFIX=prefix, WINEARCH="win64", WINEDEBUG="-all")
    subprocess.run(["wine", "wineboot", "--init"], env=env, capture_output=True, timeout=60)
    return prefix


@pytest.fixture
def running_windows_agent(windows_binary, wine_prefix, tmp_path):
    port = _free_port()
    env = dict(os.environ, WINEPREFIX=wine_prefix, WINEARCH="win64", WINEDEBUG="-all")
    env.pop("ORGANISER_SECRET", None)
    env["ORGANISER_PORT"] = str(port)
    proc = subprocess.Popen(["wine", windows_binary], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        import urllib.request
        for _ in range(100):
            try:
                r = urllib.request.urlopen(f"{base}/status", timeout=0.5)
                body = json.loads(r.read())
                assert body.get("platform") == "Windows", (
                    f"expected the Windows code path, got platform={body.get('platform')!r}"
                )
                break
            except Exception:
                if proc.poll() is not None:
                    out = proc.stdout.read().decode(errors="replace")
                    pytest.fail(f"windows binary exited early under wine:\n{out}")
                time.sleep(0.2)
        else:
            pytest.fail("windows binary never came up under wine")
        # translate a POSIX tmp_path into the Z: drive Wine maps the
        # real filesystem root onto, so the Windows binary can see it
        win_tmp = "Z:" + str(tmp_path).replace("/", "\\")
        yield base, win_tmp, wine_prefix
    finally:
        proc.kill()
        proc.wait(timeout=10)


def _get(base, path):
    import urllib.request
    req = urllib.request.Request(base + path)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, r.read()
    except Exception as e:
        return getattr(e, "code", -1), getattr(e, "read", lambda: str(e).encode())()


def _post(base, path, body):
    import urllib.request
    data = json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data,
                                  headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, r.read()
    except Exception as e:
        return getattr(e, "code", -1), getattr(e, "read", lambda: str(e).encode())()


def test_protected_path_blocks_windows_dir_on_real_windows(running_windows_agent):
    base, win_tmp, prefix = running_windows_agent
    status, body = _get(base, "/list?folder=C:\\windows")
    assert status == 403
    assert b"protected" in body.lower()


def test_protected_path_traversal_via_forward_slashes_IS_caught_on_real_windows(running_windows_agent):
    """The exact case tests/test_organiser_agent.py's Flask-side
    equivalent honestly marks @unittest.expectedFailure on Linux,
    explaining that real Windows path normalization would catch it but
    Linux's pathlib.PosixPath can't demonstrate that. Confirmed here
    against the real (Wine-emulated) Windows path semantics."""
    base, win_tmp, prefix = running_windows_agent
    status, body = _get(base, "/list?folder=C:/windows/system32/../../windows/system32")
    assert status == 403, f"expected the traversal to be caught, got {status}: {body}"
    assert b"protected" in body.lower()


def test_protected_path_does_not_false_positive_on_sibling_dir(running_windows_agent):
    base, win_tmp, prefix = running_windows_agent
    sibling = os.path.join(prefix, "drive_c", "windows2")
    os.makedirs(sibling, exist_ok=True)
    status, body = _get(base, "/list?folder=C:\\windows2")
    assert status == 200


def test_working_dir_injection_is_closed_on_real_windows(running_windows_agent, tmp_path):
    """Uses a real detectable side effect (a marker file written via a
    redirect) rather than a naive substring check, since the correct
    rejection message legitimately echoes the attempted payload text
    back verbatim -- a substring match against the payload itself would
    misfire as a false "injection fired" even on a fully-fixed binary."""
    base, win_tmp, prefix = running_windows_agent
    legit_dir = os.path.join(prefix, "drive_c", "wine-test-legit-dir")
    os.makedirs(legit_dir, exist_ok=True)
    marker_path = os.path.join(legit_dir, "PWNED_MARKER.txt")

    payload_working_dir = f'C:\\wine-test-legit-dir" & echo INJECTED > C:\\wine-test-legit-dir\\PWNED_MARKER.txt & echo "'
    status, body = _post(base, "/run_command", {
        "command": "echo should_not_matter", "working_dir": payload_working_dir,
    })
    text = body.decode(errors="replace")
    assert "does not exist" in text or "not a directory" in text
    assert not os.path.exists(marker_path), (
        f"injection fired on real Windows -- marker file was created: {text}"
    )


def test_working_dir_legitimate_use_still_works_on_real_windows(running_windows_agent):
    base, win_tmp, prefix = running_windows_agent
    legit_dir = os.path.join(prefix, "drive_c", "wine-test-legit-dir2")
    os.makedirs(legit_dir, exist_ok=True)
    with open(os.path.join(legit_dir, "present.txt"), "w") as f:
        f.write("marker")

    status, body = _post(base, "/run_command", {
        "command": "dir", "working_dir": "C:\\wine-test-legit-dir2",
    })
    assert status == 200
    assert b"present.txt" in body


def test_max_bytes_oversized_is_clamped_and_returns_real_content_FIXED(running_windows_agent):
    """FIXED (finding 4): max_bytes is now clamped to a MAX_READ_BYTES
    ceiling AND to the real file size (checked via fs::file_size before
    allocating), so a 10GB request against a tiny file no longer even
    attempts an oversized allocation -- it just returns the file's
    actual content. Re-verified end-to-end against the real Windows
    binary: correct content comes back, not a crash and not an error."""
    base, win_tmp, prefix = running_windows_agent
    small = os.path.join(prefix, "drive_c", "wine-small.txt")
    with open(small, "w") as f:
        f.write("hello world")

    status, body = _get(base, "/preview?path=C:\\wine-small.txt&max_bytes=10000000000")
    assert status == 200, (
        f"expected the fix to clamp cleanly and succeed, got {status}: {body}"
    )
    parsed = json.loads(body)
    assert parsed["content"] == "hello world"
    status2, _ = _get(base, "/status")
    assert status2 == 200
