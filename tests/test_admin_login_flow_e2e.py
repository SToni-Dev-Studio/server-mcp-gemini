"""
End-to-end verification of the full admin auth flow, through the real
ASGI app via Starlette's TestClient (real HTTP request/response cycle
through actual routing, not calling internal functions directly) --
built as part of a pre-production-merge auth verification pass.

Covers: login rejects wrong password -> login succeeds with correct
password and issues a cookie -> that cookie authenticates a real
request to a protected admin route -> /admin/api/env (once configured)
returns masked values through this same real cookie, not just when
called directly -> logout actually invalidates the session -> a
tampered cookie is rejected -> the whole flow fails closed when
ADMIN_PASSWORD is unset (regression coverage for the finding fixed in
test_admin_cookie_auth.py, but exercised here through real HTTP instead
of direct function calls).
"""
import os
import sys
import importlib

import pytest
from starlette.testclient import TestClient

# server.py's admin cookie is Secure (correctly -- Render/Fly serve HTTPS
# only, see the commit fixing external review A9). TestClient defaults to
# http://testserver, and a Secure cookie is legitimately never resent by
# a real HTTP client over plain http -- so these tests need an https://
# base_url to actually exercise the flow a real browser would use.
TEST_BASE_URL = "https://testserver"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fresh_app(**env_overrides):
    for k in ("ADMIN_PASSWORD", "MCP_SERVER_PASSWORD", "ADMIN_COOKIE_SECRET",
              "RENDER_API_KEY", "RENDER_SERVICE_ID"):
        os.environ.pop(k, None)
    os.environ.setdefault("PORT", "8000")
    for k, v in env_overrides.items():
        os.environ[k] = v
    import server as srv
    importlib.reload(srv)
    return srv


def test_full_login_cookie_authenticated_request_flow():
    srv = _fresh_app(ADMIN_PASSWORD="correct-horse-battery-staple")
    client = TestClient(srv.app, base_url=TEST_BASE_URL)

    # wrong password rejected, no cookie issued
    r = client.post("/admin/login", data={"password": "wrong"}, follow_redirects=False)
    assert r.status_code == 401
    assert "admin_session" not in r.cookies

    # correct password -> redirect + cookie issued
    r = client.post("/admin/login", data={"password": "correct-horse-battery-staple"}, follow_redirects=False)
    assert r.status_code == 303
    assert "admin_session" in r.cookies
    cookie_attrs = r.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie_attrs
    assert "Secure" in cookie_attrs
    assert "SameSite=lax" in cookie_attrs or "samesite=lax" in cookie_attrs.lower()

    # that real cookie authenticates a real request to a protected route
    r = client.get("/admin", follow_redirects=False)
    assert r.status_code == 200
    assert "Wrong password" not in r.text

    # /admin/api/env through the real cookie -- not configured here, so a
    # clean "not configured" message, not a 401 (proves the cookie itself
    # is being accepted for this route, not that env access happens to work)
    r = client.get("/admin/api/env")
    assert r.status_code == 200
    assert "not configured" in r.json().get("error", "").lower()


def test_login_flow_with_env_configured_returns_masked_values():
    srv = _fresh_app(
        ADMIN_PASSWORD="correct-horse-battery-staple",
        RENDER_API_KEY="fake-key-for-test",
        RENDER_SERVICE_ID="srv-fake",
    )
    client = TestClient(srv.app, base_url=TEST_BASE_URL)
    client.post("/admin/login", data={"password": "correct-horse-battery-staple"})

    from unittest.mock import AsyncMock, patch, MagicMock
    real_secret = "ghp_realproductiontoken1234567890abcdef"
    fake_items = [{"envVar": {"key": "GITHUB_TOKEN", "value": real_secret}}]
    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock()
    fake_response.json = MagicMock(return_value=fake_items)
    fake_client = AsyncMock()
    fake_client.get = AsyncMock(return_value=fake_response)
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)

    with patch("httpx.AsyncClient", return_value=fake_client):
        r = client.get("/admin/api/env")
    assert r.status_code == 200
    body = r.json()
    values = [v["value"] for v in body["vars"]]
    assert real_secret not in values, "real secret reached the client through the full real HTTP flow"
    assert any(v.endswith("cdef") for v in values), "masked value should still show last 4 chars"


def test_no_cookie_at_all_is_rejected():
    srv = _fresh_app(ADMIN_PASSWORD="correct-horse-battery-staple")
    client = TestClient(srv.app, base_url=TEST_BASE_URL)
    r = client.get("/admin", follow_redirects=False)
    # redirected to login or shown the login form, never the dashboard content
    assert r.status_code in (200, 303, 307)
    if r.status_code == 200:
        assert "Wrong password" in r.text or "password" in r.text.lower()


def test_tampered_cookie_rejected():
    srv = _fresh_app(ADMIN_PASSWORD="correct-horse-battery-staple")
    client = TestClient(srv.app, base_url=TEST_BASE_URL)
    client.post("/admin/login", data={"password": "correct-horse-battery-staple"})
    real_cookie = client.cookies.get("admin_session")
    assert real_cookie

    # flip a character in the signature half of the cookie
    expiry, sig = real_cookie.rsplit(".", 1)
    tampered_sig = ("0" if sig[0] != "0" else "1") + sig[1:]
    client.cookies.set("admin_session", f"{expiry}.{tampered_sig}")

    r = client.get("/admin/api/env")
    assert r.status_code == 401


def test_logout_actually_invalidates_the_session():
    srv = _fresh_app(ADMIN_PASSWORD="correct-horse-battery-staple")
    client = TestClient(srv.app, base_url=TEST_BASE_URL)
    client.post("/admin/login", data={"password": "correct-horse-battery-staple"})
    r = client.get("/admin/api/env")
    assert r.status_code == 200  # authenticated before logout

    client.get("/admin/logout", follow_redirects=False)
    r = client.get("/admin/api/env")
    assert r.status_code == 401, "session should be dead after logout"


def test_whole_admin_flow_fails_closed_when_unconfigured():
    """Real-HTTP version of the finding fixed in test_admin_cookie_auth.py
    -- confirms it holds through the actual routes, not just the
    function called directly."""
    srv = _fresh_app()  # no ADMIN_PASSWORD, no ADMIN_COOKIE_SECRET
    client = TestClient(srv.app, base_url=TEST_BASE_URL)

    r = client.post("/admin/login", data={"password": "anything"}, follow_redirects=False)
    assert r.status_code in (401, 503)

    # forge a cookie with the OLD known hardcoded fallback secret and try it anyway
    import hmac, hashlib, time
    old_leaked_secret = "insecure-dev-secret-set-ADMIN_PASSWORD"
    expiry = str(int(time.time()) + 3600)
    forged_sig = hmac.new(old_leaked_secret.encode(), expiry.encode(), hashlib.sha256).hexdigest()
    client.cookies.set("admin_session", f"{expiry}.{forged_sig}")

    r = client.get("/admin/api/env")
    assert r.status_code == 401, "forged cookie must be rejected even through the real route"
