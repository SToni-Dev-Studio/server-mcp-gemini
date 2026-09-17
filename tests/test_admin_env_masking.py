"""
Regression test for a critical finding from external review (A2,
coordination/proposals/external-review-2026-09-13.md): /admin/api/env
returned every env var's value in plaintext to any authenticated admin
session -- GITHUB_TOKEN, MCP_SERVER_PASSWORD, SSH_PRIVATE_KEY, everything.
Any admin-cookie leak (XSS, shared screen, browser extension, screenshot)
turned into a full credential compromise, not just dashboard access.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("PORT", "8000")

import server as srv


def test_mask_secret_value_keeps_last_4_only():
    fake_token = "ghp_ExampleFakeTokenForTestOnlyNotReal12"  # synthetic, not a real credential
    assert srv._mask_secret_value(fake_token) == "*" * (len(fake_token) - 4) + fake_token[-4:]


def test_mask_secret_value_short_string_fully_masked():
    assert srv._mask_secret_value("abcd") == "****"
    assert srv._mask_secret_value("ab") == "**"


def test_mask_secret_value_empty_string():
    assert srv._mask_secret_value("") == ""


def test_mask_secret_value_never_contains_the_real_secret_as_a_substring():
    real_secret = "tskey-auth-kk3rDgaKfz11CNTRL-Divvip8uifHVTSdFX8UPgH6Cv76A34CJ"
    masked = srv._mask_secret_value(real_secret)
    # The only part of the real value allowed to appear is the last 4 chars.
    assert real_secret[:-4] not in masked
    assert masked.endswith(real_secret[-4:])


def test_admin_api_env_get_never_returns_a_plaintext_value(monkeypatch):
    """End-to-end-ish: patches _require_admin to simulate an authenticated
    admin session (the vulnerability existed for authenticated admins,
    not just unauthenticated callers -- so that's the scenario this test
    needs to cover) and a fake Render API response containing real-looking
    secrets, then asserts none of them come back verbatim."""
    import asyncio
    from unittest.mock import AsyncMock, patch, MagicMock

    monkeypatch.setattr(srv, "_require_admin", lambda request: None)  # simulate authenticated
    monkeypatch.setattr(srv, "RENDER_API_KEY", "fake-key-for-test")
    monkeypatch.setattr(srv, "RENDER_SERVICE_ID", "srv-fake")

    real_secrets = {
        "GITHUB_TOKEN": "ghp_realsecretvaluethatmustneverleak1234",
        "MCP_SERVER_PASSWORD": "super-secret-password-value",
        "SSH_PRIVATE_KEY": "-----BEGIN OPENSSH PRIVATE KEY-----\nfakekeydata\n-----END-----",
    }
    fake_items = [{"envVar": {"key": k, "value": v}} for k, v in real_secrets.items()]

    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock()
    fake_response.json = MagicMock(return_value=fake_items)

    fake_client = AsyncMock()
    fake_client.get = AsyncMock(return_value=fake_response)
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)

    fake_request = MagicMock()

    with patch("httpx.AsyncClient", return_value=fake_client):
        response = asyncio.run(srv._admin_api_env_get(fake_request))

    import json
    body = json.loads(response.body)
    returned_values = [v["value"] for v in body["vars"]]

    for key, real_value in real_secrets.items():
        assert real_value not in returned_values, f"{key}'s real value leaked verbatim"
        # also make sure it's not hiding as a substring of any returned value
        for rv in returned_values:
            assert real_value not in rv, f"{key}'s real value leaked as a substring"
