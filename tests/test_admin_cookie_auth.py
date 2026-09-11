"""
Regression test for the admin-cookie-forgery fix.

Simulates the OLD vulnerable behavior vs the NEW code path by importing
server.py with no ADMIN_PASSWORD / ADMIN_COOKIE_SECRET set, then trying
to forge a cookie using the exact string that used to be the hardcoded
fallback secret. It must be rejected.
"""
import os, sys, hmac, hashlib, time

os.environ.pop("ADMIN_PASSWORD", None)
os.environ.pop("ADMIN_COOKIE_SECRET", None)
os.environ.pop("MCP_SERVER_PASSWORD", None)
os.environ.setdefault("PORT", "8000")

sys.path.insert(0, ".")
import importlib
import server as srv
importlib.reload(srv)

assert srv.ADMIN_PASSWORD == "", "test setup wrong: ADMIN_PASSWORD should be empty"
assert srv._ADMIN_AUTH_CONFIGURED is False, "should be unconfigured with no password/secret set"

# Attacker tries the OLD known hardcoded secret
old_leaked_secret = "insecure-dev-secret-set-ADMIN_PASSWORD"
expiry = str(int(time.time()) + 3600)
forged_sig = hmac.new(old_leaked_secret.encode(), expiry.encode(), hashlib.sha256).hexdigest()
forged_cookie = f"{expiry}.{forged_sig}"

result = srv._admin_cookie_valid(forged_cookie)
assert result is False, f"VULNERABLE: forged cookie was accepted! result={result}"

# Also confirm a cookie signed with the server's OWN randomly-generated
# per-process secret is still rejected while unconfigured (fail-closed,
# not just "reject this one known string")
real_sig = hmac.new(srv._ADMIN_COOKIE_SECRET.encode(), expiry.encode(), hashlib.sha256).hexdigest()
own_cookie = f"{expiry}.{real_sig}"
result2 = srv._admin_cookie_valid(own_cookie)
assert result2 is False, "should still fail closed when unconfigured, even with a technically-valid HMAC"

print("PASS: admin cookie forgery is blocked when ADMIN_PASSWORD/ADMIN_COOKIE_SECRET are unset")

# Now the positive case: WITH a password configured, a legitimately
# issued cookie must still work.
os.environ["ADMIN_PASSWORD"] = "correct-horse-battery-staple"
importlib.reload(srv)
assert srv._ADMIN_AUTH_CONFIGURED is True
good_cookie = srv._admin_make_cookie()
assert srv._admin_cookie_valid(good_cookie) is True, "legit cookie should validate when configured"
print("PASS: legitimate admin session still works when ADMIN_PASSWORD is set")
