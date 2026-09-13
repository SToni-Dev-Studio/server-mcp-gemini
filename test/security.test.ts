import test from "node:test";
import assert from "node:assert/strict";
import {
  constantTimeCompare,
  shQuote,
  isHostAllowed,
  adminSign,
  adminCookieValid,
  sanitizeEnvKey,
  maskSecret,
} from "../src/security.js";
import { checkBlockedCommand } from "../src/ssh.js";

test("Security - constantTimeCompare", () => {
  assert.equal(constantTimeCompare("secret123", "secret123"), true);
  assert.equal(constantTimeCompare("secret123", "secret124"), false);
  assert.equal(constantTimeCompare("secret123", "short"), false);
  assert.equal(constantTimeCompare("", ""), true);
  assert.equal(constantTimeCompare("", "a"), false);
  assert.equal(constantTimeCompare(null as any, "secret"), false);
});

test("Security - shQuote shell escaping", () => {
  assert.equal(shQuote("hello"), "'hello'");
  assert.equal(shQuote("hello world"), "'hello world'");
  assert.equal(shQuote("it's cool"), "'it'\\''s cool'");
  assert.equal(shQuote("$(rm -rf /)"), "'$(rm -rf /)'");
  assert.equal(shQuote(""), "''");
  assert.equal(shQuote(123), "'123'");
});

test("Security - isHostAllowed (DNS Rebinding protection)", () => {
  // Localhost is always allowed
  assert.equal(isHostAllowed("localhost", "mcp.example.com"), true);
  assert.equal(isHostAllowed("localhost:3000", "mcp.example.com"), true);
  assert.equal(isHostAllowed("127.0.0.1", "mcp.example.com"), true);
  assert.equal(isHostAllowed("127.0.0.1:8080", "mcp.example.com"), true);

  // Configured host
  assert.equal(isHostAllowed("mcp.example.com", "mcp.example.com"), true);
  assert.equal(isHostAllowed("mcp.example.com:443", "mcp.example.com"), true);

  // Wildcard configured host
  assert.equal(isHostAllowed("sub.example.com", "*.example.com"), true);

  // Unknown / attack host header
  assert.equal(isHostAllowed("attacker.com", "mcp.example.com"), false);
  assert.equal(isHostAllowed("evil.com:3000", "mcp.example.com"), false);

  // When no host is configured (local dev)
  assert.equal(isHostAllowed("anything.local", ""), true);
});

test("Security - Admin cookie HMAC signature and validity", () => {
  const expiry = String(Math.floor(Date.now() / 1000) + 3600); // 1 hr in future
  const sig = adminSign(expiry);
  const validCookie = `${expiry}.${sig}`;

  assert.equal(adminCookieValid(validCookie), true);

  // Tampered payload
  assert.equal(adminCookieValid(`${expiry}.badsignature`), false);

  // Expired payload
  const expiredTime = String(Math.floor(Date.now() / 1000) - 100);
  const expiredCookie = `${expiredTime}.${adminSign(expiredTime)}`;
  assert.equal(adminCookieValid(expiredCookie), false);

  // Malformed cookies
  assert.equal(adminCookieValid(""), false);
  assert.equal(adminCookieValid("undefined"), false);
  assert.equal(adminCookieValid("no-period-here"), false);
});

test("Security - sanitizeEnvKey", () => {
  assert.equal(sanitizeEnvKey("PORT"), true);
  assert.equal(sanitizeEnvKey("GITHUB_TOKEN_SECONDARY"), true);
  assert.equal(sanitizeEnvKey("_CUSTOM_VAR_123"), true);

  // Prohibited / dangerous keys
  assert.equal(sanitizeEnvKey("__proto__"), false);
  assert.equal(sanitizeEnvKey("prototype"), false);
  assert.equal(sanitizeEnvKey("constructor"), false);
  assert.equal(sanitizeEnvKey("VAR; rm -rf /"), false);
  assert.equal(sanitizeEnvKey("VAR=123"), false);
  assert.equal(sanitizeEnvKey(""), false);
});

test("Security - maskSecret", () => {
  assert.equal(maskSecret("PORT", "3000"), "3000");
  assert.equal(maskSecret("SERVER_HOST", "192.168.1.1"), "192.168.1.1");

  // Sensitive values should be masked
  assert.equal(maskSecret("GITHUB_TOKEN", "ghp_1234567890abcdef"), "ghp_••••••••cdef");
  assert.equal(maskSecret("ADMIN_PASSWORD", "short"), "••••••••");
  assert.equal(maskSecret("PLEX_TOKEN", "tokenvalue123"), "toke••••••••e123");
});

test("Security - checkBlockedCommand", () => {
  assert.equal(checkBlockedCommand("ls -la /var/log"), null);
  assert.equal(checkBlockedCommand("systemctl status plexmediaserver"), null);

  assert.notEqual(checkBlockedCommand("rm -rf /"), null);
  assert.notEqual(checkBlockedCommand("sudo rm -rf / mnt"), null);
  assert.notEqual(checkBlockedCommand("mkfs.ext4 /dev/sdb"), null);
  assert.notEqual(checkBlockedCommand("shutdown now"), null);
  assert.notEqual(checkBlockedCommand("dd if=/dev/zero of=/dev/sda"), null);
});
