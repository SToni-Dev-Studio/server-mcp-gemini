import crypto from "node:crypto";
import { Request, Response, NextFunction } from "express";
import { ADMIN_COOKIE_SECRET, ADMIN_SESSION_TTL, allowedHost } from "./config.js";

/**
 * Constant-time string equality check using SHA-256 digests.
 * Prevents length and timing-attack leaks.
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const hashA = crypto.createHash("sha256").update(a).digest();
  const hashB = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

/**
 * Validate incoming Host header to defend against DNS rebinding attacks.
 */
export function isHostAllowed(hostHeader: string | undefined, expectedHost: string): boolean {
  if (!expectedHost) return true; // Local dev without explicit host configuration
  if (!hostHeader) return false;

  // Strip port if present
  const host = hostHeader.toLowerCase().split(":")[0].trim();
  const expected = expectedHost.toLowerCase().split(":")[0].trim();

  // Local loopback is always permitted
  if (host === "localhost" || host === "127.0.0.1" || host === "::1") {
    return true;
  }

  // Exact match with configured host
  if (host === expected) {
    return true;
  }

  // Support wildcard subdomains or Cloud Run / Render defaults if matching
  if (expected.startsWith("*.") && host.endsWith(expected.slice(1))) {
    return true;
  }

  return false;
}

/**
 * Express middleware to enforce DNS rebinding protection.
 */
export function hostValidationMiddleware(req: Request, res: Response, next: NextFunction): void {
  const hostHeader = req.headers.host;
  if (!isHostAllowed(hostHeader, allowedHost)) {
    res.status(403).json({
      error: `Invalid Host header: '${hostHeader || ""}'. Expected: '${allowedHost}' or localhost.`,
    });
    return;
  }
  next();
}

/**
 * POSIX shell quotation. Safely wraps values in single quotes and escapes single quotes.
 */
export function shQuote(val: unknown): string {
  const s = String(val ?? "");
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

/**
 * Admin Session Cookie Helpers (HMAC signed stateless cookies)
 */
export function adminSign(payload: string): string {
  return crypto.createHmac("sha256", ADMIN_COOKIE_SECRET).update(payload).digest("hex");
}

export function adminMakeCookie(): string {
  const expiry = String(Math.floor(Date.now() / 1000) + ADMIN_SESSION_TTL);
  return `${expiry}.${adminSign(expiry)}`;
}

export function adminCookieValid(cookieValue: string | undefined): boolean {
  if (!cookieValue || !cookieValue.includes(".")) return false;
  const [expiryStr, sig] = cookieValue.split(".", 2);
  const expiry = parseInt(expiryStr, 10);
  if (isNaN(expiry) || Date.now() / 1000 > expiry) return false;

  const expectedSig = adminSign(expiryStr);
  return constantTimeCompare(sig, expectedSig);
}

/**
 * Validate environment variable key names to avoid prototype pollution or shell injection.
 */
export function sanitizeEnvKey(key: string): boolean {
  if (!key || typeof key !== "string") return false;
  if (["__proto__", "prototype", "constructor"].includes(key.toLowerCase())) return false;
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(key);
}

/**
 * Mask sensitive environment variable values when displayed in admin listings.
 */
export function maskSecret(key: string, value: string): string {
  if (!value) return "";
  const upperKey = key.toUpperCase();
  const isSensitive = ["TOKEN", "PASSWORD", "SECRET", "KEY", "AUTH"].some((k) => upperKey.includes(k));
  if (!isSensitive) return value;
  if (value.length <= 8) return "••••••••";
  return `${value.slice(0, 4)}••••••••${value.slice(-4)}`;
}
