import express from "express";
import type { Request, Response, NextFunction } from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { execFile } from "child_process";
import dotenv from "dotenv";

dotenv.config();

const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = "0.0.0.0";

const GITHUB_API = "https://api.github.com";
const RENDER_API = "https://api.render.com/v1";
const FLY_API = "https://api.fly.io/graphql";

const SERVER_HOST = process.env.SERVER_HOST || "192.168.101.105";
const SERVER_USER = process.env.SERVER_USER || "sepisotoni";
const SERVER_SSH_PORT = process.env.SERVER_SSH_PORT || "22";
let SERVER_SSH_KEY = process.env.SERVER_SSH_KEY || "~/.ssh/id_rsa";

const RENDER_API_KEY = (process.env.RENDER_API_KEY || "").trim();
const RENDER_SERVICE_ID = (process.env.RENDER_SERVICE_ID || "srv-da11cupt0dsc73aq2qq0").trim();
const FLY_API_TOKEN = (process.env.FLY_API_TOKEN || "").trim();
const FLY_APP_NAME = (process.env.FLY_APP_NAME || "").trim();

const SSH_PRIVATE_KEY_CONTENT = process.env.SSH_PRIVATE_KEY || "";
const SSH_KEY_PATH = process.env.SSH_KEY_PATH || "/tmp/render_mcp_key";
if (SSH_PRIVATE_KEY_CONTENT) {
  try {
    const dir = path.dirname(SSH_KEY_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(SSH_KEY_PATH, SSH_PRIVATE_KEY_CONTENT.trim() + "\n", { mode: 0o600 });
    SERVER_SSH_KEY = SSH_KEY_PATH;
  } catch (err) {
    console.warn("Failed writing SSH private key to file:", err);
  }
}

// ---------------------------------------------------------------------------
// PC Registry (multi-PC support)
// ---------------------------------------------------------------------------
interface PCEntry {
  port: number;
  secret: string;
  lan_ip?: string;
  machine_id?: string;
  machine_name?: string;
}

const PCS_RAW = (process.env.PCS || "").trim();
let PC_REGISTRY: Record<string, PCEntry> = {};
if (PCS_RAW) {
  try {
    PC_REGISTRY = JSON.parse(PCS_RAW);
  } catch {
    console.warn("WARNING: PCS env var is not valid JSON — ignoring, using single-PC mode.");
  }
}

if (!Object.keys(PC_REGISTRY).length) {
  PC_REGISTRY["default"] = {
    port: parseInt(process.env.ORGANISER_PORT || "7842", 10),
    secret: process.env.ORGANISER_SECRET || "",
  };
}

const PC_V2_DYNAMIC_REGISTRY: Record<string, any> = {};

function resolvePC(pc: string): PCEntry {
  if (!PC_REGISTRY[pc]) {
    const available = Object.keys(PC_REGISTRY).sort().join(", ") || "(none configured)";
    throw new Error(`Unknown PC '${pc}'. Configured PCs: ${available}`);
  }
  return PC_REGISTRY[pc];
}

// ---------------------------------------------------------------------------
// Host Detection & Security
// ---------------------------------------------------------------------------
function detectAllowedHost(): string {
  const explicit = (process.env.MCP_ALLOWED_HOST || "").trim();
  if (explicit) return explicit;
  const renderHost = (process.env.RENDER_EXTERNAL_HOSTNAME || "").trim();
  if (renderHost) return renderHost;
  const flyApp = (process.env.FLY_APP_NAME || "").trim();
  if (flyApp) return `${flyApp}.fly.dev`;
  return "";
}

const allowedHost = detectAllowedHost();
const isPublicDeployment = Boolean(allowedHost);

// ---------------------------------------------------------------------------
// Admin & Auth Configuration
// ---------------------------------------------------------------------------
const ADMIN_PASSWORD =
  (process.env.ADMIN_PASSWORD || "").trim() ||
  (process.env.MCP_SERVER_PASSWORD || "").trim();

const ADMIN_COOKIE_SECRET =
  (process.env.ADMIN_COOKIE_SECRET || "").trim() ||
  ADMIN_PASSWORD ||
  crypto.randomBytes(32).toString("hex");

const ADMIN_AUTH_CONFIGURED = Boolean(
  (process.env.ADMIN_COOKIE_SECRET || "").trim() || ADMIN_PASSWORD
);
const ADMIN_SESSION_TTL = 60 * 60 * 12; // 12 hours
const ADMIN_COOKIE_NAME = "admin_session";

function adminSign(payload: string): string {
  return crypto.createHmac("sha256", ADMIN_COOKIE_SECRET).update(payload).digest("hex");
}

function adminMakeCookie(): string {
  const expiry = String(Math.floor(Date.now() / 1000) + ADMIN_SESSION_TTL);
  return `${expiry}.${adminSign(expiry)}`;
}

function adminCookieValid(cookieValue?: string): boolean {
  if (!ADMIN_AUTH_CONFIGURED || !cookieValue || !cookieValue.includes(".")) return false;
  const [expiryStr, sig] = cookieValue.split(".", 2);
  const expiry = parseInt(expiryStr, 10);
  if (isNaN(expiry) || Date.now() / 1000 > expiry) return false;
  const expected = adminSign(expiryStr);
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

function requireAdminAuthed(req: Request): boolean {
  return adminCookieValid(req.cookies?.[ADMIN_COOKIE_NAME]);
}

// ---------------------------------------------------------------------------
// OAuth 2.1 State & Token Helpers
// ---------------------------------------------------------------------------
const OAUTH_TOKENS_FILE = process.env.OAUTH_TOKENS_FILE || "/tmp/oauth_tokens.json";
interface OAuthCodeData {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  expires_at: number;
}
const OAUTH_CODES = new Map<string, OAuthCodeData>();
const OAUTH_CLIENTS = new Map<string, any>();
const OAUTH_TOKENS = new Set<string>();
const OAUTH_REFRESH_TOKENS = new Map<string, string>();

function loadOAuthData() {
  if (fs.existsSync(OAUTH_TOKENS_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(OAUTH_TOKENS_FILE, "utf-8"));
      (data.tokens || []).forEach((t: string) => OAUTH_TOKENS.add(t));
      if (data.refresh_tokens) {
        Object.entries(data.refresh_tokens).forEach(([k, v]) =>
          OAUTH_REFRESH_TOKENS.set(k, String(v))
        );
      }
    } catch (e) {
      console.warn("Failed to load OAuth tokens:", e);
    }
  }
}
loadOAuthData();

function saveOAuthData() {
  try {
    const dir = path.dirname(OAUTH_TOKENS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = `${OAUTH_TOKENS_FILE}.tmp`;
    fs.writeFileSync(
      tmp,
      JSON.stringify({
        tokens: Array.from(OAUTH_TOKENS),
        refresh_tokens: Object.fromEntries(OAUTH_REFRESH_TOKENS.entries()),
      })
    );
    fs.renameSync(tmp, OAUTH_TOKENS_FILE);
  } catch (e) {
    console.warn("Failed to save OAuth tokens:", e);
  }
}

function generateOAuthToken(): string {
  const ts = String(Math.floor(Date.now() / 1000));
  const secret = process.env.MCP_SERVER_PASSWORD || "gemini_mcp_secret_2026";
  const sig = crypto.createHmac("sha256", secret).update(ts).digest("hex").slice(0, 32);
  return `mcp_oauth_${ts}_${sig}`;
}

function generateRefreshToken(): string {
  const ts = String(Math.floor(Date.now() / 1000));
  const secret = process.env.MCP_SERVER_PASSWORD || "gemini_mcp_secret_2026";
  const sig = crypto.createHmac("sha256", secret).update(ts).digest("hex").slice(0, 32);
  return `mcp_refresh_${ts}_${sig}`;
}

function safeCompare(a: string, b: string): boolean {
  if (!a || !b || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function isValidToken(token: string): boolean {
  if (!token) return false;
  const cleaned = token.replace(/^["']|["']$/g, "");
  const expectedPassword = (process.env.MCP_SERVER_PASSWORD || "").trim();
  if (expectedPassword && safeCompare(cleaned, expectedPassword)) return true;
  if (ADMIN_PASSWORD && safeCompare(cleaned, ADMIN_PASSWORD)) return true;
  if (OAUTH_TOKENS.has(cleaned)) return true;

  if (cleaned.startsWith("mcp_oauth_") || cleaned.startsWith("mcp_refresh_")) {
    const parts = cleaned.split("_");
    if (parts.length >= 4) {
      const ts = parts[2];
      const sig = parts[3];
      const secret = process.env.MCP_SERVER_PASSWORD || "gemini_mcp_secret_2026";
      const expectedSig = crypto.createHmac("sha256", secret).update(ts).digest("hex").slice(0, 32);
      if (safeCompare(sig, expectedSig)) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Shell & SSH Helpers
// ---------------------------------------------------------------------------
function shQuote(val: any): string {
  const s = String(val ?? "");
  if (!s) return "''";
  return `'${s.replace(/'/g, "'\\''")}'`;
}

function runLocal(cmd: string, args: string[], timeoutMs: number = 60000): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const proc = execFile(cmd, args, { timeout: timeoutMs }, (error, stdout, stderr) => {
      resolve({
        code: error && typeof error.code === "number" ? error.code : error ? 1 : 0,
        stdout: stdout || "",
        stderr: stderr || (error ? error.message : ""),
      });
    });
  });
}

async function sshServer(command: string, timeoutSec: number = 60): Promise<string> {
  const keyArgs = SERVER_SSH_KEY && fs.existsSync(SERVER_SSH_KEY) ? ["-i", SERVER_SSH_KEY] : [];
  const sshArgs = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=10",
    "-p", SERVER_SSH_PORT,
    ...keyArgs,
    `${SERVER_USER}@${SERVER_HOST}`,
    command,
  ];

  try {
    const res = await runLocal("ssh", sshArgs, timeoutSec * 1000);
    const out = (res.stdout + res.stderr).trim();
    if (res.code === 0) {
      return out || `(exited ${res.code}, no output)`;
    }
    return `SSH to ${SERVER_USER}@${SERVER_HOST}:${SERVER_SSH_PORT} exited with status ${res.code}: ${out || "no output"}`;
  } catch (err: any) {
    return `SSH to ${SERVER_USER}@${SERVER_HOST}:${SERVER_SSH_PORT} failed: ${err?.message || err}`;
  }
}

// Organiser agent request via SSH loopback tunnel
async function organiserSSHRequest(
  method: string,
  pathStr: string,
  pc: string = "default",
  params: Record<string, any> = {},
  body: any = null,
  timeoutSec: number = 30
): Promise<string> {
  const entry = resolvePC(pc);
  const base = `http://127.0.0.1:${entry.port}`;
  const envelope = {
    method,
    path: pathStr,
    params,
    body,
    secret: entry.secret || "",
    base,
  };
  const envB64 = Buffer.from(JSON.stringify(envelope)).toString("base64");

  const pySource = `
import urllib.request as u, urllib.parse as p, json, base64
e = json.loads(base64.b64decode("${envB64}").decode())
url = e["base"] + e["path"]
if e["params"]:
    url += "?" + p.urlencode(e["params"])
headers = {"Content-Type": "application/json"}
if e["secret"]:
    headers["X-Organiser-Secret"] = e["secret"]
data = json.dumps(e["body"]).encode() if e["body"] is not None else None
req = u.Request(url, data=data, headers=headers, method=e["method"])
try:
    with u.urlopen(req, timeout=25) as r:
        print(r.read().decode())
except u.HTTPError as ex:
    print(json.dumps({"error": ex.read().decode(), "status_code": ex.code}))
except Exception as ex:
    print(json.dumps({"error": str(ex)}))
`;
  const srcB64 = Buffer.from(pySource).toString("base64");
  const cmd = `echo ${srcB64} | base64 -d | python3 -`;
  return await sshServer(cmd, timeoutSec);
}

function parseOrganiserResponse(raw: string): any {
  const cleaned = (raw || "").trim();
  if (!cleaned) {
    throw new Error(
      "Empty response reaching the organiser-agent via the server. Check: is pc-tunnel@<name>.service running on the Linux server, and is organiser-agent.exe running on that PC?"
    );
  }
  try {
    return JSON.parse(cleaned);
  } catch {
    throw new Error(`Non-JSON response from organiser-agent (via server): ${cleaned.slice(0, 300)}`);
  }
}

async function orgGet(pathStr: string, params: Record<string, any> = {}, pc: string = "default"): Promise<any> {
  const raw = await organiserSSHRequest("GET", pathStr, pc, params);
  return parseOrganiserResponse(raw);
}

async function orgPost(pathStr: string, body: any, pc: string = "default"): Promise<any> {
  const raw = await organiserSSHRequest("POST", pathStr, pc, {}, body);
  return parseOrganiserResponse(raw);
}

// ---------------------------------------------------------------------------
// GitHub API Client with Automatic Fallback
// ---------------------------------------------------------------------------
const VALID_ACCOUNTS = new Set(["auto", "primary", "secondary", "tertiary"]);

function getGitHubToken(account: string = "auto"): { token: string; account: string } {
  if (!VALID_ACCOUNTS.has(account)) {
    throw new Error(`Unknown account '${account}' -- expected one of auto, primary, secondary, tertiary`);
  }
  const primary = (process.env.GITHUB_TOKEN || "").trim();
  const secondary = (process.env.GITHUB_TOKEN_SECONDARY || "").trim();
  const tertiary = (process.env.GITHUB_TOKEN_TERTIARY || "").trim();

  if (account === "primary") {
    if (!primary) throw new Error("GITHUB_TOKEN is not configured.");
    return { token: primary, account: "primary" };
  }
  if (account === "secondary") {
    if (!secondary) throw new Error("GITHUB_TOKEN_SECONDARY is not configured.");
    return { token: secondary, account: "secondary" };
  }
  if (account === "tertiary") {
    if (!tertiary) throw new Error("GITHUB_TOKEN_TERTIARY is not configured.");
    return { token: tertiary, account: "tertiary" };
  }

  // auto: primary -> secondary -> tertiary
  if (primary) return { token: primary, account: "primary" };
  if (secondary) return { token: secondary, account: "secondary" };
  if (tertiary) return { token: tertiary, account: "tertiary" };

  throw new Error("No GitHub tokens configured in environment.");
}

async function ghRequestWithFallback(
  method: string,
  apiPath: string,
  jsonBody?: any,
  account: string = "auto"
): Promise<any> {
  const { token, account: usedAccount } = getGitHubToken(account);
  const doFetch = async (tok: string) => {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${tok}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    };
    if (jsonBody && ["POST", "PATCH", "PUT"].includes(method.toUpperCase())) {
      headers["Content-Type"] = "application/json";
    }
    const res = await fetch(`${GITHUB_API}${apiPath}`, {
      method: method.toUpperCase(),
      headers,
      body: jsonBody ? JSON.stringify(jsonBody) : undefined,
    });
    return res;
  };

  let res = await doFetch(token);
  if ((res.status === 401 || res.status === 403) && account === "auto") {
    const fallbacks = [
      { name: "secondary", token: (process.env.GITHUB_TOKEN_SECONDARY || "").trim() },
      { name: "tertiary", token: (process.env.GITHUB_TOKEN_TERTIARY || "").trim() },
    ];
    for (const fb of fallbacks) {
      if (fb.token && fb.token !== token) {
        res = await doFetch(fb.token);
        if (res.status !== 401 && res.status !== 403) break;
      }
    }
  }

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`GitHub API error ${res.status}: ${errText}`);
  }

  const text = await res.text();
  return text ? JSON.parse(text) : {};
}

// ---------------------------------------------------------------------------
// Render & Fly API Helpers
// ---------------------------------------------------------------------------
function maskSecretValue(val: string): string {
  if (!val) return "";
  if (val.length <= 8) return "********";
  return `${val.slice(0, 4)}••••••••${val.slice(-4)}`;
}

// ---------------------------------------------------------------------------
// Express App & Middleware
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(cookieParser());

// Password auth middleware for MCP endpoint
app.use((req: Request, res: Response, next: NextFunction): void => {
  if (req.method === "OPTIONS") {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "*");
    res.header("Access-Control-Allow-Methods", "*");
    res.sendStatus(204);
    return;
  }

  const pathStr = req.path;
  if (
    pathStr === "/" ||
    pathStr === "/healthz" ||
    pathStr === "/.well-known/oauth-authorization-server" ||
    pathStr === "/.well-known/oauth-protected-resource" ||
    pathStr.startsWith("/admin") ||
    pathStr.startsWith("/oauth") ||
    pathStr.startsWith("/events")
  ) {
    return next();
  }

  const expectedPassword = (process.env.MCP_SERVER_PASSWORD || "").trim();
  if (!expectedPassword && OAUTH_TOKENS.size === 0) {
    if (isPublicDeployment) {
      res.status(503).json({ error: "Server misconfigured: MCP_SERVER_PASSWORD is not set on a public deployment." });
      return;
    }
    return next();
  }

  // 1. Authorization header
  let token = "";
  const authHeader = req.headers["authorization"] || "";
  if (authHeader) {
    token = authHeader.toLowerCase().startsWith("bearer ") ? authHeader.slice(7).trim() : authHeader.trim();
  }

  // 2. Query param
  if (!token) {
    token = (
      (req.query.access_token as string) ||
      (req.query.token as string) ||
      (req.query.auth as string) ||
      (req.query.api_key as string) ||
      ""
    ).trim();
  }

  // 3. Custom headers
  if (!token) {
    token = (
      (req.headers["x-access-token"] as string) ||
      (req.headers["x-api-key"] as string) ||
      (req.headers["x-mcp-token"] as string) ||
      ""
    ).trim();
  }

  if (!isValidToken(token)) {
    const host = allowedHost || req.headers["host"] || "localhost:3000";
    const baseUrl = host.startsWith("http") ? host : `https://${host}`;
    const protectedResUrl = `${baseUrl}/.well-known/oauth-protected-resource`;
    res.setHeader(
      "WWW-Authenticate",
      `Bearer realm="mcp", error="invalid_token", resource_metadata="${protectedResUrl}"`
    );
    res.status(401).json({ error: "Unauthorized: Invalid or missing bearer token." });
    return;
  }

  return next();
});

// ---------------------------------------------------------------------------
// Route Handlers: Root & Health
// ---------------------------------------------------------------------------
app.get("/", (req: Request, res: Response) => {
  res.json({
    status: "ok",
    service: "github-codespaces MCP server",
    message: "MCP endpoint is at /mcp — admin dashboard at /admin",
    mcp_endpoint: "/mcp",
    admin_endpoint: "/admin",
    allowed_host_configured: Boolean(allowedHost),
    auth_enabled: Boolean(process.env.MCP_SERVER_PASSWORD),
    admin_enabled: Boolean(ADMIN_PASSWORD),
    render_admin_configured: Boolean(RENDER_API_KEY),
    server_configured: Boolean(SERVER_HOST),
    pcs_configured: Object.keys(PC_REGISTRY).sort(),
    v2_dynamic_pcs: Object.keys(PC_V2_DYNAMIC_REGISTRY),
    accounts: {
      primary: Boolean(process.env.GITHUB_TOKEN),
      secondary: Boolean(process.env.GITHUB_TOKEN_SECONDARY),
      tertiary: Boolean(process.env.GITHUB_TOKEN_TERTIARY),
    },
  });
});

app.get("/healthz", (req: Request, res: Response) => {
  res.json({ status: "ok" });
});

// ---------------------------------------------------------------------------
// OAuth 2.1 Endpoints
// ---------------------------------------------------------------------------
app.get("/.well-known/oauth-authorization-server", (req: Request, res: Response) => {
  const host = allowedHost || req.headers["host"] || "localhost:3000";
  const baseUrl = host.startsWith("http") ? host : `https://${host}`;
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    registration_endpoint: `${baseUrl}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256", "plain"],
    scopes_supported: ["mcp"],
  });
});

app.get("/.well-known/oauth-protected-resource", (req: Request, res: Response) => {
  const host = allowedHost || req.headers["host"] || "localhost:3000";
  const baseUrl = host.startsWith("http") ? host : `https://${host}`;
  res.json({
    resource: baseUrl,
    authorization_servers: [baseUrl],
    scopes_supported: ["mcp"],
    bearer_methods_supported: ["header", "query"],
  });
});

app.post("/oauth/register", (req: Request, res: Response) => {
  const body = req.body || {};
  const clientId = `client_${crypto.randomBytes(8).toString("hex")}`;
  const clientSecret = `secret_${crypto.randomBytes(16).toString("hex")}`;
  const redirectUris = body.redirect_uris || ["https://claude.ai/api/mcp/auth_callback"];
  const clientName = body.client_name || "Client App";

  OAUTH_CLIENTS.set(clientId, {
    client_name: clientName,
    client_secret: clientSecret,
    redirect_uris: redirectUris,
  });

  res.status(201).json({
    client_id: clientId,
    client_secret: clientSecret,
    client_name: clientName,
    redirect_uris: redirectUris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });
});

function escapeHtml(s: any): string {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

app.get("/oauth/authorize", (req: Request, res: Response) => {
  const params = req.query;
  const clientId = escapeHtml(params.client_id || "");
  const redirectUri = escapeHtml(params.redirect_uri || "https://claude.ai/api/mcp/auth_callback");
  const state = escapeHtml(params.state || "");
  const codeChallenge = escapeHtml(params.code_challenge || "");
  const codeChallengeMethod = escapeHtml(params.code_challenge_method || "plain");

  let clientDisplayName = "Client App";
  const rawClient = OAUTH_CLIENTS.get(String(params.client_id || ""));
  if (rawClient?.client_name) {
    clientDisplayName = rawClient.client_name;
  } else if (String(params.redirect_uri || "").toLowerCase().includes("chatgpt")) {
    clientDisplayName = "ChatGPT";
  } else if (String(params.redirect_uri || "").toLowerCase().includes("claude")) {
    clientDisplayName = "Claude Web";
  }

  const errorHtml = params.error
    ? '<div style="color: #ef4444; background: #451a1a; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; border: 1px solid #7f1d1d;">Invalid password. Please try again.</div>'
    : "";

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize ${escapeHtml(clientDisplayName)} MCP Server</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; display: flex; justify-content: center; align-items: center; min-height: 80vh; }
    .card { background: #1e293b; border-radius: 12px; padding: 2.5rem; max-width: 450px; width: 100%; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }
    h1 { color: #38bdf8; margin-top: 0; font-size: 1.5rem; text-align: center; }
    p { color: #94a3b8; font-size: 0.95rem; text-align: center; line-height: 1.5; }
    label { font-weight: 600; color: #cbd5e1; font-size: 0.9rem; margin-bottom: 0.5rem; display: block; }
    input[type="password"] { width: 100%; padding: 0.75rem; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font-size: 1rem; margin-bottom: 1.25rem; box-sizing: border-box; }
    input[type="password"]:focus { outline: none; border-color: #38bdf8; }
    button { width: 100%; background: #0284c7; color: white; border: none; padding: 0.8rem; border-radius: 6px; font-size: 1rem; font-weight: 600; cursor: pointer; }
    button:hover { background: #0369a1; }
    .badge { background: #0369a1; color: #e0f2fe; font-size: 0.8rem; padding: 0.2rem 0.5rem; border-radius: 4px; font-family: monospace; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorize Connector</h1>
    <p>An application <span class="badge">${escapeHtml(clientDisplayName)}</span> is requesting access to your <strong>Gemini MCP Server</strong>.</p>
    ${errorHtml}
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="${clientId}">
      <input type="hidden" name="redirect_uri" value="${redirectUri}">
      <input type="hidden" name="state" value="${state}">
      <input type="hidden" name="code_challenge" value="${codeChallenge}">
      <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}">
      
      <label for="password">Enter MCP Server Password:</label>
      <input type="password" id="password" name="password" required autofocus placeholder="Enter password...">
      
      <button type="submit">Authorize & Return to Claude</button>
    </form>
  </div>
</body>
</html>`;
  res.send(html);
});

app.post("/oauth/authorize", (req: Request, res: Response) => {
  const password = String(req.body.password || "").trim();
  const clientId = String(req.body.client_id || "");
  const redirectUri = String(req.body.redirect_uri || "https://claude.ai/api/mcp/auth_callback");
  const state = String(req.body.state || "");
  const codeChallenge = String(req.body.code_challenge || "");
  const codeChallengeMethod = String(req.body.code_challenge_method || "plain");

  const expectedPassword = (process.env.MCP_SERVER_PASSWORD || "").trim();
  let isValid = false;
  if (expectedPassword && safeCompare(password, expectedPassword)) isValid = true;
  else if (ADMIN_PASSWORD && safeCompare(password, ADMIN_PASSWORD)) isValid = true;

  if (!isValid) {
    const errParams = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      error: "1",
    });
    res.redirect(`/oauth/authorize?${errParams.toString()}`);
    return;
  }

  const code = `code_${crypto.randomBytes(16).toString("hex")}`;
  OAUTH_CODES.set(code, {
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    expires_at: Date.now() / 1000 + 600,
  });

  const target = new URL(redirectUri);
  target.searchParams.set("code", code);
  if (state) target.searchParams.set("state", state);
  res.redirect(target.toString());
});

app.post("/oauth/token", (req: Request, res: Response) => {
  const body = req.body || {};
  const grantType = body.grant_type || "authorization_code";
  const code = body.code || "";
  const refreshToken = body.refresh_token || "";
  const codeVerifier = body.code_verifier || "";

  if (grantType === "refresh_token") {
    const newAccessToken = generateOAuthToken();
    const newRefreshToken = generateRefreshToken();
    OAUTH_TOKENS.add(newAccessToken);
    if (refreshToken) OAUTH_REFRESH_TOKENS.set(refreshToken, newAccessToken);
    saveOAuthData();
    res.json({
      access_token: newAccessToken,
      token_type: "Bearer",
      expires_in: 315360000,
      refresh_token: newRefreshToken,
      scope: "mcp",
    });
    return;
  }

  if (grantType !== "authorization_code" || !code || !OAUTH_CODES.has(code)) {
    res.status(400).json({ error: "invalid_grant", error_description: "Invalid or expired authorization code" });
    return;
  }

  const codeInfo = OAUTH_CODES.get(code)!;
  OAUTH_CODES.delete(code);

  if (Date.now() / 1000 > codeInfo.expires_at) {
    res.status(400).json({ error: "invalid_grant", error_description: "Authorization code expired" });
    return;
  }

  if (codeInfo.code_challenge && codeVerifier) {
    if (codeInfo.code_challenge_method === "S256") {
      const hash = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
      if (hash !== codeInfo.code_challenge.replace(/=+$/, "")) {
        res.status(400).json({ error: "invalid_grant", error_description: "PKCE code_verifier check failed" });
        return;
      }
    } else {
      if (codeVerifier !== codeInfo.code_challenge) {
        res.status(400).json({ error: "invalid_grant", error_description: "PKCE code_verifier check failed" });
        return;
      }
    }
  }

  const accessToken = generateOAuthToken();
  const newRefreshToken = generateRefreshToken();
  OAUTH_TOKENS.add(accessToken);
  OAUTH_REFRESH_TOKENS.set(newRefreshToken, accessToken);
  saveOAuthData();

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 315360000,
    refresh_token: newRefreshToken,
    scope: "mcp",
  });
});

// ---------------------------------------------------------------------------
// Admin Dashboard
// ---------------------------------------------------------------------------
const ADMIN_PAGE_TEMPLATE = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>codespaces-mcp admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: dark; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #0d1117; color: #e6edf3;
         max-width: 900px; margin: 0 auto; padding: 24px 16px; line-height: 1.5; }
  h1 { font-size: 1.3rem; }
  h2 { font-size: 1.05rem; border-bottom: 1px solid #30363d; padding-bottom: 6px; margin-top: 2rem; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  input, textarea, button, select { font-family: inherit; font-size: 0.9rem; }
  input[type=text], input[type=password] { background: #0d1117; border: 1px solid #30363d; color: #e6edf3;
         border-radius: 6px; padding: 8px 10px; width: 100%; box-sizing: border-box; }
  button { background: #238636; border: none; color: white; border-radius: 6px; padding: 8px 14px;
         cursor: pointer; margin-top: 8px; }
  button:hover { background: #2ea043; }
  button.secondary { background: #30363d; }
  button.secondary:hover { background: #3f4652; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  td, th { text-align: left; padding: 6px 8px; border-bottom: 1px solid #21262d; }
  .pass { color: #3fb950; } .fail { color: #f85149; } .skip { color: #8b949e; }
  pre { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 10px;
        overflow-x: auto; white-space: pre-wrap; word-break: break-word; font-size: 0.82rem; }
  .row { display: flex; gap: 8px; }
  .row > * { flex: 1; }
  .muted { color: #8b949e; font-size: 0.85rem; }
</style>
</head>
<body>
__BODY__
</body>
</html>`;

const ADMIN_LOGIN_BODY = `
<h1>codespaces-mcp admin</h1>
<div class="card">
  <form method="POST" action="/admin/login">
    <label class="muted">Admin password</label>
    <input type="password" name="password" autofocus>
    <button type="submit">Log in</button>
  </form>
  __ERROR__
</div>
`;

const ADMIN_DASHBOARD_BODY = `
<h1>codespaces-mcp admin</h1>
<p class="muted">Signed in. <a href="/admin/logout" style="color:#58a6ff;">Log out</a></p>

<h2>Render settings</h2>
<div class="card">
  <p class="muted">Service: <code>__SERVICE_ID__</code></p>
  <div id="env-table">Loading…</div>
  <div class="row" style="margin-top:12px;">
    <input type="text" id="env-key" placeholder="KEY (e.g. MCP_SERVER_PASSWORD)">
    <input type="text" id="env-value" placeholder="value">
  </div>
  <button onclick="setEnvVar()">Save variable</button>
  <button class="secondary" onclick="triggerDeploy()">Trigger redeploy</button>
  <pre id="env-result"></pre>
</div>

<h2>Linux server</h2>
<div class="card">
  <input type="text" id="server-cmd" placeholder="command to run on Linux server">
  <button onclick="runServerCmd()">Run</button>
  <pre id="server-result"></pre>
</div>

<h2>Diagnostics</h2>
<div class="card">
  <button onclick="runDiagnostics()">Run all tests</button>
  <div id="diag-result"></div>
</div>

<script>
function esc(s) {
  const d = document.createElement("div");
  d.innerText = String(s ?? "");
  return d.innerHTML;
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (r.status === 401) { window.location = "/admin"; return null; }
  return r.json();
}

async function loadEnv() {
  const data = await api("/admin/api/env");
  if (!data) return;
  if (data.error) { document.getElementById("env-table").innerText = data.error; return; }
  let rows = data.vars.map(v =>
    \`<tr><td>\${esc(v.key)}</td><td>\${esc(v.value)}</td></tr>\`
  ).join("");
  document.getElementById("env-table").innerHTML =
    \`<table><tr><th>Key</th><th>Value</th></tr>\${rows}</table>\`;
}

async function setEnvVar() {
  const key = document.getElementById("env-key").value.trim();
  const value = document.getElementById("env-value").value;
  if (!key) return;
  const data = await api("/admin/api/env", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({key, value})
  });
  document.getElementById("env-result").innerText = JSON.stringify(data, null, 2);
  loadEnv();
}

async function triggerDeploy() {
  const data = await api("/admin/api/deploy", {method: "POST"});
  document.getElementById("env-result").innerText = JSON.stringify(data, null, 2);
}

async function runServerCmd() {
  const command = document.getElementById("server-cmd").value;
  const data = await api("/admin/api/server/run", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({command})
  });
  document.getElementById("server-result").innerText = data.output ?? JSON.stringify(data, null, 2);
}

async function runDiagnostics() {
  document.getElementById("diag-result").innerText = "Running…";
  const data = await api("/admin/api/diagnostics");
  if (!data) return;
  let rows = data.checks.map(c =>
    \`<tr><td class="\${esc(c.status)}">\${esc(c.status)}</td><td>\${esc(c.name)}</td><td>\${esc(c.detail)}</td></tr>\`
  ).join("");
  document.getElementById("diag-result").innerHTML =
    \`<p class="muted">\${esc(data.summary)}</p><table><tr><th>Status</th><th>Check</th><th>Detail</th></tr>\${rows}</table>\`;
}

loadEnv();
</script>
`;

app.get("/admin", (req: Request, res: Response) => {
  if (!requireAdminAuthed(req)) {
    const body = ADMIN_LOGIN_BODY.replace("__ERROR__", "");
    res.send(ADMIN_PAGE_TEMPLATE.replace("__BODY__", body));
    return;
  }
  const body = ADMIN_DASHBOARD_BODY.replace("__SERVICE_ID__", escapeHtml(RENDER_SERVICE_ID));
  res.send(ADMIN_PAGE_TEMPLATE.replace("__BODY__", body));
});

const ADMIN_LOGIN_ATTEMPTS = new Map<string, number[]>();

app.post("/admin/login", (req: Request, res: Response) => {
  const password = String(req.body.password || "").trim();
  const ip = req.ip || req.socket.remoteAddress || "unknown";

  const now = Date.now() / 1000;
  const attempts = (ADMIN_LOGIN_ATTEMPTS.get(ip) || []).filter((t) => now - t < 60);
  ADMIN_LOGIN_ATTEMPTS.set(ip, attempts);

  if (attempts.length >= 5) {
    const body = ADMIN_LOGIN_BODY.replace(
      "__ERROR__",
      "<p style='color:#f85149'>Too many failed login attempts. Please wait 1 minute.</p>"
    );
    res.status(429).send(ADMIN_PAGE_TEMPLATE.replace("__BODY__", body));
    return;
  }

  let ok = false;
  if (ADMIN_PASSWORD && safeCompare(password, ADMIN_PASSWORD)) ok = true;
  else if (process.env.MCP_SERVER_PASSWORD && safeCompare(password, process.env.MCP_SERVER_PASSWORD)) ok = true;

  if (!ok) {
    attempts.push(now);
    const body = ADMIN_LOGIN_BODY.replace(
      "__ERROR__",
      "<p style='color:#f85149'>Incorrect password.</p>"
    );
    res.status(401).send(ADMIN_PAGE_TEMPLATE.replace("__BODY__", body));
    return;
  }

  res.cookie(ADMIN_COOKIE_NAME, adminMakeCookie(), {
    path: "/admin",
    httpOnly: true,
    sameSite: "lax",
    maxAge: ADMIN_SESSION_TTL * 1000,
  });
  res.redirect("/admin");
});

app.get("/admin/logout", (req: Request, res: Response) => {
  res.clearCookie(ADMIN_COOKIE_NAME, { path: "/admin" });
  res.redirect("/admin");
});

app.get("/admin/api/env", async (req: Request, res: Response) => {
  if (!requireAdminAuthed(req)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  if (FLY_API_TOKEN && FLY_APP_NAME) {
    // Fly secrets query
    const query = `query($appId: String!) { app(name: $appId) { secrets { name } } }`;
    try {
      const resp = await fetch(FLY_API, {
        method: "POST",
        headers: { Authorization: `Bearer ${FLY_API_TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify({ query, variables: { appId: FLY_APP_NAME } }),
      });
      const data = await resp.json();
      const secrets = data?.data?.app?.secrets || [];
      const envVars = secrets.map((s: any) => ({ key: s.name, value: "••••••••" }));
      res.json({ vars: envVars, platform: "fly" });
      return;
    } catch (err: any) {
      res.status(502).json({ error: `Fly.io API error: ${err.message}` });
      return;
    }
  }

  if (RENDER_API_KEY && RENDER_SERVICE_ID) {
    try {
      const resp = await fetch(`${RENDER_API}/services/${RENDER_SERVICE_ID}/env-vars`, {
        headers: { Authorization: `Bearer ${RENDER_API_KEY}`, Accept: "application/json" },
      });
      const items = await resp.json();
      const envVars = items.map((i: any) => ({
        key: i.envVar.key,
        value: maskSecretValue(i.envVar.value),
      }));
      envVars.sort((a: any, b: any) => a.key.localeCompare(b.key));
      res.json({ vars: envVars, platform: "render" });
      return;
    } catch (err: any) {
      res.status(502).json({ error: `Render API error: ${err.message}` });
      return;
    }
  }

  res.json({ error: "Neither FLY_API_TOKEN nor RENDER_API_KEY is configured on this deployment." });
});

app.post("/admin/api/env", async (req: Request, res: Response) => {
  if (!requireAdminAuthed(req)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const { key, value } = req.body;
  if (!key) {
    res.status(400).json({ error: "Missing 'key'." });
    return;
  }

  if (RENDER_API_KEY && RENDER_SERVICE_ID) {
    try {
      const resp = await fetch(`${RENDER_API}/services/${RENDER_SERVICE_ID}/env-vars/${key}`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${RENDER_API_KEY}`,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ value: String(value || "") }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      res.json({ ok: true, note: "Saved. Click 'Trigger redeploy' for it to take effect." });
      return;
    } catch (err: any) {
      res.status(502).json({ error: `Render API error: ${err.message}` });
      return;
    }
  }

  res.status(400).json({ error: "Neither FLY_API_TOKEN nor RENDER_API_KEY is configured on this deployment." });
});

app.post("/admin/api/deploy", async (req: Request, res: Response) => {
  if (!requireAdminAuthed(req)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  if (RENDER_API_KEY && RENDER_SERVICE_ID) {
    try {
      const resp = await fetch(`${RENDER_API}/services/${RENDER_SERVICE_ID}/deploys`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${RENDER_API_KEY}`,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ clearCache: "do_not_clear" }),
      });
      const data = await resp.json();
      res.json({ ok: true, deploy: data });
      return;
    } catch (err: any) {
      res.status(502).json({ error: `Render API error: ${err.message}` });
      return;
    }
  }

  res.status(400).json({ error: "Neither FLY_API_TOKEN nor RENDER_API_KEY is configured." });
});

app.post("/admin/api/server/run", async (req: Request, res: Response) => {
  if (!requireAdminAuthed(req)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const command = String(req.body.command || "").trim();
  if (!command) {
    res.status(400).json({ error: "Missing 'command'." });
    return;
  }
  const output = await sshServer(command, 30);
  res.json({ output });
});

// Diagnostics engine
async function executeDiagnosticsSweep(): Promise<any> {
  const checks: Array<{ name: string; status: "pass" | "fail" | "skip"; detail: string }> = [];

  const check = async (label: string, fn: Promise<string>) => {
    try {
      const detail = await fn;
      checks.push({ name: label, status: "pass", detail });
    } catch (err: any) {
      checks.push({ name: label, status: "fail", detail: err?.message || String(err) });
    }
  };

  // GitHub tokens
  const tokens = [
    { name: "primary", token: process.env.GITHUB_TOKEN },
    { name: "secondary", token: process.env.GITHUB_TOKEN_SECONDARY },
    { name: "tertiary", token: process.env.GITHUB_TOKEN_TERTIARY },
  ];
  for (const t of tokens) {
    const label = `GitHub token (${t.name})`;
    if (!t.token) {
      checks.push({ name: label, status: "skip", detail: "not configured" });
      continue;
    }
    await check(label, (async () => {
      const res = await fetch(`${GITHUB_API}/user`, {
        headers: { Authorization: `Bearer ${t.token}`, Accept: "application/vnd.github+json" },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      return `authenticated as ${data.login || "?"}`;
    })());
  }

  // Codespaces API
  await check("Codespaces API", (async () => {
    const data = await ghRequestWithFallback("GET", "/user/codespaces");
    return `${(data.codespaces || []).length} codespace(s) visible`;
  })());

  // Linux server
  await check("Linux server", (async () => {
    const out = await sshServer("echo alive", 15);
    if (!out.includes("alive")) throw new Error(out.slice(0, 200) || "no response");
    return `${SERVER_USER}@${SERVER_HOST} reachable`;
  })());

  // Configured PCs
  for (const pcName of Object.keys(PC_REGISTRY).sort()) {
    await check(`PC '${pcName}'`, (async () => {
      const data = await orgGet("/status", {}, pcName);
      return `${data.platform || "?"} v${data.version || "?"}`;
    })());
  }

  // Render API
  if (RENDER_API_KEY && RENDER_SERVICE_ID) {
    await check("Render API", (async () => {
      const resp = await fetch(`${RENDER_API}/services/${RENDER_SERVICE_ID}`, {
        headers: { Authorization: `Bearer ${RENDER_API_KEY}`, Accept: "application/json" },
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      return data.name || "?";
    })());
  } else {
    checks.push({ name: "Render API", status: "skip", detail: "RENDER_API_KEY/RENDER_SERVICE_ID not configured" });
  }

  const passed = checks.filter((c) => c.status === "pass").length;
  const failed = checks.filter((c) => c.status === "fail").length;
  const skipped = checks.filter((c) => c.status === "skip").length;
  return {
    checks,
    summary: `${passed} passed, ${failed} failed, ${skipped} skipped`,
  };
}

app.get("/admin/api/diagnostics", async (req: Request, res: Response) => {
  if (!requireAdminAuthed(req)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const report = await executeDiagnosticsSweep();
  res.json(report);
});

// Dynamic PC event status
app.post("/events/pc_status", (req: Request, res: Response) => {
  const expectedToken = process.env.MCP_SERVER_PASSWORD || ADMIN_PASSWORD;
  if (expectedToken) {
    const auth = req.headers["authorization"] || "";
    if (!auth.startsWith("Bearer ") || auth.slice(7) !== expectedToken) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }
  }

  const data = req.body || {};
  const name = data.machine_name || data.machine_id || "unknown";
  const eventStatus = data.event || "online";

  PC_V2_DYNAMIC_REGISTRY[name] = {
    id: data.machine_id,
    name,
    event: eventStatus,
    lan_ip: data.lan_ip || "",
    port: data.port || 0,
    timestamp: data.timestamp || "",
    last_updated: Date.now() / 1000,
  };

  if (data.port && eventStatus === "online") {
    PC_REGISTRY[name] = {
      port: parseInt(data.port, 10),
      secret: data.secret || process.env.ORGANISER_SECRET || "",
      lan_ip: data.lan_ip || "127.0.0.1",
    };
  }

  res.json({ status: "received", pc: name, event: eventStatus });
});

// ---------------------------------------------------------------------------
// File Transfer Support
// ---------------------------------------------------------------------------
const FILE_TRANSFER_MAX_BYTES = 15 * 1024 * 1024; // 15 MB

function parseLocation(loc: string): { kind: string; name: string; path: string } {
  if (!loc.includes(":")) {
    throw new Error(`Malformed location '${loc}' -- expected 'kind:path' or 'kind:name:path'`);
  }
  const [kind, ...restParts] = loc.split(":");
  const rest = restParts.join(":");
  const normalizedKind = kind.trim().toLowerCase();

  if (normalizedKind === "sandbox" || normalizedKind === "server") {
    return { kind: normalizedKind, name: "", path: rest };
  }
  if (normalizedKind === "pc" || normalizedKind === "codespace") {
    if (!rest.includes(":")) {
      throw new Error(`Malformed '${normalizedKind}:' location '${loc}' -- expected '${normalizedKind}:name:path'`);
    }
    const [name, ...pathParts] = rest.split(":");
    const finalPath = pathParts.join(":");
    const checkName = normalizedKind === "codespace" ? name.split("@")[0] : name;
    if (!checkName) {
      throw new Error(`Malformed '${normalizedKind}:' location '${loc}' -- empty name before path`);
    }
    return { kind: normalizedKind, name, path: finalPath };
  }
  throw new Error(`Unknown location kind '${normalizedKind}' -- expected sandbox, server, pc, or codespace`);
}

async function locationReadBytes(loc: string): Promise<Buffer> {
  const { kind, name, path: p } = parseLocation(loc);

  if (kind === "sandbox") {
    return fs.readFileSync(p);
  }

  if (kind === "server") {
    const sizeStr = (await sshServer(`stat -c%s ${shQuote(p)} 2>&1`)).trim();
    const size = parseInt(sizeStr, 10);
    if (isNaN(size)) throw new Error(`Could not stat '${p}' on server (got: ${sizeStr.slice(0, 200)})`);
    if (size > FILE_TRANSFER_MAX_BYTES) {
      throw new Error(`'${p}' on server is ${size} bytes, over the ${FILE_TRANSFER_MAX_BYTES} byte limit.`);
    }
    const b64 = await sshServer(`base64 -w0 ${shQuote(p)} 2>&1`);
    return Buffer.from(b64, "base64");
  }

  if (kind === "pc") {
    const data = await orgGet("/read_file_b64", { path: p, max_bytes: FILE_TRANSFER_MAX_BYTES }, name || "default");
    if (!data.content_b64) {
      throw new Error(`Could not read '${p}' from pc:${name} -- ${data.error || "unknown error"}`);
    }
    return Buffer.from(data.content_b64, "base64");
  }

  if (kind === "codespace") {
    const [csName, account] = name.includes("@") ? name.split("@") : [name, "auto"];
    const out = await runCodespaceCommand(csName, `base64 -w0 ${shQuote(p)} 2>&1`, 60, account);
    return Buffer.from(out.trim(), "base64");
  }

  throw new Error(`Unsupported read kind '${kind}'`);
}

async function locationWriteBytes(loc: string, data: Buffer): Promise<string> {
  const { kind, name, path: p } = parseLocation(loc);

  if (kind === "sandbox") {
    const dir = path.dirname(p);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(p, data);
    return `Wrote ${data.length} bytes to sandbox:${p}`;
  }

  if (kind === "server") {
    const b64 = data.toString("base64");
    const cmd = `mkdir -p $(dirname ${shQuote(p)}) && echo ${shQuote(b64)} | base64 -d > ${shQuote(p)} && echo OK`;
    const res = await sshServer(cmd, 60);
    if (!res.includes("OK")) throw new Error(`Server write failed: ${res}`);
    return `Wrote ${data.length} bytes to server:${p}`;
  }

  if (kind === "pc") {
    const b64 = data.toString("base64");
    const res = await orgPost("/write_file_b64", { path: p, content_b64: b64 }, name || "default");
    return res.message || `Wrote ${data.length} bytes to pc:${name}:${p}`;
  }

  if (kind === "codespace") {
    const [csName, account] = name.includes("@") ? name.split("@") : [name, "auto"];
    const b64 = data.toString("base64");
    const cmd = `mkdir -p $(dirname ${shQuote(p)}) && echo ${shQuote(b64)} | base64 -d > ${shQuote(p)} && echo __WRITE_OK__`;
    const res = await runCodespaceCommand(csName, cmd, 60, account);
    if (!res.includes("__WRITE_OK__")) throw new Error(`Codespace write failed: ${res}`);
    return `Wrote ${data.length} bytes to codespace:${name}:${p}`;
  }

  throw new Error(`Unsupported write kind '${kind}'`);
}

// ---------------------------------------------------------------------------
// Codespace Execution Helper
// ---------------------------------------------------------------------------
async function runCodespaceCommand(
  codespaceName: string,
  command: string,
  timeoutSeconds: number = 60,
  account: string = "auto"
): Promise<string> {
  const { token } = getGitHubToken(account);
  // Execute via gh CLI if present, or via GitHub codespaces API
  try {
    const res = await runLocal(
      "gh",
      ["codespace", "ssh", "--codespace", codespaceName, "--", command],
      timeoutSeconds * 1000
    );
    return (res.stdout + res.stderr).trim();
  } catch (e: any) {
    return `Codespace exec failed: ${e.message}`;
  }
}

// ---------------------------------------------------------------------------
// MCP Protocol & Tool Definitions
// ---------------------------------------------------------------------------
interface MCPToolDef {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, any>;
    required?: string[];
  };
  handler: (args: any) => Promise<string>;
}

const MCP_TOOLS: MCPToolDef[] = [
  // --- Group 1: Codespaces ---
  {
    name: "check_account_status",
    description: "Check validity and user identities for primary, secondary, and tertiary GitHub tokens.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const results: string[] = [];
      const tokens = [
        { label: "Primary", token: process.env.GITHUB_TOKEN },
        { label: "Secondary", token: process.env.GITHUB_TOKEN_SECONDARY },
        { label: "Tertiary", token: process.env.GITHUB_TOKEN_TERTIARY },
      ];
      for (const item of tokens) {
        if (!item.token) {
          results.push(`• **${item.label} Token**: Not configured.`);
          continue;
        }
        try {
          const res = await fetch(`${GITHUB_API}/user`, {
            headers: { Authorization: `Bearer ${item.token}`, Accept: "application/vnd.github+json" },
          });
          if (res.ok) {
            const data = await res.json();
            results.push(`• **${item.label} Token**: ✅ Active (User: \`${data.login}\` - ${data.name || data.login})`);
          } else {
            results.push(`• **${item.label} Token**: ❌ Invalid/Expired (HTTP ${res.status})`);
          }
        } catch (e: any) {
          results.push(`• **${item.label} Token**: ⚠️ Network error (${e.name || "Error"})`);
        }
      }
      return results.join("\n");
    },
  },
  {
    name: "list_codespaces",
    description: "List caller's GitHub Codespaces: name, repo, state, and machine spec.",
    inputSchema: {
      type: "object",
      properties: { account: { type: "string", default: "auto", description: "auto, primary, secondary, tertiary" } },
    },
    handler: async (args) => {
      const data = await ghRequestWithFallback("GET", "/user/codespaces", undefined, args.account || "auto");
      const list = data.codespaces || [];
      if (!list.length) return "No codespaces found.";
      return list
        .map(
          (cs: any) =>
            `- ${cs.name} | repo: ${cs.repository?.full_name} | state: ${cs.state} | machine: ${cs.machine?.display_name}`
        )
        .join("\n");
    },
  },
  {
    name: "create_codespace",
    description: "Create a new codespace for a given repository.",
    inputSchema: {
      type: "object",
      properties: {
        repo_full_name: { type: "string", description: "owner/repo" },
        branch: { type: "string", default: "main" },
        machine_type: { type: "string", default: "" },
        account: { type: "string", default: "auto" },
      },
      required: ["repo_full_name"],
    },
    handler: async (args) => {
      const body: any = { ref: args.branch || "main" };
      if (args.machine_type) body.machine = args.machine_type;
      const data = await ghRequestWithFallback("POST", `/repos/${args.repo_full_name}/codespaces`, body, args.account || "auto");
      return `Created codespace '${data.name}' (state: ${data.state})`;
    },
  },
  {
    name: "start_codespace",
    description: "Start a stopped/shutdown codespace by name and wait for it to become Available.",
    inputSchema: {
      type: "object",
      properties: {
        codespace_name: { type: "string" },
        account: { type: "string", default: "auto" },
      },
      required: ["codespace_name"],
    },
    handler: async (args) => {
      try {
        const data = await ghRequestWithFallback("POST", `/user/codespaces/${args.codespace_name}/start`, undefined, args.account || "auto");
        const state = data.state || "starting";
        if (state === "Available" || state === "Running") {
          return `Codespace '${args.codespace_name}' is now running.`;
        }
        return `Start requested for '${args.codespace_name}'. Current state: ${state}.`;
      } catch (e: any) {
        return `Failed to start codespace '${args.codespace_name}': ${e.message}`;
      }
    },
  },
  {
    name: "stop_codespace",
    description: "Stop a running codespace by name.",
    inputSchema: {
      type: "object",
      properties: { codespace_name: { type: "string" }, account: { type: "string", default: "auto" } },
      required: ["codespace_name"],
    },
    handler: async (args) => {
      await ghRequestWithFallback("POST", `/user/codespaces/${args.codespace_name}/stop`, undefined, args.account || "auto");
      return `Stop requested for '${args.codespace_name}'.`;
    },
  },
  {
    name: "rebuild_codespace",
    description: "Trigger a full devcontainer rebuild inside a codespace.",
    inputSchema: {
      type: "object",
      properties: { codespace_name: { type: "string" }, account: { type: "string", default: "auto" } },
      required: ["codespace_name"],
    },
    handler: async (args) => {
      const data = await ghRequestWithFallback("POST", `/user/codespaces/${args.codespace_name}/rebuild`, undefined, args.account || "auto");
      return `Rebuild initiated for '${args.codespace_name}'. State: ${data.state || "queued"}`;
    },
  },
  {
    name: "set_machine_type",
    description: "Scale machine specs (e.g. 'standardLinux32Gb' or 'premiumLinux').",
    inputSchema: {
      type: "object",
      properties: {
        codespace_name: { type: "string" },
        machine_type: { type: "string" },
        account: { type: "string", default: "auto" },
      },
      required: ["codespace_name", "machine_type"],
    },
    handler: async (args) => {
      await ghRequestWithFallback("PATCH", `/user/codespaces/${args.codespace_name}`, { machine: args.machine_type }, args.account || "auto");
      return `Machine updated to '${args.machine_type}' for '${args.codespace_name}'.`;
    },
  },
  {
    name: "exec_command",
    description: "Run a single shell command inside a codespace asynchronously via SSH.",
    inputSchema: {
      type: "object",
      properties: {
        codespace_name: { type: "string" },
        command: { type: "string" },
        timeout_seconds: { type: "number", default: 60 },
        account: { type: "string", default: "auto" },
      },
      required: ["codespace_name", "command"],
    },
    handler: async (args) => {
      return await runCodespaceCommand(args.codespace_name, args.command, args.timeout_seconds || 60, args.account || "auto");
    },
  },
  {
    name: "read_codespace_file",
    description: "Read contents of a remote file in the codespace.",
    inputSchema: {
      type: "object",
      properties: {
        codespace_name: { type: "string" },
        file_path: { type: "string" },
        account: { type: "string", default: "auto" },
      },
      required: ["codespace_name", "file_path"],
    },
    handler: async (args) => {
      return await runCodespaceCommand(args.codespace_name, `cat ${shQuote(args.file_path)}`, 15, args.account || "auto");
    },
  },
  {
    name: "write_codespace_file",
    description: "Safely write/overwrite content to a file in the codespace using base64 encoding.",
    inputSchema: {
      type: "object",
      properties: {
        codespace_name: { type: "string" },
        file_path: { type: "string" },
        content: { type: "string" },
        account: { type: "string", default: "auto" },
      },
      required: ["codespace_name", "file_path", "content"],
    },
    handler: async (args) => {
      const b64 = Buffer.from(args.content).toString("base64");
      const cmd = `mkdir -p $(dirname ${shQuote(args.file_path)}) && echo ${shQuote(b64)} | base64 -d > ${shQuote(args.file_path)} && echo __WRITE_OK__`;
      const res = await runCodespaceCommand(args.codespace_name, cmd, 15, args.account || "auto");
      if (!res.includes("__WRITE_OK__")) return `Write failed for '${args.file_path}': ${res}`;
      return `Successfully wrote ${args.content.length} characters to '${args.file_path}'.`;
    },
  },
  {
    name: "list_workspace_files",
    description: "List directory contents or file tree inside the codespace.",
    inputSchema: {
      type: "object",
      properties: {
        codespace_name: { type: "string" },
        path: { type: "string", default: "." },
        account: { type: "string", default: "auto" },
      },
      required: ["codespace_name"],
    },
    handler: async (args) => {
      return await runCodespaceCommand(
        args.codespace_name,
        `find ${shQuote(args.path || ".")} -maxdepth 2 -not -path '*/.*'`,
        15,
        args.account || "auto"
      );
    },
  },
  {
    name: "get_git_status",
    description: "Get concise git status and branch info in the codespace working directory.",
    inputSchema: {
      type: "object",
      properties: {
        codespace_name: { type: "string" },
        repo_path: { type: "string", default: "." },
        account: { type: "string", default: "auto" },
      },
      required: ["codespace_name"],
    },
    handler: async (args) => {
      return await runCodespaceCommand(
        args.codespace_name,
        `cd ${shQuote(args.repo_path || ".")} && git status --short -b`,
        15,
        args.account || "auto"
      );
    },
  },
  {
    name: "create_git_commit_and_push",
    description: "Stage tracked changes, commit, and push to remote.",
    inputSchema: {
      type: "object",
      properties: {
        codespace_name: { type: "string" },
        commit_message: { type: "string" },
        repo_path: { type: "string", default: "." },
        branch: { type: "string", default: "" },
        account: { type: "string", default: "auto" },
      },
      required: ["codespace_name", "commit_message"],
    },
    handler: async (args) => {
      const pushArgs = args.branch ? `origin ${shQuote(args.branch)}` : "";
      const cmd = `cd ${shQuote(args.repo_path || ".")} && git add -u && git commit -m ${shQuote(args.commit_message)} && git push ${pushArgs}`;
      return await runCodespaceCommand(args.codespace_name, cmd, 30, args.account || "auto");
    },
  },
  {
    name: "list_forwarded_ports",
    description: "List currently forwarded network ports and dev server addresses.",
    inputSchema: {
      type: "object",
      properties: { codespace_name: { type: "string" }, account: { type: "string", default: "auto" } },
      required: ["codespace_name"],
    },
    handler: async (args) => {
      const data = await ghRequestWithFallback("GET", `/user/codespaces/${args.codespace_name}/ports`, undefined, args.account || "auto");
      const ports = data.ports || [];
      if (!ports.length) return `No forwarded ports found for '${args.codespace_name}'.`;
      return ports
        .map(
          (p: any) =>
            `- Port ${p.port_number} ${p.label ? `(${p.label})` : ""} visibility=${p.visibility} url=${p.browser_url || p.preview_url || ""}`
        )
        .join("\n");
    },
  },

  // --- Group 2: Linux Server Management ---
  {
    name: "server_status",
    description: "Get an overview of the home Linux server: disk, RAM, and (optionally) processes/breakdown.",
    inputSchema: {
      type: "object",
      properties: {
        disk_detail: { type: "boolean", default: false },
        disk_path: { type: "string", default: "/" },
        processes: { type: "boolean", default: false },
      },
    },
    handler: async (args) => {
      const disk = await sshServer("df -h / /mnt/ssd 2>/dev/null | tail -2");
      const ram = await sshServer("free -h | grep Mem");
      const parts = [`**Disk:**\n${disk}`, `**RAM:**\n${ram}`];
      if (args.disk_detail) {
        const breakdown = await sshServer(`du -h --max-depth=2 ${shQuote(args.disk_path || "/")} 2>/dev/null | sort -rh | head -30`);
        parts.push(`**Disk breakdown of ${args.disk_path || "/"}:**\n${breakdown}`);
      }
      if (args.processes) {
        const top = await sshServer("ps aux --sort=-%cpu | head -20");
        parts.push(`**Top processes:**\n${top}`);
      }
      return parts.join("\n\n");
    },
  },
  {
    name: "server_run_command",
    description: "Run a shell command on the home Linux server over SSH.",
    inputSchema: {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"],
    },
    handler: async (args) => {
      const blocked = ["rm -rf /", "mkfs", "dd if=", "> /dev/sda", "shutdown now", "halt"];
      for (const b of blocked) {
        if (args.command.includes(b)) return `Blocked: '${b}' is not allowed.`;
      }
      return await sshServer(args.command);
    },
  },
  {
    name: "server_list_files",
    description: "List files and directories at a path on the Linux server.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, recursive: { type: "boolean", default: false } },
      required: ["path"],
    },
    handler: async (args) => {
      const cmd = args.recursive
        ? `find ${shQuote(args.path)} -maxdepth 3 -not -path '*/.*' | sort | head -200`
        : `ls -lhA ${shQuote(args.path)} 2>&1 | head -100`;
      return await sshServer(cmd);
    },
  },
  {
    name: "server_read_file",
    description: "Read a file on the Linux server.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, tail: { type: "number", default: 0 }, head: { type: "number", default: 0 } },
      required: ["path"],
    },
    handler: async (args) => {
      let cmd = `head -n 200 ${shQuote(args.path)} 2>&1`;
      if (args.tail) cmd = `tail -n ${shQuote(args.tail)} ${shQuote(args.path)} 2>&1`;
      else if (args.head) cmd = `head -n ${shQuote(args.head)} ${shQuote(args.path)} 2>&1`;
      return await sshServer(cmd);
    },
  },
  {
    name: "server_write_file",
    description: "Write (overwrite) a file on the Linux server.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, content: { type: "string" } },
      required: ["path", "content"],
    },
    handler: async (args) => {
      const b64 = Buffer.from(args.content).toString("base64");
      const cmd = `echo ${shQuote(b64)} | base64 -d > ${shQuote(args.path)} && echo 'OK'`;
      const res = await sshServer(cmd);
      return `Written to '${args.path}': ${res}`;
    },
  },
  {
    name: "server_move_file",
    description: "Move or rename a file/directory on the Linux server.",
    inputSchema: {
      type: "object",
      properties: { source: { type: "string" }, destination: { type: "string" } },
      required: ["source", "destination"],
    },
    handler: async (args) => {
      return await sshServer(`mv ${shQuote(args.source)} ${shQuote(args.destination)} && echo 'Moved OK'`);
    },
  },
  {
    name: "server_delete_file",
    description: "Delete a file (not a directory) on the Linux server.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
    handler: async (args) => {
      return await sshServer(`rm ${shQuote(args.path)} && echo 'Deleted OK'`);
    },
  },
  {
    name: "server_service_control",
    description: "Start, stop, restart, or check status of a systemd service on the Linux server.",
    inputSchema: {
      type: "object",
      properties: {
        service: { type: "string" },
        action: { type: "string", description: "start | stop | restart | status | enable | disable" },
      },
      required: ["service", "action"],
    },
    handler: async (args) => {
      const allowed = new Set(["start", "stop", "restart", "status", "enable", "disable"]);
      if (!allowed.has(args.action)) return `Invalid action '${args.action}'. Use one of: start, stop, restart, status, enable, disable`;
      return await sshServer(`sudo systemctl ${args.action} ${shQuote(args.service)} 2>&1`);
    },
  },
  {
    name: "server_tail_log",
    description: "Tail any log file on the Linux server.",
    inputSchema: {
      type: "object",
      properties: { log_path: { type: "string" }, lines: { type: "number", default: 50 } },
      required: ["log_path"],
    },
    handler: async (args) => {
      return await sshServer(`tail -n ${shQuote(args.lines || 50)} ${shQuote(args.log_path)} 2>&1`);
    },
  },
  {
    name: "server_cron_list",
    description: "List all cron jobs on the Linux server (user + root).",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const user = await sshServer("crontab -l 2>/dev/null || echo '(no user crontab)'");
      const root = await sshServer("sudo crontab -l 2>/dev/null || echo '(no root crontab)'");
      const sys = await sshServer("ls /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null | head -60");
      return `**User crontab:**\n${user}\n\n**Root crontab:**\n${root}\n\n**System cron.d:**\n${sys}`;
    },
  },
  {
    name: "server_network_info",
    description: "Show network interfaces, open ports, and active connections on the Linux server.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const ifaces = await sshServer("ip -brief addr");
      const ports = await sshServer("ss -tlnp 2>/dev/null | head -30");
      const conns = await sshServer("ss -tnp state established 2>/dev/null | head -20");
      return `**Interfaces:**\n${ifaces}\n\n**Listening ports:**\n${ports}\n\n**Active connections:**\n${conns}`;
    },
  },
  {
    name: "server_docker_status",
    description: "List Docker containers and images on the Linux server.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const c = await sshServer("docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}' 2>&1");
      const i = await sshServer("docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}' 2>&1 | head -20");
      return `**Containers:**\n${c}\n\n**Images:**\n${i}`;
    },
  },
  {
    name: "server_find_duplicates",
    description: "Find duplicate files on the Linux server by content hash (MD5).",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
    handler: async (args) => {
      const cmd = `find ${shQuote(args.path)} -type f -exec md5sum {} \\; 2>/dev/null | sort | awk 'seen[$1]++{print $2, "DUPLICATE OF", prev[$1]} {prev[$1]=$2}' | head -40`;
      const res = await sshServer(cmd);
      return res || "No duplicates found.";
    },
  },

  // --- Group 3: Windows PCs (via organiser-agent) ---
  {
    name: "pc_list_configured",
    description: "List every PC configured in the PCS registry with live reachability.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const names = Object.keys(PC_REGISTRY).sort();
      if (!names.length) return "No PCs configured.";
      const checks = await Promise.all(
        names.map(async (name) => {
          const entry = PC_REGISTRY[name];
          try {
            const data = await Promise.race([
              orgGet("/status", {}, name),
              new Promise((_, reject) => setTimeout(() => reject(new Error("timeout after 3s")), 3000)),
            ]);
            const reportedName = data.machine_name || data.machine_id || "?";
            return `- ${name} (port ${entry.port})  ✅ reachable  name="${reportedName}"  ${data.version || "?"}  ${data.platform || "?"}`;
          } catch (e: any) {
            return `- ${name} (port ${entry.port})  ⚠️ unreachable (${e.message || e})`;
          }
        })
      );
      const reachable = checks.filter((c) => c.includes("✅")).length;
      return `PC Registry (${names.length} configured, ${reachable} reachable):\n${checks.join("\n")}`;
    },
  },
  {
    name: "pc_organiser_status",
    description: "Check whether organiser-agent.exe is reachable on the given PC.",
    inputSchema: {
      type: "object",
      properties: { pc: { type: "string", default: "default" } },
    },
    handler: async (args) => {
      const pc = args.pc || "default";
      try {
        const data = await orgGet("/status", {}, pc);
        return `✅ '${pc}' reachable via ${SERVER_HOST} → loopback:${resolvePC(pc).port}\nVersion : ${data.version || "?"}\nPlatform: ${data.platform || "?"}`;
      } catch (e: any) {
        return `❌ Could not reach organiser agent '${pc}': ${e.message}\n\nChecklist:\n  1. Is organiser-agent.exe running on that PC?\n  2. Is pc-tunnel@${pc}.service active on the Linux server?\n  3. Are SERVER_HOST and SERVER_SSH_PORT reachable from this service over SSH?`;
      }
    },
  },
  {
    name: "pc_list",
    description: "List auto-detected PCs and their live status from the Linux hub's PC registry.",
    inputSchema: {
      type: "object",
      properties: { include_offline: { type: "boolean", default: false } },
    },
    handler: async (args) => {
      try {
        const flag = args.include_offline ? "true" : "false";
        const out = await sshServer(`curl -s 'http://127.0.0.1:7845/pcs?include_offline=${flag}' 2>&1`, 10);
        const data = JSON.parse(out);
        const pcs = data.pcs || [];
        if (!pcs.length) {
          const lines = Object.entries(PC_REGISTRY)
            .sort()
            .map(([k, v]) => `- **${k}** (configured fallback, port ${v.port})`);
          return `**Configured PCs (fallback mode):**\n${lines.join("\n")}`;
        }
        const lines = pcs.map((p: any) => {
          const icon = p.status === "online" ? "🟢" : "🔴";
          return `${icon} **${p.machine_name}** (${p.machine_id || "?"}) — IP: ${p.lan_ip}:${p.port} | Status: ${p.status} | Version: ${p.version || "?"}`;
        });
        return `**Auto-Detected PCs:**\n${lines.join("\n")}`;
      } catch {
        const lines = Object.entries(PC_REGISTRY)
          .sort()
          .map(([k, v]) => `- **${k}** (configured fallback, port ${v.port})`);
        return `**Configured PCs (fallback mode):**\n${lines.join("\n")}`;
      }
    },
  },
  {
    name: "pc_list_files",
    description: "List files and folders inside a directory on a PC.",
    inputSchema: {
      type: "object",
      properties: {
        folder: { type: "string" },
        recursive: { type: "boolean", default: false },
        pc: { type: "string", default: "default" },
      },
      required: ["folder"],
    },
    handler: async (args) => {
      const data = await orgGet("/list", { folder: args.folder, recursive: String(Boolean(args.recursive)) }, args.pc || "default");
      const entries = data.entries || [];
      if (!entries.length) return `No files found in '${args.folder}' (or path doesn't exist).`;
      return entries
        .map((e: any) => `[${e.is_dir ? "DIR " : "FILE"}] ${e.path} (${(e.size_bytes || 0).toLocaleString()} bytes) modified ${e.modified || "?"}`)
        .join("\n");
    },
  },
  {
    name: "pc_move_file",
    description: "Move (or rename) a file or folder on a PC. Parent directories created automatically.",
    inputSchema: {
      type: "object",
      properties: {
        source: { type: "string" },
        destination: { type: "string" },
        pc: { type: "string", default: "default" },
      },
      required: ["source", "destination"],
    },
    handler: async (args) => {
      const data = await orgPost("/move", { source: args.source, destination: args.destination }, args.pc || "default");
      return data.message || `Moved '${args.source}' → '${args.destination}'`;
    },
  },
  {
    name: "pc_delete_file",
    description: "Delete a file or empty folder on a PC. By default sends to Recycle Bin.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        permanent: { type: "boolean", default: false },
        pc: { type: "string", default: "default" },
      },
      required: ["path"],
    },
    handler: async (args) => {
      const data = await orgPost("/delete", { path: args.path, permanent: Boolean(args.permanent) }, args.pc || "default");
      return data.message || `Deleted '${args.path}'`;
    },
  },
  {
    name: "pc_read_file_preview",
    description: "Read the first max_bytes bytes of a text file on a PC.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        max_bytes: { type: "number", default: 4096 },
        pc: { type: "string", default: "default" },
      },
      required: ["path"],
    },
    handler: async (args) => {
      const maxB = Math.min(Math.max(args.max_bytes || 4096, 1), 2_000_000);
      const data = await orgGet("/preview", { path: args.path, max_bytes: maxB }, args.pc || "default");
      return data.content || "(empty or binary file)";
    },
  },
  {
    name: "pc_disk_usage",
    description: "Return a breakdown of disk usage inside a folder on a PC, sorted largest-first.",
    inputSchema: {
      type: "object",
      properties: { folder: { type: "string" }, pc: { type: "string", default: "default" } },
      required: ["folder"],
    },
    handler: async (args) => {
      const data = await orgGet("/disk_usage", { folder: args.folder }, args.pc || "default");
      const items = data.items || [];
      if (!items.length) return `'${args.folder}' appears empty.`;
      const lines = items.map((i: any) => `${String(i.size_human || "?").padStart(10)}  ${i.path}`);
      return `**${args.folder}** — total: ${data.total_human || "?"}\n${lines.join("\n")}`;
    },
  },
  {
    name: "pc_run_command",
    description: "Run a shell command on a PC (PowerShell/cmd or bash).",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string" },
        working_dir: { type: "string", default: "" },
        pc: { type: "string", default: "default" },
      },
      required: ["command"],
    },
    handler: async (args) => {
      const body: any = { command: args.command };
      if (args.working_dir) body.working_dir = args.working_dir;
      const data = await orgPost("/run_command", body, args.pc || "default");
      const output = (data.stdout || "") + (data.stderr || "");
      const rc = data.returncode ?? 0;
      return output ? `[exit ${rc}]\n${output}` : `[exit ${rc}] (no output)`;
    },
  },
  {
    name: "pc_find_duplicates",
    description: "Scan a folder on a PC for duplicate files by content hash.",
    inputSchema: {
      type: "object",
      properties: { folder: { type: "string" }, pc: { type: "string", default: "default" } },
      required: ["folder"],
    },
    handler: async (args) => {
      const data = await orgGet("/duplicates", { folder: args.folder }, args.pc || "default");
      const groups = data.groups || [];
      if (!groups.length) return "No duplicates found.";
      const lines: string[] = [];
      for (const g of groups) {
        lines.push(`${g.count}× ${g.size_human} each, wasting ${g.wasted_human}:`);
        for (const f of g.files || []) {
          lines.push(`  - ${f}`);
        }
      }
      return lines.join("\n");
    },
  },
  {
    name: "pc__screenshot",
    description: "Capture a screenshot of a PC's screen. Returns base64-encoded image data.",
    inputSchema: {
      type: "object",
      properties: { save_path: { type: "string", default: "" }, pc: { type: "string", default: "default" } },
    },
    handler: async (args) => {
      const body: any = {};
      if (args.save_path) body.save_path = args.save_path;
      const data = await orgPost("/screenshot", body, args.pc || "default");
      const b64 = data.image_base64 || "";
      if (!b64) return data.error || "Screenshot failed — no image returned.";
      const mime = data.format || "bmp";
      return `Screenshot captured (${data.size || ""}).\n${args.save_path ? `Saved to: ${data.saved_path}\n` : ""}base64_length=${b64.length}\ndata:image/${mime};base64,${b64}`;
    },
  },

  // --- Group 4: Universal File Transfer ---
  {
    name: "file_transfer",
    description: "Transfer files binary-safely between ANY two endpoints (sandbox, server, pc, codespace).",
    inputSchema: {
      type: "object",
      properties: {
        source: { type: "string", description: "sandbox:<path> | server:<path> | pc:<name>:<path> | codespace:<name>:<path>" },
        destination: { type: "string", description: "sandbox:<path> | server:<path> | pc:<name>:<path> | codespace:<name>:<path>" },
      },
      required: ["source", "destination"],
    },
    handler: async (args) => {
      const bytes = await locationReadBytes(args.source);
      const writeResult = await locationWriteBytes(args.destination, bytes);
      return `Transfer complete: '${args.source}' → '${args.destination}' (${bytes.length.toLocaleString()} bytes). ${writeResult}`;
    },
  },

  // --- Group 5: Diagnostics ---
  {
    name: "run_diagnostics",
    description: "Test every configured subsystem and report pass/fail/skip for each.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const report = await executeDiagnosticsSweep();
      const icons: Record<string, string> = { pass: "✅", fail: "❌", skip: "⏭️" };
      const lines = [`**Diagnostics — ${report.summary}**\n`];
      for (const c of report.checks) {
        lines.push(`${icons[c.status] || "?"} ${c.name}: ${c.detail}`);
      }
      return lines.join("\n");
    },
  },
];

// Map of tools by name for fast lookup
const TOOL_MAP = new Map<string, MCPToolDef>();
for (const tool of MCP_TOOLS) {
  TOOL_MAP.set(tool.name, tool);
}

// ---------------------------------------------------------------------------
// Model Context Protocol (MCP) Streamable HTTP / SSE Endpoint
// ---------------------------------------------------------------------------
async function handleMCPRPC(rpc: any): Promise<any> {
  const { jsonrpc, id, method, params } = rpc || {};
  if (jsonrpc !== "2.0") {
    return { jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid Request: expected jsonrpc 2.0" } };
  }

  switch (method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: {
            tools: { listChanged: false },
          },
          serverInfo: {
            name: "github-codespaces",
            version: "1.0.0",
          },
        },
      };

    case "notifications/initialized":
      return null; // Notifications don't get a response

    case "ping":
      return { jsonrpc: "2.0", id, result: {} };

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          tools: MCP_TOOLS.map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        },
      };

    case "tools/call": {
      const toolName = params?.name;
      const tool = TOOL_MAP.get(toolName);
      if (!tool) {
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: `Tool '${toolName}' not found.` },
        };
      }
      try {
        const textResult = await tool.handler(params?.arguments || {});
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: textResult }],
            isError: false,
          },
        };
      } catch (err: any) {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: `Tool error: ${err?.message || String(err)}` }],
            isError: true,
          },
        };
      }
    }

    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method '${method}' not found.` },
      };
  }
}

// POST /mcp endpoint
app.post("/mcp", async (req: Request, res: Response) => {
  const body = req.body;
  if (Array.isArray(body)) {
    const responses = (await Promise.all(body.map((r) => handleMCPRPC(r)))).filter(Boolean);
    res.json(responses);
    return;
  }
  const response = await handleMCPRPC(body);
  if (response) {
    res.json(response);
  } else {
    res.status(204).end();
  }
});

// GET /mcp SSE support for MCP clients like Claude Desktop
app.get("/mcp", (req: Request, res: Response) => {
  const accept = req.headers["accept"] || "";
  if (accept.includes("text/event-stream")) {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    const sessionId = crypto.randomBytes(16).toString("hex");
    res.write(`event: endpoint\ndata: /mcp?sessionId=${sessionId}\n\n`);
    req.on("close", () => res.end());
    return;
  }
  res.json({
    status: "ok",
    service: "github-codespaces MCP server",
    mcp_endpoint: "/mcp",
    transport: "Streamable HTTP / SSE",
  });
});

// ---------------------------------------------------------------------------
// Server Start
// ---------------------------------------------------------------------------
app.listen(PORT, HOST, () => {
  console.log(`Server listening on http://${HOST}:${PORT}`);
  console.log(`Allowed host: ${allowedHost || "(none detected)"}`);
  console.log(`Admin auth configured: ${ADMIN_AUTH_CONFIGURED}`);
});
