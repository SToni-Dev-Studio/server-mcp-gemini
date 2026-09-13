import dotenv from "dotenv";
import { PCRegistry, PCConfig } from "./types.js";

dotenv.config();

export const PORT = parseInt(process.env.PORT || "3000", 10);
export const GITHUB_API = "https://api.github.com";
export const RENDER_API = "https://api.render.com/v1";

export const PLEX_URL = (process.env.PLEX_URL || "http://192.168.101.105:32400").replace(/\/+$/, "");
export const PLEX_TOKEN = (process.env.PLEX_TOKEN || "").trim();

export const SERVER_HOST = (process.env.SERVER_HOST || "192.168.101.105").trim();
export const SERVER_USER = (process.env.SERVER_USER || "sepisotoni").trim();
export const SERVER_SSH_KEY = (process.env.SERVER_SSH_KEY || "~/.ssh/id_rsa").trim();
export const SSH_PRIVATE_KEY = (process.env.SSH_PRIVATE_KEY || "").trim();

export const RENDER_API_KEY = (process.env.RENDER_API_KEY || "").trim();
export const RENDER_SERVICE_ID = (process.env.RENDER_SERVICE_ID || "srv-da11cupt0dsc73aq2qq0").trim();

export const MCP_SERVER_PASSWORD = (process.env.MCP_SERVER_PASSWORD || "").trim();
export const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || "").trim() || MCP_SERVER_PASSWORD;
export const ADMIN_COOKIE_SECRET =
  (process.env.ADMIN_COOKIE_SECRET || "").trim() || ADMIN_PASSWORD || "insecure-default-admin-cookie-secret-123456";
export const ADMIN_SESSION_TTL = 60 * 60 * 12; // 12 hours
export const ADMIN_COOKIE_NAME = "admin_session";

// Detect allowed host for DNS rebinding protection
export function detectAllowedHost(): string {
  const explicit = (process.env.MCP_ALLOWED_HOST || "").trim();
  if (explicit) return explicit;
  const renderHost = (process.env.RENDER_EXTERNAL_HOSTNAME || "").trim();
  if (renderHost) return renderHost;
  const flyApp = (process.env.FLY_APP_NAME || "").trim();
  if (flyApp) return `${flyApp}.fly.dev`;
  return "";
}

export const allowedHost = detectAllowedHost();
export const isPublicDeployment = Boolean(allowedHost);

// Parse PC Registry
export function parsePCRegistry(): PCRegistry {
  let registry: PCRegistry = {};
  const pcsRaw = (process.env.PCS || "").trim();
  if (pcsRaw) {
    try {
      registry = JSON.parse(pcsRaw);
    } catch {
      console.warn("WARNING: PCS env var is not valid JSON — falling back to single-PC mode.");
    }
  }

  if (Object.keys(registry).length === 0) {
    registry = {
      default: {
        port: parseInt(process.env.ORGANISER_PORT || "7842", 10),
        secret: (process.env.ORGANISER_SECRET || "").trim(),
      },
    };
  }
  return registry;
}

export let pcRegistry: PCRegistry = parsePCRegistry();

export function updatePCRegistry(rawJson?: string): void {
  if (rawJson) {
    process.env.PCS = rawJson;
  }
  pcRegistry = parsePCRegistry();
}

export function resolvePC(pc: string = "default"): PCConfig {
  if (!pcRegistry[pc]) {
    const available = Object.keys(pcRegistry).sort().join(", ") || "(none configured)";
    throw new Error(`Unknown PC '${pc}'. Configured PCs: ${available}`);
  }
  return pcRegistry[pc];
}

// In-memory environment variable store for local updates & inspection
export const localEnvStore = new Map<string, string>();
for (const [k, v] of Object.entries(process.env)) {
  if (v !== undefined) localEnvStore.set(k, v);
}
