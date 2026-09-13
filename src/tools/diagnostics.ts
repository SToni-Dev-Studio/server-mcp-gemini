import {
  GITHUB_API,
  PLEX_URL,
  PLEX_TOKEN,
  SERVER_HOST,
  SERVER_USER,
  RENDER_API,
  RENDER_API_KEY,
  RENDER_SERVICE_ID,
  pcRegistry,
} from "../config.js";
import { sshServer } from "../ssh.js";
import { DiagnosticCheck, DiagnosticsReport, MCPTool } from "../types.js";
import { ghHeaders, ghRequestWithFallback } from "./codespaces.js";
import { organiserRequest } from "./pc.js";

export async function runDiagnostics(): Promise<DiagnosticsReport> {
  const checks: DiagnosticCheck[] = [];

  async function check(name: string, fn: () => Promise<string>) {
    try {
      const detail = await fn();
      checks.push({ name, status: "pass", detail });
    } catch (e: any) {
      checks.push({ name, status: "fail", detail: e.message || String(e) });
    }
  }

  // 1. GitHub Tokens
  const ghTokens: [string, string][] = [
    ["GitHub primary", (process.env.GITHUB_TOKEN || "").trim()],
    ["GitHub secondary", (process.env.GITHUB_TOKEN_SECONDARY || "").trim()],
    ["GitHub tertiary", (process.env.GITHUB_TOKEN_TERTIARY || "").trim()],
  ];

  for (const [label, token] of ghTokens) {
    if (!token) {
      checks.push({ name: label, status: "skip", detail: "not configured" });
      continue;
    }
    await check(label, async () => {
      const res = await fetch(`${GITHUB_API}/user`, {
        headers: ghHeaders(token),
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as any;
      return `authenticated as ${data.login || "?"}`;
    });
  }

  // 2. Codespaces API
  await check("Codespaces API", async () => {
    const data = await ghRequestWithFallback("GET", "/user/codespaces");
    const count = (data.codespaces || []).length;
    return `${count} codespace(s) visible`;
  });

  // 3. Plex
  if (PLEX_TOKEN) {
    await check("Plex", async () => {
      const res = await fetch(`${PLEX_URL}/?X-Plex-Token=${encodeURIComponent(PLEX_TOKEN)}`, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as any;
      return `reachable (${data.MediaContainer?.friendlyName || "?"})`;
    });
  } else {
    checks.push({ name: "Plex", status: "skip", detail: "PLEX_TOKEN not configured" });
  }

  // 4. Linux server SSH
  await check("Linux server", async () => {
    const out = await sshServer("echo alive", 15);
    if (!out.includes("alive")) throw new Error(out.slice(0, 200) || "no response");
    return `${SERVER_USER}@${SERVER_HOST} reachable`;
  });

  // 5. Each configured PC
  const pcNames = Object.keys(pcRegistry).sort();
  for (const pc of pcNames) {
    await check(`PC '${pc}'`, async () => {
      const data = await organiserRequest("GET", "/status", pc, undefined, undefined, 15);
      return `${data.platform || "?"} v${data.version || "?"}`;
    });
  }

  // 6. Render API
  if (RENDER_API_KEY && RENDER_SERVICE_ID) {
    await check("Render API", async () => {
      const res = await fetch(`${RENDER_API}/services/${RENDER_SERVICE_ID}`, {
        headers: {
          Authorization: `Bearer ${RENDER_API_KEY}`,
          Accept: "application/json",
        },
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as any;
      return `Service: ${data.name || "?"}`;
    });
  } else {
    checks.push({
      name: "Render API",
      status: "skip",
      detail: "RENDER_API_KEY/RENDER_SERVICE_ID not configured",
    });
  }

  const passed = checks.filter((c) => c.status === "pass").length;
  const failed = checks.filter((c) => c.status === "fail").length;
  const skipped = checks.filter((c) => c.status === "skip").length;

  return {
    checks,
    summary: `${passed} passed, ${failed} failed, ${skipped} skipped`,
  };
}

export const diagnosticsTools: Record<string, MCPTool> = {
  run_diagnostics: {
    name: "run_diagnostics",
    description:
      "Test every configured subsystem (GitHub tokens, Codespaces API, Plex, Linux server, PC agents, Render API) and report pass/fail/skip.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const report = await runDiagnostics();
      const icons: Record<string, string> = { pass: "✅", fail: "❌", skip: "⏭️" };
      const lines = [`**Diagnostics — ${report.summary}**\n`];
      for (const c of report.checks) {
        lines.push(`${icons[c.status] || "?"} ${c.name}: ${c.detail}`);
      }
      return lines.join("\n");
    },
  },
};
