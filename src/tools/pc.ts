import { resolvePC, pcRegistry, SERVER_HOST } from "../config.js";
import { sshServer } from "../ssh.js";
import { MCPTool } from "../types.js";

/**
 * Executes an HTTP request against a PC's organiser-agent via SSH loopback tunnel.
 */
export async function organiserRequest(
  method: string,
  path: string,
  pc: string = "default",
  params?: Record<string, any>,
  body?: any,
  timeoutSec: number = 30
): Promise<any> {
  const entry = resolvePC(pc);
  const base = `http://127.0.0.1:${entry.port}`;
  const envelope = {
    method,
    path,
    params: params || {},
    body: body ?? null,
    secret: entry.secret || "",
    base,
  };
  const envB64 = Buffer.from(JSON.stringify(envelope), "utf-8").toString("base64");

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
  const srcB64 = Buffer.from(pySource, "utf-8").toString("base64");
  const cmd = `echo '${srcB64}' | base64 -d | python3 -`;
  const raw = await sshServer(cmd, timeoutSec);

  const trimmed = (raw || "").trim();
  if (!trimmed) {
    throw new Error(
      `Empty response reaching organiser-agent on '${pc}'. Ensure organiser-agent.exe is running on that PC and pc-tunnel@${pc}.service is active on the server.`
    );
  }

  try {
    return JSON.parse(trimmed);
  } catch {
    throw new Error(`Non-JSON response from organiser-agent: ${trimmed.slice(0, 300)}`);
  }
}

export const pcTools: Record<string, MCPTool> = {
  pc_list_configured: {
    name: "pc_list_configured",
    description: "List every PC configured in the PCS registry (name + tunnel port; secrets are never shown).",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const keys = Object.keys(pcRegistry).sort();
      if (keys.length === 0) return "No PCs configured.";
      return keys.map((k) => `- ${k} (port ${pcRegistry[k].port})`).join("\n");
    },
  },

  pc_organiser_status: {
    name: "pc_organiser_status",
    description: "Check whether organiser-agent.exe is reachable on the given PC.",
    inputSchema: {
      type: "object",
      properties: { pc: { type: "string", description: "PC name from PCS registry, defaults to 'default'" } },
    },
    handler: async ({ pc = "default" }) => {
      try {
        const data = await organiserRequest("GET", "/status", pc);
        return (
          `✅ '${pc}' reachable via ${SERVER_HOST} → loopback:${resolvePC(pc).port}\n` +
          `Version : ${data.version || "?"}\n` +
          `Platform: ${data.platform || "?"}`
        );
      } catch (e: any) {
        return (
          `❌ Could not reach organiser agent '${pc}': ${e.message}\n\n` +
          "Checklist:\n" +
          `  1. Is organiser-agent.exe running on that PC (Task Scheduler)?\n` +
          `  2. Is pc-tunnel@${pc}.service active on the Linux server?\n` +
          `  3. Is the Linux server reachable over Tailscale?`
        );
      }
    },
  },

  pc_list_files: {
    name: "pc_list_files",
    description: "List files and folders inside a directory on a PC.",
    inputSchema: {
      type: "object",
      required: ["folder"],
      properties: {
        folder: { type: "string" },
        recursive: { type: "boolean" },
        pc: { type: "string" },
      },
    },
    handler: async ({ folder, recursive = false, pc = "default" }) => {
      const data = await organiserRequest("GET", "/list", pc, {
        folder,
        recursive: String(recursive).toLowerCase(),
      });
      const entries = data.entries || [];
      if (entries.length === 0) {
        return `No files found in '${folder}' (or path does not exist).`;
      }
      const lines = entries.map((e: any) => {
        const kind = e.is_dir ? "DIR " : "FILE";
        const size = (e.size_bytes || 0).toLocaleString();
        return `[${kind}] ${e.path} (${size} bytes) modified ${e.modified || "?"}`;
      });
      return lines.join("\n");
    },
  },

  pc_move_file: {
    name: "pc_move_file",
    description: "Move (or rename) a file or folder on a PC. Parent directories are created automatically.",
    inputSchema: {
      type: "object",
      required: ["source", "destination"],
      properties: {
        source: { type: "string" },
        destination: { type: "string" },
        pc: { type: "string" },
      },
    },
    handler: async ({ source, destination, pc = "default" }) => {
      const data = await organiserRequest("POST", "/move", pc, undefined, { source, destination });
      return data.message || `Moved '${source}' → '${destination}'`;
    },
  },

  pc_delete_file: {
    name: "pc_delete_file",
    description: "Delete a file or empty folder on a PC (Recycle Bin by default; permanent=true to delete permanently).",
    inputSchema: {
      type: "object",
      required: ["path"],
      properties: {
        path: { type: "string" },
        permanent: { type: "boolean" },
        pc: { type: "string" },
      },
    },
    handler: async ({ path, permanent = false, pc = "default" }) => {
      const data = await organiserRequest("POST", "/delete", pc, undefined, { path, permanent });
      return data.message || `Deleted '${path}'`;
    },
  },

  pc_read_file_preview: {
    name: "pc_read_file_preview",
    description: "Read the first max_bytes bytes of a text file on a PC.",
    inputSchema: {
      type: "object",
      required: ["path"],
      properties: {
        path: { type: "string" },
        max_bytes: { type: "number" },
        pc: { type: "string" },
      },
    },
    handler: async ({ path, max_bytes = 4096, pc = "default" }) => {
      const data = await organiserRequest("GET", "/preview", pc, { path, max_bytes });
      return data.content ?? "(empty or binary file)";
    },
  },

  pc_disk_usage: {
    name: "pc_disk_usage",
    description: "Return a breakdown of disk usage inside a folder on a PC, sorted largest-first.",
    inputSchema: {
      type: "object",
      required: ["folder"],
      properties: { folder: { type: "string" }, pc: { type: "string" } },
    },
    handler: async ({ folder, pc = "default" }) => {
      const data = await organiserRequest("GET", "/disk_usage", pc, { folder });
      const items = data.items || [];
      const lines = items.map((i: any) => `${(i.size_human || "?").padStart(10)}  ${i.path}`);
      const total = data.total_human || "?";
      return lines.length > 0
        ? `**${folder}** — total: ${total}\n${lines.join("\n")}`
        : `'${folder}' appears empty.`;
    },
  },

  pc_run_command: {
    name: "pc_run_command",
    description: "Run a shell command on a PC (PowerShell/cmd on Windows, bash on Mac/Linux).",
    inputSchema: {
      type: "object",
      required: ["command"],
      properties: {
        command: { type: "string" },
        working_dir: { type: "string" },
        pc: { type: "string" },
      },
    },
    handler: async ({ command, working_dir = "", pc = "default" }) => {
      const body: Record<string, any> = { command };
      if (working_dir) body.working_dir = working_dir;
      const data = await organiserRequest("POST", "/run_command", pc, undefined, body);
      const output = (data.stdout || "") + (data.stderr || "");
      const rc = data.returncode ?? 0;
      return output ? `[exit ${rc}]\n${output}` : `[exit ${rc}] (no output)`;
    },
  },

  pc_find_duplicates: {
    name: "pc_find_duplicates",
    description: "Scan a folder on a PC for duplicate files by content hash.",
    inputSchema: {
      type: "object",
      required: ["folder"],
      properties: { folder: { type: "string" }, pc: { type: "string" } },
    },
    handler: async ({ folder, pc = "default" }) => {
      const data = await organiserRequest("GET", "/duplicates", pc, { folder });
      const groups = data.groups || [];
      if (groups.length === 0) return "No duplicates found.";
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

  pc__screenshot: {
    name: "pc__screenshot",
    description: "Capture a screenshot of a PC's screen. Returns base64 image data.",
    inputSchema: {
      type: "object",
      properties: { save_path: { type: "string" }, pc: { type: "string" } },
    },
    handler: async ({ save_path = "", pc = "default" }) => {
      const body: Record<string, any> = {};
      if (save_path) body.save_path = save_path;
      const data = await organiserRequest("POST", "/screenshot", pc, undefined, body);
      const b64 = data.image_base64 || "";
      const path = data.saved_path || "";
      const size = data.size || "";
      if (!b64) {
        return data.error || "Screenshot failed — no image returned.";
      }
      return (
        `Screenshot captured (${size}).\n` +
        (path ? `Saved to: ${path}\n` : "") +
        `base64_length=${b64.length}\n` +
        `data:image/png;base64,${b64.slice(0, 200)}...`
      );
    },
  },
};
