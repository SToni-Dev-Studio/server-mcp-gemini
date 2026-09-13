import { exec } from "node:child_process";
import { GITHUB_API } from "../config.js";
import { shQuote } from "../security.js";
import { MCPTool } from "../types.js";

export function getToken(account: string = "auto"): [string, string] {
  const primary = (process.env.GITHUB_TOKEN || "").trim();
  const secondary = (process.env.GITHUB_TOKEN_SECONDARY || "").trim();
  const tertiary = (process.env.GITHUB_TOKEN_TERTIARY || "").trim();

  if (account === "secondary") {
    if (!secondary) throw new Error("GITHUB_TOKEN_SECONDARY is not configured.");
    return [secondary, "secondary"];
  }
  if (account === "tertiary") {
    if (!tertiary) throw new Error("GITHUB_TOKEN_TERTIARY is not configured.");
    return [tertiary, "tertiary"];
  }
  if (account === "primary") {
    if (!primary) throw new Error("GITHUB_TOKEN is not configured.");
    return [primary, "primary"];
  }

  if (primary) return [primary, "primary"];
  if (secondary) return [secondary, "secondary"];
  if (tertiary) return [tertiary, "tertiary"];

  throw new Error("No GitHub tokens configured in environment.");
}

export function ghHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "codespaces-mcp-server",
  };
}

export async function ghRequestWithFallback(
  method: string,
  path: string,
  body?: unknown,
  account: string = "auto"
): Promise<any> {
  const [initialToken] = getToken(account);
  const url = `${GITHUB_API}${path}`;

  async function makeRequest(token: string) {
    const headers: Record<string, string> = ghHeaders(token);
    const options: RequestInit = {
      method: method.toUpperCase(),
      headers,
      signal: AbortSignal.timeout(30000),
    };
    if (body !== undefined && ["POST", "PATCH", "PUT"].includes(method.toUpperCase())) {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    return await fetch(url, options);
  }

  let res = await makeRequest(initialToken);

  if ((res.status === 401 || res.status === 403) && account === "auto") {
    for (const [fallbackName, envKey] of [
      ["secondary", "GITHUB_TOKEN_SECONDARY"],
      ["tertiary", "GITHUB_TOKEN_TERTIARY"],
    ]) {
      const fallbackToken = (process.env[envKey] || "").trim();
      if (fallbackToken && fallbackToken !== initialToken) {
        console.warn(`Token failed with HTTP ${res.status}. Trying ${fallbackName}...`);
        res = await makeRequest(fallbackToken);
        if (res.status !== 401 && res.status !== 403) break;
      }
    }
  }

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`GitHub API HTTP ${res.status}: ${errorText}`);
  }

  const text = await res.text();
  return text ? JSON.parse(text) : {};
}

export const codespacesTools: Record<string, MCPTool> = {
  check_account_status: {
    name: "check_account_status",
    description: "Check validity and user identities for primary, secondary, and tertiary GitHub tokens.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      const results: string[] = [];
      const tokensToCheck = [
        ["primary", (process.env.GITHUB_TOKEN || "").trim()],
        ["secondary", (process.env.GITHUB_TOKEN_SECONDARY || "").trim()],
        ["tertiary", (process.env.GITHUB_TOKEN_TERTIARY || "").trim()],
      ];
      for (const [label, token] of tokensToCheck) {
        if (!token) {
          results.push(`• **${label.charAt(0).toUpperCase() + label.slice(1)} Token**: Not configured.`);
          continue;
        }
        try {
          const res = await fetch(`${GITHUB_API}/user`, {
            headers: ghHeaders(token),
            signal: AbortSignal.timeout(15000),
          });
          if (res.ok) {
            const data = (await res.json()) as any;
            const login = data.login || "unknown";
            const name = data.name || login;
            results.push(`• **${label.charAt(0).toUpperCase() + label.slice(1)} Token**: ✅ Active (User: \`${login}\` - ${name})`);
          } else {
            results.push(`• **${label.charAt(0).toUpperCase() + label.slice(1)} Token**: ❌ Invalid/Expired (HTTP ${res.status})`);
          }
        } catch (e: any) {
          results.push(`• **${label.charAt(0).toUpperCase() + label.slice(1)} Token**: ⚠️ Network error (${e.message})`);
        }
      }
      return results.join("\n");
    },
  },

  list_codespaces: {
    name: "list_codespaces",
    description: "List caller's GitHub Codespaces: name, repo, state, and machine spec.",
    inputSchema: {
      type: "object",
      properties: { account: { type: "string", description: "auto, primary, secondary, tertiary" } },
    },
    handler: async ({ account = "auto" }) => {
      const data = await ghRequestWithFallback("GET", "/user/codespaces", undefined, account);
      const items = data.codespaces || [];
      if (items.length === 0) return "No codespaces found.";
      return items
        .map(
          (cs: any) =>
            `- ${cs.name} | repo: ${cs.repository?.full_name} | state: ${cs.state} | machine: ${cs.machine?.display_name}`
        )
        .join("\n");
    },
  },

  create_codespace: {
    name: "create_codespace",
    description: "Create a new codespace for a given repository.",
    inputSchema: {
      type: "object",
      required: ["repo_full_name"],
      properties: {
        repo_full_name: { type: "string" },
        branch: { type: "string" },
        machine_type: { type: "string" },
        account: { type: "string" },
      },
    },
    handler: async ({ repo_full_name, branch = "main", machine_type = "", account = "auto" }) => {
      const body: Record<string, any> = { ref: branch };
      if (machine_type) body.machine = machine_type;
      const data = await ghRequestWithFallback("POST", `/repos/${repo_full_name}/codespaces`, body, account);
      return `Created codespace '${data.name}' (state: ${data.state})`;
    },
  },

  stop_codespace: {
    name: "stop_codespace",
    description: "Stop a running codespace by name.",
    inputSchema: {
      type: "object",
      required: ["codespace_name"],
      properties: { codespace_name: { type: "string" }, account: { type: "string" } },
    },
    handler: async ({ codespace_name, account = "auto" }) => {
      await ghRequestWithFallback("POST", `/user/codespaces/${codespace_name}/stop`, undefined, account);
      return `Stop requested for '${codespace_name}'.`;
    },
  },

  rebuild_codespace: {
    name: "rebuild_codespace",
    description: "Trigger a full devcontainer rebuild inside a codespace.",
    inputSchema: {
      type: "object",
      required: ["codespace_name"],
      properties: { codespace_name: { type: "string" }, account: { type: "string" } },
    },
    handler: async ({ codespace_name, account = "auto" }) => {
      const data = await ghRequestWithFallback("POST", `/user/codespaces/${codespace_name}/rebuild`, undefined, account);
      return `Rebuild initiated for '${codespace_name}'. State: ${data.state || "queued"}`;
    },
  },

  set_machine_type: {
    name: "set_machine_type",
    description: "Scale machine specs (e.g. 'standardLinux32Gb' or 'premiumLinux').",
    inputSchema: {
      type: "object",
      required: ["codespace_name", "machine_type"],
      properties: {
        codespace_name: { type: "string" },
        machine_type: { type: "string" },
        account: { type: "string" },
      },
    },
    handler: async ({ codespace_name, machine_type, account = "auto" }) => {
      await ghRequestWithFallback(
        "PATCH",
        `/user/codespaces/${codespace_name}`,
        { machine: machine_type },
        account
      );
      return `Machine updated to '${machine_type}' for '${codespace_name}'.`;
    },
  },

  exec_command: {
    name: "exec_command",
    description: "Run a single shell command inside a codespace asynchronously via SSH.",
    inputSchema: {
      type: "object",
      required: ["codespace_name", "command"],
      properties: {
        codespace_name: { type: "string" },
        command: { type: "string" },
        timeout_seconds: { type: "number" },
        account: { type: "string" },
      },
    },
    handler: async ({ codespace_name, command, timeout_seconds = 60, account = "auto" }) => {
      const [token] = getToken(account);
      return new Promise((resolve) => {
        const cmd = `gh codespace ssh --codespace ${shQuote(codespace_name)} -- ${shQuote(command)}`;
        exec(
          cmd,
          { env: { ...process.env, GH_TOKEN: token }, timeout: timeout_seconds * 1000 },
          (err, stdout, stderr) => {
            if (err) {
              const out = ((stdout || "") + (stderr || "")).trim();
              resolve(out || `Execution error: ${err.message}`);
            } else {
              const out = ((stdout || "") + (stderr || "")).trim();
              resolve(out || "(command executed, no output)");
            }
          }
        );
      });
    },
  },

  read_codespace_file: {
    name: "read_codespace_file",
    description: "Read contents of a remote file in the codespace.",
    inputSchema: {
      type: "object",
      required: ["codespace_name", "file_path"],
      properties: { codespace_name: { type: "string" }, file_path: { type: "string" }, account: { type: "string" } },
    },
    handler: async ({ codespace_name, file_path, account = "auto" }) => {
      return await codespacesTools.exec_command.handler({
        codespace_name,
        command: `cat ${shQuote(file_path)}`,
        timeout_seconds: 15,
        account,
      });
    },
  },

  write_codespace_file: {
    name: "write_codespace_file",
    description: "Safely write/overwrite content to a file in the codespace using base64 encoding.",
    inputSchema: {
      type: "object",
      required: ["codespace_name", "file_path", "content"],
      properties: {
        codespace_name: { type: "string" },
        file_path: { type: "string" },
        content: { type: "string" },
        account: { type: "string" },
      },
    },
    handler: async ({ codespace_name, file_path, content, account = "auto" }) => {
      const b64 = Buffer.from(content, "utf-8").toString("base64");
      const cmd = `mkdir -p $(dirname ${shQuote(file_path)}) && echo ${shQuote(b64)} | base64 -d > ${shQuote(file_path)}`;
      await codespacesTools.exec_command.handler({ codespace_name, command: cmd, timeout_seconds: 20, account });
      return `Successfully wrote ${content.length} characters to '${file_path}'.`;
    },
  },

  list_workspace_files: {
    name: "list_workspace_files",
    description: "List directory contents or file tree inside the codespace.",
    inputSchema: {
      type: "object",
      required: ["codespace_name"],
      properties: { codespace_name: { type: "string" }, path: { type: "string" }, account: { type: "string" } },
    },
    handler: async ({ codespace_name, path = ".", account = "auto" }) => {
      return await codespacesTools.exec_command.handler({
        codespace_name,
        command: `find ${shQuote(path)} -maxdepth 2 -not -path '*/.*'`,
        timeout_seconds: 15,
        account,
      });
    },
  },

  get_git_status: {
    name: "get_git_status",
    description: "Get concise git status and branch info in the codespace working directory.",
    inputSchema: {
      type: "object",
      required: ["codespace_name"],
      properties: { codespace_name: { type: "string" }, repo_path: { type: "string" }, account: { type: "string" } },
    },
    handler: async ({ codespace_name, repo_path = ".", account = "auto" }) => {
      return await codespacesTools.exec_command.handler({
        codespace_name,
        command: `cd ${shQuote(repo_path)} && git status --short -b`,
        timeout_seconds: 15,
        account,
      });
    },
  },

  create_git_commit_and_push: {
    name: "create_git_commit_and_push",
    description: "Stage tracked changes, commit, and push to remote.",
    inputSchema: {
      type: "object",
      required: ["codespace_name", "commit_message"],
      properties: {
        codespace_name: { type: "string" },
        commit_message: { type: "string" },
        repo_path: { type: "string" },
        branch: { type: "string" },
        account: { type: "string" },
      },
    },
    handler: async ({ codespace_name, commit_message, repo_path = ".", branch = "", account = "auto" }) => {
      const pushArgs = branch ? `origin ${shQuote(branch)}` : "";
      const cmd = `cd ${shQuote(repo_path)} && git add -u && git commit -m ${shQuote(commit_message)} && git push ${pushArgs}`;
      return await codespacesTools.exec_command.handler({ codespace_name, command: cmd, timeout_seconds: 30, account });
    },
  },

  list_forwarded_ports: {
    name: "list_forwarded_ports",
    description: "List currently forwarded network ports and dev server addresses.",
    inputSchema: {
      type: "object",
      required: ["codespace_name"],
      properties: { codespace_name: { type: "string" }, account: { type: "string" } },
    },
    handler: async ({ codespace_name, account = "auto" }) => {
      return await codespacesTools.exec_command.handler({
        codespace_name,
        command: `gh codespace ports -c ${shQuote(codespace_name)}`,
        timeout_seconds: 15,
        account,
      });
    },
  },
};
