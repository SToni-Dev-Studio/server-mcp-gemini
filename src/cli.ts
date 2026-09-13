#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { runDiagnostics } from "./tools/diagnostics.js";
import { executeTransfer } from "./tools/transfers.js";
import { sshServer } from "./ssh.js";
import { organiserRequest } from "./tools/pc.js";
import { codespacesTools } from "./tools/codespaces.js";
import { sanitizeEnvKey, maskSecret } from "./security.js";
import { pcRegistry } from "./config.js";

const SENSITIVE_KEYS = [
  "GITHUB_TOKEN",
  "GITHUB_TOKEN_SECONDARY",
  "GITHUB_TOKEN_TERTIARY",
  "MCP_SERVER_PASSWORD",
  "ADMIN_PASSWORD",
  "RENDER_API_KEY",
  "ORGANISER_SECRET",
  "SERVER_SSH_KEY",
];

function printHelp() {
  console.log(`
======================================================
  Codespaces MCP — Linux Management CLI (mcp-cli)
======================================================

Usage:
  mcp-cli <command> [arguments] [options]

Commands:
  status, diagnostics
      Run end-to-end subsystem diagnostics across GitHub, Codespaces,
      Linux home server, PC agents, and cloud deployment.

  secrets list
      List all configured environment variables and secrets (masked).

  secrets set <KEY> <VALUE>
      Set or update a secret / configuration key in the environment
      and persist it into .env safely.

  secrets get <KEY> [--reveal]
      Display the value of a secret key (masked unless --reveal).

  transfer <source> <destination> [--recursive]
      Transfer files or directories between any two nodes:
      - sandbox:<path> (or local:<path> or plain path)
      - server:<path> (or linux:<path>)
      - pc:<path> or pc:<name>:<path>
      - codespace:<name>:<path>
      Examples:
        mcp-cli transfer local:/tmp/app.tar.gz server:/mnt/ssd/app.tar.gz
        mcp-cli transfer pc:C:\\logs server:/var/log/pc --recursive
        mcp-cli transfer codespace:my-cs:/repo/dist pc:C:\\dist --recursive

  server exec <command>
      Run a shell command on the Linux server over SSH.

  server status
      Check status of services, disk, and memory on Linux server.

  pc status [pc_name]
      Query organiser-agent status on configured PC.

  codespace list
      List all GitHub Codespaces and their states.

Options:
  -h, --help    Show this help message
  -v, --version Show version
`);
}

async function handleSecrets(args: string[]) {
  const sub = args[0] || "list";
  const envPath = path.resolve(process.cwd(), ".env");

  if (sub === "list") {
    console.log("\nConfigured Secrets & Environment Variables:\n");
    const keys = Array.from(
      new Set([...SENSITIVE_KEYS, ...Object.keys(process.env)])
    ).sort();

    const output: Array<{ Key: string; Value: string; Status: string }> = [];
    for (const key of keys) {
      if (
        !key.startsWith("npm_") &&
        !key.startsWith("NODE_") &&
        !key.startsWith("PATH") &&
        !key.startsWith("SHLVL") &&
        !key.startsWith("_")
      ) {
        const val = process.env[key];
        const isSet = !!val;
        const displayVal = val ? (SENSITIVE_KEYS.some((s) => key.includes(s)) ? maskSecret(key, val) : val) : "(unset)";
        output.push({ Key: key, Value: displayVal, Status: isSet ? "configured" : "missing" });
      }
    }
    console.table(output);
    return;
  }

  if (sub === "get") {
    const key = args[1];
    if (!key) {
      console.error("Error: Please provide a key name. Example: mcp-cli secrets get MCP_SERVER_PASSWORD");
      return;
    }
    const val = process.env[key];
    if (val === undefined) {
      console.log(`Key '${key}' is not set.`);
      return;
    }
    const reveal = args.includes("--reveal");
    console.log(`${key} = ${reveal ? val : maskSecret(key, val)}`);
    return;
  }

  if (sub === "set") {
    const key = args[1];
    const val = args.slice(2).join(" ");
    if (!key || val === undefined) {
      console.error("Error: Usage is: mcp-cli secrets set <KEY> <VALUE>");
      return;
    }

    const isValid = sanitizeEnvKey(key);
    if (!isValid) {
      console.error(`Error: Invalid environment variable key name '${key}'.`);
      return;
    }

    process.env[key] = val;

    let envContent = "";
    if (fs.existsSync(envPath)) {
      envContent = fs.readFileSync(envPath, "utf-8");
    }

    const regex = new RegExp(`^${key}=.*$`, "m");
    if (regex.test(envContent)) {
      envContent = envContent.replace(regex, `${key}=${val}`);
    } else {
      envContent += (envContent.endsWith("\n") || envContent === "" ? "" : "\n") + `${key}=${val}\n`;
    }

    fs.writeFileSync(envPath, envContent, "utf-8");
    console.log(`✓ Secret '${key}' successfully updated and saved to .env.`);
    return;
  }

  console.error(`Unknown secrets subcommand: ${sub}`);
  printHelp();
}

async function handleTransfer(args: string[]) {
  const isRecursive = args.includes("--recursive") || args.includes("-r");
  const filtered = args.filter((a) => a !== "--recursive" && a !== "-r");

  if (filtered.length < 2) {
    console.error("Error: transfer requires <source> and <destination>");
    console.error("Example: mcp-cli transfer local:./file.txt server:/tmp/file.txt");
    process.exit(1);
  }

  const [source, destination] = filtered;
  console.log(`\nInitiating transfer: ${source} → ${destination} ${isRecursive ? "(recursive)" : ""}\n`);

  try {
    const result = await executeTransfer(source, destination, isRecursive);
    console.log(result);
  } catch (err: any) {
    console.error(`\n✗ Transfer failed: ${err.message || String(err)}\n`);
    process.exit(1);
  }
}

async function handleStatus() {
  console.log("\nRunning full system diagnostics sweep...\n");
  const report = await runDiagnostics();
  for (const c of report.checks) {
    const icon = c.status === "pass" ? "✓" : c.status === "fail" ? "✗" : "○";
    console.log(`  [${icon}] ${c.name.padEnd(20)}: ${c.detail}`);
  }
  console.log(`\nSummary: ${report.summary}\n`);
}

async function handleServer(args: string[]) {
  const sub = args[0] || "status";
  if (sub === "status") {
    const cmd =
      "systemctl is-active sonarr jackett qbittorrent 2>&1 | paste - - - | awk '{print \"sonarr:\", $1, \"| jackett:\", $2, \"| qbittorrent:\", $3}'";
    const res = await sshServer(cmd);
    const disk = await sshServer("df -h / /mnt/ssd 2>/dev/null | tail -2");
    console.log(`\nServer Services:\n${res}\n\nDisk Space:\n${disk}\n`);
    return;
  }
  if (sub === "exec") {
    const cmd = args.slice(1).join(" ");
    if (!cmd) {
      console.error("Error: Please specify a command to execute. Example: mcp-cli server exec 'uptime'");
      process.exit(1);
    }
    const out = await sshServer(cmd);
    console.log(out);
    return;
  }
  console.error(`Unknown server subcommand: ${sub}`);
}

async function handlePC(args: string[]) {
  const pc = args[1] || "default";
  const status = await organiserRequest("GET", "/status", pc);
  console.log(`\nPC Agent [${pc}]:`);
  console.log(JSON.stringify(status, null, 2));
}

async function handleCodespace(args: string[]) {
  const sub = args[0] || "list";
  if (sub === "list") {
    const out = await codespacesTools.list_codespaces.handler({});
    console.log(out);
    return;
  }
  console.error(`Unknown codespace subcommand: ${sub}`);
}

export async function runCli(argv = process.argv.slice(2)): Promise<void> {
  const cmd = argv[0];

  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") {
    printHelp();
    return;
  }

  if (cmd === "--version" || cmd === "-v") {
    console.log("Codespaces MCP CLI v2.1.0");
    return;
  }

  switch (cmd) {
    case "status":
    case "diagnostics":
      await handleStatus();
      break;
    case "secrets":
      await handleSecrets(argv.slice(1));
      break;
    case "transfer":
      await handleTransfer(argv.slice(1));
      break;
    case "server":
      await handleServer(argv.slice(1));
      break;
    case "pc":
      await handlePC(argv.slice(1));
      break;
    case "codespace":
    case "codespaces":
      await handleCodespace(argv.slice(1));
      break;
    default:
      console.error(`Unknown command: ${cmd}`);
      printHelp();
      process.exit(1);
  }
}

// If invoked directly from terminal
if (process.argv[1] && (process.argv[1].endsWith("cli.ts") || process.argv[1].endsWith("cli.cjs") || process.argv[1].endsWith("mcp-cli"))) {
  runCli().catch((e) => {
    console.error("CLI Execution Error:", e);
    process.exit(1);
  });
}
