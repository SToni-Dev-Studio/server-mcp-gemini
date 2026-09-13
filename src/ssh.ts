import { exec } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { SERVER_HOST, SERVER_USER, SSH_PRIVATE_KEY, SERVER_SSH_KEY } from "./config.js";
import { shQuote } from "./security.js";

const SSH_KEY_PATH = process.env.SSH_KEY_PATH || "/tmp/render_mcp_key";

// If raw private key text was provided in env, write to disk with 0600 permissions
if (SSH_PRIVATE_KEY) {
  try {
    fs.mkdirSync(path.dirname(SSH_KEY_PATH), { recursive: true });
    fs.writeFileSync(SSH_KEY_PATH, SSH_PRIVATE_KEY.trim() + "\n", { mode: 0o600 });
  } catch (err: any) {
    console.warn("Could not write SSH_PRIVATE_KEY to disk:", err.message);
  }
}

export const BLOCKED_SERVER_COMMANDS = [
  "rm -rf /",
  "mkfs",
  "dd if=",
  "> /dev/sda",
  "shutdown now",
  "halt",
];

export function checkBlockedCommand(command: string): string | null {
  for (const b of BLOCKED_SERVER_COMMANDS) {
    if (command.includes(b)) {
      return `Blocked: '${b}' is not allowed.`;
    }
  }
  return null;
}

/**
 * Execute command on the Linux server over Tailscale SSH.
 */
export async function sshServer(command: string, timeoutSec: number = 60): Promise<string> {
  const blocked = checkBlockedCommand(command);
  if (blocked) return blocked;

  return new Promise((resolve) => {
    // Determine SSH identity option if key exists
    let identityOption = "";
    if (fs.existsSync(SSH_KEY_PATH)) {
      identityOption = `-i ${SSH_KEY_PATH} `;
    } else if (SERVER_SSH_KEY && fs.existsSync(SERVER_SSH_KEY)) {
      identityOption = `-i ${SERVER_SSH_KEY} `;
    }

    const prefix = process.env.SSH_COMMAND_PREFIX || "tailscale ssh";
    const sshCmd = `${prefix} ${identityOption}${SERVER_USER}@${SERVER_HOST} ${shQuote(command)}`;

    exec(sshCmd, { timeout: timeoutSec * 1000 }, (err, stdout, stderr) => {
      if (err) {
        const out = ((stdout || "") + (stderr || "")).trim();
        resolve(out || `(SSH execution failed: ${err.message})`);
      } else {
        const out = ((stdout || "") + (stderr || "")).trim();
        resolve(out || "(command executed, no output)");
      }
    });
  });
}
