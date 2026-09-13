import fs from "node:fs";
import path from "node:path";
import { GITHUB_API } from "../config.js";
import { shQuote } from "../security.js";
import { sshServer } from "../ssh.js";
import { MCPTool } from "../types.js";
import { codespacesTools, getToken, ghHeaders } from "./codespaces.js";
import { organiserRequest } from "./pc.js";

export interface ParsedLocation {
  type: "sandbox" | "server" | "pc" | "codespace";
  target?: string;
  path: string;
}

/**
 * Parses node location strings such as:
 * - "sandbox:/path/to/file" or "local:/path" or "/path"
 * - "server:/path/to/file" or "linux:/path"
 * - "pc:C:\Users\file.txt" or "pc:desktop:C:\path"
 * - "codespace:name:/workspaces/repo/file" or "cs:name:/path"
 */
export function parseLocation(spec: string): ParsedLocation {
  const trimmed = (spec || "").trim();
  if (!trimmed) {
    throw new Error("Location specification cannot be empty.");
  }

  if (trimmed.startsWith("codespace:") || trimmed.startsWith("cs:")) {
    const withoutPrefix = trimmed.replace(/^(codespace|cs):/, "");
    const colonIdx = withoutPrefix.indexOf(":");
    if (colonIdx === -1) {
      throw new Error(`Invalid codespace location: "${spec}". Expected "codespace:<name>:<path>"`);
    }
    const target = withoutPrefix.slice(0, colonIdx);
    const remotePath = withoutPrefix.slice(colonIdx + 1);
    return { type: "codespace", target, path: remotePath };
  }

  if (trimmed.startsWith("pc:")) {
    const withoutPrefix = trimmed.slice(3);
    const colonIdx = withoutPrefix.indexOf(":");
    // If there is another colon not corresponding to a Windows drive (e.g. pc:gaming:C:\...)
    const isWindowsDrive = /^[a-zA-Z]:[/\\]/.test(withoutPrefix);
    if (!isWindowsDrive && colonIdx > 0) {
      const target = withoutPrefix.slice(0, colonIdx);
      const remotePath = withoutPrefix.slice(colonIdx + 1);
      return { type: "pc", target, path: remotePath };
    }
    return { type: "pc", target: "default", path: withoutPrefix };
  }

  if (trimmed.startsWith("server:") || trimmed.startsWith("linux:")) {
    const withoutPrefix = trimmed.replace(/^(server|linux):/, "");
    return { type: "server", path: withoutPrefix };
  }

  if (trimmed.startsWith("sandbox:") || trimmed.startsWith("local:")) {
    const withoutPrefix = trimmed.replace(/^(sandbox|local):/, "");
    return { type: "sandbox", path: withoutPrefix };
  }

  // Default to local sandbox
  return { type: "sandbox", path: trimmed };
}

/**
 * Reads a single file from any node location, returning its content as base64.
 */
export async function readNodeFile(loc: ParsedLocation): Promise<{ base64: string; sizeBytes: number }> {
  switch (loc.type) {
    case "sandbox": {
      if (!fs.existsSync(loc.path)) {
        throw new Error(`Sandbox file not found: ${loc.path}`);
      }
      const buf = fs.readFileSync(loc.path);
      return { base64: buf.toString("base64"), sizeBytes: buf.length };
    }
    case "server": {
      const cmd = `base64 < ${shQuote(loc.path)} 2>&1`;
      const out = await sshServer(cmd);
      if (out.includes("No such file") || out.includes("cannot open") || out.includes("Is a directory")) {
        throw new Error(`Server read error on ${loc.path}: ${out}`);
      }
      const sanitized = out.replace(/\s+/g, "");
      const buf = Buffer.from(sanitized, "base64");
      return { base64: sanitized, sizeBytes: buf.length };
    }
    case "codespace": {
      const cmd = `base64 < ${shQuote(loc.path)} 2>&1`;
      const out = await codespacesTools.exec_command.handler({
        codespace_name: loc.target!,
        command: cmd,
      });
      if (out.includes("No such file") || out.includes("cannot open")) {
        throw new Error(`Codespace (${loc.target}) read error on ${loc.path}: ${out}`);
      }
      const sanitized = out.replace(/\s+/g, "");
      const buf = Buffer.from(sanitized, "base64");
      return { base64: sanitized, sizeBytes: buf.length };
    }
    case "pc": {
      const data = await organiserRequest("GET", "/preview", loc.target || "default", {
        path: loc.path,
        max_bytes: 50_000_000,
      });
      if (data.error) {
        throw new Error(`PC read error on ${loc.path}: ${data.error}`);
      }
      const content = data.content || "";
      const buf = Buffer.from(content, "utf-8");
      return { base64: buf.toString("base64"), sizeBytes: buf.length };
    }
  }
}

/**
 * Writes a single file to any node location from base64 content.
 */
export async function writeNodeFile(loc: ParsedLocation, base64Content: string): Promise<string> {
  const buf = Buffer.from(base64Content, "base64");

  switch (loc.type) {
    case "sandbox": {
      fs.mkdirSync(path.dirname(loc.path), { recursive: true });
      fs.writeFileSync(loc.path, buf);
      return `Saved to sandbox: '${loc.path}' (${buf.length} bytes)`;
    }
    case "server": {
      const cmd = `mkdir -p $(dirname ${shQuote(loc.path)}) && echo ${shQuote(base64Content)} | base64 -d > ${shQuote(loc.path)} && echo OK`;
      const res = await sshServer(cmd);
      if (!res.includes("OK")) {
        throw new Error(`Server write error on ${loc.path}: ${res}`);
      }
      return `Saved to server: '${loc.path}' (${buf.length} bytes)`;
    }
    case "codespace": {
      const cmd = `mkdir -p $(dirname ${shQuote(loc.path)}) && echo ${shQuote(base64Content)} | base64 -d > ${shQuote(loc.path)} && echo OK`;
      const res = await codespacesTools.exec_command.handler({
        codespace_name: loc.target!,
        command: cmd,
      });
      return `Saved to codespace ${loc.target}: '${loc.path}' (${buf.length} bytes)`;
    }
    case "pc": {
      const utf8 = buf.toString("utf-8");
      const data = await organiserRequest(
        "POST",
        "/write_file",
        loc.target || "default",
        undefined,
        { path: loc.path, content: utf8 }
      );
      if (data.error) {
        throw new Error(`PC write error on ${loc.path}: ${data.error}`);
      }
      return data.message || `Saved to PC: '${loc.path}' (${buf.length} bytes)`;
    }
  }
}

/**
 * Recursively lists relative file paths within a directory at a node location.
 */
export async function listNodeFiles(loc: ParsedLocation): Promise<string[]> {
  switch (loc.type) {
    case "sandbox": {
      if (!fs.existsSync(loc.path)) {
        throw new Error(`Sandbox directory does not exist: ${loc.path}`);
      }
      const files: string[] = [];
      function walk(dir: string, base: string) {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const full = path.join(dir, entry.name);
          const rel = path.join(base, entry.name);
          if (entry.isDirectory()) {
            walk(full, rel);
          } else if (entry.isFile()) {
            files.push(rel.replace(/\\/g, "/"));
          }
        }
      }
      walk(loc.path, "");
      return files;
    }
    case "server": {
      const cmd = `cd ${shQuote(loc.path)} 2>/dev/null && find . -type f -not -path '*/.*' 2>/dev/null | sed 's|^\\./||'`;
      const out = await sshServer(cmd);
      if (!out || out.includes("No such file")) {
        throw new Error(`Server directory does not exist or empty: ${loc.path}`);
      }
      return out.split("\n").map((s) => s.trim()).filter(Boolean);
    }
    case "codespace": {
      const cmd = `cd ${shQuote(loc.path)} 2>/dev/null && find . -type f -not -path '*/.*' 2>/dev/null | sed 's|^\\./||'`;
      const out = await codespacesTools.exec_command.handler({
        codespace_name: loc.target!,
        command: cmd,
      });
      return out.split("\n").map((s) => s.trim()).filter(Boolean);
    }
    case "pc": {
      const data = await organiserRequest("GET", "/list", loc.target || "default", {
        folder: loc.path,
        recursive: true,
      });
      if (data.error) {
        throw new Error(`PC list directory error on ${loc.path}: ${data.error}`);
      }
      const items: any[] = data.items || [];
      const baseNorm = loc.path.replace(/\\/g, "/").replace(/\/+$/, "");
      const files: string[] = [];
      for (const item of items) {
        if (!item.is_dir) {
          const itemPath = (item.path || "").replace(/\\/g, "/");
          let rel = itemPath;
          if (itemPath.startsWith(baseNorm)) {
            rel = itemPath.slice(baseNorm.length).replace(/^\/+/, "");
          }
          if (rel) files.push(rel);
        }
      }
      return files;
    }
  }
}

/**
 * Executes a file or directory transfer between any two nodes.
 */
export async function executeTransfer(
  sourceSpec: string,
  destSpec: string,
  recursive = false
): Promise<string> {
  const sourceLoc = parseLocation(sourceSpec);
  const destLoc = parseLocation(destSpec);

  // If recursive transfer requested: transfer entire directory structure
  if (recursive) {
    const files = await listNodeFiles(sourceLoc);
    if (files.length === 0) {
      return `Source directory '${sourceSpec}' has no files to transfer.`;
    }

    let transferredCount = 0;
    let totalBytes = 0;

    for (const relFile of files) {
      const srcSubLoc: ParsedLocation = {
        ...sourceLoc,
        path: sourceLoc.path.replace(/[/\\]+$/, "") + "/" + relFile,
      };
      const destSubLoc: ParsedLocation = {
        ...destLoc,
        path: destLoc.path.replace(/[/\\]+$/, "") + "/" + relFile,
      };

      const fileData = await readNodeFile(srcSubLoc);
      await writeNodeFile(destSubLoc, fileData.base64);
      transferredCount++;
      totalBytes += fileData.sizeBytes;
    }

    return (
      `**Folder Transfer Completed Successfully**\n` +
      `• Source: \`${sourceSpec}\` (${sourceLoc.type}${sourceLoc.target ? ":" + sourceLoc.target : ""})\n` +
      `• Destination: \`${destSpec}\` (${destLoc.type}${destLoc.target ? ":" + destLoc.target : ""})\n` +
      `• Files transferred: ${transferredCount}\n` +
      `• Total transferred: ${(totalBytes / 1024).toFixed(2)} KB`
    );
  }

  // Single file transfer
  const fileData = await readNodeFile(sourceLoc);
  await writeNodeFile(destLoc, fileData.base64);

  return (
    `**File Transfer Completed Successfully**\n` +
    `• From: \`${sourceSpec}\` (${sourceLoc.type}${sourceLoc.target ? ":" + sourceLoc.target : ""})\n` +
    `• To: \`${destSpec}\` (${destLoc.type}${destLoc.target ? ":" + destLoc.target : ""})\n` +
    `• Transferred: ${(fileData.sizeBytes / 1024).toFixed(2)} KB (${fileData.sizeBytes} bytes)`
  );
}

export const transferTools: Record<string, MCPTool> = {
  file_transfer: {
    name: "file_transfer",
    description:
      "Universal file transfer across ANY nodes (sandbox, pc, server, codespace) in any direction (e.g. pc -> server, codespace -> pc, server -> codespace, sandbox -> any). Supports recursive folder transfer if recursive=true.",
    inputSchema: {
      type: "object",
      required: ["source", "destination"],
      properties: {
        source: {
          type: "string",
          description:
            "Source path with node prefix: 'sandbox:<path>', 'pc:<path>' (or 'pc:<name>:<path>'), 'server:<path>', or 'codespace:<name>:<path>'",
        },
        destination: {
          type: "string",
          description:
            "Destination path with node prefix: 'sandbox:<path>', 'pc:<path>', 'server:<path>', or 'codespace:<name>:<path>'",
        },
        recursive: {
          type: "boolean",
          description: "Set to true to transfer an entire directory recursively.",
        },
      },
    },
    handler: async ({ source, destination, recursive = false }) => {
      return await executeTransfer(source, destination, recursive);
    },
  },

  folder_transfer: {
    name: "folder_transfer",
    description:
      "Recursively transfer an entire folder across ANY nodes (sandbox, pc, server, codespace) in any direction with directory hierarchy preserved.",
    inputSchema: {
      type: "object",
      required: ["source", "destination"],
      properties: {
        source: {
          type: "string",
          description:
            "Source folder path with node prefix: 'sandbox:<path>', 'pc:<path>', 'server:<path>', or 'codespace:<name>:<path>'",
        },
        destination: {
          type: "string",
          description:
            "Destination folder path with node prefix: 'sandbox:<path>', 'pc:<path>', 'server:<path>', or 'codespace:<name>:<path>'",
        },
      },
    },
    handler: async ({ source, destination }) => {
      return await executeTransfer(source, destination, true);
    },
  },

  // Backwards compatibility aliases
  transfer__pc_to_sandbox: {
    name: "transfer__pc_to_sandbox",
    description: "Download a file from a PC into this sandbox (convenience alias for file_transfer).",
    inputSchema: {
      type: "object",
      required: ["remote_path", "local_save_path"],
      properties: {
        remote_path: { type: "string" },
        local_save_path: { type: "string" },
        pc: { type: "string" },
      },
    },
    handler: async ({ remote_path, local_save_path, pc = "default" }) => {
      const src = `pc:${pc}:${remote_path}`;
      const dst = `sandbox:${local_save_path}`;
      return await executeTransfer(src, dst, false);
    },
  },

  transfer__sandbox_to_pc: {
    name: "transfer__sandbox_to_pc",
    description: "Upload a file from this sandbox to a PC (convenience alias for file_transfer).",
    inputSchema: {
      type: "object",
      required: ["local_path", "remote_dest_path"],
      properties: {
        local_path: { type: "string" },
        remote_dest_path: { type: "string" },
        pc: { type: "string" },
      },
    },
    handler: async ({ local_path, remote_dest_path, pc = "default" }) => {
      const src = `sandbox:${local_path}`;
      const dst = `pc:${pc}:${remote_dest_path}`;
      return await executeTransfer(src, dst, false);
    },
  },

  transfer__sandbox_to_codespace: {
    name: "transfer__sandbox_to_codespace",
    description: "Copy a file from this sandbox into a GitHub Codespace.",
    inputSchema: {
      type: "object",
      required: ["local_path", "codespace_name", "remote_path"],
      properties: {
        local_path: { type: "string" },
        codespace_name: { type: "string" },
        remote_path: { type: "string" },
      },
    },
    handler: async ({ local_path, codespace_name, remote_path }) => {
      const src = `sandbox:${local_path}`;
      const dst = `codespace:${codespace_name}:${remote_path}`;
      return await executeTransfer(src, dst, false);
    },
  },

  transfer__server_to_sandbox: {
    name: "transfer__server_to_sandbox",
    description: "Download a file from the Linux server into this sandbox via SSH.",
    inputSchema: {
      type: "object",
      required: ["remote_path", "local_save_path"],
      properties: {
        remote_path: { type: "string" },
        local_save_path: { type: "string" },
      },
    },
    handler: async ({ remote_path, local_save_path }) => {
      const src = `server:${remote_path}`;
      const dst = `sandbox:${local_save_path}`;
      return await executeTransfer(src, dst, false);
    },
  },

  transfer__sandbox_to_server: {
    name: "transfer__sandbox_to_server",
    description: "Upload a file from this sandbox to the Linux server via SSH.",
    inputSchema: {
      type: "object",
      required: ["local_path", "remote_dest_path"],
      properties: {
        local_path: { type: "string" },
        remote_dest_path: { type: "string" },
      },
    },
    handler: async ({ local_path, remote_dest_path }) => {
      const src = `sandbox:${local_path}`;
      const dst = `server:${remote_dest_path}`;
      return await executeTransfer(src, dst, false);
    },
  },
};
