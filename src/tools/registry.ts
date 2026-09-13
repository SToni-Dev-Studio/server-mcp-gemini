import { MCPTool } from "../types.js";
import { codespacesTools } from "./codespaces.js";
import { serverTools } from "./server.js";
import { plexTools } from "./plex.js";
import { pcTools } from "./pc.js";
import { transferTools } from "./transfers.js";
import { diagnosticsTools } from "./diagnostics.js";

export const allTools: Record<string, MCPTool> = {
  ...codespacesTools,
  ...serverTools,
  ...plexTools,
  ...pcTools,
  ...transferTools,
  ...diagnosticsTools,
};

export function getTool(name: string): MCPTool | undefined {
  return allTools[name];
}

export function listTools(): { name: string; description: string; inputSchema: any }[] {
  return Object.values(allTools).map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  }));
}
