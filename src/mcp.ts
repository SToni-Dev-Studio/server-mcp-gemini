import { Request, Response, NextFunction } from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { MCP_SERVER_PASSWORD, isPublicDeployment } from "./config.js";
import { constantTimeCompare } from "./security.js";
import { allTools, listTools } from "./tools/registry.js";
import { JsonRpcRequest, JsonRpcResponse } from "./types.js";

/**
 * Authentication middleware for MCP requests (/sse, /messages, /mcp).
 */
export function mcpAuthMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (!MCP_SERVER_PASSWORD) {
    if (isPublicDeployment) {
      res.status(503).json({
        error: "Server misconfigured: MCP_SERVER_PASSWORD is not set on a public deployment.",
      });
      return;
    }
    return next();
  }

  const authHeader = (req.headers.authorization || "").trim();
  const bearerToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  const headerToken = String(req.headers["x-mcp-token"] || "").trim();
  const queryToken = String(req.query.token || "").trim();

  const tokenToVerify = bearerToken || headerToken || queryToken;

  if (!tokenToVerify || !constantTimeCompare(tokenToVerify, MCP_SERVER_PASSWORD)) {
    res.status(401).json({
      error: "Unauthorized: Invalid or missing MCP server password.",
    });
    return;
  }

  next();
}

/**
 * Create a configured instance of the official MCP Server.
 */
export function createMcpServer(): Server {
  const server = new Server(
    {
      name: "codespaces-mcp",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Register tools/list handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: listTools(),
    };
  });

  // Register tools/call handler returning standard CallToolResult
  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    const { name, arguments: args = {} } = request.params;
    const tool = allTools[name];

    if (!tool) {
      return {
        content: [{ type: "text", text: `Error: Unknown tool '${name}'` }],
        isError: true,
      };
    }

    try {
      const output = await tool.handler(args as Record<string, any>);
      return {
        content: [{ type: "text", text: String(output) }],
        isError: false,
      };
    } catch (err: any) {
      return {
        content: [{ type: "text", text: `Tool error: ${err.message || String(err)}` }],
        isError: true,
      };
    }
  });

  return server;
}

// Active SSE Transports indexed by sessionId
const activeTransports = new Map<string, SSEServerTransport>();

/**
 * Handle GET /sse endpoint using SSEServerTransport.
 */
export async function handleSseConnection(req: Request, res: Response): Promise<void> {
  // Construct the message endpoint path including any auth query params
  const tokenQuery = req.query.token ? `?token=${encodeURIComponent(String(req.query.token))}` : "";
  const endpointPath = `/messages${tokenQuery}`;

  const transport = new SSEServerTransport(endpointPath, res);
  const server = createMcpServer();

  // SSEServerTransport generates a sessionId accessible via transport.sessionId
  const sessionId = transport.sessionId;
  activeTransports.set(sessionId, transport);

  res.on("close", () => {
    activeTransports.delete(sessionId);
  });

  await server.connect(transport);
}

/**
 * Handle POST /messages endpoint using SSEServerTransport.
 */
export async function handleMessagesPost(req: Request, res: Response): Promise<void> {
  const sessionId = String(req.query.sessionId || "");
  const transport = activeTransports.get(sessionId);

  if (!transport) {
    // If sessionId is omitted or expired, check if there is a single active session
    if (!sessionId && activeTransports.size === 1) {
      const singleTransport = activeTransports.values().next().value;
      if (singleTransport) {
        await singleTransport.handlePostMessage(req, res);
        return;
      }
    }
    res.status(400).json({ error: `No active SSE transport session found for sessionId: '${sessionId}'` });
    return;
  }

  await transport.handlePostMessage(req, res);
}

/**
 * Process a single JSON-RPC 2.0 request directly (for direct POST /mcp & automated testing).
 * Fully enforces CallToolResult return format: { content: [{ type: "text", text: result }] }.
 */
export async function processMcpMessage(msg: JsonRpcRequest): Promise<JsonRpcResponse | null> {
  const { jsonrpc = "2.0", id = null, method, params } = msg;

  if (method === "notifications/initialized") {
    // Client notification after initialize handshake; no response required
    return null;
  }

  if (method === "initialize") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: {
          tools: {},
        },
        serverInfo: {
          name: "codespaces-mcp",
          version: "1.0.0",
        },
      },
    };
  }

  if (method === "ping") {
    return { jsonrpc: "2.0", id, result: {} };
  }

  if (method === "tools/list") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        tools: listTools(),
      },
    };
  }

  if (method === "tools/call") {
    const toolName = params?.name;
    const toolArgs = params?.arguments || {};
    const tool = allTools[toolName];

    if (!tool) {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: `Error: Unknown tool '${toolName}'` }],
          isError: true,
        },
      };
    }

    try {
      const output = await tool.handler(toolArgs);
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: String(output) }],
          isError: false,
        },
      };
    } catch (err: any) {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: `Tool error: ${err.message}` }],
          isError: true,
        },
      };
    }
  }

  // Unsupported method
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: -32601,
      message: `Method not found: '${method}'`,
    },
  };
}

/**
 * Handle HTTP POST /mcp endpoint (for JSON-RPC POST clients)
 */
export async function handleMcpPost(req: Request, res: Response): Promise<void> {
  const body = req.body;
  if (!body || typeof body !== "object") {
    res.status(400).json({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "Parse error: Request body must be a JSON object or array" },
    });
    return;
  }

  if (Array.isArray(body)) {
    const responses: JsonRpcResponse[] = [];
    for (const msg of body) {
      const r = await processMcpMessage(msg);
      if (r !== null) responses.push(r);
    }
    res.json(responses);
    return;
  }

  const response = await processMcpMessage(body);
  if (response === null) {
    res.status(204).end();
    return;
  }
  res.json(response);
}
