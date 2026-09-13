import express, { Express, Request, Response } from "express";
import { allowedHost } from "./config.js";
import { hostValidationMiddleware } from "./security.js";
import {
  mcpAuthMiddleware,
  handleSseConnection,
  handleMessagesPost,
  handleMcpPost,
} from "./mcp.js";
import { allTools } from "./tools/registry.js";

/**
 * Creates a lightweight, strict Model Context Protocol (MCP) Express application.
 * All web/HTML UI dashboards, templates, and session cookies have been completely removed.
 */
export function createApp(): Express {
  const app = express();

  // Security headers & JSON parsing
  app.disable("x-powered-by");
  app.use(express.json({ limit: "15mb" }));
  app.use(express.urlencoded({ extended: false, limit: "15mb" }));

  // CORS middleware for MCP client compatibility (Claude Desktop, Antigravity, Inspector, etc.)
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, X-MCP-Token, X-Organiser-Secret, Accept"
    );
    if (req.method === "OPTIONS") {
      res.status(204).end();
      return;
    }
    next();
  });

  // Host header validation (DNS Rebinding protection)
  app.use(hostValidationMiddleware);

  // Health check endpoint (Pure JSON)
  app.get("/healthz", (req: Request, res: Response) => {
    res.json({
      status: "ok",
      server: "codespaces-mcp",
      uptime: process.uptime(),
      toolsCount: Object.keys(allTools).length,
      allowedHost: allowedHost || "localhost",
      timestamp: new Date().toISOString(),
    });
  });

  // Root endpoint: Pure JSON server metadata (Zero HTML)
  app.get("/", (req: Request, res: Response) => {
    res.json({
      name: "codespaces-mcp",
      version: "1.0.0",
      description: "Official Model Context Protocol (MCP) Server for GitHub Codespaces & Infrastructure",
      protocol: "mcp",
      endpoints: {
        sse: "/sse",
        messages: "/messages",
        mcp: "/mcp",
        health: "/healthz",
      },
      toolsCount: Object.keys(allTools).length,
    });
  });

  // Official MCP SDK Server-Sent Events (SSE) stream endpoint
  app.get("/sse", mcpAuthMiddleware, handleSseConnection);

  // Official MCP SDK message endpoint for incoming client JSON-RPC messages
  app.post("/messages", mcpAuthMiddleware, handleMessagesPost);

  // Direct JSON-RPC 2.0 endpoint (compatible with POST /mcp clients)
  app.post("/mcp", mcpAuthMiddleware, handleMcpPost);
  app.get("/mcp", (req: Request, res: Response) => {
    res.json({
      name: "codespaces-mcp",
      version: "1.0.0",
      description: "Model Context Protocol Server",
      transport: ["sse", "http-post"],
      sseEndpoint: "/sse",
      messagesEndpoint: "/messages",
      toolsCount: Object.keys(allTools).length,
    });
  });

  // Strict 404 handler (JSON only)
  app.use((req: Request, res: Response) => {
    res.status(404).json({ error: "Not Found" });
  });

  return app;
}
