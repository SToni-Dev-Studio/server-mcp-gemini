import { createApp } from "./src/app.js";
import { PORT, allowedHost } from "./src/config.js";
import { allTools } from "./src/tools/registry.js";

const app = createApp();

const server = app.listen(PORT, () => {
  console.log(`========================================================`);
  console.log(` Codespaces MCP Server running on port ${PORT}`);
  console.log(` Registered Tools   : ${Object.keys(allTools).length}`);
  console.log(` Allowed Host       : ${allowedHost || "localhost"}`);
  console.log(` Official MCP SSE   : http://localhost:${PORT}/sse`);
  console.log(` MCP Messages Post  : http://localhost:${PORT}/messages`);
  console.log(` Direct MCP JSON-RPC: http://localhost:${PORT}/mcp`);
  console.log(`========================================================`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, closing HTTP server...");
  server.close(() => {
    console.log("HTTP server closed.");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  console.log("SIGINT received, closing HTTP server...");
  server.close(() => {
    console.log("HTTP server closed.");
    process.exit(0);
  });
});
