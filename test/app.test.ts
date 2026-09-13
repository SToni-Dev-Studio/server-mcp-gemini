import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createApp } from "../src/app.js";
import { allTools } from "../src/tools/registry.js";
import { MCP_SERVER_PASSWORD } from "../src/config.js";

function startTestServer(): Promise<{ server: http.Server; url: string }> {
  return new Promise((resolve) => {
    const app = createApp();
    const server = http.createServer(app);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as any;
      resolve({ server, url: `http://127.0.0.1:${addr.port}` });
    });
  });
}

test("App - GET /healthz endpoint returns JSON status", async () => {
  const { server, url } = await startTestServer();
  try {
    const res = await fetch(`${url}/healthz`);
    assert.equal(res.status, 200);
    const data = (await res.json()) as any;
    assert.equal(data.status, "ok");
    assert.equal(data.server, "codespaces-mcp");
    assert.equal(data.toolsCount, Object.keys(allTools).length);
    assert.ok(data.uptime >= 0);
  } finally {
    server.close();
  }
});

test("App - GET / returns JSON server metadata (no HTML)", async () => {
  const { server, url } = await startTestServer();
  try {
    const res = await fetch(`${url}/`);
    assert.equal(res.status, 200);
    const data = (await res.json()) as any;
    assert.equal(data.name, "codespaces-mcp");
    assert.equal(data.protocol, "mcp");
    assert.equal(data.endpoints.sse, "/sse");
    assert.equal(data.endpoints.messages, "/messages");
    assert.equal(data.toolsCount, Object.keys(allTools).length);
  } finally {
    server.close();
  }
});

test("App - GET /mcp returns transport metadata", async () => {
  const { server, url } = await startTestServer();
  try {
    const res = await fetch(`${url}/mcp`);
    assert.equal(res.status, 200);
    const data = (await res.json()) as any;
    assert.equal(data.name, "codespaces-mcp");
    assert.ok(data.transport.includes("sse"));
    assert.equal(data.sseEndpoint, "/sse");
    assert.equal(data.messagesEndpoint, "/messages");
  } finally {
    server.close();
  }
});

test("App - Authentication protection on /sse and /messages endpoints", async () => {
  const { server, url } = await startTestServer();
  try {
    if (MCP_SERVER_PASSWORD) {
      // Unauthenticated /sse request rejected
      const unauthSse = await fetch(`${url}/sse`);
      assert.equal(unauthSse.status, 401);

      // Unauthenticated /messages request rejected
      const unauthMsg = await fetch(`${url}/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      });
      assert.equal(unauthMsg.status, 401);
    }
  } finally {
    server.close();
  }
});

test("App - POST /mcp JSON-RPC ping with authentication check", async () => {
  const { server, url } = await startTestServer();
  try {
    if (MCP_SERVER_PASSWORD) {
      const unauthRes = await fetch(`${url}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 98, method: "ping" }),
      });
      assert.equal(unauthRes.status, 401);
    }

    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (MCP_SERVER_PASSWORD) {
      headers["Authorization"] = `Bearer ${MCP_SERVER_PASSWORD}`;
    }

    const authRes = await fetch(`${url}/mcp`, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 99, method: "ping" }),
    });
    assert.equal(authRes.status, 200);
    const data = (await authRes.json()) as any;
    assert.equal(data.id, 99);
    assert.deepEqual(data.result, {});
  } finally {
    server.close();
  }
});

test("App - MCP batch JSON-RPC requests processing", async () => {
  const { server, url } = await startTestServer();
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (MCP_SERVER_PASSWORD) {
      headers["Authorization"] = `Bearer ${MCP_SERVER_PASSWORD}`;
    }

    const batchBody = [
      { jsonrpc: "2.0", id: "batch-1", method: "ping" },
      { jsonrpc: "2.0", id: "batch-2", method: "initialize" },
    ];

    const res = await fetch(`${url}/mcp`, {
      method: "POST",
      headers,
      body: JSON.stringify(batchBody),
    });

    assert.equal(res.status, 200);
    const data = (await res.json()) as any[];
    assert.ok(Array.isArray(data));
    assert.equal(data.length, 2);
    assert.equal(data[0].id, "batch-1");
    assert.equal(data[1].id, "batch-2");
  } finally {
    server.close();
  }
});

test("App - CORS headers are properly set on OPTIONS requests", async () => {
  const { server, url } = await startTestServer();
  try {
    const res = await fetch(`${url}/sse`, {
      method: "OPTIONS",
    });
    assert.equal(res.status, 204);
    assert.equal(res.headers.get("access-control-allow-origin"), "*");
    assert.ok(res.headers.get("access-control-allow-methods")?.includes("POST"));
  } finally {
    server.close();
  }
});

test("App - DNS rebinding protection blocks unauthorized Host header", async () => {
  const { server, url } = await startTestServer();
  try {
    const res = await fetch(`${url}/healthz`, {
      headers: { Host: "attacker.evil.com" },
    });
    assert.ok([200, 403].includes(res.status));
  } finally {
    server.close();
  }
});
