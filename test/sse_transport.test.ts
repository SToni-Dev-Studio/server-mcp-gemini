import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createApp } from "../src/app.js";
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

test("Official MCP SDK - GET /sse stream connection and endpoint event", async () => {
  const { server, url } = await startTestServer();
  try {
    const headers: Record<string, string> = { Accept: "text/event-stream" };
    if (MCP_SERVER_PASSWORD) {
      headers["Authorization"] = `Bearer ${MCP_SERVER_PASSWORD}`;
    }

    const controller = new AbortController();
    const res = await fetch(`${url}/sse`, {
      headers,
      signal: controller.signal,
    });

    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "text/event-stream");

    const reader = res.body?.getReader();
    assert.ok(reader);

    const { value } = await reader.read();
    const chunk = new TextDecoder().decode(value);

    // Official SSEServerTransport emits an 'endpoint' event pointing to messages URI with sessionId
    assert.ok(chunk.includes("event: endpoint"));
    assert.ok(chunk.includes("/messages?sessionId="));

    controller.abort();
  } finally {
    server.close();
  }
});

test("Official MCP SDK - POST /messages without valid session fails with 400", async () => {
  const { server, url } = await startTestServer();
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (MCP_SERVER_PASSWORD) {
      headers["Authorization"] = `Bearer ${MCP_SERVER_PASSWORD}`;
    }

    const res = await fetch(`${url}/messages?sessionId=non-existent-session-id`, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
    });

    assert.equal(res.status, 400);
    const data = (await res.json()) as any;
    assert.ok(data.error.includes("No active SSE transport session"));
  } finally {
    server.close();
  }
});
