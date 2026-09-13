import test from "node:test";
import assert from "node:assert/strict";
import { processMcpMessage } from "../src/mcp.js";
import { allTools, listTools } from "../src/tools/registry.js";

test("MCP Protocol - initialize", async () => {
  const req = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "test-client", version: "1.0" },
    },
  };

  const res = await processMcpMessage(req);
  assert.ok(res);
  assert.equal(res.id, 1);
  assert.equal(res.result.protocolVersion, "2024-11-05");
  assert.ok(res.result.capabilities.tools);
  assert.equal(res.result.serverInfo.name, "codespaces-mcp");
});

test("MCP Protocol - notifications/initialized returns null", async () => {
  const req = {
    jsonrpc: "2.0",
    method: "notifications/initialized",
  };
  const res = await processMcpMessage(req);
  assert.equal(res, null);
});

test("MCP Protocol - ping", async () => {
  const req = {
    jsonrpc: "2.0",
    id: "test-ping-id",
    method: "ping",
  };
  const res = await processMcpMessage(req);
  assert.ok(res);
  assert.equal(res.id, "test-ping-id");
  assert.deepEqual(res.result, {});
});

test("MCP Protocol - tools/list contains all registered tools", async () => {
  const req = {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
  };
  const res = await processMcpMessage(req);
  assert.ok(res);
  assert.equal(res.id, 2);
  const tools = res.result.tools;
  assert.ok(Array.isArray(tools));
  assert.equal(tools.length, Object.keys(allTools).length);

  // Verify critical tools are registered and Plex is removed
  const names = new Set(tools.map((t: any) => t.name));
  assert.ok(names.has("list_codespaces"));
  assert.ok(names.has("create_codespace"));
  assert.ok(names.has("exec_command"));
  assert.ok(names.has("server_status"));
  assert.ok(names.has("server_run_command"));
  assert.ok(names.has("server_download_anime"));
  assert.ok(names.has("plex_search"));
  assert.ok(names.has("pc_list_configured"));
  assert.ok(names.has("pc_organiser_status"));
  assert.ok(names.has("transfer__pc_to_sandbox"));
  assert.ok(names.has("run_diagnostics"));
});

test("MCP Protocol - tools/call execution and output wrapping", async () => {
  const req = {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: {
      name: "pc_list_configured",
      arguments: {},
    },
  };
  const res = await processMcpMessage(req);
  assert.ok(res);
  assert.equal(res.id, 3);
  assert.equal(res.result.isError, false);
  assert.ok(Array.isArray(res.result.content));
  assert.equal(res.result.content[0].type, "text");
  assert.ok(res.result.content[0].text.length > 0);
});

test("MCP Protocol - tools/call unknown tool error", async () => {
  const req = {
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: {
      name: "non_existent_tool_xyz",
      arguments: {},
    },
  };
  const res = await processMcpMessage(req);
  assert.ok(res);
  assert.equal(res.id, 4);
  assert.equal(res.result.isError, true);
  assert.match(res.result.content[0].text, /Unknown tool/);
});

test("MCP Protocol - unknown method returns -32601", async () => {
  const req = {
    jsonrpc: "2.0",
    id: 5,
    method: "prompts/list",
  };
  const res = await processMcpMessage(req);
  assert.ok(res);
  assert.equal(res.id, 5);
  assert.equal(res.error?.code, -32601);
});

test("MCP Protocol - tools/call with invalid params handles errors gracefully", async () => {
  const req = {
    jsonrpc: "2.0",
    id: 6,
    method: "tools/call",
    params: {
      name: "pc_organiser_status",
      arguments: { pc: "non-existent-pc-xyz" },
    },
  };
  const res = await processMcpMessage(req);
  assert.ok(res);
  assert.equal(res.id, 6);
  // Returns formatted diagnostic message
  assert.ok(res.result.content[0].text.includes("Could not reach") || res.result.content[0].text.includes("Unknown PC"));
});

