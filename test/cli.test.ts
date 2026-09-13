import test from "node:test";
import assert from "node:assert/strict";
import { runCli } from "../src/cli.js";

test("CLI - help argument executes without throwing", async () => {
  let output = "";
  const originalLog = console.log;
  console.log = (msg: string) => {
    output += msg + "\n";
  };
  try {
    await runCli(["--help"]);
    assert.match(output, /Codespaces MCP — Linux Management CLI/);
    assert.match(output, /transfer <source> <destination>/);
    assert.match(output, /secrets/);
  } finally {
    console.log = originalLog;
  }
});

test("CLI - secrets list displays environment config", async () => {
  let tableData: any = null;
  const originalTable = console.table;
  console.table = (data: any) => {
    tableData = data;
  };
  try {
    await runCli(["secrets", "list"]);
    assert.ok(Array.isArray(tableData));
    assert.ok(tableData.length > 0);
    const hasKeys = tableData.some((row: any) => row.Key === "GITHUB_TOKEN" || row.Key === "NODE");
    assert.ok(hasKeys, "Should list configuration keys");
  } finally {
    console.table = originalTable;
  }
});

test("CLI - secrets set and get", async () => {
  let logged = "";
  const originalLog = console.log;
  console.log = (msg: string) => {
    logged += msg + "\n";
  };
  try {
    await runCli(["secrets", "set", "TEST_CLI_SECRET_KEY", "mypassword123"]);
    assert.equal(process.env.TEST_CLI_SECRET_KEY, "mypassword123");

    logged = "";
    await runCli(["secrets", "get", "TEST_CLI_SECRET_KEY", "--reveal"]);
    assert.match(logged, /mypassword123/);
  } finally {
    delete process.env.TEST_CLI_SECRET_KEY;
    console.log = originalLog;
  }
});
