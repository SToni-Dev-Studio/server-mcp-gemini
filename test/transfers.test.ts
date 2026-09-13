import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { parseLocation, executeTransfer } from "../src/tools/transfers.js";

test("Transfers - parseLocation prefixes", () => {
  const p1 = parseLocation("sandbox:/tmp/test.txt");
  assert.equal(p1.type, "sandbox");
  assert.equal(p1.path, "/tmp/test.txt");

  const p2 = parseLocation("server:/var/log/syslog");
  assert.equal(p2.type, "server");
  assert.equal(p2.path, "/var/log/syslog");

  const p3 = parseLocation("pc:default:C:\\logs\\agent.log");
  assert.equal(p3.type, "pc");
  assert.equal(p3.target, "default");
  assert.equal(p3.path, "C:\\logs\\agent.log");

  const p4 = parseLocation("codespace:my-cs:/workspace/repo");
  assert.equal(p4.type, "codespace");
  assert.equal(p4.target, "my-cs");
  assert.equal(p4.path, "/workspace/repo");

  // Local without prefix defaults to sandbox
  const p5 = parseLocation("/tmp/foo.txt");
  assert.equal(p5.type, "sandbox");
  assert.equal(p5.path, "/tmp/foo.txt");
});

test("Transfers - Local file transfer between sandbox paths", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-test-"));
  const srcFile = path.join(tmpDir, "source.txt");
  const dstFile = path.join(tmpDir, "destination.txt");

  fs.writeFileSync(srcFile, "Hello universal transfer system!", "utf-8");

  const res = await executeTransfer(srcFile, dstFile, false);
  assert.match(res, /Completed Successfully/i);
  assert.ok(fs.existsSync(dstFile));
  assert.equal(fs.readFileSync(dstFile, "utf-8"), "Hello universal transfer system!");

  // Clean up
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Transfers - Local folder transfer between sandbox paths", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-folder-"));
  const srcDir = path.join(tmpDir, "src-folder");
  const dstDir = path.join(tmpDir, "dst-folder");

  fs.mkdirSync(srcDir, { recursive: true });
  fs.writeFileSync(path.join(srcDir, "a.txt"), "File A", "utf-8");
  fs.writeFileSync(path.join(srcDir, "b.txt"), "File B", "utf-8");

  const res = await executeTransfer(srcDir, dstDir, true);
  assert.match(res, /Completed Successfully/i);
  assert.ok(fs.existsSync(path.join(dstDir, "a.txt")));
  assert.ok(fs.existsSync(path.join(dstDir, "b.txt")));
  assert.equal(fs.readFileSync(path.join(dstDir, "a.txt"), "utf-8"), "File A");

  // Clean up
  fs.rmSync(tmpDir, { recursive: true, force: true });
});
