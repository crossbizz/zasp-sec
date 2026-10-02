import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { dirname } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const childPath = fileURLToPath(new URL("./fixtures/dependency-esbuild-regression-child.mjs", import.meta.url));

async function runOwnedChild(mode) {
  // A separate POSIX process group includes esbuild's native service. Timeout
  // cleanup kills that whole owned group, then joins the direct child.
  assert.notEqual(process.platform, "win32", "this owned-process regression requires POSIX process groups");
  const child = spawn(process.execPath, ["--max-old-space-size=96", childPath, mode], {
    cwd: fileURLToPath(new URL("../", import.meta.url)),
    env: { PATH: dirname(process.execPath), TZ: "UTC", ESBK_DISABLE_CACHE: "1" },
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "", stderr = "", failure;
  const killOwned = () => {
    if (!child.pid) return;
    try { process.kill(-child.pid, "SIGKILL"); } catch (error) {
      if (error.code !== "ESRCH") throw error;
    }
  };
  const timer = setTimeout(() => { failure = "owned child exceeded 15 seconds"; killOwned(); }, 15_000);
  for (const [stream, isError] of [[child.stdout, false], [child.stderr, true]]) {
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => {
      if (failure) return;
      const remaining = 32 * 1024 - Buffer.byteLength(stdout) - Buffer.byteLength(stderr);
      const bounded = Buffer.from(chunk).subarray(0, remaining).toString("utf8");
      if (isError) stderr += bounded; else stdout += bounded;
      if (Buffer.byteLength(chunk) > remaining) {
        failure = "owned child exceeded 32 KiB output";
        killOwned();
      }
    });
  }
  let result;
  try {
    result = await new Promise((resolve) => {
      child.once("error", (error) => { failure = error.message; });
      child.once("close", (status, signal) => resolve({ status, signal }));
    });
  } finally {
    clearTimeout(timer);
    // Normal helper cleanup disposes the context and stops the native service.
    // Check the group too, so a returned JSON object can't hide a live server.
    for (let attempt = 0; child.pid && attempt < 20; attempt++) {
      try { process.kill(-child.pid, 0); } catch (error) {
        if (error.code === "ESRCH") break;
        failure ??= `cannot inspect owned process group: ${error.message}`;
        killOwned();
        break;
      }
      if (attempt === 19) { failure ??= "owned process group survived child exit"; killOwned(); }
      else await delay(25);
    }
  }
  assert.equal(failure, undefined, `${mode}: ${failure}\n${stderr}`);
  assert.deepEqual(result, { status: 0, signal: null }, `${mode}: ${stderr}`);
  assert.equal(stderr, "", `${mode}: unexpected stderr`);
  return JSON.parse(stdout);
}

test("core-utils' actual esbuild serves the local fixture without allowing an unrelated origin to read it", async () => {
  const result = await runOwnedChild("cors");
  assert.equal(result.control.status, 200);
  assert.equal(result.control.value, 17);
  assert.equal(result.crossOrigin.status, 200);
  assert.equal(result.crossOrigin.value, 17);
  assert.equal(result.crossOrigin.allowOrigin, null);
  assert.match(result.parser, /\/esbuild\/lib\/main\.js$/);
});

test("core-utils' actual async and sync TypeScript transforms preserve exported values", async () => {
  const result = await runOwnedChild("transform");
  const expected = { id: 7, title: "local-note", content: "", createdAt: "2026-09-15" };
  assert.deepEqual(result.async, expected);
  assert.deepEqual(result.sync, expected);
});

test("real drizzle-kit generation retains the nonempty D1 notes schema and defaults", async () => {
  const result = await runOwnedChild("drizzle");
  assert.deepEqual(result.tables, ["notes"]);
  assert.deepEqual(result.columns, {
    id: { name: "id", type: "integer", primaryKey: true, notNull: true, autoincrement: true },
    title: { name: "title", type: "text", primaryKey: false, notNull: true, autoincrement: false },
    content: { name: "content", type: "text", primaryKey: false, notNull: true, autoincrement: false, default: "''" },
    created_at: { name: "created_at", type: "text", primaryKey: false, notNull: true, autoincrement: false, default: "CURRENT_TIMESTAMP" },
  });
  assert.match(result.sql, /CREATE TABLE `notes`/);
  assert.match(result.sql, /`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL/);
  assert.match(result.sql, /`content` text DEFAULT '' NOT NULL/);
  assert.match(result.sql, /`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL/);
});
