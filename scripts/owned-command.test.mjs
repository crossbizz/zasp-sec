import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { spawnOwnedCommand } from "./owned-command.mjs";

const descendant = `
  process.on('SIGTERM', () => {});
  process.stdout.write('descendant:' + process.pid + '\\n');
  setInterval(() => {}, 1000);
`;
const parent = `
  const { spawn } = require('node:child_process');
  const child = spawn(process.execPath, ['-e', ${JSON.stringify(descendant)}], { stdio: 'inherit' });
  if (process.argv[1] === 'parent-exits') {
    child.unref();
    setTimeout(() => process.exit(0), 100);
  }
`;

test("owned command retains exact result and settled cleanup is idempotent", async () => {
  const owned = spawnOwnedCommand(process.execPath, ["-e", "process.stdout.write('out'); process.stderr.write('err'); process.exitCode = 7"]);
  assert.deepEqual(await owned.completed, { status: 7, signal: null, stdout: "out", stderr: "err" });
  await owned.stop();
  await owned.stop();
});

test("failed spawn still settles cleanup without hiding the command error", async () => {
  const owned = spawnOwnedCommand("/zasp-owned-command-missing-executable", []);
  await assert.rejects(owned.completed, { code: "ENOENT" });
  await owned.stop();
});

function running(pid) {
  const result = spawnSync("ps", ["-p", String(pid), "-o", "stat="], { encoding: "utf8" });
  assert.ok(result.status === 0 || result.status === 1, "process inspection failed");
  return result.status === 0 && !result.stdout.trim().startsWith("Z");
}

for (const mode of ["parent-waits", "parent-exits"]) {
  test(`owned command settles a TERM-resistant descendant when ${mode}`, { timeout: 12_000, skip: process.platform === "win32" }, async () => {
    const unrelated = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
    const owned = spawnOwnedCommand(process.execPath, ["-e", parent, mode], { graceMs: 100, killMs: 1000 });
    let output = "", descendantPID;
    owned.child.stdout.on("data", (value) => { output += value; });
    try {
      for (let i = 0; i < 100 && !/descendant:(\d+)/.test(output); i++) await delay(20);
      descendantPID = Number(output.match(/descendant:(\d+)/)?.[1]);
      assert.ok(Number.isSafeInteger(descendantPID) && descendantPID > 1, "child did not publish its identity");
      assert.equal(running(descendantPID), true);
      if (mode === "parent-exits") {
        if (owned.child.exitCode === null) await once(owned.child, "exit");
        assert.equal(owned.child.exitCode, 0);
      }
      await owned.stop();
      assert.equal(running(descendantPID), false, "command cleanup left its descendant running");
      await owned.completed;
      await owned.stop();
      assert.equal(running(unrelated.pid), true, "cleanup signaled an unrelated child");
    } finally {
      // These are exact PIDs returned by this test's own child creation. The
      // fallback keeps the intentionally failing regression from leaking work.
      if (descendantPID && running(descendantPID)) process.kill(descendantPID, "SIGKILL");
      if (owned.child.exitCode === null && owned.child.signalCode === null) owned.child.kill("SIGKILL");
      await owned.completed;
      unrelated.kill("SIGKILL");
      await once(unrelated, "exit");
    }
  });
}
