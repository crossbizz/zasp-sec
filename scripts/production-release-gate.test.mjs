import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { runInNewContext } from "node:vm";

async function executeGate(run, logs = []) {
  const source = await readFile(new URL("./production-release-gate.mjs", import.meta.url), "utf8");
  const start = source.indexOf("await verifyReleaseSources();");
  const end = source.indexOf("\nasync function run(", start);
  assert.ok(start > 0 && end > start);
  return runInNewContext(`(async () => { ${source.slice(start, end)} })()`, {
    verifyReleaseSources: async () => {}, run, path, root: "/owned/release",
    console: { log(message) { logs.push(message); } },
  });
}

test("standalone release gate runs canonical rollout tests before later release checks", async () => {
  const commands = [];
  await assert.rejects(executeGate(async (command, args) => {
    commands.push([command, [...args]]);
    return { stdout: JSON.stringify({ metadata: { vulnerabilities: { high: 0, critical: 0 } } }) };
  }), /dependency audit evidence unavailable/);
  assert.deepEqual(commands[0], ["npm", ["run", "production:release:test"]]);
  assert.equal(commands.filter(([command, args]) => command === "npm" && args[1] === "production:release:test").length, 1);
});

test("missing advisory evidence blocks release without an audit request or clearance claim", async () => {
  const commands = [];
  const logs = [];
  await assert.rejects(executeGate(async (command, args) => {
    commands.push([command, [...args]]);
    // Offline npm can emit these counters even though no advisory lookup ran.
    return { stdout: JSON.stringify({ metadata: { vulnerabilities: { high: 0, critical: 0 } } }) };
  }, logs), /dependency audit evidence unavailable/);
  assert.equal(commands.some(([command, args]) => command === "npm" && args[0] === "audit"), false);
  assert.equal(logs.some((message) => /checks passed/.test(message)), false);
  assert.ok(commands.some(([command, args]) => command === "go" && args[0] === "list"));
});

test("failed canonical rollout tests stop standalone release before any audit invocation", async () => {
  const commands = [];
  await assert.rejects(executeGate(async (command, args) => {
    commands.push([command, [...args]]);
    if (command === "npm" && args.join(" ") === "run production:release:test") throw new Error("owned rollout failure");
    return { stdout: JSON.stringify({ metadata: { vulnerabilities: { high: 0, critical: 0 } } }) };
  }), /owned rollout failure/);
  assert.deepEqual(commands, [["npm", ["run", "production:release:test"]]]);
});
