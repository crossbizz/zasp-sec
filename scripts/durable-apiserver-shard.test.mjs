import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { durableApiserverShard } from "./durable-apiserver-shard.mjs";

const summary = "ok  \tgithub.com/zasp-ai/zasp-sec/services/platform/apiserver\t0.032s";
const names = Array.from({ length: 890 }, (_, i) => `TestSecurityAgentCase${i}`);
names.push("TestSensor", "TestSensorRead", "TestSensorÜnicode");
const list = (tests, footer = summary) => [...tests, footer].join("\n") + "\n";

test("eight exact-name selections cover every listed test once, independently of list order", () => {
  const tests = names;
  const shards = Array.from({ length: 8 }, (_, i) => durableApiserverShard(list(tests), i));
  const sizes = shards.map(shard => shard.selected.length);
  assert.ok(Math.max(...sizes) - Math.min(...sizes) <= 1);
  assert.deepEqual(shards.flatMap(shard => shard.selected).sort(), [...tests].sort());
  for (const [i, shard] of shards.entries()) {
    assert.equal(shard.total, tests.length);
    const expression = new RegExp(shard.pattern, "u");
    assert.deepEqual(tests.filter(name => expression.test(name)).sort(), shard.selected);
    assert.equal(expression.test("TestSensorUnlisted"), false);
    assert.deepEqual(durableApiserverShard(list([...tests].reverse()), i), shard);
  }
});

test("rejects incomplete, duplicate and malformed listings and out-of-range shards", () => {
  for (const invalid of [
    list(names.slice(0, 7)), list([...names, names[0]]), list([...names, "TestSensor.*"]),
    list([...names, "unparsed output"]), list(names, "FAIL"), list(names, ""),
    list(names, summary.replace("apiserver", "agentsec-worker")),
  ]) assert.throws(() => durableApiserverShard(invalid, 0));
  for (const invalid of [-1, 8, 0.5, NaN]) {
    assert.throws(() => durableApiserverShard(list(names), invalid));
  }
  assert.equal(durableApiserverShard(list(names, summary.replace("0.032s", "(cached)")), 7).total, names.length);
});

test("CLI prints only the Go selector on stdout and refuses malformed shard arguments", t => {
  const directory = mkdtempSync(join(tmpdir(), "zasp-apiserver-selection-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, "tests");
  writeFileSync(path, list(names));
  const script = join(import.meta.dirname, "durable-apiserver-shard.mjs");
  const output = execFileSync(process.execPath, [script, path, "4"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  assert.equal(output.trim(), durableApiserverShard(list(names), 4).pattern);
  for (const args of [[], [path], [path, ""], [path, "08"], [path, "2", "extra"]]) {
    const child = spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
    assert.notEqual(child.status, 0);
    assert.equal(child.stdout, "");
  }
});
