import assert from "node:assert/strict";
import test from "node:test";
import * as proof from "./audit-export-browser-proof.mjs";
import { spawnOwnedCommand } from "./owned-command.mjs";
import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";

test("policy diagnostics preserve the original browser failure when CDP is unavailable", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("  try { await waitForBrowserText(cdp,/Production runtime policy/); }");
  const end = source.indexOf("  assert.equal(await sql(", start);
  assert.ok(start > 0 && end > start);
  const original = new Error("policy result unavailable");
  const context = { cdp: {}, waitForBrowserText: async () => { throw original; },
    browserTextControlDisabled: async () => { throw new Error("CDP disconnected"); },
    console: { log() {}, error() {} } };
  await assert.rejects(runInNewContext(`(async()=>{${source.slice(start, end)}})()`, context), error => error === original);
});

test("browser text click waits for enabled controls before reporting a dispatched action", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function clickBrowserText(cdp, text) {");
  const end = source.indexOf("\nasync function clickBrowserTextContains", start);
  assert.ok(start > 0 && end > start);
  let clicks = 0;
  const button = { textContent: "Create policy", disabled: true, focus() {}, click() { if (!this.disabled) clicks++; } };
  const document = { querySelectorAll: () => [button] };
  const context = { waitForBrowserAction: async (_cdp, expression) => {
    assert.equal(runInNewContext(expression, { document }), false, "disabled click must not report success");
    assert.equal(clicks, 0);
    button.disabled = false;
    assert.equal(runInNewContext(expression, { document }), true);
    assert.equal(clicks, 1);
  } };
  await runInNewContext(`${source.slice(start, end)};clickBrowserText({},'Create policy')`, context);
});

test("both browser terminal branches propagate provider failure after joining", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const branches = source.match(/await auditExportProviderCommand\(ready,\{action:"stop"\}\);[^\n]+/g);
  assert.equal(branches.length, 2);
  for (const branch of branches) {
    for (const result of [{ status: 1, signal: null }, { status: null, signal: "SIGTERM" }]) {
      const context = { ready: {}, auditExportProviderCommand: async () => {},
        auditExportProvider: { completed: Promise.resolve(result) },
        joinAuditExportProvider: proof.joinAuditExportProvider, console: { log() {} } };
      await assert.rejects(runInNewContext(`(async()=>{${branch}})()`, context), /audit provider failed/);
    }
  }
});

test("provider completion rejects actual nonzero and signalled child exits", async () => {
  assert.equal(typeof proof.joinAuditExportProvider, "function");
  for (const [source, accepted] of [
    ["process.exit(0)", true],
    ["process.exit(1)", false],
    ["process.kill(process.pid,'SIGTERM')", false],
  ]) {
    const command = spawnOwnedCommand(process.execPath, ["-e", source]);
    try {
      if (accepted) assert.equal((await proof.joinAuditExportProvider(command)).status, 0);
      else await assert.rejects(proof.joinAuditExportProvider(command), /audit provider failed/);
    } finally { await command.stop(); }
  }
});

test("provider join preserves a rejected completion", async () => {
  const failure = new Error("owned provider spawn failed");
  await assert.rejects(proof.joinAuditExportProvider({ completed: Promise.reject(failure) }), error => error === failure);
});

test("package acceptance selects both audit browser regression files", async () => {
  const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const command = manifest.scripts["production:combined-e2e:test"].split(" && ")[0].split(/\s+/);
  assert.deepEqual(command.slice(0, 2), ["node", "--test"]);
  for (const file of ["scripts/audit-export-browser-proof.test.mjs", "scripts/audit-export-volume-proof.test.mjs"]) {
    assert.ok(command.includes(file), `package command omits ${file}`);
  }
});

test("large-export validation retains measured diagnostics before rejecting a short envelope", () => {
  const lines = [];
  const measurements = { events: 100008, chunkBytes: 99431964, maximumEnvelopeBytes: 990000 };
  assert.equal(typeof proof.assertAuditExportVolume, "function");
  assert.throws(() => proof.assertAuditExportVolume(measurements, line => lines.push(line)), /near-limit envelope/);
  assert.equal(lines.length, 1);
  assert.deepEqual(JSON.parse(lines[0].slice("AUDIT_EXPORT_VOLUME_MEASURED ".length)), measurements);
});

test("large-export validation preserves event, byte and envelope acceptance boundaries", () => {
  assert.equal(typeof proof.assertAuditExportVolume, "function");
  const accepted = { events: 100001, chunkBytes: 67108865, maximumEnvelopeBytes: 1064960 };
  assert.doesNotThrow(() => proof.assertAuditExportVolume(accepted, () => {}));
  assert.doesNotThrow(() => proof.assertAuditExportVolume({ ...accepted, maximumEnvelopeBytes: 1000001 }, () => {}));
  for (const changed of [
    { events: 100000 }, { chunkBytes: 67108864 },
    { maximumEnvelopeBytes: 1000000 }, { maximumEnvelopeBytes: 1064961 },
    { events: NaN }, { chunkBytes: Infinity }, { maximumEnvelopeBytes: 1000001.5 },
  ]) {
    assert.throws(() => proof.assertAuditExportVolume({ ...accepted, ...changed }, () => {}));
  }
});
