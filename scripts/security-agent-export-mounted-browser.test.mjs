import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { assertExportBrowserDownload, prepareExportBrowserRelease } from "./security-agent-export-mounted-browser.mjs";

const bytes = Buffer.from('{"version":1,"run_id":"run","step_id":"step","records":[]}');
const envelope = Buffer.from(`{"version":1,"id":"export","json":${bytes},"csv":"a,b\\n","human":"evidence\\n"}`);
const sha256 = value => createHash("sha256").update(value).digest("hex");

// Exercise the persisted-evidence acceptance boundary without launching a browser.
// The old single-record assumption must fail on the public manual + run_audit selection.
async function checkCompletedEvidence(mutate = () => {}, sourceResult = value => value, observeSQL = () => {}) {
  const source = await readFile(new URL("./security-agent-export-mounted-browser.mjs", import.meta.url), "utf8");
  const begin = source.indexOf("  const job = await read(exportPath);");
  const end = source.indexOf('  await clickBrowserText(cdp,"Refresh export status");', begin);
  assert.ok(begin >= 0 && end > begin);
  const run = { id: "pid_10000010-0000-4000-8000-000000000010", manual_trigger: { intent_digest: `sha256:${"a".repeat(64)}`, version: 1 } };
  const definition = { id: "pid_10000011-0000-4000-8000-000000000011" };
  const stepID = "pid_10000012-0000-4000-8000-000000000012";
  const scope = "pid_10000001-0000-4000-8000-000000000001/pid_10000022-0000-4000-8000-000000000022/pid_10000023-0000-4000-8000-000000000023";
  const [organization_id, workspace_id, environment_id] = scope.split("/");
  const auditID = "pid_10000013-0000-4000-8000-000000000013";
  const manual = { run_id: run.id, definition_id: definition.id, trigger_id: "a".repeat(64), trigger_kind: "manual", trigger_version: 1, trigger_digest: run.manual_trigger.intent_digest, received_at: "2026-09-19T12:00:00+00:00" };
  const audit = { id: auditID, run_id: run.id, organization_id, workspace_id, environment_id, actor_reference: "pid_10000004-0000-4000-8000-000000000004", event_kind: "run_queued", correlation_id: "pid_10000014-0000-4000-8000-000000000014", occurred_at: "2026-09-19T12:00:00.000000Z" };
  const selection = [{ source_kind: "manual", source_id: "a".repeat(64), source_version: 1, association_digest: run.manual_trigger.intent_digest }, { source_kind: "run_audit", source_id: auditID, source_version: 1, association_digest: run.manual_trigger.intent_digest }];
  const records = [manual, audit].map((content, index) => { const content_json = JSON.stringify(content); return { ...selection[index], content_json, content_sha256: sha256(content_json) }; });
  const manifest = { run_id: run.id, step_id: stepID, organization_id, workspace_id, environment_id, records };
  const job = { state: "completed", cleanup_state: "retained", export_id: "pid_10000015-0000-4000-8000-000000000015", selection };
  const input = { job, manifest, run, definition, stepID, scope };
  mutate(input);
  const state = { version: 1, objects: [{ deleted: false, body: Buffer.from(JSON.stringify({ id: job.export_id, json: manifest })).toString("base64") }] };
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  const execute = new AsyncFunction("assert", "read", "exportPath", "readFile", "path", "storeDirectory", "run", "stepID", "scope", "definition", "createHash", "sql", "productID", source.slice(begin, end));
  await execute(assert, async () => job, "/owned/export", async () => JSON.stringify(state), { join: () => "/owned/state.json" }, "/owned", input.run, input.stepID, input.scope, input.definition, createHash, async query => {
    observeSQL(query);
    if (query.includes("zasp_security_agent_trigger_receipts")) return sourceResult(JSON.stringify(manual));
    if (query.includes("zasp_security_agent_audit")) return sourceResult(JSON.stringify(audit));
    throw new Error(`Unexpected evidence query: ${query}`);
  }, /^pid_[0-9a-f-]{36}$/);
}

test("completed public manual export accepts and verifies both original selected records", async () => {
  await checkCompletedEvidence();
});

test("completed export refuses missing, reordered, altered, or corrupt selected evidence", async () => {
  for (const mutate of [
    ({ job, manifest }) => { job.selection.pop(); manifest.records.pop(); },
    ({ job, manifest }) => { job.selection.push({ ...job.selection[1] }); manifest.records.push({ ...manifest.records[1] }); },
    ({ job, manifest }) => { job.selection.reverse(); manifest.records.reverse(); },
    ({ manifest }) => { manifest.records[1].source_id = "pid_10000099-0000-4000-8000-000000000099"; },
    ({ manifest }) => { manifest.records[1].content_sha256 = "0".repeat(64); },
    ({ manifest }) => { const record = manifest.records[1]; record.content_json = JSON.stringify({ ...JSON.parse(record.content_json), event_kind: "run_succeeded" }); record.content_sha256 = sha256(record.content_json); },
    ({ manifest }) => { const record = manifest.records[0]; record.content_json = JSON.stringify({ ...JSON.parse(record.content_json), received_at: "2026-09-19T13:00:00+00:00" }); record.content_sha256 = sha256(record.content_json); },
  ]) await assert.rejects(checkCompletedEvidence(mutate), { name: "AssertionError" });
});

test("completed export requires one independently retained source row, not an absent or duplicate result", async () => {
  for (const sourceResult of [() => "", value => `${value}\n${value}`]) {
    await assert.rejects(checkCompletedEvidence(undefined, sourceResult), { name: "SyntaxError" });
  }
});

test("completed export rejects noncanonical SQL values before either owner query", async () => {
  const mutations = [
    input => { input.definition.id += "'); SELECT 1; --"; },
    input => { input.definition.id = "pid_" + "-".repeat(36); },
    input => { input.run.id += "'"; input.manifest.run_id = input.run.id; },
    input => { input.stepID += "'"; input.manifest.step_id = input.stepID; },
    input => { input.manifest.organization_id += "'"; input.scope = [input.manifest.organization_id, input.manifest.workspace_id, input.manifest.environment_id].join("/"); },
    input => { input.job.selection[1].source_id = "pid_" + "-".repeat(36); input.manifest.records[1].source_id = input.job.selection[1].source_id; },
    input => { input.run.manual_trigger.version = "1); SELECT 1; --"; input.job.selection[0].source_version = input.run.manual_trigger.version; input.manifest.records[0].source_version = input.run.manual_trigger.version; },
  ];
  for (const invalidDigest of ["sha256:" + "a".repeat(64) + "'", "sha256:" + "A".repeat(64), "sha256:" + "a".repeat(63), "sha256:" + "a".repeat(64) + "\n", "a".repeat(64)]) {
    mutations.push(input => {
      input.run.manual_trigger.intent_digest = invalidDigest;
      for (const item of [...input.job.selection, ...input.manifest.records]) item.association_digest = invalidDigest;
      input.job.selection[0].source_id = input.manifest.records[0].source_id = invalidDigest.replace(/^sha256:/, "");
    });
  }
  for (const mutate of mutations) {
    const queries = [];
    await assert.rejects(checkCompletedEvidence(mutate, undefined, query => queries.push(query)), { name: "AssertionError" });
    assert.deepEqual(queries, [], "malformed evidence reached owner SQL");
  }
});
function fixture() { return { saved: bytes, envelope, format: "json", exportID: "export", packageSHA256: sha256(envelope), packageSize: envelope.length, filename: "agent-export-export.json", events: [{ guid: "native-1", suggestedFilename: "agent-export-export.json" }, { guid: "native-1", state: "completed", receivedBytes: bytes.length }] }; }

test("saved export bytes require the matching completed browser download and persisted package", () => {
  assert.doesNotThrow(() => assertExportBrowserDownload(fixture()));
  for (const change of [{ saved: Buffer.from("other") }, { events: [] }, { filename: "wrong.json" }, { packageSHA256: "0".repeat(64) }, { packageSize: 1 }, { events: [{ guid: "x", state: "completed", receivedBytes: bytes.length }] }]) {
    assert.throws(() => assertExportBrowserDownload({ ...fixture(), ...change }));
  }
});

test("native CSV and readable use their exact stored strings and refuse cancelled or wrong-GUID downloads",()=>{
  for(const [format,suffix,content] of [["csv","csv","a,b\n"],["human","txt","evidence\n"]]){
    const value=fixture(),filename=`agent-export-export.${suffix}`,saved=Buffer.from(content);
    const input={...value,format,filename,saved,events:[{guid:"format-1",suggestedFilename:filename},{guid:"format-1",state:"completed",receivedBytes:saved.length}]};
    assert.equal(assertExportBrowserDownload(input).bytes,saved.length);
    assert.throws(()=>assertExportBrowserDownload({...input,events:[input.events[0],{...input.events[1],guid:"other"}]}));
    assert.throws(()=>assertExportBrowserDownload({...input,events:[input.events[0],{...input.events[1],state:"canceled"}]}));
  }
});

test("export release refuses checksum and fingerprint drift without registering principals",async()=>{
  for(const pin of ["0".repeat(64)+"|8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f","5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985|"+"0".repeat(64)]){
    const calls=[];
    await assert.rejects(prepareExportBrowserRelease({migrate:"/migrate",migrationEnvironment:{},command:async(...v)=>calls.push(v),sql:async q=>q.includes("max(version)")?"58":pin}),/pin drift/);
    assert.equal(calls.length,1);
  }
});

test("selected export setup installs58 and refuses stale catalog readback before registration", async () => {
  const calls = [];
  await prepareExportBrowserRelease({ migrate: "/migrate", migrationEnvironment: { owned: "yes" }, command: async (exe, args) => { calls.push([exe, args]); }, sql: async q => q.includes("max(version)") ? "58" : "5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985|8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f" });
  assert.deepEqual(calls[0], ["/migrate", ["up-to-58"]]);
  assert.deepEqual(calls.at(-1), ["/migrate", ["register-compliance-workers"]]);
  const before = calls.length;
  await assert.rejects(prepareExportBrowserRelease({ migrate: "/migrate", migrationEnvironment: {}, command: async (...v) => calls.push(v), sql: async () => "57" }), /58/);
  assert.equal(calls.length, before + 1, "stale release registered workers");
});
