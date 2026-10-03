import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, readdir, rm, rmdir } from "node:fs/promises";
import os from "node:os";
import http from "node:http";
import path from "node:path";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { auditBrowserAPISettings, auditBrowserEnvironment, auditBrowserPolicyEnvironment } from "./audit-log-browser-proof.mjs";
import { exportBrowserIdentity, exportBrowserRelease } from "./security-agent-export-mounted-browser.mjs";

const discoveryRelease60 = {
  version: 60,
  checksum: "37956023196757f30a7ecb415e9d7d7e6f76cfa32a3ffa2d45445c172f6313ab",
  fingerprint: "1ed52fb5f9a83384e1d3fecbc3bc116d3981a36479e9b3b1f6ec04b5cd4f3b36",
};

// Execute the actual automatic-mode startup with only process, filesystem and
// database boundaries controlled. Stop at API readiness, before any provider or
// browser work; this is harness behavior evidence, not connected acceptance.
async function automaticDiscoveryStartupFixture({ release = {}, joinFailure = false, sourceChanged = false } = {}) {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseAutomaticDiscoveryBrowser("), end = source.indexOf("\nasync function stopExportBrowserAPI", start);
  const pinStart = source.indexOf("const automaticDiscoveryRelease ="), pinEnd = source.indexOf("\n", pinStart);
  const hashStart = source.indexOf("async function hashAutomaticDiscoveryInputs("), hashEnd = source.indexOf("\nasync function ", hashStart + 1);
  const files = new Map(), environments = [], queries = [], reads = [];
  const stageFailure = new Error("controlled API readiness failure");
  let changed = false;
  const context = {
    assert, path, os, Date, Buffer, createHash, AggregateError, process: { env: {} }, console: { log() {} },
    root: "/owned", platform: "/owned/services/platform", postgresBin: "/bin", temporaryRoot: "/owned/tmp", productHostname: "owned.test",
    children: [], ownedCommands: new WeakMap(), automaticDiscoveryEvidenceDirectory: null, automaticDiscoverySourceHashes: undefined,
    postgres: { containerID: "a".repeat(64), name: "owned-postgres" }, exportBrowserRelease,
    mkdtemp: async () => "/evidence", writeFile: async (file, value) => { files.set(file, JSON.parse(value)); },
    readdir: async directory => [{ name: directory.endsWith("scripts") ? "production-combined-e2e.mjs" : "source.go", isDirectory: () => false, isFile: () => true }],
    readFile: async file => { reads.push(file); return Buffer.from(`${file}${sourceChanged && changed ? "changed" : ""}`); },
    auditBrowserEnvironment: env => env, combinedAPIEnvironment: () => ({}),
    command: async (_exe, args) => {
      if (args.includes("-c")) {
        const statement = args.at(-1); queries.push(statement);
        if (statement.includes("jsonb_build_object")) return { stdout: JSON.stringify({ ...discoveryRelease60, liveFingerprint: discoveryRelease60.fingerprint, ready: true, maxVersion: 60, ...release }) };
        return { stdout: `${exportBrowserRelease.checksum}|${exportBrowserRelease.fingerprint}` };
      }
      return { stdout: "755 999 999" };
    },
    startIdentityServer: async () => ({}), startPolicyHistoryServer: async () => ({}),
    spawnOwnedCommand: (_binary, _args, { env }) => {
      environments.push(env);
      let resolve;
      const completed = new Promise(done => { resolve = done; });
      return { child: { pid: 123, stdout: { on() {} }, stderr: { on() {} } }, completed,
        stop: async () => { resolve({ status: joinFailure ? 7 : 0, signal: null, stdout: "", stderr: joinFailure ? "controlled join failure" : "" }); } };
    },
    waitForHTTP: async () => { changed = true; throw stageFailure; },
  };
  const definitions = `${pinStart < 0 ? "" : source.slice(pinStart, pinEnd)}\n${hashStart < 0 ? "" : source.slice(hashStart, hashEnd)}`;
  const run = runInNewContext(`${definitions}\n(${source.slice(start, end)})`, context);
  let failure;
  try { await run({ dsn: "owned", apiBinary: "/api", workerBinary: "/worker", workerE2EBinary: "/worker.test", postgresPort: 15432, proxyPort: 14443 }); }
  catch (error) { failure = error; }
  return { failure, stageFailure, environments, queries, reads, manifest: files.get("/evidence/manifest.json") };
}

test("automatic discovery migrates only its mode to release60", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("  if (automaticDiscoveryMode) await command(migrate"), end = source.indexOf("\n  if (securityAgentExportMode)", start);
  for (const enabled of [false, true]) {
    const calls = [];
    await runInNewContext(`(async()=>{${source.slice(start, end)}})()`, {
      automaticDiscoveryMode: enabled, migrate: "/migrate", migrationEnvironment: { owner: "registered" },
      command: async (exe, args, options) => { calls.push([exe, Array.from(args), options.env.owner]); },
    });
    assert.deepEqual(calls, enabled ? [["/migrate", ["up-to-60"], "registered"]] : []);
  }
});

test("automatic discovery checks exact60 metadata live fingerprint and readiness before API startup", async t => {
  for (const [label, release] of Object.entries({ predecessor: { version: 59 }, checksum: { checksum: "0".repeat(64) }, metadata: { fingerprint: "0".repeat(64) }, drift: { liveFingerprint: "0".repeat(64) }, notReady: { ready: false }, laterRelease: { maxVersion: 61 } })) {
    await t.test(label, async () => {
      const result = await automaticDiscoveryStartupFixture({ release });
      assert.equal(result.environments.length, 0, "unverified schema started the API");
      assert.ok(result.failure);
      assert.equal(result.manifest.completed, false);
    });
  }
});

test("automatic discovery starts the API expecting60 without changing export58", async () => {
  const result = await automaticDiscoveryStartupFixture();
  assert.equal(result.failure, result.stageFailure);
  assert.equal(result.environments.length, 1);
  assert.equal(result.environments[0].ZASP_EXPECTED_SCHEMA_VERSION, "60");
  assert.equal(exportBrowserRelease.version, 58);
  const exported = await exportShutdownFixture();
  for (const env of exported.apiEnvironments) assert.equal(env.ZASP_EXPECTED_SCHEMA_VERSION, "58");
});

test("automatic discovery records release60 in its source-bound manifest", async () => {
  const result = await automaticDiscoveryStartupFixture();
  assert.deepEqual(result.manifest.release, discoveryRelease60);
});

test("automatic discovery retains stage failure separately from process join failure", async () => {
  const result = await automaticDiscoveryStartupFixture({ joinFailure: true });
  assert.ok(result.manifest.failure, "caught stage failure was discarded");
  assert.equal(result.manifest.failure.stage, "startup");
  assert.equal(result.manifest.failure.message, "controlled API readiness failure");
  assert.equal(result.manifest.joinErrors.length, 1);
  assert.match(result.manifest.joinErrors[0].message, /controlled join failure/);
  assert.equal(result.manifest.completed, false);
  assert.ok(result.failure instanceof AggregateError);
  assert.equal(result.failure.errors[0], result.stageFailure);
});

test("automatic discovery freezes source and binary hashes before startup and refuses changed inputs", async () => {
  const result = await automaticDiscoveryStartupFixture({ sourceChanged: true });
  assert.ok(result.reads.some(file => file.startsWith("/owned/services/platform/")), "platform input hashes absent");
  assert.ok(result.reads.includes("/owned/tmp/agentsec-migrate"), "migration binary hash absent");
  assert.ok(result.reads.includes("/owned/tmp/postgres-relay"), "relay binary hash absent");
  assert.equal(result.manifest.inputsUnchanged, false);
  assert.equal(result.manifest.completed, false);
  assert.notDeepEqual(result.manifest.hashes, result.manifest.finalHashes);
});

test("automatic discovery requires one rebound occurrence with durable completion", async t => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("    const durable=JSON.parse", source.indexOf("async function exerciseAutomaticDiscoveryBrowser(")), end = source.indexOf("    const disable=", start);
  const occurrence = { integration_id: "A", schedule_id: "schedule", sync_id: "sync", job_id: "job", outbox_id: "outbox", scheduled_for: "2026-09-20T00:00:00.000Z", rebind_generation: 1, completed_at: "2026-09-20T00:00:06.000Z", completion_digest: "a".repeat(64), completion_result: { id: "schedule", state: "enabled", next_run_at: "2026-09-20T00:05:06.000Z", version: 4 }, lease_owner: "automatic-discovery-scheduler-restarted" };
  // The public IntegrationSchedule deliberately omits the internal schedule id.
  const publicSchedule = { integration_id: "A", cadence_seconds: 300, state: "enabled", time_zone: "UTC", next_run_at: occurrence.scheduled_for, version: 1, created_at: "2026-09-19T23:55:00Z", updated_at: "2026-09-19T23:55:00Z" };
  for (const [label, rows] of Object.entries({ accepted: [occurrence], absent: [], duplicate: [occurrence, occurrence], noRebind: [{ ...occurrence, rebind_generation: 0 }], noCompletion: [{ ...occurrence, completed_at: null }], noDigest: [{ ...occurrence, completion_digest: null }], wrongSync: [{ ...occurrence, sync_id: "other" }], wrongIntegration: [{ ...occurrence, integration_id: "other" }], wrongScheduleResult: [{ ...occurrence, completion_result: { ...occurrence.completion_result, id: "other" } }], wrongDue: [{ ...occurrence, scheduled_for: "2026-09-20T00:01:00.000Z" }], wrongResult: [{ ...occurrence, completion_result: { ...occurrence.completion_result, version: 3 } }] })) {
    await t.test(label, async () => {
      const checkpoints = [];
      const context = { assert, Date, checkpoints, primaryPredicate: "true", task5KubernetesAIntegrationID: "A", task5KubernetesBIntegrationID: "B", syncID: "sync", saved: { body: publicSchedule }, advanced: { body: { ...publicSchedule, next_run_at: occurrence.completion_result.next_run_at, version: 4 } },
        sql: async query => JSON.stringify(query.includes("jsonb_build_object('syncs'") ? { syncs: 1, jobs: 1, outbox: 1, deleted_syncs: 0 } : query.includes("'undefined'") ? [] : rows),
      };
      const run = () => runInNewContext(`(async()=>{${source.slice(start, end)}})()`, context);
      if (label === "accepted") { await run(); assert.ok(checkpoints[0].occurrence, "durable occurrence evidence missing"); assert.equal(checkpoints[0].occurrence.rebind_generation, 1); }
      else await assert.rejects(run, undefined, "incomplete or mismatched occurrence accepted");
    });
  }
});

test("automatic discovery withdrawal crosses the version-bound stored disabled due", async t => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf('    stage="disabled-real-due-window"'), end = source.indexOf("    await join(second)", start);
  const advancedDue = "2026-09-20T06:08:41.620497Z", storedDue = "2026-09-20T06:08:47.084951Z";
  const stored = { integration_id: "A", state: "disabled", version: 5, next_run_at: storedDue };
  for (const [label, row] of Object.entries({ accepted: stored, foreign: { ...stored, integration_id: "B" }, stale: { ...stored, version: 4 }, enabled: { ...stored, state: "enabled" }, noDue: { ...stored, next_run_at: null }, noRow: null })) {
    await t.test(label, async () => {
      let now = Date.parse(advancedDue) + 1_000;
      class Clock extends Date { static now() { return now; } constructor(...args) { super(...(args.length ? args : [now])); } }
      const checkpoints = [], statements = [];
      const run = () => runInNewContext(`(async()=>{${source.slice(start, end)}})()`, {
        assert, Date: Clock, checkpoints, console: { log() {} }, primaryPredicate: "organization_id='org' AND workspace_id='workspace' AND environment_id='environment'", task5KubernetesAIntegrationID: "A", task5KubernetesBIntegrationID: "B",
        advanced: { body: { next_run_at: advancedDue } }, disable: { body: { integration_id: "A", cadence_seconds: 300, state: "disabled", time_zone: "UTC", next_run_at: null, version: 5, created_at: "2026-09-20T05:58:41Z", updated_at: "2026-09-20T06:03:47Z" } },
        second: { child: { exitCode: null }, output: () => "" },
        sql: async query => { statements.push(query); return query.startsWith("SELECT count(*)") ? "1" : JSON.stringify(row); },
        waitUntil: async (deadline, condition) => {
          assert.equal(deadline, Date.parse(storedDue) + 10_000, "withdrawal deadline used pre-disable due");
          assert.equal(await condition(), false, "withdrawal accepted before stored disabled due");
          now = Date.parse(storedDue) + 1_000;
          assert.equal(await condition(), true);
        },
      });
      if (label === "accepted") {
        await run();
        assert.match(statements[0], /organization_id='org' AND workspace_id='workspace' AND environment_id='environment'/);
        assert.match(statements[0], /integration_id='A'/);assert.match(statements[0], /version=5/);assert.match(statements[0], /state='disabled'/);
        assert.equal(checkpoints[0].observedBeyond, storedDue);
        assert.deepEqual(JSON.parse(JSON.stringify(checkpoints[0].withdrawalSchedule)), stored);
      } else await assert.rejects(run);
    });
  }
});

test("automatic inventory distinguishes seeded rows and requires the collected target", async()=>{
  const source=await readFile(new URL("./production-combined-e2e.mjs",import.meta.url),"utf8");
  const start=source.indexOf("function assertAutomaticDiscoveryInventory("),end=source.indexOf("\nasync function ",start);
  const check=runInNewContext(`(${source.slice(start,end)})`,{assert});
  const seed={id:"seed",name:"Authorized prior inventory"},agent={id:"agent",name:"zasp/scheduled-agent"};
  assert.equal(check([seed],[seed,agent],"zasp/scheduled-agent"),"agent");
  assert.throws(()=>check([seed],[seed],"zasp/scheduled-agent"));
  assert.throws(()=>check([seed],[{...seed,name:"changed seed"},agent],"zasp/scheduled-agent"));
  assert.throws(()=>check([seed],[seed,agent,{...agent,id:"duplicate"}],"zasp/scheduled-agent"));
  assert.throws(()=>check([seed,agent],[seed,agent],"zasp/scheduled-agent"));
  assert.equal(check([seed,agent],[seed,{...agent,name:"zasp/scheduled-agent-updated"}],"zasp/scheduled-agent-updated","agent"),"agent");
  assert.throws(()=>check([seed,agent],[seed,{...agent,id:"replaced",name:"zasp/scheduled-agent-updated"}],"zasp/scheduled-agent-updated","agent"));
});
import { spawnOwnedCommand } from "./owned-command.mjs";

test("automatic discovery proof refuses malformed or mixed modes before resource allocation", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const preamble = source.slice(source.indexOf("const securityAgentSimulationMode"), source.indexOf("const FIXED_NODE_VERSION"));
  const select = env => runInNewContext(`${preamble}\ntypeof automaticDiscoveryMode !== 'undefined' && automaticDiscoveryMode`, {
    assert, process: { env }, validateSecurityAgentSimulationMode: () => false,
    validateSecurityAgentRunContextMode: () => false, validateAuditBrowserMode: () => false,
    validateAuditExportBrowserMode: () => false, validateAuditExportPrepareMode: () => false,
    validatePrecisionBrowserMode: () => false, createAuditMutationCollector: () => ({}), createAuditRequestTrace: () => ({}),
  });
  assert.equal(select({}), false);
  assert.equal(select({ ZASP_COMBINED_E2E_AUTOMATIC_DISCOVERY: "true" }), true);
  for (const value of ["false", "", "1", "TRUE"]) assert.throws(() => select({ ZASP_COMBINED_E2E_AUTOMATIC_DISCOVERY: value }));
  for (const key of ["SECURITY_AGENT_EXPORT", "COMPLIANCE", "EXISTING_TEST", "RUNTIME_PIPELINE_ONLY", "AUDIT_EXPORT"]) {
    assert.throws(() => select({ ZASP_COMBINED_E2E_AUTOMATIC_DISCOVERY: "true", [`ZASP_COMBINED_E2E_${key}`]: "true" }));
  }
});

test("export browser mode refuses mixed or malformed selections before allocating resources", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const preamble = source.slice(source.indexOf("const securityAgentSimulationMode"), source.indexOf("const FIXED_NODE_VERSION"));
  const select = env => runInNewContext(`${preamble}\ntypeof securityAgentExportMode !== 'undefined' && securityAgentExportMode`, {
    assert, process: { env }, validateSecurityAgentSimulationMode: () => false,
    validateSecurityAgentRunContextMode: () => false, validateAuditBrowserMode: () => false,
    validateAuditExportBrowserMode: () => false, validateAuditExportPrepareMode: () => false,
    validatePrecisionBrowserMode: () => false, createAuditMutationCollector: () => ({}), createAuditRequestTrace: () => ({}),
  });
  assert.equal(select({}), false);
  assert.equal(select({ ZASP_COMBINED_E2E_SECURITY_AGENT_EXPORT: "true" }), true);
  for (const value of ["false", "1", "", "TRUE"]) assert.throws(() => select({ ZASP_COMBINED_E2E_SECURITY_AGENT_EXPORT: value }));
  for (const key of ["COMPLIANCE", "EXISTING_TEST", "ATTACK_LAB", "AUDIT_BROWSE", "AUDIT_EXPORT", "SECURITY_AGENT_SIMULATION_ONLY", "SECURITY_AGENT_RUN_CONTEXT", "RUNTIME_PIPELINE_ONLY", "RUNTIME_PRECISION", "RED_TEAM_RUNTIME"]) {
    assert.throws(() => select({ ZASP_COMBINED_E2E_SECURITY_AGENT_EXPORT: "true", [`ZASP_COMBINED_E2E_${key}`]: "true" }), key);
  }
});

test("export callback authenticates distinct author approver and foreign provider sessions without cookie injection", async () => {
  const source=await readFile(new URL("./production-combined-e2e.mjs",import.meta.url),"utf8");
  const start=source.indexOf("async function startIdentityServer("),end=source.indexOf("\nasync function startPolicyHistoryServer",start);
  let handler;
  const context={http:{createServer:fn=>{handler=fn;return {listen(){}};}},once:async()=>{},assert,URL,Buffer,Date,securityAgentExportMode:true,exportBrowserIdentity,identityOAuthStarts:0,nextIdentityLogin:"author",pendingIdentityLogin:"author",readBody:async r=>r.body};
  await runInNewContext(`(${source.slice(start,end)})(15432,'https://owned.test')`,context);
  const invoke=async(method,url,body)=>{
    let status,value,headers;
    await handler({method,url,body:JSON.stringify(body),headers:{authorization:`Basic ${Buffer.from("project-test-local:secret-test-local").toString("base64")}`}},{writeHead:(code,h)=>{status=code;headers=h;},end:raw=>{value=raw?JSON.parse(raw):null;}});
    return {status,value,headers};
  };
  const sessions=[];
  for(const [name,member,organization] of [["author","member-test-local","organization-test-local"],["approver","member-export-approver","organization-test-local"],["foreign","member-export-foreign","organization-export-foreign"]]){
    context.nextIdentityLogin=name;
    const callback="https://owned.test/auth/callback?state="+"a".repeat(32),query=new URLSearchParams({public_token:"public-token-test-local",organization_id:"organization-test-local",login_redirect_url:callback,signup_redirect_url:callback});
    const redirect=await invoke("GET",`/v1/b2b/public/oauth/google/start?${query}`);assert.equal(redirect.status,302);
    const token=new URL(redirect.headers.location).searchParams.get("token");
    const oauth=await invoke("POST","/v1/b2b/oauth/authenticate",{oauth_token:token,session_duration_minutes:60});assert.equal(oauth.status,200);
    const session=await invoke("POST","/v1/b2b/sessions/authenticate",{session_jwt:oauth.value.session_jwt});
    assert.equal(session.status,200);assert.equal(session.value.member.member_id,member);assert.equal(session.value.member.organization_id,organization);assert.equal(session.value.member_session.member_id,member);assert.equal(session.value.member_session.organization_id,organization);
    sessions.push(session.value.member_session.member_session_id);
  }
  assert.equal(new Set(sessions).size,3);assert.equal(context.identityOAuthStarts,3);
});

// Run the actual export orchestration and cleanup against owned-process and
// browser boundaries. No child, socket, browser or container is started here.
async function exportShutdownFixture({ restartExit, finalExit, assertionFailure } = {}) {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseSecurityAgentExportMountedBrowser(");
  const end = source.indexOf("\nasync function exerciseAttackLabMountedBrowser", start);
  const cleanupStart = source.indexOf("async function cleanupOwnedResources() {");
  const cleanupEnd = source.indexOf("\nasync function generateHarnessGitHubAppPrivateKey", cleanupStart);
  const stopStart = source.indexOf("async function stopExportBrowserAPI(");
  const stopEnd = stopStart < 0 ? -1 : source.indexOf("\nasync function ", stopStart + 1);
  const cleanExit = { status: 0, signal: null, stdout: "PASS", stderr: "" };
  const files = new Map(), apiOwners = [], apiEnvironments = [];
  let removed = false;
  const scope = "organization/workspace/environment", origin = "https://owned.test:14443";
  const requests = Array.from({ length: 8 }, () => ({ method: "POST", path: "/api/v1/security-agent/runs", status: 200,
    expectedScope: scope, origin, csrfPresent: true, idempotencyHash: "a".repeat(64),
    receiptID: "pid_11111111-1111-4111-8111-111111111111", auditID: "pid_22222222-2222-4222-8222-222222222222" }));
  if (assertionFailure === "mutation") requests.pop();
  if (assertionFailure === "receipt") requests[0].receiptID = "missing";
  const context = {
    assert, path, os, Date, Buffer, createHash, process: { env: {} }, console: { log() {} }, AggregateError,
    currentComplianceStateRoot: undefined, currentComplianceClosing: false, currentComplianceProjectionController: undefined, currentComplianceProjectionLoop: undefined, currentComplianceServices: undefined, currentCompliancePostgres: undefined,
    root: "/owned", postgresBin: "/owned/bin", temporaryRoot: "/owned/zasp-production-e2e-fixture", productHostname: "owned.test",
    children: [], ownedCommands: new WeakMap(), mountedRuntimeProofs: [], exportBrowserAPILifetimes: [], exportBrowserAPIShutdowns: new WeakMap(), exportBrowserProfiles: [],
    exportBrowserTrace: requests, exportBrowserEvidenceDirectory: null, automaticDiscoveryEvidenceDirectory: null,
    exportBrowserRelease: { version: 58 }, exportBrowserScope: scope,
    observedSessionCookie: true, browserConsoleErrors: assertionFailure === "console" ? ["uncaught"] : [],
    proxyFailure: assertionFailure === "proxy" ? new Error("proxy failed") : undefined,
    exportBrowserIdentity, command: async () => ({ stdout: "" }), reservePort: async () => 15432,
    mkdtemp: async () => "/evidence", mkdir: async () => {}, readFile: async () => Buffer.from("fixture bytes"),
    writeFile: async (file, value) => { files.set(file, JSON.parse(value)); },
    auditBrowserEnvironment: env => env, combinedAPIEnvironment: () => ({ ZASP_SHUTDOWN_TIMEOUT: "5s" }),
    spawnOwnedCommand: (_binary, args, options) => {
      const isAPI = args[0].includes("BrowserAPIProcess");
      const result = isAPI ? (apiOwners.length === 0 ? restartExit : finalExit) ?? cleanExit : cleanExit;
      const owned = { child: {}, completed: Promise.resolve(result), stop: async () => {} };
      if (isAPI) { apiOwners.push(owned); apiEnvironments.push(options.env); }
      return owned;
    },
    waitForHTTP: async () => {}, startIdentityServer: async () => ({}), startPolicyHistoryServer: async () => ({}),
    startChild: () => ({}), startProxy: async () => ({}), startBrowser: async () => ({ child: {}, cdp: { close: async () => {} } }),
    navigateBrowser() {}, waitForBrowserText() {}, waitForBrowserScope() {}, selectBrowserOption() {}, clickBrowserText() {},
    clickBrowserAria() {}, fillBrowserLabel() {}, browserFetchJSON() {}, waitForBrowserAction() {},
    runSecurityAgentExportMountedBrowser: async ({ restart }) => { await restart(); return { downloads: 3 }; },
    stopChild: async () => {}, closeServer: async () => {}, stopPostgres: async () => {},
    precisionBrowserCheckpoint: undefined, runtimePipelineChild: undefined, runtimeGraphDependency: undefined,
    redTeamRuntimeProof: { close: async () => {} }, runtimePipelineDependencies: { close: async () => {} },
    secondBrowserTab: undefined, task4Workers: [], postgres: {}, auditExportProvider: undefined,
    rm: async () => { removed = true; },
  };
  const code = `browserConsoleErrors=JSON.parse(${JSON.stringify(JSON.stringify(context.browserConsoleErrors))});\n${stopStart < 0 ? "" : source.slice(stopStart, stopEnd)}\n${source.slice(start, end)}\n${source.slice(cleanupStart, cleanupEnd)}\n({run:exerciseSecurityAgentExportMountedBrowser,cleanup:cleanupOwnedResources})`;
  const flow = runInNewContext(code, context);
  let failure, cleanupFailure;
  try { await flow.run({ dsn: "owned", apiBinary: "/api", workerE2EBinary: "/worker", postgresPort: 15432, identityPort: 14441,
    policyHistoryPort: 14442, apiPort: 14440, healthPort: 14439, webPort: 14438, proxyPort: 14443, chromePort: 14444 }); }
  catch (error) { failure = error; }
  const beforeCleanup = files.get("/evidence/manifest.json");
  try { await flow.cleanup(); } catch (error) { cleanupFailure = error; }
  return { failure, cleanupFailure, manifest: beforeCleanup, cleanup: files.get("/evidence/cleanup.json"), removed, apiOwners, apiEnvironments, files };
}

test("export API leaves shutdown margin inside the owned five second grace", async () => {
  const result = await exportShutdownFixture();
  assert.equal(result.failure, undefined);
  assert.equal(result.apiEnvironments.length, 2);
  for (const environment of result.apiEnvironments) assert.equal(environment.ZASP_SHUTDOWN_TIMEOUT, "1s");
});

test("export API persists clean slow shutdown and forced kill before acceptance checks", { timeout: 15_000 }, async t => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function stopExportBrowserAPI("), end = source.indexOf("\nasync function ", start + 1);
  for (const [drainMs, status, signal, stopped] of [[1100, 0, null, true], [5100, null, "SIGKILL", false]]) {
    await t.test(`owned drain ${drainMs}ms`, async () => {
      const childCode = `process.on("SIGTERM",()=>setTimeout(()=>{process.stdout.write(JSON.stringify({event:"runtime_stopped",service:"agentsec-api"})+"\\n");process.exit(0)},${drainMs}));process.stdout.write("ready\\n");process.stderr.write("secret=DO-NOT-PERSIST postgres://private token=DO-NOT-PERSIST\\n");setInterval(()=>{},1000)`;
      const owned = spawnOwnedCommand(process.execPath, ["-e", childCode], { env: {} });
      const files = new Map();
      const stop = runInNewContext(`(${source.slice(start, end)})`, {
        assert, Date, Buffer, createHash, path, exportBrowserAPILifetimes: [owned], exportBrowserAPIShutdowns: new WeakMap(),
        exportBrowserEvidenceDirectory: "/evidence", writeFile: async (file, raw) => { files.set(file, JSON.parse(raw)); },
      });
      try {
        await once(owned.child.stdout, "data");
        if (signal) await assert.rejects(stop(owned), /export API/); else await stop(owned);
        const record = files.get("/evidence/api-lifetime-1.json");
        assert.ok(record, "API completion evidence missing after shutdown");
        assert.equal(record.status, status); assert.equal(record.signal, signal); assert.equal(record.lifecycleStopped, stopped);
        assert.ok(record.shutdownElapsedMs >= (signal ? 4900 : 1000));
        assert.match(record.stdout.sha256, /^[a-f0-9]{64}$/); assert.match(record.stderr.sha256, /^[a-f0-9]{64}$/);
        assert.ok(record.stdout.bytes > 0 && record.stderr.bytes > 0);
        assert.doesNotMatch(JSON.stringify(record), /DO-NOT-PERSIST|postgres:|secret=/);
        if (signal) await assert.rejects(stop(owned), /export API/); else await stop(owned);
        assert.equal(files.get("/evidence/api-lifetime-1.json"), record, "cleanup replaced original shutdown timing");
      } finally { await owned.stop(); await owned.completed; }
    });
  }
});

test("export API shutdown rejects nonzero and signaled restart and final lifetimes", async t => {
  for (const phase of ["restart", "final"]) {
    for (const exit of [{ status: 7, signal: null }, { status: null, signal: "SIGKILL" }, { status: 0, signal: "SIGTERM" }]) {
      await t.test(`${phase} status=${exit.status} signal=${exit.signal}`, async () => {
        const result = await exportShutdownFixture({ [`${phase}Exit`]: { ...exit, stdout: "", stderr: "" } });
        if (phase === "restart") {
          assert.ok(result.failure, "restart accepted an unsuccessful API lifetime");
          assert.equal(result.apiOwners.length, 1, "restart launched another API after unsuccessful shutdown");
        } else assert.equal(result.failure, undefined);
        assert.equal(result.manifest.completed, phase !== "restart");
        assert.equal(result.manifest.cleanup.status, "pending");
        assert.ok(result.cleanupFailure instanceof AggregateError, "cleanup discarded unsuccessful API completion");
        assert.ok(result.cleanupFailure.errors.some(error => /export API/.test(error.message)), "cleanup lost the API exit failure");
        const diagnostic = result.files.get(`/evidence/api-lifetime-${phase === "restart" ? 1 : 2}.json`);
        assert.equal(diagnostic.status, exit.status); assert.equal(diagnostic.signal, exit.signal);
        assert.equal(result.cleanup.joined, false);
        assert.equal(result.removed, false, "unsuccessful API cleanup removed owned root");
      });
    }
  }
});

test("export manifest completion waits for console proxy mutation and receipt acceptance", async t => {
  for (const assertionFailure of ["console", "proxy", "mutation", "receipt", undefined]) {
    await t.test(assertionFailure ?? "accepted with cleanup still pending", async () => {
      const result = await exportShutdownFixture({ assertionFailure });
      assert.equal(Boolean(result.failure), Boolean(assertionFailure));
      assert.equal(result.manifest.completed, !assertionFailure, "manifest claimed acceptance before final assertions");
      assert.equal(Boolean(result.manifest.failure), Boolean(assertionFailure));
      if (assertionFailure) assert.equal(result.manifest.failure.stage, {
        console: "browser-console", proxy: "proxy", mutation: "lifecycle-mutations", receipt: "lifecycle-receipts",
      }[assertionFailure]);
      assert.equal(result.manifest.cleanup?.status, "pending", "manifest claimed joins before cleanup");
      assert.equal(result.cleanupFailure, undefined);
      assert.equal(result.cleanup.joined, true);
      assert.equal(result.removed, true);
    });
  }
});

test("temporary policy child budget covers lease recovery and preserves failures", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function runTemporaryPolicyActionWorker(");
  const end = source.indexOf("\nasync function ", start + 1);
  assert.ok(start > 0 && end > start);
  for (const key of ["create_temporary_policy", "isolate_session"]) {
    for (const phase of ["apply", "cleanup", "reconcile"]) {
      const failure = new Error("child failed after recovery");
      for (const reject of [false, true]) {
        const run = runInNewContext(`(${source.slice(start, end)})`, {
          assert, platform: "/platform", process: { env: {} }, auditBrowserEnvironment: env => env,
          command: async (exe, args, options) => {
            assert.equal(exe, "/worker.test");
            assert.ok(args.includes("-test.run=^TestProductionCombinedE2ETemporaryPolicyActionWorker$"));
            assert.ok(options.timeout >= 110_000, `child timeout ${options.timeout} cannot cover 90s helper and shutdown`);
            assert.equal(options.env.ZASP_COMBINED_E2E_ACTION_RUN_ID, "exact-run");
            assert.equal(options.env.ZASP_COMBINED_E2E_ACTION_KEY, key);
            assert.equal(options.env.ZASP_COMBINED_E2E_ACTION_PHASE, phase);
            assert.equal(options.env.ZASP_COMBINED_E2E_AFTER_SEQUENCE, "3");
            assert.equal(options.env.ZASP_COMBINED_E2E_ACTION_SESSION_ID, "target");
            assert.equal(options.env.ZASP_COMBINED_E2E_ACTION_OTHER_SESSION_ID, "unrelated");
            if (reject) throw failure;
            return { stdout: phase === "reconcile" ? "connector revocation reconciled through the production action worker" : key === "isolate_session" ? `central policy deployment signed session isolation gateway policy ${phase} and verified exact target plus unrelated allowance through gateway authority` : `central policy deployment signed temporary gateway policy ${phase} and verified through gateway authority` };
          },
        });
        const execute = () => run("/worker.test", 1234, "key", phase, { key, runID: "exact-run", afterSequence: 3, sessionID: "target", otherSessionID: "unrelated" });
        if (reject) await assert.rejects(execute, error => error === failure);
        else await execute();
      }
    }
  }
});

test("broad release helper rejects migration or readback failure", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function prepareAutomaticLifecycleRelease(");
  const end = source.indexOf("\nfunction ", start + 1);
  assert.ok(start > 0 && end > start, "missing broad release preparation");
  for (const failAt of [null, "migration", "readback"]) {
    const calls = [], failure = new Error("release setup rejected");
    const prepare = runInNewContext(`(${source.slice(start, end)})`, { assert, path, postgresBin: "/pg", command: async (exe, args, options) => {
      calls.push({ exe, args: Array.from(args), options });
      if (failAt === (calls.length === 1 ? "migration" : "readback")) throw failure;
      return { stdout: "55" };
    } });
    const env = { principal: "registered" };
    if (failAt) await assert.rejects(prepare({ migrate: "/migrate", migrationEnvironment: env, dsn: "owned" }), error => error === failure);
    else await prepare({ migrate: "/migrate", migrationEnvironment: env, dsn: "owned" });
    assert.deepEqual(JSON.parse(JSON.stringify(calls[0])), { exe: "/migrate", args: ["up-to-55"], options: { env } });
    assert.equal(calls.length, failAt === "migration" ? 1 : 2);
  }
});

async function verifyAutomaticLifecycleOrchestration(source, mode = "broad", failureAt = null) {
  const marker = (text, after = 0) => {
    const index = source.indexOf(text, after);
    assert.ok(index >= after, `orchestration boundary missing: ${text}`);
    return index;
  };
  const begin = marker("  if (automaticDiscoveryMode) {", marker("await seedPostgres(dsn)"));
  const ready = marker('  console.log("combined E2E: Go product and internal listeners ready");', begin);
  const throughReady = source.indexOf("\n", ready);
  const planner = marker("\tawait exerciseSecurityAgentAutomaticLifecycle(browser.cdp,", throughReady);
  const plannerEnd = source.indexOf("\n", planner);
  const helper = marker("async function prepareAutomaticLifecycleRelease(");
  const helperEnd = marker("\nfunction ", helper);
  // Execute the real mode branches, historical proof verification, compiled
  // release helper and API readiness. Elide the unrelated UI between readiness
  // and the real automatic-lifecycle call; its planner boundary is stubbed.
  const program = `(async()=>{${source.slice(helper, helperEnd)}\n${source.slice(begin, throughReady)}\n${source.slice(planner, plannerEnd)}\n}}})()`;
  const events = [], failure = new Error(`fixture ${failureAt} rejected`);
  let releaseRuntime, runtimeStarted;
  const started = new Promise(resolve => { runtimeStarted = resolve; });
  const historical = new Promise(resolve => { releaseRuntime = () => resolve({ stdout: [
    "runtime pipeline proof passed:", "semantic observation pipeline proven:",
    "runtime observed lineage preservation proven:", "runtime candidate recovery proven:",
    "runtime mixed session input proven:", "runtime v2 reader v1 backlog proven:",
    "runtime correlation routing proven:",
    "runtime session persistence proven: worker-written event, unknown attribution retained, predecessor receipt digest, byte-stable replay",
    "runtime session summaries proven: completion-triggered unknown collection, byte-stable replay",
    "runtime session search index proven: committed PG receipt, exact S3 archive, real OpenSearch, immutable replay, structured process filter, pagination and scope denial",
    "real OpenSearch selector matrix passed: all ten structured filter kinds, same-event conjunction, millisecond bounds, cross-batch deduplication, two-page completeness and foreign-tenant positive/negative controls; synthetic component fixtures only",
    "production session indexing outbox proven: completion transaction, registered index worker, exact receipt/archive read, live lease renewal, indexed checkpoint and idle replay without duplicate claims",
    "--- PASS: TestProductionCombinedE2ERuntimeQueueIndex",
  ].join("\n") }); });
  const boundary = name => { events.push(name); if (failureAt === name) throw failure; };
  const context = {
    assert, path, Error, console: { log() {} }, process: { env: mode === "runtime-only" ? { ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY: "true" } : {} },
    automaticDiscoveryMode: false, securityAgentExportMode: false, attackLabMountedMode: false, complianceBrowserMode: false, existingTestMountedMode: mode === "existing-test", securityAgentSimulationMode: ["simulation", "run-context"].includes(mode), auditExportBrowserMode: mode === "audit-export", precisionBrowserMode: false,
    dsn: "owned", apiDSN: "owned-api", apiBinary: "api", workerE2EBinary: "worker", gatewayE2EBinary: "gateway", migrate: "migrate", migrationEnvironment: { owner: "registered" },
    postgresBin: "/pg", postgresPort: 1, identityPort: 2, policyHistoryPort: 3, apiPort: 4, healthPort: 5, webPort: 6, proxyPort: 7, chromePort: 8, productHostname: "owned.test", actionPrivateKey: "fixture", browser: { cdp: {} },
    exerciseExistingTestMountedBrowser: async () => boundary("existing-test"),
    exerciseSecurityAgentSimulationBrowser: async () => boundary(mode),
    exerciseAuditExportNativeBrowser: async () => boundary("audit-export"),
    createGraphFixtureDependency: () => ({ start: async () => ({ uri: "owned", password: "fixture", certificate: "fixture" }) }),
    runtimePipelineDependencies: { prepare: async () => {}, start: async name => `owned-${name}` },
    auditBrowserEnvironment: () => ({}), precisionBrowserCheckpoint: undefined,
    command: async (executable, args) => {
      if (executable === "worker") {
        assert.ok(["broad", "runtime-only"].includes(mode), "selected mode started historical runtime");
        assert.equal(args[1], "^TestProductionCombinedE2ERuntimeQueueIndex$");
        boundary("historical-start"); runtimeStarted();
        const result = await historical;
        boundary("historical-joined"); return result;
      }
      if (executable === "migrate") { assert.deepEqual(Array.from(args), ["up-to-55"]); boundary("migration"); return {}; }
      assert.equal(executable, "/pg/psql");
      assert.equal(args.at(-1), "SELECT max(version) FROM zasp_schema_versions");
      boundary("readback"); return { stdout: failureAt === "non55" ? "54" : "55" };
    },
    startIdentityServer: async () => boundary("identity"), startPolicyHistoryServer: async () => boundary("policy"), combinedAPIEnvironment: () => ({}),
    startChild: executable => { assert.equal(executable, "api"); boundary("api"); return { exitCode: 1, signalCode: null, output: () => "fixture" }; },
    waitForHTTP: async (url, status) => { assert.equal(url, "http://127.0.0.1:5/readyz"); assert.equal(status, 200); boundary("api-ready"); },
    exerciseSecurityAgentAutomaticLifecycle: async () => boundary("planner"),
  };
  const execution = runInNewContext(program, context);
  // Attach failure handling before releasing the asynchronous historical proof.
  const completed = execution.then(() => null, error => error);
  if (["broad", "runtime-only"].includes(mode)) {
    try {
      await Promise.race([started, completed.then(error => { throw error ?? new Error("historical proof was never started"); })]);
      assert.deepEqual(events, ["historical-start"], "downstream startup raced the historical proof join");
    } finally { releaseRuntime(); }
  }
  const error = await completed;
  const success = ["historical-start", "historical-joined", "migration", "readback", "identity", "policy", "api", "api-ready", "planner"];
  if (failureAt) {
    assert.ok(error, `${failureAt} did not prevent downstream startup`);
    if (failureAt === "non55") assert.match(error.message, /requires registered compiled55/);
    else assert.match(error.message, new RegExp(`fixture ${failureAt} rejected`));
    const last = failureAt === "non55" ? "readback" : failureAt;
    assert.deepEqual(events, success.slice(0, success.indexOf(last) + 1));
  } else {
    assert.equal(error, null);
    assert.deepEqual(events, mode === "broad" ? success : mode === "runtime-only" ? ["historical-start", "historical-joined"] : [mode]);
  }
}

test("broad lifecycle orchestration gates migration and startup on the joined historical proof", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const mode of ["broad", "runtime-only", "existing-test", "simulation", "run-context", "audit-export"]) await verifyAutomaticLifecycleOrchestration(source, mode);
  for (const failure of ["historical-joined", "migration", "readback", "non55", "api-ready"]) await verifyAutomaticLifecycleOrchestration(source, "broad", failure);
});

test("broad lifecycle orchestration detects missing joins and bypassed mode or release guards", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const join = "verifyRuntimePipelineResult(await runRuntimePipeline());";
  const upgrade = "await prepareAutomaticLifecycleRelease({ migrate, migrationEnvironment, dsn });";
  for (const [mutant, mode, expected] of [
    [source.replace(join, ""), "broad", /historical proof was never started/],
    [source.replace(upgrade, "").replace(join, `${upgrade}\n${join}`), "broad", /downstream startup raced/],
    [source.replace('if (process.env.ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY !== "true")', "if (true)"), "runtime-only", /Expected values to be strictly deep-equal/],
    [source.replace('    await exerciseExistingTestMountedBrowser({ dsn,', `    ${upgrade}\n    await exerciseExistingTestMountedBrowser({ dsn,`), "existing-test", /Expected values to be strictly deep-equal/],
  ]) {
    assert.notEqual(mutant, source, "mutation did not alter its intended boundary");
    await assert.rejects(verifyAutomaticLifecycleOrchestration(mutant, mode), expected);
  }
  const uncheckedRelease = source.replace('  assert.equal(release.stdout.trim(), "55", "broad automatic lifecycle requires registered compiled55");', "");
  assert.notEqual(uncheckedRelease, source);
  await assert.rejects(verifyAutomaticLifecycleOrchestration(uncheckedRelease, "broad", "non55"), /non55 did not prevent downstream startup/);
});

test("automatic fixture selects concurrency from exact scoped trigger inventory", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("function automaticLifecycleConcurrency(");
  const end = source.indexOf("\nasync function ", start);
  assert.ok(start > 0 && end > start, "missing bounded trigger inventory");
  const select = runInNewContext(`(${source.slice(start, end)})`, { assert });
  const expected = { finding: ["finding"], temporary: ["temporary"], connector: ["connector"], attackPath: ["path"], session: ["session"], foreign: ["foreign"] };
  assert.equal(select(expected, expected), 5);
  for (const inventory of [{ ...expected, finding: [] }, { ...expected, session: ["session", "extra"] }, { ...expected, attackPath: ["path", "extra-verified"] }, { ...expected, attackPath: [] }, { ...expected, foreign: ["other"] }]) assert.throws(() => select(inventory, expected));
});

test("pagination seed retains102 paths but grants verified trigger state only to canonical path1", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("function productionAttackPathFixtures(");
  assert.ok(start > 0, "missing explicit pagination/trigger fixture partition");
  const end = source.indexOf("\nasync function ", start);
  const build = runInNewContext(`(${source.slice(start, end)})`);
  const rows = Array.from(build());
  assert.equal(rows.length, 102);
  assert.deepEqual(rows.map(row => row.ordinal), Array.from({ length: 102 }, (_, i) => i + 1));
  assert.equal(rows[0].state, "verified");
  assert.equal(rows.filter(row => row.state === "observed").length, 101);
  assert.equal(rows.filter(row => row.state === "verified").length, 1);
  const seed = source.indexOf("async function seedPostgres(");
  const insert = source.indexOf("INSERT INTO zasp_risk_attack_paths", seed);
  const next = source.indexOf("INSERT INTO zasp_risk_attack_path_nodes", insert);
  const sql = runInNewContext(`\`${source.slice(insert, next)}\``, { productionAttackPathFixtures: build });
  const serialized = sql.match(/jsonb_to_recordset\('([^']+)'::jsonb\)/);
  assert.ok(serialized, "initial path insert did not consume the partitioned fixture");
  assert.deepEqual(JSON.parse(serialized[1]), rows.map(row => ({ ordinal: row.ordinal, state: row.state })));
  assert.match(sql, /fixture\.state/);
});

test("scoped path readback rejects lost pagination evidence, duplicate IDs and any extra verified trigger", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function verifyProductionAttackPathFixtures(");
  assert.ok(start > 0, "missing scoped fixture population readback");
  const end = source.indexOf("\nasync function ", start + 1);
  const fixture = Array.from({ length: 102 }, (_, i) => {
    const ordinal = i + 1, suffix = `-0000-4000-8000-${String(ordinal).padStart(12, "0")}`;
    const entry = `pid_${50000000 + ordinal}${suffix}`, evidence = `pid_${70000000 + ordinal}${suffix}`;
    return { id: `pid_${40000000 + ordinal}${suffix}`, state: i === 0 ? "verified" : "observed", version: 1, visible: true, nodes: [entry, `pid_${60000000 + ordinal}${suffix}`], evidence: [evidence], break_options: [[1, entry, evidence, "remove_node"]] };
  });
  for (const corruption of [null, "missing", "duplicate", "all-verified", "canonical-observed", "invisible", "node", "evidence", "break-option", "version"]) {
    const rows = structuredClone(fixture);
    if (corruption === "missing") rows.pop();
    if (corruption === "duplicate") rows[101] = rows[100];
    if (corruption === "all-verified") for (const row of rows) row.state = "verified";
    if (corruption === "canonical-observed") rows[0].state = "observed";
    if (corruption === "invisible") rows[101].visible = false;
    if (corruption === "node") rows[101].nodes.pop();
    if (corruption === "evidence") rows[101].evidence = [];
    if (corruption === "break-option") rows[101].break_options[0][2] = "wrong-evidence";
    if (corruption === "version") rows[0].version = 2;
    const verify = runInNewContext(`(${source.slice(start, end)})`, { assert, path, postgresBin: "/pg", command: async (exe, args) => {
      assert.equal(exe, "/pg/psql"); assert.equal(args[0], "owned");
      const sql = args.at(-1);
      assert.match(sql, /zasp_risk_attack_path_valid\(p\)/);
      assert.match(sql, /\(p\.organization_id,p\.workspace_id,p\.environment_id\)=\('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003'\)/);
      assert.doesNotMatch(sql, /UPDATE|DELETE|LIMIT 1\b|state='verified'/);
      return { stdout: JSON.stringify(rows) };
    } });
    if (corruption) await assert.rejects(verify("owned"), undefined, corruption);
    else await verify("owned");
  }
  const seed = source.slice(source.indexOf("async function seedPostgres("), source.indexOf("async function exercisePublicDiscoveryLifecycle("));
  assert.ok(seed.indexOf("await verifyProductionAttackPathFixtures(dsn);") > seed.indexOf("input: sql"));
  const lifecycle = source.slice(source.indexOf("async function exerciseSecurityAgentAutomaticLifecycle("), source.indexOf("async function exerciseHomeDailyOperations("));
  assert.ok(lifecycle.indexOf("await verifyProductionAttackPathFixtures(dsn);") >= 0);
  assert.ok(lifecycle.indexOf("await verifyProductionAttackPathFixtures(dsn);") < lifecycle.indexOf("automaticLifecycleConcurrency(await readInventory()"));
});

async function automaticReceiptProtocol({ autonomy = "supervised", foreign = false, corrupt } = {}) {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const functions = ["createAutomaticLifecycleDefinition", "automaticLifecycleRequest"].map(name => {
    const start = source.indexOf(`async function ${name}(`), end = source.indexOf("\nasync function ", start + 1);
    assert.ok(start > 0 && end > start);
    return source.slice(start, end);
  }).join("\n");
  const id = "pid_78000010-0000-4000-8000-000000000010";
  const receiptID = "pid_11000001-0000-4000-8000-000000000001", auditID = "pid_11000002-0000-4000-8000-000000000002";
  const scope = `${foreign ? "foreign" : "primary"}/workspace/environment`;
  const definition = { name: "Fixture", trigger_kind: "finding", trigger_source: "credential", environment_ids: ["environment"], autonomy: "supervised", max_steps: 1, max_duration_seconds: 900, temporary_policy_seconds: 600, ai_token_budget: 1000, max_ai_cost_nano_credits: 10000, concurrency_limit: foreign ? 1 : 5, allowed_actions: ["update_finding_response"], verification_kind: "finding_state", definition_version: 1, enabled: false };
  const result = { ...structuredClone(definition), id };
  const receipt = { id: receiptID, operation: "createSecurityAgent", idempotency_key: "pending", intent: { resource_id: "", expected_version: 0, body: structuredClone(definition) }, result: structuredClone(result), resource_kind: "security_agent", resource_id: id, resource_version: 1, audit_id: auditID, correlation_id: "pid_11000003-0000-4000-8000-000000000003", created_at: "2026-09-17T00:00:00Z", expires_at: "2026-09-24T00:00:00Z" };
  const unrelated = { ...structuredClone(receipt), id: "pid_12000001-0000-4000-8000-000000000001", resource_id: "pid_12000002-0000-4000-8000-000000000002" };
  unrelated.result.id = unrelated.resource_id;
  const foreignReceiptID = "pid_13000001-0000-4000-8000-000000000001";
  const calls = [], durable = [];
  let acknowledged = false, sequence = 0;
  const requestHTTPSJSON = async (url, options, body) => {
    const target = new URL(url).pathname, input = body === undefined ? undefined : JSON.parse(body);
    assert.equal(options.headers.cookie, `__Host-zasp_session=${foreign ? "foreign" : "primary"}-cookie`);
    assert.equal(options.headers["X-Zasp-Expected-Scope"], scope);
    if (target.endsWith("/bootstrap")) return { status: 200, body: { organization_id: scope.split("/")[0], workspace_id: "workspace", environment_id: "environment", csrf_token: "csrf-fixture-at-least-16" } };
    if (options.method !== "GET") assert.equal(options.headers["X-CSRF-Token"], "csrf-fixture-at-least-16");
    let stage, response;
    if (target === "/api/v1/security-agents") {
      stage = "create";
      assert.equal(options.method, "POST"); assert.deepEqual(input, definition);
      receipt.idempotency_key = options.headers["Idempotency-Key"];
      response = { status: 201, headers: { etag: '"1"', "x-audit-id": auditID, "x-mutation-receipt-id": receiptID }, body: structuredClone(result) };
    } else if (target === "/api/v1/workflow-mutation-receipts") {
      stage = acknowledged ? "listed-after" : "listed-before";
      assert.equal(options.method, "GET"); assert.equal(new URL(url).search, "?limit=50");
      response = { status: 200, headers: {}, body: { items: structuredClone(acknowledged ? [unrelated] : [unrelated, receipt]) } };
    } else if (target === `/api/v1/security-agents/${id}`) {
      stage = "readback"; assert.equal(options.method, "GET");
      response = { status: 200, headers: { etag: '"1"' }, body: structuredClone(result) };
    } else if (target.endsWith("/acknowledge")) {
      stage = "acknowledge";
      assert.equal(target, `/api/v1/workflow-mutation-receipts/${receiptID}/acknowledge`, "acknowledged an unowned receipt");
      assert.equal(options.method, "POST"); assert.deepEqual(input, {});
      acknowledged = true;
      response = { status: 204, headers: {}, body: null };
    } else {
      stage = input.activation;
      assert.equal(target, `/api/v1/security-agents/${id}/activation`);
      const version = { validated: 1, supervised: 2, autonomous: 3 }[stage];
      assert.equal(options.headers["If-Match"], `"${version}"`);
      response = { status: 200, headers: { etag: `"${version + 1}"`, "x-audit-id": auditID, "x-mutation-receipt-id": receiptID }, body: { id, activation: stage, enabled: stage !== "validated", version: version + 1 } };
    }
    calls.push(stage);
    corrupt?.(stage, response, { receipt, foreignReceiptID });
    return response;
  };
  const { create, authenticate } = new Function("assert", "randomBytes", "requestHTTPSJSON", `${functions}\nreturn {create:createAutomaticLifecycleDefinition,authenticate:automaticLifecycleRequest};`)(assert, () => ({ toString: () => String(++sequence).padStart(32, "0") }), requestHTTPSJSON);
  const request = await authenticate("https://owned.test", `${foreign ? "foreign" : "primary"}-cookie`, scope, durable);
  let error;
  try { assert.equal(await create(request, definition, autonomy), id); } catch (failure) { error = failure; }
  return { calls, error, durable, scope };
}

test("automatic fixture reconciles only its owned create receipt at v1 before public activation", async () => {
  for (const foreign of [false, true]) for (const autonomy of ["supervised", "autonomous"]) {
    const proof = await automaticReceiptProtocol({ foreign, autonomy });
    assert.equal(proof.error, undefined);
    assert.deepEqual(proof.calls, ["create", "listed-before", "readback", "acknowledge", "listed-after", "validated", "supervised", ...(autonomy === "autonomous" ? ["autonomous"] : [])]);
    assert.equal(proof.durable.length, autonomy === "autonomous" ? 4 : 3, "ACK is not a new mutation receipt; retain all real mutations");
    for (const row of proof.durable) assert.equal(row.slice(2).join("/"), proof.scope);
  }
});

test("automatic fixture rejects mismatched receipts and readbacks without ACK or activation", async () => {
  const cases = [
    ["missing", (r) => { r.body.items.pop(); }],
    ["duplicate", (r) => { r.body.items.push(structuredClone(r.body.items[1])); }],
    ["foreign ID", (r, c) => { r.body.items[1].id = c.foreignReceiptID; }],
    ["operation", (r) => { r.body.items[1].operation = "updateSecurityAgent"; }],
    ["resource kind", (r) => { r.body.items[1].resource_kind = "policy"; }],
    ["resource ID", (r) => { r.body.items[1].resource_id = r.body.items[0].resource_id; }],
    ["version", (r) => { r.body.items[1].resource_version = 2; }],
    ["audit", (r) => { r.body.items[1].audit_id = r.body.items[0].id; }],
    ["intent", (r) => { r.body.items[1].intent.body.max_ai_cost_nano_credits = 1; }],
    ["foreign intent", (r) => { r.body.items[1].intent.body.environment_ids = ["foreign"]; }],
    ["expected version", (r) => { r.body.items[1].intent.expected_version = 1; }],
    ["intent resource", (r) => { r.body.items[1].intent.resource_id = r.body.items[1].resource_id; }],
    ["result", (r) => { r.body.items[1].result.enabled = true; }],
  ];
  for (const [name, mutate] of cases) {
    const proof = await automaticReceiptProtocol({ corrupt: (stage, response, context) => { if (stage === "listed-before") mutate(response, context); } });
    assert.ok(proof.error, `${name} was accepted`);
    assert.deepEqual(proof.calls, ["create", "listed-before"], name);
  }
  for (const stage of ["create", "listed-before", "readback"]) {
    const mutations = stage === "listed-before" ? [r => { r.status = 503; }] : [
      r => { r.status = 503; }, r => { r.headers.etag = '"2"'; },
      r => { r.body.id = "foreign"; }, r => { r.body.environment_ids = ["foreign"]; },
      r => { r.body.enabled = true; }, r => { r.body.autonomy = "autonomous"; },
      r => { r.body.max_ai_cost_nano_credits = 1; }, r => { r.body.concurrency_limit = 10; },
    ];
    for (const mutate of mutations) {
      const proof = await automaticReceiptProtocol({ corrupt: (at, response) => { if (at === stage) mutate(response); } });
      assert.ok(proof.error, `${stage} corruption was accepted`);
      assert.ok(!proof.calls.includes("acknowledge") && !proof.calls.includes("validated"));
    }
  }
});

test("automatic fixture rejects failed ACK or altered pending receipts before activation", async () => {
  for (const status of [200, 202, 400, 403, 404, 503]) {
    const proof = await automaticReceiptProtocol({ corrupt: (stage, response) => { if (stage === "acknowledge") response.status = status; } });
    assert.ok(proof.error, `ACK ${status} was accepted`);
    assert.deepEqual(proof.calls, ["create", "listed-before", "readback", "acknowledge"]);
  }
  for (const problem of ["owned retained", "unrelated removed", "unrelated changed", "list failed"]) {
    const proof = await automaticReceiptProtocol({ corrupt: (stage, response, { receipt }) => {
      if (stage !== "listed-after") return;
      if (problem === "owned retained") response.body.items.push(structuredClone(receipt));
      if (problem === "unrelated removed") response.body.items = [];
      if (problem === "unrelated changed") response.body.items[0].resource_version++;
      if (problem === "list failed") response.status = 503;
    } });
    assert.ok(proof.error, problem);
    assert.deepEqual(proof.calls, ["create", "listed-before", "readback", "acknowledge", "listed-after"]);
  }
});

test("automatic fixture control setup preserves global authority and uses each tenant CAS version", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function configureAutomaticLifecycleControls(");
  const end = source.indexOf("\nasync function ", start + 1);
  assert.ok(start > 0 && end > start, "missing public control setup");
  const configure = runInNewContext(`(${source.slice(start, end)})`, { assert });
  for (const globalEnabled of [true, false]) {
    const controls = { global: { enabled: globalEnabled, version: 9 }, environment: { target: "environment", action_key: "*", enabled: false, version: 0 }, actions: [{ target: "action", action_key: "update_finding_response", enabled: false, version: 3 }] };
    const writes = [];
    const request = async (_target, method, body, version) => {
      if (!method || method === "GET") return { status: 200, body: structuredClone(controls) };
      writes.push({ body, version });
      const row = body.target === "environment" ? controls.environment : controls.actions[0];
      Object.assign(row, body, { version: version + 1 });
      return { status: 200, headers: { etag: `"${row.version}"` }, body: { ...row } };
    };
    if (!globalEnabled) { await assert.rejects(configure(request, ["update_finding_response"])); assert.equal(writes.length, 0); }
    else { await configure(request, ["update_finding_response"]); assert.deepEqual(writes.map(item => [item.body.target, item.version]), [["environment", 0], ["action", 3]]); }
  }
});

test("automatic fixture authenticates exact scope and sends fresh CAS browser authority", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function automaticLifecycleRequest(");
  const end = source.indexOf("\nasync function ", start + 1);
  const calls = [];
  const id = "pid_78000010-0000-4000-8000-000000000010";
  let sequence = 0;
  const request = runInNewContext(`(${source.slice(start, end)})`, { assert, randomBytes: () => ({ toString: () => String(++sequence).padStart(32, "0") }), requestHTTPSJSON: async (url, options, body) => {
    calls.push({ url, options, body });
    if (url.endsWith("/bootstrap")) return { status: 200, body: { organization_id: "org", workspace_id: "workspace", environment_id: "environment", csrf_token: "csrf-fixture-at-least-16" } };
    return { status: 200, headers: { "x-audit-id": id, "x-mutation-receipt-id": id }, body: {} };
  } });
  const send = await request("https://owned.test", "owned-cookie", "org/workspace/environment");
  await send("/api/v1/security-agent-execution-controls", "PUT", { target: "environment", enabled: true }, 0);
  await send("/api/v1/security-agent-execution-controls", "PUT", { target: "action", enabled: true }, 3);
  await send("/api/v1/security-agent-runs/fixture");
  assert.equal(calls[1].options.headers["If-Match"], '"0"');
  assert.equal(calls[2].options.headers["If-Match"], '"3"');
  assert.notEqual(calls[1].options.headers["Idempotency-Key"], calls[2].options.headers["Idempotency-Key"]);
  assert.equal(calls[1].options.headers["X-Zasp-Fresh-Auth"], "confirmed");
  assert.equal(calls[1].options.headers["X-CSRF-Token"], "csrf-fixture-at-least-16");
  assert.equal(calls[3].options.headers["Idempotency-Key"], undefined);
  assert.equal(calls[3].options.headers["X-Zasp-Budget-Details"], "v1");
  for (const { options } of calls) {
    assert.equal(options.headers.cookie, "__Host-zasp_session=owned-cookie");
    assert.equal(options.headers["X-Zasp-Expected-Scope"], "org/workspace/environment");
    assert.equal(options.headers.authorization, undefined);
  }
  await assert.rejects(request("https://owned.test", "owned-cookie", "foreign/workspace/environment"));
});

test("automatic fixture permits headerless204 only for the exact receipt ACK protocol", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function automaticLifecycleRequest("), end = source.indexOf("\nasync function ", start + 1);
  const id = "pid_11000001-0000-4000-8000-000000000001";
  for (const [target, method, body, status, accepted] of [
    [`/api/v1/workflow-mutation-receipts/${id}/acknowledge`, "POST", {}, 204, true],
    [`/api/v1/workflow-mutation-receipts/${id}/acknowledge`, "POST", {}, 200, false],
    [`/api/v1/workflow-mutation-receipts/${id}/acknowledge`, "POST", { all: true }, 204, false],
    [`/api/v1/workflow-mutation-receipts/${id}/acknowledge`, "DELETE", {}, 204, false],
    ["/api/v1/workflow-mutation-receipts/all/acknowledge", "POST", {}, 204, false],
    [`/api/v1/workflow-mutation-receipts/${id}/acknowledge?all=true`, "POST", {}, 204, false],
    ["/api/v1/security-agents", "POST", {}, 201, false],
    ["/api/v1/security-agent-execution-controls", "PUT", {}, 204, false],
    [`/api/v1/security-agents/${id}/activation`, "POST", {}, 200, false],
  ]) {
    const receipts = [];
    const authenticate = new Function("assert", "randomBytes", "requestHTTPSJSON", `return (${source.slice(start, end)});`)(assert, () => ({ toString: () => "0123456789abcdef0123456789abcdef" }), async url => url.endsWith("/bootstrap") ? { status: 200, body: { organization_id: "org", workspace_id: "ws", environment_id: "env", csrf_token: "csrf-at-least-16-bytes" } } : { status, headers: {}, body: null });
    const request = await authenticate("https://owned.test", "cookie", "org/ws/env", receipts);
    if (accepted) assert.equal((await request(target, method, body)).status, 204);
    else await assert.rejects(request(target, method, body), undefined, `${method} ${target} ${status}`);
    assert.deepEqual(receipts, []);
  }
});

test("automatic fixture preserves every scenario and never seeds execution or resets admitted budgets", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const lifecycle = source.slice(source.indexOf("async function exerciseSecurityAgentAutomaticLifecycle("), source.indexOf("async function exerciseHomeDailyOperations("));
  assert.doesNotMatch(lifecycle, /(?:INSERT INTO|UPDATE) zasp_security_agent_(?:definitions|kill_switches|run_budgets|provider_reservations|plans|approvals|steps)\b/);
  for (const input of ['"AI cost budget (nano OpenRouter credits)", "10000"', '"Concurrency", String(concurrency)', '"Runtime seconds", "900"']) assert.ok(lifecycle.includes(input));
  const ordered = ["automaticLifecycleConcurrency(await readInventory()", "configureAutomaticLifecycleControls(primaryRequest", '"Create Security Agent"', '"Validate definition"', '"Enable supervised execution"', "configureAutomaticLifecycleControls(foreignRequest", "Foreign autonomous response", "Temporary containment response", "Verified attack path containment", "Compromised runtime session", "Compromised connector response", "let worker = startSecurityAgentE2EWorker", "worker did not prepare supervised authority", "attack-path scheduler duplicated", "exerciseHomeDailyOperations", "multi-tenant automatic response did not preserve", "non-admin browser could approve", "approved connector revocation did not reach", "expired fresh authentication exposed", "containment approval did not use exactly one", "session isolation was not exact", "session isolation cleanup did not restore", "connector revocation did not finish", "blocked capability evidence survived", "const history", "Planner unavailable response", "needs_human|budget_usage_unknown", "budget_stop_reason", "planner outage changed"];
  let position = -1;
  for (const marker of ordered) { const next = lifecycle.indexOf(marker); assert.ok(next > position, `missing or reordered scenario: ${marker}`); position = next; }
  assert.match(lifecycle, /immutable admitted budget snapshots changed/);
});

test("Security Agent simulation mode rejects invalid and conflicting flags before allocating resources", () => {
  const selected = "ZASP_COMBINED_E2E_SECURITY_AGENT_SIMULATION_ONLY";
  for (const environment of [
    ...["", "false", "TRUE"].map(value => ({ [selected]: value })),
    ...["AUDIT_BROWSE", "RUNTIME_PIPELINE_ONLY", "RUNTIME_SANDBOX_SEARCH", "RUNTIME_PRECISION", "RUNTIME_PRECISION_BROWSER", "RED_TEAM_RUNTIME"].map(key => ({ [selected]: "true", [`ZASP_COMBINED_E2E_${key}`]: "true" })),
    { [selected]: "true", ZASP_RECONCILIATION_API_LOAD_DIAGNOSTIC: "1" },
  ]) {
    const result = spawnSync(process.execPath, [new URL("./production-combined-e2e.mjs", import.meta.url).pathname], {
      env: { PATH: "", ...environment }, encoding: "utf8", timeout: 5000,
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Security Agent simulation mode/);
    assert.doesNotMatch(result.stderr, /pg_config|ENOENT/);
    assert.equal(result.stdout, "");
  }
});

test("Security Agent simulation selection bypasses broad dependencies and propagates failure", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("  if (automaticDiscoveryMode) {", source.indexOf("await seedPostgres(dsn)"));
  assert.ok(start > 0, "missing post-seed acceptance selection");
  const end = source.indexOf('  console.log("combined E2E: owned runtime dependencies ready");', start);
  assert.ok(end > start);
  // Keep all real branches through broad dependency startup; no provider is started.
  const selected = `(async()=>{${source.slice(start,end)} }})()`;
  const configuration = { dsn: "owned", apiDSN: "owned-api", apiBinary: "owned-bin", postgresPort: 1, identityPort: 2, policyHistoryPort: 3, apiPort: 4, healthPort: 5, webPort: 6, proxyPort: 7, chromePort: 8 };
  for (const [mode, expected] of [
    ["automaticDiscoveryMode", ["automatic discovery"]],
    ["securityAgentExportMode", ["agent export"]],
    ["attackLabMountedMode", ["attack lab"]],
    ["complianceBrowserMode", ["compliance"]],
    ["existingTestMountedMode", ["mounted"]],
    ["securityAgentSimulationMode", ["simulation"]],
    ["auditExportBrowserMode", ["audit export"]],
    ["normal", ["graph owner", "prepare", "aws", "search", "graph start"]],
  ]) {
    for (const failureAt of [null, ...expected.filter(name => name !== "graph owner")]) {
      const calls = [], failure = new Error(`${mode}: ${failureAt} failed`);
      const call = async name => { calls.push(name); if (name === failureAt) throw failure; };
      const proof = (name, extra = {}) => async received => {
        assert.deepEqual(JSON.parse(JSON.stringify(received)), { ...configuration, ...extra });
        await call(name);
      };
      const context = {
        ...configuration, automaticDiscoveryMode: false, securityAgentExportMode: false, attackLabMountedMode: false, complianceBrowserMode: false, existingTestMountedMode: false, securityAgentSimulationMode: false, auditExportBrowserMode: false, [mode]: true,
        workerBinary: "owned-worker-production", workerE2EBinary: "owned-worker", migrate: "owned-migrate", migrationEnvironment: { owner: "owned" },
        exerciseAutomaticDiscoveryBrowser: proof("automatic discovery", {workerBinary:"owned-worker-production",workerE2EBinary:"owned-worker"}),
        exerciseExistingTestMountedBrowser: proof("mounted", { workerE2EBinary: "owned-worker" }),
        exerciseSecurityAgentExportMountedBrowser: proof("agent export", { workerE2EBinary: "owned-worker" }),
        exerciseAttackLabMountedBrowser: proof("attack lab", { workerE2EBinary: "owned-worker", migrate: "owned-migrate", migrationEnvironment: { owner: "owned" } }),
        exerciseComplianceBrowser: proof("compliance", { workerE2EBinary: "owned-worker", migrate: "owned-migrate", migrationEnvironment: { owner: "owned" } }),
        exerciseSecurityAgentSimulationBrowser: proof("simulation"),
        exerciseAuditExportNativeBrowser: proof("audit export", { migrate: "owned-migrate", migrationEnvironment: { owner: "owned" } }),
        createGraphFixtureDependency: () => { calls.push("graph owner"); return { start: () => call("graph start") }; },
        runtimePipelineDependencies: { prepare: () => call("prepare"), start: call },
      };
      if (failureAt) await assert.rejects(runInNewContext(selected, context), error => error === failure);
      else await runInNewContext(selected, context);
      assert.deepEqual(calls, failureAt === "prepare" ? ["graph owner", "prepare"] : expected);
    }
  }
});

test("selected lost-create proof waits for enabled retry after the real response settles", async () => {
  const source=await readFile(new URL("./production-combined-e2e.mjs",import.meta.url),"utf8");
  const start=source.indexOf('  await clickBrowserText(cdp,"Create export");');
  const end=source.indexOf('  assert.equal(await sql("SELECT count(*) FROM zasp_audit_export_jobs")',start);
  assert.ok(start>0&&end>start);
  const exercise=async code=>{
    const button={textContent:"Retry create export",disabled:true},requests=[];
    let settled=false;
    const context={assert,cdp:{},auditExportCreateRequests:requests,clickBrowserText:async()=>{},waitForBrowserText:async()=>{}};
    context.waitForBrowserAction=async(_cdp,expression)=>{
      const document={querySelectorAll:()=>[button]};
      assert.equal(runInNewContext(expression,{document}),false,"busy retained intent is not a completed POST");
      requests.push({status:201});button.disabled=false;settled=true;
      assert.equal(runInNewContext(expression,{document}),true);
    };
    await runInNewContext(`(async()=>{${code}})()`,context);
    assert.equal(settled,true);
  };
  const checkpoint=source.slice(start,end);
  await exercise(checkpoint);
  await assert.rejects(exercise(checkpoint.replace(/await waitForBrowserAction\(cdp,`[^`]+`\);/,"await waitForBrowserText(cdp,/Retry create export/);")),/0 !== 1|Expected values/);
});

test("actual audit adapter replaces the principal through public login and logs out the owned reader", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseAuditBrowserAcceptance(");
  const end = source.indexOf("\nasync function exerciseRedTeamRetainedRun(", start);
  const admin = "pid_10000004-0000-4000-8000-000000000004";
  const reader = "pid_10000007-0000-4000-8000-000000000007";
  let authenticated = admin, route = "/", mapping, pendingMapping = {}, readerSessions = 0;
  const transitions = [];
  const context = {
    assert, path, URL, Date, setTimeout, nextIdentityLogin: "admin", identityGroupReference: "owned-group", postgresBin: "/owned/pg", proxyFailure: undefined,
    auditMutationWitnesses: { read: () => [] }, auditExpectedEvents: [], auditRequestTrace: { read: () => [] },
    auditFailNext: false, auditDelayNext: false, releaseAuditDelayed: undefined, console: { log() {} },
    command: async () => ({ stdout: "" }),
    navigateBrowser: async (_cdp,url) => { route = new URL(url).pathname; },
    fillBrowserLabel: async (_cdp,label,value) => { pendingMapping[label] = value; },
    selectBrowserOption: async (_cdp,label,value) => { pendingMapping[label] = value; },
    waitForBrowserText: async (_cdp,pattern) => {
      const text = route === "/sign-in" ? "Sign in to Zasp Continue through the configured identity provider" : !authenticated ? "Sign in to Zasp" : mapping ? "Group mapping saved; affected sessions revoked Security overview" : "member-group-e2e";
      assert.match(text,pattern); return text;
    },
    clickBrowserText: async (_cdp,label) => {
      if (label === "Save group mapping") { assert.equal(authenticated,admin); mapping = { ...pendingMapping }; }
      else if (label === "Continue to sign in") {
        assert.equal(route,"/sign-in");
        authenticated = context.nextIdentityLogin === "group" ? reader : admin;
        if (authenticated === reader) { assert.ok(mapping); readerSessions++; }
        transitions.push(authenticated); route = "/";
      } else { assert.equal(label,"Sign out"); assert.equal(authenticated,reader); readerSessions--; authenticated = null; }
    },
    runAuditLogBrowserProof: async ({ browser, fixtures }) => {
      assert.equal(typeof browser.preparePrincipalReplacement,"function","actual adapter lacks principal setup");
      await browser.preparePrincipalReplacement();
      assert.equal((await browser.authenticatedPrincipal()).id,admin);
      await browser.replacePrincipal();
      const identity = await browser.authenticatedPrincipal();
      assert.equal(identity.id,reader); assert.equal(identity.role,"read_only_viewer"); assert.equal(identity.auditRead,false);
      assert.equal(fixtures.replacementPrincipalID,reader);
      assert.equal(JSON.stringify(identity).includes("never-retain-csrf"),false);
      await browser.restorePrincipal();
      assert.equal((await browser.authenticatedPrincipal()).id,admin);
      return {};
    },
  };
  const cdp = { send: async (method,options) => {
    assert.equal(method,"Runtime.evaluate");
    const result = await runInNewContext(options.expression, { fetch: async (url,options) => {
      assert.equal(url,"/api/v1/session/bootstrap"); assert.equal(options.cache,"no-store");
      return { status: authenticated ? 200 : 401, json: async () => ({ principal: { id: authenticated, role: authenticated === admin ? "security_admin" : "read_only_viewer" }, capabilities: authenticated === admin ? ["audit.read"] : ["inventory.read"], csrf_token: "never-retain-csrf" }) };
    }, AbortSignal });
    return { result: { value: result } };
  } };
  const exercise = runInNewContext(`(()=>{${source.slice(start,end)};return exerciseAuditBrowserAcceptance;})()`,context);
  await exercise(cdp,"owned","https://owned.invalid");
  assert.deepEqual(transitions,[reader,admin]);
  assert.equal(readerSessions,0,"reader logout must preserve the later exact-one-session proof");
  assert.deepEqual(mapping,{"Stytch SCIM group ID":"owned-group","Mapped role":"read only viewer","Workspace ID":"pid_10000002-0000-4000-8000-000000000002","Environment ID":"pid_10000003-0000-4000-8000-000000000003"});
  assert.equal(context.nextIdentityLogin,"admin");
});

test("audit principal restoration failure does not skip owned paging cleanup", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseAuditBrowserAcceptance(");
  const end = source.indexOf("\nfunction createAuditBrowserPrincipalSession(", start);
  let pagingCleaned = false;
  const exercise = runInNewContext(`(${source.slice(start,end)})`, {
    assert, path, Date, setTimeout, postgresBin: "/owned/pg", proxyFailure: undefined,
    auditMutationWitnesses: { read: () => [] }, auditExpectedEvents: [], auditRequestTrace: { read: () => [] },
    auditFailNext: false, auditDelayNext: false, releaseAuditDelayed: undefined,
    createAuditBrowserPrincipalSession: () => ({ restore: async () => { throw new Error("owned logout unavailable"); } }),
    runAuditLogBrowserProof: async () => { throw new Error("acceptance failed"); },
    command: async (_executable,args) => { if (args.at(-1).startsWith("DELETE FROM zasp_admin_audit")) pagingCleaned = true; return {stdout:""}; },
  });
  await assert.rejects(exercise({},"owned","https://owned.invalid"), /owned logout unavailable/);
  assert.equal(pagingCleaned,true,"principal cleanup failure skipped existing owned paging cleanup");
});

test("selected audit setup runs compiled53 and real API registration before policy configuration", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("  if (auditBrowserMode) {\n    await command(migrate");
  const end = source.indexOf("\n  if (securityAgentRunContextMode)", start);
  assert.ok(start > 0 && end > start);
  const commands = [];
  const migrationEnvironment = { ZASP_POSTGRES_DSN: "owned", ZASP_DISCOVERY_API_DB_PRINCIPAL: "zasp_e2e_api", ZASP_SECURITY_AGENT_API_DB_PRINCIPAL: "zasp_e2e_security_agent_api" };
  const context = {
    auditBrowserMode: true, complianceBrowserMode: false, securityAgentRunContextMode: false, existingTestMountedMode: false, migrate: "/owned/migrate", temporaryRoot: "/owned", platform: "/owned/platform", postgresBin: "/owned/pg", postgresPort: 54321,
    dsn: "postgres://zasp_e2e@127.0.0.1:54321/postgres?sslmode=disable", migrationEnvironment, path, assert,
    auditBrowserPolicyEnvironment,
    console: { log() {} }, command: async (executable, args, options) => {
      commands.push({ executable, args: [...args], options });
      return { stdout: executable === "/owned/pg/psql" ? "49|production_runtime_correlation_routing\n50|production_runtime_sandbox_binding\n51|production_runtime_precision\n52|production_audit_exports\n53|production_security_agent_budgets" : "" };
    },
  };
  await runInNewContext(`(async()=>{${source.slice(start,end)}})()`, context);
  assert.deepEqual(commands.map(item => [item.executable, item.args[0]]), [["/owned/migrate","up-to-53"],["/owned/pg/psql",context.dsn],["/owned/migrate","register-audit-export-api"],["/owned/migrate","configure-audit-exports"]]);
  assert.equal(commands[0].options.env, migrationEnvironment);
  assert.equal(commands[2].options.env, migrationEnvironment);
  assert.equal(commands[3].options.env.ZASP_AUDIT_EXPORT_POLICY_ID, JSON.parse(auditBrowserAPISettings().ZASP_AUDIT_EXPORT_POLICIES_JSON)[0].policy_id);
  await runInNewContext(`(async()=>{${source.slice(start,end)}})()`, { ...context, auditBrowserMode: false });
  assert.equal(commands.length, 4, "default48 path allocated selected resources");
  for (let failure = 0; failure < 4; failure++) {
    const seen = [];
    await assert.rejects(runInNewContext(`(async()=>{${source.slice(start,end)}})()`, { ...context, command: async (...args) => {
      seen.push(args);
      if (seen.length === failure + 1) throw new Error("owned setup failure");
      return context.command(...args);
    } }), /owned setup failure/);
    assert.equal(seen.length, failure + 1, "setup continued after failed authority step");
  }
  for (const mutation of [value => value.replace(/\n53\|[^\n]+$/, ""), value => value.replace("53|production_security_agent_budgets", "53|wrong_release"), value => value + "\n54|unapproved_release"]) {
    const seen = [];
    await assert.rejects(runInNewContext(`(async()=>{${source.slice(start,end)}})()`, { ...context, command: async (...args) => {
      seen.push(args);
      const result = await context.command(...args);
      return args[0] === "/owned/pg/psql" ? { stdout: mutation(result.stdout) } : result;
    } }), /did not reach exact compiled53/);
    assert.equal(seen.length, 2, "unapproved schema reached API or policy mutation");
  }
});

test("actual combined API environment keeps separate logins and removes ambient audit presence", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("function combinedAPIEnvironment(");
  const end = source.indexOf("\nasync function beginPrecisionBrowserAcceptance(", start);
  for (const selected of [false, true]) {
    const build = runInNewContext(`(${source.slice(start,end)})`, { process: { env: { PATH: "/owned", ZASP_AUDIT_EXPORT_UNKNOWN: "", ZASP_AUDIT_EXPORT_BUCKET: "ambient" } }, auditBrowserMode: selected, auditBrowserEnvironment, auditBrowserAPISettings, stytchWebhookSecret: "owned" });
    const result = build({ apiDSN: "postgres://zasp_e2e_api@127.0.0.1:54321/postgres?sslmode=disable", postgresPort: 54321 });
    assert.equal(result.ZASP_POSTGRES_DSN, "postgres://zasp_e2e_api@127.0.0.1:54321/postgres?sslmode=disable");
    assert.equal(result.ZASP_SECURITY_AGENT_POSTGRES_DSN, "postgres://zasp_e2e_security_agent_api@127.0.0.1:54321/postgres?sslmode=disable");
    assert.deepEqual(Object.keys(result).filter(key => key.startsWith("ZASP_AUDIT_EXPORT_")).sort(), selected ? Object.keys(auditBrowserAPISettings()).sort() : []);
  }
});

test("audit browser mode refuses before PostgreSQL discovery or resource allocation", () => {
  for (const value of ["", "false", "TRUE"]) {
    const result = spawnSync(process.execPath, [new URL("./production-combined-e2e.mjs", import.meta.url).pathname], {
      env: { PATH: "", ZASP_COMBINED_E2E_AUDIT_BROWSE: value }, encoding: "utf8", timeout: 5000,
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /audit browser mode/);
    assert.doesNotMatch(result.stderr, /pg_config|ENOENT/);
    assert.equal(result.stdout, "");
  }
});

test("precise browser rejects every missing prerequisite before dependency allocation", () => {
  const flags = { ZASP_COMBINED_E2E_RUNTIME_PRECISION_BROWSER: "true", ZASP_COMBINED_E2E_RUNTIME_PRECISION: "true", ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY: "true", ZASP_COMBINED_E2E_RUNTIME_SANDBOX_SEARCH: "true" };
  for (const key of Object.keys(flags).filter(key => !key.endsWith("_BROWSER"))) {
    for (const value of ["", "TRUE", "false"]) {
      const result = spawnSync(process.execPath, [new URL("./production-combined-e2e.mjs", import.meta.url).pathname], {
        env: { ...process.env, ...flags, [key]: value, PATH: "" }, encoding: "utf8", timeout: 5000,
      });
      assert.equal(result.status, 1);
      assert.match(result.stderr, /precision browser checkpoint requires/);
      assert.doesNotMatch(result.stderr, /pg_config|ENOENT/);
      assert.equal(result.stdout, "");
    }
  }
});

test("precision proof rejects missing prerequisite flags before starting dependencies", () => {
  for (const [only, sandbox] of [["false", "false"], ["true", "false"], ["false", "true"]]) {
    const result = spawnSync(process.execPath, [new URL("./production-combined-e2e.mjs", import.meta.url).pathname], {
      env: { ...process.env, PATH: "", ZASP_COMBINED_E2E_RUNTIME_PRECISION: "true", ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY: only, ZASP_COMBINED_E2E_RUNTIME_SANDBOX_SEARCH: sandbox },
      encoding: "utf8", timeout: 5000,
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /precision proof requires runtime-only and sandbox-search modes/);
    assert.doesNotMatch(result.stdout, /disposable PostgreSQL ready/);
  }
});

test("sandbox search cutover rejects broad harness mode before starting dependencies", () => {
  const result = spawnSync(process.execPath, [new URL("./production-combined-e2e.mjs", import.meta.url).pathname], {
    env: { ...process.env, PATH: "", ZASP_COMBINED_E2E_RUNTIME_SANDBOX_SEARCH: "true", ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY: "false" },
    encoding: "utf8", timeout: 5000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /sandbox search cutover requires runtime-only mode/);
  assert.doesNotMatch(result.stdout, /disposable PostgreSQL ready/);
});

test("combined product proof requires the forward reconciliation migration", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const marker of ["46|production_reconciliation_lane_plan", "schema 46 production_reconciliation_lane_plan verified", "47|production_runtime_candidate_authority", "schema 47 production_runtime_candidate_authority verified", "48|production_runtime_acceptance", "schema 48 production_runtime_acceptance verified"])
    assert.ok(source.includes(marker), marker);
});

test("enrollment pairing proof requires schema45 and real browser lifecycle", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const marker of ["45|production_runtime_enrollment_pairing", "schema 45 production_runtime_enrollment_pairing verified", "await exerciseRuntimeEnrollmentPairing(cdp, dsn, sensorID)", "Runtime sensor pairing", "Configured runtime pairing", "runtime enrollment pairing proven:", "paired token survived reload", "anchor deletion rewrote configured pairing"])
    assert.ok(source.includes(marker), marker);
});

test("observed lineage composition separates v1 preservation from local v2 correlation", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const worker = await readFile(new URL("../services/platform/agentsec-worker/runtime_pipeline_combined_e2e_test.go", import.meta.url), "utf8");
  assert.ok(source.includes("/runtime observed lineage preservation proven:/"));
  for (const marker of ["runtime observed lineage preservation proven:", 'events[i]["observed_lineage"] = observedLineage', "record.ObservedLineage != observedLineage", "same observed lineage granted unpaired sensors correlation authority", "semantic archive lost observed lineage", "fresh v2 Strong/Probable proven separately on local schema49, live producer attestation NOT RUN"]) assert.ok(worker.includes(marker), marker);
});

test("confidence display fixture cannot claim production correlation reachability", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const marker of ["await exerciseRuntimeConfidenceDisplay(browser.cdp, dsn)", "runtime confidence display fixture passed:", "Strong/Probable production correlation NOT RUN", "confidence fixture cleanup changed worker evidence", "data-runtime-confidence", "probable.background, exact.background", "probable.color, exact.color"]) assert.ok(source.includes(marker), marker);
});

test("mixed evidence browser acceptance uses worker data and visible confidence", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseWorkerMixedEvidence");
  const flow = source.slice(start, source.indexOf("async function exerciseRuntimeConfidenceDisplay", start));
  assert.ok(source.includes("await exerciseWorkerMixedEvidence(browser.cdp, dsn, chromePort, publicOrigin)"));
  for (const marker of ["mixed session lacks worker-created pagination evidence", "reverse-ingress mixed evidence lost canonical ordering across pages", "visible mixed confidence differs from worker decision", 'unknown[0].label, "Probable"', "foreign tenant read worker-created evidence", "revoked investigator retained evidence access", "mixed-evidence browser proof changed worker evidence", "identity setup fixture only, live deployment NOT RUN"])
    assert.ok(flow.includes(marker), marker);
  assert.doesNotMatch(flow, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_/);
});

test("six-class evidence proof requires schema44 and worker-backed scoped links", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const worker = await readFile(new URL("../services/platform/agentsec-worker/runtime_pipeline_combined_e2e_test.go", import.meta.url), "utf8");
  for (const marker of ["44|production_runtime_session_evidence", "schema 44 production_runtime_session_evidence verified", "runtime six-class evidence links proven:", "Open evidence ", "Canonical evidence metadata", "another scope exposed canonical event evidence", "revoked permission exposed canonical event evidence"]) assert.ok(source.includes(marker), marker);
  for (const marker of ["semantic observation pipeline proven:", '"credential", "use"', '"policy", "block"', 'events[1]["class"], events[1]["action"] = "file", "read"', 'events[2]["class"], events[2]["action"] = "network", "connect"']) assert.ok(worker.includes(marker), marker);
  assert.doesNotMatch(worker, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_session/);
});

test("session indexing composition requires schema42 and production checkpoint proof", async()=>{
  const source=await readFile(new URL("./production-combined-e2e.mjs",import.meta.url),"utf8");
  assert.ok(source.includes("42|production_runtime_session_search"));
  assert.ok(source.includes("schema 42 production_runtime_session_search verified"));
  assert.ok(source.includes("production session indexing outbox proven: completion transaction, registered index worker"));
});

test("runtime query composition requires schema43 and real indexed HTTP search", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const marker of ["43|production_runtime_session_query", "schema 43 production_runtime_session_query verified", "startPolicyHistoryServer(policyHistoryPort, runtimeSearchEndpoint)", "worker-indexed runtime search API proven: structured matching, canonical counts, observed-only checkpoints and provider failure"])
    assert.ok(source.includes(marker), marker);
  assert.ok(source.includes('"/zasp-runtime-sessions-v1/_mapping"'));
  assert.ok(source.includes('"/zasp-runtime-sessions-v1/_doc/_zasp_session_schema_v1"'));
  assert.ok(source.includes('"/zasp-runtime-sessions-v1/_search"'));
});

test("audit-only policy fixture refuses session reads when no runtime engine is configured", async t => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function startPolicyHistoryServer(");
  const end = source.indexOf("\nasync function startProxy(", start);
  const failures = [];
  const startFixture = runInNewContext(`(${source.slice(start, end)})`, {
    readFile, path, platform: new URL("../services/platform/", import.meta.url).pathname, assert, createHash, URL, once,
    policyHistoryRequests: [], failNextRuntimeSessionSearch: false,
    http: { ...http, createServer: handler => http.createServer((request, response) => {
      Promise.resolve(handler(request, response)).catch(error => {
        failures.push(error.message);
        response.writeHead(500, { "content-type": "application/json" });
        response.end('{"error":"unexpected fixture exception"}');
      });
    }) },
  });
  const server = await startFixture(0);
  t.after(() => new Promise(resolve => server.close(resolve)));
  for (const [method, route] of [
    ["GET", "/zasp-runtime-sessions-v1/_mapping"], ["GET", "/zasp-runtime-sessions-v2/_mapping"],
    ["GET", "/zasp-runtime-sessions-v1/_doc/_zasp_session_schema_v1"], ["GET", "/zasp-runtime-sessions-v2/_doc/_zasp_session_schema_v2"],
    ["POST", "/zasp-runtime-sessions-v1/_search"], ["POST", "/zasp-runtime-sessions-v2/_search?allow_partial_search_results=false&request_cache=false&typed_keys=false&terminate_after=0&timeout=5s"],
  ]) {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${route}`, { method, headers: { authorization: "AWS4-HMAC-SHA256 owned-fixture-test" }, signal: AbortSignal.timeout(3000) });
    assert.equal(response.status, 503, "missing runtime engine must be unavailable, not throw or fabricate readiness");
    assert.deepEqual(await response.json(), { error: "runtime search not configured in selected fixture" });
  }
  assert.deepEqual(failures, []);
});

test("runtime proxy forwards only fixed target1 and target2 read routes to the owned engine", async t => {
  const requests = [];
  const engine = http.createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    requests.push({ method: request.method, path: request.url, body });
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ forwarded: requests.at(-1) }));
  });
  engine.listen(0, "127.0.0.1");
  await once(engine, "listening");
  t.after(() => new Promise(resolve => engine.close(resolve)));
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function startPolicyHistoryServer(");
  const end = source.indexOf("\nasync function startProxy(", start);
  assert.ok(start > 0 && end > start);
  const startProxy = runInNewContext(`(${source.slice(start, end)})`, {
    readFile, path, platform: new URL("../services/platform/", import.meta.url).pathname, assert, createHash, http, URL, once,
    policyHistoryRequests: [], failNextRuntimeSessionSearch: false,
  });
  const proxy = await startProxy(0, `http://127.0.0.1:${engine.address().port}`);
  t.after(() => new Promise(resolve => proxy.close(resolve)));
  const request = async (method, route, signed = true) => {
    const response = await fetch(`http://127.0.0.1:${proxy.address().port}${route}`, {
      method, headers: { ...(signed ? { authorization: "AWS4-HMAC-SHA256 owned-route-test" } : {}), "content-type": "application/json" },
      ...(method === "POST" || method === "PUT" ? { body: '{"query":{"match_none":{}}}' } : {}),
    });
    return { status: response.status, body: await response.json() };
  };
  const productionQuery = "allow_partial_search_results=false&request_cache=false&typed_keys=false&terminate_after=0&timeout=5s";
  for (const version of [1, 2]) {
    for (const [method, route] of [["GET", `_mapping`], ["GET", `_doc/_zasp_session_schema_v${version}`], ["POST", "_search"]]) {
      const pathname = `/zasp-runtime-sessions-v${version}/${route}${version === 2 && method === "POST" ? `?${productionQuery}` : ""}`;
      const response = await request(method, pathname);
      assert.equal(response.status, 200, pathname);
      assert.deepEqual(response.body.forwarded, { method, path: pathname, body: method === "POST" ? '{"query":{"match_none":{}}}' : "" });
    }
  }
  const sorted = new URLSearchParams(productionQuery);
  sorted.sort();
  assert.equal((await request("POST", `/zasp-runtime-sessions-v2/_search?${sorted}`)).status, 200, "AWS signer query sorting changed fixed read authority");
  const accepted = [...requests];
  for (const [method, route] of [["PUT", "_mapping"], ["POST", "_bulk"], ["POST", "_delete_by_query"], ["DELETE", "_doc/_zasp_session_schema_v2"], ["GET", "_doc/foreign"], ["GET", "_search"], ["POST", "_search"], ["POST", "_search?scroll=1m"], ["GET", "_mapping?expand_wildcards=all"], ...[`${productionQuery}&scroll=1m`, `${productionQuery}&timeout=5s`, productionQuery.replace("request_cache=false", "request_cache=true"), productionQuery.replace("&timeout=5s", ""), productionQuery.replace("timeout=5s", "timeout=60s")].map(query => ["POST", `_search?${query}`])]) {
    assert.equal((await request(method, `/zasp-runtime-sessions-v2/${route}`)).status, 404);
  }
  assert.equal((await request("POST", "/zasp-runtime-sessions-v2/_search", false)).status, 403);
  assert.deepEqual(requests, accepted, "unknown/write/unsigned route reached real engine");
});

test("precise callback readiness accepts authorized empty inventory and still checks fresh session authority", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("  await pendingStep(() => navigateBrowser(cdp,", source.indexOf("async function beginPrecisionBrowserAcceptance("));
  const end = source.indexOf('  await pendingStep(() => selectBrowserOption(cdp, "Authorized scope", "Staging"));', start);
  assert.ok(start > 0 && end > start);
  const sqlQueries = [], scopes = [];
  const context = {
    assert, cdp: {}, publicOrigin: "https://owned.test", productionScope: "authorized-production-scope", authenticationStarted: "2026-09-12T00:00:00.000Z", observedSessionCookie: true,
    pendingStep: operation => operation(), navigateBrowser: async () => {},
    waitForBrowserText: async (_cdp, pattern) => assert.match("Zasp Production Staging Sign out Agents Authorized canonical inventory. No records in this scope.", pattern),
    waitForBrowserScope: async (_cdp, scope) => { scopes.push(scope); },
    sql: async query => { sqlQueries.push(query); return "1"; },
  };
  await runInNewContext(`(async () => { ${source.slice(start, end)} })()`, context);
  assert.deepEqual(scopes, [context.productionScope]);
  assert.equal(sqlQueries.length, 1);
  assert.match(sqlQueries[0], /authenticated_at>=.*expires_at>transaction_timestamp\(\).*revoked_at IS NULL/);
  await assert.rejects(runInNewContext(`(async () => { ${source.slice(start, end)} })()`, { ...context, observedSessionCookie: false }), /did not receive callback cookie/);
  await assert.rejects(runInNewContext(`(async () => { ${source.slice(start, end)} })()`, { ...context, sql: async () => "0" }), /did not authenticate freshly/);
});

test("a pending deadline after server allocation leaves the server owned by parent cleanup", async t => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function beginPrecisionBrowserAcceptance(");
  const end = source.indexOf("\nasync function closePrecisionBrowserPanel(", start);
  assert.ok(start > 0 && end > start);
  let now = 100_000;
  const server = http.createServer((_request, response) => response.end());
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise(resolve => server.close(resolve)));
  const context = {
    assert, path, productHostname: "zasp.production-e2e.test", postgresBin: "/owned/postgres", identity: undefined,
    Date: { now: () => now },
    command: async (_executable, args) => { assert.ok(args.at(-1).startsWith("SELECT jsonb_build_object")); return { stdout: "immutable snapshot" }; },
    startIdentityServer: async () => { now = 102_000; return server; },
  };
  const begin = runInNewContext(`(${source.slice(start, end)})`, context);
  await assert.rejects(begin({ scope: { organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000022-0000-4000-8000-000000000022", environment_id: "pid_10000023-0000-4000-8000-000000000023" }, deadline_unix_ms: 101_000 }, { dsn: "owned", proxyPort: 1234, identityPort: server.address().port }), /exceeded provider deadline/);
  assert.equal(context.identity, server, "deadline rejection lost ownership of listening server");
});

test("runtime timeline proves reverse-ingress canonical order across real UI pages", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseRuntimeSessionReads");
  const flow = source.slice(start, source.indexOf("async function exerciseRuntimeConfidenceDisplay", start));
  for (const marker of ['clickBrowserAria(cdp, "Open runtime timeline unattributed")', 'clickBrowserText(cdp, "Next event page")', 'clickBrowserText(cdp, "First event page")', "128 - index", "new Set(timeline.map", "runtime timeline proven: reverse-ingress worker events, canonical 25-plus-1 pagination, source confidence and scope reset"])
    assert.ok(flow.includes(marker), marker);
  assert.doesNotMatch(flow, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_session/);
});

test("runtime Sessions UI filters worker-written evidence and resets on scope change", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseRuntimeSessionReads");
  const flow = source.slice(start, source.indexOf("async function exerciseRuntimeConfidenceDisplay", start));
  for (const marker of ['fillBrowserLabel(cdp, "Process", "/usr/bin/other")', 'fillBrowserLabel(cdp, "Process", "/usr/bin/agent")', 'clickBrowserText(cdp, "Search sessions")', "runtime Sessions UI proven: structured process filter, canonical confidence, indexing checkpoint and scope reset"])
    assert.ok(flow.includes(marker), marker);
  assert.doesNotMatch(flow, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_session/);
});
import { fileURLToPath } from "node:url";
import { installBoundedSignalCleanup } from "./bounded-signal-cleanup.mjs";

test("runtime recovery proof owns authenticated TLS Neo4j instead of a graph stub", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const worker = await readFile(new URL("../services/platform/agentsec-worker/runtime_pipeline_combined_e2e_test.go", import.meta.url), "utf8");
  assert.match(source, /runtimeGraphDependency\.start\(\)/);
  assert.match(source, /runtimeGraphDependency\?\.close\(\)/);
  const construction = source.indexOf("runtimeGraphDependency = createGraphFixtureDependency()");
  assert.ok(construction > source.indexOf("try {\n  const ports"));
  assert.ok(construction < source.indexOf("await runtimePipelineDependencies.prepare()"));
  assert.match(source, /ZASP_COMBINED_E2E_RUNTIME_GRAPH_URI/);
  assert.match(worker, /newRuntimePipelineGraphFixture/);
  assert.doesNotMatch(worker, /runtimeCorrelationGraphStoreStub/);
});

test("runtime candidate recovery requires production-created v2 jobs without fixture relabeling", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const worker = await readFile(new URL("../services/platform/agentsec-worker/runtime_candidate_recovery_e2e_test.go", import.meta.url), "utf8");
  assert.ok(source.includes("/runtime candidate recovery proven:/"));
  for (const marker of ["expires.Add(100 * time.Millisecond)", "production-created v2 jobs on local schema49, cloud deployment NOT RUN", "NewPostgresCorrelationPipelineRepository", "newRuntimeCorrelationExecutorWithDatabase", "ObjectReferencingArtifactStore.Put(ctx, request)", "graph.delegate.ApplySnapshot(ctx, snapshot)"])
    assert.ok(worker.includes(marker), marker);
  assert.doesNotMatch(worker, /UPDATE zasp_runtime_stage_work SET (?:lease_expires_at|implementation_version)|INSERT INTO zasp_runtime_candidate|(?:INSERT INTO|UPDATE) zasp_runtime_session/);
  const pipeline = await readFile(new URL("../services/platform/agentsec-worker/runtime_pipeline_combined_e2e_test.go", import.meta.url), "utf8");
  assert.ok(pipeline.indexOf("runner.UpProductionRuntimeCorrelationRouting(ctx)") > pipeline.indexOf('t.Log("runtime v2 reader v1 backlog proven:'));
  assert.ok(source.includes("/runtime correlation routing proven:/"));
});

test("runtime session browser proof reads worker-written evidence without seeding sessions", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const worker = await readFile(new URL("../services/platform/agentsec-worker/runtime_pipeline_combined_e2e_test.go", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseRuntimeSessionReads");
  const flow = source.slice(start, source.indexOf("async function exerciseRuntimeConfidenceDisplay", start));
  assert.ok(start > 0);
  for (const text of ["await exerciseRuntimeSessionReads(browser.cdp, dsn)", "runtime session summaries proven: completion-triggered unknown collection, byte-stable replay"]) assert.ok(source.includes(text), text);
  for (const text of ["another scope exposed runtime investigation", "summary.agent_id, null", "summary.principal_id, null", "summary.kind, \"unattributed\"", "revoked investigation permission retained runtime API access", "runtime session fixture permission ownership changed"]) assert.ok(flow.includes(text), text);
  assert.doesNotMatch(flow, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_session/);
  assert.doesNotMatch(worker, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_session/);
  assert.ok(worker.includes("SQS redelivery changed runtime session summaries"));
  assert.ok(flow.includes("scope = staging"), "positive browser reads must use the worker's actual Staging scope");
});

test("session search proof requires committed evidence and real-engine filter completeness", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const worker = await readFile(new URL("../services/platform/agentsec-worker/runtime_pipeline_combined_e2e_test.go", import.meta.url), "utf8");
  const proof = await readFile(new URL("../services/platform/agentsec-worker/runtime_session_search_combined_e2e_test.go", import.meta.url), "utf8");
  const matrix = await readFile(new URL("../services/platform/agentsec-worker/runtime_session_search_filters_e2e_test.go", import.meta.url), "utf8");
  for (const marker of ["runtime session search index proven:", "real OpenSearch selector matrix passed:"]) assert.ok(source.includes(`assert.match(runtimePipelineResult.stdout, /${marker}`), marker);
  assert.ok(worker.includes("proveRuntimeSessionSearchIndex(t, ctx, admin, scope,"));
  for (const text of ["receipt.receipt_digest=project.result_digest", "complete.state='succeeded'", "receipts.Get(ctx, locator)", "index.Apply(ctx, binding, artifact.Body, archive)", "proveRuntimeStructuredSearchSelectors(t, ctx, index)", "number_of_replicas", "search API remains pending"]) assert.ok(proof.includes(text), text);
  assert.doesNotMatch(proof, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_session/);
  for (const text of ["selectors incorrectly joined different events within one session", "composite pagination incomplete", "foreign positive control absent", "when.Add(time.Nanosecond)", "synthetic component fixtures only"]) assert.ok(matrix.includes(text), text);
});

test("Home exposure E2E waits for loaded rows, not the persistent navigation title", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf('await clickBrowserTextContains(cdp, "Critical exposures")');
  const end = source.indexOf('await clickBrowserTextContains(cdp, "Pending approvals")', start);
  const flow = source.slice(start, end);
  assert.match(flow, /await waitForBrowserAction\(cdp,.*Open attack path/);
  assert.ok(flow.indexOf("await waitForBrowserAction") < flow.indexOf("await browserCountAriaPrefix"));
  assert.match(flow, /Home critical exposure route had no authoritative path/);
});

test("webhook browser E2E verifies real persisted outcome across response loss and reload", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const expected of ["integrationWebhookTestRequests", "webhook retry changed its idempotency key", "webhook retry changed its audit record", "webhook failure was not durably retained once", "webhook status reload emitted another delivery", "Signature and acceptance are unconfirmed", "1|failed"]) assert.ok(source.includes(expected));
});

test("Red Team response recovery proves committed authority without duplicate work", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const expected of ["exerciseRedTeamRetainedRun", "response loss was not injected after a real committed run", "reload automatically submitted an unresolved run", "another tenant scope exposed the retained run", "retained replay duplicated durable run authority", "1|queued|0|1|1|1|1", "1|cancelled|0|1|2|2|1", "request.body, redTeamRunRequests[0].body", "request.idempotencyKey, redTeamRunRequests[0].idempotencyKey", "request.expectedScope, expectedScope", "confirmed Red Team operation left a browser checkpoint"]) assert.ok(source.includes(expected), expected);
});

test("recommendation browser proof uses discovered targets without granting execution",async()=>{
  const source=await readFile(new URL("./production-combined-e2e.mjs",import.meta.url),"utf8");
  for(const expected of ["exerciseRedTeamRecommendations", "Support agent", "Automation repository", "Use recommended categories", "recommendation selection created execution authority", "recommendation fixture permission ownership changed", "finally { await setPermission(false)", "Discovered identity or administrative authority warrants authorization-boundary testing"])assert.ok(source.includes(expected),expected);
});

test("Red Team runtime proof preserves real composition and exact evidence claims", async()=>{
  const source=await readFile(new URL("./production-combined-e2e.mjs",import.meta.url),"utf8");
  const worker=await readFile(new URL("../services/platform/agentsec-worker/red_team_runtime_combined_e2e_test.go",import.meta.url),"utf8");
  const start=source.indexOf("async function exerciseRedTeamRuntime");
  const flow=source.slice(start,source.indexOf("async function exerciseRedTeamRetainedRun",start));
  for(const text of ["Save test","Run Runtime pipeline proof","redTeamRuntimeProof.run","--- PASS: TestProductionCombinedE2ERedTeamRuntime","assert.doesNotMatch(result.stdout, /--- SKIP:/)","await reloadBrowser","Verify safely","customer invocation fixture only"])assert.ok(flow.includes(text),text);
  for(const text of ["composeRedTeamWorkerRuntime(","composeRedTeamOutboxWorkerRuntime(","productionRedTeamCommand{}","redteamadapter.NewPostgresResolver(","redteamadapter.NewHandler(","outbox.Ready(ctx)","worker.Ready(ctx)","outbox.Processor.RunOnce(ctx)","worker.Processor.RunOnce(ctx)","p.queue.PublishBatch(ctx, jobs)","attempts != 1","fixture.calls.Load() != 1","!leaseCleared","s3API.GetObject(","!bytes.Equal(checksum, digest[:])","aws.ToString(object.VersionId) != version","object.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms","aws.ToString(object.SSEKMSKeyId) != keyARN","customer invocation fixture only"])assert.ok(worker.includes(text),text);
  assert.equal(worker.match(/p\.queue\.PublishBatch\(ctx, jobs\)/g)?.length,2,"duplicate delivery must be physically published");
  assert.doesNotMatch(worker,/zasp_red_team_(?:finish_run|claim_run|acknowledge_outbox)\s*\(/);
  assert.doesNotMatch(worker,/newRedTeam(?:Processor|OutboxProcessor)\(/);
});

test("Red Team outcome browser proof reaches safety review without granting execution", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseRedTeamRuntime");
  const flow = source.slice(start, source.indexOf("async function exerciseRedTeamRetainedRun", start));
  for (const expected of ["Unsafe behavior observed", "Cancelled", "Verify safely in Attack Lab", "Review safety decision", "Approve exact safety decision", "outcome navigation granted Attack Lab execution", "readAttackLabAuthority", "source_run_id", "Safety approval"]) assert.ok(flow.includes(expected), expected);
});

test("combined production E2E owns every local boundary and fixed assertion", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const recoveryWorkerSource = await readFile(new URL("../services/platform/agentsec-worker/production_combined_e2e_test.go", import.meta.url), "utf8");
  for (const value of [
    "postgres", "agentsec-migrate", "agentsec-api", "vinext",
    "/api/v1/session/start", "/auth/callback", "__Host-zasp_session", "Support agent",
    "not_found", "SIGTERM", "FIXED_NODE_VERSION", "Roll to monitor",
    "Save Security Agent definition", "configured", "Tenant-scoped response definitions",
    "lostPolicyResponseKeys", "replaceTarget", "Recover committed operations", "Acknowledge recovered result", "full-document receipt recovery", "two lost browser responses changed idempotency key", "1|2|2|1",
    "Input.dispatchKeyEvent", "browserDialogIsolation", "keyboard focus trap and restoration",
    "PAT success, replay, and zero browser receipts", "1|1|0", "workflowPageRequests", "Paged policy 1000", "Paged integration 1001",
    "Second-tab committed policy", "Expiry-race committed policy", "seedExpiringReceipt", "expired receipt left workflow mutations locked",
    "startBrowserTab", "actual two-tab delayed out-of-order ABA stale-scope recovery proven", "X-Zasp-Expected-Scope",
    "delayedFirstTabBootstrap", "secondTabBootstrapWhileFirstDelayed", "firstTabScopeStaleResponses", "X-Zasp-E2E-Tab",
    "ZASP_DEPLOYMENT_MODE", "/administration/identity-access", "member-target-local", "Member role updated; active sessions revoked",
    "ZASP_STYTCH_WEBHOOK_SECRET", "schema 19 identity_administration verified", "schema 20 security_agent_controls verified", "schema 21 security_agent_autonomous_response verified", "schema 24 security_agent_session_isolation verified",
    "production SSO, SCIM, and group-mapping browser workflow proven",
    "signed Stytch webhook replay and tenant deprovision proven",
    "group-derived browser login scope and cross-tenant denial proven",
    "E2E Workspace", "workspace onboarding did not atomically create its first authorized environment and reload boundary", "E2E Development",
    "/administration/api-access", "ZASP_TOKEN_REVEAL_KEY", "lostTokenResponses", "Save API token", "Copy token",
    "Acknowledgement failed", "Rotate E2E API token", "old API token remained valid after rotation", "api_token.reveal.acknowledge", "restartReloadURL",
    "Fresh authentication expired", "Reauthenticate", "configured provider remained falsely healthy", "CDP request timed out", "navigateBrowser", "reloadBrowser", "waitForBrowserScope", "Target.attachToTarget", "Target.closeTarget", "sessionId", "cdp.replaceTarget",
    "session-investigation-e2e", "Shell requested by E2E", "Revoke session session-investigation-e2e",
    "/administration/audit-log", "Audit exports unavailable", "/compliance/evidence",
    "/administration/data-retention", "Data deletion unavailable", "/administration/external-data-flows", "identity-provider",
    "/administration/system-health", "production administration lifecycle and hidden provider/export mutations proven",
    "/violations", "/exposure/attack-paths", "Production credential exposure 0001", "Ranked break option evidence",
    "lostFindingResponseKeys", "Finding status updated through committed-response recovery", "Accepted production exception",
    "PAT risk mutation and zero browser receipts proven", "risk pagination, detail, recovery, acceptance, and persistence proven",
    "Injected authoritative refetch failure", "receipt ACK did not follow authoritative refetch", "findings.write downgrade retained an interactive mutation or retry",
    "Loading path detail", "Loading break options", "Injected break-option failure", "route unmount did not abort both attack-path detail responses",
    "browserStorageHistoryAndCaches", "indexedDB.databases", "assertResponsiveRiskLayout", "Emulation.setDeviceMetricsOverride",
    "browser console and exception stream remained clean", "hidden risk-adjacent routes canonicalized without hidden API calls",
    "/red-team/results", "/test/attack-lab", "/reports", "/guardrails/dashboard", "/prompt-hardening",
    "schema 14 typed_inventory_cutover verified", "schema 15 runtime_data_plane verified", "schema 17 runtime_ingest_reconciliation verified", "schema 18 security_agent_execution verified", "schema 19 identity_administration verified", "schema 20 security_agent_controls verified", "schema 21 security_agent_autonomous_response verified", "ZASP_CONNECTOR_AWS_REGION", "ZASP_CONNECTOR_ROLE_ARN",
    "ZASP_DISCOVERY_PARSER_VERSION", "ZASP_DISCOVERY_TOOL_VERSION",
    "ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE", "ZASP_CONNECTOR_KMS_KEY_ARN", "ZASP_CONNECTOR_SECRET_PREFIX",
    "ZASP_AWS_CUSTOMER_ROLE_PREFIXES", "ZASP_AWS_CUSTOMER_ROLE_ARNS", "ZASP_KUBERNETES_EGRESS_CIDRS",
		"ZASP_FINDING_TICKET_EGRESS_CIDRS", "/api/v1/findings/{id}/ticket", "findingTicketRequests",
		"finding ticket retained one idempotency key across retry and reload",
    "ZASP_GITHUB_CLIENT_ID", "ZASP_GITHUB_CLIENT_SECRET_REFERENCE", "ZASP_GITHUB_APP_ID", "ZASP_GITHUB_PRIVATE_KEY_REFERENCE",
    "generateHarnessGitHubAppPrivateKey", "github-app-private-key.pem", "ZASP_OKTA_CLIENT_ID", "ZASP_OKTA_CLIENT_SECRET_REFERENCE",
    "/api/v1/integrations/{id}/authorize", "/api/v1/integrations/oauth/callback", "assertRejectedConnectorResponse",
    "unavailable managed OAuth authority remained fail-closed with zero provider calls", "browser launch connector setup catalog proven", "Configure Amazon Web Services", "Configure Kubernetes", "connectorAuthorizationRequests", "browserConnectorForensics", "Page.getNavigationHistory",
    "live AWS/GitHub/Okta connector success remains typed external evidence", "zero provider/AWS calls",
    "integrationDeleteRequests", "malformNextIntegrationDeleteResponse", "completeHarnessConnectorRevocation",
    "external-provider completion simulation", "real DELETE 202 durable revoking receipt",
    "same idempotency key + If-Match", "Retry pending integration deletion", "no premature deleted toast/removal",
    "reload revocation receipt remained locked", "live provider revocation NOT RUN",
		"malformed public 202 response replay", "harness direct-public-API replay",
    "schema 14 typed_inventory_cutover verified", "agentsec-worker",
    "ZASP_DISCOVERY_SCHEDULER_DB_PRINCIPAL", "ZASP_PROJECTION_RISK_DB_PRINCIPAL",
    "ZASP_PROJECTION_GRAPH_DB_PRINCIPAL", "ZASP_PROJECTION_SEARCH_DB_PRINCIPAL",
    "ZASP_WORKER_MODE", "outbox", "discovery", "scheduler", "projection-risk", "projection-graph", "projection-search",
    "ZASP_DATABASE_AUTHORITY", "zasp_outbox_worker", "zasp_discovery_worker", "zasp_discovery_scheduler",
    "zasp_projection_risk_worker", "zasp_projection_graph_worker", "zasp_projection_search_worker",
    "ZASP_WORKER_ID", "ZASP_POLL_INTERVAL", "ZASP_LEASE_DURATION", "ZASP_BATCH_SIZE", "ZASP_SHUTDOWN_TIMEOUT",
    "/api/v1/integrations/{id}/sync", "/api/v1/integrations/{id}/syncs", "/api/v1/integrations/{id}/syncs/{syncId}",
    "/api/v1/integrations/{id}/schedule", "/api/v1/integrations/{id}/freshness",
    "/api/v1/integrations/${integrationID}/setup-status", "multi-tenant AWS, Kubernetes, GitHub, and Okta setup scope remained exact and credential-redacted",
    "real public manual sync returned 202", "public schedule create/read/delete proven",
    "public sync history/detail/freshness proven", "Task4 reload preserved authoritative discovery state",
    "Task4 discovery forensics found no token, credential reference, artifact key, cursor, or worker identity in persistent browser state",
    "Task4 opaque pagination cursors remained same-origin transport-only data",
    "integration_version,configuration_digest,requested_scopes",
    "202 Retry-After window emitted an early integration DELETE",
    "live AWS/Kubernetes/GitHub/Okta collection and managed SQS/S3/OpenSearch/Neo4j remain NOT RUN",
    "zero fake collection/projection database completion", "cleanup Task4 workers",
    "ZASP_MIGRATION_DB_PRINCIPAL", "ZASP_DISCOVERY_API_DB_PRINCIPAL", "ZASP_DISCOVERY_WORKER_DB_PRINCIPAL",
    "ZASP_RUNTIME_INGEST_DB_PRINCIPAL", "ZASP_RUNTIME_WORKER_DB_PRINCIPAL", "ZASP_OUTBOX_WORKER_DB_PRINCIPAL", "ZASP_RUNTIME_GATEWAY_DB_PRINCIPAL",
    "ZASP_RUNTIME_COORDINATOR_DB_PRINCIPAL", "ZASP_RUNTIME_ARCHIVE_DB_PRINCIPAL", "ZASP_RUNTIME_INDEX_DB_PRINCIPAL",
    "ZASP_RUNTIME_CORRELATION_DB_PRINCIPAL", "ZASP_RUNTIME_PROJECTION_DB_PRINCIPAL", "ZASP_GATEWAY_CONTROL_DB_PRINCIPAL",
    "ZASP_SECURITY_AGENT_API_DB_PRINCIPAL", "ZASP_SECURITY_AGENT_WORKER_DB_PRINCIPAL", "ZASP_SECURITY_AGENT_POSTGRES_DSN",
    "provisionPostgresPrincipals", "apiDSN", "zasp.production-e2e.test", "zasp.production-e2e.localhost", "--host-resolver-rules", "SIGQUIT",
    "schema 14 typed_inventory_cutover verified", "agentsec-worker-e2e", "runDeterministicLocalDiscovery",
    "deterministic local provider and artifact authority completed public sync", "typed inventory public routes derive only from complete discovery snapshots",
    "typed inventory browser deep-link reload proven", "second-source retention proven", "complete-empty source removal proven",
    "failed and partial discovery retained the last complete inventory", "typed inventory database forensics proved exact current source/snapshot/evidence bindings",
    "/api/v1/tools", "/api/v1/identities", "/api/v1/runtimes", "inventory=pid_",
		"assertTask6SensorBrowserState", "/api/v1/sensors", "/coverage", "/rotate-token", "Runtime sensors", "Enroll sensor",
		"Create enrollment", "Copy this token now", "Save sensor", "Rotate enrollment token", "Delete sensor",
		"Helm deployment boundary", "sensorAgent.enabled=true", "sensorAgent.tokenSecretName=<pre-created-secret-name>",
		"Task6 authenticated heartbeat and healthy sensor coverage proven", "Task6 token rotation and version-pinned sensor update proven",
    "Task6 reload and deletion left no enrollment credential in persistent browser state", "zasp_runtime_sensor_heartbeat",
		"exerciseSecurityAgentAutomaticLifecycle", "production-e2e-security-agent", "multi-tenant supervised approval, autonomous response, exact-session isolation with unrelated allowance and cleanup, signed temporary policy apply/cleanup, and irreversible connector revocation proven", "Verified attack path containment", "verified attack path did not create one exact version-bound supervised plan", "attack-path scheduler duplicated a durable run or receipt", "TestProductionCombinedE2ETemporaryPolicyActionWorker", "Apply temporary containment policy", "Isolate runtime session", "ZASP_COMBINED_E2E_ACTION_SESSION_ID", "ZASP_COMBINED_E2E_ACTION_OTHER_SESSION_ID", "TTL 600s", "zasp_e2e_security_agent_action",
		"exerciseHomeDailyOperations", "Daily ops stale sensor", "Foreign daily ops stale sensor", "dailyOpsSensorToken", "foreignDailyOpsSensorToken", "Home exposed every daily-ops item", "daily-ops sensor disappeared without exact deleted state", "Home daily-ops routing preserved explicit terminal and degraded authority",
		"agentsecctl", "schema 27 production_recovery verified", "schema 28 production_policy_deployment verified", "schema 29 production_home_attention verified", "schema 30 production_approval_notification verified", "schema 31 production_workflow_compatibility verified", "schema 32 production_security_agent_planner verified", "schema 33 production_security_agent_attack_path verified", "schema 34 production_integration_setup verified", "schema 35 production_integration_webhook verified", "ZASP_POLICY_DEPLOYMENT_DB_PRINCIPAL", "ZASP_RECOVERY_WORKER_DB_PRINCIPAL", "ZASP_RECOVERY_OUTBOX_DB_PRINCIPAL",
		"ZASP_COMBINED_E2E_POLICY_DEPLOYMENT_DSN", "central policy deployment signed temporary gateway policy", "central policy deployment signed session isolation gateway policy",
		"runProductionRecoveryLifecycle", "TestProductionCombinedE2ERecoveryWorker", "ZASP_COMBINED_E2E_RECOVERY_PHASE",
		"committed recovery response loss replayed one backup, outbox, audit, and receipt", "signed recovery manifest published last", "cross-tenant recovery read rejected",
		"Recovery rehearsal completed", "Temporary resources deleted", "live Neon/AWS/S3/KMS/Kubernetes recovery remains NOT RUN",
		"exerciseProductionAttackLabLifecycle", "TestProductionCombinedE2EAttackLabWorker", "ZASP_COMBINED_E2E_ATTACK_LAB_CONTROLLER_DSN",
		"Review safety decision", "Approve exact safety decision", "composed Attack Lab outbox and controller completed deterministic isolated sandbox evidence",
  ]) assert.match(source, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  const apiEnvironment = source.slice(source.indexOf("function combinedAPIEnvironment("), source.indexOf("async function beginPrecisionBrowserAcceptance("));
  for (const value of ["HOSTNAME", "ZASP_STYTCH_WEBHOOK_SECRET", "ZASP_SECURITY_AGENT_POSTGRES_DSN", "ZASP_DISCOVERY_PARSER_VERSION", "ZASP_DISCOVERY_TOOL_VERSION", "ZASP_AWS_CUSTOMER_ROLE_PREFIXES", "ZASP_AWS_CUSTOMER_ROLE_ARNS", "ZASP_KUBERNETES_EGRESS_CIDRS", "ZASP_FINDING_TICKET_EGRESS_CIDRS"]) assert.match(apiEnvironment, new RegExp(value));
  const outboxBoundary = source.slice(source.indexOf("const outbox = startTask4Worker"), source.indexOf("for (const candidate of", source.indexOf("const outbox = startTask4Worker")));
  assert.match(outboxBoundary, /waitForChildExit\(outbox, 10_000\)/);
  assert.match(outboxBoundary, /status: 1, signal: null/);
  assert.doesNotMatch(outboxBoundary, /assertFailClosedTask4Worker/);
  const discoveryBrowserBoundary = source.slice(source.indexOf("async function assertTask4BrowserPublicState"), source.indexOf("async function navigateBrowser", source.indexOf("async function assertTask4BrowserPublicState")));
  assert.equal(discoveryBrowserBoundary.match(/await waitForBrowserText\(cdp, \/Risk projection: pending\/\)/g)?.length, 2);
  assert.equal(discoveryBrowserBoundary.match(/await waitForBrowserText\(cdp, \/No automatic sync schedule\/\)/g)?.length, 2);
  assert.match(discoveryBrowserBoundary, /const \{ resources, \.\.\.persistentForensics \} = forensics/);
  assert.match(discoveryBrowserBoundary, /resources\.every\(\(resource\) => new URL\(resource\)\.origin === publicOrigin\)/);
  assert.doesNotMatch(source, /Shown only once/);
  const complianceStart = source.indexOf("async function exerciseComplianceBrowser(");
  const complianceEnd = source.indexOf("async function exerciseExistingTestMountedBrowser(");
  const complianceFlow = source.slice(complianceStart, complianceEnd);
  assert.doesNotMatch(source.slice(0, complianceStart) + source.slice(complianceEnd), /"Page\.(?:navigate|reload)"/);
  assert.equal(complianceFlow.match(/"Page.navigate"/g)?.length, 2, "source inspection and restart recovery preserve the user's tab storage");
  assert.match(complianceFlow, /await reloadBrowser\(cdp\)/);
  assert.match(complianceFlow, /storedComplianceJSON/);
  assert.match(complianceFlow, /Browser.setDownloadBehavior/);
  assert.doesNotMatch(source, /zasp_execution_(?:finish_job|finish_projection|apply_complete_snapshot)\s*\(/i);
  const seedBoundary = source.slice(source.indexOf("async function seedPostgres"), source.indexOf("async function exercisePublicDiscoveryLifecycle"));
  assert.doesNotMatch(seedBoundary, /INSERT INTO zasp_inventory_/i);
  assert.doesNotMatch(seedBoundary, /'(?:home|agents|tools|identities|runtimes|(?:agent|tool|identity|runtime|asset):pid_[0-9a-f-]{36}|agent_(?:capabilities|relationships|sessions):pid_[0-9a-f-]{36})'/i);
	const securityAgentBoundary = source.slice(source.indexOf("async function exerciseSecurityAgentAutomaticLifecycle"), source.indexOf("async function", source.indexOf("async function exerciseSecurityAgentAutomaticLifecycle") + 15));
	for (const value of ["security-agent", "zasp_security_agent_worker", "30s", "Validate definition", "Enable supervised execution", "Approve", "autonomous", "pid_90000001-0000-4000-8000-000000000001", "Apply temporary containment policy", "Isolate runtime session", "TTL 600s", "create_temporary_policy", "isolate_session", "runTemporaryPolicyActionWorker", "cleanup_pending", "remediated\\|cleaned\\|4\\|3", "contained\\|cleanup_pending\\|1\\|3\\|0", "remediated\\|cleaned\\|2\\|4", "Revoke integration connection", "Identity administrator approval required", "revoke_integration_connection", "runConnectorRevocationProviderWorker", "INSERT INTO zasp_risk_finding_evidence", "remediated\\|verified\\|verified\\|revoked\\|revoked\\|pending\\|pending_authorization"]) assert.match(securityAgentBoundary, new RegExp(value));
	for (const field of ["artifact_reference", "artifact_key", "artifact_version_id", "size_bytes", "tool_version"]) assert.match(securityAgentBoundary, new RegExp(field));
	const connectorWorkerBoundary = source.slice(source.indexOf("async function runConnectorRevocationProviderWorker"), source.indexOf("async function", source.indexOf("async function runConnectorRevocationProviderWorker") + 15));
	for (const value of ["TestProductionCombinedE2EConnectorRevocationWorker", "real connector reconciler revoked exact reference", "ZASP_COMBINED_E2E_CONNECTOR_REFERENCE"]) assert.match(connectorWorkerBoundary, new RegExp(value));
	assert.match(connectorWorkerBoundary, /ZASP_COMBINED_E2E_CONNECTOR_DSN: `postgres:\/\/zasp_e2e_api@/);
	assert.match(source, /ZASP_COMBINED_E2E_GATEWAY_DSN: `postgres:\/\/zasp_e2e_gateway_control@/);
	assert.doesNotMatch(source, /ZASP_COMBINED_E2E_GATEWAY_DSN: `postgres:\/\/zasp_e2e_gateway@/);
	assert.doesNotMatch(securityAgentBoundary, /zasp_security_agent_(?:schedule_triggers|prepare_run|execute_run)(?:_v21)?\s*\(/i);
	assert.match(securityAgentBoundary, /NOT EXISTS\(SELECT 1 FROM zasp_security_agent_runs run WHERE \(run\.organization_id,run\.workspace_id,run\.environment_id,run\.run_id\)=\(effect\.organization_id,effect\.workspace_id,effect\.environment_id,effect\.run_id\)\)/i);
	assert.doesNotMatch(securityAgentBoundary, /JOIN zasp_security_agent_runs run USING\(organization_id,workspace_id,environment_id,run_id\)[\s\S]*effect\.organization_id<>run\.organization_id/i);
	const recoveryBoundary = source.slice(source.indexOf("async function runProductionRecoveryLifecycle"), source.indexOf("async function", source.indexOf("async function runProductionRecoveryLifecycle") + 15));
	for (const value of ["backup", "start", "--credential-file", "--ca-bundle-file", "TestProductionCombinedE2ERecoveryWorker", "ZASP_COMBINED_E2E_RECOVERY_ARTIFACT_FILE", "/administration/recovery", "Start restore rehearsal", "committed recovery response loss replayed one backup, outbox, audit, and receipt", "cross-tenant recovery read rejected", "signed recovery manifest published last", "Temporary resources deleted"]) assert.match(recoveryBoundary, new RegExp(value));
	assert.match(recoveryBoundary, /recoveryOrigin\.origin}\/api\/v1\/recovery\/backups/);
	assert.match(recoveryBoundary, /JSON\.stringify\(\{ backup_id: foreignBackupID, retention_days: 30 \}\)/);
	assert.doesNotMatch(recoveryBoundary, /publicOrigin}\/api\/v1\/recovery\/backups/);
	assert.ok(recoveryBoundary.indexOf('document.readyState !== "loading"') < recoveryBoundary.indexOf("sessionStorage.setItem"), "recovery state was written before the replacement product document loaded");
	assert.match(recoveryBoundary, /recovery session state was not retained in the loaded product document/);
	assert.doesNotMatch(recoveryBoundary, /zasp_recovery_(?:finish_backup|finish_restore|fail_operation|acknowledge_outbox)\s*\(/i);
	const recoveryWorkerBoundary = recoveryWorkerSource.slice(recoveryWorkerSource.indexOf("func TestProductionCombinedE2ERecoveryWorker"), recoveryWorkerSource.indexOf("func combinedE2ERecoveryDatabase"));
	for (const value of ["composeRecoveryOutboxWorkerRuntime", "composeRecoveryWorkerRuntime", ".Ready(ctx)", ".Processor.RunOnce(ctx)", ".Close()"]) assert.match(recoveryWorkerBoundary, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
	assert.doesNotMatch(recoveryWorkerBoundary, /newRecovery(?:Outbox|Backup|Restore)Processor/);
	const attackLabBoundary = recoveryWorkerSource.slice(recoveryWorkerSource.indexOf("func TestProductionCombinedE2EAttackLabWorker"), recoveryWorkerSource.indexOf("func TestProductionCombinedE2ERecoveryWorker"));
	for (const value of ["composeAttackLabOutboxWorkerRuntime", "composeAttackLabWorkerRuntime", ".Ready(ctx)", ".Processor.RunOnce(ctx)", ".Close()", "ZASP_COMBINED_E2E_ATTACK_LAB_EXPECT_CANCELLED", "composed Attack Lab outbox and controller acknowledged cancelled run without sandbox side effects"]) assert.match(attackLabBoundary, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
	assert.doesNotMatch(attackLabBoundary, /newAttackLab(?:Outbox|Processor)/);
  for (const unsafeControl of ["Start bounded run", "waiting_approval", "Simulate policy", "Decision history"]) {
    const escaped = unsafeControl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    assert.doesNotMatch(source, new RegExp(`(?:clickBrowserText|clickBrowserTextContains|clickBrowserAria)\\([^\\n]*${escaped}`, "i"));
  }
  assert.doesNotMatch(source, /(?:^|[/])\.env(?:$|[/ ])|--env-file|dotenv|kubectl|localhost:\d{2,5}|docker\.sock|--privileged|--network[= ]host/i);
  // Direct Docker calls may only inspect a pinned cached image or read logs from
  // the owned PostgreSQL ID. Lifecycle modules enforce labels and exact cleanup.
  assert.deepEqual([...source.matchAll(/command\("docker",\s*(\[[^\n]+?\])/g)].map(match => match[1]), [
    '["logs","--tail","250",postgres.containerID]',
    '["exec",postgres.containerID,"test","-x",collectorContainerPath]',
    '["exec",postgres.containerID,"stat","-c","%a %u %g",collectorContainerPath]',
    '["image","inspect","localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c"]',
    '["image", "inspect", "--format", "{{.Architecture}}", image]',
  ]);
  assert.match(source, /if\(existingTestMountedMode && postgres\.containerID\)/);
  assert.match(source, /createRuntimePipelineDependencies\(command\)/);
  assert.match(source, /createRedTeamRuntimeProof\(command\)/);
  assert.match(source, /mountedRuntimeProofs\.push\(proof\);try\{const result=await proof\.run/);
});

test("mounted acceptance rejects Docker pull and build before allocating an owned command", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function command(executable, args, options = {}) {");
  const end = source.indexOf("\nasync function reservePort()", start);
  assert.ok(start > 0 && end > start);
  const children = [], ownedCommands = new Map(), calls = [];
  const owner = { child: {}, completed: Promise.resolve({ status: 0, stdout: "owned", stderr: "" }) };
  const command = runInNewContext(`(${source.slice(start, end)})`, {
    currentComplianceClosing: false, currentComplianceFailure: undefined, existingTestMountedMode: true, root: "/owned", temporaryRoot: "/owned/tmp", process: { env: {} }, path,
    auditBrowserEnvironment: () => ({ bounded: "true" }), children, ownedCommands, setTimeout, clearTimeout,
    spawnOwnedCommand: (...args) => { calls.push(args); return owner; },
  });
  for (const verb of ["pull", "build"]) await assert.rejects(command("docker", [verb, "unapproved"]), /mounted acceptance forbids/);
  assert.deepEqual(calls, []);
  assert.deepEqual(children, []);
  assert.equal(ownedCommands.size, 0);
  for (const args of [["image", "inspect", "cached@sha256:owned"], ["logs", "--tail", "250", "owned-container"]]) {
    assert.equal((await command("docker", args)).stdout, "owned");
    assert.equal(calls.at(-1)[0], "docker");
    assert.deepEqual(calls.at(-1)[1], args);
    assert.equal(children.at(-1), owner.child);
    assert.equal(ownedCommands.get(owner.child), owner);
  }
});

test("owned cleanup is idempotent", async () => {
	let calls = 0;
	const controller = installBoundedSignalCleanup(async () => { calls += 1; }, { timeout: 100 });
	try {
		const first = controller.run();
		const second = controller.run();
		assert.equal(first, second);
		await Promise.all([first, second]);
		assert.equal(calls, 1);
	} finally {
		controller.dispose();
	}
});

test("failed checkpoint or provider joins retain errors and files while other owned resources close", async t => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function cleanupOwnedResources() {");
  const end = source.indexOf("\nasync function generateHarnessGitHubAppPrivateKey", start);
  assert.ok(start > 0 && end > start);
  // Execute the actual cleanup function, substituting only its owned external
  // process/server boundaries so a failed join is deterministic and bounded.
  for (const failureAt of ["checkpoint", "mounted first", "provider", "graph", "browser", "audit provider", "postgres", ""]) {
    await t.test(failureAt || "all closed", async () => {
    const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "zasp-cleanup-order-test-"));
    const events = [], expectedError = new Error(`${failureAt} cleanup rejected`);
    const close = async name => { events.push(name); if (name === failureAt) throw expectedError; };
    const cleanup = runInNewContext(`(${source.slice(start, end)})`, {
      currentComplianceStateRoot: undefined, currentComplianceClosing: false, currentComplianceProjectionController: undefined, currentComplianceProjectionLoop: undefined, currentComplianceServices: undefined, currentCompliancePostgres: undefined,
      console: { log() {} }, AggregateError, temporaryRoot, exportBrowserProfiles: [], exportBrowserAPILifetimes: [], exportBrowserEvidenceDirectory: null, automaticDiscoveryEvidenceDirectory: null,
      precisionBrowserCheckpoint: { close: () => close("checkpoint") }, runtimePipelineChild: "provider",
      mountedRuntimeProofs: ["mounted first", "mounted second"].map(name => ({ close: () => close(name) })),
      runtimeGraphDependency: { close: () => close("graph") }, redTeamRuntimeProof: { close: () => close("redteam") }, runtimePipelineDependencies: { close: () => close("aws/search") },
      secondBrowserTab: { dispose: () => close("second tab") }, browser: { cdp: { close: () => { events.push("cdp"); } }, child: "browser" },
      task4Workers: ["task4"], api: "api", proxy: "proxy", identity: "identity", policyHistory: "policy history", web: "web", postgres: "postgres", children: ["remaining child"],
      auditExportProvider: {stop:()=>close("audit provider")},
      stopChild: close, closeServer: close, stopPostgres: close,
      rm: async (...args) => { events.push("files"); await rm(...args); },
    });
    try {
      let caught;
      try { await cleanup(); } catch (error) { caught = error; }
      assert.deepEqual(events, ["checkpoint", "mounted first", "mounted second", "provider", "graph", "redteam", "aws/search", "second tab", "cdp", "browser", "task4", "api", "proxy", "identity", "policy history", "web", "audit provider", "postgres", "remaining child", ...(failureAt ? [] : ["files"])]);
      if (failureAt) {
        assert.ok(caught instanceof AggregateError, "cleanup lost collected errors");
        assert.ok(caught.errors.includes(expectedError), "cleanup replaced original failure");
        assert.deepEqual(await readdir(temporaryRoot), [], "failed join deleted its owned root");
      } else {
        assert.equal(caught, undefined);
        await assert.rejects(readdir(temporaryRoot), { code: "ENOENT" });
      }
    } finally {
      // Empty-only removal cannot hide files leaked by the cleanup under test.
      await rmdir(temporaryRoot).catch(error => { if (error.code !== "ENOENT") throw error; });
    }
    });
  }
});

test("combined PostgreSQL startup registers its owner before readiness rejects", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function startPostgres(port)");
  const end = source.indexOf("async function provisionPostgresPrincipals", start);
  const failure = new Error("owned readiness rejected");
  const owner = { start: async () => { throw failure; }, stop: async () => { owner.stopped = true; } };
  const context = { process: { env: { ZASP_RECONCILIATION_API_LOAD_DIAGNOSTIC: "1" } }, postgres: undefined, automaticDiscoveryMode: false, attackLabMountedMode: false, securityAgentExportMode: false,
    path, temporaryRoot: "/unused", postgresBin: "/unused", command: async () => { throw failure; },
    createOwnedBrowserPostgres: options => { assert.deepEqual(JSON.parse(JSON.stringify(options)), { port: 54321, trackFunctions: true }); return owner; } };
  const flow = runInNewContext(`(async () => { ${source.slice(start, end)} try { await startPostgres(54321); } catch (error) { if (postgres) await stopPostgres(postgres); throw error; } })`, context);
  await assert.rejects(flow(), error => error === failure);
  assert.equal(context.postgres, owner);
  assert.equal(owner.stopped, true);
});

test("retirement diagnostic rejects dead owned container despite a live Docker CLI child", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseConcurrentRetirementLoad(");
  const end = source.indexOf("async function runProductionRecoveryLifecycle", start);
  const failure = new Error("owned container exited");
  const run = runInNewContext(`(${source.slice(start, end)})`, { assert, URL, Date, path, postgresBin: "/unused",
    command: async () => { throw new Error("SQL reached before owned container liveness check"); },
    postgres: { child: { exitCode: null }, assertRunning: async () => { throw failure; } } });
  await assert.rejects(run("postgres://zasp_e2e@127.0.0.1:54321/postgres"), error => error === failure);
});

test("combined production E2E removes owned processes and temp root on SIGTERM", { timeout: 90_000 }, async () => {
  const temporaryParent = await mkdtemp(path.join(os.tmpdir(), "zasp-signal-test-"));
  // Another harness can create a similarly named root concurrently. Only this
  // child's private TMPDIR is evidence of ownership, never a global set difference.
  const unrelatedRoot = await mkdtemp(path.join(os.tmpdir(), "zasp-production-e2e-"));
  // Early PostgreSQL shutdown must not construct the unused Docker dependency.
  // This synthetic non-secret variable reproduces a forbidden inherited CI env.
  const child = spawn(process.execPath, [fileURLToPath(new URL("./production-combined-e2e.mjs", import.meta.url))], { env: { ...process.env, TMPDIR: temporaryParent, AWS_REGION: "synthetic-cleanup-regression" }, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (value) => { output += value; });
  child.stderr.on("data", (value) => { output += value; });
  try {
  await waitFor(() => output.includes("combined E2E: disposable PostgreSQL ready") || child.exitCode !== null || child.signalCode !== null, 20_000, () => output);
  assert.equal(child.exitCode, null, output);
  assert.equal(child.signalCode, null, output);
  const owned = (await readdir(temporaryParent)).filter((value) => value.startsWith("zasp-production-e2e-"));
  assert.equal(owned.length, 1, `owned roots: ${owned.join(", ")}`);
  const ownedRoot = path.join(temporaryParent, owned[0]);
  child.kill("SIGTERM");
  const [status, signal] = await Promise.race([once(child, "exit"), rejectAfter(45_000, () => `harness did not exit after SIGTERM: ${output}`)]);
  assert.equal(signal, null);
  assert.equal(status, 143);
  assert.equal((await readdir(temporaryParent)).includes(owned[0]), false, `temporary root survived: ${ownedRoot}`);
  assert.equal((await readdir(os.tmpdir())).includes(path.basename(unrelatedRoot)), true, "unrelated root was removed");
  const processes = spawnSync("ps", ["-axo", "command="], { encoding: "utf8" });
  assert.equal(processes.status, 0);
  assert.doesNotMatch(processes.stdout, new RegExp(escapeRegExp(ownedRoot)));
  assert.match(output, /combined E2E: cleanup files/);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), rejectAfter(45_000, () => output)]);
    }
    // Empty-directory removal preserves evidence if the harness leaked files.
    await rmdir(unrelatedRoot);
    const processes = spawnSync("ps", ["-axo", "command="], { encoding: "utf8" });
    assert.equal(processes.status, 0);
    assert.doesNotMatch(processes.stdout, new RegExp(escapeRegExp(temporaryParent)));
    // Interrupted go run can leave an empty compiler scratch directory outside
    // the harness root. Remove only those empty, exact child directories.
    for (const entry of await readdir(temporaryParent, { withFileTypes: true })) {
      if (entry.isDirectory() && /^go-build[0-9]+$/.test(entry.name)) {
        await rmdir(path.join(temporaryParent, entry.name));
      }
    }
    await rmdir(temporaryParent);
  }
});

test("combined runtime proof removes owned containers and processes on real SIGTERM", { timeout: 240_000, skip: process.env.ZASP_RUNTIME_PIPELINE_SIGNAL_TEST !== "true" }, async () => {
  const listContainers = () => {
    const ids = new Set();
    for (const label of ["zasp.proof=runtime-pipeline", "com.zasp.proof=neo4j-graphstore"]) {
      const result = spawnSync("docker", ["ps", "--all", "--quiet", "--no-trunc", "--filter", `label=${label}`], { encoding: "utf8", timeout: 5000 });
      assert.equal(result.status, 0);
      for (const id of result.stdout.trim().split("\n").filter(Boolean)) ids.add(id);
    }
    return ids;
  };
  const isProofRoot = (value) => value.startsWith("zasp-production-e2e-") || value.startsWith("zasp-m1-16-");
  const beforeContainers = listContainers();
  const beforeRoots = new Set((await readdir(os.tmpdir())).filter(isProofRoot));
  const child = spawn(process.execPath, [fileURLToPath(new URL("./production-combined-e2e.mjs", import.meta.url))], { env: { ...process.env, ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY: "true" }, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (value) => { output += value; });
  child.stderr.on("data", (value) => { output += value; });
  try {
    await waitFor(() => output.includes("combined E2E: owned runtime dependencies ready") || child.exitCode !== null, 180_000, () => output);
    assert.equal(child.exitCode, null, output);
    const ownedContainers = [...listContainers()].filter((id) => !beforeContainers.has(id));
    const ownedRoots = (await readdir(os.tmpdir())).filter((value) => isProofRoot(value) && !beforeRoots.has(value));
    assert.equal(ownedContainers.length, 3);
    assert.equal(ownedRoots.length, 2);
    child.kill("SIGTERM");
    const [status, signal] = await Promise.race([once(child, "exit"), rejectAfter(45_000, () => output)]);
    assert.equal(status, 143, output);
    assert.equal(signal, null);
    for (const id of ownedContainers) assert.equal(listContainers().has(id), false, `owned container survived: ${id}`);
    for (const root of ownedRoots) assert.equal((await readdir(os.tmpdir())).includes(root), false);
    const processes = spawnSync("ps", ["-axo", "command="], { encoding: "utf8" });
    assert.equal(processes.status, 0);
    for (const root of ownedRoots) assert.doesNotMatch(processes.stdout, new RegExp(escapeRegExp(path.join(os.tmpdir(), root))));
    assert.match(output, /combined E2E: cleanup files/);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), rejectAfter(45_000, () => output)]);
    }
  }
});

// Four action children now have 120s ceilings, adding 240s to the prior bounds.
test("composed Red Team runtime removes its owned container on real SIGTERM", { timeout:660_000, skip:process.env.ZASP_RED_TEAM_RUNTIME_SIGNAL_TEST!=="true" }, async()=>{
  const beforeRoots=new Set((await readdir(os.tmpdir())).filter(value=>value.startsWith("zasp-production-e2e-")));
  const child=spawn(process.execPath,[fileURLToPath(new URL("./production-combined-e2e.mjs",import.meta.url))],{env:{...process.env,ZASP_COMBINED_E2E_RED_TEAM_RUNTIME:"true"},stdio:["ignore","pipe","pipe"]});
  let output="";child.stdout.on("data",value=>{output+=value;});child.stderr.on("data",value=>{output+=value;});
  try{
    await waitFor(()=>output.includes("browser-created Red Team definition and run ready for pinned runtime") || child.exitCode!==null,600_000,()=>output);
    assert.equal(child.exitCode,null,output);
    const roots=(await readdir(os.tmpdir())).filter(value=>value.startsWith("zasp-production-e2e-")&&!beforeRoots.has(value));
    assert.equal(roots.length,1);
    const ownedRoot=path.join(os.tmpdir(),roots[0]);
    let ownedID;
    await waitFor(()=>{
      const result=spawnSync("docker",["ps","--all","--quiet","--no-trunc","--filter","label=zasp.proof=red-team-runtime"],{encoding:"utf8",timeout:3000});
      assert.equal(result.status,0);
      for(const id of result.stdout.trim().split("\n").filter(Boolean)){
        const inspect=spawnSync("docker",["inspect",id],{encoding:"utf8",timeout:3000});
        if(inspect.status!==0)continue;
        const record=JSON.parse(inspect.stdout)[0];
        if(record.Mounts?.some(mount=>mount.Source===path.join(ownedRoot,"red-team-worker.test"))&&record.State?.Running){ownedID=id;return true;}
      }
      return false;
    },15_000,()=>output);
    child.kill("SIGTERM");
    const [status,signal]=await Promise.race([once(child,"exit"),rejectAfter(45_000,()=>output)]);
    assert.equal(status,143,output);assert.equal(signal,null);
    const remaining=spawnSync("docker",["inspect",ownedID],{encoding:"utf8",timeout:3000});
    assert.notEqual(remaining.status,0);assert.match(remaining.stderr,/No such (object|container)/i);
    assert.equal((await readdir(os.tmpdir())).includes(roots[0]),false);
    const processes=spawnSync("ps",["-axo","command="],{encoding:"utf8"});assert.equal(processes.status,0);assert.doesNotMatch(processes.stdout,new RegExp(escapeRegExp(ownedRoot)));
    assert.match(output,/combined E2E: cleanup files/);
  }finally{if(child.exitCode===null&&child.signalCode===null){child.kill("SIGTERM");await Promise.race([once(child,"exit"),rejectAfter(45_000,()=>output)]);}}
});

async function waitFor(predicate, timeout, describe) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail(describe());
}

function rejectAfter(milliseconds, describe) {
	return new Promise((_, reject) => {
		const timer = setTimeout(() => reject(new Error(describe())), milliseconds);
		timer.unref();
	});
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Run the published cleanup body with actual projection cancellation and finite
// owned boundary doubles. No services, database, browser or provider are started.
async function currentComplianceCleanupFixture({ failureAt, holdProjection = false } = {}) {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function cleanupOwnedResources() {");
  const end = source.indexOf("\nasync function generateHarnessGitHubAppPrivateKey", start);
  assert.ok(start > 0 && end > start);
  const events = [], failure = new Error("owned current fixture close rejected");
  const controller = new AbortController();
  let settleProjection;
  const loop = new Promise((resolve, reject) => {
    settleProjection = () => {
      events.push("projection joined");
      if (failureAt === "projection") reject(failure); else resolve();
    };
  });
  void loop.catch(() => {});
  controller.signal.addEventListener("abort", () => {
    events.push("projection canceled");
    if (!holdProjection) settleProjection();
  }, { once: true });
  const close = async name => { events.push(name); if (failureAt === name) throw failure; };
  let removed = false;
  const context = {
    console: { log() {} }, AggregateError, currentComplianceStateRoot: undefined, currentComplianceClosing: false,
    currentComplianceProjectionController: controller, currentComplianceProjectionLoop: loop,
    currentComplianceServices: { close: () => close("current services") },
    currentCompliancePostgres: { stop: () => close("current postgres") },
    temporaryRoot: "/unused-owned-current-root", exportBrowserProfiles: [], exportBrowserAPILifetimes: [],
    exportBrowserEvidenceDirectory: null, automaticDiscoveryEvidenceDirectory: null,
    precisionBrowserCheckpoint: undefined, mountedRuntimeProofs: [], runtimePipelineChild: undefined,
    runtimeGraphDependency: undefined, redTeamRuntimeProof: { close: async () => {} },
    runtimePipelineDependencies: { close: async () => {} }, secondBrowserTab: undefined,
    browser: undefined, task4Workers: [], api: undefined, proxy: undefined, identity: undefined,
    policyHistory: undefined, web: undefined, auditExportProvider: undefined,
    postgres: "legacy postgres", stopPostgres: () => close("legacy postgres"), children: [],
    rm: async () => { events.push("files"); removed = true; },
  };
  const cleanup = runInNewContext(`(${source.slice(start, end)})`, context);
  return { cleanup, context, controller, events, failure, settleProjection, removed: () => removed };
}

test("current compliance cleanup cancels and joins projection before services and both PostgreSQL owners", async () => {
  const fixture = await currentComplianceCleanupFixture({ holdProjection: true });
  let completed = false;
  const cleanup = fixture.cleanup().then(() => { completed = true; });
  try {
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(fixture.controller.signal.aborted, true);
    assert.equal(fixture.context.currentComplianceClosing, true);
    assert.deepEqual(fixture.events, ["projection canceled"]);
    assert.equal(completed, false, "cleanup declared closed before projection joined");
    assert.equal(fixture.removed(), false);
  } finally {
    fixture.settleProjection();
    await cleanup;
  }
  assert.deepEqual(fixture.events, ["projection canceled", "projection joined", "current services", "current postgres", "legacy postgres", "files"]);
  assert.equal(fixture.removed(), true);
});

test("current compliance cleanup retains each original failure while joining later owners and retaining files", async () => {
  for (const failureAt of ["projection", "current services", "current postgres"]) {
    const fixture = await currentComplianceCleanupFixture({ failureAt });
    await assert.rejects(fixture.cleanup(), error => error instanceof AggregateError && error.errors.includes(fixture.failure));
    assert.equal(fixture.controller.signal.aborted, true);
    assert.equal(fixture.context.currentComplianceClosing, true);
    assert.deepEqual(fixture.events, ["projection canceled", "projection joined", "current services", "current postgres", "legacy postgres"]);
    assert.equal(fixture.removed(), false, "failed current join deleted owned state");
  }
});
