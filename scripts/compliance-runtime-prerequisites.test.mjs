import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { complianceRuntimeBindings, complianceOwnedRuntimeInputs } from "./compliance-runtime-prerequisites.mjs";
const here = path.dirname(fileURLToPath(import.meta.url));
const candidate = path.join(here, "production-combined-e2e.mjs");
const selected = process.env.ZASP_COMPLIANCE_PREFLIGHT_SOURCE || candidate;
const complete = () => ({
  ZASP_RUNTIME_SERVICES_ENABLED: "true", ZASP_RUNTIME_SERVICES_TIMEOUT: "5s",
  ZASP_TEMPORAL_ADDRESS: "127.0.0.1:17233", ZASP_TEMPORAL_NAMESPACE: "owned-browser",
  ZASP_TEMPORAL_TASK_QUEUE: "owned-main", ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE: "owned-discovery",
  ZASP_OPENFGA_URL: "http://127.0.0.1:18088", ZASP_OPENFGA_STORE_ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  ZASP_OPENFGA_MODEL_ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ZASP_OPENFGA_TOKEN_FILE: "/tmp/owned-browser/token",
});
function prefix(source) {
  const start = source.indexOf("\ntry {\n");
  const end = source.indexOf("  const githubAppPrivateKey =", start);
  assert.ok(start > 0 && end > start);
  return source.slice(start + "\ntry {\n".length, end);
}
async function dispatchPrefix(environment, mode = true) {
  let resources = 0;
  const boundary = new Error("controlled first-owned-port boundary");
  const context = vm.createContext({ complianceBrowserMode: mode, automaticDiscoveryMode: false,
    complianceRuntimeBindings, complianceOwnedRuntimeInputs, process: { env: environment }, reservePort() { resources++; throw boundary; } });
  let error;
  try { await vm.runInContext(`(async()=>{${prefix(fs.readFileSync(selected,"utf8"))}})()`, context); } catch (caught) { error = caught; }
  return { error, resources, boundary };
}
test("compliance missing owned tool inputs refuses before preparation or compiler dispatch", async () => {
  const result = await dispatchPrefix({});
  assert.equal(result.resources, 0);
  assert.equal(result.error?.code, "ZASP_COMPLIANCE_RUNTIME_PREREQUISITE_REFUSED");
  assert.match(result.error.message, /ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT/);
});
test("complete runtime fields validate configuration only and preserve actual readiness gate", async () => {
  const env = complete(); const result = complianceRuntimeBindings(env);
  assert.equal(result.status, "CONFIG_VALIDATED_ONLY");
  assert.equal(result.runtimeReadiness, "NOT_CHECKED"); assert.equal(result.schemaReadiness, "NOT_CHECKED");
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.environment));
  assert.deepEqual(result.environment, env);
  for (const duration of ["0.000001ms", "0.000000001s", "30s"]) assert.equal(complianceRuntimeBindings({ ...env, ZASP_RUNTIME_SERVICES_TIMEOUT: duration }).status, "CONFIG_VALIDATED_ONLY");
  const dispatch = await dispatchPrefix({...env,ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT:"/owned/archives",ZASP_BROWSER_RUNTIME_RAW_ROOT:"/owned/raw"});
  assert.equal(dispatch.resources, 1); assert.equal(dispatch.error, dispatch.boundary);
});
test("noncompliance source path preserves its original owned preparation dispatch", async () => {
  const result = await dispatchPrefix({}, false);
  assert.equal(result.resources, 1); assert.equal(result.error, result.boundary);
});
test("incomplete and mismatched runtime config refuses without publishing input values", () => {
  const challenge = "private-preflight-canary-value";
  const mutations = [
    ["missing model", e => delete e.ZASP_OPENFGA_MODEL_ID],
    ["disabled", e => e.ZASP_RUNTIME_SERVICES_ENABLED = "false"],
    ["wrong flag", e => e.ZASP_RUNTIME_SERVICES_ENABLED = "TRUE"],
    ["overlong timeout", e => e.ZASP_RUNTIME_SERVICES_TIMEOUT = "31s"],
    ["zero timeout", e => e.ZASP_RUNTIME_SERVICES_TIMEOUT = "0s"],
    ["subnanosecond ms", e => e.ZASP_RUNTIME_SERVICES_TIMEOUT = "0.000000999999999999999ms"],
    ["subnanosecond s", e => e.ZASP_RUNTIME_SERVICES_TIMEOUT = "0.000000000999999999999s"],
    ["one ns over cap", e => e.ZASP_RUNTIME_SERVICES_TIMEOUT = "30.000000001s"],
    ["malformed timeout", e => e.ZASP_RUNTIME_SERVICES_TIMEOUT = challenge],
    ["shared queues", e => e.ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE = e.ZASP_TEMPORAL_TASK_QUEUE],
    ["bad namespace", e => e.ZASP_TEMPORAL_NAMESPACE = challenge + "!"],
    ["foreign Temporal", e => e.ZASP_TEMPORAL_ADDRESS = "192.0.2.1:7233"],
    ["invalid Temporal port", e => e.ZASP_TEMPORAL_ADDRESS = "127.0.0.1:65536"],
    ["foreign FGA", e => e.ZASP_OPENFGA_URL = "https://" + challenge + ".invalid"],
    ["URL credentials", e => e.ZASP_OPENFGA_URL = "http://" + challenge + "@127.0.0.1:8088"],
    ["URL path", e => e.ZASP_OPENFGA_URL += "/"],
    ["bad store", e => e.ZASP_OPENFGA_STORE_ID = challenge],
    ["bad model", e => e.ZASP_OPENFGA_MODEL_ID = "8" + e.ZASP_OPENFGA_MODEL_ID.slice(1)],
    ["relative token", e => e.ZASP_OPENFGA_TOKEN_FILE = challenge],
    ["traversal token", e => e.ZASP_OPENFGA_TOKEN_FILE = "/tmp/../" + challenge],
    ["partial TLS", e => e.ZASP_TEMPORAL_TLS_CA_FILE = "/tmp/owned/ca"],
    ["relative TLS", e => { e.ZASP_TEMPORAL_TLS_CA_FILE = "/tmp/owned/ca"; e.ZASP_TEMPORAL_TLS_CERT_FILE = "/tmp/owned/cert"; e.ZASP_TEMPORAL_TLS_KEY_FILE = challenge; }],
    ["relative FGA CA", e => e.ZASP_OPENFGA_TLS_CA_FILE = challenge],
    ["control text", e => e.ZASP_TEMPORAL_NAMESPACE = "owned\n" + challenge],
  ];
  for (const [name, mutate] of mutations) {
    const env = complete(); mutate(env);
    assert.throws(() => complianceRuntimeBindings(env), error => error.code === "ZASP_COMPLIANCE_RUNTIME_PREREQUISITE_REFUSED" && !error.message.includes(challenge), name);
  }
});
test("actual compliance API environment propagates validated owned runtime fields instead of ambient settings", () => {
  const source = fs.readFileSync(candidate,"utf8");
  const start = source.indexOf("function combinedAPIEnvironment(");
  const end = Math.min(...["\nfunction ","\nasync function "].map(marker=>source.indexOf(marker,start+1)).filter(index=>index>start));
  const exercise = source.indexOf("async function exerciseComplianceBrowser(");
  const environmentStart = source.indexOf("  const apiEnvironment=",exercise);
  const environmentEnd = source.indexOf("\n  const startAPI=",environmentStart);
  assert.ok(start>0&&end>start&&environmentStart>exercise&&environmentEnd>environmentStart);
  const env = {...complete(),ZASP_ENVIRONMENT:"test",ZASP_WORKER_FORWARD_SEED_FILE:"/owned/forward.seed"};
  complianceRuntimeBindings(env);
  const expression = source.slice(environmentStart,environmentEnd).trim().replace(/^const apiEnvironment=/,"").replace(/;$/u,"");
  const context = vm.createContext({process:{env:{ZASP_RUNTIME_SERVICES_ENABLED:"false",ZASP_OPENFGA_MODEL_ID:"ambient-invalid"}},auditBrowserMode:false,
    auditBrowserEnvironment:()=>({}),stytchWebhookSecret:"controlled-placeholder",closedOwnedAmbientEnvironment:()=>({}),
    configuration:{postgresPort:15432,apiPort:18080,healthPort:18081,identityPort:18082,policyHistoryPort:18083,apiDSN:"owned",currentRuntimeEnvironment:env},
    publicOrigin:"http://127.0.0.1:18084",postgresPort:15432,object:"controlled-object"});
  const actual = vm.runInContext(`${source.slice(start,end)};(${expression})`,context);
  for (const [key,value] of Object.entries(env)) assert.equal(actual[key],value);
  assert.equal(actual.ZASP_ENVIRONMENT,"test");
});
