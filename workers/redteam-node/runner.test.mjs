import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";

import { buildPromptfooConfiguration, normalizePromptfooResult, parseUniqueJson, promptfooChildEnvironment, waitForPromptfooProcess } from "./runner.mjs";

test("launcher cancellation kills and reaps its engine before rejecting",async()=>{
  for(const signal of ["SIGINT","SIGTERM"]){
    const child=new EventEmitter(),signals=new EventEmitter(),kills=[];
    child.kill=value=>{kills.push(value);return true;};
    let settled=false;
    const pending=waitForPromptfooProcess(child,signals);
    const rejected=assert.rejects(pending,/interrupted/).then(()=>{settled=true;});
    signals.emit(signal);await Promise.resolve();
    assert.deepEqual(kills,["SIGKILL"]);assert.equal(settled,false,"launcher returned before engine exit");
    child.emit("exit",null,"SIGKILL");await rejected;
    assert.equal(signals.listenerCount("SIGTERM"),0);assert.equal(signals.listenerCount("SIGINT"),0);
  }
});
test("completed engine preserves its exact exit code and removes signal listeners",async()=>{
  const child=new EventEmitter(),signals=new EventEmitter();child.kill=()=>assert.fail("completed engine was killed");
  const pending=waitForPromptfooProcess(child,signals);child.emit("exit",100,null);
  assert.equal(await pending,100);assert.equal(signals.listenerCount("SIGTERM"),0);assert.equal(child.listenerCount("error"),0);
});
test("engine spawn error rejects without leaving cancellation listeners",async()=>{
  const child=new EventEmitter(),signals=new EventEmitter();child.kill=()=>true;
  const pending=waitForPromptfooProcess(child,signals);child.emit("error",new Error("owned fixture spawn failed"));
  await assert.rejects(pending,/spawn failed/);assert.equal(signals.listenerCount("SIGINT"),0);assert.equal(child.listenerCount("exit"),0);
});

const input = Object.freeze({
  schema_version: "red-team-runner-input-v1",
  organization_id: "pid_99300001-0000-4000-8000-000000000001",
  workspace_id: "pid_99300002-0000-4000-8000-000000000002",
  environment_id: "pid_99300003-0000-4000-8000-000000000003",
  run_id: "pid_99300004-0000-4000-8000-000000000004",
  definition_id: "pid_99300005-0000-4000-8000-000000000005",
  definition_version: 1,
  target_id: "pid_99300006-0000-4000-8000-000000000006",
  target_kind: "agent_endpoint",
  categories: ["prompt_injection", "tool_abuse"],
  input_digest: "a".repeat(64),
});

test("buildPromptfooConfiguration emits only curated prompts and the fixed adapter", () => {
  const configuration = buildPromptfooConfiguration(input, "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate");
  assert.equal(configuration.providers[0].config.url, "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate");
  assert.deepEqual(configuration.tests.map((item) => item.metadata.category), input.categories);
  assert.equal(configuration.tests.every((item) => item.vars.prompt.includes("ZASP_RED_TEAM_")), true);
  assert.doesNotMatch(JSON.stringify(configuration), /secret|api[_-]?key|production_write/i);
});

test("normalizePromptfooResult retains bounded product evidence and no native response", () => {
  const results = input.categories.map((category, index) => ({
    success: index === 0,
    provider: { label: "zasp-red-team-adapter" },
    vars: { category, prompt: buildPromptfooConfiguration(input, "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate").tests[index].vars.prompt },
    testCase: { metadata: { category } },
    response: { metadata: { http: { status: 200 } }, output: index === 0 ? "safe" : "ZASP_RED_TEAM_TOOL_ABUSE" },
    gradingResult: { pass: index === 0 },
  }));
  const normalized = normalizePromptfooResult(input, { metadata: { promptfooVersion: "0.121.19" }, results: { version: 3, results } });
  assert.equal(normalized.verdict, "fail");
  assert.equal(normalized.evidence.length, 2);
  assert.deepEqual(Object.keys(normalized).sort(), ["behavior", "engine", "engine_version", "error_code", "evidence", "input_digest", "objective", "run_id", "schema_version", "verdict"].sort());
  assert.doesNotMatch(JSON.stringify(normalized), /ZASP_RED_TEAM_|"output"|"response"|"provider"/i);
});

test("runner rejects arbitrary categories, endpoints, and mismatched provider results", () => {
  assert.throws(() => buildPromptfooConfiguration({ ...input, categories: ["custom_prompt"] }, "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate"));
  assert.throws(() => buildPromptfooConfiguration(input, "https://example.com/v1/evaluate"));
  assert.throws(() => normalizePromptfooResult(input, { metadata: { promptfooVersion: "0.121.19" }, results: { version: 3, results: [] } }));
  assert.throws(() => parseUniqueJson('{"run_id":"first","run_id":"second"}', 1024));
});

test("promptfoo child receives only the pinned internal CA and bounded runtime authority", () => {
  const environment = promptfooChildEnvironment("/tmp/run", "t".repeat(64), "/var/run/secrets/zasp-red-team/adapter-ca.crt", "a".repeat(32));
	assert.equal(environment.ZASP_RED_TEAM_RUN_LEASE,"a".repeat(32));
  assert.equal(environment.NODE_EXTRA_CA_CERTS, "/var/run/secrets/zasp-red-team/adapter-ca.crt");
  assert.equal(environment.ZASP_RED_TEAM_ADAPTER_TOKEN, "t".repeat(64));
  assert.deepEqual(Object.keys(environment).sort(), ["HOME", "NODE_EXTRA_CA_CERTS", "PROMPTFOO_CACHE_ENABLED", "PROMPTFOO_CONFIG_DIR", "PROMPTFOO_DISABLE_ERROR_LOG", "PROMPTFOO_DISABLE_REMOTE_GENERATION", "PROMPTFOO_DISABLE_TELEMETRY", "PROMPTFOO_DISABLE_UPDATE", "ZASP_RED_TEAM_ADAPTER_TOKEN", "ZASP_RED_TEAM_RUN_LEASE"].sort());
	for(const lease of [undefined,"","a".repeat(31),"A".repeat(32),"a".repeat(33)]) assert.throws(()=>promptfooChildEnvironment("/tmp/run","t".repeat(64),"/tmp/ca.crt",lease));
  assert.throws(() => promptfooChildEnvironment("/tmp/run", "t".repeat(64), "relative-ca.crt"));
});
