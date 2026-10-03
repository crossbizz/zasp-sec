import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import test from "node:test";
import { load, JSON_SCHEMA } from "js-yaml";
const require = createRequire(import.meta.url);
const generator = createRequire(require.resolve("openapi-typescript"));
const validator = createRequire(generator.resolve("@redocly/openapi-core"));
const Ajv2020 = validator("@redocly/ajv/dist/2020.js").default;
const document = load(await readFile(new URL("./openapi.yaml", import.meta.url), "utf8"), { schema: JSON_SCHEMA });
function schema(name) {
  return new Ajv2020({ strict: false, allErrors: true, validateFormats: false }).compile({ components: document.components, $ref: `#/components/schemas/${name}` });
}
const action = schema("SecurityAgentActionArguments");
const input = schema("SecurityAgentInput");
const id = "pid_81000001-0000-4000-8000-000000000001";
const argumentsFor = mode => ({ target_id: id, mode, scope: id, ttl_seconds: 600 });
const definition = { name: "Scoped temporary observation", trigger_kind: "finding", trigger_source: "credential", environment_ids: [id], autonomy: "supervised", max_steps: 1, max_duration_seconds: 900, temporary_policy_seconds: 600, ai_token_budget: 1000, concurrency_limit: 1, allowed_actions: ["create_temporary_policy"], verification_kind: "policy_state", definition_version: 1, enabled: false };
test("temporary policy accepts typed Monitor without changing legacy Block arguments", () => {
  assert.equal(action(argumentsFor("block")), true, JSON.stringify(action.errors));
  assert.equal(action(argumentsFor("monitor")), true, JSON.stringify(action.errors));
});
test("temporary policy refuses permanent, unbounded and unknown-mode arguments", () => {
  for (const value of [{ ...argumentsFor("block"), ttl_seconds: 0 }, { ...argumentsFor("block"), ttl_seconds: 3601 }, { ...argumentsFor("block"), mode: "allow" }, { ...argumentsFor("block"), mode: null }, { target_id: id, mode: "block", scope: id }]) assert.equal(action(value), false);
});
test("definition persists selected Monitor and accepts explicit Block or legacy omission", () => {
  assert.equal(input(definition), true, JSON.stringify(input.errors));
  assert.equal(input({ ...definition, temporary_policy_mode: "monitor" }), true, JSON.stringify(input.errors));
  assert.equal(input({ ...definition, temporary_policy_mode: "block" }), true, JSON.stringify(input.errors));
});
test("definition refuses unknown temporary-policy mode", () => {
  for (const mode of ["allow", "permanent", null, 1]) assert.equal(input({ ...definition, temporary_policy_mode: mode }), false);
});

test("Monitor definition is supervised, single-action, bounded and never claims other verification", () => {
 const monitor = { ...definition, temporary_policy_mode: "monitor" };
 for (const delta of [{autonomy:"autonomous"},{max_steps:2},{temporary_policy_seconds:59},{temporary_policy_seconds:3601},{verification_kind:"test_run"},{allowed_actions:["create_temporary_policy","run_test"]},{allowed_actions:["run_test"]}]) assert.equal(input({...monitor,...delta}),false, JSON.stringify(delta));
});

test("approval schema truthfully represents temporary monitoring without accepting invented effects", () => {
 const approval = schema("SecurityAgentApproval");
 const value = { id, run_id:id, step_id:id, state:"pending", expires_at:"2026-10-03T10:00:00Z", version:1, expected_effect:"Apply temporary monitoring policy", reversible:true, ttl_seconds:600, evidence_summary:[id] };
 assert.equal(approval(value),true,JSON.stringify(approval.errors));
 assert.equal(approval({...value,expected_effect:"Apply permanent monitoring policy"}),false);
 for (const delta of [{ttl_seconds:0},{ttl_seconds:59},{ttl_seconds:3601},{reversible:false}]) assert.equal(approval({...value,...delta}),false,JSON.stringify(delta));
});
