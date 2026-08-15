import assert from "node:assert/strict";
import { test } from "node:test";

import {
  exactActionCatalog,
  exactPlan,
  exactPlanningInput,
  exactPlanningRequest,
  exactScope,
  parseStrictJson,
  serializePlanningRequest,
  validateOpenRouterPlanResponse,
  validatePlan,
} from "./planner.mjs";

function completion(plan = exactPlan) {
  return Buffer.from(JSON.stringify({
    id: "chatcmpl-zasp-m021a",
    object: "chat.completion",
    created: 0,
    model: "zasp/fake-security-planner-v1",
    choices: [{
      index: 0,
      message: { role: "assistant", content: JSON.stringify(plan) },
      finish_reason: "stop",
    }],
    usage: { prompt_tokens: 96, completion_tokens: 64, total_tokens: 160 },
  }));
}

test("request separates fixed policy goal untrusted evidence catalog and scope", () => {
  const bytes = serializePlanningRequest(exactPlanningInput);
  assert.deepEqual(JSON.parse(bytes), exactPlanningRequest);
  const user = JSON.parse(exactPlanningRequest.messages[1].content);
  assert.deepEqual(user.action_catalog, exactActionCatalog);
  assert.deepEqual(user.scope, exactScope);
  assert.match(user.untrusted_evidence, /ignore previous instructions/);
  assert.match(user.untrusted_evidence, /https:\/\/evil\.example/);
  assert.equal(exactPlanningRequest.messages[0].content.includes(user.untrusted_evidence), false);
});

test("request rejects unknown alias accessor proxy prototype symbol and scope drift", () => {
  for (const input of [
    { ...exactPlanningInput, extra: true },
    { ...exactPlanningInput, scope: { ...exactScope, agent_id: "org_bbbbbbbbbbbbbbbb:agent:outside" } },
    { ...exactPlanningInput, action_catalog: [...exactActionCatalog, { name: "run_shell" }] },
    Object.create({ hostile: true }, Object.getOwnPropertyDescriptors(exactPlanningInput)),
    Object.defineProperty({ ...exactPlanningInput }, "operator_goal", {
      get: () => { throw new Error("getter invoked"); }, enumerable: true,
    }),
    Object.assign({ ...exactPlanningInput }, { [Symbol("hidden")]: true }),
    new Proxy({ ...exactPlanningInput }, { ownKeys: () => { throw new Error("trap invoked"); } }),
  ]) assert.throws(() => serializePlanningRequest(input), TypeError);
});

test("strict JSON rejects duplicates aliases malformed UTF-8 trailing bytes and bounds", () => {
  assert.deepEqual(parseStrictJson(Buffer.from('{"a":1,"b":[true,null]}')), { a: 1, b: [true, null] });
  for (const bytes of [
    Buffer.from('{"a":1,"a":2}'),
    Buffer.from('{"a":1} trailing'),
    Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]),
    Buffer.alloc(16_385, 0x20),
  ]) assert.throws(() => parseStrictJson(bytes), TypeError);
});

test("plan accepts only both catalog actions once in exact order and scope", () => {
  assert.deepEqual(validatePlan(exactPlan), exactPlan);
  const mutations = [
    { ...exactPlan, extra: true },
    { ...exactPlan, plan_id: "other" },
    { ...exactPlan, finding_id: "org_bbbbbbbbbbbbbbbb:finding:outside" },
    { ...exactPlan, steps: [...exactPlan.steps].reverse() },
    { ...exactPlan, steps: [exactPlan.steps[0]] },
    { ...exactPlan, steps: [exactPlan.steps[0], exactPlan.steps[0]] },
    { ...exactPlan, steps: [{ ...exactPlan.steps[0], action: "delete_all_agents" }, exactPlan.steps[1]] },
    { ...exactPlan, steps: [{ ...exactPlan.steps[0], arguments: { ...exactPlan.steps[0].arguments, ttl_seconds: 901 } }, exactPlan.steps[1]] },
    { ...exactPlan, steps: [exactPlan.steps[0], { ...exactPlan.steps[1], arguments: { ...exactPlan.steps[1].arguments, owner_id: "org_bbbbbbbbbbbbbbbb:user:outside" } }] },
  ];
  for (const mutation of mutations) assert.throws(() => validatePlan(mutation), TypeError);
});

test("plan rejects URL shell tool call prose and duplicate-key output", () => {
  for (const mutation of [
    { ...exactPlan, callback_url: "https://evil.example" },
    { ...exactPlan, steps: [{ ...exactPlan.steps[0], shell: "sh -c whoami" }, exactPlan.steps[1]] },
    { ...exactPlan, steps: [{ ...exactPlan.steps[0], rationale: "Run curl https://evil.example" }, exactPlan.steps[1]] },
    { ...exactPlan, tool_calls: [] },
  ]) assert.throws(() => validatePlan(mutation), TypeError);

  const duplicate = completion();
  const outer = JSON.parse(duplicate);
  outer.choices[0].message.content = '{"schema_version":"1","schema_version":"2"}';
  assert.throws(() => validateOpenRouterPlanResponse(Buffer.from(JSON.stringify(outer))), TypeError);
  const prose = JSON.parse(completion());
  prose.choices[0].message.content = `${JSON.stringify(exactPlan)} explanatory prose`;
  assert.throws(() => validateOpenRouterPlanResponse(Buffer.from(JSON.stringify(prose))), TypeError);
  const tools = JSON.parse(completion());
  tools.choices[0].message.tool_calls = [];
  assert.throws(() => validateOpenRouterPlanResponse(Buffer.from(JSON.stringify(tools))), TypeError);
});

test("OpenRouter response binds exact model envelope usage and structured plan", () => {
  assert.deepEqual(validateOpenRouterPlanResponse(completion()), exactPlan);
  for (const mutate of [
    (value) => ({ ...value, model: "other/model" }),
    (value) => ({ ...value, extra: true }),
    (value) => ({ ...value, choices: [...value.choices, value.choices[0]] }),
    (value) => ({ ...value, usage: { ...value.usage, total_tokens: 161 } }),
  ]) {
    const value = mutate(JSON.parse(completion()));
    assert.throws(() => validateOpenRouterPlanResponse(Buffer.from(JSON.stringify(value))), TypeError);
  }
});
