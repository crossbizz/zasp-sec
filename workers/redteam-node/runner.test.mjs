import assert from "node:assert/strict";
import test from "node:test";

import { buildPromptfooConfiguration, normalizePromptfooResult, parseUniqueJson } from "./runner.mjs";

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
