import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { describe, it } from "node:test";
import { load, JSON_SCHEMA } from "js-yaml";

const require = createRequire(import.meta.url);
const generator = createRequire(require.resolve("openapi-typescript"));
const validator = createRequire(generator.resolve("@redocly/openapi-core"));
const Ajv2020 = validator("@redocly/ajv/dist/2020.js").default;
const document = load(await readFile(new URL("./openapi.yaml", import.meta.url), "utf8"), { schema: JSON_SCHEMA });
const validate = new Ajv2020({ strict: false, allErrors: true }).compile(document.components.schemas.HomeSummary);
const counts = { agent_count: 4, high_risk_paths: 0, verified_changes: 2, blocked_changes: 1, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0 };

describe("executable HomeSummary schema", () => {
  for (const [healthy, attention_required] of [[null, null], [true, false], [false, true]]) {
    it(`accepts status pair ${healthy}/${attention_required}`, () => assert.equal(validate({ ...counts, healthy, attention_required }), true, JSON.stringify(validate.errors)));
  }
  for (const [healthy, attention_required] of [[null, false], [null, true], [false, null], [true, null], [true, true], [false, false], ["true", false], [true, 0]]) {
    it(`rejects invalid status pair ${healthy}/${attention_required}`, () => assert.equal(validate({ ...counts, healthy, attention_required }), false));
  }
  it("requires both statuses and refuses unknown fields", () => {
    for (const status of [{}, { healthy: null }, { attention_required: null }, { healthy: null, attention_required: null, extra: true }]) assert.equal(validate({ ...counts, ...status }), false);
  });
  for (const key of Object.keys(counts)) {
    it(`retains the safe integer boundary for ${key}`, () => {
      for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, null, "0"]) assert.equal(validate({ ...counts, healthy: true, attention_required: false, [key]: value }), false);
      assert.equal(validate({ ...counts, healthy: null, attention_required: null, [key]: Number.MAX_SAFE_INTEGER }), true);
    });
  }
});
