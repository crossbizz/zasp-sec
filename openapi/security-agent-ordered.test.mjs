import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { load } from "js-yaml";

const spec = load(await readFile(new URL("./openapi.yaml", import.meta.url), "utf8"));
const schemas = spec.components.schemas;
test("ordered publication has closed public schemas and separate cancellation response", () => {
  for (const name of ["SecurityAgentOrderedDetail", "SecurityAgentOrderedStep", "SecurityAgentOrderedDependency", "SecurityAgentOrderedApproval", "SecurityAgentOrderedReceipt", "SecurityAgentOrderedCleanup", "SecurityAgentCancellation", "SecurityAgentOrderedTriggerInput"]) {
    assert.ok(schemas[name], name);
    assert.equal(schemas[name].additionalProperties, false, name);
  }
  assert.equal(spec.paths["/api/v1/security-agent-runs/{id}/cancel"].post.responses["200"].content["application/json"].schema.$ref, "#/components/schemas/SecurityAgentCancellation");
  assert.equal(schemas.SecurityAgentRunDetail.properties.ordered.$ref, "#/components/schemas/SecurityAgentOrderedDetail");
  assert.equal(schemas.SecurityAgentRunDetail.required.includes("ordered"), false);
  assert.equal(schemas.SecurityAgentRun.properties.ordered, undefined);
  assert.equal(schemas.SecurityAgentManualRunInput.oneOf.length, 2);
  assert.deepEqual(schemas.SecurityAgentOrderedApproval.properties.state.enum, ["absent", "pending", "approved", "rejected", "expired"]);
});
test("generated types expose immutable ordered data without altering ordinary runs", async () => {
  const source = await readFile(new URL("../apps/web/api/generated.ts", import.meta.url), "utf8");
  for (const name of ["SecurityAgentOrderedDetail", "SecurityAgentOrderedStep", "SecurityAgentCancellation", "SecurityAgentOrderedTriggerInput"]) assert.match(source, new RegExp(`export type ${name} =`));
  assert.match(source, /readonly ordered\?: components\["schemas"\]\["SecurityAgentOrderedDetail"\]/);
});
