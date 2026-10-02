import assert from "node:assert/strict";
import test from "node:test";
import { renderRelease, validateRenderedRelease } from "./release-contract.mjs";
import { productionReleaseFixture } from "./release-fixture.mjs";
import { auditExportReleaseFixture } from "./audit-export-release-fixture.mjs";
import { testReconcilerReleaseFixture } from "./test-reconciler-release-fixture.mjs";
import { complianceExportReleaseFixture } from "./compliance-export-release-fixture.mjs";
import { attackLabReconcilerReleaseFixture } from "./attack-lab-reconciler-release-fixture.mjs";

test("schema58 renders exact migration and preserves optional predecessor authority", async t => {
  for (const phase of ["precision-consumers", "precision-intake"]) {
    for (let mask = 0; mask < 16; mask++) await t.test(`${phase}/${mask}`, async () => {
      const audit = mask & 1 ? auditExportReleaseFixture() : undefined;
      const existing = mask & 2 ? testReconcilerReleaseFixture() : undefined;
      const compliance = mask & 4 ? complianceExportReleaseFixture() : undefined;
      const attack = mask & 8 ? attackLabReconcilerReleaseFixture() : undefined;
      const rows = await renderRelease(productionReleaseFixture, { schemaVersion: 58, sessionSearchPhase: phase, auditExports: audit, testReconciler: existing, complianceExports: compliance, attackLabReconciler: attack });
      const validate = rs => validateRenderedRelease(rs, "123456789012", 58, phase, audit, existing, compliance, attack);
      assert.doesNotThrow(() => validate(rows));
      const jobs = rows.filter(r => r.kind === "Job" && r.metadata.name.startsWith("agentsec-schema-v"));
      assert.equal(jobs.length, 1);
      assert.equal(jobs[0].metadata.name, "agentsec-schema-v58");
      const command = jobs[0].spec.template.spec.containers[0].args[0];
      assert.deepEqual([...command.matchAll(/\/app\/agentsec-migrate ([a-z0-9-]+)/g)].map(m => m[1]), [
        "up-to-58", ...(audit ? ["register-audit-export-api", "register-audit-export-workers", "configure-audit-exports"] : []),
        ...(compliance ? ["register-compliance-workers"] : []), ...(attack ? ["register-security-agent-attack-lab-reconciler"] : []),
      ]);
      const api = rows.find(r => r.kind === "Deployment" && r.metadata.name === "agentsec-api");
      assert.equal(api.spec.template.spec.containers[0].env.find(e => e.name === "ZASP_EXPECTED_SCHEMA_VERSION").value, "58");
      assert.equal(api.spec.template.spec.containers[0].env.some(e => e.name === "ZASP_SECURITY_AGENT_EVIDENCE_EXPORT_WORKFLOW"), false);
      const changed = structuredClone(rows);
      changed.find(r => r.kind === "Job" && r.metadata.name === "agentsec-schema-v58").spec.template.spec.containers[0].args[0] = command.replace("up-to-58", "up-to-57");
      assert.throws(() => validate(changed), /release rejected/);
    });
  }
});

test("schema58 refuses incompatible phases and unknown successor", async () => {
  for (const phase of ["compatibility", "backfill", "query"]) await assert.rejects(renderRelease(productionReleaseFixture, { schemaVersion: 58, sessionSearchPhase: phase }), /release rejected/);
  await assert.rejects(renderRelease(productionReleaseFixture, { schemaVersion: 59, sessionSearchPhase: "precision-intake" }), /release rejected/);
});
