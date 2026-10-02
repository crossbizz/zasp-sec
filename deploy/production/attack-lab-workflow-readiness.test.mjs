import assert from "node:assert/strict";
import test from "node:test";
import { renderRelease, validateRenderedRelease } from "./release-contract.mjs";
import { productionReleaseFixture } from "./release-fixture.mjs";
import { attackLabReconcilerReleaseFixture } from "./attack-lab-reconciler-release-fixture.mjs";
import { complianceExportReleaseFixture } from "./compliance-export-release-fixture.mjs";
import { auditExportReleaseFixture } from "./audit-export-release-fixture.mjs";
import { testReconcilerReleaseFixture } from "./test-reconciler-release-fixture.mjs";

test("schema57 catalog readiness has fixed private network access and closed deployment authority", async () => {
  const options = { schemaVersion: 57, sessionSearchPhase: "precision-intake", attackLabReconciler: attackLabReconcilerReleaseFixture(), complianceExports: complianceExportReleaseFixture(), auditExports: auditExportReleaseFixture(), testReconciler: testReconcilerReleaseFixture() };
  const resources = await renderRelease(productionReleaseFixture, options);
  const api = list => list.find(r => r.kind === "Deployment" && r.metadata.name === "agentsec-api").spec.template.spec.containers[0];
  assert.deepEqual(api(resources).env.filter(e => e.name === "ZASP_SECURITY_AGENT_ATTACK_LAB_WORKFLOW"), [{ name: "ZASP_SECURITY_AGENT_ATTACK_LAB_WORKFLOW", value: "enabled" }]);
  const ingress = resources.find(r => r.kind === "NetworkPolicy" && r.metadata.name === "attack-lab-workflow-readiness-ingress");
  assert.equal(ingress.spec.podSelector.matchExpressions[0].values.length, 5);
  assert.deepEqual(ingress.spec.ingress, [{ from: [{ podSelector: { matchLabels: { "app.kubernetes.io/name": "agentsec-api" } } }], ports: [{ protocol: "TCP", port: 8081 }] }]);
  const validate = value => validateRenderedRelease(value, "123456789012", 57, "precision-intake", options.auditExports, options.testReconciler, options.complianceExports, options.attackLabReconciler);
  for (const mutate of [
    value => { api(value).env.find(e => e.name === "ZASP_SECURITY_AGENT_ATTACK_LAB_WORKFLOW").value = "true"; },
    value => { api(value).env.push({ name: "ZASP_SECURITY_AGENT_ATTACK_LAB_WORKFLOW_URL", value: "https://arbitrary.invalid" }); },
    value => { value.find(r => r.metadata.name === "attack-lab-workflow-readiness-ingress").spec.ingress[0].ports[0].port = 443; },
    value => { value.find(r => r.metadata.name === "attack-lab-workflow-readiness-egress").spec.egress[0].to = [{}]; },
    value => { value.find(r => r.kind === "Service" && r.metadata.name === "agentsec-attack-lab-proxy").spec.ports.find(p => p.name === "internal").port = 443; },
  ]) { const changed = structuredClone(resources); mutate(changed); assert.throws(() => validate(changed), /release rejected/); }
  const legacy = await renderRelease(productionReleaseFixture);
  assert.equal(api(legacy).env.some(e => e.name.startsWith("ZASP_SECURITY_AGENT_ATTACK_LAB_WORKFLOW")), false);
  assert.equal(legacy.some(r => r.metadata.name.startsWith("attack-lab-workflow-readiness-")), false);
});
