import assert from "node:assert/strict";
import test from "node:test";
import { renderRelease, validateRenderedRelease } from "./release-contract.mjs";
import { productionReleaseFixture as release } from "./release-fixture.mjs";
import { auditExportReleaseFixture } from "./audit-export-release-fixture.mjs";

test("export workers have bounded scaling, spread and separate availability rules", async t => {
  const expected = auditExportReleaseFixture();
  const resources = await renderRelease(release, { schemaVersion: 52, sessionSearchPhase: "precision-intake", auditExports: expected });
  const one = (rows, kind, name) => { const found = rows.filter(r => r.kind === kind && r.metadata.name === name); assert.equal(found.length, 1, `${kind}/${name}`); return found[0]; };
  for (const [suffix, alertPrefix] of [["worker", "ZaspAuditExportWorker"], ["outbox", "ZaspAuditExportOutbox"]]) {
    const name = `zasp-audit-export-${suffix}`;
    const hpa = one(resources, "HorizontalPodAutoscaler", name).spec;
    assert.deepEqual(hpa, {
      scaleTargetRef: { apiVersion: "apps/v1", kind: "Deployment", name }, minReplicas: 2, maxReplicas: 10,
      behavior: { scaleUp: { stabilizationWindowSeconds: 60, policies: [{ type: "Percent", value: 100, periodSeconds: 60 }] }, scaleDown: { stabilizationWindowSeconds: 300, policies: [{ type: "Percent", value: 25, periodSeconds: 60 }] } },
      metrics: [{ type: "Resource", resource: { name: "cpu", target: { type: "Utilization", averageUtilization: 70 } } }],
    });
    assert.deepEqual(one(resources, "Deployment", name).spec.template.spec.topologySpreadConstraints, [
      { maxSkew: 1, topologyKey: "topology.kubernetes.io/zone", whenUnsatisfiable: "DoNotSchedule", labelSelector: { matchLabels: { "app.kubernetes.io/name": name } } },
      { maxSkew: 1, topologyKey: "kubernetes.io/hostname", whenUnsatisfiable: "ScheduleAnyway", labelSelector: { matchLabels: { "app.kubernetes.io/name": name } } },
    ]);
    const rules = one(resources, "PrometheusRule", "zasp-audit-export-availability").spec.groups[0].rules;
    assert.equal(rules.find(r => r.alert === `${alertPrefix}Unavailable`).for, "5m");
    assert.equal(rules.find(r => r.alert === `${alertPrefix}NotReady`).for, "10m");
  }
  const mutations = [
    r => { one(r, "HorizontalPodAutoscaler", "zasp-audit-export-worker").spec.maxReplicas = 1000; },
    r => { one(r, "HorizontalPodAutoscaler", "zasp-audit-export-outbox").spec.scaleTargetRef.name = "agentsec-api"; },
    r => { one(r, "Deployment", "zasp-audit-export-worker").spec.template.spec.topologySpreadConstraints[0].labelSelector = {}; },
    r => { one(r, "PrometheusRule", "zasp-audit-export-availability").spec.groups[0].rules[0].expr = "vector(0)"; },
    r => { delete one(r, "Deployment", "zasp-audit-export-worker").spec.template.spec.containers[0].resources.requests.cpu; },
    r => { one(r, "Deployment", "zasp-audit-export-outbox").spec.strategy = { type: "Recreate" }; },
  ];
  for (const [index, name] of ["unbounded scale", "wrong scale target", "wrong spread selector", "disabled alert", "missing CPU request", "recreate rollout"].entries()) {
    await t.test(name, () => { const changed = structuredClone(resources); mutations[index](changed); assert.throws(() => validateRenderedRelease(changed, "123456789012", 52, "precision-intake", expected), /release rejected/); });
  }
});
