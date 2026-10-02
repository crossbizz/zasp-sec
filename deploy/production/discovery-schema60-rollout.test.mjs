import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { productionReleaseFixture } from "./release-fixture.mjs";
import { renderRelease, validateRenderedRelease } from "./release-contract.mjs";

const phase = "precision-intake";
const scheduler = resources => resources.find(resource => resource.kind === "Deployment" && resource.metadata?.name === "agentsec-discovery-scheduler");
const named = (resources, kind, name) => resources.filter(resource => resource.kind === kind && resource.metadata?.name === name);

test("schema60 requires a schema59 scheduler fence before the release60 scheduler starts", async () => {
  const maintenance = await renderRelease(productionReleaseFixture, {
    schemaVersion: 59,
    sessionSearchPhase: phase,
    discoveryScheduleReplayPhase: "maintenance",
  });
  const active = await renderRelease(productionReleaseFixture, {
    schemaVersion: 60,
    sessionSearchPhase: phase,
    discoveryScheduleReplayPhase: "active",
  });

  assert.equal(scheduler(maintenance).spec.replicas, 0);
  assert.equal(scheduler(maintenance).spec.template.metadata.annotations["zasp.io/schema-version"], "59");
  assert.equal(named(maintenance, "HorizontalPodAutoscaler", "agentsec-discovery-scheduler").length, 0);
  assert.equal(named(maintenance, "PodDisruptionBudget", "agentsec-discovery-scheduler").length, 0);
  assert.equal(maintenance.flatMap(resource => resource.spec?.groups ?? []).flatMap(group => group.rules ?? []).some(rule => rule.alert === "ZaspDiscoverySchedulerUnavailable"), false);
  assert.equal(named(maintenance, "Job", "agentsec-schema-v59")[0].spec.template.spec.containers[0].args[0].includes("up-to-59"), true);

  assert.equal(scheduler(active).spec.replicas, 2);
  assert.equal(scheduler(active).spec.template.metadata.annotations["zasp.io/schema-version"], "60");
  assert.equal(named(active, "HorizontalPodAutoscaler", "agentsec-discovery-scheduler").length, 1);
  assert.equal(named(active, "PodDisruptionBudget", "agentsec-discovery-scheduler").length, 1);
  assert.equal(active.flatMap(resource => resource.spec?.groups ?? []).flatMap(group => group.rules ?? []).some(rule => rule.alert === "ZaspDiscoverySchedulerUnavailable"), true);
  assert.equal(named(active, "Job", "agentsec-schema-v60")[0].spec.template.spec.containers[0].args[0].includes("up-to-60"), true);

  assert.doesNotThrow(() => validateRenderedRelease(maintenance, "123456789012", 59, phase, undefined, undefined, undefined, undefined, undefined, "maintenance"));
  assert.doesNotThrow(() => validateRenderedRelease(active, "123456789012", 60, phase, undefined, undefined, undefined, undefined, undefined, "active"));
});

test("schema60 rollout rejects an absent fence, a fenced new scheduler, and unknown successors", async () => {
  for (const options of [
    { schemaVersion: 59, sessionSearchPhase: phase },
    { schemaVersion: 59, sessionSearchPhase: phase, discoveryScheduleReplayPhase: "active" },
    { schemaVersion: 60, sessionSearchPhase: phase },
    { schemaVersion: 60, sessionSearchPhase: phase, discoveryScheduleReplayPhase: "maintenance" },
    { schemaVersion: 61, sessionSearchPhase: phase, discoveryScheduleReplayPhase: "active" },
    { schemaVersion: 58, sessionSearchPhase: phase, discoveryScheduleReplayPhase: "maintenance" },
  ]) await assert.rejects(renderRelease(productionReleaseFixture, options), /release rejected/);

  const maintenance = await renderRelease(productionReleaseFixture, { schemaVersion: 59, sessionSearchPhase: phase, discoveryScheduleReplayPhase: "maintenance" });
  scheduler(maintenance).spec.replicas = 2;
  assert.throws(() => validateRenderedRelease(maintenance, "123456789012", 59, phase, undefined, undefined, undefined, undefined, undefined, "maintenance"), /release rejected/);

  const active = await renderRelease(productionReleaseFixture, { schemaVersion: 60, sessionSearchPhase: phase, discoveryScheduleReplayPhase: "active" });
  scheduler(active).spec.replicas = 0;
  assert.throws(() => validateRenderedRelease(active, "123456789012", 60, phase, undefined, undefined, undefined, undefined, undefined, "active"), /release rejected/);
});

test("the canonical release suite and runbook require the live schema60 transition guard", async () => {
  const packageJSON = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8"));
  assert.match(packageJSON.scripts["production:release:test"], /discovery-schema60-transition\.test\.mjs/);
  const runbook = await readFile(new URL("../../docs/operations/production-deployment.md", import.meta.url), "utf8");
  assert.match(runbook, /Do not apply schema 59 or 60 directly/);
  assert.match(runbook, /node deploy\/production\/discovery-schema60-transition\.mjs/);
  assert.match(runbook, /every\s+scheduler pod \(including terminating pods\) is absent/);
});
