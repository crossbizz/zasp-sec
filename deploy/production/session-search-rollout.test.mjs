import assert from "node:assert/strict";
import test from "node:test";
import { renderRelease, validateRenderedRelease } from "./release-contract.mjs";
import { productionReleaseFixture as release } from "./release-fixture.mjs";
import { auditExportReleaseFixture } from "./audit-export-release-fixture.mjs";

const one = (resources, kind, name) => {
  const matches = resources.filter(r => r.kind === kind && r.metadata.name === name);
  assert.equal(matches.length, 1, `${kind}/${name}`);
  return matches[0];
};
const env = resource => Object.fromEntries(resource.spec.template.spec.containers[0].env.map(e => [e.name, e.value]));

for (const phase of ["precision-consumers", "precision-intake"]) {
  for (const exportsEnabled of [false, true]) {
    test(`schema55 retains ${phase} and audit exports=${exportsEnabled} with reconciler disabled`, async () => {
      const auditExports = exportsEnabled ? auditExportReleaseFixture() : undefined;
      const previous = await renderRelease(release, { schemaVersion: 54, sessionSearchPhase: phase, auditExports });
      const resources = await renderRelease(release, { schemaVersion: 55, sessionSearchPhase: phase, auditExports });
      const expected = structuredClone(previous);
      const migration = one(expected, "Job", "agentsec-schema-v54");
      migration.metadata.name = "agentsec-schema-v55";
      const command = migration.spec.template.spec.containers[0];
      assert.match(command.args[0], /up-to-54\b/);
      command.args[0] = command.args[0].replace(/up-to-54\b/, "up-to-55");
      for (const resource of expected.filter(r => r.kind === "Deployment")) {
        const annotations = resource.spec.template.metadata.annotations;
        if (annotations?.["zasp.io/schema-version"] !== undefined) {
          assert.equal(annotations["zasp.io/schema-version"], "54");
          annotations["zasp.io/schema-version"] = "55";
        }
      }
      one(expected, "Deployment", "agentsec-api").spec.template.spec.containers[0].env.find(e => e.name === "ZASP_EXPECTED_SCHEMA_VERSION").value = "55";
      assert.deepEqual(resources, expected, "schema upgrade changed capability activation or workload authority");
      assert.equal(resources.some(r => r.metadata.name === "zasp-test-reconciler"), false);
      assert.doesNotThrow(() => validateRenderedRelease(resources, "123456789012", 55, phase, auditExports));
      for (const mutate of [
        rows => one(rows, "Job", "agentsec-schema-v55").spec.template.spec.containers[0].args[0] = command.args[0].replace(/up-to-55\b/, "up-to-54"),
        rows => one(rows, "Deployment", "agentsec-api").spec.template.spec.containers[0].env.find(e => e.name === "ZASP_EXPECTED_SCHEMA_VERSION").value = "54",
        rows => one(rows, "Deployment", "agentsec-runtime-coordinator").spec.template.metadata.annotations["zasp.io/schema-version"] = "54",
      ]) {
        const changed = structuredClone(resources);
        mutate(changed);
        assert.throws(() => validateRenderedRelease(changed, "123456789012", 55, phase, auditExports), /release rejected/);
      }
    });
  }
}

for (const phase of ["precision-consumers", "precision-intake"]) {
  test(`audit schema52 preserves ${phase} without activating export workloads`, async () => {
    const previous = await renderRelease(release, { schemaVersion: 51, sessionSearchPhase: phase });
    const resources = await renderRelease(release, { schemaVersion: 52, sessionSearchPhase: phase });
    const expected = structuredClone(previous);
    const migration = one(expected, "Job", "agentsec-schema-v51");
    migration.metadata.name = "agentsec-schema-v52";
    const command = migration.spec.template.spec.containers[0];
    assert.match(command.args[0], /up-to-51$/);
    command.args[0] = command.args[0].replace(/up-to-51$/, "up-to-52");
    for (const resource of expected.filter(r => r.kind === "Deployment")) {
      const annotations = resource.spec.template.metadata.annotations;
      if (annotations?.["zasp.io/schema-version"] !== undefined) {
        assert.equal(annotations["zasp.io/schema-version"], "51");
        annotations["zasp.io/schema-version"] = "52";
      }
    }
    const api = one(expected, "Deployment", "agentsec-api");
    const version = api.spec.template.spec.containers[0].env.find(e => e.name === "ZASP_EXPECTED_SCHEMA_VERSION");
    assert.equal(version.value, "51");
    version.value = "52";
    assert.deepEqual(resources, expected, "schema-only upgrade changed workload selections or enabled new capabilities");
    assert.doesNotThrow(() => validateRenderedRelease(resources, "123456789012", 52, phase));
    for (const mutate of [
      rows => one(rows, "Job", "agentsec-schema-v52").spec.template.spec.containers[0].args[0] = command.args[0].replace(/up-to-52$/, "up-to-51"),
      rows => one(rows, "Deployment", "agentsec-api").spec.template.metadata.annotations["zasp.io/schema-version"] = "51",
      rows => one(rows, "Deployment", "agentsec-runtime-coordinator").spec.template.metadata.annotations["zasp.io/schema-version"] = "51",
      rows => one(rows, "Deployment", "agentsec-event-ingest").spec.template.spec.containers[0].env.find(e => e.name === "ZASP_RUNTIME_INGEST_SCHEMA").value = phase === "precision-intake" ? "runtime-event-v1" : "runtime-event-v2",
    ]) {
      const drift = structuredClone(resources);
      mutate(drift);
      assert.throws(() => validateRenderedRelease(drift, "123456789012", 52, phase), /release rejected/);
    }
  });
}

test("audit schema52 requires an explicit supported precision phase", async () => {
  for (const options of [
    { schemaVersion: 52 },
    { schemaVersion: 52, sessionSearchPhase: "compatibility" },
    { schemaVersion: 52, sessionSearchPhase: "backfill" },
    { schemaVersion: 52, sessionSearchPhase: "query" },
    { schemaVersion: 52, sessionSearchPhase: "audit-exports" },
    { schemaVersion: 55 },
    { schemaVersion: 55, sessionSearchPhase: "compatibility" },
    { schemaVersion: 55, sessionSearchPhase: "query" },
    { schemaVersion: 59, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 59, sessionSearchPhase: "precision-intake" },
  ]) await assert.rejects(renderRelease(release, options), /release rejected/);
});

test("precision intake changes only admitted schema after consumer upgrade", async () => {
  const consumers = await renderRelease(release, { schemaVersion: 51, sessionSearchPhase: "precision-consumers" });
  const intake = await renderRelease(release, { schemaVersion: 51, sessionSearchPhase: "precision-intake" });
  const expected = structuredClone(consumers);
  one(expected, "Deployment", "agentsec-event-ingest").spec.template.spec.containers[0].env.find(e => e.name === "ZASP_RUNTIME_INGEST_SCHEMA").value = "runtime-event-v2";
  assert.deepEqual(intake, expected);
  for (const name of ["agentsec-runtime-outbox", "agentsec-runtime-coordinator"]) {
    const drift = structuredClone(intake);
    one(drift, "Deployment", name).spec.template.spec.containers[0].env.find(e => e.name === "ZASP_RUNTIME_DELIVERY_SCHEMA").value = "runtime-event-v1";
    assert.throws(() => validateRenderedRelease(drift, "123456789012", 51, "precision-intake"), /release rejected/);
  }
  await assert.rejects(renderRelease(release, { schemaVersion: 50, sessionSearchPhase: "precision-intake" }), /release rejected/);
});

test("precision consumers install51 with dual readers while intake remains v1", async () => {
  const resources = await renderRelease(release, { schemaVersion: 51, sessionSearchPhase: "precision-consumers" });
  one(resources, "Job", "agentsec-schema-v51");
  const selections = [
    ["agentsec-event-ingest", "ZASP_RUNTIME_INGEST_SCHEMA", "runtime-event-v1"],
    ["agentsec-runtime-outbox", "ZASP_RUNTIME_DELIVERY_SCHEMA", "runtime-event-v2"],
    ["agentsec-runtime-coordinator", "ZASP_RUNTIME_DELIVERY_SCHEMA", "runtime-event-v2"],
    ["agentsec-runtime-archive", "ZASP_RUNTIME_STAGE_VERSION", "runtime-archive-v2"],
    ["agentsec-runtime-session-index-v2", "ZASP_RUNTIME_STAGE_VERSION", "runtime-index-v2"],
    ["agentsec-runtime-correlation", "ZASP_RUNTIME_STAGE_VERSION", "runtime-correlation-v4"],
    ["agentsec-runtime-projection", "ZASP_RUNTIME_STAGE_VERSION", "runtime-projection-v3"],
    ["agentsec-runtime-complete", "ZASP_RUNTIME_STAGE_VERSION", "runtime-complete-v3"],
    ["agentsec-runtime-index", "ZASP_RUNTIME_STAGE_VERSION", "runtime-index-v1"],
    ["agentsec-api", "ZASP_RUNTIME_SESSION_INDEX", "zasp-runtime-sessions-v2"],
  ];
  for (const [name, key, value] of selections) {
    assert.equal(env(one(resources, "Deployment", name))[key], value);
    const drift = structuredClone(resources);
    one(drift, "Deployment", name).spec.template.spec.containers[0].env.find(e => e.name === key).value = "unsupported";
    assert.throws(() => validateRenderedRelease(drift, "123456789012", 51, "precision-consumers"), /release rejected/);
  }
  const early = structuredClone(resources);
  one(early, "Deployment", "agentsec-event-ingest").spec.template.spec.containers[0].env.find(e => e.name === "ZASP_RUNTIME_INGEST_SCHEMA").value = "runtime-event-v2";
  assert.throws(() => validateRenderedRelease(early, "123456789012", 51, "precision-consumers"), /release rejected/);
});

for (const phase of ["backfill", "query"]) {
  test(`session search ${phase} keeps independent v1 and v2 resources`, async () => {
    const resources = await renderRelease(release, { schemaVersion: 50, sessionSearchPhase: phase });
    assert.equal(env(one(resources, "Deployment", "agentsec-api")).ZASP_RUNTIME_SESSION_INDEX, `zasp-runtime-sessions-v${phase === "query" ? 2 : 1}`);
    assert.equal(env(one(resources, "Deployment", "agentsec-runtime-index")).ZASP_RUNTIME_SESSION_INDEX, "zasp-runtime-sessions-v1");
    const worker = one(resources, "Deployment", "agentsec-runtime-session-index-v2");
    assert.equal(env(worker).ZASP_RUNTIME_SESSION_INDEX, "zasp-runtime-sessions-v2");
    assert.equal(env(worker).ZASP_DATABASE_AUTHORITY, "zasp_runtime_index_worker");
    for (const kind of ["Service", "PodDisruptionBudget", "HorizontalPodAutoscaler", "ServiceMonitor"]) one(resources, kind, "agentsec-runtime-session-index-v2");
    const first = one(resources, "Job", "agentsec-projection-search-init-v1");
    const second = one(resources, "Job", "agentsec-projection-search-init-v2");
    assert.equal(env(first).ZASP_RUNTIME_SESSION_INDEX, "zasp-runtime-sessions-v1");
    assert.equal(env(second).ZASP_RUNTIME_SESSION_INDEX, "zasp-runtime-sessions-v2");
    assert.equal(first.metadata.annotations["helm.sh/hook-weight"], "-7");
    assert.equal(second.metadata.annotations["helm.sh/hook-weight"], "-6");
    assert.doesNotThrow(() => validateRenderedRelease(resources, "123456789012", 50, phase));
    for (const mutate of [
      rows => rows.splice(rows.indexOf(one(rows, "Deployment", "agentsec-runtime-session-index-v2")), 1),
      rows => one(rows, "Deployment", "agentsec-runtime-session-index-v2").spec.template.spec.containers[0].env.find(e => e.name === "ZASP_RUNTIME_SESSION_INDEX").value = "zasp-runtime-sessions-v1",
      rows => one(rows, "Deployment", "agentsec-runtime-session-index-v2").spec.template.spec.containers[0].env.find(e => e.name === "ZASP_DATABASE_AUTHORITY").value = "zasp_discovery_api",
      rows => one(rows, "Deployment", "agentsec-runtime-session-index-v2").spec.template.spec.containers[0].resources = {},
      rows => one(rows, "NetworkPolicy", "runtime-index-dependencies").spec.egress = [],
      rows => one(rows, "NetworkPolicy", "runtime-index-dependencies").spec.egress.pop(),
      rows => one(rows, "NetworkPolicy", "task6-runtime-monitoring").spec.ingress = [],
      rows => one(rows, "Service", "agentsec-runtime-session-index-v2").spec.ports = [],
      rows => one(rows, "Job", "agentsec-schema-v50").metadata.annotations["helm.sh/hook"] = "post-upgrade",
      rows => one(rows, "Job", "agentsec-schema-v50").metadata.annotations["helm.sh/hook-weight"] = "-5",
      rows => one(rows, "Job", "agentsec-projection-search-init-v1").metadata.annotations["helm.sh/hook"] = "post-install,post-upgrade",
      rows => one(rows, "Job", "agentsec-projection-graph-init-v1").metadata.annotations["helm.sh/hook"] = "post-install,post-upgrade",
      rows => one(rows, "ServiceMonitor", "agentsec-runtime-session-index-v2").spec.endpoints = [],
      rows => one(rows, "Deployment", "agentsec-runtime-session-index-v2").spec.template.spec.containers[0].env.push({ name: "ZASP_RUNTIME_SESSION_INDEX", value: "zasp-runtime-sessions-v2" }),
      rows => one(rows, "Deployment", "agentsec-runtime-session-index-v2").spec.template.spec.containers[0].env.find(e => e.name === "ZASP_RUNTIME_SESSION_INDEX").valueFrom = { secretKeyRef: { name: "override", key: "index" } },
      rows => one(rows, "Deployment", "agentsec-runtime-session-index-v2").spec.template.spec.containers[0].readinessProbe.httpGet.path = "/healthz",
      rows => one(rows, "Job", "agentsec-projection-search-init-v2").metadata.annotations["helm.sh/hook-weight"] = "-8",
      rows => rows.splice(rows.indexOf(one(rows, "ServiceMonitor", "agentsec-runtime-session-index-v2")), 1),
      rows => one(rows, "NetworkPolicy", "runtime-index-dependencies").spec.podSelector.matchExpressions[0].values = ["agentsec-runtime-index"],
      rows => one(rows, "Deployment", "agentsec-api").spec.template.spec.containers[0].env.find(e => e.name === "ZASP_RUNTIME_SESSION_INDEX").value = phase === "query" ? "zasp-runtime-sessions-v1" : "zasp-runtime-sessions-v2",
    ]) {
      const drift = structuredClone(resources);
      mutate(drift);
      assert.throws(() => validateRenderedRelease(drift, "123456789012", 50, phase), /release rejected/);
    }
  });
}

test("compatibility keeps only v1 and rejects mixed phase/schema selections", async () => {
  const resources = await renderRelease(release);
  assert.equal(env(one(resources, "Deployment", "agentsec-api")).ZASP_RUNTIME_SESSION_INDEX, "zasp-runtime-sessions-v1");
  assert.equal(resources.some(r => r.metadata.name === "agentsec-runtime-session-index-v2"), false);
  for (const options of [
    { schemaVersion: 50 }, { schemaVersion: 49, sessionSearchPhase: "query" },
    { schemaVersion: 50, sessionSearchPhase: "unknown" }, { schemaVersion: 50, sessionSearchPhase: "compatibility" },
    { schemaVersion: 50, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 51, sessionSearchPhase: "query" },
    { schemaVersion: 51, sessionSearchPhase: "precision-active" },
  ]) await assert.rejects(renderRelease(release, options), /release rejected/);
});

test("historical phases reject accidental precision producer and consumer selectors", async () => {
  const resources = await renderRelease(release);
  for (const [name, key] of [["agentsec-event-ingest", "ZASP_RUNTIME_INGEST_SCHEMA"], ["agentsec-runtime-outbox", "ZASP_RUNTIME_DELIVERY_SCHEMA"], ["agentsec-runtime-coordinator", "ZASP_RUNTIME_DELIVERY_SCHEMA"]]) {
    const drift = structuredClone(resources);
    one(drift, "Deployment", name).spec.template.spec.containers[0].env.push({ name: key, value: "runtime-event-v2" });
    assert.throws(() => validateRenderedRelease(drift, "123456789012", 49, "compatibility"), /release rejected/);
  }
  for (const [name, version] of [["archive",2], ["projection",3], ["complete",3]]) {
    const drift = structuredClone(resources);
    one(drift, "Deployment", `agentsec-runtime-${name}`).spec.template.spec.containers[0].env.find(e => e.name === "ZASP_RUNTIME_STAGE_VERSION").value = `runtime-${name}-v${version}`;
    assert.throws(() => validateRenderedRelease(drift, "123456789012", 49, "compatibility"), /release rejected/);
  }
});
