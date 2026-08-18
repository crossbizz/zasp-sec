import assert from "node:assert/strict";
import test from "node:test";

import {
  buildStagingDeployment,
  createStagingEvidence,
  evaluateM1AGate,
  inspectStagingDeployment,
  runStagingDependencySmoke,
  startStagingDeployment,
} from "./gate.mjs";

const digest = (name, character) => `${name}@sha256:${character.repeat(64)}`;
const deployment = {
  cluster: "zasp-staging",
  namespace: "agentsec",
  serviceAccount: "agentsec-product",
  privateEndpoints: true,
  workloads: [
    { name: "web", image: digest("registry.example/zasp/web", "a") },
    { name: "agentsec-api", image: digest("registry.example/zasp/api", "b") },
    { name: "agentsec-worker", image: digest("registry.example/zasp/worker", "c") },
    { name: "event-ingest", image: digest("registry.example/zasp/ingest", "d") },
  ],
};

test("staging deployment is immutable, private, and exposes no vendor dashboard", () => {
  assert.deepEqual(buildStagingDeployment(deployment), deployment);
  const runtime = {
    start: () => "deploy-run-1",
    inspect: () => ({ runID: "deploy-run-1", ready: ["web", "agentsec-api", "agentsec-worker", "event-ingest"], vendorDashboardsExposed: false, privateEndpoints: true }),
  };
  assert.equal(startStagingDeployment(deployment, runtime), "deploy-run-1");
  assert.equal(inspectStagingDeployment("deploy-run-1", runtime).ready.length, 4);
  assert.throws(() => buildStagingDeployment({ ...deployment, privateEndpoints: false }), /rejected/);
});

test("staging smoke requires exact IRSA operations and OTLP health", () => {
  const runtime = { smoke: () => ({ runID: "deploy-run-1", throughIRSA: true, otlpHealthEmitted: true, operations: ["s3_put_get_delete", "sqs_send_receive_delete", "opensearch_index_search_delete"] }) };
  assert.equal(runStagingDependencySmoke("deploy-run-1", runtime).operations.length, 3);
  assert.throws(() => runStagingDependencySmoke("deploy-run-1", { smoke: () => ({ ...runtime.smoke(), throughIRSA: false }) }), /rejected/);
});

test("staging evidence is deterministic, credential-free, and gates private readiness", () => {
  const evidence = createStagingEvidence({
    terraformRevision: "a".repeat(40),
    clusterVersion: "1.35.5",
    cluster: "zasp-staging",
    images: deployment.workloads,
    deploymentRunID: "deploy-run-1",
    smokeRunID: "smoke-run-1",
  });
  assert.deepEqual(evidence.images.map(({ name }) => name), ["agentsec-api", "agentsec-worker", "event-ingest", "web"]);
  assert.equal(evaluateM1AGate({ deploymentReady: true, dependenciesReady: true, privateEndpoints: true, irsa: true, otlpHealth: true, evidence }).ready, true);
  assert.throws(() => createStagingEvidence({ ...evidence, accessKey: "forbidden" }), /rejected/);
  assert.throws(() => evaluateM1AGate({ deploymentReady: true, dependenciesReady: true, privateEndpoints: false, irsa: true, otlpHealth: true, evidence }), /rejected/);
});
