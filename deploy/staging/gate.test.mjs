import assert from "node:assert/strict";
import test from "node:test";

import {
  buildStagingDeployment,
  createStagingEvidence,
  evaluateM1AGate,
  inspectStagingDeployment,
  startStagingDeployment,
} from "./gate.mjs";

const digest = (name, character) => `${name}@sha256:${character.repeat(64)}`;
const deployment = {
  cluster: "zasp-staging",
  namespace: "agentsec",
  privateEndpoints: true,
  workloads: [
    { name: "web", image: digest("registry.example/zasp/web", "a"), serviceAccount: "agentsec-web", roleArn: null },
    { name: "agentsec-api", image: digest("registry.example/zasp/api", "b"), serviceAccount: "agentsec-api", roleArn: "arn:aws:iam::123456789012:role/zasp-production-api" },
  ],
};

test("staging deployment is the exact buildable two-workload release with per-workload identity", () => {
  assert.deepEqual(buildStagingDeployment(deployment), deployment);
  const runtime = {
    start: () => "deploy-run-1",
    inspect: () => ({ runID: "deploy-run-1", ready: ["web", "agentsec-api"], vendorDashboardsExposed: false, privateEndpoints: true }),
  };
  assert.equal(startStagingDeployment(deployment, runtime), "deploy-run-1");
  assert.deepEqual(inspectStagingDeployment("deploy-run-1", runtime).ready, ["web", "agentsec-api"]);
  assert.throws(() => buildStagingDeployment({ ...deployment, privateEndpoints: false }), /rejected/);
  assert.throws(() => buildStagingDeployment({ ...deployment, serviceAccount: "shared-release" }), /rejected/);
  assert.throws(() => buildStagingDeployment({ ...deployment, workloads: [...deployment.workloads, { name: "unsupported-extra", image: digest("registry.example/zasp/extra", "c"), serviceAccount: "shared-release", roleArn: "arn:aws:iam::123456789012:role/zasp-production" }] }), /rejected/);
  assert.throws(() => buildStagingDeployment({ ...deployment, workloads: deployment.workloads.map((workload) => ({ ...workload, serviceAccount: "shared-release" })) }), /rejected/);
});

test("staging evidence is deterministic, credential-free, and gates exact private readiness", () => {
  const evidence = createStagingEvidence({
    terraformRevision: "a".repeat(40),
    clusterVersion: "1.35.5",
    cluster: "zasp-staging",
    images: deployment.workloads.map(({ name, image }) => ({ name, image })),
    deploymentRunID: "deploy-run-1",
  });
  assert.deepEqual(evidence.images.map(({ name }) => name), ["agentsec-api", "web"]);
  assert.equal(evaluateM1AGate({ deploymentReady: true, privateEndpoints: true, perWorkloadIAM: true, evidence }).ready, true);
  assert.throws(() => createStagingEvidence({ ...evidence, accessKey: "forbidden" }), /rejected/);
  assert.throws(() => evaluateM1AGate({ deploymentReady: true, privateEndpoints: false, perWorkloadIAM: true, evidence }), /rejected/);
  assert.throws(() => evaluateM1AGate({ deploymentReady: true, dependenciesReady: true, privateEndpoints: true, perWorkloadIAM: true, evidence }), /rejected/);
});
