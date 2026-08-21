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
  platformAccountID: "123456789012",
  privateEndpoints: true,
  workloads: [
    { name: "web", image: digest("registry.example/zasp/web", "a"), serviceAccount: "agentsec-web", roleArn: null },
    { name: "agentsec-api", image: digest("registry.example/zasp/api", "b"), serviceAccount: "agentsec-api", roleArn: "arn:aws:iam::123456789012:role/zasp-production-api" },
    { name: "agentsec-discovery-scheduler", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-discovery-scheduler", roleArn: "arn:aws:iam::123456789012:role/zasp-production-discovery-scheduler" },
    { name: "agentsec-discovery-worker", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-discovery-worker", roleArn: "arn:aws:iam::123456789012:role/zasp-production-discovery-worker" },
    { name: "agentsec-outbox-publisher", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-outbox-publisher", roleArn: "arn:aws:iam::123456789012:role/zasp-production-outbox" },
    { name: "agentsec-projection-risk", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-projection-risk", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-risk" },
    { name: "agentsec-projection-graph", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-projection-graph", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-graph" },
    { name: "agentsec-projection-search", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-projection-search", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-search" },
    { name: "agentsec-event-ingest", image: digest("registry.example/zasp/event-ingest", "d"), serviceAccount: "zasp-runtime-ingest", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-ingest" },
    { name: "agentsec-gateway-control", image: digest("registry.example/zasp/gateway-control", "e"), serviceAccount: "zasp-gateway-control", roleArn: "arn:aws:iam::123456789012:role/zasp-production-gateway-control" },
    { name: "agentsec-runtime-outbox", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-outbox", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-outbox" },
    { name: "agentsec-runtime-coordinator", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-coordinator", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-coordinator" },
    { name: "agentsec-runtime-archive", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-archive", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-archive" },
    { name: "agentsec-runtime-index", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-index", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-index" },
    { name: "agentsec-runtime-correlation", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-correlation", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-correlation" },
    { name: "agentsec-runtime-projection", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-projection", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-projection" },
    { name: "agentsec-runtime-complete", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-complete", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-complete" },
    { name: "nango", image: "nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed", serviceAccount: "nango", roleArn: null },
    { name: "otel-collector", image: "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5", serviceAccount: "otel-collector", roleArn: null },
  ],
  jobIdentities: [
    { name: "agentsec-schema-v16", serviceAccount: "agentsec-migration", roleArn: "arn:aws:iam::123456789012:role/zasp-production-migration" },
    { name: "agentsec-projection-graph-init-v1", serviceAccount: "agentsec-projection-graph-init", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-graph-init" },
    { name: "agentsec-projection-search-init-v1", serviceAccount: "agentsec-projection-search-init", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-search-init" },
    { name: "nango-migrate", serviceAccount: "nango-migrate", roleArn: null },
    { name: "production-readonly-canary", serviceAccount: "agentsec-canary", roleArn: null },
    { name: "zasp-canary-secret-sync", serviceAccount: "agentsec-canary-secret-sync", roleArn: "arn:aws:iam::123456789012:role/zasp-production-canary-secret-sync" },
  ],
};

test("staging deployment binds nineteen deployments and every init/canary identity to one account", () => {
  assert.deepEqual(buildStagingDeployment(deployment), deployment);
  const runtime = {
    start: () => "deploy-run-1",
    inspect: () => ({ runID: "deploy-run-1", ready: deployment.workloads.map(({ name }) => name), vendorDashboardsExposed: false, privateEndpoints: true }),
  };
  assert.equal(startStagingDeployment(deployment, runtime), "deploy-run-1");
  assert.deepEqual(inspectStagingDeployment("deploy-run-1", runtime).ready, deployment.workloads.map(({ name }) => name));
  assert.throws(() => buildStagingDeployment({ ...deployment, privateEndpoints: false }), /rejected/);
  assert.throws(() => buildStagingDeployment({ ...deployment, serviceAccount: "shared-release" }), /rejected/);
  assert.throws(() => buildStagingDeployment({ ...deployment, workloads: [...deployment.workloads, { name: "unsupported-extra", image: digest("registry.example/zasp/extra", "c"), serviceAccount: "shared-release", roleArn: "arn:aws:iam::123456789012:role/zasp-production" }] }), /rejected/);
  assert.throws(() => buildStagingDeployment({ ...deployment, workloads: deployment.workloads.map((workload) => ({ ...workload, serviceAccount: "shared-release" })) }), /rejected/);
  assert.throws(() => buildStagingDeployment({ ...deployment, jobIdentities: deployment.jobIdentities.map((identity) => identity.name === "agentsec-schema-v16" ? { ...identity, roleArn: "arn:aws:iam::210987654321:role/zasp-production-migration" } : identity) }), /rejected/);
});

test("staging evidence is deterministic, credential-free, and gates exact private readiness", () => {
  const evidence = createStagingEvidence({
    terraformRevision: "a".repeat(40),
    clusterVersion: "1.35.5",
    cluster: "zasp-staging",
    platformAccountID: deployment.platformAccountID,
    images: deployment.workloads.map(({ name, image }) => ({ name, image })),
    identities: [...deployment.workloads, ...deployment.jobIdentities].map(({ name, serviceAccount, roleArn }) => ({ name, serviceAccount, roleArn })),
    deploymentRunID: "deploy-run-1",
  });
  assert.deepEqual(evidence.images.map(({ name }) => name), deployment.workloads.map(({ name }) => name).sort());
  assert.deepEqual(evaluateM1AGate({ deploymentReady: true, privateEndpoints: true, perWorkloadIAM: true, evidence }).workloads, deployment.workloads.map(({ name }) => name));
  assert.throws(() => createStagingEvidence({ ...evidence, accessKey: "forbidden" }), /rejected/);
  assert.throws(() => evaluateM1AGate({ deploymentReady: true, privateEndpoints: false, perWorkloadIAM: true, evidence }), /rejected/);
  assert.throws(() => evaluateM1AGate({ deploymentReady: true, dependenciesReady: true, privateEndpoints: true, perWorkloadIAM: true, evidence }), /rejected/);
});
