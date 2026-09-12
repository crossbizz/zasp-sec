import assert from "node:assert/strict";
import test from "node:test";
import { readFile, readdir } from "node:fs/promises";
import { load } from "js-yaml";
import { renderRelease } from "../production/release-contract.mjs";
import { productionReleaseFixture } from "../production/release-fixture.mjs";

test("embedded migration release has explicit compatibility and forward chart phases", async () => {
  const files = await readdir(new URL("../../services/platform/migrations/sql/", import.meta.url));
  const latest = Math.max(...files.filter(name => /^\d+_.*\.up\.sql$/.test(name)).map(name => Number(name.split("_")[0])));
  const values = load(await readFile(new URL("./product/values.yaml", import.meta.url), "utf8"));
  // A future embedded migration must define its own rollout before this gate
  // accepts it. Default49 is deliberate: compatible pods precede the50 hook.
  // This is a manifest compatibility gate, not live transition authorization.
  assert.equal(latest, 51, "embedded migration needs an explicit rollout contract");
  assert.equal(values.schema.expectedVersion, 49);
  assert.equal(values.runtime.sessionSearchPhase, "compatibility");
  for (const options of [
    { schemaVersion: 48, sessionSearchPhase: "compatibility" },
    { schemaVersion: values.schema.expectedVersion, sessionSearchPhase: values.runtime.sessionSearchPhase },
    { schemaVersion: 50, sessionSearchPhase: "backfill" },
    { schemaVersion: 50, sessionSearchPhase: "query" },
    { schemaVersion: 51, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 51, sessionSearchPhase: "precision-intake" },
  ]) {
    const resources = await renderRelease(productionReleaseFixture, options);
    const jobs = resources.filter(r => r.kind === "Job" && r.metadata.name.startsWith("agentsec-schema-v"));
    assert.equal(jobs.length, 1);
    assert.equal(jobs[0].metadata.name, `agentsec-schema-v${options.schemaVersion}`);
    const api = resources.find(r => r.kind === "Deployment" && r.metadata.name === "agentsec-api");
    assert.equal(api.spec.template.spec.containers[0].env.find(e => e.name === "ZASP_RUNTIME_SESSION_INDEX").value, options.sessionSearchPhase === "query" || options.schemaVersion === 51 ? "zasp-runtime-sessions-v2" : "zasp-runtime-sessions-v1");
    assert.equal(resources.filter(r => r.kind === "Deployment" && r.metadata.name === "agentsec-runtime-session-index-v2").length, options.schemaVersion >= 50 ? 1 : 0);
    if (options.schemaVersion === 51) {
      const env = name => resources.find(r => r.kind === "Deployment" && r.metadata.name === name).spec.template.spec.containers[0].env;
      assert.equal(env("agentsec-event-ingest").find(e => e.name === "ZASP_RUNTIME_INGEST_SCHEMA").value, options.sessionSearchPhase === "precision-intake" ? "runtime-event-v2" : "runtime-event-v1");
      for (const name of ["outbox", "coordinator"]) assert.equal(env(`agentsec-runtime-${name}`).find(e => e.name === "ZASP_RUNTIME_DELIVERY_SCHEMA").value, "runtime-event-v2");
      for (const [name, version] of [["archive", 2], ["index", 1], ["correlation", 4], ["projection", 3], ["complete", 3]]) assert.equal(env(`agentsec-runtime-${name}`).find(e => e.name === "ZASP_RUNTIME_STAGE_VERSION").value, `runtime-${name}-v${version}`);
      assert.equal(env("agentsec-runtime-session-index-v2").find(e => e.name === "ZASP_RUNTIME_STAGE_VERSION").value, "runtime-index-v2");
    }
  }
  for (const options of [
    { schemaVersion: 50 },
    { schemaVersion: 49, sessionSearchPhase: "query" },
    { schemaVersion: 50, sessionSearchPhase: "compatibility" },
    { schemaVersion: 50, sessionSearchPhase: "unknown" },
    { schemaVersion: 51, sessionSearchPhase: "query" },
    { schemaVersion: 51 },
    { schemaVersion: 50, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 50, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 49, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 51, sessionSearchPhase: "precision-active" },
  ]) await assert.rejects(renderRelease(productionReleaseFixture, options), /release rejected/);
});

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
    { name: "agentsec-security-agent", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-security-agent", roleArn: "arn:aws:iam::123456789012:role/zasp-production-security-agent-worker" },
    { name: "agentsec-security-agent-action", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-security-agent-action", roleArn: "arn:aws:iam::123456789012:role/zasp-production-security-agent-action-worker" },
    { name: "agentsec-policy-deployment", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-policy-deployment", roleArn: "arn:aws:iam::123456789012:role/zasp-production-policy-deployment-worker" },
    { name: "agentsec-outbox-publisher", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-outbox-publisher", roleArn: "arn:aws:iam::123456789012:role/zasp-production-outbox" },
    { name: "agentsec-recovery-backup-outbox", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-recovery-backup-outbox", roleArn: "arn:aws:iam::123456789012:role/zasp-production-recovery-backup-outbox" },
    { name: "agentsec-recovery-restore-outbox", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-recovery-restore-outbox", roleArn: "arn:aws:iam::123456789012:role/zasp-production-recovery-restore-outbox" },
    { name: "agentsec-recovery-backup", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-recovery-backup", roleArn: "arn:aws:iam::123456789012:role/zasp-production-recovery-backup" },
    { name: "agentsec-recovery-restore", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-recovery-restore", roleArn: "arn:aws:iam::123456789012:role/zasp-production-recovery-restore" },
    { name: "agentsec-red-team-outbox", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-red-team-outbox", roleArn: "arn:aws:iam::123456789012:role/zasp-production-red-team-outbox" },
    { name: "agentsec-red-team-worker", image: digest("registry.example/zasp/red-team-worker", "2"), serviceAccount: "zasp-red-team-worker", roleArn: "arn:aws:iam::123456789012:role/zasp-production-red-team-worker" },
    { name: "agentsec-red-team-adapter", image: digest("registry.example/zasp/red-team-worker", "2"), serviceAccount: "zasp-red-team-adapter", roleArn: "arn:aws:iam::123456789012:role/zasp-production-red-team-adapter" },
    { name: "agentsec-attack-lab-outbox", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-attack-lab-outbox", roleArn: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-outbox" },
    { name: "agentsec-attack-lab-controller", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-attack-lab-controller", roleArn: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-controller" },
    { name: "agentsec-attack-lab-proxy", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-attack-lab-proxy", roleArn: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-proxy" },
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
    { name: "agentsec-schema-v49", serviceAccount: "agentsec-migration", roleArn: "arn:aws:iam::123456789012:role/zasp-production-migration" },
    { name: "agentsec-attack-lab-runner", serviceAccount: "agentsec-attack-lab-runner", roleArn: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test" },
    { name: "agentsec-projection-graph-init-v1", serviceAccount: "agentsec-projection-graph-init", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-graph-init" },
    { name: "agentsec-projection-search-init-v1", serviceAccount: "agentsec-projection-search-init", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-search-init" },
    { name: "nango-migrate", serviceAccount: "nango-migrate", roleArn: null },
    { name: "production-readonly-canary", serviceAccount: "agentsec-canary", roleArn: null },
    { name: "zasp-canary-secret-sync", serviceAccount: "agentsec-canary-secret-sync", roleArn: "arn:aws:iam::123456789012:role/zasp-production-canary-secret-sync" },
  ],
};

test("staging deployment binds thirty-two deployments and every init/runner/canary identity to one account", () => {
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
  assert.throws(() => buildStagingDeployment({ ...deployment, jobIdentities: deployment.jobIdentities.map((identity) => identity.name === "agentsec-schema-v49" ? { ...identity, roleArn: "arn:aws:iam::210987654321:role/zasp-production-migration" } : identity) }), /rejected/);
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

test("staging deployment forbids missing and inherited sandbox roles", () => {
  for (const roleArn of [null, "arn:aws:iam::123456789012:role/zasp-production-discovery-worker"]) {
    assert.throws(() => buildStagingDeployment({ ...deployment, jobIdentities: deployment.jobIdentities.map((identity) => identity.name === "agentsec-attack-lab-runner" ? { ...identity, roleArn } : identity) }), /rejected/);
  }
});
