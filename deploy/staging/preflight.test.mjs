import assert from "node:assert/strict";
import test from "node:test";

import { requiredTools, runPreflight, validateReleaseInput } from "./preflight.mjs";

const digest = (name, character) => `${name}@sha256:${character.repeat(64)}`;
const input = {
  environment: "production",
  platformAccountID: "123456789012",
  privateEndpointOnly: true,
  endpoint_public_access: false,
  productImages: {
    web: digest("zasp/web", "a"),
    agentsecApi: digest("zasp/api", "b"),
    agentsecWorker: digest("zasp/worker", "c"),
    eventIngest: digest("zasp/event-ingest", "d"),
    gatewayControl: digest("zasp/gateway-control", "e"),
    runtimeGateway: digest("zasp/runtime-gateway", "f"),
    sensorAgent: digest("zasp/sensor-agent", "1"),
  },
  dependencyImages: {
    nango: "nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed",
    otelCollector: "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5",
  },
  workloadIdentities: {
    web: { serviceAccount: "agentsec-web", roleArn: null },
    agentsecApi: { serviceAccount: "agentsec-api", roleArn: "arn:aws:iam::123456789012:role/zasp-production-api" },
    discoveryScheduler: { serviceAccount: "zasp-discovery-scheduler", roleArn: "arn:aws:iam::123456789012:role/zasp-production-discovery-scheduler" },
    discoveryWorker: { serviceAccount: "zasp-discovery-worker", roleArn: "arn:aws:iam::123456789012:role/zasp-production-discovery-worker" },
    securityAgent: { serviceAccount: "zasp-security-agent", roleArn: "arn:aws:iam::123456789012:role/zasp-production-security-agent-worker" },
    projectionRisk: { serviceAccount: "zasp-projection-risk", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-risk" },
    projectionGraph: { serviceAccount: "zasp-projection-graph", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-graph" },
    projectionSearch: { serviceAccount: "zasp-projection-search", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-search" },
    outboxPublisher: { serviceAccount: "zasp-outbox-publisher", roleArn: "arn:aws:iam::123456789012:role/zasp-production-outbox" },
    runtimeIngest: { serviceAccount: "zasp-runtime-ingest", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-ingest" },
    gatewayControl: { serviceAccount: "zasp-gateway-control", roleArn: "arn:aws:iam::123456789012:role/zasp-production-gateway-control" },
    runtimeOutbox: { serviceAccount: "zasp-runtime-outbox", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-outbox" },
    runtimeCoordinator: { serviceAccount: "zasp-runtime-coordinator", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-coordinator" },
    runtimeArchive: { serviceAccount: "zasp-runtime-archive", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-archive" },
    runtimeIndex: { serviceAccount: "zasp-runtime-index", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-index" },
    runtimeCorrelation: { serviceAccount: "zasp-runtime-correlation", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-correlation" },
    runtimeProjection: { serviceAccount: "zasp-runtime-projection", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-projection" },
    runtimeComplete: { serviceAccount: "zasp-runtime-complete", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-complete" },
    nango: { serviceAccount: "nango", roleArn: null },
    nangoMigrate: { serviceAccount: "nango-migrate", roleArn: null },
    otelCollector: { serviceAccount: "otel-collector", roleArn: null },
    migration: { serviceAccount: "agentsec-migration", roleArn: "arn:aws:iam::123456789012:role/zasp-production-migration" },
    projectionGraphInit: { serviceAccount: "agentsec-projection-graph-init", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-graph-init" },
    projectionSearchInit: { serviceAccount: "agentsec-projection-search-init", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-search-init" },
    canary: { serviceAccount: "agentsec-canary", roleArn: null },
    canarySecretSync: { serviceAccount: "agentsec-canary-secret-sync", roleArn: "arn:aws:iam::123456789012:role/zasp-production-canary-secret-sync" },
  },
};

test("release preflight validates all nine images and least-privilege identities", () => {
  const calls = [];
  const value = runPreflight(["--input", "release.json"], { read: () => JSON.stringify(input), spawn: (tool, args, options) => { calls.push({ tool, args, options }); return { status: 0 }; } });
  assert.deepEqual(value, { environment: "production", privateEndpointOnly: true, images: 9, deployments: 20, cloudIdentities: 21 });
  assert.deepEqual(calls.map(({ tool, args }) => ({ tool, args })), [
    { tool: "terraform", args: ["version", "-json"] },
    { tool: "helm", args: ["version", "--short"] },
    { tool: "kubectl", args: ["version", "--client=true", "--output=json"] },
    { tool: "aws", args: ["--version"] },
  ]);
  assert.deepEqual(calls.map(({ tool }) => tool), requiredTools);
  assert.ok(calls.every(({ options }) => options.timeout === 10_000 && Object.keys(options.env).join() === "PATH"));
});

test("release preflight rejects public access, mutable images, stale workloads, and shared IAM", () => {
  for (const invalid of [
    { ...input, environment: "staging" },
    { ...input, privateEndpointOnly: false },
    { ...input, endpoint_public_access: true },
    { ...input, platformAccountID: "000000000000" },
    { ...input, productImages: { ...input.productImages, web: "zasp/web:latest" } },
    { ...input, productImages: { ...input.productImages, extra: digest("zasp/extra", "c") } },
    { ...input, dependencyImages: { ...input.dependencyImages, nango: "nangohq/nango-server:latest" } },
    { ...input, workloadIdentities: { ...input.workloadIdentities, web: { serviceAccount: "shared-release", roleArn: "arn:aws:iam::123456789012:role/zasp-production" } } },
    { ...input, workloadIdentities: { ...input.workloadIdentities, projectionGraph: { ...input.workloadIdentities.projectionGraph, roleArn: "arn:aws:iam::210987654321:role/zasp-production-projection-graph" } } },
    { ...input, retiredSecurityGroupID: "sg-1234abcd" },
  ]) assert.throws(() => validateReleaseInput(invalid), /rejected/);
  assert.throws(() => runPreflight(["--input", "release.json"], { read: () => JSON.stringify(input), spawn: () => ({ status: 1 }) }), /rejected/);
});
