import assert from "node:assert/strict";
import test from "node:test";

import { requiredTools, runPreflight, validateReleaseInput } from "./preflight.mjs";

const digest = (name, character) => `${name}@sha256:${character.repeat(64)}`;
const input = {
  environment: "production",
  privateEndpointOnly: true,
  endpoint_public_access: false,
  productImages: {
    web: digest("zasp/web", "a"),
    agentsecApi: digest("zasp/api", "b"),
    agentsecWorker: digest("zasp/worker", "c"),
  },
  workloadIdentities: {
    web: { serviceAccount: "agentsec-web", roleArn: null },
    agentsecApi: { serviceAccount: "agentsec-api", roleArn: "arn:aws:iam::123456789012:role/zasp-production-api" },
    discoveryScheduler: { serviceAccount: "zasp-discovery-scheduler", roleArn: "arn:aws:iam::123456789012:role/zasp-production-discovery-scheduler" },
    projectionSearch: { serviceAccount: "zasp-projection-search", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-search" },
    outboxPublisher: { serviceAccount: "zasp-outbox-publisher", roleArn: "arn:aws:iam::123456789012:role/zasp-production-outbox" },
    migration: { serviceAccount: "agentsec-migration", roleArn: "arn:aws:iam::123456789012:role/zasp-production-migration" },
    canary: { serviceAccount: "agentsec-canary", roleArn: null },
    canarySecretSync: { serviceAccount: "agentsec-canary-secret-sync", roleArn: "arn:aws:iam::123456789012:role/zasp-production-canary-secret-sync" },
  },
};

test("release preflight validates the exact three images and least-privilege identities", () => {
  const calls = [];
  const value = runPreflight(["--input", "release.json"], { read: () => JSON.stringify(input), spawn: (tool, args, options) => { calls.push({ tool, args, options }); return { status: 0 }; } });
  assert.deepEqual(value, { environment: "production", privateEndpointOnly: true, images: 3, cloudIdentities: 6 });
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
    { ...input, productImages: { ...input.productImages, web: "zasp/web:latest" } },
    { ...input, productImages: { ...input.productImages, extra: digest("zasp/extra", "c") } },
    { ...input, workloadIdentities: { ...input.workloadIdentities, web: { serviceAccount: "shared-release", roleArn: "arn:aws:iam::123456789012:role/zasp-production" } } },
    { ...input, retiredSecurityGroupID: "sg-1234abcd" },
  ]) assert.throws(() => validateReleaseInput(invalid), /rejected/);
  assert.throws(() => runPreflight(["--input", "release.json"], { read: () => JSON.stringify(input), spawn: () => ({ status: 1 }) }), /rejected/);
});
