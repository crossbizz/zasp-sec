import assert from "node:assert/strict";
import test from "node:test";

import {
  PROXY_PINS,
  PROXY_PROOF_LABEL,
  buildProxyRuntimeSpec,
} from "./manifest.mjs";

const marker = "0123456789abcdef";
const root = `/private/tmp/zasp-m0-15-${marker}-ABC123`;
const providerKey = `eyJ${"a".repeat(16)}.ey${"b".repeat(16)}.${"c".repeat(32)}`;
const input = Object.freeze({
  marker,
  platform: "linux/amd64",
  password: "A".repeat(32),
  encryptionKey: Buffer.alloc(32, 2).toString("base64"),
  providerKey,
  workspaceRoot: root,
  dockerConfigPath: `${root}/docker-config`,
  caCertificatePath: `${root}/tls/ca.crt`,
  fixtureCertificatePath: `${root}/tls/server.crt`,
  fixtureKeyPath: `${root}/tls/server.key`,
  proofSourcePath: "/workspace/proofs",
});

test("pins the reviewed Nango and PostgreSQL images and source", () => {
  assert.equal(PROXY_PINS.nango.version, "v0.70.5");
  assert.equal(PROXY_PINS.nango.sourceCommit, "7faf2c303bbb0322333f526e9ca31c0fe95ef58e");
  assert.equal(PROXY_PINS.nango.reference, "nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed");
  assert.equal(PROXY_PINS.postgres.reference, "postgres:16.0-alpine@sha256:acf5271bbecd4b8733f4e93959a8d2b536a57aeee6cc4b6a71890aaf646425b8");
  assert.equal(PROXY_PROOF_LABEL, "m0-15");
});

test("builds one internal four-role runtime with zero host ports", () => {
  const spec = buildProxyRuntimeSpec(input);
  assert.equal(spec.prefix, `zasp-m0-15-${marker}`);
  assert.equal(spec.network.internal, true);
  assert.deepEqual(spec.roles, ["database", "nango", "fixture", "wrapper"]);
  for (const role of spec.roles) {
    assert.deepEqual(spec[role].publishedPorts, {});
    assert.equal(spec[role].network, spec.network.name);
    assert.deepEqual(spec[role].labels, {
      "zasp.dev/proof": PROXY_PROOF_LABEL,
      "zasp.dev/run": marker,
      "zasp.dev/role": role,
    });
  }
  assert.equal(spec.fixture.networkAlias, "events.1password.com");
  assert.equal(Object.isFrozen(spec), true);
});

test("binds Nango, fixture, and wrapper to exact generated material", () => {
  const spec = buildProxyRuntimeSpec(input);
  assert.equal(spec.nango.environment.NODE_EXTRA_CA_CERTS, "/proof/tls/ca.crt");
  assert.deepEqual(spec.fixture.command, ["/proofs/nango-proxy/fixture_provider.mjs"]);
  assert.deepEqual(spec.wrapper.command, ["/proofs/nango-proxy/product_wrapper.mjs"]);
  assert.deepEqual(spec.nango.mounts, [{ source: input.caCertificatePath, target: "/proof/tls/ca.crt", readOnly: true }]);
  assert.deepEqual(spec.fixture.mounts, [
    { source: input.proofSourcePath, target: "/proofs", readOnly: true },
    { source: input.fixtureCertificatePath, target: "/proof/tls/server.crt", readOnly: true },
    { source: input.fixtureKeyPath, target: "/proof/tls/server.key", readOnly: true },
  ]);
  assert.deepEqual(spec.wrapper.mounts, [
    { source: input.proofSourcePath, target: "/proofs", readOnly: true },
    { source: input.caCertificatePath, target: "/proof/tls/ca.crt", readOnly: true },
  ]);
});

test("passes the raw provider key only to fixture and wrapper, never product output fields", () => {
  const spec = buildProxyRuntimeSpec(input);
  assert.equal(spec.fixture.environment.NANGO_PROXY_PROVIDER_KEY, providerKey);
  assert.equal(spec.wrapper.environment.NANGO_PROXY_PROVIDER_KEY, providerKey);
  assert.equal(spec.wrapper.environment.NANGO_PROXY_ORGANIZATION_ID, `org_${marker}`);
  assert.equal(spec.wrapper.environment.NANGO_PROXY_INTEGRATION_KEY, `${spec.prefix}-1password-events`);
  assert.equal(spec.wrapper.environment.NANGO_PROXY_FORBIDDEN_VALUES.includes(providerKey), false);
  assert.equal(JSON.stringify({
    organizationId: spec.wrapper.environment.NANGO_PROXY_ORGANIZATION_ID,
    integrationKey: spec.wrapper.environment.NANGO_PROXY_INTEGRATION_KEY,
  }).includes(providerKey), false);
});

test("rejects malformed platform, secret, path, and extra input", () => {
  for (const mutation of [
    { ...input, marker: "short" },
    { ...input, platform: "linux/386" },
    { ...input, providerKey: "" },
    { ...input, providerKey: `eyJ${"a".repeat(17)}.ey${"b".repeat(16)}.${"c".repeat(32)}` },
    { ...input, encryptionKey: "bad" },
    { ...input, workspaceRoot: "/tmp/other" },
    { ...input, dockerConfigPath: `${root}/elsewhere` },
    { ...input, proofSourcePath: "relative" },
    { ...input, unknown: true },
  ]) assert.throws(() => buildProxyRuntimeSpec(mutation));
});

test("returns deeply isolated immutable specifications", () => {
  const first = buildProxyRuntimeSpec(input);
  const second = buildProxyRuntimeSpec(input);
  assert.deepEqual(first, second);
  assert.notEqual(first, second);
  assert.throws(() => { first.fixture.environment.NANGO_PROXY_PROVIDER_KEY = "changed"; });
});
