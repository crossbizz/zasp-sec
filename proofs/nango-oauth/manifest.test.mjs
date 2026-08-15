import assert from "node:assert/strict";
import test from "node:test";

import {
  OAUTH_PINS,
  OAUTH_PROOF_LABEL,
  buildOAuthRuntimeSpec,
  validateOAuthMarker,
} from "./manifest.mjs";

const marker = "0123456789abcdef";
const input = Object.freeze({
  marker,
  platform: "linux/amd64",
  password: "A".repeat(32),
  encryptionKey: Buffer.alloc(32, 2).toString("base64"),
  clientId: "client_0123456789abcdef",
  clientSecret: "client-secret-0123456789abcdef",
  code: "code-0123456789abcdef",
  accessToken: "token-0123456789abcdef",
  workspaceRoot: "/private/tmp/zasp-m0-14b-0123456789abcdef-ABC123",
  dockerConfigPath: "/private/tmp/zasp-m0-14b-0123456789abcdef-ABC123/docker-config",
  caCertificatePath: "/private/tmp/zasp-m0-14b-0123456789abcdef-ABC123/tls/ca.crt",
  fixtureCertificatePath: "/private/tmp/zasp-m0-14b-0123456789abcdef-ABC123/tls/server.crt",
  fixtureKeyPath: "/private/tmp/zasp-m0-14b-0123456789abcdef-ABC123/tls/server.key",
  proofSourcePath: "/workspace/proofs",
});

test("pins the exact completed M0-14a images and Nango source", () => {
  assert.equal(OAUTH_PINS.nango.version, "v0.70.5");
  assert.equal(OAUTH_PINS.nango.sourceCommit, "7faf2c303bbb0322333f526e9ca31c0fe95ef58e");
  assert.equal(OAUTH_PINS.nango.sourceTagObject, "bf8ea10293c20c6d8affff754205851011023285");
  assert.equal(OAUTH_PINS.nango.reference, "nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed");
  assert.equal(OAUTH_PINS.postgres.reference, "postgres:16.0-alpine@sha256:acf5271bbecd4b8733f4e93959a8d2b536a57aeee6cc4b6a71890aaf646425b8");
  assert.equal(OAUTH_PROOF_LABEL, "m0-14b");
});

test("builds one internal four-role OAuth runtime with zero host ports", () => {
  const spec = buildOAuthRuntimeSpec(input);
  assert.equal(spec.prefix, `zasp-m0-14b-${marker}`);
  assert.equal(spec.network.internal, true);
  assert.deepEqual(spec.roles, ["database", "nango", "fixture", "wrapper"]);
  for (const role of spec.roles) {
    assert.deepEqual(spec[role].publishedPorts, {});
    assert.equal(spec[role].network, spec.network.name);
    assert.equal(spec[role].labels["zasp.dev/proof"], OAUTH_PROOF_LABEL);
    assert.equal(spec[role].labels["zasp.dev/run"], marker);
    assert.equal(spec[role].labels["zasp.dev/role"], role);
  }
  assert.equal(spec.fixture.networkAlias, "github.com");
  assert.equal(spec.nango.networkAlias, spec.nango.name);
  assert.equal(Object.isFrozen(spec), true);
});

test("binds Nango, fixture, and wrapper to the generated CA and exact source", () => {
  const spec = buildOAuthRuntimeSpec(input);
  assert.equal(spec.nango.environment.FLAG_AUTH_ENABLED, "false");
  assert.equal(spec.nango.environment.NODE_EXTRA_CA_CERTS, "/proof/tls/ca.crt");
  assert.equal(spec.nango.environment.NANGO_PUBLIC_CONNECT_URL, `http://${spec.nango.name}:3003/connect`);
  assert.equal(spec.nango.environment.NANGO_PUBLIC_SERVER_URL, `http://${spec.nango.name}:3003`);
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
  assert.deepEqual(spec.fixture.command, ["/proofs/nango-oauth/fixture_provider.mjs"]);
  assert.deepEqual(spec.wrapper.command, ["/proofs/nango-oauth/product_wrapper.mjs"]);
});

test("uses only generated OAuth values and durable Organization identifiers", () => {
  const spec = buildOAuthRuntimeSpec(input);
  assert.equal(spec.fixture.environment.NANGO_OAUTH_CLIENT_ID, input.clientId);
  assert.equal(spec.fixture.environment.NANGO_OAUTH_CLIENT_SECRET, input.clientSecret);
  assert.equal(spec.fixture.environment.NANGO_OAUTH_CODE, input.code);
  assert.equal(spec.fixture.environment.NANGO_OAUTH_ACCESS_TOKEN, input.accessToken);
  assert.equal(spec.wrapper.environment.NANGO_OAUTH_ORGANIZATION_ID, `org_${marker}`);
  assert.equal(spec.wrapper.environment.NANGO_OAUTH_END_USER_ID, `user_${marker}`);
  assert.equal(spec.wrapper.environment.NANGO_OAUTH_INTEGRATION_KEY, `${spec.prefix}-github`);
  assert.equal(spec.wrapper.environment.NANGO_OAUTH_FORBIDDEN_VALUES, [input.clientSecret, input.code, input.accessToken].join(","));
});

test("rejects malformed markers, platforms, secrets, and ownership paths", () => {
  for (const value of ["short", "A".repeat(16), "0".repeat(17), null]) assert.throws(() => validateOAuthMarker(value));
  for (const mutation of [
    { ...input, platform: "linux/386" },
    { ...input, clientSecret: "" },
    { ...input, encryptionKey: "bad" },
    { ...input, workspaceRoot: "/tmp/other" },
    { ...input, dockerConfigPath: `${input.workspaceRoot}/elsewhere` },
    { ...input, proofSourcePath: "relative" },
    { ...input, unknown: true },
  ]) assert.throws(() => buildOAuthRuntimeSpec(mutation));
});

test("returns deeply isolated specifications", () => {
  const first = buildOAuthRuntimeSpec(input);
  const second = buildOAuthRuntimeSpec(input);
  assert.deepEqual(first, second);
  assert.notEqual(first, second);
  assert.throws(() => { first.fixture.environment.NANGO_OAUTH_CODE = "changed"; });
});
