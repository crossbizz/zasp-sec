import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  PINS,
  PROOF_LABEL,
  buildRuntimeSpec,
  parseBoundedUniqueJson,
  parseReadyOutput,
  validateMarker,
} from "./manifest.mjs";

const marker = "0123456789abcdef";
const password = "p".repeat(32);
const encryptionKey = Buffer.alloc(32, 7).toString("base64");

function runtime(platform = "linux/arm64") {
  return buildRuntimeSpec({ marker, platform, password, encryptionKey });
}

test("pins the exact current official free self-hosted runtime images", () => {
  assert.deepEqual(PINS.nango, {
    version: "v0.70.5",
    sourceCommit: "7faf2c303bbb0322333f526e9ca31c0fe95ef58e",
    sourceTagObject: "bf8ea10293c20c6d8affff754205851011023285",
    reference: "nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed",
    platform: "linux/amd64",
    manifestDigest: "sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed",
    configDigest: "sha256:41de4cc7a0061baefb846306d6666f74ddd4ca46d0b51b7bd24ffa2581a482d9",
  });
  assert.equal(PINS.postgres.reference, "postgres:16.0-alpine@sha256:acf5271bbecd4b8733f4e93959a8d2b536a57aeee6cc4b6a71890aaf646425b8");
  assert.deepEqual(PINS.postgres, {
    version: "16.0-alpine",
    reference: "postgres:16.0-alpine@sha256:acf5271bbecd4b8733f4e93959a8d2b536a57aeee6cc4b6a71890aaf646425b8",
  });
  assert.equal(PINS.probe.reference, "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9");
  assert.equal(PINS.probe.version, "1.36.1-1");
});

test("accepts only the exact marker grammar", () => {
  assert.equal(validateMarker(marker), marker);
  for (const candidate of ["", "a".repeat(15), "a".repeat(17), "ABCDEF0123456789", "../../owned", 1, null]) {
    assert.throws(() => validateMarker(candidate));
  }
});

test("builds exactly two long-running services and one product probe", () => {
  const spec = runtime();

  assert.equal(PROOF_LABEL, "m0-14a");
  assert.equal(spec.prefix, `zasp-m0-14a-${marker}`);
  assert.deepEqual(spec.serviceRoles, ["database", "nango"]);
  assert.equal(spec.network.internal, true);
  assert.equal(spec.network.name, `${spec.prefix}-network`);
  assert.deepEqual(spec.network.labels, {
    "zasp.dev/proof": PROOF_LABEL,
    "zasp.dev/run": marker,
    "zasp.dev/role": "network",
  });
  assert.equal(spec.database.name, `${spec.prefix}-db`);
  assert.equal(spec.nango.name, `${spec.prefix}-server`);
  assert.equal(spec.probe.name, `${spec.prefix}-probe`);
  assert.deepEqual(spec.database.publishedPorts, {});
  assert.deepEqual(spec.nango.publishedPorts, {});
  assert.deepEqual(spec.probe.publishedPorts, {});
  assert.equal(Object.isFrozen(spec), true);
  assert.equal(Object.isFrozen(spec.nango.environment), true);
});

test("uses separate marker-scoped storage and one exact free boot environment", () => {
  const spec = runtime();
  const env = spec.nango.environment;

  assert.equal(spec.database.databaseName, `nango_${marker}`);
  assert.equal(spec.database.schema, "nango");
  assert.equal(spec.database.recordsSchema, "nango_records");
  assert.equal(
    env.NANGO_DATABASE_URL,
    `postgresql://${spec.database.user}:${password}@${spec.database.name}:5432/${spec.database.databaseName}`,
  );
  assert.equal(env.NANGO_DB_NAME, spec.database.databaseName);
  assert.equal(env.NANGO_DB_SCHEMA, spec.database.schema);
  assert.equal(env.RECORDS_DATABASE_SCHEMA, spec.database.recordsSchema);
  assert.equal(env.NANGO_ENCRYPTION_KEY, encryptionKey);
  assert.equal(env.FLAG_SERVE_CONNECT_UI, "false");
  assert.equal(env.NANGO_LOGS_ENABLED, "false");
  assert.equal(env.NANGO_TELEMETRY_SDK, "false");
  assert.equal(env.NANGO_CLOUD, "false");
  assert.equal(env.NANGO_ENTERPRISE, "false");
  assert.equal(env.FLAG_AUTH_ROLES_ENABLED, "false");
  assert.equal(env.NANGO_MIGRATE_AT_START, "true");
  assert.equal(env.SERVER_PORT, "3003");
  assert.equal(env.NANGO_SERVER_URL, `http://${spec.nango.name}:3003`);
  assert.deepEqual(Object.keys(env).sort(), [
    "CSP_REPORT_ONLY",
    "FLAG_AUTH_ROLES_ENABLED",
    "FLAG_SERVE_CONNECT_UI",
    "NANGO_CLOUD",
    "NANGO_DATABASE_URL",
    "NANGO_DB_APPLICATION_NAME",
    "NANGO_DB_NAME",
    "NANGO_DB_POOL_MAX",
    "NANGO_DB_POOL_MIN",
    "NANGO_DB_SCHEMA",
    "NANGO_DB_SSL",
    "NANGO_ENCRYPTION_KEY",
    "NANGO_ENTERPRISE",
    "NANGO_LOGS_ENABLED",
    "NANGO_MIGRATE_AT_START",
    "NANGO_PUBLIC_SERVER_URL",
    "NANGO_SERVER_URL",
    "NANGO_TELEMETRY_SDK",
    "RECORDS_DATABASE_POOL_MAX",
    "RECORDS_DATABASE_POOL_MIN",
    "RECORDS_DATABASE_SCHEMA",
    "RECORDS_DATABASE_URL",
    "SERVER_PORT",
  ]);
  assert.equal(Object.keys(env).some((key) => /REDIS|ELASTIC|ORCHESTRATOR|FUNCTION|WEBHOOK|MCP|WORKOS|RBAC/i.test(key)), false);
});

test("keeps the product probe fixed on database-backed ready over the private network", () => {
  const spec = runtime("linux/amd64");

  assert.equal(spec.probe.endpoint, `http://${spec.nango.name}:3003/ready`);
  assert.equal(spec.probe.expectedOutput, '{"result":"ok"}');
  assert.deepEqual(spec.probe.command.slice(0, 2), ["sh", "-ec"]);
  assert.match(spec.probe.command[2], /\/ready/);
  assert.doesNotMatch(spec.probe.command[2], /\/health/);
  assert.deepEqual(spec.probe.environment, {});
  assert.equal(spec.probe.network, spec.network.name);
});

test("the product probe rejects redirects and preserves exact response bytes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zasp-nango-probe-test-"));
  const fakeNetcat = join(directory, "nc");
  await writeFile(fakeNetcat, `#!/bin/sh
case "$FAKE_MODE" in
  exact) printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 15\\r\\n\\r\\n%s' '{"result":"ok"}' ;;
  newline) printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 16\\r\\n\\r\\n%s\\n' '{"result":"ok"}' ;;
  redirect) printf 'HTTP/1.1 302 Found\\r\\nLocation: http://foreign/\\r\\nContent-Length: 15\\r\\n\\r\\n%s' '{"result":"ok"}' ;;
  extra) printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 23\\r\\n\\r\\nJUNK\\r\\n\\r\\n%s' '{"result":"ok"}' ;;
  *) exit 9 ;;
esac
`, { mode: 0o700 });
  await chmod(fakeNetcat, 0o700);
  try {
    const script = runtime().probe.command[2]
      .replace("seq 1 240", "seq 1 1")
      .replace("sleep 1", "sleep 0");
    const execute = (mode) => spawnSync("sh", ["-ec", script], {
      encoding: "utf8",
      env: { PATH: `${directory}:/bin:/usr/bin`, FAKE_MODE: mode },
    });
    const exact = execute("exact");
    assert.equal(exact.status, 0);
    assert.equal(exact.stdout, '{"result":"ok"}');
    assert.equal(exact.stderr, "");
    for (const mode of ["newline", "redirect", "extra"]) {
      const hostile = execute(mode);
      assert.notEqual(hostile.status, 0, mode);
      assert.equal(hostile.stdout, "", mode);
      assert.equal(hostile.stderr, "", mode);
    }
    assert.match(script, /HTTP\/1\.1 200 OK/);
    assert.match(script, /nc -w 2/);
    assert.doesNotMatch(script, /wget|body=\$\(/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejects unsupported platforms and malformed synthetic secret inputs", () => {
  for (const changed of [
    { platform: "darwin/arm64" },
    { platform: "linux/386" },
    { password: "short" },
    { password: "p".repeat(31) + ":" },
    { encryptionKey: Buffer.alloc(31).toString("base64") },
    { encryptionKey: Buffer.alloc(32, 7).toString("base64").replace(/=$/, "") },
  ]) {
    assert.throws(() => buildRuntimeSpec({ marker, platform: "linux/arm64", password, encryptionKey, ...changed }));
  }
});

test("strict bounded JSON parser rejects duplicate, malformed, and oversized data", () => {
  assert.deepEqual(parseBoundedUniqueJson(Buffer.from('{"outer":{"value":1},"items":[true,null]}')), {
    outer: { value: 1 },
    items: [true, null],
  });
  for (const source of [
    '{"value":1,"value":2}',
    '{"outer":{"value":1,"value":2}}',
    '{"value":1} trailing',
    '{"value":01}',
    Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]),
    Buffer.alloc(65_537, 0x20),
  ]) {
    assert.throws(() => parseBoundedUniqueJson(source));
  }
});

test("accepts only the exact canonical readiness output", () => {
  assert.deepEqual(parseReadyOutput(Buffer.from('{"result":"ok"}')), { result: "ok" });
  for (const source of [
    '{"result":"ok"}\n',
    ' {"result":"ok"}',
    '{"result":"OK"}',
    '{"Result":"ok"}',
    '{"result":"ok","extra":true}',
    '{"result":"not ready"}',
    '{"result":"not ready","result":"ok"}',
    'null',
  ]) {
    assert.throws(() => parseReadyOutput(Buffer.from(source)));
  }
});

test("returns deeply isolated specifications for repeated builds", () => {
  const first = runtime();
  const second = runtime();

  assert.notEqual(first, second);
  assert.deepEqual(first, second);
  assert.throws(() => { first.nango.environment.NANGO_CLOUD = "true"; });
  assert.throws(() => { first.serviceRoles.push("redis"); });
});
