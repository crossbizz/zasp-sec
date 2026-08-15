import assert from "node:assert/strict";
import test from "node:test";

import {
  configurationFromEnvironment,
  createFixtureProvider,
  runMain,
} from "./fixture_provider.mjs";

const providerKey = `eyJ${"a".repeat(16)}.ey${"b".repeat(16)}.${"c".repeat(32)}`;
const configuration = Object.freeze({
  hostname: "events.1password.com",
  providerKey,
});

function request(overrides = {}) {
  return {
    method: "GET",
    host: "events.1password.com",
    url: "/api/v2/auth/introspect",
    headers: {
      accept: "application/json, text/plain, */*",
      authorization: `Bearer ${providerKey}`,
    },
    body: Buffer.alloc(0),
    bodyComplete: true,
    ...overrides,
  };
}

test("accepts one exact bearer introspection request and rejects replay", async () => {
  const fixture = createFixtureProvider(configuration);
  const accepted = await fixture.handle(request());
  assert.deepEqual(accepted, {
    status: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: Buffer.from('{"features":[],"items":[]}'),
  });
  assert.deepEqual(fixture.state(), { verificationUsed: true });
  assert.equal((await fixture.handle(request())).status, 400);
});

test("rejects host, method, path, query, body, authorization, and content drift", async () => {
  const invalid = [
    request({ host: "evil.example" }),
    request({ method: "POST" }),
    request({ url: "/api/v2/auth/introspect?extra=true" }),
    request({ url: "/other" }),
    request({ body: Buffer.from("x") }),
    request({ body: Buffer.alloc(16_385, 0x61) }),
    request({ bodyComplete: false }),
    request({ headers: { accept: "application/json, text/plain, */*", authorization: "Bearer wrong" } }),
    request({ headers: { accept: "text/plain", authorization: `Bearer ${providerKey}` } }),
    request({ headers: { accept: "application/json, text/plain, */*", authorization: [`Bearer ${providerKey}`] } }),
  ];
  for (const value of invalid) {
    const fixture = createFixtureProvider(configuration);
    assert.equal((await fixture.handle(value)).status, 400);
    assert.deepEqual(fixture.state(), { verificationUsed: false });
  }
});

test("rejects malformed configuration and hostile coercion", async () => {
  for (const value of [
    { ...configuration, hostname: "example.com" },
    { ...configuration, providerKey: "" },
    { ...configuration, unknown: true },
  ]) assert.throws(() => createFixtureProvider(value));

  let coerced = false;
  const hostile = { toString() { coerced = true; throw new Error(providerKey); } };
  const fixture = createFixtureProvider(configuration);
  assert.equal((await fixture.handle({ ...request(), url: hostile })).status, 400);
  assert.equal(coerced, false);
});

test("wires HTTPS with bounded exact TLS material", async () => {
  const events = [];
  const fakeServer = {
    listen(port, host, callback) { events.push(["listen", port, host]); callback(); return this; },
    close(callback) { events.push(["close"]); callback(); },
    once() { return this; },
    removeListener() { return this; },
  };
  const fixture = createFixtureProvider(configuration, {
    createServer: (options, listener) => { events.push(["create", options, typeof listener]); return fakeServer; },
    key: Buffer.from("key"),
    certificate: Buffer.from("certificate"),
  });
  await fixture.listen(443, "0.0.0.0");
  await fixture.close();
  assert.deepEqual(events, [
    ["create", { key: Buffer.from("key"), cert: Buffer.from("certificate") }, "function"],
    ["listen", 443, "0.0.0.0"],
    ["close"],
  ]);
});

test("keeps startup failure output fixed and provider-key free", async () => {
  let stdout = "";
  let stderr = "";
  const code = await runMain(configuration, {
    createServer: () => { throw new Error(providerKey); },
    key: Buffer.from("key"),
    certificate: Buffer.from("certificate"),
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
  });
  assert.equal(code, 1);
  assert.equal(stdout, "");
  assert.equal(stderr, "Nango API-key fixture failed.\n");
  assert.equal(stderr.includes(providerKey), false);
});

test("accepts process.env-shaped configuration without extra keys", () => {
  const environment = Object.assign(Object.create({}), {
    NANGO_API_KEY_PROVIDER_KEY: providerKey,
    NANGO_API_KEY_HOSTNAME: "events.1password.com",
    NANGO_API_KEY_TLS_KEY_PATH: "/proof/tls/server.key",
    NANGO_API_KEY_TLS_CERTIFICATE_PATH: "/proof/tls/server.crt",
  });
  assert.deepEqual(configurationFromEnvironment(environment), {
    ...configuration,
    tlsKeyPath: "/proof/tls/server.key",
    tlsCertificatePath: "/proof/tls/server.crt",
  });
});
