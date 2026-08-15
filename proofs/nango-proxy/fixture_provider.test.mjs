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

function request(stage = "verification", overrides = {}) {
  return {
    method: "GET",
    host: "events.1password.com",
    url: stage === "verification" ? "/api/v2/auth/introspect" : "/api/v2/events?limit=1",
    headers: {
      accept: "application/json, text/plain, */*",
      authorization: `Bearer ${providerKey}`,
    },
    body: Buffer.alloc(0),
    bodyComplete: true,
    ...overrides,
  };
}

test("accepts exact ordered verification and proxied event requests once", async () => {
  const fixture = createFixtureProvider(configuration);
  assert.deepEqual(await fixture.handle(request("verification")), {
    status: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: Buffer.from('{"features":[],"items":[]}'),
  });
  assert.deepEqual(fixture.state(), { verificationUsed: true, proxyUsed: false });

  assert.deepEqual(await fixture.handle(request("proxy")), {
    status: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: Buffer.from('{"cursor":null,"items":[{"action":"item.usage","uuid":"11111111-1111-4111-8111-111111111111"}]}'),
  });
  assert.deepEqual(fixture.state(), { verificationUsed: true, proxyUsed: true });
  assert.equal((await fixture.handle(request("verification"))).status, 400);
  assert.equal((await fixture.handle(request("proxy"))).status, 400);
});

test("rejects the proxy request before exact credential verification", async () => {
  const fixture = createFixtureProvider(configuration);
  assert.equal((await fixture.handle(request("proxy"))).status, 400);
  assert.deepEqual(fixture.state(), { verificationUsed: false, proxyUsed: false });
  assert.equal((await fixture.handle(request("verification"))).status, 200);
  assert.equal((await fixture.handle(request("proxy"))).status, 200);
});

test("rejects host, method, path, query, body, authorization, and content drift at either stage", async () => {
  const invalid = [
    request("verification", { host: "evil.example" }),
    request("verification", { method: "POST" }),
    request("verification", { url: "/api/v2/auth/introspect?extra=true" }),
    request("verification", { url: "/other" }),
    request("verification", { body: Buffer.from("x") }),
    request("verification", { body: Buffer.alloc(16_385, 0x61) }),
    request("verification", { bodyComplete: false }),
    request("verification", { headers: { accept: "application/json, text/plain, */*", authorization: "Bearer wrong" } }),
    request("verification", { headers: { accept: "text/plain", authorization: `Bearer ${providerKey}` } }),
    request("verification", { headers: { accept: "application/json, text/plain, */*", authorization: [`Bearer ${providerKey}`] } }),
  ];
  for (const value of invalid) {
    const fixture = createFixtureProvider(configuration);
    assert.equal((await fixture.handle(value)).status, 400);
    assert.deepEqual(fixture.state(), { verificationUsed: false, proxyUsed: false });
  }

  for (const value of [
    request("proxy", { url: "/api/v2/events" }),
    request("proxy", { url: "/api/v2/events?limit=01" }),
    request("proxy", { url: "/api/v2/events?limit=1&extra=true" }),
    request("proxy", { method: "POST" }),
    request("proxy", { body: Buffer.from("x") }),
    request("proxy", { headers: { accept: "application/json", authorization: `Bearer ${providerKey}` } }),
  ]) {
    const fixture = createFixtureProvider(configuration);
    assert.equal((await fixture.handle(request("verification"))).status, 200);
    assert.equal((await fixture.handle(value)).status, 400);
    assert.deepEqual(fixture.state(), { verificationUsed: true, proxyUsed: false });
  }
});

test("rejects malformed configuration and hostile coercion", async () => {
  for (const value of [
    { ...configuration, hostname: "example.com" },
    { ...configuration, providerKey: "" },
    { ...configuration, providerKey: `eyJ${"a".repeat(17)}.ey${"b".repeat(16)}.${"c".repeat(32)}` },
    { ...configuration, unknown: true },
  ]) assert.throws(() => createFixtureProvider(value));

  let coerced = false;
  const hostile = { toString() { coerced = true; throw new Error(providerKey); } };
  const fixture = createFixtureProvider(configuration);
  assert.equal((await fixture.handle({ ...request("verification"), url: hostile })).status, 400);
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
  assert.equal(stderr, "Nango proxy fixture failed.\n");
  assert.equal(stderr.includes(providerKey), false);
});

test("accepts process.env-shaped configuration without extra keys", () => {
  const environment = Object.assign(Object.create({}), {
    NANGO_PROXY_PROVIDER_KEY: providerKey,
    NANGO_PROXY_HOSTNAME: "events.1password.com",
    NANGO_PROXY_TLS_KEY_PATH: "/proof/tls/server.key",
    NANGO_PROXY_TLS_CERTIFICATE_PATH: "/proof/tls/server.crt",
  });
  assert.deepEqual(configurationFromEnvironment(environment), {
    ...configuration,
    tlsKeyPath: "/proof/tls/server.key",
    tlsCertificatePath: "/proof/tls/server.crt",
  });
});
