import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  configurationFromEnvironment,
  createFixtureProvider,
  runMain,
} from "./fixture_provider.mjs";

const clientId = "fixture-client-id";
const clientSecret = "fixture-client-secret-value";
const code = "single-use-code-value";
const accessToken = "fixture-access-token-value";
const callbackUrl = "http://zasp-m0-14b-0123456789abcdef-server:3003/oauth/callback";
const verifier = "v".repeat(64);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const state = "b".repeat(64);
const configuration = Object.freeze({
  clientId,
  clientSecret,
  code,
  accessToken,
  callbackUrl,
  hostname: "github.com",
});

function authorizeRequest(overrides = {}) {
  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: callbackUrl,
    response_type: "code",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return {
    method: "GET",
    host: "github.com",
    url: `/login/oauth/authorize?${query.toString()}`,
    headers: {},
    body: Buffer.alloc(0),
    bodyComplete: true,
    ...overrides,
  };
}

function tokenRequest(overrides = {}) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: callbackUrl,
    client_id: clientId,
    client_secret: clientSecret,
    code_verifier: verifier,
  }).toString();
  return {
    method: "POST",
    host: "github.com",
    url: "/login/oauth/access_token",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: Buffer.from(body),
    bodyComplete: true,
    ...overrides,
  };
}

test("authorizes once and exchanges one PKCE-bound code for a synthetic token", async () => {
  const fixture = createFixtureProvider(configuration);
  const authorization = await fixture.handle(authorizeRequest());

  assert.equal(authorization.status, 302);
  assert.deepEqual(authorization.headers, {
    location: `${callbackUrl}?code=${encodeURIComponent(code)}&state=${state}`,
    "content-length": "0",
  });
  assert.deepEqual(authorization.body, Buffer.alloc(0));

  const token = await fixture.handle(tokenRequest());
  assert.equal(token.status, 200);
  assert.deepEqual(token.headers, {
    "content-type": "application/json",
    "cache-control": "no-store",
    pragma: "no-cache",
  });
  assert.deepEqual(JSON.parse(token.body.toString("utf8")), {
    access_token: accessToken,
    token_type: "bearer",
    scope: "",
  });
  assert.deepEqual(fixture.state(), { authorizationUsed: true, codeUsed: true });
});

test("rejects every host, method, path, query, callback, state, and PKCE drift", async () => {
  const cases = [
    authorizeRequest({ host: "evil.example" }),
    authorizeRequest({ method: "POST" }),
    authorizeRequest({ url: "/other" }),
    authorizeRequest({ body: Buffer.from("x") }),
  ];
  const mutations = [
    ["client_id", "other"],
    ["redirect_uri", "http://evil.example/callback"],
    ["response_type", "token"],
    ["state", "short"],
    ["code_challenge", "x"],
    ["code_challenge_method", "plain"],
  ];
  for (const [key, value] of mutations) {
    const request = authorizeRequest();
    const url = new URL(request.url, "https://github.com");
    url.searchParams.set(key, value);
    cases.push({ ...request, url: `${url.pathname}${url.search}` });
  }
  const duplicate = authorizeRequest();
  duplicate.url += `&state=${state}`;
  cases.push(duplicate, { ...authorizeRequest(), url: `${authorizeRequest().url}&extra=true` });

  for (const request of cases) {
    const fixture = createFixtureProvider(configuration);
    assert.deepEqual(await fixture.handle(request), {
      status: 400,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
      body: Buffer.from('{"error":"invalid_request"}'),
    });
    assert.deepEqual(fixture.state(), { authorizationUsed: false, codeUsed: false });
  }
});

test("rejects authorization replay without changing the issued-code state", async () => {
  const fixture = createFixtureProvider(configuration);
  assert.equal((await fixture.handle(authorizeRequest())).status, 302);
  assert.equal((await fixture.handle(authorizeRequest())).status, 400);
  assert.deepEqual(fixture.state(), { authorizationUsed: true, codeUsed: false });
});

test("rejects token drift, duplicate members, overflow, disconnect, and code replay", async () => {
  const invalid = [
    tokenRequest({ host: "evil.example" }),
    tokenRequest({ method: "GET" }),
    tokenRequest({ url: "/other" }),
    tokenRequest({ headers: { "content-type": "application/json" } }),
    tokenRequest({ body: Buffer.from(`${tokenRequest().body.toString("utf8")}&code=${code}`) }),
    tokenRequest({ body: Buffer.alloc(16_385, 0x61) }),
    tokenRequest({ bodyComplete: false }),
  ];
  for (const [key, value] of [
    ["grant_type", "client_credentials"],
    ["code", "wrong"],
    ["redirect_uri", "http://evil.example/callback"],
    ["client_id", "wrong"],
    ["client_secret", "wrong"],
    ["code_verifier", "wrong"],
  ]) {
    const body = new URLSearchParams(tokenRequest().body.toString("utf8"));
    body.set(key, value);
    invalid.push(tokenRequest({ body: Buffer.from(body.toString()) }));
  }
  for (const request of invalid) {
    const fixture = createFixtureProvider(configuration);
    await fixture.handle(authorizeRequest());
    assert.equal((await fixture.handle(request)).status, 400);
    assert.deepEqual(fixture.state(), { authorizationUsed: true, codeUsed: false });
  }

  const fixture = createFixtureProvider(configuration);
  await fixture.handle(authorizeRequest());
  assert.equal((await fixture.handle(tokenRequest())).status, 200);
  assert.equal((await fixture.handle(tokenRequest())).status, 400);
  assert.deepEqual(fixture.state(), { authorizationUsed: true, codeUsed: true });
});

test("rejects malformed configuration before creating server state", () => {
  for (const mutation of [
    { ...configuration, hostname: "example.com" },
    { ...configuration, callbackUrl: "https://example.com/callback" },
    { ...configuration, clientSecret: "" },
    { ...configuration, unknown: true },
  ]) {
    assert.throws(() => createFixtureProvider(mutation));
  }
});

test("does not coerce hostile request values or emit request data", async () => {
  let coerced = false;
  const hostile = { toString() { coerced = true; throw new Error(clientSecret); } };
  const fixture = createFixtureProvider(configuration);
  const response = await fixture.handle({ ...authorizeRequest(), url: hostile });
  assert.equal(response.status, 400);
  assert.equal(coerced, false);
  assert.equal(response.body.includes(Buffer.from(clientSecret)), false);
});

test("wires HTTPS server requests through the same strict handler", async () => {
  const events = [];
  const fakeServer = {
    listen(port, host, callback) { events.push(["listen", port, host]); callback(); return this; },
    close(callback) { events.push(["close"]); callback(); },
    on() { return this; },
  };
  const fixture = createFixtureProvider(configuration, {
    createServer: (options, listener) => {
      events.push(["create", options, typeof listener]);
      return fakeServer;
    },
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

test("keeps startup failure output fixed and secret-free", async () => {
  let stdout = "";
  let stderr = "";
  const code_ = await runMain(configuration, {
    createServer: () => { throw new Error(clientSecret); },
    key: Buffer.from("key"),
    certificate: Buffer.from("certificate"),
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
  });
  assert.equal(code_, 1);
  assert.equal(stdout, "");
  assert.equal(stderr, "Nango OAuth fixture failed.\n");
  assert.equal(stderr.includes(clientSecret), false);
});

test("accepts Node's special process.env record without relaxing provider JSON", () => {
  const environment = Object.assign(Object.create({}), {
    NANGO_OAUTH_CLIENT_ID: clientId,
    NANGO_OAUTH_CLIENT_SECRET: clientSecret,
    NANGO_OAUTH_CODE: code,
    NANGO_OAUTH_ACCESS_TOKEN: accessToken,
    NANGO_OAUTH_CALLBACK_URL: callbackUrl,
    NANGO_OAUTH_HOSTNAME: "github.com",
    NANGO_OAUTH_TLS_KEY_PATH: "/proof/tls/server.key",
    NANGO_OAUTH_TLS_CERTIFICATE_PATH: "/proof/tls/server.crt",
  });
  assert.deepEqual(configurationFromEnvironment(environment), { ...configuration, tlsKeyPath: "/proof/tls/server.key", tlsCertificatePath: "/proof/tls/server.crt" });
});
