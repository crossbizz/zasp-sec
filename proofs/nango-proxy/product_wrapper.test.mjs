import assert from "node:assert/strict";
import test from "node:test";

import {
  Failure,
  boundedRequest,
  configurationFromEnvironment,
  runMain,
  runProxyConnection,
} from "./product_wrapper.mjs";

const apiKey = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const connectToken = `nango_connect_session_${"a".repeat(64)}`;
const connectionId = "22222222-2222-4222-8222-222222222222";
const providerKey = `eyJ${"a".repeat(16)}.ey${"b".repeat(16)}.${"c".repeat(32)}`;
const timestamp = "2026-08-15T00:00:00.000Z";
const connectionTimestamp = "2026-08-15T00:00:00.000+00:00";
const event = Object.freeze({ action: "item.usage", uuid: "11111111-1111-4111-8111-111111111111" });
const input = Object.freeze({
  baseUrl: "http://nango:3003",
  environment: "dev",
  organizationId: "org_0123456789abcdef",
  endUserId: "user_0123456789abcdef",
  integrationKey: "zasp-m0-15-0123456789abcdef-1password-events",
  providerKey,
  forbiddenValues: ["database-secret", "encryption-secret"],
});

function json(status, value) {
  return { status, headers: { "content-type": "application/json" }, body: Buffer.from(JSON.stringify(value)) };
}

function happyTransport(options = {}) {
  const calls = [];
  const request = async (specification) => {
    calls.push(specification);
    const url = new URL(specification.url);
    if (url.pathname === "/api/v1/environment/api-keys") return json(200, {
      data: [{ id: 1, display_name: "Dev Secret Key", scopes: ["environment:*"], secret: apiKey, last_used_at: null, created_at: timestamp, updated_at: timestamp }],
    });
    if (url.pathname === "/api/v1/integrations") return json(200, { data: {
      id: 2,
      unique_key: input.integrationKey,
      provider: "1password-events",
      oauth_client_id: null,
      oauth_client_secret: null,
      oauth_scopes: null,
      environment_id: 3,
      app_link: null,
      custom: null,
      missing_fields: [],
      display_name: input.integrationKey,
      forward_webhooks: false,
      shared_credentials_id: null,
      created_at: timestamp,
      updated_at: timestamp,
    } });
    if (url.pathname === "/api/v1/connect/sessions") return json(201, { data: {
      token: connectToken,
      connect_link: `${input.baseUrl}/connect/session?session_token=${connectToken}`,
      expires_at: timestamp,
    } });
    if (url.pathname === `/api-auth/api-key/${input.integrationKey}`) return json(200, {
      connectionId,
      providerConfigKey: input.integrationKey,
    });
    if (url.pathname === "/api/v1/connections") return json(200, { data: [{
      id: 4,
      connection_id: connectionId,
      provider_config_key: input.integrationKey,
      provider: "1password-events",
      errors: [],
      endUser: { id: input.endUserId, display_name: null, email: null, tags: { origin: "nango_dashboard" }, organization: { id: input.organizationId, display_name: null } },
      tags: { end_user_id: input.endUserId, organization_id: input.organizationId, origin: "nango_dashboard" },
      pausedSyncs: [],
      created_at: connectionTimestamp,
      updated_at: connectionTimestamp,
    }] });
    if (url.pathname === "/proxy/api/v2/events") return json(200, { cursor: null, items: [event] });
    throw new Error("unexpected request");
  };
  return { calls, request: options.request ?? request };
}

test("creates one verified connection, proxies one GET, and returns only scoped normalized state", async () => {
  const transport = happyTransport();
  const result = await runProxyConnection(input, { request: transport.request, sleep: async () => {} });
  assert.deepEqual(result, {
    organizationId: input.organizationId,
    integrationKey: input.integrationKey,
    connectionId,
    event: { id: event.uuid, action: event.action },
  });
  assert.deepEqual(transport.calls.map((call) => [call.method, new URL(call.url).pathname]), [
    ["GET", "/api/v1/environment/api-keys"],
    ["POST", "/api/v1/integrations"],
    ["POST", "/api/v1/connect/sessions"],
    ["POST", `/api-auth/api-key/${input.integrationKey}`],
    ["GET", "/api/v1/connections"],
    ["GET", "/proxy/api/v2/events"],
  ]);
  assert.deepEqual(JSON.parse(transport.calls[1].body), {
    provider: "1password-events",
    integrationId: input.integrationKey,
    displayName: input.integrationKey,
    forward_webhooks: false,
    useSharedCredentials: false,
  });
  const authorizationUrl = new URL(transport.calls[3].url);
  assert.equal(authorizationUrl.searchParams.size, 2);
  assert.equal(authorizationUrl.searchParams.get("connect_session_token"), connectToken);
  assert.equal(authorizationUrl.searchParams.get("params[domain]"), "events.1password.com");
  assert.deepEqual(JSON.parse(transport.calls[3].body), { apiKey: providerKey });

  const proxyCall = transport.calls[5];
  const proxyUrl = new URL(proxyCall.url);
  assert.equal(proxyUrl.searchParams.size, 1);
  assert.equal(proxyUrl.searchParams.get("limit"), "1");
  assert.deepEqual(proxyCall.headers, {
    authorization: `Bearer ${apiKey}`,
    "connection-id": connectionId,
    "provider-config-key": input.integrationKey,
  });
  assert.equal(proxyCall.redirect, "manual");
  assert.equal(proxyCall.body, undefined);

  const output = JSON.stringify(result);
  for (const secret of [providerKey, apiKey, connectToken, ...input.forbiddenValues]) assert.equal(output.includes(secret), false);
});

test("accepts an exact process.env-shaped configuration", () => {
  const environment = Object.assign(Object.create({}), {
    NANGO_PROXY_BASE_URL: input.baseUrl,
    NANGO_PROXY_ENVIRONMENT: input.environment,
    NANGO_PROXY_ORGANIZATION_ID: input.organizationId,
    NANGO_PROXY_END_USER_ID: input.endUserId,
    NANGO_PROXY_INTEGRATION_KEY: input.integrationKey,
    NANGO_PROXY_PROVIDER_KEY: providerKey,
    NANGO_PROXY_FORBIDDEN_VALUES: input.forbiddenValues.join(","),
  });
  assert.deepEqual(configurationFromEnvironment(environment), input);
});

test("keeps top-level output fixed and secret-free", async () => {
  let stdout = "";
  let stderr = "";
  const code = await runMain(input, {
    request: async () => { throw new Error(providerKey); },
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
  });
  assert.equal(code, 1);
  assert.equal(stdout, "");
  assert.equal(stderr, "Nango proxy wrapper failed.\n");
  assert.equal(stderr.includes(providerKey), false);
});

test("rejects malformed input before transport", async () => {
  for (const mutation of [
    { ...input, baseUrl: "https://evil.example" },
    { ...input, organizationId: "other" },
    { ...input, integrationKey: "wrong" },
    { ...input, providerKey: "" },
    { ...input, providerKey: `eyJ${"a".repeat(17)}.ey${"b".repeat(16)}.${"c".repeat(32)}` },
    { ...input, forbiddenValues: [] },
    { ...input, extra: true },
  ]) {
    let called = false;
    await assert.rejects(() => runProxyConnection(mutation, { request: async () => { called = true; } }), Failure);
    assert.equal(called, false);
  }
});

test("rejects duplicate-key, unknown-key, malformed, and oversized provider JSON", async () => {
  const cases = [
    Buffer.from('{"data":[],"data":[]}'),
    Buffer.from('{"data":[],"extra":true}'),
    Buffer.from("null"),
    Buffer.alloc(65_537, 0x61),
  ];
  for (const body of cases) {
    await assert.rejects(() => runProxyConnection(input, {
      request: async () => ({ status: 200, headers: {}, body }),
    }), Failure);
  }
});

test("rejects non-JSON and duplicate JSON content-type response headers", async () => {
  for (const headers of [
    { "content-type": "text/plain" },
    { "content-type": "application/json", "Content-Type": "application/json" },
  ]) {
    let first = true;
    const base = happyTransport();
    await assert.rejects(() => runProxyConnection(input, {
      request: async (specification) => {
        const response = await base.request(specification);
        if (!first) return response;
        first = false;
        return { ...response, headers };
      },
    }), Failure);
  }
});

test("rejects connection and proxied provider response drift", async () => {
  const mutations = [
    (value, path) => path.includes("/api-auth/api-key/") ? { connectionId: "33333333-3333-4333-8333-333333333333", providerConfigKey: input.integrationKey } : value,
    (value, path) => path === "/api/v1/connections" ? { data: [] } : value,
    (value, path) => path === "/proxy/api/v2/events" ? { cursor: null, items: [] } : value,
    (value, path) => path === "/proxy/api/v2/events" ? { cursor: "next", items: [event] } : value,
    (value, path) => path === "/proxy/api/v2/events" ? { cursor: null, items: [{ ...event, extra: true }] } : value,
    (value, path) => path === "/proxy/api/v2/events" ? { cursor: null, items: [{ action: providerKey, uuid: event.uuid }] } : value,
  ];
  for (const mutate of mutations) {
    const base = happyTransport();
    await assert.rejects(() => runProxyConnection(input, {
      maximumPollAttempts: 1,
      request: async (specification) => {
        const response = await base.request(specification);
        const path = new URL(specification.url).pathname;
        return json(response.status, mutate(JSON.parse(response.body.toString("utf8")), path));
      },
      sleep: async () => {},
    }), Failure);
  }
});

test("rejects duplicate keys inside the proxied response", async () => {
  const base = happyTransport();
  await assert.rejects(() => runProxyConnection(input, {
    request: async (specification) => {
      const response = await base.request(specification);
      if (new URL(specification.url).pathname !== "/proxy/api/v2/events") return response;
      return { ...response, body: Buffer.from('{"cursor":null,"items":[{"action":"item.usage","uuid":"11111111-1111-4111-8111-111111111111","uuid":"11111111-1111-4111-8111-111111111111"}]}') };
    },
    sleep: async () => {},
  }), Failure);
});

test("retries one transient incomplete connection until exact state before proxying", async () => {
  const base = happyTransport();
  let connectionReads = 0;
  let sleeps = 0;
  const result = await runProxyConnection(input, {
    maximumPollAttempts: 2,
    request: async (specification) => {
      const response = await base.request(specification);
      if (new URL(specification.url).pathname !== "/api/v1/connections" || connectionReads++ > 0) return response;
      const value = JSON.parse(response.body.toString("utf8"));
      value.data[0].tags.origin = "pending";
      return json(response.status, value);
    },
    sleep: async () => { sleeps += 1; },
  });
  assert.equal(connectionReads, 2);
  assert.equal(sleeps, 1);
  assert.equal(result.connectionId, connectionId);
  assert.deepEqual(result.event, { id: event.uuid, action: event.action });
});

test("honors cancellation before and after transport", async () => {
  const before = new AbortController();
  before.abort();
  await assert.rejects(() => runProxyConnection(input, { signal: before.signal, request: async () => assert.fail("unexpected") }), Failure);

  const after = new AbortController();
  await assert.rejects(() => runProxyConnection(input, {
    signal: after.signal,
    request: async () => { after.abort(); return json(200, { data: [] }); },
  }), Failure);
});

test("bounded request refuses an already aborted operation", async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(() => boundedRequest({ method: "GET", url: "http://127.0.0.1/", headers: {}, redirect: "manual", signal: controller.signal }), Failure);
});
