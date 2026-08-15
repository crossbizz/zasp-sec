import assert from "node:assert/strict";
import test from "node:test";

import {
  Failure,
  boundedRequest,
  configurationFromEnvironment,
  runApiKeyConnection,
  runMain,
} from "./product_wrapper.mjs";

const apiKey = "11111111-1111-4111-8111-111111111111";
const connectToken = `nango_connect_session_${"a".repeat(64)}`;
const connectionId = "22222222-2222-4222-8222-222222222222";
const providerKey = `pk_${"b".repeat(32)}`;
const timestamp = "2026-08-15T00:00:00.000Z";
const connectionTimestamp = "2026-08-15T00:00:00.000+00:00";
const input = Object.freeze({
  baseUrl: "http://nango:3003",
  environment: "dev",
  organizationId: "org_0123456789abcdef",
  endUserId: "user_0123456789abcdef",
  integrationKey: "zasp-m0-14c-0123456789abcdef-1password-events",
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
    throw new Error("unexpected request");
  };
  return { calls, request: options.request ?? request };
}

test("creates one verified API-key connection and returns only the scoped reference", async () => {
  const transport = happyTransport();
  const result = await runApiKeyConnection(input, { request: transport.request, sleep: async () => {} });
  assert.deepEqual(result, {
    organizationId: input.organizationId,
    integrationKey: input.integrationKey,
    connectionId,
  });
  assert.deepEqual(transport.calls.map((call) => [call.method, new URL(call.url).pathname]), [
    ["GET", "/api/v1/environment/api-keys"],
    ["POST", "/api/v1/integrations"],
    ["POST", "/api/v1/connect/sessions"],
    ["POST", `/api-auth/api-key/${input.integrationKey}`],
    ["GET", "/api/v1/connections"],
  ]);
  assert.deepEqual(JSON.parse(transport.calls[1].body), {
    provider: "1password-events",
    integrationId: input.integrationKey,
    displayName: input.integrationKey,
    auth: { authType: "API_KEY" },
    forward_webhooks: false,
    useSharedCredentials: false,
  });
  assert.equal(new URL(transport.calls[3].url).searchParams.get("connect_session_token"), connectToken);
  assert.deepEqual(JSON.parse(transport.calls[3].body), { apiKey: providerKey });
  const output = JSON.stringify(result);
  for (const secret of [providerKey, apiKey, connectToken, ...input.forbiddenValues]) assert.equal(output.includes(secret), false);
});

test("accepts an exact process.env-shaped configuration", () => {
  const environment = Object.assign(Object.create({}), {
    NANGO_API_KEY_BASE_URL: input.baseUrl,
    NANGO_API_KEY_ENVIRONMENT: input.environment,
    NANGO_API_KEY_ORGANIZATION_ID: input.organizationId,
    NANGO_API_KEY_END_USER_ID: input.endUserId,
    NANGO_API_KEY_INTEGRATION_KEY: input.integrationKey,
    NANGO_API_KEY_PROVIDER_KEY: providerKey,
    NANGO_API_KEY_FORBIDDEN_VALUES: input.forbiddenValues.join(","),
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
  assert.equal(stderr, "Nango API-key wrapper failed.\n");
  assert.equal(stderr.includes(providerKey), false);
});

test("rejects malformed input before transport", async () => {
  for (const mutation of [
    { ...input, baseUrl: "https://evil.example" },
    { ...input, organizationId: "other" },
    { ...input, integrationKey: "wrong" },
    { ...input, providerKey: "" },
    { ...input, forbiddenValues: [] },
    { ...input, extra: true },
  ]) {
    let called = false;
    await assert.rejects(() => runApiKeyConnection(mutation, { request: async () => { called = true; } }), Failure);
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
    await assert.rejects(() => runApiKeyConnection(input, {
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
    await assert.rejects(() => runApiKeyConnection(input, {
      request: async (specification) => {
        const response = await base.request(specification);
        if (!first) return response;
        first = false;
        return { ...response, headers };
      },
    }), Failure);
  }
});

test("rejects API-key authorization and connection identity drift", async () => {
  for (const mutate of [
    (response, index) => index === 3 ? json(200, { connectionId: "33333333-3333-4333-8333-333333333333", providerConfigKey: input.integrationKey }) : response,
    (response, index) => index === 3 ? json(200, { connectionId, providerConfigKey: "other" }) : response,
    (response, index) => index === 4 ? json(200, { data: [] }) : response,
  ]) {
    const base = happyTransport();
    let index = 0;
    await assert.rejects(() => runApiKeyConnection(input, {
      maximumPollAttempts: 1,
      request: async (specification) => mutate(await base.request(specification), index++),
      sleep: async () => {},
    }), Failure);
  }
});

test("honors cancellation before and after transport", async () => {
  const before = new AbortController();
  before.abort();
  await assert.rejects(() => runApiKeyConnection(input, { signal: before.signal, request: async () => assert.fail("unexpected") }), Failure);

  const after = new AbortController();
  await assert.rejects(() => runApiKeyConnection(input, {
    signal: after.signal,
    request: async () => { after.abort(); return json(200, { data: [] }); },
  }), Failure);
});

test("bounded request refuses an already aborted operation", async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(() => boundedRequest({ method: "GET", url: "http://127.0.0.1/", headers: {}, redirect: "manual", signal: controller.signal }), Failure);
});
