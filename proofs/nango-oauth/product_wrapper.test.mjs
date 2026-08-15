import assert from "node:assert/strict";
import test from "node:test";

import {
  Failure,
  configurationFromEnvironment,
  runMain,
  runOAuthConnection,
} from "./product_wrapper.mjs";

const apiKey = "00000000-0000-4000-8000-000000000014";
const clientSecret = "fixture-client-secret-value";
const connectToken = `nango_connect_session_${"a".repeat(64)}`;
const connectionId = "00000000-0000-4000-8000-0000000000b4";
const code = "single-use-code-value";
const accessToken = "fixture-access-token-value";
const input = Object.freeze({
  baseUrl: "http://nango:3003",
  environment: "dev",
  organizationId: "org_aaaaaaaaaaaaaaaa",
  endUserId: "user_aaaaaaaaaaaaaaaa",
  integrationKey: "zasp-m0-14b-0123456789abcdef-github",
  clientId: "fixture-client-id",
  clientSecret,
  forbiddenValues: [clientSecret, connectToken, code, accessToken, apiKey],
});

function jsonResponse(status, value, headers = {}) {
  return { status, headers, body: Buffer.from(JSON.stringify(value)) };
}

function redirectResponse(location) {
  return { status: 302, headers: { location }, body: Buffer.alloc(0) };
}

function nangoRedirectResponse(location, suffix = "") {
  const body = Buffer.from(`Found. Redirecting to ${location}${suffix}`);
  return {
    status: 302,
    headers: { location, "content-type": "text/plain; charset=utf-8", "content-length": String(body.byteLength) },
    body,
  };
}

function createHappyTransport(options = {}) {
  const requests = [];
  let connectionReads = 0;
  const state = "b".repeat(64);
  const callback = `http://nango:3003/oauth/callback?code=${encodeURIComponent(code)}&state=${state}`;
  const authorization = new URL("https://github.com/login/oauth/authorize");
  authorization.searchParams.set("client_id", input.clientId);
  authorization.searchParams.set("redirect_uri", "http://nango:3003/oauth/callback");
  authorization.searchParams.set("response_type", "code");
  authorization.searchParams.set("state", state);
  authorization.searchParams.set("code_challenge", "c".repeat(43));
  authorization.searchParams.set("code_challenge_method", "S256");

  const request = async (request_) => {
    requests.push(request_);
    const url = new URL(request_.url);
    if (url.pathname === "/api/v1/environment/api-keys") {
      return options.keyResponse ?? jsonResponse(200, {
        data: [{
          id: 1,
          display_name: "Default",
          scopes: ["environment:*"],
          secret: apiKey,
          last_used_at: null,
          created_at: "2026-08-14T00:00:00.000Z",
          updated_at: "2026-08-14T00:00:00.000Z",
        }],
      });
    }
    if (url.pathname === "/api/v1/integrations") {
      return jsonResponse(200, {
        data: {
          id: 2,
          unique_key: input.integrationKey,
          provider: "github",
          oauth_client_id: input.clientId,
          oauth_client_secret: "encrypted-client-secret-value",
          oauth_scopes: "",
          environment_id: 1,
          app_link: null,
          custom: null,
          missing_fields: [],
          display_name: input.integrationKey,
          forward_webhooks: false,
          shared_credentials_id: null,
          created_at: "2026-08-14T00:00:00.000Z",
          updated_at: "2026-08-14T00:00:00.000Z",
        },
      });
    }
    if (url.pathname === "/api/v1/connect/sessions") {
      return jsonResponse(201, {
        data: {
          token: connectToken,
          connect_link: `http://nango:3003/connect?session_token=${connectToken}`,
          expires_at: "2026-08-14T00:15:00.000Z",
        },
      });
    }
    if (url.pathname === `/oauth/connect/${input.integrationKey}`) {
      return nangoRedirectResponse(authorization.href);
    }
    if (url.hostname === "github.com" && url.pathname === "/login/oauth/authorize") {
      return redirectResponse(callback);
    }
    if (url.pathname === "/oauth/callback") {
      return { status: 200, headers: { "content-type": "text/html; charset=utf-8" }, body: Buffer.from("<!doctype html><title>success</title>") };
    }
    if (url.pathname === "/api/v1/connections") {
      connectionReads += 1;
      if (connectionReads <= (options.emptyConnectionReads ?? 0)) {
        return jsonResponse(200, { data: [] });
      }
      return options.connectionResponse ?? jsonResponse(200, {
        data: [{
          id: 42,
          connection_id: connectionId,
          provider_config_key: input.integrationKey,
          provider: "github",
          errors: [],
          endUser: {
            id: input.endUserId,
            display_name: null,
            email: null,
            tags: { origin: "nango_dashboard" },
            organization: { id: input.organizationId, display_name: null },
          },
          tags: {
            end_user_id: input.endUserId,
            organization_id: input.organizationId,
            origin: "nango_dashboard",
          },
          pausedSyncs: [],
          created_at: "2026-08-14T00:00:00.000+00:00",
          updated_at: "2026-08-14T00:00:00.000+00:00",
        }],
      });
    }
    throw new Error("unexpected test request");
  };
  return { request, requests, getConnectionReads: () => connectionReads };
}

test("completes the exact OAuth redirect flow and returns only a durable reference", async () => {
  const transport = createHappyTransport({ emptyConnectionReads: 1 });
  const result = await runOAuthConnection(input, {
    request: transport.request,
    sleep: async () => {},
    maximumPollAttempts: 2,
  });

  assert.deepEqual(result, {
    organizationId: input.organizationId,
    integrationKey: input.integrationKey,
    connectionId,
  });
  assert.deepEqual(Object.keys(result), ["organizationId", "integrationKey", "connectionId"]);
  assert.equal(transport.getConnectionReads(), 2);
  assert.equal(transport.requests.length, 8);
  for (const index of [0, 1, 2, 6, 7]) {
    assert.equal(new URL(transport.requests[index].url).searchParams.get("env"), "dev");
  }
  assert.deepEqual(JSON.parse(transport.requests[1].body), {
    provider: "github",
    integrationId: input.integrationKey,
    displayName: input.integrationKey,
    auth: { authType: "OAUTH2", clientId: input.clientId, clientSecret: input.clientSecret, scopes: "" },
    forward_webhooks: false,
    useSharedCredentials: false,
  });
  assert.deepEqual(JSON.parse(transport.requests[2].body), {
    end_user: { id: input.endUserId },
    organization: { id: input.organizationId },
    allowed_integrations: [input.integrationKey],
  });
  assert.match(transport.requests[3].url, /connect_session_token=nango_connect_session_/);
  assert.equal(transport.requests[3].redirect, "manual");
  assert.equal(transport.requests[4].redirect, "manual");
  assert.equal(transport.requests[5].redirect, "manual");
  assert.deepEqual(transport.requests[6].headers, { authorization: `Bearer ${apiKey}` });
  const connectionQuery = new URL(transport.requests[6].url).searchParams;
  assert.deepEqual([...connectionQuery.entries()], [
    ["env", "dev"],
    ["integrationIds", input.integrationKey],
    ["page", "0"],
  ]);
});

test("rejects malformed input before issuing a request", async () => {
  for (const mutation of [
    { ...input, baseUrl: "https://example.com" },
    { ...input, organizationId: "org/escape" },
    { ...input, integrationKey: "github" },
    { ...input, clientSecret: "" },
    { ...input, forbiddenValues: [] },
  ]) {
    let calls = 0;
    await assert.rejects(
      runOAuthConnection(mutation, { request: async () => { calls += 1; } }),
      Failure,
    );
    assert.equal(calls, 0);
  }
});

test("requires one exact full-access dashboard API key", async () => {
  for (const data of [
    [],
    [{ id: 1, display_name: "Default", scopes: ["environment:connections:list"], secret: apiKey, last_used_at: null, created_at: "2026-08-14T00:00:00.000Z", updated_at: "2026-08-14T00:00:00.000Z" }],
    [
      { id: 1, display_name: "Default", scopes: ["environment:*"], secret: apiKey, last_used_at: null, created_at: "2026-08-14T00:00:00.000Z", updated_at: "2026-08-14T00:00:00.000Z" },
      { id: 2, display_name: "Other", scopes: ["environment:*"], secret: "00000000-0000-4000-8000-000000000015", last_used_at: null, created_at: "2026-08-14T00:00:00.000Z", updated_at: "2026-08-14T00:00:00.000Z" },
    ],
  ]) {
    const transport = createHappyTransport({ keyResponse: jsonResponse(200, { data }) });
    await assert.rejects(runOAuthConnection(input, { request: transport.request }), Failure);
    assert.equal(transport.requests.length, 1);
  }
});

test("rejects duplicate, unknown, malformed UTF-8, and oversized JSON", async () => {
  const invalidBodies = [
    Buffer.from(`{"data":[],"data":[]}`),
    Buffer.from(`{"data":[],"unknown":true}`),
    Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]),
    Buffer.alloc(65_537, 0x20),
  ];
  for (const body of invalidBodies) {
    const transport = createHappyTransport({ keyResponse: { status: 200, headers: {}, body } });
    await assert.rejects(runOAuthConnection(input, { request: transport.request }), Failure);
  }
});

test("rejects redirect host, path, state, callback, and PKCE drift", async () => {
  const base = createHappyTransport();
  const cases = [
    "https://evil.example/login/oauth/authorize?state=x&code_challenge=x&code_challenge_method=S256&client_id=x&redirect_uri=x&response_type=code",
    "https://github.com/other?state=x&code_challenge=x&code_challenge_method=S256&client_id=x&redirect_uri=x&response_type=code",
    "https://github.com/login/oauth/authorize?state=x&code_challenge=x&code_challenge_method=plain&client_id=x&redirect_uri=x&response_type=code",
  ];
  for (const location of cases) {
    const request = async (request_) => {
      const url = new URL(request_.url);
      if (url.pathname === `/oauth/connect/${input.integrationKey}`) return redirectResponse(location);
      return base.request(request_);
    };
    await assert.rejects(runOAuthConnection(input, { request }), Failure);
  }
  for (const suffix of ["\n", " trailing"]) {
    const request = async (request_) => {
      const url = new URL(request_.url);
      if (url.pathname === `/oauth/connect/${input.integrationKey}`) return nangoRedirectResponse(authorizationUrl(input), suffix);
      return base.request(request_);
    };
    await assert.rejects(runOAuthConnection(input, { request }), Failure);
  }
});

function authorizationUrl(value) {
  const authorization = new URL("https://github.com/login/oauth/authorize");
  authorization.searchParams.set("client_id", value.clientId);
  authorization.searchParams.set("redirect_uri", `${value.baseUrl}/oauth/callback`);
  authorization.searchParams.set("response_type", "code");
  authorization.searchParams.set("state", "b".repeat(64));
  authorization.searchParams.set("code_challenge", "c".repeat(43));
  authorization.searchParams.set("code_challenge_method", "S256");
  return authorization.href;
}

test("requires exactly one matching Organization-scoped connection", async () => {
  const wrong = createHappyTransport({
    connectionResponse: jsonResponse(200, {
      data: [{
        id: 42,
        connection_id: connectionId,
        provider_config_key: input.integrationKey,
        provider: "github",
        errors: [],
        endUser: { id: input.endUserId, display_name: null, email: null, tags: { origin: "nango_dashboard" }, organization: { id: "org_bbbbbbbbbbbbbbbb", display_name: null } },
        tags: { end_user_id: input.endUserId, organization_id: "org_bbbbbbbbbbbbbbbb", origin: "nango_dashboard" },
        pausedSyncs: [], created_at: "2026-08-14T00:00:00.000+00:00", updated_at: "2026-08-14T00:00:00.000+00:00",
      }],
    }),
  });
  await assert.rejects(runOAuthConnection(input, { request: wrong.request }), Failure);
});

test("bounds connection polling and propagates cancellation without coercing errors", async () => {
  const transport = createHappyTransport({ emptyConnectionReads: 4 });
  const hostile = { toString() { throw new Error("coercion reached"); } };
  await assert.rejects(
    runOAuthConnection(input, { request: transport.request, sleep: async () => {}, maximumPollAttempts: 2 }),
    Failure,
  );
  await assert.rejects(
    runOAuthConnection(input, { request: async () => { throw hostile; } }),
    Failure,
  );
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    runOAuthConnection(input, { request: transport.request, signal: controller.signal }),
    Failure,
  );
});

test("keeps the CLI boundary fixed and free of every seeded sensitive value", async () => {
  const transport = createHappyTransport();
  let stdout = "";
  let stderr = "";
  const code_ = await runMain(input, {
    request: transport.request,
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
  });
  assert.equal(code_, 0);
  assert.equal(stderr, "");
  assert.deepEqual(JSON.parse(stdout), {
    organizationId: input.organizationId,
    integrationKey: input.integrationKey,
    connectionId,
  });
  for (const forbidden of input.forbiddenValues) assert.equal(stdout.includes(forbidden), false);

  stdout = "";
  stderr = "";
  const failureCode = await runMain(input, {
    request: async () => { throw new Error(clientSecret); },
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
  });
  assert.equal(failureCode, 1);
  assert.equal(stdout, "");
  assert.equal(stderr, "Nango OAuth wrapper failed.\n");
  assert.equal(stderr.includes(clientSecret), false);
});

test("builds the direct CLI input from only the exact synthetic environment", () => {
  const environment = Object.assign(Object.create({}), {
    NANGO_OAUTH_BASE_URL: input.baseUrl,
    NANGO_OAUTH_ENVIRONMENT: input.environment,
    NANGO_OAUTH_ORGANIZATION_ID: input.organizationId,
    NANGO_OAUTH_END_USER_ID: input.endUserId,
    NANGO_OAUTH_INTEGRATION_KEY: input.integrationKey,
    NANGO_OAUTH_CLIENT_ID: input.clientId,
    NANGO_OAUTH_CLIENT_SECRET: input.clientSecret,
    NANGO_OAUTH_FORBIDDEN_VALUES: input.forbiddenValues.join(","),
  });
  assert.deepEqual(configurationFromEnvironment(environment), input);
  for (const environment of [
    {},
    { NANGO_OAUTH_FORBIDDEN_VALUES: "" },
    { NANGO_OAUTH_FORBIDDEN_VALUES: "one,,two" },
  ]) assert.throws(() => configurationFromEnvironment(environment), Failure);
});
