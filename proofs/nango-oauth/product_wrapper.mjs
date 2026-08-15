import { pathToFileURL } from "node:url";

import { parseBoundedUniqueJson } from "../nango-free-boot/manifest.mjs";

const maximumBodyBytes = 65_536;
const requestTimeoutMilliseconds = 5_000;
const defaultMaximumPollAttempts = 20;
const uuidV4Pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const organizationPattern = /^org_[a-z0-9]{16}$/;
const endUserPattern = /^user_[a-z0-9]{16}$/;
const integrationPattern = /^zasp-m0-14b-[0-9a-f]{16}-github$/;
const connectTokenPattern = /^nango_connect_session_[0-9a-f]{64}$/;
const connectionPattern = /^conn_[a-z0-9]{16,64}$/;
const statePattern = /^[A-Za-z0-9_-]{16,128}$/;
const codePattern = /^[A-Za-z0-9._~-]{1,512}$/;
const pkcePattern = /^[A-Za-z0-9_-]{43,128}$/;

export class Failure extends Error {
  constructor(category = "oauth", options) {
    super(`${category} rejected`, options);
    this.category = category;
  }
}

export async function runOAuthConnection(input, dependencies = {}) {
  try {
    validateInput(input);
    const request = typeof dependencies.request === "function"
      ? dependencies.request
      : boundedRequest;
    const sleep = typeof dependencies.sleep === "function"
      ? dependencies.sleep
      : (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
    const maximumPollAttempts = dependencies.maximumPollAttempts ?? defaultMaximumPollAttempts;
    if (!positiveInteger(maximumPollAttempts)) throw failure("configuration");
    assertActive(dependencies.signal);

    const apiKey = await readApiKey(input, request, dependencies.signal);
    await createIntegration(input, apiKey, request, dependencies.signal);
    const connectToken = await createConnectSession(input, apiKey, request, dependencies.signal);
    const authorization = await beginOAuth(input, connectToken, request, dependencies.signal);
    const callback = await authorizeFixture(input, authorization, request, dependencies.signal);
    await completeCallback(input, callback, request, dependencies.signal);
    const connectionId = await readConnection(
      input,
      apiKey,
      request,
      sleep,
      maximumPollAttempts,
      dependencies.signal,
    );
    const result = {
      organizationId: input.organizationId,
      integrationKey: input.integrationKey,
      connectionId,
    };
    const serialized = JSON.stringify(result);
    for (const value of [...input.forbiddenValues, apiKey, connectToken]) {
      if (serialized.includes(value)) throw failure("normalization");
    }
    return result;
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw failure("oauth");
  }
}

export async function runMain(input, dependencies = {}) {
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;
  try {
    if (typeof stdout?.write !== "function" || typeof stderr?.write !== "function") {
      return 1;
    }
    const result = await runOAuthConnection(input, dependencies);
    stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch {
    try { stderr?.write?.("Nango OAuth wrapper failed.\n"); } catch { /* fixed boundary */ }
    return 1;
  }
}

export function configurationFromEnvironment(environment) {
  if (!plainObject(environment)) throw failure("configuration");
  const forbidden = environment.NANGO_OAUTH_FORBIDDEN_VALUES;
  if (typeof forbidden !== "string" || forbidden.length === 0) throw failure("configuration");
  const forbiddenValues = forbidden.split(",");
  if (forbiddenValues.some((value) => value.length === 0)) throw failure("configuration");
  const input = {
    baseUrl: environment.NANGO_OAUTH_BASE_URL,
    environment: environment.NANGO_OAUTH_ENVIRONMENT,
    organizationId: environment.NANGO_OAUTH_ORGANIZATION_ID,
    endUserId: environment.NANGO_OAUTH_END_USER_ID,
    integrationKey: environment.NANGO_OAUTH_INTEGRATION_KEY,
    clientId: environment.NANGO_OAUTH_CLIENT_ID,
    clientSecret: environment.NANGO_OAUTH_CLIENT_SECRET,
    forbiddenValues,
  };
  validateInput(input);
  return Object.freeze(input);
}

async function readApiKey(input, request, signal) {
  const response = await requestJson(request, {
    method: "GET",
    url: `${input.baseUrl}/api/v1/environment/api-keys?env=${input.environment}`,
    headers: {},
    redirect: "manual",
    signal,
  }, 200);
  exactKeys(response, ["data"]);
  if (!Array.isArray(response.data) || response.data.length !== 1) throw failure("provider");
  const [key] = response.data;
  exactKeys(key, ["id", "display_name", "scopes", "secret", "last_used_at", "created_at", "updated_at"]);
  if (
    !positiveInteger(key.id) || !boundedString(key.display_name, 1, 255) ||
    !Array.isArray(key.scopes) || key.scopes.length !== 1 || key.scopes[0] !== "environment:*" ||
    typeof key.secret !== "string" || !uuidV4Pattern.test(key.secret) ||
    (key.last_used_at !== null && !validTimestamp(key.last_used_at)) ||
    !validTimestamp(key.created_at) || !validTimestamp(key.updated_at)
  ) {
    throw failure("provider");
  }
  return key.secret;
}

async function createIntegration(input, apiKey, request, signal) {
  const response = await requestJson(request, {
    method: "POST",
    url: `${input.baseUrl}/integrations`,
    headers: authorizationHeaders(apiKey),
    body: JSON.stringify({
      provider: "github",
      unique_key: input.integrationKey,
      display_name: input.integrationKey,
      credentials: {
        type: "OAUTH2",
        client_id: input.clientId,
        client_secret: input.clientSecret,
      },
      forward_webhooks: false,
    }),
    redirect: "manual",
    signal,
  }, 200);
  exactKeys(response, ["data"]);
  const value = response.data;
  exactKeys(value, ["unique_key", "provider", "display_name", "logo", "forward_webhooks", "created_at", "updated_at"]);
  if (
    value.unique_key !== input.integrationKey || value.provider !== "github" ||
    value.display_name !== input.integrationKey || value.forward_webhooks !== false ||
    !boundedHttpUrl(value.logo) || !validTimestamp(value.created_at) || !validTimestamp(value.updated_at)
  ) {
    throw failure("provider");
  }
}

async function createConnectSession(input, apiKey, request, signal) {
  const response = await requestJson(request, {
    method: "POST",
    url: `${input.baseUrl}/connect/sessions`,
    headers: authorizationHeaders(apiKey),
    body: JSON.stringify({
      end_user: { id: input.endUserId },
      organization: { id: input.organizationId },
      allowed_integrations: [input.integrationKey],
    }),
    redirect: "manual",
    signal,
  }, 201);
  exactKeys(response, ["data"]);
  exactKeys(response.data, ["token", "connect_link", "expires_at"]);
  const { token, connect_link: connectLink, expires_at: expiresAt } = response.data;
  if (!connectTokenPattern.test(token) || !validTimestamp(expiresAt)) throw failure("provider");
  let parsed;
  try { parsed = new URL(connectLink); } catch { throw failure("provider"); }
  if (parsed.origin !== new URL(input.baseUrl).origin || parsed.searchParams.get("session_token") !== token) {
    throw failure("provider");
  }
  return token;
}

async function beginOAuth(input, connectToken, request, signal) {
  const response = await requestRaw(request, {
    method: "GET",
    url: `${input.baseUrl}/oauth/connect/${input.integrationKey}?connect_session_token=${connectToken}`,
    headers: {},
    redirect: "manual",
    signal,
  });
  requireEmptyRedirect(response, 302);
  const location = header(response.headers, "location");
  let authorization;
  try { authorization = new URL(location); } catch { throw failure("oauth"); }
  if (authorization.protocol !== "https:" || authorization.hostname !== "github.com" || authorization.port !== "" || authorization.pathname !== "/login/oauth/authorize" || authorization.hash !== "") {
    throw failure("oauth");
  }
  const query = uniqueSearch(authorization);
  const allowed = new Set(["client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method", "scope", "allow_signup"]);
  if ([...query.keys()].some((key) => !allowed.has(key))) throw failure("oauth");
  const callback = new URL(`${input.baseUrl}/oauth/callback`).href;
  if (
    query.get("client_id") !== input.clientId || query.get("redirect_uri") !== callback ||
    query.get("response_type") !== "code" || !statePattern.test(query.get("state") ?? "") ||
    !pkcePattern.test(query.get("code_challenge") ?? "") || query.get("code_challenge_method") !== "S256"
  ) {
    throw failure("oauth");
  }
  return { url: authorization.href, state: query.get("state") };
}

async function authorizeFixture(input, authorization, request, signal) {
  const response = await requestRaw(request, {
    method: "GET",
    url: authorization.url,
    headers: {},
    redirect: "manual",
    signal,
  });
  requireEmptyRedirect(response, 302);
  let callback;
  try { callback = new URL(header(response.headers, "location")); } catch { throw failure("oauth"); }
  const base = new URL(input.baseUrl);
  if (callback.origin !== base.origin || callback.pathname !== "/oauth/callback" || callback.hash !== "") {
    throw failure("oauth");
  }
  const query = uniqueSearch(callback);
  if (query.size !== 2 || query.get("state") !== authorization.state || !codePattern.test(query.get("code") ?? "")) {
    throw failure("oauth");
  }
  return callback.href;
}

async function completeCallback(input, callback, request, signal) {
  const response = await requestRaw(request, {
    method: "GET",
    url: callback,
    headers: {},
    redirect: "manual",
    signal,
  });
  if (response.status !== 200 || !header(response.headers, "content-type").toLowerCase().startsWith("text/html")) {
    throw failure("oauth");
  }
  decodeUtf8(response.body);
  if (response.body.byteLength === 0) throw failure("oauth");
}

async function readConnection(input, apiKey, request, sleep, maximumPollAttempts, signal) {
  const query = new URLSearchParams({
    endUserId: input.endUserId,
    integrationId: input.integrationKey,
    endUserOrganizationId: input.organizationId,
    limit: "2",
  });
  for (let attempt = 0; attempt < maximumPollAttempts; attempt += 1) {
    assertActive(signal);
    const response = await requestJson(request, {
      method: "GET",
      url: `${input.baseUrl}/connections?${query.toString()}`,
      headers: { authorization: `Bearer ${apiKey}` },
      redirect: "manual",
      signal,
    }, 200);
    exactKeys(response, ["connections"]);
    if (!Array.isArray(response.connections) || response.connections.length > 1) throw failure("provider");
    if (response.connections.length === 1) return validateConnection(input, response.connections[0]);
    if (attempt + 1 < maximumPollAttempts) {
      try { await sleep(100); } catch { throw failure("oauth"); }
    }
  }
  throw failure("provider");
}

function validateConnection(input, connection) {
  exactKeys(connection, ["id", "connection_id", "provider_config_key", "provider", "errors", "end_user", "tags", "metadata", "created"]);
  exactKeys(connection.end_user, ["id", "display_name", "email", "tags", "organization"]);
  exactKeys(connection.end_user.organization, ["id", "display_name"]);
  if (
    !positiveInteger(connection.id) || !connectionPattern.test(connection.connection_id) ||
    connection.provider_config_key !== input.integrationKey || connection.provider !== "github" ||
    !Array.isArray(connection.errors) || connection.errors.length !== 0 ||
    connection.end_user.id !== input.endUserId || connection.end_user.display_name !== null ||
    connection.end_user.email !== null || connection.end_user.tags !== null ||
    connection.end_user.organization.id !== input.organizationId ||
    connection.end_user.organization.display_name !== null || !plainObject(connection.tags) ||
    Object.keys(connection.tags).length !== 0 || connection.metadata !== null || !validTimestamp(connection.created)
  ) {
    throw failure("provider");
  }
  return connection.connection_id;
}

async function requestJson(request, specification, expectedStatus) {
  const response = await requestRaw(request, specification);
  if (response.status !== expectedStatus) throw failure("provider");
  const value = parseBoundedUniqueJson(response.body);
  if (!plainObject(value)) throw failure("provider");
  return value;
}

async function requestRaw(request, specification) {
  assertActive(specification.signal);
  let response;
  try { response = await request(specification); } catch { throw failure("provider"); }
  assertActive(specification.signal);
  if (!plainObject(response) || !Number.isInteger(response.status) || response.status < 100 || response.status > 599 || !plainObject(response.headers) || !Buffer.isBuffer(response.body) || response.body.byteLength > maximumBodyBytes) {
    throw failure("provider");
  }
  return response;
}

export async function boundedRequest(specification) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  const timer = setTimeout(abort, requestTimeoutMilliseconds);
  specification.signal?.addEventListener?.("abort", abort, { once: true });
  try {
    if (specification.signal?.aborted === true) throw failure("oauth");
    const response = await fetch(specification.url, {
      method: specification.method,
      headers: specification.headers,
      body: specification.body,
      redirect: specification.redirect,
      signal: controller.signal,
    });
    const chunks = [];
    let size = 0;
    if (response.body) {
      for await (const chunk of response.body) {
        const value = Buffer.from(chunk);
        size += value.byteLength;
        if (size > maximumBodyBytes) {
          controller.abort();
          throw failure("provider");
        }
        chunks.push(value);
      }
    }
    const headers = {};
    for (const [key, value] of response.headers.entries()) headers[key.toLowerCase()] = value;
    return { status: response.status, headers, body: Buffer.concat(chunks) };
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw failure("provider");
  } finally {
    clearTimeout(timer);
    specification.signal?.removeEventListener?.("abort", abort);
  }
}

function validateInput(input) {
  if (!plainObject(input)) throw failure("configuration");
  exactKeys(input, ["baseUrl", "environment", "organizationId", "endUserId", "integrationKey", "clientId", "clientSecret", "forbiddenValues"]);
  let base;
  try { base = new URL(input.baseUrl); } catch { throw failure("configuration"); }
  if (
    base.protocol !== "http:" || base.port !== "3003" || base.pathname !== "/" ||
    base.search !== "" || base.hash !== "" || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(base.hostname) ||
    input.environment !== "dev" || !organizationPattern.test(input.organizationId) ||
    !endUserPattern.test(input.endUserId) || !integrationPattern.test(input.integrationKey) ||
    !boundedString(input.clientId, 1, 255) || !boundedString(input.clientSecret, 1, 2048) ||
    !Array.isArray(input.forbiddenValues) || input.forbiddenValues.length < 1 || input.forbiddenValues.length > 16 ||
    input.forbiddenValues.some((value) => !boundedString(value, 1, 4096))
  ) {
    throw failure("configuration");
  }
}

function authorizationHeaders(apiKey) {
  return { authorization: `Bearer ${apiKey}`, "content-type": "application/json" };
}

function requireEmptyRedirect(response, status) {
  if (response.status !== status || response.body.byteLength !== 0 || header(response.headers, "location") === "") {
    throw failure("oauth");
  }
}

function uniqueSearch(url) {
  const result = new Map();
  for (const [key, value] of url.searchParams.entries()) {
    if (result.has(key)) throw failure("oauth");
    result.set(key, value);
  }
  return result;
}

function header(headers, name) {
  const matches = Object.entries(headers).filter(([key]) => key.toLowerCase() === name);
  if (matches.length !== 1 || typeof matches[0][1] !== "string") return "";
  return matches[0][1];
}

function exactKeys(value, expected) {
  if (!plainObject(value)) throw failure("provider");
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw failure("provider");
  }
}

function decodeUtf8(value) {
  if (!Buffer.isBuffer(value) || value.byteLength > maximumBodyBytes) throw failure("provider");
  try { return new TextDecoder("utf-8", { fatal: true }).decode(value); }
  catch { throw failure("provider"); }
}

function validTimestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}

function boundedHttpUrl(value) {
  if (!boundedString(value, 1, 2048)) return false;
  try {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:") && url.username === "" && url.password === "";
  } catch { return false; }
}

function assertActive(signal) {
  if (signal?.aborted === true) throw failure("oauth");
}

function positiveInteger(value) {
  return Number.isInteger(value) && value > 0 && typeof value !== "boolean";
}

function boundedString(value, minimum, maximum) {
  return typeof value === "string" && value.length >= minimum && value.length <= maximum && !value.includes("\0");
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function failure(category) {
  return new Failure(category);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runMain(configurationFromEnvironment(process.env));
}
