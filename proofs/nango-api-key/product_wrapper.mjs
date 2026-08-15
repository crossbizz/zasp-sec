import { pathToFileURL } from "node:url";

import { parseBoundedUniqueJson } from "../nango-free-boot/manifest.mjs";

const maximumBodyBytes = 65_536;
const requestTimeoutMilliseconds = 5_000;
const defaultMaximumPollAttempts = 20;
const uuidV4Pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const organizationPattern = /^org_[a-z0-9]{16}$/;
const endUserPattern = /^user_[a-z0-9]{16}$/;
const integrationPattern = /^zasp-m0-14c-[0-9a-f]{16}-1password-events$/;
const providerKeyPattern = /^eyJ[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const connectTokenPattern = /^nango_connect_session_[0-9a-f]{64}$/;

export class Failure extends Error {
  constructor(category = "api_key", options) {
    super(`${category} rejected`, options);
    this.category = category;
  }
}

export async function runApiKeyConnection(input, dependencies = {}) {
  try {
    validateInput(input);
    const request = typeof dependencies.request === "function" ? dependencies.request : boundedRequest;
    const sleep = typeof dependencies.sleep === "function" ? dependencies.sleep : (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
    const maximumPollAttempts = dependencies.maximumPollAttempts ?? defaultMaximumPollAttempts;
    if (!positiveInteger(maximumPollAttempts)) throw failure("configuration");
    assertActive(dependencies.signal);

    const apiKey = await readApiKey(input, request, dependencies.signal);
    await createIntegration(input, apiKey, request, dependencies.signal);
    const connectToken = await createConnectSession(input, apiKey, request, dependencies.signal);
    const connectionId = await authorizeApiKey(input, connectToken, request, dependencies.signal);
    const retainedConnectionId = await readConnection(input, apiKey, request, sleep, maximumPollAttempts, dependencies.signal);
    if (retainedConnectionId !== connectionId) throw failure("provider");

    const result = { organizationId: input.organizationId, integrationKey: input.integrationKey, connectionId };
    const serialized = JSON.stringify(result);
    for (const value of [...input.forbiddenValues, input.providerKey, apiKey, connectToken]) {
      if (serialized.includes(value)) throw failure("normalization");
    }
    return result;
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw failure("api_key");
  }
}

export async function runMain(input, dependencies = {}) {
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;
  try {
    if (typeof stdout?.write !== "function" || typeof stderr?.write !== "function") return 1;
    const result = await runApiKeyConnection(input, dependencies);
    stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch {
    try { stderr?.write?.("Nango API-key wrapper failed.\n"); } catch { /* fixed boundary */ }
    return 1;
  }
}

export function configurationFromEnvironment(environment) {
  if (!environmentRecord(environment)) throw failure("configuration");
  const forbidden = environment.NANGO_API_KEY_FORBIDDEN_VALUES;
  if (typeof forbidden !== "string" || forbidden.length === 0) throw failure("configuration");
  const forbiddenValues = forbidden.split(",");
  if (forbiddenValues.some((value) => value.length === 0)) throw failure("configuration");
  const input = {
    baseUrl: environment.NANGO_API_KEY_BASE_URL,
    environment: environment.NANGO_API_KEY_ENVIRONMENT,
    organizationId: environment.NANGO_API_KEY_ORGANIZATION_ID,
    endUserId: environment.NANGO_API_KEY_END_USER_ID,
    integrationKey: environment.NANGO_API_KEY_INTEGRATION_KEY,
    providerKey: environment.NANGO_API_KEY_PROVIDER_KEY,
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
  if (!positiveInteger(key.id) || !boundedString(key.display_name, 1, 255) || !Array.isArray(key.scopes) || key.scopes.length !== 1 || key.scopes[0] !== "environment:*" || !uuidV4Pattern.test(key.secret ?? "") || (key.last_used_at !== null && !validTimestamp(key.last_used_at)) || !validTimestamp(key.created_at) || !validTimestamp(key.updated_at)) throw failure("provider");
  return key.secret;
}

async function createIntegration(input, apiKey, request, signal) {
  const response = await requestJson(request, {
    method: "POST",
    url: `${input.baseUrl}/api/v1/integrations?env=${input.environment}`,
    headers: authorizationHeaders(apiKey),
    body: JSON.stringify({
      provider: "1password-events",
      integrationId: input.integrationKey,
      displayName: input.integrationKey,
      forward_webhooks: false,
      useSharedCredentials: false,
    }),
    redirect: "manual",
    signal,
  }, 200);
  exactKeys(response, ["data"]);
  const value = response.data;
  exactKeys(value, ["id", "unique_key", "provider", "oauth_client_id", "oauth_client_secret", "oauth_scopes", "environment_id", "app_link", "custom", "missing_fields", "display_name", "forward_webhooks", "shared_credentials_id", "created_at", "updated_at"]);
  if (!positiveInteger(value.id) || value.unique_key !== input.integrationKey || value.provider !== "1password-events" || value.oauth_client_id !== null || value.oauth_client_secret !== null || value.oauth_scopes !== null || !positiveInteger(value.environment_id) || value.app_link !== null || value.custom !== null || !Array.isArray(value.missing_fields) || value.missing_fields.length !== 0 || value.display_name !== input.integrationKey || value.forward_webhooks !== false || value.shared_credentials_id !== null || !validTimestamp(value.created_at) || !validTimestamp(value.updated_at)) throw failure("provider");
}

async function createConnectSession(input, apiKey, request, signal) {
  const response = await requestJson(request, {
    method: "POST",
    url: `${input.baseUrl}/api/v1/connect/sessions?env=${input.environment}`,
    headers: authorizationHeaders(apiKey),
    body: JSON.stringify({ end_user: { id: input.endUserId }, organization: { id: input.organizationId }, allowed_integrations: [input.integrationKey] }),
    redirect: "manual",
    signal,
  }, 201);
  exactKeys(response, ["data"]);
  exactKeys(response.data, ["token", "connect_link", "expires_at"]);
  const { token, connect_link: connectLink, expires_at: expiresAt } = response.data;
  if (!connectTokenPattern.test(token ?? "") || !validTimestamp(expiresAt)) throw failure("provider");
  let parsed;
  try { parsed = new URL(connectLink); } catch { throw failure("provider"); }
  if (parsed.origin !== new URL(input.baseUrl).origin || parsed.searchParams.size !== 1 || parsed.searchParams.get("session_token") !== token) throw failure("provider");
  return token;
}

async function authorizeApiKey(input, connectToken, request, signal) {
  const query = new URLSearchParams({ connect_session_token: connectToken, "params[domain]": "events.1password.com" });
  const response = await requestJson(request, {
    method: "POST",
    url: `${input.baseUrl}/api-auth/api-key/${input.integrationKey}?${query.toString()}`,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ apiKey: input.providerKey }),
    redirect: "manual",
    signal,
  }, 200);
  exactKeys(response, ["connectionId", "providerConfigKey"]);
  if (!uuidV4Pattern.test(response.connectionId ?? "") || response.providerConfigKey !== input.integrationKey) throw failure("provider");
  return response.connectionId;
}

async function readConnection(input, apiKey, request, sleep, maximumPollAttempts, signal) {
  const query = new URLSearchParams({ env: input.environment, integrationIds: input.integrationKey, page: "0" });
  for (let attempt = 0; attempt < maximumPollAttempts; attempt += 1) {
    assertActive(signal);
    const response = await requestJson(request, {
      method: "GET",
      url: `${input.baseUrl}/api/v1/connections?${query.toString()}`,
      headers: { authorization: `Bearer ${apiKey}` },
      redirect: "manual",
      signal,
    }, 200);
    exactKeys(response, ["data"]);
    if (!Array.isArray(response.data) || response.data.length > 1) throw failure("provider");
    if (response.data.length === 1) return validateConnection(input, response.data[0]);
    if (attempt + 1 < maximumPollAttempts) {
      try { await sleep(100); } catch { throw failure("api_key"); }
    }
  }
  throw failure("provider");
}

function validateConnection(input, connection) {
  exactKeys(connection, ["id", "connection_id", "provider_config_key", "provider", "errors", "endUser", "tags", "pausedSyncs", "created_at", "updated_at"]);
  exactKeys(connection.endUser, ["id", "display_name", "email", "tags", "organization"]);
  exactKeys(connection.endUser.organization, ["id", "display_name"]);
  exactKeys(connection.endUser.tags, ["origin"]);
  exactKeys(connection.tags, ["end_user_id", "organization_id", "origin"]);
  if (!positiveInteger(connection.id) || !uuidV4Pattern.test(connection.connection_id ?? "") || connection.provider_config_key !== input.integrationKey || connection.provider !== "1password-events" || !Array.isArray(connection.errors) || connection.errors.length !== 0 || connection.endUser.id !== input.endUserId || connection.endUser.display_name !== null || connection.endUser.email !== null || connection.endUser.tags.origin !== "nango_dashboard" || connection.endUser.organization.id !== input.organizationId || connection.endUser.organization.display_name !== null || connection.tags.end_user_id !== input.endUserId || connection.tags.organization_id !== input.organizationId || connection.tags.origin !== "nango_dashboard" || !Array.isArray(connection.pausedSyncs) || connection.pausedSyncs.length !== 0 || !validConnectionTimestamp(connection.created_at) || !validConnectionTimestamp(connection.updated_at)) throw failure("provider");
  return connection.connection_id;
}

async function requestJson(request, specification, expectedStatus) {
  const response = await requestRaw(request, specification);
  if (response.status !== expectedStatus || !exactJsonContentType(response.headers)) throw failure("provider");
  const value = parseBoundedUniqueJson(response.body);
  if (!plainObject(value)) throw failure("provider");
  return value;
}

async function requestRaw(request, specification) {
  assertActive(specification.signal);
  let response;
  try { response = await request(specification); } catch { throw failure("provider"); }
  assertActive(specification.signal);
  if (!plainObject(response) || !Number.isInteger(response.status) || response.status < 100 || response.status > 599 || !plainObject(response.headers) || !Buffer.isBuffer(response.body) || response.body.byteLength > maximumBodyBytes) throw failure("provider");
  return response;
}

export async function boundedRequest(specification) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  const timer = setTimeout(abort, requestTimeoutMilliseconds);
  specification.signal?.addEventListener?.("abort", abort, { once: true });
  try {
    if (specification.signal?.aborted === true) throw failure("api_key");
    const response = await fetch(specification.url, { method: specification.method, headers: specification.headers, body: specification.body, redirect: specification.redirect, signal: controller.signal });
    const chunks = [];
    let size = 0;
    if (response.body) {
      for await (const chunk of response.body) {
        const value = Buffer.from(chunk);
        size += value.byteLength;
        if (size > maximumBodyBytes) { controller.abort(); throw failure("provider"); }
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
  exactKeys(input, ["baseUrl", "environment", "organizationId", "endUserId", "integrationKey", "providerKey", "forbiddenValues"]);
  let base;
  try { base = new URL(input.baseUrl); } catch { throw failure("configuration"); }
  if (base.protocol !== "http:" || base.port !== "3003" || base.pathname !== "/" || base.search !== "" || base.hash !== "" || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(base.hostname) || input.environment !== "dev" || !organizationPattern.test(input.organizationId) || !endUserPattern.test(input.endUserId) || !integrationPattern.test(input.integrationKey) || !providerKeyPattern.test(input.providerKey ?? "") || !Array.isArray(input.forbiddenValues) || input.forbiddenValues.length < 1 || input.forbiddenValues.length > 16 || input.forbiddenValues.some((value) => !boundedString(value, 1, 4096))) throw failure("configuration");
}

function authorizationHeaders(apiKey) { return { authorization: `Bearer ${apiKey}`, "content-type": "application/json" }; }
function exactJsonContentType(headers) { const matches = Object.entries(headers).filter(([key]) => key.toLowerCase() === "content-type"); return matches.length === 1 && typeof matches[0][1] === "string" && /^(?:application\/json|application\/json; charset=utf-8)$/.test(matches[0][1]); }
function exactKeys(value, expected) { if (!plainObject(value)) throw failure("provider"); const actual = Object.keys(value).sort(); const wanted = [...expected].sort(); if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw failure("provider"); }
function validTimestamp(value) { if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false; const time = Date.parse(value); return Number.isFinite(time) && new Date(time).toISOString() === value; }
function validConnectionTimestamp(value) { if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00$/.test(value)) return false; const time = Date.parse(value); return Number.isFinite(time) && new Date(time).toISOString() === `${value.slice(0, -6)}Z`; }
function assertActive(signal) { if (signal?.aborted === true) throw failure("api_key"); }
function positiveInteger(value) { return Number.isInteger(value) && value > 0 && typeof value !== "boolean"; }
function boundedString(value, minimum, maximum) { return typeof value === "string" && value.length >= minimum && value.length <= maximum && !value.includes("\0"); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function environmentRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function failure(category) { return new Failure(category); }

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.exitCode = await runMain(configurationFromEnvironment(process.env)); }
  catch { process.stderr.write("Nango API-key wrapper failed.\n"); process.exitCode = 1; }
}
