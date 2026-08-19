import createClient from "openapi-fetch";
import type { ClientOptions } from "openapi-fetch";

import type { paths, ProductError, ProductId } from "./generated";
import type { Decoder } from "./decoders";

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAXIMUM_RESPONSE_BYTES = 1024 * 1024;
const PRODUCT_ID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EXPECTED_SCOPE_HEADER = "X-Zasp-Expected-Scope";
const SCOPE_STALE_MESSAGE = "Session scope changed; rebootstrap required";
const FRESH_AUTH_MESSAGE = "Fresh authentication required";

export type APITransportErrorKind =
  | "invalid_configuration"
  | "invalid_error"
  | "invalid_response"
  | "response_too_large"
  | "timeout";

export class APITransportError extends Error {
  readonly kind: APITransportErrorKind;

  constructor(kind: APITransportErrorKind, message: string) {
    super(message);
    this.name = "APITransportError";
    this.kind = kind;
  }
}

export class APIProductError extends Error {
  readonly status: number;
  readonly product: ProductError;
  readonly correlationID: string;

  constructor(status: number, product: ProductError) {
    super(product.message);
    this.name = "APIProductError";
    this.status = status;
    this.product = product;
    this.correlationID = product.correlation_id;
  }
}

export function requireAPIData<T>(result: { data?: unknown; error?: unknown; response: Response }, decode?: Decoder<T>): T {
  if (result.data !== undefined) {
    if (!decode) return result.data as T;
    try { return decode(result.data); } catch { throw new APITransportError("invalid_response", "API success response failed its operation schema"); }
  }
  if (isProductError(result.error)) throw new APIProductError(result.response.status, result.error as ProductError);
  throw new APITransportError("invalid_error", "API request failed without a valid product error");
}

export type APIClientOptions = Omit<ClientOptions, "baseUrl" | "credentials" | "fetch" | "redirect"> & {
  baseUrl?: string;
  fetch?: (request: Request) => Promise<Response>;
  timeoutMs?: number;
  maximumResponseBytes?: number;
  getCSRFToken?: () => string | undefined;
	getExpectedScope?: () => string | undefined;
  generateCorrelationID?: () => string;
  onSessionExpired?: () => void;
	onScopeStale?: () => void;
	onFreshAuthRequired?: () => void;
};

export function createAPIClient(options: APIClientOptions = {}) {
  const {
    baseUrl = "",
    fetch: configuredFetch = globalThis.fetch,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maximumResponseBytes = DEFAULT_MAXIMUM_RESPONSE_BYTES,
    getCSRFToken = () => undefined,
	getExpectedScope = () => undefined,
    generateCorrelationID = defaultCorrelationID,
    onSessionExpired = () => undefined,
	onScopeStale = () => undefined,
	onFreshAuthRequired = () => undefined,
    ...clientOptions
  } = options;
  if (!validRelativeBaseURL(baseUrl) || typeof configuredFetch !== "function" || !validBound(timeoutMs) || !validBound(maximumResponseBytes)) {
    throw new APITransportError("invalid_configuration", "Invalid API client configuration");
  }
  // Client Components also render on the server. This non-routable placeholder
  // prevents server rendering from performing I/O while browser instances bind
  // to the actual same-origin location below.
  const origin = globalThis.location?.origin && globalThis.location.origin !== "null" ? globalThis.location.origin : "http://same-origin.invalid";
  const transport = async (request: Request): Promise<Response> => {
    const correlationID = generateCorrelationID();
    if (!PRODUCT_ID.test(correlationID)) {
      throw new APITransportError("invalid_configuration", "Invalid correlation ID");
    }
    const headers = new Headers(request.headers);
    headers.set("X-Correlation-ID", correlationID);
	const expectedScope = headers.get(EXPECTED_SCOPE_HEADER) ?? getExpectedScope();
	if (expectedScope !== undefined) {
		if (!validExpectedScope(expectedScope)) throw new APITransportError("invalid_configuration", "Invalid expected API scope");
		headers.set(EXPECTED_SCOPE_HEADER, expectedScope);
	}
    if (isMutation(request.method)) {
      const csrfToken = getCSRFToken();
      if (csrfToken) headers.set("X-CSRF-Token", csrfToken);
    }
    const timeout = new AbortController();
    const timer = globalThis.setTimeout(() => timeout.abort(), timeoutMs);
    const signal = AbortSignal.any([request.signal, timeout.signal]);
    const securedRequest = new Request(request, {
      credentials: "same-origin",
      redirect: "error",
      headers,
      signal,
    });
    try {
      const response = await configuredFetch(securedRequest);
	  throwIfRequestStopped(request.signal, timeout.signal);
	  await validateResponse(response, maximumResponseBytes, onSessionExpired, onScopeStale, onFreshAuthRequired, signal);
	  throwIfRequestStopped(request.signal, timeout.signal);
      return response;
    } catch (error) {
      if (request.signal.aborted) throw request.signal.reason;
      if (timeout.signal.aborted) throw new APITransportError("timeout", "API request timed out");
      throw error;
    } finally {
      globalThis.clearTimeout(timer);
    }
  };
  return createClient<paths>({
    ...clientOptions,
    baseUrl: `${origin}${baseUrl}`,
    credentials: "same-origin",
    redirect: "error",
    fetch: transport,
  });
}

export type APIClient = ReturnType<typeof createAPIClient>;
export type ProductID = ProductId;
export type { Cursor, PageInfo, ProductError } from "./generated";

function validRelativeBaseURL(value: string): boolean {
  if (value === "") return true;
  if (!value.startsWith("/") || value.startsWith("//") || value.includes("\\") || value.includes("?") || value.includes("#")) return false;
  const lower = value.toLowerCase();
  if (lower.includes("%2f") || lower.includes("%5c") || value.includes("//")) return false;
  return value.split("/").every((segment) => segment !== "." && segment !== "..");
}

function validBound(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && value <= 60 * 1024 * 1024;
}

function defaultCorrelationID(): string {
  return `pid_${globalThis.crypto.randomUUID()}`;
}

function isMutation(method: string): boolean {
  return method === "POST" || method === "PUT" || method === "PATCH" || method === "DELETE";
}

async function validateResponse(response: Response, maximumBytes: number, onSessionExpired: () => void, onScopeStale: () => void, onFreshAuthRequired: () => void, signal: AbortSignal): Promise<void> {
  if (signal.aborted) throw signal.reason;
  if (!(response instanceof Response) || response.redirected) {
    throw new APITransportError("invalid_response", "API returned an invalid response");
  }
  if (response.status === 204 || response.status === 205) return;
  const contentType = response.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new APITransportError(response.ok ? "invalid_response" : "invalid_error", "API returned an invalid content type");
  }
  const payload = await readBounded(response.clone(), maximumBytes);
	if (signal.aborted) throw signal.reason;
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder().decode(payload));
  } catch {
    throw new APITransportError(response.ok ? "invalid_response" : "invalid_error", "API returned malformed JSON");
  }
  if (!response.ok) {
    if (!isProductError(decoded)) {
      throw new APITransportError("invalid_error", "API returned an invalid product error");
    }
    if (response.status === 401 && decoded.code === "authentication_required") onSessionExpired();
	if (response.status === 409 && decoded.code === "scope_stale" && decoded.message === SCOPE_STALE_MESSAGE && decoded.retryable) onScopeStale();
	if (response.status === 403 && decoded.code === "fresh_auth_required" && decoded.message === FRESH_AUTH_MESSAGE && !decoded.retryable) onFreshAuthRequired();
  }
}

function throwIfRequestStopped(requestSignal: AbortSignal, timeoutSignal: AbortSignal): void {
	if (requestSignal.aborted) throw requestSignal.reason;
	if (timeoutSignal.aborted) throw new APITransportError("timeout", "API request timed out");
}

function validExpectedScope(value: string): boolean {
	const parts = value.split("/");
	return parts.length === 3 && parts.every((part) => PRODUCT_ID.test(part));
}

async function readBounded(response: Response, maximumBytes: number): Promise<Uint8Array> {
  const declared = response.headers.get("Content-Length");
  if (declared !== null && Number(declared) > maximumBytes) {
    throw new APITransportError("response_too_large", "API response exceeded the configured limit");
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > maximumBytes) {
      void reader.cancel();
      throw new APITransportError("response_too_large", "API response exceeded the configured limit");
    }
    chunks.push(value);
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function isProductError(value: unknown): value is { code: string; message: string; correlation_id: string; retryable: boolean } {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).length === 4 &&
    typeof record.code === "string" && /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/.test(record.code) &&
    typeof record.message === "string" && record.message.length > 0 &&
    typeof record.correlation_id === "string" && PRODUCT_ID.test(record.correlation_id) &&
    typeof record.retryable === "boolean";
}
