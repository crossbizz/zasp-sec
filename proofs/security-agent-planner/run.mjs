import { createServer, request as httpRequest } from "node:http";
import { isDeepStrictEqual, types } from "node:util";
import { pathToFileURL } from "node:url";

import {
  exactPlan,
  exactPlanningInput,
  exactPlanningRequest,
  parseStrictJson,
  serializePlanningRequest,
  validateOpenRouterPlanResponse,
  validatePlanningRequest,
} from "./planner.mjs";

const maximumRequestBytes = 16_384;
const maximumResponseBytes = 8_192;
const ioDeadlineMs = 2_000;
const cleanupDeadlineMs = 2_000;
const syntheticAuthorization = "Bearer or_zasp_m021a_synthetic_test_only";
const exactResponseDocument = Object.freeze({
  id: "chatcmpl-zasp-m021a",
  object: "chat.completion",
  created: 0,
  model: "zasp/fake-security-planner-v1",
  choices: Object.freeze([Object.freeze({
    index: 0,
    message: Object.freeze({ role: "assistant", content: JSON.stringify(exactPlan) }),
    finish_reason: "stop",
  })]),
  usage: Object.freeze({ prompt_tokens: 96, completion_tokens: 64, total_tokens: 160 }),
});
const exactResponseBody = Buffer.from(JSON.stringify(exactResponseDocument));

export const successLine =
  "Security Agent planner proof passed: catalog=true scope=true injection=false url=false shell=false cleanup=true.";
export const failureCategories = Object.freeze([
  "configuration", "catalog", "scope", "injection", "endpoint", "structured", "operation", "cleanup", "deadline", "panic",
]);

class Failure extends Error {
  constructor(category) {
    super(category);
    this.category = failureCategories.includes(category) ? category : "operation";
  }
}

export async function createFakePlannerEndpoint() {
  const receipts = [];
  const sockets = new Set();
  let requestCount = 0;
  const server = createServer((request, response) => {
    response.sendDate = false;
    requestCount += 1;
    request.setTimeout(ioDeadlineMs, () => request.destroy());
    const chunks = [];
    let size = 0;
    let overflow = false;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > maximumRequestBytes) overflow = true;
      else chunks.push(chunk);
    });
    request.on("error", () => {
      if (!response.headersSent) response.writeHead(400, rejectionHeaders()).end('{"error":"rejected"}');
    });
    request.on("end", () => {
      try {
        const address = server.address();
        if (requestCount !== 1 || overflow || request.method !== "POST" ||
            request.url !== "/api/v1/chat/completions" || !address || typeof address === "string" ||
            singleRawHeader(request.rawHeaders, "host") !== `127.0.0.1:${address.port}` ||
            singleRawHeader(request.rawHeaders, "content-type") !== "application/json" ||
            singleRawHeader(request.rawHeaders, "authorization") !== syntheticAuthorization ||
            singleRawHeader(request.rawHeaders, "content-length") !== String(size) ||
            singleRawHeader(request.rawHeaders, "connection") !== "close") throw new Failure("endpoint");
        const body = Buffer.concat(chunks);
        validatePlanningRequest(parseStrictJson(body));
        receipts.push(body.toString("utf8"));
        response.writeHead(200, responseHeaders(exactResponseBody.length));
        response.end(exactResponseBody);
      } catch {
        response.writeHead(400, rejectionHeaders());
        response.end('{"error":"rejected"}');
      }
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  server.on("clientError", (_error, socket) => socket.destroy());

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Failure("deadline")), ioDeadlineMs);
    server.once("error", (error) => { clearTimeout(timer); reject(error); });
    server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, () => { clearTimeout(timer); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === "string" || address.address !== "127.0.0.1" || address.family !== "IPv4") {
    await closeServer(server, sockets);
    throw new Failure("endpoint");
  }

  let closed = false;
  return {
    url: `http://127.0.0.1:${address.port}/api/v1/chat/completions`,
    receipts,
    get requestCount() { return requestCount; },
    async close() {
      if (closed) throw new Failure("cleanup");
      closed = true;
      await closeServer(server, sockets);
    },
  };
}

export async function sendPlanningRequest({ endpoint, input, requestImpl = performRequest, signal }) {
  const body = serializePlanningRequest(input);
  const target = validateEndpoint(endpoint);
  if (signal?.aborted) throw new Failure("deadline");
  const response = await requestImpl(target, body, signal);
  const responseBody = Buffer.isBuffer(response?.body) ? response.body : Buffer.from(response?.body ?? "");
  const headers = safeHeaders(response?.headers);
  if (responseBody.byteLength > maximumResponseBytes || response?.statusCode !== 200 ||
      headers === undefined || !exactResponseRawHeaders(response?.rawHeaders, responseBody.length) ||
      !isDeepStrictEqual(headers, Object.assign(Object.create(null), responseHeaders(responseBody.length)))) {
    throw new Failure("endpoint");
  }
  try { return { plan: validateOpenRouterPlanResponse(responseBody) }; }
  catch { throw new Failure("structured"); }
}

export async function runProof({
  createEndpoint = createFakePlannerEndpoint,
  send = sendPlanningRequest,
  mainTimeoutMs = 10_000,
  cleanupTimeoutMs = cleanupDeadlineMs,
} = {}) {
  let endpoint;
  let operationError;
  let result;
  try {
    result = await withDeadline(async (signal) => {
      endpoint = await createEndpoint({ signal });
      if (signal.aborted) throw new Failure("deadline");
      const response = await send({ endpoint: endpoint.url, input: exactPlanningInput, signal });
      if (!isDeepStrictEqual(response?.plan, exactPlan)) throw new Failure("structured");
      if (endpoint.receipts && (endpoint.requestCount !== 1 || endpoint.receipts.length !== 1 ||
          endpoint.receipts[0] !== JSON.stringify(exactPlanningRequest))) throw new Failure("endpoint");
      return { catalog: true, scope: true, injection: false, url: false, shell: false, cleanup: true };
    }, mainTimeoutMs);
  } catch (error) {
    operationError = error;
  }

  let cleanupError;
  if (endpoint) {
    try { await withDeadline(() => endpoint.close(), cleanupTimeoutMs, "cleanup"); }
    catch (error) { cleanupError = error; }
  }
  if (cleanupError) throw asFailure(cleanupError, "cleanup");
  if (operationError) throw asFailure(operationError, operationError instanceof TypeError ? "configuration" : "operation");
  return result;
}

export async function runMain({ write = (line) => process.stdout.write(`${line}\n`), run = runProof } = {}) {
  try {
    const result = await run();
    if (!isDeepStrictEqual(result, {
      catalog: true, scope: true, injection: false, url: false, shell: false, cleanup: true,
    })) throw new Failure("operation");
    write(successLine);
    return 0;
  } catch (error) {
    const category = failureCategories.includes(error?.category) ? error.category : "operation";
    write(`Security Agent planner proof failed: ${category} rejected.`);
    return 1;
  }
}

function validateEndpoint(endpoint) {
  if (typeof endpoint !== "string") throw new TypeError("invalid endpoint");
  let target;
  try { target = new URL(endpoint); }
  catch { throw new TypeError("invalid endpoint"); }
  if (target.protocol !== "http:" || target.hostname !== "127.0.0.1" ||
      target.pathname !== "/api/v1/chat/completions" || target.search !== "" || target.hash !== "" ||
      target.username !== "" || target.password !== "" || target.port === "" ||
      !/^[0-9]{1,5}$/.test(target.port) || Number(target.port) < 1 || Number(target.port) > 65_535 ||
      endpoint !== `http://127.0.0.1:${target.port}/api/v1/chat/completions`) throw new TypeError("invalid endpoint");
  return target;
}

async function performRequest(target, body, signal) {
  return await new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: "127.0.0.1",
      port: target.port,
      method: "POST",
      path: "/api/v1/chat/completions",
      agent: false,
      headers: {
        authorization: syntheticAuthorization,
        "content-type": "application/json",
        "content-length": String(body.length),
        connection: "close",
      },
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > maximumResponseBytes) response.destroy(new Failure("endpoint"));
        else chunks.push(chunk);
      });
      response.once("error", reject);
      response.on("end", () => resolve({
        statusCode: response.statusCode,
        headers: response.headers,
        rawHeaders: response.rawHeaders,
        body: Buffer.concat(chunks),
      }));
    });
    const timer = setTimeout(() => request.destroy(new Failure("deadline")), ioDeadlineMs);
    const abort = () => request.destroy(new Failure("deadline"));
    signal?.addEventListener("abort", abort, { once: true });
    request.once("close", () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    });
    request.once("error", reject);
    request.end(body);
  });
}

async function closeServer(server, sockets) {
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      for (const socket of sockets) socket.destroy();
      reject(new Failure("cleanup"));
    }, cleanupDeadlineMs);
    server.close((error) => {
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    });
    server.closeIdleConnections?.();
  });
}

function responseHeaders(length) {
  return {
    "content-type": "application/json", "content-length": String(length),
    "cache-control": "no-store", connection: "close",
  };
}

function rejectionHeaders() {
  return { "content-type": "application/json", "cache-control": "no-store", connection: "close" };
}

function singleRawHeader(rawHeaders, expectedName) {
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0) return "";
  const values = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (typeof rawHeaders[index] !== "string" || typeof rawHeaders[index + 1] !== "string") return "";
    if (rawHeaders[index].toLowerCase() === expectedName) values.push(rawHeaders[index + 1]);
  }
  return values.length === 1 ? values[0] : "";
}

function safeHeaders(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) return undefined;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) return undefined;
  const output = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value") || descriptor.get || descriptor.set ||
        (typeof descriptor.value !== "string" &&
         !(Array.isArray(descriptor.value) && descriptor.value.every((item) => typeof item === "string")))) return undefined;
    output[key.toLowerCase()] = descriptor.value;
  }
  return output;
}

function exactResponseRawHeaders(rawHeaders, bodyLength) {
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0) return false;
  const values = Object.create(null);
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1];
    if (typeof name !== "string" || typeof value !== "string") return false;
    const lower = name.toLowerCase();
    if (Object.hasOwn(values, lower)) return false;
    values[lower] = value;
  }
  return isDeepStrictEqual(values, Object.assign(Object.create(null), responseHeaders(bodyLength)));
}

function asFailure(error, fallback) {
  return error instanceof Failure ? error : new Failure(fallback);
}

async function withDeadline(operation, timeoutMs, timeoutCategory = "deadline") {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) throw new Failure("configuration");
  const controller = new AbortController();
  let timer;
  const result = Promise.resolve().then(() => operation(controller.signal)).then(
    (value) => ({ state: "fulfilled", value }),
    (error) => ({ state: "rejected", error }),
  );
  const winner = await Promise.race([result, new Promise((resolve) => {
    timer = setTimeout(() => { controller.abort(); resolve({ state: "timeout" }); }, timeoutMs);
  })]);
  clearTimeout(timer);
  if (winner.state === "timeout") throw new Failure(timeoutCategory);
  if (winner.state === "rejected") throw winner.error;
  return winner.value;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runMain();
}
