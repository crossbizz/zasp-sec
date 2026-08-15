import { createServer, request as httpRequest } from "node:http";
import { isDeepStrictEqual } from "node:util";
import { pathToFileURL } from "node:url";

import {
  exactAnalyticsInput,
  exactCaptureDocument,
  parseStrictJson,
  serializeAnalyticsEvent,
  validateCaptureDocument,
} from "./serializer.mjs";

const maximumRequestBytes = 16_384;
const maximumResponseBytes = 4_096;
const ioDeadlineMs = 2_000;
const exactResponseBody = Buffer.from('{"status":"ok"}');

export const successLine =
  "PostHog privacy proof passed: event=true prompt=false secret=false ip=false evidence=false cleanup=true.";
export const failureCategories = Object.freeze(["configuration", "privacy", "endpoint", "operation", "cleanup", "deadline", "panic"]);

class Failure extends Error {
  constructor(category) {
    super(category);
    this.category = failureCategories.includes(category) ? category : "operation";
  }
}

export async function createFakePostHogEndpoint() {
  const receipts = [];
  let requestCount = 0;
  const sockets = new Set();
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
      if (!response.headersSent) response.writeHead(400, rejectionHeaders()).end('{"status":"rejected"}');
    });
    request.on("end", () => {
      try {
        if (requestCount !== 1 || overflow) throw new Failure("endpoint");
        if (request.method !== "POST" || request.url !== "/capture") throw new Failure("endpoint");
        const boundAddress = server.address();
        if (!boundAddress || typeof boundAddress === "string" ||
            singleRawHeader(request.rawHeaders, "host") !== `127.0.0.1:${boundAddress.port}`) throw new Failure("endpoint");
        if (!singleHeader(request.rawHeaders, "content-type", "application/json")) throw new Failure("endpoint");
        const declaredLength = singleRawHeader(request.rawHeaders, "content-length");
        if (declaredLength !== String(size)) throw new Failure("endpoint");
        const document = validateCaptureDocument(parseStrictJson(Buffer.concat(chunks)));
        receipts.push(document);
        response.writeHead(200, {
          "content-type": "application/json",
          "content-length": String(exactResponseBody.length),
          "cache-control": "no-store",
          connection: "close",
        });
        response.end(exactResponseBody);
      } catch {
        response.writeHead(400, rejectionHeaders());
        response.end('{"status":"rejected"}');
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
    url: `http://127.0.0.1:${address.port}/capture`,
    receipts,
    get requestCount() { return requestCount; },
    async close() {
      if (closed) throw new Failure("cleanup");
      closed = true;
      await closeServer(server, sockets);
    },
  };
}

export async function sendAnalyticsEvent({ endpoint, event, requestImpl = performRequest, signal }) {
  const body = serializeAnalyticsEvent(event);
  const target = validateEndpoint(endpoint);
  if (signal?.aborted) throw new Failure("deadline");
  const response = await requestImpl(target, body, signal);
  const responseBody = Buffer.isBuffer(response?.body) ? response.body : Buffer.from(response?.body ?? "");
  const headers = safeHeaders(response?.headers);
  if (response?.statusCode !== 200 || headers === undefined || !exactResponseRawHeaders(response?.rawHeaders)) {
    throw new Failure("endpoint");
  }
  if (singleValue(headers, "content-type") !== "application/json") throw new Failure("endpoint");
  if (singleValue(headers, "content-length") !== String(exactResponseBody.length)) throw new Failure("endpoint");
  if (responseBody.byteLength !== exactResponseBody.byteLength || !responseBody.equals(exactResponseBody)) throw new Failure("endpoint");
  return true;
}

export async function runProof({
  createEndpoint = createFakePostHogEndpoint,
  send = sendAnalyticsEvent,
  mainTimeoutMs = 10_000,
} = {}) {
  let endpoint;
  let operationError;
  let result;
  try {
    result = await withDeadline(async (signal) => {
      endpoint = await createEndpoint({ signal });
      if (signal.aborted) throw new Failure("deadline");
      await send({ endpoint: endpoint.url, event: exactAnalyticsInput, signal });
      if (endpoint.receipts && (!isDeepStrictEqual(endpoint.receipts, [exactCaptureDocument]) || endpoint.requestCount !== 1)) {
        throw new Failure("privacy");
      }
      for (const [key, value] of [
        ["prompt", "seeded-raw-prompt"],
        ["secret", "seeded-secret"],
        ["ipAddress", "203.0.113.10"],
        ["rawEvidence", "seeded-raw-evidence"],
      ]) {
        let rejected = false;
        try { await send({ endpoint: endpoint.url, event: { ...exactAnalyticsInput, [key]: value }, signal }); }
        catch (error) { rejected = error instanceof TypeError; }
        if (!rejected || (endpoint.receipts && (endpoint.receipts.length !== 1 || endpoint.requestCount !== 1))) {
          throw new Failure("privacy");
        }
      }
      return { event: true, prompt: false, secret: false, ip: false, evidence: false, cleanup: true };
    }, mainTimeoutMs);
  } catch (error) {
    operationError = error;
  }

  let cleanupError;
  if (endpoint) {
    try { await endpoint.close(); }
    catch (error) { cleanupError = error; }
  }
  if (cleanupError) throw asFailure(cleanupError, "cleanup");
  if (operationError) throw asFailure(operationError, operationError instanceof TypeError ? "privacy" : "operation");
  return result;
}

export async function runMain({ write = (line) => process.stdout.write(`${line}\n`), run = runProof } = {}) {
  try {
    const result = await run();
    if (!isDeepStrictEqual(result, { event: true, prompt: false, secret: false, ip: false, evidence: false, cleanup: true })) {
      throw new Failure("operation");
    }
    write(successLine);
    return 0;
  } catch (error) {
    const category = failureCategories.includes(error?.category) ? error.category : "operation";
    write(`PostHog privacy proof failed: ${category} rejected.`);
    return 1;
  }
}

function validateEndpoint(endpoint) {
  if (typeof endpoint !== "string") throw new TypeError("invalid endpoint");
  let target;
  try { target = new URL(endpoint); }
  catch { throw new TypeError("invalid endpoint"); }
  if (target.protocol !== "http:" || target.hostname !== "127.0.0.1" || target.pathname !== "/capture" ||
      target.search !== "" || target.hash !== "" || target.username !== "" || target.password !== "" ||
      target.port === "" || !/^[0-9]{1,5}$/.test(target.port) || Number(target.port) < 1 || Number(target.port) > 65_535) {
    throw new TypeError("invalid endpoint");
  }
  if (endpoint !== `http://127.0.0.1:${target.port}/capture`) throw new TypeError("invalid endpoint");
  return target;
}

async function performRequest(target, body, signal) {
  return await new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: "127.0.0.1",
      port: target.port,
      method: "POST",
      path: "/capture",
      agent: false,
      headers: {
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
    request.once("close", () => clearTimeout(timer));
    request.once("close", () => signal?.removeEventListener("abort", abort));
    request.once("error", reject);
    request.end(body);
  });
}

async function closeServer(server, sockets) {
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      for (const socket of sockets) socket.destroy();
      reject(new Failure("cleanup"));
    }, ioDeadlineMs);
    server.close((error) => {
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    });
    server.closeIdleConnections?.();
  });
}

function rejectionHeaders() {
  return { "content-type": "application/json", "cache-control": "no-store", connection: "close" };
}

function singleHeader(rawHeaders, expectedName, expectedValue) {
  return singleRawHeader(rawHeaders, expectedName) === expectedValue;
}

function singleRawHeader(rawHeaders, expectedName) {
  const values = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (rawHeaders[index]?.toLowerCase() === expectedName) values.push(rawHeaders[index + 1]);
  }
  return values.length === 1 ? values[0] : "";
}

function safeHeaders(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) return undefined;
  const output = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.get || descriptor.set) return undefined;
    if (typeof descriptor.value !== "string" &&
        !(Array.isArray(descriptor.value) && descriptor.value.every((item) => typeof item === "string"))) return undefined;
    output[key.toLowerCase()] = descriptor.value;
  }
  return output;
}

function singleValue(headers, key) {
  const value = headers[key];
  return Array.isArray(value) ? (value.length === 1 ? value[0] : "") : value;
}

function exactResponseRawHeaders(rawHeaders) {
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
  return isDeepStrictEqual(values, Object.assign(Object.create(null), {
    "content-type": "application/json",
    "content-length": String(exactResponseBody.length),
    "cache-control": "no-store",
    connection: "close",
  }));
}

function asFailure(error, fallback) {
  return error instanceof Failure ? error : new Failure(fallback);
}

async function withDeadline(operation, timeoutMs) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) throw new Failure("configuration");
  const controller = new AbortController();
  let timer;
  const operationResult = Promise.resolve().then(() => operation(controller.signal)).then(
    (value) => ({ state: "fulfilled", value }),
    (error) => ({ state: "rejected", error }),
  );
  const winner = await Promise.race([
    operationResult,
    new Promise((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve({ state: "timeout" });
      }, timeoutMs);
    }),
  ]);
  clearTimeout(timer);
  if (winner.state === "timeout") throw new Failure("deadline");
  if (winner.state === "rejected") throw winner.error;
  return winner.value;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runMain();
}
