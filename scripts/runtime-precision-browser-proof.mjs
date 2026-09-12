import http from "node:http";
import assert from "node:assert/strict";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { once } from "node:events";

const failure = reason => new Error(`precision browser checkpoint ${reason}`);
const id = value => typeof value === "string" && /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const instant = value => typeof value === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value));
const keys = (value, names) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join(",") === [...names].sort().join(",");
// Match encoding/json's compact default, including its HTML and JS separators.
const goJSON = value => JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, character => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);

export function assertPrecisionBrowserCanonicalOrder(previous, current) {
  const before = canonicalNanos(previous.at), after = canonicalNanos(current.at);
  assert.ok(before < after || before === after && previous.id < current.id, "visible timeline reversed canonical event_time/event_id order");
}

function canonicalNanos(value) {
  const parts = typeof value === "string" && /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/.exec(value);
  assert.ok(parts && Number.isFinite(Date.parse(value)), "invalid canonical instant");
  // The public API preserves PostgreSQL's offset. Keep its instant and full
  // fraction here; the visible row must still retain the API's original bytes.
  return BigInt(Date.parse(parts[1] + parts[3])) * 1_000_000n + BigInt((parts[2] ?? "").padEnd(9, "0"));
}

export function assertPrecisionBrowserIdentity(metadata, bound, unknown) {
  assert.equal(canonicalNanos(metadata.process_start_times[1]) - canonicalNanos(metadata.process_start_times[0]), 1n, "fixture did not distinguish adjacent process-start nanoseconds");
  assert.equal(Date.parse(metadata.process_start_times[0]), Date.parse(metadata.process_start_times[1]), "process starts were not in the same displayed millisecond");
  assert.notEqual(metadata.source_event_times[0], metadata.source_event_times[1]);
  for (const [event, expected] of [[bound, metadata.bound_event], [unknown, metadata.unknown_event]]) {
    assert.equal(event.id, expected.event_id);
    assert.equal(event.evidence_id, expected.evidence_id);
    assert.equal(canonicalNanos(event.at), canonicalNanos(expected.at), "public at must remain persisted canonical event_time");
    assert.equal(event.source, "tetragon");
  }
  assert.equal(bound.confidence, "strong", "precise correlation must not upgrade Strong to Exact");
  assert.equal(bound.agent_id, metadata.agent_id);
  assert.equal(bound.session_id, metadata.session_id);
  assert.equal(bound.sandbox_id, metadata.sandbox_id);
  assert.equal(bound.sandbox_source_sensor_id, metadata.sandbox_source_sensor_id);
  assert.equal(unknown.confidence, "unattributed");
  for (const field of ["agent_id", "session_id"]) assert.equal(unknown[field], null, `unknown event acquired ${field}`);
  for (const field of ["sandbox_id", "sandbox_source_sensor_id"]) assert.equal(Object.hasOwn(unknown, field), false, `unknown wire event included ${field}`);
}

export async function runPrecisionBrowserProof({ checkpoint, startProvider, stopProvider, observePending, verifyProvider, observeCurrent }) {
  let providerError, released = false;
  // Install rejection handling in the same turn as command creation, before
  // waiting for either the checkpoint or the browser startup.
  const provider = Promise.resolve().then(startProvider);
  void provider.then(() => {
    if (!released) { providerError = failure("provider exited before release"); void checkpoint.close(); }
  }, error => { providerError = error; void checkpoint.close(); });
  try {
    const metadata = await checkpoint.waitReady();
    const product = await observePending(metadata);
    checkpoint.release();
    released = true;
    const result = await provider;
    await verifyProvider(result);
    await observeCurrent(metadata, product);
    return result;
  } catch (error) {
    throw providerError ?? error;
  } finally {
    // Unblock an actual paused HTTP caller and every ready waiter before a
    // bounded child join. A later browser failure still rejects this parent.
    await checkpoint.close();
    await stopProvider();
    await provider.catch(() => {});
  }
}

export function validatePrecisionBrowserMode(env) {
  if (env.ZASP_COMBINED_E2E_RUNTIME_PRECISION_BROWSER !== "true") return false;
  for (const name of ["ZASP_COMBINED_E2E_RUNTIME_PRECISION", "ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY", "ZASP_COMBINED_E2E_RUNTIME_SANDBOX_SEARCH"]) {
    if (env[name] !== "true") throw failure("requires runtime-only, sandbox-search and precision modes");
  }
  return true;
}

function validMetadata(value) {
  if (!keys(value, ["schema", "deadline_unix_ms", "scope", "batch_id", "agent_id", "session_id", "sandbox_id", "sandbox_source_sensor_id", "bound_event", "unknown_event", "process_start_times", "source_event_times"]) || value.schema !== "runtime-precision-browser-checkpoint-v1") return false;
  if (!Number.isSafeInteger(value.deadline_unix_ms) || value.deadline_unix_ms <= Date.now() || value.deadline_unix_ms > Date.now() + 420_000) return false;
  if (!keys(value.scope, ["organization_id", "workspace_id", "environment_id"]) || !Object.values(value.scope).every(id)) return false;
  if (![value.batch_id, value.agent_id, value.session_id, value.sandbox_source_sensor_id].every(id) || value.agent_id === value.session_id) return false;
  if (typeof value.sandbox_id !== "string" || Buffer.byteLength(value.sandbox_id) < 1 || Buffer.byteLength(value.sandbox_id) > 256 || [...value.sandbox_id].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) return false;
  for (const event of [value.bound_event, value.unknown_event]) {
    if (!keys(event, ["event_id", "evidence_id", "at"]) || !id(event.event_id) || !id(event.evidence_id) || !instant(event.at)) return false;
  }
  if (value.bound_event.event_id === value.unknown_event.event_id || value.bound_event.evidence_id === value.unknown_event.evidence_id) return false;
  return [value.process_start_times, value.source_event_times].every(values => Array.isArray(values) && values.length === 2 && values.every(instant) && values[0] !== values[1]);
}

// This endpoint only holds an owned test process. It never selects a database,
// writes runtime evidence, or authorizes a product operation.
export async function createPrecisionBrowserCheckpoint({ readyTimeoutMs = 300_000, releaseTimeoutMs = 90_000, signal } = {}) {
  if (![readyTimeoutMs, releaseTimeoutMs].every(value => Number.isSafeInteger(value) && value > 0) || readyTimeoutMs > 300_000 || releaseTimeoutMs > 90_000) throw failure("timeout rejected");
  const token = randomBytes(32).toString("hex");
  const expectedAuthorization = Buffer.from(`Bearer ${token}`);
  let state = "waiting", pendingResponse, timer, closing;
  let resolveReady, rejectReady;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  // An early provider failure may precede the parent's waitReady call.
  ready.catch(() => {});
  const respond = (response, status, released) => {
    response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", connection: "close" });
    response.end(JSON.stringify({ released }));
  };
  const stop = () => {
    if (closing) return closing;
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
    closing = new Promise(resolve => {
      const force = setTimeout(() => server.closeAllConnections(), 50);
      server.close(() => { clearTimeout(force); resolve(); });
      server.closeIdleConnections();
    });
    return closing;
  };
  const fail = reason => {
    if (state === "released" || state === "failed") return;
    state = "failed";
    rejectReady(failure(reason));
    if (pendingResponse && !pendingResponse.destroyed) respond(pendingResponse, 503, false);
    void stop();
  };
  const abort = () => fail("cancelled");
  const server = http.createServer((request, response) => {
    if (request.method !== "POST" || request.url !== "/checkpoint") { request.resume(); respond(response, 404, false); return; }
    const authorization = Buffer.from(request.headers.authorization ?? "");
    if (authorization.length !== expectedAuthorization.length || !timingSafeEqual(authorization, expectedAuthorization)) { request.resume(); respond(response, 401, false); return; }
    if (state !== "waiting") { request.resume(); respond(response, state === "failed" ? 503 : 409, false); return; }
    if (request.headers["content-type"] !== "application/json") { request.resume(); respond(response, 400, false); return; }
    state = "reading";
    let size = 0, chunks = [], rejected = false;
    request.on("aborted", () => fail("caller disconnected"));
    request.on("error", () => fail("caller failed"));
    request.on("data", chunk => {
      size += chunk.length;
      if (size > 16_384 && !rejected) {
        rejected = true; chunks = []; state = "waiting";
        respond(response, 413, false);
      } else if (!rejected) chunks.push(chunk);
    });
    request.on("end", () => {
      if (rejected || state !== "reading") return;
      let value;
      try {
        const body = Buffer.concat(chunks).toString("utf8");
        value = JSON.parse(body);
        // Both endpoints emit compact JSON. Reject duplicate keys and invalid
        // UTF-8 instead of silently accepting a different metadata authority.
        if (!Buffer.from(body).equals(Buffer.concat(chunks)) || goJSON(value) !== body || !validMetadata(value)) throw failure("metadata rejected");
      } catch {
        state = "waiting"; respond(response, 400, false); return;
      }
      state = "ready";
      pendingResponse = response;
      response.on("close", () => { if (!response.writableEnded) fail("caller disconnected"); });
      clearTimeout(timer);
      timer = setTimeout(() => fail("release timed out"), Math.min(releaseTimeoutMs, value.deadline_unix_ms - Date.now()));
      resolveReady(value);
    });
  });
  server.headersTimeout = 5_000;
  server.requestTimeout = 5_000;
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const endpoint = `http://127.0.0.1:${server.address().port}/checkpoint`;
  timer = setTimeout(() => fail("readiness timed out"), readyTimeoutMs);
  signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) abort();
  return {
    endpoint, token,
    waitReady: () => ready.then(value => structuredClone(value)),
    release() {
      if (state !== "ready") throw failure("release rejected");
      state = "released";
      clearTimeout(timer);
      respond(pendingResponse, 200, true);
    },
    close() { fail("closed before release"); return stop(); },
  };
}
