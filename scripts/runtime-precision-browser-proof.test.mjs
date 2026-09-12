import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import { assertPrecisionBrowserCanonicalOrder, assertPrecisionBrowserIdentity, createPrecisionBrowserCheckpoint, runPrecisionBrowserProof, validatePrecisionBrowserMode } from "./runtime-precision-browser-proof.mjs";

const enabled = {
  ZASP_COMBINED_E2E_RUNTIME_PRECISION_BROWSER: "true",
  ZASP_COMBINED_E2E_RUNTIME_PRECISION: "true",
  ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY: "true",
  ZASP_COMBINED_E2E_RUNTIME_SANDBOX_SEARCH: "true",
};

test("browser mode requires every exact prerequisite before allocation", () => {
  assert.equal(validatePrecisionBrowserMode({}), false);
  assert.equal(validatePrecisionBrowserMode({ ...enabled, ZASP_COMBINED_E2E_RUNTIME_PRECISION_BROWSER: "false" }), false);
  assert.equal(validatePrecisionBrowserMode(enabled), true);
  for (const key of Object.keys(enabled).filter(key => key !== "ZASP_COMBINED_E2E_RUNTIME_PRECISION_BROWSER")) {
    for (const value of [undefined, "false", "TRUE", "1"]) {
      assert.throws(() => validatePrecisionBrowserMode({ ...enabled, [key]: value }), /precision browser/);
    }
  }
});

function metadata(deadline = Date.now() + 60_000) {
  return {
    schema: "runtime-precision-browser-checkpoint-v1", deadline_unix_ms: deadline,
    scope: { organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000022-0000-4000-8000-000000000022", environment_id: "pid_10000023-0000-4000-8000-000000000023" },
    batch_id: "pid_78991901-0000-4000-8000-000000000001",
    agent_id: "pid_78991201-0000-4000-8000-000000000001", session_id: "pid_78991202-0000-4000-8000-000000000002",
    sandbox_id: "precision-observed-sandbox", sandbox_source_sensor_id: "pid_78991002-0000-4000-8000-000000000002",
    bound_event: { event_id: "pid_78991902-0000-4000-8000-000000000002", evidence_id: "pid_78991903-0000-4000-8000-000000000003", at: "2026-09-11T12:00:00.123Z" },
    unknown_event: { event_id: "pid_78991904-0000-4000-8000-000000000004", evidence_id: "pid_78991905-0000-4000-8000-000000000005", at: "2026-09-11T12:00:00.124Z" },
    process_start_times: ["2026-09-11T12:00:00.123456789Z", "2026-09-11T12:00:00.12345679Z"],
    source_event_times: ["2026-09-11T12:00:00.123999999Z", "2026-09-11T12:00:00.124111111Z"],
  };
}

function post(gate, body = metadata(), options = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request(options.url ?? gate.endpoint, { method: options.method ?? "POST", headers: { authorization: `Bearer ${options.token ?? gate.token}`, "content-type": "application/json" } }, response => {
      let text = "";
      response.on("data", chunk => { text += chunk; });
      response.on("end", () => resolve({ status: response.statusCode, body: text }));
    });
    request.on("error", reject);
    request.end(typeof body === "string" ? body : JSON.stringify(body));
  });
}

test("browser acceptance requires exact persisted Strong and unknown identities without inventing source-time display", () => {
  const input = metadata();
  const bound = { id: input.bound_event.event_id, evidence_id: input.bound_event.evidence_id, at: input.bound_event.at, confidence: "strong", source: "tetragon", agent_id: input.agent_id, session_id: input.session_id, sandbox_id: input.sandbox_id, sandbox_source_sensor_id: input.sandbox_source_sensor_id };
  const unknown = { id: input.unknown_event.event_id, evidence_id: input.unknown_event.evidence_id, at: input.unknown_event.at, confidence: "unattributed", source: "tetragon", agent_id: null, session_id: null };
  assert.doesNotThrow(() => assertPrecisionBrowserIdentity(input, bound, unknown));
  assert.doesNotThrow(() => assertPrecisionBrowserIdentity(input, { ...bound, at: "2026-09-11T05:00:00.123-07:00" }, { ...unknown, at: "2026-09-11T17:30:00.124+05:30" }));
  assert.throws(() => assertPrecisionBrowserIdentity(input, { ...bound, at: "2026-09-11T05:00:00.123000001-07:00" }, unknown));
  for (const change of [{ confidence: "exact" }, { sandbox_id: null }, { sandbox_source_sensor_id: null }, { agent_id: unknown.id }, { at: input.source_event_times[0] }, { evidence_id: unknown.evidence_id }]) {
    assert.throws(() => assertPrecisionBrowserIdentity(input, { ...bound, ...change }, unknown));
  }
  for (const change of [{ confidence: "strong" }, { sandbox_id: null }, { sandbox_source_sensor_id: null }, { sandbox_id: null, sandbox_source_sensor_id: null }, { sandbox_id: undefined }, { sandbox_id: input.sandbox_id }, { sandbox_source_sensor_id: input.sandbox_source_sensor_id }, { sandbox_id: input.sandbox_id, sandbox_source_sensor_id: input.sandbox_source_sensor_id }, { agent_id: input.agent_id }, { session_id: input.session_id }, { id: bound.id }]) {
    assert.throws(() => assertPrecisionBrowserIdentity(input, bound, { ...unknown, ...change }));
  }
  assert.throws(() => assertPrecisionBrowserIdentity({ ...input, process_start_times: [input.process_start_times[0], input.process_start_times[0]] }, bound, unknown));
});

test("canonical browser order preserves adjacent nanoseconds despite reverse lexical IDs", () => {
  const earlier = { id: "z", at: "2026-09-11T12:00:00.123456789Z" };
  const later = { id: "a", at: "2026-09-11T12:00:00.123456790Z" };
  assert.doesNotThrow(() => assertPrecisionBrowserCanonicalOrder(earlier, later));
  assert.throws(() => assertPrecisionBrowserCanonicalOrder(later, earlier));
});

test("canonical browser order uses IDs for equal instants with different fraction widths", () => {
  const earlier = { id: "a", at: "2026-09-11T12:00:00.123Z" };
  const later = { id: "z", at: "2026-09-11T12:00:00.123000000Z" };
  assert.doesNotThrow(() => assertPrecisionBrowserCanonicalOrder(earlier, later));
  assert.throws(() => assertPrecisionBrowserCanonicalOrder(later, earlier));
  assert.throws(() => assertPrecisionBrowserCanonicalOrder(earlier, { ...later, id: earlier.id }));
});

test("canonical browser order compares offset instants without dropping nanoseconds", () => {
  const earlier = { id: "z", at: "2026-09-11T05:00:00.123456789-07:00" };
  const later = { id: "a", at: "2026-09-11T17:30:00.123456790+05:30" };
  assert.doesNotThrow(() => assertPrecisionBrowserCanonicalOrder(earlier, later));
  assert.throws(() => assertPrecisionBrowserCanonicalOrder(later, earlier));
  const equal = { id: "a", at: "2026-09-11T12:00:00.123456789Z" };
  assert.doesNotThrow(() => assertPrecisionBrowserCanonicalOrder(equal, earlier));
  assert.throws(() => assertPrecisionBrowserCanonicalOrder(earlier, equal));
  for (const at of ["2026-09-11T12:00:00", "2026-09-11T12:00:00.1234567890Z", "2026-09-11T12:00:00+99:00"]) {
    assert.throws(() => assertPrecisionBrowserCanonicalOrder(equal, { ...later, at }));
  }
});

test("checkpoint holds the actual HTTP caller until one authorized release", async t => {
  const gate = await createPrecisionBrowserCheckpoint();
  t.after(() => gate.close());
  assert.match(gate.endpoint, /^http:\/\/127\.0\.0\.1:[1-9][0-9]*\/checkpoint$/);
  assert.match(gate.token, /^[0-9a-f]{64}$/);
  assert.throws(() => gate.release(), /precision browser/);
  const input = metadata();
  let settled = false;
  const response = post(gate, input).then(value => { settled = true; return value; });
  assert.deepEqual(await gate.waitReady(), input);
  assert.equal(settled, false, "provider resumed before browser acceptance");
  assert.equal((await post(gate, input)).status, 409);
  gate.release();
  assert.throws(() => gate.release(), /precision browser/);
  assert.deepEqual(await response, { status: 200, body: '{"released":true}' });
  await gate.close();
  await gate.close();
  await assert.rejects(post(gate), /ECONNREFUSED|ECONNRESET|socket hang up/);
});

test("invalid requests cannot choose a runtime authority or consume readiness", async t => {
  const gate = await createPrecisionBrowserCheckpoint();
  t.after(() => gate.close());
  assert.equal((await post(gate, metadata(), { token: "wrong" })).status, 401);
  assert.equal((await post(gate, metadata(), { method: "GET" })).status, 404);
  assert.equal((await post(gate, metadata(), { url: gate.endpoint + "/other" })).status, 404);
  for (const body of ["{", "x".repeat(16_385), { ...metadata(), database: "postgres://foreign" }, { ...metadata(), deadline_unix_ms: Date.now() - 1 }, { ...metadata(), agent_id: "bad" }, { ...metadata(), sandbox_id: "bad\u0001" }, { ...metadata(), sandbox_id: "bad\u007f" }, { ...metadata(), bound_event: { ...metadata().bound_event, raw: "forbidden" } }]) {
    assert.ok([400, 413].includes((await post(gate, body)).status));
  }
  const response = post(gate);
  await gate.waitReady();
  gate.release();
  assert.equal((await response).status, 200);
});

test("close before ready rejects all waiters and closes the port", async () => {
  const gate = await createPrecisionBrowserCheckpoint();
  const first = assert.rejects(gate.waitReady(), /precision browser/);
  const second = assert.rejects(gate.waitReady(), /precision browser/);
  await gate.close();
  await Promise.all([first, second]);
  await assert.rejects(post(gate), /ECONNREFUSED|ECONNRESET|socket hang up/);
});

test("ready timeout and abort settle readiness without a caller", async () => {
  for (const abort of [false, true]) {
    const controller = new AbortController();
    const gate = await createPrecisionBrowserCheckpoint({ readyTimeoutMs: 20, signal: controller.signal });
    const result = assert.rejects(gate.waitReady(), /precision browser/);
    if (abort) controller.abort();
    await result;
    await gate.close();
    await assert.rejects(post(gate), /ECONNREFUSED|ECONNRESET|socket hang up/);
  }
});

test("release deadline respects the shorter inherited provider deadline", async t => {
  const gate = await createPrecisionBrowserCheckpoint({ releaseTimeoutMs: 60_000 });
  t.after(() => gate.close());
  const response = post(gate, metadata(Date.now() + 80));
  await gate.waitReady();
  const result = await response;
  assert.equal(result.status, 503);
  assert.deepEqual(JSON.parse(result.body), { released: false });
  assert.throws(() => gate.release(), /precision browser/);
});

test("closing before release fails the paused provider, not a successful release", async () => {
  const gate = await createPrecisionBrowserCheckpoint();
  const response = post(gate);
  await gate.waitReady();
  await gate.close();
  assert.deepEqual(await response, { status: 503, body: '{"released":false}' });
  assert.throws(() => gate.release(), /precision browser/);
});

test("a disconnected paused provider cannot later be released", async t => {
  const gate = await createPrecisionBrowserCheckpoint();
  t.after(() => gate.close());
  const request = http.request(gate.endpoint, { method: "POST", headers: { authorization: `Bearer ${gate.token}`, "content-type": "application/json" } });
  request.on("error", () => {});
  request.end(JSON.stringify(metadata()));
  await gate.waitReady();
  const closed = new Promise(resolve => request.once("close", resolve));
  request.destroy();
  await closed;
  for (let attempt = 0; attempt < 20; attempt++) {
    if (await post(gate).then(value => value.status, () => 503) === 503) break;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.throws(() => gate.release(), /precision browser/);
});

test("checkpoint accepts Go HTML escapes while refusing duplicate metadata keys", async t => {
  const gate = await createPrecisionBrowserCheckpoint();
  t.after(() => gate.close());
  const value = { ...metadata(), sandbox_id: "sandbox-<>&\u2028\u2029" };
  const goJSON = JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, character => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
  assert.equal((await post(gate, goJSON.replace('"schema":', '"schema":"ignored","schema":'))).status, 400);
  const response = post(gate, goJSON);
  const ready = await Promise.race([gate.waitReady(), response.then(result => { throw new Error(`valid Go metadata rejected: ${result.status}`); })]);
  assert.deepEqual(ready, value);
  gate.release();
  assert.equal((await response).status, 200);
});

test("an already cancelled gate returns a valid closed owned endpoint", async () => {
  const controller = new AbortController();
  controller.abort();
  const gate = await createPrecisionBrowserCheckpoint({ signal: controller.signal });
  assert.match(gate.endpoint, /^http:\/\/127\.0\.0\.1:[1-9][0-9]*\/checkpoint$/);
  await assert.rejects(gate.waitReady(), /cancelled/);
  await gate.close();
  await assert.rejects(post(gate), /ECONNREFUSED|ECONNRESET|socket hang up/);
});

test("parent lifecycle preserves provider success but suppresses browser success after a later failure", async t => {
  for (const failingPhase of ["", "pending", "provider", "current"]) {
    const gate = await createPrecisionBrowserCheckpoint();
    t.after(() => gate.close());
    const observed = [];
    let result;
    const proof = runPrecisionBrowserProof({
      checkpoint: gate,
      startProvider: async () => {
        result = await post(gate);
        observed.push(result.status === 200 ? "provider passed" : "provider aborted");
        if (result.status !== 200) throw new Error("provider aborted");
        return result;
      },
      stopProvider: async () => { observed.push("stop after gate close"); await assert.rejects(post(gate), /ECONNREFUSED|ECONNRESET|socket hang up/); },
      observePending: async value => { assert.equal(value.schema, "runtime-precision-browser-checkpoint-v1"); observed.push("pending"); if (failingPhase === "pending") throw new Error("pending failed"); return "actual product handle"; },
      verifyProvider: value => { assert.equal(value.status, 200); observed.push("provider verified"); if (failingPhase === "provider") throw new Error("provider marker failed"); },
      observeCurrent: async (value, handle) => { assert.equal(handle, "actual product handle"); observed.push("current"); if (failingPhase === "current") throw new Error("current failed"); },
    }).then(value => { observed.push("browser marker"); return value; });
    if (failingPhase) await assert.rejects(proof, new RegExp(`${failingPhase}.*failed`)); else await proof;
    assert.equal(observed.includes("browser marker"), failingPhase === "");
    assert.equal(observed.includes("provider passed"), failingPhase !== "pending");
    assert.equal(observed.includes("current"), failingPhase === "" || failingPhase === "current");
    await gate.close();
    await assert.rejects(post(gate), /ECONNREFUSED|ECONNRESET|socket hang up/);
  }
});

test("an early provider failure settles the ready waiter before child join", async t => {
  const gate = await createPrecisionBrowserCheckpoint();
  t.after(() => gate.close());
  const observed = [];
  const waiter = assert.rejects(gate.waitReady(), /precision browser/).then(() => observed.push("waiter settled"));
  await assert.rejects(runPrecisionBrowserProof({
    checkpoint: gate,
    startProvider: async () => { throw new Error("provider failed before checkpoint"); },
    stopProvider: async () => { await waiter; observed.push("child joined"); },
    observePending: () => { throw new Error("must not reach browser"); },
    verifyProvider: () => { throw new Error("must not verify failed provider"); },
    observeCurrent: () => { throw new Error("must not reach browser"); },
  }), /provider failed before checkpoint/);
  assert.deepEqual(observed, ["waiter settled", "child joined"]);
  await gate.close();
});
