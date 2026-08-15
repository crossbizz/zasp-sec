import assert from "node:assert/strict";
import { test } from "node:test";

import { exactPlan, exactPlanningInput, exactPlanningRequest } from "./planner.mjs";
import {
  createFakePlannerEndpoint,
  failureCategories,
  runMain,
  runProof,
  sendPlanningRequest,
  successLine,
} from "./run.mjs";

test("exact local lifecycle returns a catalog-only in-scope plan and closes endpoint", async () => {
  assert.deepEqual(await runProof(), {
    catalog: true, scope: true, injection: false, url: false, shell: false, cleanup: true,
  });
});

test("fake endpoint accepts one exact request containing bounded untrusted data", async () => {
  const endpoint = await createFakePlannerEndpoint();
  try {
    const result = await sendPlanningRequest({ endpoint: endpoint.url, input: exactPlanningInput });
    assert.deepEqual(result.plan, exactPlan);
    assert.equal(endpoint.requestCount, 1);
    assert.deepEqual(endpoint.receipts, [JSON.stringify(exactPlanningRequest)]);
    await assert.rejects(() => sendPlanningRequest({ endpoint: endpoint.url, input: exactPlanningInput }));
  } finally {
    await endpoint.close();
  }
});

test("client rejects noncanonical endpoints and hostile response metadata", async () => {
  for (const endpoint of [
    "https://127.0.0.1:443/api/v1/chat/completions",
    "http://localhost:1234/api/v1/chat/completions",
    "http://2130706433:1234/api/v1/chat/completions",
    "http://127.0.0.1:1234/other",
    "http://127.0.0.1:1234/api/v1/chat/completions?x=1",
  ]) await assert.rejects(() => sendPlanningRequest({ endpoint, input: exactPlanningInput }), TypeError);

  const validEndpoint = "http://127.0.0.1:1234/api/v1/chat/completions";
  const responseBody = Buffer.from(JSON.stringify({
    id: "chatcmpl-zasp-m021a", object: "chat.completion", created: 0,
    model: "zasp/fake-security-planner-v1",
    choices: [{ index: 0, message: { role: "assistant", content: JSON.stringify(exactPlan) }, finish_reason: "stop" }],
    usage: { prompt_tokens: 96, completion_tokens: 64, total_tokens: 160 },
  }));
  const headers = {
    "content-type": "application/json", "content-length": String(responseBody.length),
    "cache-control": "no-store", connection: "close",
  };
  const base = {
    statusCode: 200, headers,
    rawHeaders: ["Content-Type", "application/json", "Content-Length", String(responseBody.length), "Cache-Control", "no-store", "Connection", "close"],
    body: responseBody,
  };
  for (const response of [
    { ...base, statusCode: 201 },
    { ...base, rawHeaders: [...base.rawHeaders, "Content-Type", "application/json"] },
    { ...base, headers: { ...headers, "x-extra": "no" } },
    { ...base, body: Buffer.concat([responseBody, Buffer.from("x")]) },
  ]) await assert.rejects(() => sendPlanningRequest({
    endpoint: validEndpoint, input: exactPlanningInput, requestImpl: async () => response,
  }));
});

test("invalid input performs zero request I/O", async () => {
  let calls = 0;
  await assert.rejects(() => sendPlanningRequest({
    endpoint: "http://127.0.0.1:1234/api/v1/chat/completions",
    input: { ...exactPlanningInput, extra: true },
    requestImpl: async () => { calls += 1; return {}; },
  }), TypeError);
  assert.equal(calls, 0);
});

test("main deadline aborts work and independent cleanup continues", async () => {
  let aborted = false;
  let cleaned = false;
  await assert.rejects(() => runProof({
    createEndpoint: async () => ({
      url: "http://127.0.0.1:1234/api/v1/chat/completions", receipts: [], requestCount: 0,
      close: async () => { cleaned = true; },
    }),
    send: async ({ signal }) => await new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => { aborted = true; reject(new Error("aborted")); }, { once: true });
    }),
    mainTimeoutMs: 20,
  }));
  assert.equal(aborted, true);
  assert.equal(cleaned, true);
});

test("cleanup is independently bounded and wins precedence", async () => {
  const events = [];
  await assert.rejects(() => runProof({
    createEndpoint: async () => ({
      url: "http://127.0.0.1:1234/api/v1/chat/completions", receipts: [], requestCount: 0,
      close: async () => { events.push("cleanup"); throw Object.assign(new Error("no"), { category: "cleanup" }); },
    }),
    send: async () => { events.push("main"); throw new Error("main"); },
  }), (error) => error?.category === "cleanup");
  assert.deepEqual(events, ["main", "cleanup"]);

  const started = Date.now();
  await assert.rejects(() => runProof({
    createEndpoint: async () => ({
      url: "http://127.0.0.1:1234/api/v1/chat/completions", receipts: [], requestCount: 0,
      close: async () => await new Promise(() => {}),
    }),
    send: async () => { throw new Error("main"); },
    cleanupTimeoutMs: 20,
  }), (error) => error?.category === "cleanup");
  assert.ok(Date.now() - started < 500);
});

test("CLI emits exactly one fixed line for success and every failure", async () => {
  const lines = [];
  assert.equal(await runMain({ write: (line) => lines.push(line) }), 0);
  assert.deepEqual(lines, [successLine]);
  for (const category of failureCategories) {
    const failed = [];
    assert.equal(await runMain({ write: (line) => failed.push(line), run: async () => { throw { category }; } }), 1);
    assert.deepEqual(failed, [`Security Agent planner proof failed: ${category} rejected.`]);
  }
  const unknown = [];
  assert.equal(await runMain({ write: (line) => unknown.push(line), run: async () => { throw new Error("secret raw failure"); } }), 1);
  assert.deepEqual(unknown, ["Security Agent planner proof failed: operation rejected."]);
});
