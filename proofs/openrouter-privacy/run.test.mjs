import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createFakeOpenRouterEndpoint,
  failureCategories,
  runMain,
  runProof,
  sendExplanation,
  successLine,
} from "./run.mjs";
import { exactFindingInput, seededSensitiveValues } from "./gateway.mjs";

test("exact local lifecycle sends one redacted explanation and closes endpoint", async () => {
  const result = await runProof();
  assert.deepEqual(result, { explanation: true, secret: false, pii: false, structured: true, cleanup: true });
});

test("fake endpoint accepts exactly one exact request and contains no seeded sensitive value", async () => {
  const endpoint = await createFakeOpenRouterEndpoint();
  try {
    const result = await sendExplanation({ endpoint: endpoint.url, finding: exactFindingInput });
    assert.equal(result.structured, true);
    assert.equal(endpoint.requestCount, 1);
    assert.equal(endpoint.receipts.length, 1);
    for (const value of seededSensitiveValues) assert.equal(endpoint.receipts[0].includes(value), false);
    await assert.rejects(() => sendExplanation({ endpoint: endpoint.url, finding: exactFindingInput }));
  } finally {
    await endpoint.close();
  }
});

test("client rejects non-loopback endpoints and hostile response headers and body", async () => {
  for (const endpoint of [
    "https://127.0.0.1:443/api/v1/chat/completions",
    "http://localhost:1234/api/v1/chat/completions",
    "http://2130706433:1234/api/v1/chat/completions",
    "http://127.0.0.1:1234/other",
    "http://127.0.0.1:1234/api/v1/chat/completions?x=1",
  ]) await assert.rejects(() => sendExplanation({ endpoint, finding: exactFindingInput }), TypeError);

  const validEndpoint = "http://127.0.0.1:1234/api/v1/chat/completions";
  const validBody = Buffer.from(JSON.stringify({
    id: "chatcmpl-zasp-m021", object: "chat.completion", created: 0, model: "zasp/fake-explanation-v1",
    choices: [{ index: 0, message: { role: "assistant", content: JSON.stringify({
      schema_version: "1", finding_id: exactFindingInput.findingId,
      explanation: "The high-severity identity finding requires review.",
      recommendation: "Review the affected identity through approved product workflows.",
    }) }, finish_reason: "stop" }],
    usage: { prompt_tokens: 32, completion_tokens: 24, total_tokens: 56 },
  }));
  const base = {
    statusCode: 200,
    headers: { "content-type": "application/json", "content-length": String(validBody.length), "cache-control": "no-store", connection: "close" },
    rawHeaders: ["Content-Type", "application/json", "Content-Length", String(validBody.length), "Cache-Control", "no-store", "Connection", "close"],
    body: validBody,
  };
  for (const response of [
    { ...base, statusCode: 201 },
    { ...base, rawHeaders: [...base.rawHeaders, "Content-Type", "application/json"] },
    { ...base, headers: { ...base.headers, "x-extra": "no" } },
    { ...base, headers: Object.defineProperty({}, "content-type", { get: () => { throw new Error("getter"); } }) },
    { ...base, body: Buffer.concat([validBody, Buffer.from("x")]) },
  ]) await assert.rejects(() => sendExplanation({
    endpoint: validEndpoint,
    finding: exactFindingInput,
    requestImpl: async () => response,
  }));
});

test("privacy rejection performs zero request I/O and hostile header proxy traps are not invoked", async () => {
  let calls = 0;
  await assert.rejects(() => sendExplanation({
    endpoint: "http://127.0.0.1:1234/api/v1/chat/completions",
    finding: { ...exactFindingInput, secret: "no" },
    requestImpl: async () => { calls += 1; return {}; },
  }), TypeError);
  assert.equal(calls, 0);

  let trapped = false;
  const headers = new Proxy({}, {
    getPrototypeOf() { trapped = true; throw new Error("trap invoked"); },
  });
  await assert.rejects(() => sendExplanation({
    endpoint: "http://127.0.0.1:1234/api/v1/chat/completions",
    finding: exactFindingInput,
    requestImpl: async () => ({ statusCode: 200, headers, rawHeaders: [], body: Buffer.alloc(0) }),
  }));
  assert.equal(trapped, false);
});

test("main deadline aborts active work and independent cleanup continues", async () => {
  let aborted = false;
  let cleaned = false;
  const endpoint = { url: "http://127.0.0.1:1234/api/v1/chat/completions", receipts: [], requestCount: 0, close: async () => { cleaned = true; } };
  await assert.rejects(() => runProof({
    createEndpoint: async () => endpoint,
    send: async ({ signal }) => await new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => { aborted = true; reject(new Error("aborted")); }, { once: true });
    }),
    mainTimeoutMs: 20,
  }));
  assert.equal(aborted, true);
  assert.equal(cleaned, true);
});

test("cleanup continues independently and wins error precedence", async () => {
  const events = [];
  await assert.rejects(() => runProof({
    createEndpoint: async () => ({
      url: "http://127.0.0.1:1234/api/v1/chat/completions", receipts: [], requestCount: 0,
      close: async () => { events.push("cleanup"); throw Object.assign(new Error("no"), { category: "cleanup" }); },
    }),
    send: async () => { events.push("main"); throw new Error("main"); },
  }), (error) => error?.category === "cleanup");
  assert.deepEqual(events, ["main", "cleanup"]);
});

test("injected cleanup is bounded by the configured independent deadline", async () => {
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

test("CLI emits one fixed line for success and every failure category", async () => {
  const lines = [];
  assert.equal(await runMain({ write: (line) => lines.push(line) }), 0);
  assert.deepEqual(lines, [successLine]);
  for (const category of failureCategories) {
    const failed = [];
    assert.equal(await runMain({ write: (line) => failed.push(line), run: async () => { throw { category }; } }), 1);
    assert.deepEqual(failed, [`OpenRouter privacy proof failed: ${category} rejected.`]);
  }
  const unknown = [];
  assert.equal(await runMain({ write: (line) => unknown.push(line), run: async () => { throw new Error("raw"); } }), 1);
  assert.deepEqual(unknown, ["OpenRouter privacy proof failed: operation rejected."]);
});
