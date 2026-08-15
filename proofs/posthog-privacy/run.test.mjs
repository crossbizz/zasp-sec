import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import test from "node:test";

import { exactAnalyticsInput, serializeAnalyticsEvent } from "./serializer.mjs";
import {
  createFakePostHogEndpoint,
  failureCategories,
  runMain,
  runProof,
  sendAnalyticsEvent,
  successLine,
} from "./run.mjs";

async function rawRequest(endpoint, {
  body,
  method = "POST",
  path = "/capture",
  contentType = "application/json",
  hostHeader,
}) {
  const target = new URL(endpoint);
  return await new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: target.hostname,
      port: target.port,
      method,
      path,
      agent: false,
      headers: {
        "content-type": contentType,
        "content-length": Buffer.byteLength(body),
        ...(hostHeader === undefined ? {} : { host: hostHeader }),
      },
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({ statusCode: response.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
    });
    request.once("error", reject);
    request.end(body);
  });
}

test("exact local lifecycle sends one event and closes the endpoint", async () => {
  const result = await runProof();
  assert.deepEqual(result, {
    event: true,
    prompt: false,
    secret: false,
    ip: false,
    evidence: false,
    cleanup: true,
  });
});

test("privacy rejection happens before transport I/O", async () => {
  for (const key of ["prompt", "secret", "ipAddress", "rawEvidence"]) {
    let calls = 0;
    await assert.rejects(
      sendAnalyticsEvent({
        endpoint: "http://127.0.0.1:1/capture",
        event: { ...exactAnalyticsInput, [key]: `seeded-${key}` },
        requestImpl: () => { calls += 1; throw new Error("must not run"); },
      }),
      { name: "TypeError" },
    );
    assert.equal(calls, 0, key);
  }

  const hostEndpoint = await createFakePostHogEndpoint();
  try {
    const response = await rawRequest(hostEndpoint.url, {
      body: serializeAnalyticsEvent(exactAnalyticsInput),
      hostHeader: "attacker.example.test",
    });
    assert.notEqual(response.statusCode, 200);
    assert.equal(hostEndpoint.receipts.length, 0);
  } finally {
    await hostEndpoint.close();
  }
});

test("endpoint accepts exactly one request and rejects hostile HTTP and JSON forms", async () => {
  for (const request of [
    { body: "{}", method: "GET" },
    { body: "{}", path: "/capture?redirect=https://example.test" },
    { body: "{}", contentType: "text/plain" },
    { body: '{"event":"proof_completed","event":"other"}' },
    { body: " ".repeat(16_385) },
  ]) {
    const endpoint = await createFakePostHogEndpoint();
    try {
      const response = await rawRequest(endpoint.url, request);
      assert.notEqual(response.statusCode, 200);
      assert.equal(endpoint.receipts.length, 0);
    } finally {
      await endpoint.close();
    }
  }

  const endpoint = await createFakePostHogEndpoint();
  try {
    await sendAnalyticsEvent({ endpoint: endpoint.url, event: exactAnalyticsInput });
    await assert.rejects(sendAnalyticsEvent({ endpoint: endpoint.url, event: exactAnalyticsInput }));
    assert.equal(endpoint.receipts.length, 1);
  } finally {
    await endpoint.close();
  }
});

test("client refuses non-loopback destinations and hostile responses", async () => {
  for (const endpoint of [
    "https://app.posthog.com/capture",
    "http://localhost:8000/capture",
    "http://127.0.0.1:8000/other",
    "http://127.0.0.2:8000/capture",
    "http://2130706433:8000/capture",
    "http://user:pass@127.0.0.1:8000/capture",
  ]) {
    await assert.rejects(sendAnalyticsEvent({ endpoint, event: exactAnalyticsInput }), { name: "TypeError" });
  }

  for (const response of [
    { statusCode: 302, headers: { "content-type": "application/json", "content-length": "15" }, body: '{"status":"ok"}' },
    { statusCode: 200, headers: { "content-type": "text/html", "content-length": "15" }, body: '{"status":"ok"}' },
    { statusCode: 200, headers: { "content-type": "application/json", "content-length": "16" }, body: '{"status":"ok"}\n' },
    { statusCode: 200, headers: { "content-type": "application/json", "content-length": "15" }, body: '{"status":"no"}' },
  ]) {
    await assert.rejects(sendAnalyticsEvent({
      endpoint: "http://127.0.0.1:8000/capture",
      event: exactAnalyticsInput,
      requestImpl: async () => response,
    }));
  }

  let headerReads = 0;
  const hostileHeaders = {};
  Object.defineProperty(hostileHeaders, "content-type", {
    enumerable: true,
    get() { headerReads += 1; return "application/json"; },
  });
  Object.defineProperty(hostileHeaders, "content-length", { enumerable: true, value: "15" });
  await assert.rejects(sendAnalyticsEvent({
    endpoint: "http://127.0.0.1:8000/capture",
    event: exactAnalyticsInput,
    requestImpl: async () => ({ statusCode: 200, headers: hostileHeaders, body: '{"status":"ok"}' }),
  }));
  assert.equal(headerReads, 0);

  await assert.rejects(sendAnalyticsEvent({
    endpoint: "http://127.0.0.1:8000/capture",
    event: exactAnalyticsInput,
    requestImpl: async () => ({
      statusCode: 200,
      headers: { "content-type": "application/json", "content-length": "15" },
      rawHeaders: ["content-type", "text/plain", "Content-Type", "application/json", "content-length", "15"],
      body: '{"status":"ok"}',
    }),
  }));
});

test("main deadline aborts the active request and independent cleanup still runs", async () => {
  const events = [];
  const endpoint = {
    url: "http://127.0.0.1:8000/capture",
    async close() { events.push("close"); },
  };
  const send = async ({ signal }) => {
    assert.ok(signal instanceof AbortSignal);
    events.push("send");
    await new Promise((resolve, reject) => {
      signal.addEventListener("abort", () => reject(Object.assign(new Error("deadline"), { category: "deadline" })), { once: true });
    });
  };
  await assert.rejects(runProof({ createEndpoint: async () => endpoint, send, mainTimeoutMs: 20 }), (error) => error?.category === "deadline");
  assert.deepEqual(events, ["send", "close"]);
});

test("cleanup is independent continues after failure and wins precedence", async () => {
  const events = [];
  const endpoint = {
    url: "http://127.0.0.1:8000/capture",
    receipts: [],
    async close() { events.push("close"); throw Object.assign(new Error("cleanup"), { category: "cleanup" }); },
  };
  await assert.rejects(
    runProof({
      createEndpoint: async () => endpoint,
      send: async () => { events.push("send"); throw Object.assign(new Error("operation"), { category: "operation" }); },
    }),
    (error) => error?.category === "cleanup",
  );
  assert.deepEqual(events, ["send", "close"]);
});

test("CLI emits one fixed line for success and every failure category", async () => {
  const output = [];
  assert.equal(await runMain({ write: (line) => output.push(line), run: async () => ({
    event: true, prompt: false, secret: false, ip: false, evidence: false, cleanup: true,
  }) }), 0);
  assert.deepEqual(output, [successLine]);

  for (const category of failureCategories) {
    const lines = [];
    const error = Object.assign(new Error("sensitive provider response"), { category });
    assert.equal(await runMain({ write: (line) => lines.push(line), run: async () => { throw error; } }), 1);
    assert.deepEqual(lines, [`PostHog privacy proof failed: ${category} rejected.`]);
  }
});
