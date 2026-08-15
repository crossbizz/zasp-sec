import assert from "node:assert/strict";
import { request } from "node:http";
import { test } from "node:test";

import {
  agentCanary,
  createFakeAgent,
  injectionPrompt,
  runMain,
} from "./fake_agent.mjs";

const expectedHost = "zasp-m0-16-0123456789abcdef-agent:3001";
const canonicalRequest = Buffer.from(JSON.stringify({ input: injectionPrompt }));

function requestFixture(overrides = {}) {
  return {
    method: "POST",
    url: "/v1/agent",
    host: expectedHost,
    headers: {
      host: [expectedHost],
      "content-type": ["application/json"],
      "content-length": [String(canonicalRequest.byteLength)],
      "x-zasp-proof": ["m0-16"],
    },
    body: canonicalRequest,
    bodyComplete: true,
    ...overrides,
  };
}

test("accepts exactly one direct injection after exact readiness", async () => {
  const agent = createFakeAgent({ expectedHost });

  const health = await agent.handle({
    method: "GET",
    url: "/health",
    host: expectedHost,
    headers: { host: [expectedHost] },
    body: Buffer.alloc(0),
    bodyComplete: true,
  });
  assert.deepEqual(health, {
    status: 200,
    headers: { "cache-control": "no-store", "content-type": "application/json" },
    body: Buffer.from('{"ready":true}'),
  });

  const accepted = await agent.handle(requestFixture());
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.toString("utf8"), JSON.stringify({ output: agentCanary }));
  assert.deepEqual(agent.state(), { evaluations: 1 });

  const replay = await agent.handle(requestFixture());
  assert.equal(replay.status, 400);
  assert.equal(replay.body.toString("utf8"), '{"error":"invalid_request"}');
});

test("rejects method, path, query, host, header, body, and representation drift", async (context) => {
  const cases = [
    ["method", { method: "GET" }],
    ["path", { url: "/v1/chat" }],
    ["query", { url: "/v1/agent?debug=1" }],
    ["host", { host: "other:3001" }],
    ["missing proof header", { headers: { ...requestFixture().headers, "x-zasp-proof": undefined } }],
    ["duplicate proof header", { headers: { ...requestFixture().headers, "x-zasp-proof": ["m0-16", "m0-16"] } }],
    ["content type", { headers: { ...requestFixture().headers, "content-type": ["text/plain"] } }],
    ["content length", { headers: { ...requestFixture().headers, "content-length": ["1"] } }],
    ["partial", { bodyComplete: false }],
    ["malformed", { body: Buffer.from("{") }],
    ["duplicate JSON key", { body: Buffer.from(`{"input":${JSON.stringify(injectionPrompt)},"input":${JSON.stringify(injectionPrompt)}}`) }],
    ["unknown key", { body: Buffer.from(JSON.stringify({ input: injectionPrompt, extra: true })) }],
    ["wrong prompt", { body: Buffer.from(JSON.stringify({ input: "hello" })) }],
    ["oversized", { body: Buffer.alloc(4_097, 65), headers: { ...requestFixture().headers, "content-length": ["4097"] } }],
    ["primitive", { body: Buffer.from("true"), headers: { ...requestFixture().headers, "content-length": ["4"] } }],
  ];

  for (const [name, overrides] of cases) {
    await context.test(name, async () => {
      const agent = createFakeAgent({ expectedHost });
      const candidate = requestFixture(overrides);
      candidate.headers = Object.fromEntries(Object.entries(candidate.headers).filter(([, value]) => value !== undefined));
      if (overrides.body && !overrides.headers?.["content-length"]) {
        candidate.headers["content-length"] = [String(candidate.body.byteLength)];
      }
      const result = await agent.handle(candidate);
      assert.equal(result.status, 400);
      assert.deepEqual(agent.state(), { evaluations: 0 });
    });
  }
});

test("serves the real bounded HTTP boundary and closes cleanly", async () => {
  const agent = createFakeAgent({ expectedHost: "127.0.0.1" });
  await agent.listen(0, "127.0.0.1");
  const address = agent.address();
  assert.equal(typeof address, "object");

  const result = await new Promise((resolve, reject) => {
    const call = request({
      host: "127.0.0.1",
      port: address.port,
      method: "POST",
      path: "/v1/agent",
      headers: {
        Host: "127.0.0.1",
        "Content-Type": "application/json",
        "Content-Length": canonicalRequest.byteLength,
        "X-Zasp-Proof": "m0-16",
      },
    });
    const chunks = [];
    call.on("response", (response) => {
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolve({ status: response.statusCode, body: Buffer.concat(chunks) }));
    });
    call.on("error", reject);
    call.end(canonicalRequest);
  });

  assert.equal(result.status, 200);
  assert.equal(result.body.toString("utf8"), JSON.stringify({ output: agentCanary }));
  await agent.close();
});

test("contains construction and process failures behind fixed output", async () => {
  const stdout = { text: "", write(value) { this.text += value; } };
  const stderr = { text: "", write(value) { this.text += value; } };
  const readyAgent = {
    listen: async () => {},
  };
  assert.equal(await runMain({ expectedHost }, { createAgent: () => readyAgent, stdout, stderr }), 0);
  assert.equal(stdout.text, "Promptfoo fake agent ready.\n");
  assert.equal(stderr.text, "");

  stdout.text = "";
  assert.equal(await runMain({ expectedHost }, { createAgent: () => { throw new Error("sensitive"); }, stdout, stderr }), 1);
  assert.equal(stdout.text, "");
  assert.equal(stderr.text, "Promptfoo fake agent failed.\n");
  assert.doesNotMatch(stderr.text, /sensitive/);
});
