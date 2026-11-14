// Smoke test of the generated client against a local fake of the API.
//
// It checks what a generated client can get wrong without a compile error:
// the paths, the bearer header, the cursor of auto-pagination, the request
// body, and the mapping of an error status to an exception. The fake serves
// the contract-shaped responses of ../../fixtures/responses.json.
//
// Run after `npm run build`:  node --test tests/smoke.test.mjs

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { after, before, test } from "node:test";

import { ZaspClient, ZaspError } from "../dist/index.js";

const fixtures = JSON.parse(readFileSync(new URL("../../fixtures/responses.json", import.meta.url), "utf8"));
const TOKEN = fixtures.token;
const requests = [];
let server;
let baseUrl;

function send(response, status, body) {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(body));
}

before(async () => {
  server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      const url = new URL(request.url, "http://local.test");
      const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
      requests.push({ method: request.method, path: url.pathname, query: Object.fromEntries(url.searchParams), headers: request.headers, body });
      if (request.headers.authorization !== `Bearer ${TOKEN}`) return send(response, 401, fixtures.error_unauthenticated);
      if (request.method === "GET" && url.pathname === "/api/v1/agents") {
        return send(response, 200, url.searchParams.get("cursor") === fixtures.next_cursor ? fixtures.agents_page_2 : fixtures.agents_page_1);
      }
      if (request.method === "GET" && url.pathname === "/api/v1/findings") return send(response, 200, fixtures.findings_page);
      if (request.method === "POST" && url.pathname === "/api/v1/guardrails/decisions") return send(response, 200, fixtures.guardrail_decision);
      return send(response, 404, fixtures.error_not_found);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test("lists agents across pages with the bearer token and the cursor", async () => {
  requests.length = 0;
  const client = new ZaspClient({ baseUrl, token: TOKEN });
  const names = [];
  for await (const agent of await client.agents.list({ limit: 1 })) names.push(agent.name);
  assert.deepEqual(names, ["support-copilot", "claims-triage-handler"]);
  assert.equal(requests.length, 2);
  assert.equal(requests[0].path, "/api/v1/agents");
  assert.equal(requests[0].headers.authorization, `Bearer ${TOKEN}`);
  assert.equal(requests[0].query.limit, "1");
  assert.equal(requests[0].query.cursor, undefined);
  assert.equal(requests[1].query.cursor, fixtures.next_cursor);
});

test("lists findings", async () => {
  requests.length = 0;
  const client = new ZaspClient({ baseUrl, token: TOKEN });
  const page = await client.findings.list();
  assert.equal(page.data.length, 1);
  assert.equal(page.data[0].severity, "critical");
  assert.equal(page.data[0].rule, "agent_guardrail_missing");
  assert.equal(page.hasNextPage(), false);
  assert.equal(requests[0].path, "/api/v1/findings");
});

test("creates a guardrail decision", async () => {
  requests.length = 0;
  const client = new ZaspClient({ baseUrl, token: TOKEN });
  const decision = await client.guardrails.createDecision(fixtures.guardrail_request);
  assert.equal(decision.decision, "redact");
  assert.equal(decision.redacted_text, fixtures.guardrail_decision.redacted_text);
  assert.equal(decision.matched_rules[0].id, "pii.email");
  assert.equal(requests[0].method, "POST");
  assert.equal(requests[0].path, "/api/v1/guardrails/decisions");
  assert.deepEqual(requests[0].body, fixtures.guardrail_request);
});

test("raises the product error of a refused request", async () => {
  const client = new ZaspClient({ baseUrl, token: "wrong", maxRetries: 0 });
  await assert.rejects(client.findings.list(), (error) => {
    assert.ok(error instanceof ZaspError);
    assert.equal(error.statusCode, 401);
    assert.equal(error.body.code, "unauthenticated");
    return true;
  });
});
