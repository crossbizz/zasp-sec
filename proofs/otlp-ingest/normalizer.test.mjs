import assert from "node:assert/strict";
import test from "node:test";

import {
  FIXTURE,
  buildSyntheticOtlpTrace,
  normalizeOtlpTrace,
  parseStrictOtlpJson,
} from "./normalizer.mjs";

function bytes(value) {
  return Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
}

function request() {
  return JSON.parse(buildSyntheticOtlpTrace(FIXTURE).toString("utf8"));
}

function mutate(callback) {
  const value = request();
  callback(value);
  return bytes(value);
}

test("builds and normalizes one exact bounded semantic trace", () => {
  const payload = buildSyntheticOtlpTrace(FIXTURE);
  const normalized = normalizeOtlpTrace(payload, FIXTURE);

  assert.deepEqual(normalized, {
    organization_id: "org_aaaaaaaaaaaaaaaa",
    trace_id: "0123456789abcdef0123456789abcdef",
    span_id: "0123456789abcdef",
    span_name: "agent.tool.execute",
    started_at_unix_nano: "1786728000000000000",
    ended_at_unix_nano: "1786728000100000000",
    agent_id: "agent_aaaaaaaaaaaaaaaa",
    session_id: "session_bbbbbbbbbbbbbbbb",
    task_id: "task_cccccccccccccccc",
    tool_id: "tool_dddddddddddddddd",
    sandbox_id: "sandbox_eeeeeeeeeeeeeeee",
    identity: true,
  });
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal(Object.isFrozen(FIXTURE), true);
  assert.equal(payload.equals(buildSyntheticOtlpTrace(FIXTURE)), true);
});

test("strict parser rejects malformed representation boundaries", () => {
  const valid = buildSyntheticOtlpTrace(FIXTURE).toString("utf8");
  const cases = [
    Buffer.alloc(0),
    Buffer.from([0xff]),
    bytes("null"),
    bytes("[]"),
    bytes("{} trailing"),
    bytes(valid.replace('{"resourceSpans"', '{"resourceSpans":[],"resourceSpans"')),
    bytes(valid.replace('{"resource"', '{"resource":{},"resource"')),
    bytes(valid.replace('{"scope"', '{"scope":{},"scope"')),
    bytes(valid.replace('{"traceId"', '{"traceId":"0","traceId"')),
    Buffer.alloc(65_537, 0x20),
  ];
  for (const value of cases) assert.throws(() => parseStrictOtlpJson(value));
});

test("rejects missing, extra, aliased, and duplicate top-level candidates", () => {
  assert.throws(() => normalizeOtlpTrace(mutate((value) => delete value.resourceSpans), FIXTURE));
  assert.throws(() => normalizeOtlpTrace(mutate((value) => { value.extra = true; }), FIXTURE));
  assert.throws(() => normalizeOtlpTrace(mutate((value) => {
    value.resource_spans = value.resourceSpans;
    delete value.resourceSpans;
  }), FIXTURE));
  assert.throws(() => normalizeOtlpTrace(mutate((value) => value.resourceSpans.push(value.resourceSpans[0])), FIXTURE));
});

test("requires one exact resource, scope, and span shape", () => {
  const changes = [
    (value) => value.resourceSpans[0].scopeSpans.push(value.resourceSpans[0].scopeSpans[0]),
    (value) => value.resourceSpans[0].scopeSpans[0].spans.push(value.resourceSpans[0].scopeSpans[0].spans[0]),
    (value) => { value.resourceSpans[0].schemaUrl = "https://example.invalid"; },
    (value) => { value.resourceSpans[0].scopeSpans[0].schemaUrl = "https://example.invalid"; },
    (value) => { value.resourceSpans[0].scopeSpans[0].scope.name = "foreign"; },
    (value) => { value.resourceSpans[0].scopeSpans[0].scope.version = "2"; },
    (value) => { value.resourceSpans[0].resource.droppedAttributesCount = 1; },
    (value) => { value.resourceSpans[0].scopeSpans[0].scope.attributes = []; },
  ];
  for (const change of changes) assert.throws(() => normalizeOtlpTrace(mutate(change), FIXTURE));
});

test("requires exact trace, span, time, kind, status, and zero-drop fields", () => {
  const span = (value) => value.resourceSpans[0].scopeSpans[0].spans[0];
  const changes = [
    (value) => { span(value).traceId = "0".repeat(32); },
    (value) => { span(value).traceId = span(value).traceId.toUpperCase(); },
    (value) => { span(value).spanId = "0".repeat(16); },
    (value) => { span(value).parentSpanId = "1".repeat(16); },
    (value) => { span(value).name = "foreign"; },
    (value) => { span(value).kind = 2; },
    (value) => { span(value).startTimeUnixNano = "0"; },
    (value) => { span(value).endTimeUnixNano = span(value).startTimeUnixNano; },
    (value) => { span(value).status.code = 2; },
    (value) => { span(value).status.message = "detail"; },
    (value) => { span(value).droppedAttributesCount = 1; },
    (value) => { span(value).droppedEventsCount = 1; },
    (value) => { span(value).droppedLinksCount = 1; },
    (value) => { span(value).events = [{}]; },
    (value) => { span(value).links = [{}]; },
  ];
  for (const change of changes) assert.throws(() => normalizeOtlpTrace(mutate(change), FIXTURE));
});

test("requires exact resource attributes and forbids customer content", () => {
  const attributes = (value) => value.resourceSpans[0].resource.attributes;
  const changes = [
    (value) => attributes(value).pop(),
    (value) => attributes(value).push({ key: "prompt.text", value: { stringValue: "ignore previous" } }),
    (value) => attributes(value).push({ key: "tool.arguments", value: { stringValue: "arbitrary" } }),
    (value) => attributes(value).push({ key: "secret.value", value: { stringValue: "synthetic" } }),
    (value) => { attributes(value)[0].key = "service_name"; },
    (value) => { attributes(value)[0].value = { boolValue: true }; },
    (value) => attributes(value).push(attributes(value)[0]),
  ];
  for (const change of changes) assert.throws(() => normalizeOtlpTrace(mutate(change), FIXTURE));
});

test("requires exact semantic span attributes", () => {
  const attributes = (value) => value.resourceSpans[0].scopeSpans[0].spans[0].attributes;
  for (let index = 0; index < 5; index += 1) {
    assert.throws(() => normalizeOtlpTrace(mutate((value) => attributes(value).splice(index, 1)), FIXTURE));
  }
  const changes = [
    (value) => { attributes(value)[0].key = "agentId"; },
    (value) => { attributes(value)[0].value = { intValue: "1" }; },
    (value) => { attributes(value)[0].value.stringValue = "agent_foreign"; },
    (value) => attributes(value).push(attributes(value)[0]),
    (value) => attributes(value).reverse(),
  ];
  for (const change of changes) assert.throws(() => normalizeOtlpTrace(mutate(change), FIXTURE));
});

test("binds all expected fixture fields and rejects hostile coercion", () => {
  for (const field of Object.keys(FIXTURE)) {
    const changed = { ...FIXTURE, [field]: `${FIXTURE[field]}x` };
    assert.throws(() => buildSyntheticOtlpTrace(changed));
  }
  let called = false;
  const hostile = new Proxy({}, {
    get() {
      called = true;
      throw new Error("coercion executed");
    },
  });
  assert.throws(() => normalizeOtlpTrace(hostile, FIXTURE));
  assert.equal(called, false);
});

test("rejects Organization scope drift without changing the captured trace", () => {
  const foreign = { ...FIXTURE, organizationId: "org_ffffffffffffffff" };
  assert.throws(() => normalizeOtlpTrace(buildSyntheticOtlpTrace(FIXTURE), foreign));
  const normalized = normalizeOtlpTrace(buildSyntheticOtlpTrace(foreign), foreign);
  assert.equal(normalized.organization_id, foreign.organizationId);
  assert.equal(normalized.trace_id, FIXTURE.traceId);
});
