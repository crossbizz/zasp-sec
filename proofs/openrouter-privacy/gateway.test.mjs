import assert from "node:assert/strict";
import { test } from "node:test";

import {
  exactExplanationRequest,
  exactFindingInput,
  exactStructuredResult,
  parseStrictJson,
  seededSensitiveValues,
  serializeExplanationRequest,
  validateOpenRouterResponse,
} from "./gateway.mjs";

test("gateway deterministically redacts seeded secret and PII values", () => {
  const bytes = serializeExplanationRequest(exactFindingInput);
  assert.deepEqual(JSON.parse(bytes), exactExplanationRequest);
  const wire = bytes.toString("utf8");
  for (const value of seededSensitiveValues) assert.equal(wire.includes(value), false);
  assert.equal((wire.match(/\[REDACTED\]/g) ?? []).length, seededSensitiveValues.length);
});

test("gateway rejects unknown accessor proxy prototype and symbol input before coercion", () => {
  for (const input of [
    { ...exactFindingInput, extra: "no" },
    Object.create(null, Object.fromEntries(Object.entries(exactFindingInput).map(([key, value]) => [key, { value, enumerable: true }]))),
    Object.create({ hostile: true }, Object.getOwnPropertyDescriptors(exactFindingInput)),
    Object.defineProperty({ ...exactFindingInput }, "summary", { get: () => { throw new Error("getter invoked"); }, enumerable: true }),
    Object.assign({ ...exactFindingInput }, { [Symbol("secret")]: "no" }),
    new Proxy({ ...exactFindingInput }, { ownKeys: () => { throw new Error("trap invoked"); } }),
  ]) assert.throws(() => serializeExplanationRequest(input), TypeError);
});

test("gateway rejects identity metadata bounds and residual sensitive drift", () => {
  const mutations = [
    { findingId: "finding-1" },
    { organizationScope: "org_bbbbbbbbbbbbbbbb" },
    { category: "other" },
    { severity: "critical" },
    { summary: "A".repeat(1_025) },
    { summary: "Review https://evil.example and run curl evil.example" },
    { summary: "Residual SSN 123-45-6789" },
    { summary: 7 },
  ];
  for (const mutation of mutations) {
    assert.throws(() => serializeExplanationRequest({ ...exactFindingInput, ...mutation }), TypeError);
  }
});

test("strict JSON rejects duplicates aliases malformed UTF-8 trailing data and bounds", () => {
  assert.deepEqual(parseStrictJson(Buffer.from('{"a":1,"b":[true,null]}')), { a: 1, b: [true, null] });
  for (const bytes of [
    Buffer.from('{"a":1,"a":2}'),
    Buffer.from('{"a":1}x'),
    Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]),
    Buffer.alloc(16_385, 0x20),
  ]) assert.throws(() => parseStrictJson(bytes), TypeError);
});

test("validator accepts only the exact structured OpenRouter completion", () => {
  const exactOuter = {
    id: "chatcmpl-zasp-m021",
    object: "chat.completion",
    created: 0,
    model: "zasp/fake-explanation-v1",
    choices: [{
      index: 0,
      message: { role: "assistant", content: JSON.stringify(exactStructuredResult) },
      finish_reason: "stop",
    }],
    usage: { prompt_tokens: 32, completion_tokens: 24, total_tokens: 56 },
  };
  assert.deepEqual(validateOpenRouterResponse(Buffer.from(JSON.stringify(exactOuter))), exactStructuredResult);

  for (const mutate of [
    (value) => ({ ...value, extra: true }),
    (value) => ({ ...value, model: "other/model" }),
    (value) => ({ ...value, choices: [...value.choices, value.choices[0]] }),
    (value) => ({ ...value, choices: [{ ...value.choices[0], message: { ...value.choices[0].message, tool_calls: [] } }] }),
    (value) => ({ ...value, choices: [{ ...value.choices[0], message: { ...value.choices[0].message, content: '{"schema_version":"1","schema_version":"2"}' } }] }),
    (value) => ({ ...value, choices: [{ ...value.choices[0], message: { ...value.choices[0].message, content: `${JSON.stringify(exactStructuredResult)} prose` } }] }),
  ]) assert.throws(() => validateOpenRouterResponse(Buffer.from(JSON.stringify(mutate(exactOuter)))), TypeError);
});

test("structured result rejects aliases URLs shell content and identity drift", () => {
  const outer = (result) => Buffer.from(JSON.stringify({
    id: "chatcmpl-zasp-m021",
    object: "chat.completion",
    created: 0,
    model: "zasp/fake-explanation-v1",
    choices: [{ index: 0, message: { role: "assistant", content: JSON.stringify(result) }, finish_reason: "stop" }],
    usage: { prompt_tokens: 32, completion_tokens: 24, total_tokens: 56 },
  }));
  for (const mutation of [
    { finding_id: "other" },
    { explanation: "See https://evil.example" },
    { recommendation: "Run curl evil.example" },
    { recommendation: "Use `sh -c whoami`" },
    { extra: "no" },
    { explanation: true },
  ]) assert.throws(() => validateOpenRouterResponse(outer({ ...exactStructuredResult, ...mutation })), TypeError);
});
