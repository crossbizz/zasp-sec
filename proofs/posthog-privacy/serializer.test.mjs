import assert from "node:assert/strict";
import test from "node:test";

import {
  exactAnalyticsInput,
  exactCaptureDocument,
  parseStrictJson,
  serializeAnalyticsEvent,
  validateCaptureDocument,
} from "./serializer.mjs";

const expectedBytes = Buffer.from(
  '{"api_key":"phc_zasp_m020_synthetic_test_only","event":"proof_completed","properties":{"distinct_id":"org_aaaaaaaaaaaaaaaa:analytics","$process_person_profile":false,"organization_scope":"org_aaaaaaaaaaaaaaaa","environment":"test","source":"m0-20","success":true}}',
);

test("serializer constructs the exact deterministic allowlisted capture", () => {
  const input = { ...exactAnalyticsInput };
  const bytes = serializeAnalyticsEvent(input);

  assert.deepEqual(bytes, expectedBytes);
  assert.deepEqual(parseStrictJson(bytes), exactCaptureDocument);
  assert.deepEqual(validateCaptureDocument(parseStrictJson(bytes)), exactCaptureDocument);
  assert.deepEqual(input, exactAnalyticsInput);
});

test("serializer rejects each prohibited and unknown property before coercion", () => {
  const prohibited = ["prompt", "secret", "ip", "ipAddress", "rawEvidence", "raw_evidence", "evidence", "context"];
  for (const key of prohibited) {
    let reads = 0;
    const input = { ...exactAnalyticsInput };
    Object.defineProperty(input, key, {
      enumerable: true,
      get() {
        reads += 1;
        return `seeded-${key}`;
      },
    });
    assert.throws(() => serializeAnalyticsEvent(input), { name: "TypeError" }, key);
    assert.equal(reads, 0, key);
  }

  const symbolInput = { ...exactAnalyticsInput, [Symbol("secret")]: "seeded" };
  assert.throws(() => serializeAnalyticsEvent(symbolInput), { name: "TypeError" });
  const hiddenInput = { ...exactAnalyticsInput };
  Object.defineProperty(hiddenInput, "secret", { value: "seeded", enumerable: false });
  assert.throws(() => serializeAnalyticsEvent(hiddenInput), { name: "TypeError" });
});

test("serializer rejects non-plain hostile values and every field drift", () => {
  for (const value of [null, undefined, true, 1, "event", [], new Date(), Object.create(null)]) {
    assert.throws(() => serializeAnalyticsEvent(value), { name: "TypeError" });
  }

  for (const [key, value] of [
    ["event", "prompt_seen"],
    ["organizationScope", "org_bbbbbbbbbbbbbbbb"],
    ["environment", "production"],
    ["source", "browser"],
    ["success", false],
    ["success", 1],
  ]) {
    assert.throws(() => serializeAnalyticsEvent({ ...exactAnalyticsInput, [key]: value }), { name: "TypeError" }, key);
  }

  const accessor = { ...exactAnalyticsInput };
  Object.defineProperty(accessor, "event", { enumerable: true, get: () => "proof_completed" });
  assert.throws(() => serializeAnalyticsEvent(accessor), { name: "TypeError" });

  const inherited = Object.create({ secret: "seeded" });
  Object.assign(inherited, exactAnalyticsInput);
  assert.throws(() => serializeAnalyticsEvent(inherited), { name: "TypeError" });

  let traps = 0;
  const proxy = new Proxy({ ...exactAnalyticsInput }, {
    getPrototypeOf() { traps += 1; return Object.prototype; },
    ownKeys() { traps += 1; return Reflect.ownKeys(exactAnalyticsInput); },
  });
  assert.throws(() => serializeAnalyticsEvent(proxy), { name: "TypeError" });
  assert.equal(traps, 0);
});

test("strict JSON parser rejects duplicate keys malformed UTF-8 trailing data and bounds", () => {
  const cases = [
    Buffer.from('{"event":"proof_completed","event":"other"}'),
    Buffer.from('{"properties":{"success":true,"success":false}}'),
    Buffer.from('{"event":}'),
    Buffer.from('{"event":"proof_completed"} trailing'),
    Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]),
    Buffer.alloc(16_385, 0x20),
  ];
  for (const bytes of cases) assert.throws(() => parseStrictJson(bytes), { name: "TypeError" });
});

test("capture validator rejects aliases extras prototypes and primitive confusion", () => {
  assert.deepEqual(validateCaptureDocument(structuredClone(exactCaptureDocument)), exactCaptureDocument);
  for (const mutate of [
    (value) => { value.prompt = "seeded"; },
    (value) => { value.apiKey = value.api_key; },
    (value) => { value.properties.ip = "203.0.113.10"; },
    (value) => { value.properties.success = 1; },
    (value) => { value.properties.$process_person_profile = true; },
    (value) => { value.properties.distinct_id = "person@example.test"; },
  ]) {
    const document = structuredClone(exactCaptureDocument);
    mutate(document);
    assert.throws(() => validateCaptureDocument(document), { name: "TypeError" });
  }
});
