import { TextDecoder } from "node:util";
import { types } from "node:util";

const maximumJsonBytes = 16_384;
const expectedInputKeys = ["environment", "event", "organizationScope", "source", "success"];
const expectedCaptureKeys = ["api_key", "event", "properties"];
const expectedPropertyKeys = [
  "$process_person_profile",
  "distinct_id",
  "environment",
  "organization_scope",
  "source",
  "success",
];

export const exactAnalyticsInput = Object.freeze({
  event: "proof_completed",
  organizationScope: "org_aaaaaaaaaaaaaaaa",
  environment: "test",
  source: "m0-20",
  success: true,
});

export const exactCaptureDocument = Object.freeze({
  api_key: "phc_zasp_m020_synthetic_test_only",
  event: "proof_completed",
  properties: Object.freeze({
    distinct_id: "org_aaaaaaaaaaaaaaaa:analytics",
    $process_person_profile: false,
    organization_scope: "org_aaaaaaaaaaaaaaaa",
    environment: "test",
    source: "m0-20",
    success: true,
  }),
});

export function serializeAnalyticsEvent(input) {
  const values = exactOwnDataValues(input, expectedInputKeys);
  requireExact(values.event, exactAnalyticsInput.event);
  requireExact(values.organizationScope, exactAnalyticsInput.organizationScope);
  requireExact(values.environment, exactAnalyticsInput.environment);
  requireExact(values.source, exactAnalyticsInput.source);
  requireExact(values.success, exactAnalyticsInput.success);
  return Buffer.from(JSON.stringify(exactCaptureDocument));
}

export function validateCaptureDocument(document) {
  const root = exactOwnDataValues(document, expectedCaptureKeys, true);
  const properties = exactOwnDataValues(root.properties, expectedPropertyKeys, true);
  requireExact(root.api_key, exactCaptureDocument.api_key);
  requireExact(root.event, exactCaptureDocument.event);
  for (const key of expectedPropertyKeys) requireExact(properties[key], exactCaptureDocument.properties[key]);
  return structuredClone(exactCaptureDocument);
}

export function parseStrictJson(bytes, maximumBytes = maximumJsonBytes) {
  if (!Buffer.isBuffer(bytes) || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || bytes.byteLength > maximumBytes) {
    throw new TypeError("invalid JSON");
  }
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new TypeError("invalid JSON");
  }
  try {
    return parseUniqueJson(source);
  } catch {
    throw new TypeError("invalid JSON");
  }
}

function exactOwnDataValues(value, expectedKeys, permitNullPrototype = false) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError("invalid object");
  if (types.isProxy(value)) throw new TypeError("invalid proxy");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && !(permitNullPrototype && prototype === null)) throw new TypeError("invalid prototype");
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string") || !sameStringSet(keys, expectedKeys)) throw new TypeError("invalid keys");
  const output = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.get || descriptor.set || !descriptor.enumerable) {
      throw new TypeError("invalid property");
    }
    output[key] = descriptor.value;
  }
  return output;
}

function sameStringSet(actual, expected) {
  if (actual.length !== expected.length) return false;
  const sorted = [...actual].sort();
  const wanted = [...expected].sort();
  return sorted.every((key, index) => key === wanted[index]);
}

function requireExact(actual, expected) {
  if (typeof actual !== typeof expected || !Object.is(actual, expected)) throw new TypeError("invalid value");
}

function parseUniqueJson(source) {
  if (typeof source !== "string" || Buffer.byteLength(source) > maximumJsonBytes) throw new SyntaxError("invalid JSON");
  let index = 0;
  const whitespace = () => { while (index < source.length && /[\t\n\r ]/.test(source[index])) index += 1; };
  const string = () => {
    if (source[index] !== '"') throw new SyntaxError("invalid JSON");
    const start = index++;
    while (index < source.length) {
      const character = source[index];
      if (character === '"') { index += 1; return JSON.parse(source.slice(start, index)); }
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError("invalid JSON");
      if (character !== "\\") { index += 1; continue; }
      index += 1;
      const escape = source[index];
      if ('"\\/bfnrt'.includes(escape ?? "")) index += 1;
      else if (escape === "u" && /^[a-fA-F0-9]{4}$/.test(source.slice(index + 1, index + 5))) index += 5;
      else throw new SyntaxError("invalid JSON");
    }
    throw new SyntaxError("invalid JSON");
  };
  const value = (depth) => {
    if (depth > 8) throw new SyntaxError("invalid JSON");
    whitespace();
    if (source[index] === "{") {
      index += 1; whitespace();
      const output = {};
      const keys = new Set();
      if (source[index] === "}") { index += 1; return output; }
      while (true) {
        const key = string();
        if (keys.has(key)) throw new SyntaxError("duplicate JSON key");
        keys.add(key); whitespace();
        if (source[index++] !== ":") throw new SyntaxError("invalid JSON");
        Object.defineProperty(output, key, { value: value(depth + 1), enumerable: true, configurable: true, writable: true });
        whitespace();
        if (source[index] === "}") { index += 1; return output; }
        if (source[index++] !== ",") throw new SyntaxError("invalid JSON");
        whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1; whitespace();
      const output = [];
      if (source[index] === "]") { index += 1; return output; }
      while (true) {
        output.push(value(depth + 1));
        if (output.length > 64) throw new SyntaxError("invalid JSON");
        whitespace();
        if (source[index] === "]") { index += 1; return output; }
        if (source[index++] !== ",") throw new SyntaxError("invalid JSON");
        whitespace();
      }
    }
    if (source[index] === '"') return string();
    for (const [literal, parsed] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, index)) { index += literal.length; return parsed; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(index));
    if (!number) throw new SyntaxError("invalid JSON");
    index += number[0].length;
    const parsed = Number(number[0]);
    if (!Number.isFinite(parsed)) throw new SyntaxError("invalid JSON");
    return parsed;
  };
  const output = value(0);
  whitespace();
  if (index !== source.length) throw new SyntaxError("invalid JSON");
  return output;
}
