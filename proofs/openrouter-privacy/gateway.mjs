import { TextDecoder, types } from "node:util";

const maximumJsonBytes = 16_384;
const inputKeys = ["category", "findingId", "organizationScope", "severity", "summary"];
const requestKeys = ["max_tokens", "messages", "model", "response_format", "stream", "temperature"];
const outerKeys = ["choices", "created", "id", "model", "object", "usage"];
const resultKeys = ["explanation", "finding_id", "recommendation", "schema_version"];

export const seededSensitiveValues = Object.freeze([
  "sk-zasp-m021-secret-value",
  "Alice Example",
  "alice@example.test",
  "+1-415-555-0199",
  "raw-evidence-zasp-m021",
]);

export const exactFindingInput = Object.freeze({
  findingId: "org_aaaaaaaaaaaaaaaa:finding:openrouter-privacy",
  organizationScope: "org_aaaaaaaaaaaaaaaa",
  category: "identity",
  severity: "high",
  summary:
    "Identity credential sk-zasp-m021-secret-value belongs to Alice Example at alice@example.test or +1-415-555-0199. Evidence raw-evidence-zasp-m021.",
});

export const exactStructuredResult = Object.freeze({
  schema_version: "1",
  finding_id: exactFindingInput.findingId,
  explanation: "The high-severity identity finding requires review.",
  recommendation: "Review the affected identity through approved product workflows.",
});

const exactSafeFinding = Object.freeze({
  category: "identity",
  finding_id: exactFindingInput.findingId,
  organization_scope: exactFindingInput.organizationScope,
  severity: "high",
  summary: "Identity credential [REDACTED] belongs to [REDACTED] at [REDACTED] or [REDACTED]. Evidence [REDACTED].",
});

export const exactExplanationRequest = deepFreeze({
  model: "zasp/fake-explanation-v1",
  messages: [
    {
      role: "system",
      content: "Return only the required JSON explanation for the supplied redacted finding metadata.",
    },
    { role: "user", content: JSON.stringify(exactSafeFinding) },
  ],
  response_format: {
    type: "json_schema",
    json_schema: {
      name: "zasp_finding_explanation",
      strict: true,
      schema: {
        type: "object",
        additionalProperties: false,
        required: ["schema_version", "finding_id", "explanation", "recommendation"],
        properties: {
          schema_version: { type: "string", const: "1" },
          finding_id: { type: "string", const: exactFindingInput.findingId },
          explanation: { type: "string", maxLength: 256 },
          recommendation: { type: "string", maxLength: 256 },
        },
      },
    },
  },
  max_tokens: 128,
  temperature: 0,
  stream: false,
});

export function serializeExplanationRequest(input) {
  const values = exactOwnDataValues(input, inputKeys);
  requireExact(values.findingId, exactFindingInput.findingId);
  requireExact(values.organizationScope, exactFindingInput.organizationScope);
  requireExact(values.category, exactFindingInput.category);
  requireExact(values.severity, exactFindingInput.severity);
  if (typeof values.summary !== "string" || values.summary.length < 1 || values.summary.length > 1_024 ||
      [...values.summary].some((character) => character.charCodeAt(0) <= 0x1f || character.charCodeAt(0) === 0x7f)) {
    throw new TypeError("invalid summary");
  }

  let summary = values.summary;
  for (const sensitive of seededSensitiveValues) summary = summary.split(sensitive).join("[REDACTED]");
  if (summary !== exactSafeFinding.summary || hasProhibitedMaterial(summary)) throw new TypeError("invalid redaction");
  const body = Buffer.from(JSON.stringify(exactExplanationRequest));
  if (body.byteLength > maximumJsonBytes || seededSensitiveValues.some((value) => body.includes(Buffer.from(value)))) {
    throw new TypeError("invalid request");
  }
  return body;
}

export function validateExplanationRequest(document) {
  exactOwnDataValues(document, requestKeys);
  const canonical = Buffer.from(JSON.stringify(document));
  const exact = Buffer.from(JSON.stringify(exactExplanationRequest));
  if (!canonical.equals(exact)) throw new TypeError("invalid request");
  for (const value of seededSensitiveValues) if (canonical.includes(Buffer.from(value))) throw new TypeError("invalid request");
  return structuredClone(exactExplanationRequest);
}

export function validateOpenRouterResponse(bytes) {
  const outer = exactOwnDataValues(parseStrictJson(bytes, 8_192), outerKeys);
  requireExact(outer.id, "chatcmpl-zasp-m021");
  requireExact(outer.object, "chat.completion");
  requireExact(outer.created, 0);
  requireExact(outer.model, "zasp/fake-explanation-v1");
  if (!Array.isArray(outer.choices) || outer.choices.length !== 1) throw new TypeError("invalid choices");
  const choice = exactOwnDataValues(outer.choices[0], ["finish_reason", "index", "message"]);
  requireExact(choice.index, 0);
  requireExact(choice.finish_reason, "stop");
  const message = exactOwnDataValues(choice.message, ["content", "role"]);
  requireExact(message.role, "assistant");
  if (typeof message.content !== "string" || Buffer.byteLength(message.content) > 4_096) throw new TypeError("invalid content");
  const result = exactOwnDataValues(parseStrictJson(Buffer.from(message.content), 4_096), resultKeys);
  for (const [key, value] of Object.entries(exactStructuredResult)) requireExact(result[key], value);
  if (hasProhibitedMaterial(result.explanation) || hasProhibitedMaterial(result.recommendation)) {
    throw new TypeError("invalid content");
  }
  const usage = exactOwnDataValues(outer.usage, ["completion_tokens", "prompt_tokens", "total_tokens"]);
  requireExact(usage.prompt_tokens, 32);
  requireExact(usage.completion_tokens, 24);
  requireExact(usage.total_tokens, 56);
  return structuredClone(exactStructuredResult);
}

export function parseStrictJson(bytes, maximumBytes = maximumJsonBytes) {
  if (!Buffer.isBuffer(bytes) || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 ||
      maximumBytes > maximumJsonBytes || bytes.byteLength > maximumBytes) throw new TypeError("invalid JSON");
  let source;
  try { source = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new TypeError("invalid JSON"); }
  try { return parseUniqueJson(source); }
  catch { throw new TypeError("invalid JSON"); }
}

function hasProhibitedMaterial(value) {
  if (typeof value !== "string") return true;
  const lower = value.toLowerCase();
  return seededSensitiveValues.some((sensitive) => lower.includes(sensitive.toLowerCase())) ||
    /(?:https?:\/\/|\bcurl\b|\bwget\b|\bsh\s+-c\b|`)/iu.test(value) ||
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu.test(value) ||
    /\b\d{3}-\d{2}-\d{4}\b/u.test(value) ||
    /(?:\+?1[- .]?)?\d{3}[- .]\d{3}[- .]\d{4}/u.test(value) ||
    /\b(?:sk|api|token)[-_][A-Za-z0-9._-]{8,}\b/u.test(value);
}

function exactOwnDataValues(value, expectedKeys) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError("invalid object");
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string") || !sameStringSet(keys, expectedKeys)) throw new TypeError("invalid keys");
  const output = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value") || !descriptor.enumerable || descriptor.get || descriptor.set) {
      throw new TypeError("invalid property");
    }
    output[key] = descriptor.value;
  }
  return output;
}

function sameStringSet(actual, expected) {
  return actual.length === expected.length && [...actual].sort().every((key, index) => key === [...expected].sort()[index]);
}

function requireExact(actual, expected) {
  if (typeof actual !== typeof expected || !Object.is(actual, expected)) throw new TypeError("invalid value");
}

function deepFreeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function parseUniqueJson(source) {
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
    if (depth > 12) throw new SyntaxError("invalid JSON");
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
