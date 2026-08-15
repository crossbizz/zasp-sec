const limits = Object.freeze({
  maximumBytes: 65_536,
  maximumDepth: 24,
  maximumStringLength: 1_024,
  maximumCollectionSize: 32,
});

const organizationPattern = /^org_[a-z0-9]{16}$/;
const semanticPatterns = Object.freeze({
  agentId: /^agent_[a-z0-9]{16}$/,
  sessionId: /^session_[a-z0-9]{16}$/,
  taskId: /^task_[a-z0-9]{16}$/,
  toolId: /^tool_[a-z0-9]{16}$/,
  sandboxId: /^sandbox_[a-z0-9]{16}$/,
});
const traceIdPattern = /^(?!0{32})[0-9a-f]{32}$/;
const spanIdPattern = /^(?!0{16})[0-9a-f]{16}$/;
const nanosPattern = /^(?:[1-9][0-9]{0,18})$/;

export const FIXTURE = Object.freeze({
  organizationId: "org_aaaaaaaaaaaaaaaa",
  agentId: "agent_aaaaaaaaaaaaaaaa",
  sessionId: "session_bbbbbbbbbbbbbbbb",
  taskId: "task_cccccccccccccccc",
  toolId: "tool_dddddddddddddddd",
  sandboxId: "sandbox_eeeeeeeeeeeeeeee",
  traceId: "0123456789abcdef0123456789abcdef",
  spanId: "0123456789abcdef",
  startTimeUnixNano: "1786728000000000000",
  endTimeUnixNano: "1786728000100000000",
});

const resourceAttributes = Object.freeze([
  ["service.name", "zasp.proof.agent"],
  ["service.version", "1"],
  ["organization.id", "organizationId"],
]);
const spanAttributes = Object.freeze([
  ["agent.id", "agentId"],
  ["session.id", "sessionId"],
  ["task.id", "taskId"],
  ["tool.id", "toolId"],
  ["sandbox.id", "sandboxId"],
]);

export function buildSyntheticOtlpTrace(input) {
  const specification = validateFixture(input);
  const document = {
    resourceSpans: [{
      resource: {
        attributes: resourceAttributes.map(([key, value]) => attribute(
          key,
          value === "organizationId" ? specification.organizationId : value,
        )),
        droppedAttributesCount: 0,
      },
      scopeSpans: [{
        scope: { name: "zasp.m0-13.proof", version: "1" },
        spans: [{
          traceId: specification.traceId,
          spanId: specification.spanId,
          traceState: "",
          flags: 1,
          name: "agent.tool.execute",
          kind: 3,
          startTimeUnixNano: specification.startTimeUnixNano,
          endTimeUnixNano: specification.endTimeUnixNano,
          attributes: spanAttributes.map(([key, field]) => attribute(key, specification[field])),
          droppedAttributesCount: 0,
          events: [],
          droppedEventsCount: 0,
          links: [],
          droppedLinksCount: 0,
          status: { code: 1 },
        }],
      }],
    }],
  };
  return Buffer.from(JSON.stringify(document));
}

export function parseStrictOtlpJson(bytes) {
  const source = decodeBytes(bytes);
  let parsed;
  try {
    parsed = parseUniqueJson(source);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "invalid JSON";
    throw new TypeError(`OTLP artifact is not strict JSON: ${reason}`);
  }
  expectObject(parsed, "OTLP artifact");
  return parsed;
}

export function normalizeOtlpTrace(bytes, input) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("OTLP artifact must be bytes");
  const specification = validateFixture(input);
  const document = parseStrictOtlpJson(bytes);
  expectKeys(document, ["resourceSpans"], "OTLP artifact");
  const resourceSpan = exactOne(document.resourceSpans, "resource spans");
  expectObject(resourceSpan, "resource span");
  expectKeys(resourceSpan, ["resource", "scopeSpans"], "resource span");

  const resource = resourceSpan.resource;
  expectObject(resource, "resource");
  expectKeys(resource, ["attributes", "droppedAttributesCount"], "resource");
  expectZeroInteger(resource.droppedAttributesCount, "resource dropped attributes");
  validateAttributes(resource.attributes, resourceAttributes.map(([key, value]) => [
    key,
    value === "organizationId" ? specification.organizationId : value,
  ]), "resource");

  const scopeSpan = exactOne(resourceSpan.scopeSpans, "scope spans");
  expectObject(scopeSpan, "scope span");
  expectKeys(scopeSpan, ["scope", "spans"], "scope span");
  expectObject(scopeSpan.scope, "scope");
  expectKeys(scopeSpan.scope, ["name", "version"], "scope");
  if (scopeSpan.scope.name !== "zasp.m0-13.proof" || scopeSpan.scope.version !== "1") {
    throw new TypeError("scope identity is invalid");
  }

  const span = exactOne(scopeSpan.spans, "spans");
  expectObject(span, "span");
  expectKeys(span, [
    "attributes", "droppedAttributesCount", "droppedEventsCount",
    "droppedLinksCount", "endTimeUnixNano", "events", "flags", "kind",
    "links", "name", "spanId", "startTimeUnixNano", "status", "traceId",
    "traceState",
  ], "span");
  if (
    span.traceId !== specification.traceId || !traceIdPattern.test(span.traceId) ||
    span.spanId !== specification.spanId || !spanIdPattern.test(span.spanId) ||
    span.traceState !== "" || span.flags !== 1 || span.name !== "agent.tool.execute" ||
    span.kind !== 3
  ) {
    throw new TypeError("span identity is invalid");
  }
  validateTimes(span, specification);
  expectZeroInteger(span.droppedAttributesCount, "span dropped attributes");
  expectZeroInteger(span.droppedEventsCount, "span dropped events");
  expectZeroInteger(span.droppedLinksCount, "span dropped links");
  if (!Array.isArray(span.events) || span.events.length !== 0) throw new TypeError("span events are invalid");
  if (!Array.isArray(span.links) || span.links.length !== 0) throw new TypeError("span links are invalid");
  expectObject(span.status, "span status");
  expectKeys(span.status, ["code"], "span status");
  if (span.status.code !== 1) throw new TypeError("span status is invalid");
  validateAttributes(
    span.attributes,
    spanAttributes.map(([key, field]) => [key, specification[field]]),
    "span",
  );

  return Object.freeze({
    organization_id: specification.organizationId,
    trace_id: span.traceId,
    span_id: span.spanId,
    span_name: span.name,
    started_at_unix_nano: span.startTimeUnixNano,
    ended_at_unix_nano: span.endTimeUnixNano,
    agent_id: specification.agentId,
    session_id: specification.sessionId,
    task_id: specification.taskId,
    tool_id: specification.toolId,
    sandbox_id: specification.sandboxId,
    identity: true,
  });
}

export function normalizeCollectorOtlpTrace(bytes, input) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("Collector artifact must be bytes");
  const document = parseStrictOtlpJson(bytes);
  expectKeys(document, ["resourceSpans"], "Collector artifact");
  const resourceSpan = exactOne(document.resourceSpans, "Collector resource spans");
  expectKeys(resourceSpan, ["resource", "scopeSpans"], "Collector resource span");
  const resource = resourceSpan.resource;
  expectKeys(resource, ["attributes"], "Collector resource");
  const scopeSpan = exactOne(resourceSpan.scopeSpans, "Collector scope spans");
  expectKeys(scopeSpan, ["scope", "spans"], "Collector scope span");
  const span = exactOne(scopeSpan.spans, "Collector spans");
  expectKeys(span, [
    "attributes", "endTimeUnixNano", "flags", "kind", "name", "spanId",
    "startTimeUnixNano", "status", "traceId",
  ], "Collector span");

  resource.droppedAttributesCount = 0;
  Object.assign(span, {
    traceState: "",
    droppedAttributesCount: 0,
    events: [],
    droppedEventsCount: 0,
    links: [],
    droppedLinksCount: 0,
  });
  return normalizeOtlpTrace(Buffer.from(JSON.stringify(document)), input);
}

function attribute(key, value) {
  return { key, value: { stringValue: value } };
}

function validateFixture(input) {
  if (!isObject(input)) throw new TypeError("fixture must be a plain object");
  expectKeys(input, [
    "agentId", "endTimeUnixNano", "organizationId", "sandboxId", "sessionId",
    "spanId", "startTimeUnixNano", "taskId", "toolId", "traceId",
  ], "fixture");
  if (!organizationPattern.test(input.organizationId)) throw new TypeError("Organization ID is invalid");
  for (const [field, pattern] of Object.entries(semanticPatterns)) {
    if (!pattern.test(input[field])) throw new TypeError(`${field} is invalid`);
  }
  if (!traceIdPattern.test(input.traceId) || !spanIdPattern.test(input.spanId)) {
    throw new TypeError("trace identity is invalid");
  }
  if (
    !nanosPattern.test(input.startTimeUnixNano) ||
    !nanosPattern.test(input.endTimeUnixNano) ||
    BigInt(input.endTimeUnixNano) <= BigInt(input.startTimeUnixNano)
  ) {
    throw new TypeError("fixture time is invalid");
  }
  return { ...input };
}

function validateTimes(span, specification) {
  if (
    span.startTimeUnixNano !== specification.startTimeUnixNano ||
    span.endTimeUnixNano !== specification.endTimeUnixNano ||
    !nanosPattern.test(span.startTimeUnixNano) || !nanosPattern.test(span.endTimeUnixNano) ||
    BigInt(span.endTimeUnixNano) <= BigInt(span.startTimeUnixNano)
  ) {
    throw new TypeError("span time is invalid");
  }
}

function validateAttributes(actual, expected, context) {
  if (!Array.isArray(actual) || actual.length !== expected.length) {
    throw new TypeError(`${context} attributes are invalid`);
  }
  for (let index = 0; index < expected.length; index += 1) {
    const candidate = actual[index];
    const [key, value] = expected[index];
    expectObject(candidate, `${context} attribute`);
    expectKeys(candidate, ["key", "value"], `${context} attribute`);
    expectObject(candidate.value, `${context} attribute value`);
    expectKeys(candidate.value, ["stringValue"], `${context} attribute value`);
    if (candidate.key !== key || candidate.value.stringValue !== value) {
      throw new TypeError(`${context} attribute identity is invalid`);
    }
  }
}

function exactOne(value, context) {
  if (!Array.isArray(value) || value.length !== 1) throw new TypeError(`${context} are not exact`);
  return value[0];
}

function expectZeroInteger(value, context) {
  if (value !== 0 || !Number.isInteger(value)) throw new TypeError(`${context} are invalid`);
}

function expectKeys(value, expected, context) {
  if (!isObject(value)) throw new TypeError(`${context} must be a plain object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError(`${context} has invalid keys`);
  }
}

function expectObject(value, context) {
  if (!isObject(value)) throw new TypeError(`${context} must be a plain object`);
}

function isObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function decodeBytes(value) {
  if (!(value instanceof Uint8Array) || value.byteLength === 0 || value.byteLength > limits.maximumBytes) {
    throw new TypeError("OTLP artifact size is invalid");
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength),
    );
  } catch {
    throw new TypeError("OTLP artifact is not valid UTF-8");
  }
}

function parseUniqueJson(source) {
  let index = 0;
  const whitespace = () => {
    while (index < source.length && /[\t\n\r ]/.test(source[index])) index += 1;
  };
  const parseString = () => {
    if (source[index] !== '"') throw new SyntaxError("invalid string");
    const start = index;
    index += 1;
    while (index < source.length) {
      const character = source[index];
      if (character === '"') {
        index += 1;
        const value = JSON.parse(source.slice(start, index));
        if (value.length > limits.maximumStringLength || hasUnpairedSurrogate(value)) {
          throw new SyntaxError("invalid string");
        }
        return value;
      }
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError("invalid control character");
      if (character !== "\\") {
        index += 1;
        continue;
      }
      index += 1;
      const escape = source[index];
      if ('"\\/bfnrt'.includes(escape ?? "")) index += 1;
      else if (escape === "u" && /^[a-fA-F0-9]{4}$/.test(source.slice(index + 1, index + 5))) index += 5;
      else throw new SyntaxError("invalid escape");
    }
    throw new SyntaxError("unterminated string");
  };
  const parseValue = (depth) => {
    if (depth > limits.maximumDepth) throw new SyntaxError("excessive depth");
    whitespace();
    if (source[index] === "{") {
      index += 1;
      whitespace();
      const output = Object.create(null);
      const keys = new Set();
      if (source[index] === "}") { index += 1; return output; }
      while (true) {
        const key = parseString();
        if (keys.has(key) || keys.size >= limits.maximumCollectionSize) {
          throw new SyntaxError("duplicate or excessive object");
        }
        keys.add(key);
        whitespace();
        if (source[index] !== ":") throw new SyntaxError("invalid object");
        index += 1;
        output[key] = parseValue(depth + 1);
        whitespace();
        if (source[index] === "}") { index += 1; return output; }
        if (source[index] !== ",") throw new SyntaxError("invalid object");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1;
      whitespace();
      const output = [];
      if (source[index] === "]") { index += 1; return output; }
      while (true) {
        output.push(parseValue(depth + 1));
        if (output.length > limits.maximumCollectionSize) throw new SyntaxError("excessive array");
        whitespace();
        if (source[index] === "]") { index += 1; return output; }
        if (source[index] !== ",") throw new SyntaxError("invalid array");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === '"') return parseString();
    for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, index)) { index += literal.length; return value; }
    }
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(source.slice(index));
    if (!match) throw new SyntaxError("invalid value");
    index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) throw new SyntaxError("invalid number");
    return value;
  };
  const output = parseValue(0);
  whitespace();
  if (index !== source.length) throw new SyntaxError("trailing JSON");
  return output;
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return true;
  }
  return false;
}
