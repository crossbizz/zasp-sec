import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { parseGraphLicenseInventory } from "./graph-license-audit.mjs";

const inventoryUrl = new URL("./observability-licenses.json", import.meta.url);
const graphInventoryUrl = new URL("./graph-licenses.json", import.meta.url);
const maximumInventoryBytes = 32 * 1024;
const maximumArtifactBytes = 8 * 1024 * 1024;
const maximumJsonDepth = 16;
const maximumCollectionSize = 128;
const maximumStringLength = 4_096;
const defaultFetchTimeoutMilliseconds = 30_000;
const defaultCleanupTimeoutMilliseconds = 1_000;

export const OBSERVABILITY_LICENSE_SUCCESS_LINE = "Local observability license audit passed: components=2 artifacts=3 prohibited=0 redistribution_approved=false.";

const expectedInventory = deepFreeze({
  schema_version: 1,
  scope: {
    use: "opt-in-local-development",
    redistribution_approved: false,
    production_packaging_approved: false,
    remote_backend_approved: false,
  },
  allowed_licenses: ["Apache-2.0", "GPL-2.0-only"],
  images: {
    collector: {
      name: "opentelemetry-collector-contrib",
      version: "0.158.0",
      reference: "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5",
      index_digest: "sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5",
      image_revision: "1400269f8ace841f8d0492f4f9c6c7f305f95268",
      image_source: "https://github.com/open-telemetry/opentelemetry-collector-releases",
      image_license: "Apache-2.0",
      platforms: {
        "linux/amd64": {
          manifest_digest: "sha256:e290476fa9a75f7a84a28798832bde7068d27825745de67bc38957e22949a64c",
          config_digest: "sha256:837606a793453fd0c2eef9a6d4ee47ecc970d228ede7bc0c15d32ea9324c9e80",
        },
        "linux/arm64": {
          manifest_digest: "sha256:51e1afc9d762a359387723170be5cecccad2c09e73a5a2061361c62c60855ccf",
          config_digest: "sha256:e4ed3985c0db662ed2f0be81ac3b10110aefd379b0be24c780e2803571997c93",
        },
      },
    },
    busybox: {
      reference: "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9",
      index_digest: "sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9",
    },
  },
  components: [
    {
      name: "OpenTelemetry Collector Contrib",
      version: "0.158.0",
      license: "Apache-2.0",
      source_repository: "https://github.com/open-telemetry/opentelemetry-collector-contrib",
      source_tag: "v0.158.0",
      source_commit: "821a9d9c2c1623c4a0ceba5d47b57c48879c3f84",
      scope: "opt-in-local-development",
      redistribution_approved: false,
      production_packaging_approved: false,
    },
    {
      name: "BusyBox runtime (reused M1-30b evidence)",
      version: "1.36.1",
      license: "GPL-2.0-only",
      evidence_inventory: "deploy/local/graph-licenses.json",
      scope: "opt-in-local-development",
      redistribution_approved: false,
      production_packaging_approved: false,
    },
  ],
  artifacts: [
    {
      name: "Collector Contrib source boundary",
      url: "https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-contrib/821a9d9c2c1623c4a0ceba5d47b57c48879c3f84/README.md",
      sha256: "52ad80dffa63b52255af59d8c4f9c0c9979e607faa9d7dbd23e3a9fecbbf98e8",
    },
    {
      name: "Collector Contrib Apache license",
      url: "https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-contrib/821a9d9c2c1623c4a0ceba5d47b57c48879c3f84/LICENSE",
      sha256: "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
    },
    {
      name: "Collector Contrib image recipe",
      url: "https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-releases/1400269f8ace841f8d0492f4f9c6c7f305f95268/distributions/otelcol-contrib/Dockerfile",
      sha256: "757b955a2258b9289d7bda2510dfd160d681c2e8bdfc45a75e3ee78b31c7d633",
    },
  ],
  busybox_reuse: {
    graph_inventory: "deploy/local/graph-licenses.json",
    graph_inventory_sha256: "b4bfd72f704a86d812a056c3fd153a8d8e384b6e81e53f5ac327c5d3844a8323",
    required_license: "GPL-2.0-only",
  },
  boundary: "The Collector Contrib and reused BusyBox images are opt-in local-development dependencies. The pipeline writes only to a proof-owned local file sink, approves no remote telemetry backend, and does not approve redistribution or production packaging.",
});

export function parseObservabilityLicenseInventory(source) {
  if (typeof source !== "string" || Buffer.byteLength(source, "utf8") === 0 ||
      Buffer.byteLength(source, "utf8") > maximumInventoryBytes ||
      Buffer.from(source, "utf8").toString("utf8") !== source) reject();
  let value;
  try {
    value = parseUniqueJson(source);
  } catch {
    reject();
  }
  if (!isDeepStrictEqual(value, expectedInventory)) reject();
  return deepFreeze(structuredClone(value));
}

export async function auditObservabilityLicenses(options = {}) {
  const allowedOptions = new Set(["fingerprintArtifact", "graphInventoryText", "inventoryText"]);
  requireOptionsObject(options, allowedOptions);
  const inventorySource = options.inventoryText ?? await readFile(inventoryUrl, "utf8");
  const graphSource = options.graphInventoryText ?? await readFile(graphInventoryUrl, "utf8");
  const fingerprintArtifact = options.fingerprintArtifact ?? fingerprintObservabilityArtifact;
  if (typeof fingerprintArtifact !== "function") reject();
  const inventory = parseObservabilityLicenseInventory(inventorySource);
  parseGraphLicenseInventory(graphSource);
  if (createHash("sha256").update(graphSource).digest("hex") !== inventory.busybox_reuse.graph_inventory_sha256) reject();
  for (const artifact of inventory.artifacts) {
    let actual;
    try {
      actual = await fingerprintArtifact(artifact.url);
    } catch {
      reject();
    }
    if (actual !== artifact.sha256) reject();
  }
  return deepFreeze({ components: 2, artifacts: 3, prohibited: 0, redistributionApproved: false });
}

export async function runMain(options = {}) {
  const writeOutput = options.writeOutput ?? ((value) => process.stdout.write(value));
  const writeError = options.writeError ?? ((value) => process.stderr.write(value));
  try {
    await auditObservabilityLicenses({
      ...(options.inventoryText === undefined ? {} : { inventoryText: options.inventoryText }),
      ...(options.graphInventoryText === undefined ? {} : { graphInventoryText: options.graphInventoryText }),
      ...(options.fingerprintArtifact === undefined ? {} : { fingerprintArtifact: options.fingerprintArtifact }),
    });
    writeOutput(`${OBSERVABILITY_LICENSE_SUCCESS_LINE}\n`);
    return 0;
  } catch {
    writeError("Local observability license audit failed.\n");
    return 1;
  }
}

export async function fingerprintObservabilityArtifact(url, options = {}) {
  if (typeof url !== "string" || !url.startsWith("https://")) reject();
  const allowedOptions = new Set(["cleanupTimeoutMilliseconds", "fetchImpl", "timeoutMilliseconds"]);
  requireOptionsObject(options, allowedOptions);
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMilliseconds = options.timeoutMilliseconds ?? defaultFetchTimeoutMilliseconds;
  const cleanupTimeoutMilliseconds = options.cleanupTimeoutMilliseconds ?? defaultCleanupTimeoutMilliseconds;
  if (typeof fetchImpl !== "function" || !validTimeout(timeoutMilliseconds, defaultFetchTimeoutMilliseconds) ||
      !validTimeout(cleanupTimeoutMilliseconds, defaultCleanupTimeoutMilliseconds)) reject();
  const controller = new AbortController();
  let timer;
  const deadline = new Promise((_resolve, rejectDeadline) => {
    timer = setTimeout(() => {
      controller.abort();
      rejectDeadline(new Error("bounded artifact deadline"));
    }, timeoutMilliseconds);
  });
  let reader;
  let succeeded = false;
  try {
    const response = await Promise.race([Promise.resolve().then(() => fetchImpl(url, {
      signal: controller.signal,
      redirect: "error",
      headers: {
        Accept: "application/octet-stream",
        "Accept-Encoding": "identity",
        "User-Agent": "zasp-local-observability-license-audit/1",
      },
    })), deadline]);
    reader = response?.body?.getReader?.();
    if (reader === undefined || response.ok !== true || response.status !== 200 || response.redirected !== false ||
        typeof response.headers?.get !== "function") reject();
    const contentLengthHeader = response.headers.get("content-length");
    let contentLength;
    if (contentLengthHeader !== null) {
      if (typeof contentLengthHeader !== "string" || !/^(?:0|[1-9]\d*)$/u.test(contentLengthHeader)) reject();
      contentLength = Number(contentLengthHeader);
      if (!Number.isSafeInteger(contentLength) || contentLength > maximumArtifactBytes) reject();
    }
    const hash = createHash("sha256");
    let bytes = 0;
    while (true) {
      const chunk = await Promise.race([Promise.resolve().then(() => reader.read()), deadline]);
      if (chunk?.done === true) break;
      if (chunk?.done !== false || !(chunk.value instanceof Uint8Array) || chunk.value.byteLength === 0) reject();
      bytes += chunk.value.byteLength;
      if (bytes > maximumArtifactBytes || contentLength !== undefined && bytes > contentLength) reject();
      hash.update(chunk.value);
    }
    if (bytes === 0 || contentLength !== undefined && bytes !== contentLength) reject();
    succeeded = true;
    return hash.digest("hex");
  } catch {
    reject();
  } finally {
    if (!succeeded) {
      controller.abort();
      await cancelReader(reader, cleanupTimeoutMilliseconds);
    }
    try { reader?.releaseLock?.(); } catch { /* fixed rejection boundary */ }
    clearTimeout(timer);
  }
}

async function cancelReader(reader, timeoutMilliseconds) {
  if (typeof reader?.cancel !== "function") return;
  let timer;
  const cancelled = Promise.resolve().then(() => reader.cancel()).catch(() => {});
  const bounded = new Promise((resolve) => { timer = setTimeout(resolve, timeoutMilliseconds); });
  await Promise.race([cancelled, bounded]);
  clearTimeout(timer);
}

function validTimeout(value, maximum) {
  return Number.isSafeInteger(value) && value > 0 && value <= maximum;
}

function parseUniqueJson(source) {
  let index = 0;
  const whitespace = () => { while (index < source.length && /[\t\n\r ]/u.test(source[index])) index += 1; };
  const parseString = () => {
    if (source[index] !== '"') throw new SyntaxError("invalid JSON string");
    const start = index;
    index += 1;
    while (index < source.length) {
      const character = source[index];
      if (character === '"') {
        index += 1;
        const value = JSON.parse(source.slice(start, index));
        if (value.length > maximumStringLength || hasUnpairedSurrogate(value)) throw new SyntaxError("invalid JSON string");
        return value;
      }
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError("invalid JSON string");
      if (character !== "\\") { index += 1; continue; }
      index += 1;
      const escape = source[index];
      if ('"\\/bfnrt'.includes(escape ?? "")) index += 1;
      else if (escape === "u" && /^[a-fA-F0-9]{4}$/u.test(source.slice(index + 1, index + 5))) index += 5;
      else throw new SyntaxError("invalid JSON escape");
    }
    throw new SyntaxError("unterminated JSON string");
  };
  const parseValue = (depth) => {
    if (depth > maximumJsonDepth) throw new SyntaxError("excessive JSON depth");
    whitespace();
    if (source[index] === "{") {
      index += 1;
      whitespace();
      const entries = [];
      const keys = new Set();
      if (source[index] === "}") { index += 1; return {}; }
      while (true) {
        const key = parseString();
        if (keys.has(key)) throw new SyntaxError("duplicate JSON key");
        keys.add(key);
        whitespace();
        if (source[index] !== ":") throw new SyntaxError("missing JSON colon");
        index += 1;
        entries.push([key, parseValue(depth + 1)]);
        if (entries.length > maximumCollectionSize) throw new SyntaxError("oversized JSON object");
        whitespace();
        if (source[index] === "}") { index += 1; return Object.fromEntries(entries); }
        if (source[index] !== ",") throw new SyntaxError("missing JSON comma");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1;
      whitespace();
      const values = [];
      if (source[index] === "]") { index += 1; return values; }
      while (true) {
        values.push(parseValue(depth + 1));
        if (values.length > maximumCollectionSize) throw new SyntaxError("oversized JSON array");
        whitespace();
        if (source[index] === "]") { index += 1; return values; }
        if (source[index] !== ",") throw new SyntaxError("missing JSON comma");
        index += 1;
      }
    }
    if (source[index] === '"') return parseString();
    for (const [token, value] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(token, index)) { index += token.length; return value; }
    }
    const match = source.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u);
    if (match === null) throw new SyntaxError("invalid JSON value");
    index += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) throw new SyntaxError("invalid JSON number");
    return number;
  };
  const value = parseValue(0);
  whitespace();
  if (index !== source.length) throw new SyntaxError("trailing JSON input");
  return value;
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function requireOptionsObject(value, allowedKeys) {
  if (!isPlainObject(value)) reject();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || !allowedKeys.has(key)) reject();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) reject();
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function reject() {
  throw new TypeError("observability license audit rejected");
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runMain();
}
