import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

const inventoryUrl = new URL("./aws-emulator-licenses.json", import.meta.url);
const maximumInventoryBytes = 32 * 1024;
const maximumArtifactBytes = 8 * 1024 * 1024;
const maximumJsonDepth = 16;
const maximumCollectionSize = 128;
const maximumStringLength = 4_096;
const defaultFetchTimeoutMilliseconds = 30_000;
const defaultCleanupTimeoutMilliseconds = 1_000;

export const AWS_EMULATOR_LICENSE_SUCCESS_LINE = "Local AWS emulator license audit passed: components=1 artifacts=3 prohibited=0 redistribution_approved=false.";

const expectedInventory = deepFreeze({
  schema_version: 1,
  scope: {
    use: "opt-in-local-development",
    redistribution_approved: false,
    production_packaging_approved: false,
    remote_aws_approved: false,
  },
  allowed_licenses: ["Apache-2.0"],
  image: {
    component: "localstack-community",
    reference: "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c",
    repo_digest: "localstack/localstack@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c",
    environment_sha256: "1e4fe2995cc9b2339761b690070d16ababb619a51bf41a49d5148ddac7517092",
    environment_count: 10,
    entrypoint: ["docker-entrypoint.sh"],
    command: null,
    user: "",
    working_directory: "/opt/code/localstack/",
    labels: {
      authors: "LocalStack Contributors",
      description: "LocalStack Docker image",
      maintainer: "LocalStack Team (info@localstack.cloud)",
    },
  },
  component: {
    name: "localstack-community",
    version: "4.7.0",
    license: "Apache-2.0",
    source_repository: "https://github.com/localstack/localstack",
    source_tag: "v4.7.0",
    source_tag_object: "dff59755581d7c1832e4e9e985362b6062b88a08",
    source_commit: "82de91e30b0185a6792dd5047168b29d69bbb1f9",
    boundary: "Exact free/community LocalStack image and tagged source used only for the local Kubernetes S3 endpoint fixture. Bundled third-party components retain their own terms and are not relicensed by this inventory.",
    artifacts: [
      {
        kind: "license",
        url: "https://raw.githubusercontent.com/localstack/localstack/82de91e30b0185a6792dd5047168b29d69bbb1f9/LICENSE.txt",
        sha256: "dcf0bef59ebd52c34046e43df3480d47f26c2f1f2ebcc8dd1ba0bb71ce0b058b",
      },
      {
        kind: "supplemental-terms",
        url: "https://raw.githubusercontent.com/localstack/localstack/82de91e30b0185a6792dd5047168b29d69bbb1f9/docs/end_user_license_agreement/README.md",
        sha256: "5df76f56494d8cdbfb56a1d8e4c4c53cbe25281a4a09f4e8e9c63041dbe55a61",
      },
      {
        kind: "manifest",
        url: "https://raw.githubusercontent.com/localstack/localstack/82de91e30b0185a6792dd5047168b29d69bbb1f9/pyproject.toml",
        sha256: "48995e124a42ce9a20d2856eaab5123b257f3cbe3218705d6f17cff1e7c86f50",
      },
    ],
  },
  boundary: "The exact LocalStack Community image is an opt-in local-development dependency for an internal S3 endpoint proof. It exposes no host port, uses no ambient AWS authority, and approves neither redistribution nor production packaging.",
});

export function parseAwsEmulatorLicenseInventory(source) {
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

export async function auditAwsEmulatorLicenses(options = {}) {
  requireOptionsObject(options, new Set(["fingerprintArtifact", "inventoryText", "timeoutMilliseconds"]));
  const source = options.inventoryText ?? await readFile(inventoryUrl, "utf8");
  const fingerprintArtifact = options.fingerprintArtifact ?? fingerprintAwsEmulatorArtifact;
  const timeoutMilliseconds = options.timeoutMilliseconds ?? defaultFetchTimeoutMilliseconds;
  if (typeof fingerprintArtifact !== "function" || !validTimeout(timeoutMilliseconds, defaultFetchTimeoutMilliseconds)) reject();
  const inventory = parseAwsEmulatorLicenseInventory(source);
  const controller = new AbortController();
  let timer;
  const deadline = new Promise((_resolve, rejectDeadline) => {
    timer = setTimeout(() => {
      controller.abort();
      rejectDeadline(new Error("bounded audit deadline"));
    }, timeoutMilliseconds);
  });
  let succeeded = false;
  try {
    for (const artifact of inventory.component.artifacts) {
      let actual;
      try {
        actual = await Promise.race([
          Promise.resolve().then(() => fingerprintArtifact(artifact.url, { signal: controller.signal })),
          deadline,
        ]);
      } catch {
        reject();
      }
      if (actual !== artifact.sha256) reject();
    }
    succeeded = true;
    return deepFreeze({ components: 1, artifacts: 3, prohibited: 0, redistributionApproved: false });
  } finally {
    if (!succeeded) controller.abort();
    clearTimeout(timer);
  }
}

export async function runMain(options = {}) {
  requireOptionsObject(options, new Set(["fingerprintArtifact", "inventoryText", "writeError", "writeOutput"]));
  const writeOutput = options.writeOutput ?? ((value) => process.stdout.write(value));
  const writeError = options.writeError ?? ((value) => process.stderr.write(value));
  if (typeof writeOutput !== "function" || typeof writeError !== "function") reject();
  try {
    await auditAwsEmulatorLicenses({
      ...(options.inventoryText === undefined ? {} : { inventoryText: options.inventoryText }),
      ...(options.fingerprintArtifact === undefined ? {} : { fingerprintArtifact: options.fingerprintArtifact }),
    });
    writeOutput(`${AWS_EMULATOR_LICENSE_SUCCESS_LINE}\n`);
    return 0;
  } catch {
    writeError("Local AWS emulator license audit failed.\n");
    return 1;
  }
}

export async function fingerprintAwsEmulatorArtifact(url, options = {}) {
  if (typeof url !== "string" || !url.startsWith("https://")) reject();
  requireOptionsObject(options, new Set(["cleanupTimeoutMilliseconds", "fetchImpl", "signal", "timeoutMilliseconds"]));
  const fetchImpl = options.fetchImpl ?? fetch;
  const externalSignal = options.signal;
  const timeoutMilliseconds = options.timeoutMilliseconds ?? defaultFetchTimeoutMilliseconds;
  const cleanupTimeoutMilliseconds = options.cleanupTimeoutMilliseconds ?? defaultCleanupTimeoutMilliseconds;
  if (typeof fetchImpl !== "function" || !validTimeout(timeoutMilliseconds, defaultFetchTimeoutMilliseconds) ||
      !validTimeout(cleanupTimeoutMilliseconds, defaultCleanupTimeoutMilliseconds) ||
      externalSignal !== undefined && Object.getPrototypeOf(externalSignal) !== AbortSignal.prototype) reject();
  const controller = new AbortController();
  const abortFromExternal = () => controller.abort();
  externalSignal?.addEventListener("abort", abortFromExternal, { once: true });
  if (externalSignal?.aborted === true) controller.abort();
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
        "User-Agent": "zasp-local-aws-emulator-license-audit/1",
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
    externalSignal?.removeEventListener("abort", abortFromExternal);
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

function requireOptionsObject(value, allowed) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) reject();
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string" || !allowed.has(key))) reject();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) reject();
  }
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

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function reject() {
  throw new TypeError("AWS emulator license evidence is invalid");
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runMain();
}
