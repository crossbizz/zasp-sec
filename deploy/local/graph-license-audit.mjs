import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

const inventoryUrl = new URL("./graph-licenses.json", import.meta.url);
const maximumInventoryBytes = 32 * 1024;
const maximumArtifactBytes = 8 * 1024 * 1024;
const maximumJsonDepth = 16;
const maximumCollectionSize = 64;
const maximumStringLength = 4_096;
const defaultFetchTimeoutMilliseconds = 30_000;
const defaultCleanupTimeoutMilliseconds = 1_000;

export const GRAPH_LICENSE_SUCCESS_LINE = "Local graph license audit passed: components=3 artifacts=6 prohibited=0 redistribution_approved=false.";

const expectedInventory = deepFreeze({
  schema_version: 1,
  scope: {
    use: "opt-in-local-development",
    redistribution_approved: false,
    production_packaging_approved: false,
  },
  allowed_licenses: ["Apache-2.0", "GPL-2.0-only", "GPL-3.0-only"],
  images: {
    neo4j: {
      name: "neo4j-community-server",
      version: "5.26.28-community",
      reference: "neo4j:5.26.28-community@sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357",
      index_digest: "sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357",
      platforms: {
        "linux/amd64": {
          manifest_digest: "sha256:77a7a788aa3348c66a4c12a07930bc12232f22535b0e1a2a043df80bbfa823bd",
          config_digest: "sha256:534fe13ef23432459f04f65e1fa4c25876bb981f147d96b1b3896278d23e7552",
        },
        "linux/arm64": {
          manifest_digest: "sha256:5bed6b3adb938c45722e3639b853ecbc948b2e51cd5599d45fcd23f6d49b2d89",
          config_digest: "sha256:db03e618d0cd04bbabeb4bf5296c91108f4be5185456565bb4046a33b226fcd2",
        },
      },
    },
    busybox: {
      name: "kubernetes-e2e-busybox",
      version: "1.36.1-1",
      reference: "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9",
      index_digest: "sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9",
      platforms: {
        "linux/amd64": {
          manifest_digest: "sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb",
          config_digest: "sha256:3e0d9138669908f438c06993e9a6815bbd8c05411b8e9acfc297b3c8b017c28c",
        },
        "linux/arm64": {
          manifest_digest: "sha256:55c89c6d9404d6668eb237dda92f28a99eb14e640f1c177a55cc9d738c53c303",
          config_digest: "sha256:6d0099de92b2a095017ed32499154f16eec2df38f0d2e9192bcf6ae7d241ac75",
        },
      },
    },
  },
  components: [
    {
      name: "Neo4j Community server",
      version: "5.26.28",
      license: "GPL-3.0-only",
      source_repository: "https://github.com/neo4j/neo4j",
      source_tag: "5.26.28",
      source_commit: "09de4c547ee24f69400c75df8428685e27a9cffc",
      source_path: "pom.xml",
      source_url: "https://raw.githubusercontent.com/neo4j/neo4j/09de4c547ee24f69400c75df8428685e27a9cffc/pom.xml",
      source_sha256: "288ac5913d95557ab36b1139ed7854aadcdd4cbf5ca2d3cf1c86a4afcd743067",
      license_url: "https://raw.githubusercontent.com/neo4j/neo4j/09de4c547ee24f69400c75df8428685e27a9cffc/LICENSE.txt",
      license_sha256: "8e1bb72dd89711d9612ea2749c906e4b17760245f4ffdfcc237219f4df48e440",
      scope: "opt-in-local-development",
      redistribution_approved: false,
      production_packaging_approved: false,
    },
    {
      name: "Kubernetes e2e BusyBox image packaging",
      version: "1.36.1-1",
      license: "Apache-2.0",
      source_repository: "https://github.com/kubernetes/kubernetes",
      source_commit: "22d90ebde235edec3541f728b37a01285bdd8b1b",
      source_path: "test/images/busybox/Dockerfile",
      source_url: "https://raw.githubusercontent.com/kubernetes/kubernetes/22d90ebde235edec3541f728b37a01285bdd8b1b/test/images/busybox/Dockerfile",
      source_sha256: "b1a06c7718262b6de2aebb822093dbc4215f980500024ca65d2206341a7a3838",
      license_url: "https://raw.githubusercontent.com/kubernetes/kubernetes/22d90ebde235edec3541f728b37a01285bdd8b1b/LICENSE",
      license_sha256: "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
      scope: "opt-in-local-development",
      redistribution_approved: false,
      production_packaging_approved: false,
    },
    {
      name: "BusyBox runtime",
      version: "1.36.1",
      license: "GPL-2.0-only",
      source_repository: "https://busybox.net",
      source_commit: "release-tarball-busybox-1.36.1",
      source_path: "busybox-1.36.1.tar.bz2",
      source_url: "https://busybox.net/downloads/busybox-1.36.1.tar.bz2",
      source_sha256: "b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314",
      license_url: "https://raw.githubusercontent.com/mirror/busybox/1_36_1/LICENSE",
      license_sha256: "bbfc9843646d483c334664f651c208b9839626891d8f17604db2146962f43548",
      scope: "opt-in-local-development",
      redistribution_approved: false,
      production_packaging_approved: false,
    },
  ],
  boundary: "Neo4j Community and BusyBox are opt-in local-development server images only. ZASP does not embed, redistribute, sublicense, or approve either image for production packaging; bundled dependencies retain their own terms.",
});

export function parseGraphLicenseInventory(source) {
  if (
    typeof source !== "string" || Buffer.byteLength(source, "utf8") === 0 ||
    Buffer.byteLength(source, "utf8") > maximumInventoryBytes ||
    Buffer.from(source, "utf8").toString("utf8") !== source
  ) reject();
  let value;
  try {
    value = parseUniqueJson(source);
  } catch {
    reject();
  }
  if (!isDeepStrictEqual(value, expectedInventory)) reject();
  return deepFreeze(structuredClone(value));
}

export async function auditGraphLicenses(options = {}) {
  if (!isPlainObject(options)) reject();
  const source = options.inventoryText ?? await readFile(inventoryUrl, "utf8");
  const fingerprintArtifact = options.fingerprintArtifact ?? fingerprintUrl;
  if (typeof fingerprintArtifact !== "function") reject();
  const inventory = parseGraphLicenseInventory(source);
  for (const component of inventory.components) {
    for (const [url, expected] of [
      [component.source_url, component.source_sha256],
      [component.license_url, component.license_sha256],
    ]) {
      let actual;
      try {
        actual = await fingerprintArtifact(url);
      } catch {
        reject();
      }
      if (actual !== expected) reject();
    }
  }
  return deepFreeze({ components: 3, artifacts: 6, prohibited: 0, redistributionApproved: false });
}

export async function runMain(options = {}) {
  const writeOutput = options.writeOutput ?? ((value) => process.stdout.write(value));
  const writeError = options.writeError ?? ((value) => process.stderr.write(value));
  try {
    await auditGraphLicenses({
      ...(options.inventoryText === undefined ? {} : { inventoryText: options.inventoryText }),
      ...(options.fingerprintArtifact === undefined ? {} : { fingerprintArtifact: options.fingerprintArtifact }),
    });
    writeOutput(`${GRAPH_LICENSE_SUCCESS_LINE}\n`);
    return 0;
  } catch {
    writeError("Local graph license audit failed.\n");
    return 1;
  }
}

export async function fingerprintUrl(url, options = {}) {
  if (typeof url !== "string" || !url.startsWith("https://") || !isPlainObject(options)) reject();
  const allowedOptions = new Set(["cleanupTimeoutMilliseconds", "fetchImpl", "timeoutMilliseconds"]);
  if (Object.keys(options).some((key) => !allowedOptions.has(key))) reject();
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
        "User-Agent": "zasp-local-graph-license-audit/1",
      },
    })), deadline]);
    reader = response.body?.getReader?.();
    if (reader === undefined) reject();
    if (response.ok !== true || response.status !== 200 || response.redirected !== false ||
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
      if (character !== "\\") {
        index += 1;
        continue;
      }
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
        if (keys.has(key) || keys.size >= maximumCollectionSize) throw new SyntaxError("duplicate JSON key");
        keys.add(key);
        whitespace();
        if (source[index] !== ":") throw new SyntaxError("invalid JSON object");
        index += 1;
        entries.push([key, parseValue(depth + 1)]);
        whitespace();
        if (source[index] === "}") { index += 1; return Object.fromEntries(entries); }
        if (source[index] !== ",") throw new SyntaxError("invalid JSON object");
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
        if (output.length > maximumCollectionSize) throw new SyntaxError("excessive JSON array");
        whitespace();
        if (source[index] === "]") { index += 1; return output; }
        if (source[index] !== ",") throw new SyntaxError("invalid JSON array");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === '"') return parseString();
    for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, index)) { index += literal.length; return value; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(source.slice(index));
    if (number === null) throw new SyntaxError("invalid JSON value");
    index += number[0].length;
    const parsed = Number(number[0]);
    if (!Number.isFinite(parsed)) throw new SyntaxError("invalid JSON number");
    return parsed;
  };
  const value = parseValue(0);
  whitespace();
  if (index !== source.length) throw new SyntaxError("trailing JSON data");
  return value;
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function reject() {
  throw new Error("local graph license audit rejected");
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await runMain();
}
