import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { lstat, mkdtemp, readdir, realpath, rm, readFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { mergeNormalizedGraphs, normalizeGraph, parseRawGraph } from "./normalizer.mjs";

export const CARTOGRAPHY_IMAGE = "ghcr.io/cartography-cncf/cartography:0.139.1@sha256:f1d7c1f46a8a2137b9a955327d3cd47e8340c7d537d0447467d2e952af8bb8f0";
export const NEO4J_IMAGE = "neo4j:5.26-community@sha256:d9dd3dc7d1c78fa959191ff02dbdcbefadceaf83eee23428fb92a58cac8ad3fe";
export const SUCCESS_LINE = "Cartography scope proof passed: fixtures=2 nodes=8 relationships=4 isolated=true labels_safe=true cleanup=true.";
export const CARTOGRAPHY_BOOTSTRAP = 'import runpy,sys;m=runpy.run_path(sys.argv[2]);raise SystemExit(m["bootstrap_main"](sys.argv[1:]))';

const allowedCategories = new Set([
  "configuration", "provider", "ownership", "normalization", "cleanup", "operation",
]);
const outputLimit = 16_384;
const readinessTimeoutMs = 500;
const bridgeTimeoutMs = 45_000;
const dockerTimeoutMs = 30_000;
const imagePullTimeoutMs = 120_000;
const mainTimeoutMs = 300_000;
const cleanupTimeoutMs = 60_000;
const proofDirectory = dirname(fileURLToPath(import.meta.url));
const markerPattern = /^[a-f0-9]{16}$/;
const objectIDPattern = /^[a-f0-9]{64}$/;
const imageIDPattern = /^sha256:[a-f0-9]{64}$/;
const organizationBySlot = Object.freeze({
  a: "org_aaaaaaaaaaaaaaaa",
  b: "org_bbbbbbbbbbbbbbbb",
});
const fixtureMountpointBytes = Buffer.from("{}\n");
const fixtureMountpointDigest = "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356";
const readinessBody = Buffer.from('{"statements":[{"statement":"RETURN 1"}]}');
const neo4jProofEnvironment = Object.freeze([
  "NEO4J_AUTH=none",
  "NEO4J_db_tx__log_preallocate=false",
  "NEO4J_db_tx__log_rotation_size=128K",
]);

export class Failure extends Error {
  constructor(category) {
    super("fixed Cartography orchestrator failure");
    this.category = allowedCategories.has(category) ? category : "operation";
  }
}

function fixedFailure(category) {
  const safe = allowedCategories.has(category) ? category : "operation";
  return `Cartography scope proof failed: ${safe} rejected.`;
}

function markerFromName(name, suffix) {
  const match = typeof name === "string"
    ? new RegExp(`^zasp-m0-10-([a-f0-9]{16})-${suffix}$`).exec(name)
    : null;
  if (match === null) throw new Failure("configuration");
  return match[1];
}

function validateSlot(slot) {
  if (slot !== "a" && slot !== "b") throw new Failure("configuration");
  return slot;
}

export function buildNetworkCreateArguments(name) {
  const marker = markerFromName(name, "network");
  return [
    "network", "create",
    "--label", "zasp.proof=m0-10",
    "--label", `zasp.marker=${marker}`,
    name,
  ];
}

export function buildNeo4jRunArguments(name, network) {
  const marker = markerFromName(name, "neo4j-[ab]");
  if (markerFromName(network, "network") !== marker) throw new Failure("configuration");
  return [
    "run", "--detach", "--rm", "--name", name,
    "--network", network,
    ...neo4jProofEnvironment.flatMap((value) => ["--env", value]),
    "--label", "zasp.proof=m0-10",
    "--label", `zasp.marker=${marker}`,
    "--publish", "127.0.0.1::7474",
    "--publish", "127.0.0.1::7687",
    NEO4J_IMAGE,
  ];
}

export function buildCartographyCreateArguments(name, neo4jName, network, mount, slot) {
  validateSlot(slot);
  const marker = markerFromName(name, `cartography-${slot}`);
  if (
    markerFromName(neo4jName, `neo4j-${slot}`) !== marker ||
    markerFromName(network, "network") !== marker ||
    typeof mount !== "string" || !isAbsolute(mount) || resolve(mount) !== mount
  ) {
    throw new Failure("configuration");
  }
  return [
    "create", "--rm", "--name", name,
    "--hostname", name,
    "--network", network,
    "--label", "zasp.proof=m0-10",
    "--label", `zasp.marker=${marker}`,
    "--entrypoint", "python",
    "--volume", `${mount}:/proof:ro`,
    "--volume", `${join(mount, "fixtures", `org-${slot}.json`)}:/proof/fixture.json:ro`,
    CARTOGRAPHY_IMAGE,
    "-I", "-c", CARTOGRAPHY_BOOTSTRAP,
    name,
    "/proof/fixture_runner.py",
    "--fixture", "/proof/fixture.json",
    "--neo4j-uri", `bolt://${neo4jName}:7687`,
  ];
}

export function runBounded(command, arguments_, options, spawnImplementation = spawn) {
  return new Promise((resolvePromise, rejectPromise) => {
    let child;
    try {
      child = spawnImplementation(command, arguments_, {
        env: options.env,
        cwd: options.cwd,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      rejectPromise(new Failure(options.category));
      return;
    }
    if (
      child === null || typeof child !== "object" ||
      typeof child.once !== "function" ||
      typeof child.stdout?.on !== "function" ||
      typeof child.stderr?.on !== "function"
    ) {
      rejectPromise(new Failure(options.category));
      return;
    }

    let settled = false;
    let bytes = 0;
    let timer;
    const stdout = [];
    const stderr = [];
    const signal = options.signal;
    const stop = () => {
      child.stdout?.destroy?.();
      child.stderr?.destroy?.();
      child.kill?.("SIGKILL");
    };
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener?.("abort", abort);
      callback();
    };
    const fail = () => finish(() => rejectPromise(new Failure(options.category)));
    const abort = () => {
      stop();
      fail();
    };
    const consume = (target) => (chunk) => {
      if (settled) return;
      const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += value.byteLength;
      if (bytes > options.outputLimit) {
        stop();
        fail();
        return;
      }
      target.push(value);
    };
    child.stdout.on("data", consume(stdout));
    child.stderr.on("data", consume(stderr));
    child.once("error", fail);
    child.once("close", (status, closeSignal) => finish(() => resolvePromise({
      status,
      signal: closeSignal,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
    })));
    signal?.addEventListener?.("abort", abort, { once: true });
    timer = setTimeout(abort, options.timeoutMs);
    if (signal?.aborted === true) abort();
  });
}

export function probeNeo4jReadiness(port, {
  signal,
  timeoutMs = readinessTimeoutMs,
  requestImplementation = request,
} = {}) {
  if (
    !Number.isInteger(port) || port < 1024 || port > 65_535 ||
    !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > readinessTimeoutMs ||
    typeof requestImplementation !== "function"
  ) {
    throw new Failure("configuration");
  }
  return new Promise((resolvePromise, rejectPromise) => {
    const requestController = new AbortController();
    let requestHandle;
    let responseHandle;
    let timer;
    let settled = false;
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener?.("abort", abort);
      requestHandle?.destroy?.();
      responseHandle?.destroy?.();
      callback();
    };
    const unavailable = () => finish(() => resolvePromise(false));
    const abort = () => finish(() => {
      requestController.abort();
      rejectPromise(new Failure("provider"));
    });
    const timeout = () => finish(() => {
      requestController.abort();
      resolvePromise(false);
    });
    if (signal?.aborted === true) {
      abort();
      return;
    }
    signal?.addEventListener?.("abort", abort, { once: true });
    timer = setTimeout(timeout, timeoutMs);
    try {
      requestHandle = requestImplementation({
        protocol: "http:",
        hostname: "127.0.0.1",
        port,
        method: "POST",
        path: "/db/neo4j/tx/commit",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "Content-Length": readinessBody.byteLength,
        },
        signal: requestController.signal,
      }, (response) => {
        responseHandle = response;
        if (
          response === null || typeof response !== "object" ||
          typeof response.on !== "function" || response.statusCode !== 200 ||
          !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers?.["content-type"] ?? "")
        ) {
          unavailable();
          return;
        }
        const chunks = [];
        let bytes = 0;
        response.on("data", (chunk) => {
          if (settled) return;
          const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          bytes += value.byteLength;
          if (bytes > outputLimit) {
            unavailable();
            return;
          }
          chunks.push(value);
        });
        response.once("error", unavailable);
        response.once("aborted", unavailable);
        response.once("end", () => {
          if (settled) return;
          let document;
          try { document = parseUniqueJson(Buffer.concat(chunks).toString("utf8")); } catch { unavailable(); return; }
          finish(() => resolvePromise(validReadinessDocument(document)));
        });
      });
    } catch {
      unavailable();
      return;
    }
    if (
      requestHandle === null || typeof requestHandle !== "object" ||
      typeof requestHandle.once !== "function" || typeof requestHandle.end !== "function" ||
      typeof requestHandle.destroy !== "function"
    ) {
      unavailable();
      return;
    }
    requestHandle.once("error", unavailable);
    requestHandle.end(readinessBody);
  });
}

function validReadinessDocument(value) {
  if (!plainObject(value) || !isDeepStrictEqual(Object.keys(value).sort(), ["errors", "lastBookmarks", "results"])) return false;
  const result = value.results?.[0];
  const data = result?.data?.[0];
  const bookmark = value.lastBookmarks?.[0];
  return (
    Array.isArray(value.errors) && value.errors.length === 0 &&
    Array.isArray(value.results) && value.results.length === 1 && plainObject(result) &&
    isDeepStrictEqual(Object.keys(result).sort(), ["columns", "data"]) &&
    isDeepStrictEqual(result.columns, ["1"]) && Array.isArray(result.data) &&
    result.data.length === 1 && plainObject(data) &&
    isDeepStrictEqual(Object.keys(data).sort(), ["meta", "row"]) &&
    isDeepStrictEqual(data.row, [1]) && isDeepStrictEqual(data.meta, [null]) &&
    Array.isArray(value.lastBookmarks) && value.lastBookmarks.length === 1 &&
    typeof bookmark === "string" && bookmark.length > 0 && bookmark.length <= 4_096 &&
    !hasControlCharacter(bookmark)
  );
}

function parseUniqueJson(source) {
  if (typeof source !== "string") throw new SyntaxError("invalid JSON");
  let index = 0;
  const whitespace = () => {
    while (index < source.length && /[\t\n\r ]/.test(source[index])) index += 1;
  };
  const string = () => {
    if (source[index] !== '"') throw new SyntaxError("invalid JSON string");
    const start = index;
    index += 1;
    while (index < source.length) {
      const character = source[index];
      if (character === '"') {
        index += 1;
        return JSON.parse(source.slice(start, index));
      }
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError("invalid JSON string");
      if (character !== "\\") {
        index += 1;
        continue;
      }
      index += 1;
      const escape = source[index];
      if ('"\\/bfnrt'.includes(escape ?? "")) {
        index += 1;
      } else if (escape === "u" && /^[a-fA-F0-9]{4}$/.test(source.slice(index + 1, index + 5))) {
        index += 5;
      } else {
        throw new SyntaxError("invalid JSON escape");
      }
    }
    throw new SyntaxError("unterminated JSON string");
  };
  const value = () => {
    whitespace();
    if (source[index] === "{") {
      index += 1;
      whitespace();
      const keys = new Set();
      if (source[index] === "}") { index += 1; return; }
      while (true) {
        const key = string();
        if (keys.has(key)) throw new SyntaxError("duplicate JSON key");
        keys.add(key);
        whitespace();
        if (source[index] !== ":") throw new SyntaxError("invalid JSON object");
        index += 1;
        value();
        whitespace();
        if (source[index] === "}") { index += 1; return; }
        if (source[index] !== ",") throw new SyntaxError("invalid JSON object");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1;
      whitespace();
      if (source[index] === "]") { index += 1; return; }
      while (true) {
        value();
        whitespace();
        if (source[index] === "]") { index += 1; return; }
        if (source[index] !== ",") throw new SyntaxError("invalid JSON array");
        index += 1;
      }
    }
    if (source[index] === '"') { string(); return; }
    for (const literal of ["true", "false", "null"]) {
      if (source.startsWith(literal, index)) { index += literal.length; return; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(index));
    if (number === null) throw new SyntaxError("invalid JSON value");
    index += number[0].length;
  };
  value();
  whitespace();
  if (index !== source.length) throw new SyntaxError("invalid trailing JSON");
  return JSON.parse(source);
}

function hasControlCharacter(value) {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint <= 0x1f || codePoint === 0x7f) return true;
  }
  return false;
}

export class DockerRuntime {
  constructor({
    path = process.env.PATH,
    marker = randomBytes(8).toString("hex"),
    proofDirectory: selectedProofDirectory = proofDirectory,
    tempParent = tmpdir(),
    command = runBounded,
    spawnProcess = spawn,
    makeTemp = mkdtemp,
    removeTemp = rm,
    canonicalPath = realpath,
    statPath = lstat,
    readDirectory = readdir,
    wait = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds)),
    readinessProbe = probeNeo4jReadiness,
    readPath = readFile,
  } = {}) {
    if (
      typeof path !== "string" || path.length === 0 ||
      !markerPattern.test(marker) ||
      typeof selectedProofDirectory !== "string" || !isAbsolute(selectedProofDirectory) || resolve(selectedProofDirectory) !== selectedProofDirectory ||
      typeof tempParent !== "string" || !isAbsolute(tempParent) || resolve(tempParent) !== tempParent ||
      ![command, spawnProcess, makeTemp, removeTemp, canonicalPath, statPath, readDirectory, wait, readinessProbe, readPath].every((value) => typeof value === "function")
    ) {
      throw new Failure("configuration");
    }
    this.path = path;
    this.marker = marker;
    this.prefix = `zasp-m0-10-${marker}`;
    this.networkName = `${this.prefix}-network`;
    this.proofDirectory = selectedProofDirectory;
    this.tempParent = tempParent;
    this.command = command;
    this.spawnProcess = spawnProcess;
    this.makeTemp = makeTemp;
    this.removeTemp = removeTemp;
    this.canonicalPath = canonicalPath;
    this.statPath = statPath;
    this.readDirectory = readDirectory;
    this.wait = wait;
    this.readinessProbe = readinessProbe;
    this.readPath = readPath;
    this.dockerConfigIdentity = undefined;
    this.dockerConfigCandidate = undefined;
    this.dockerConfigCreation = undefined;
    this.dockerConfigCreationStarted = false;
    this.dockerConfigRemoved = false;
    this.networkToken = undefined;
    this.networkAttempted = false;
    this.networkRemovalAttempted = false;
    this.containerTokens = new Map();
    this.containerVolumes = new Map();
    this.containerAttempts = new Set();
    this.imageIDs = new Map();
    this.imageRuntimeMetadata = new Map();
    this.neo4jPorts = new Map();
    this.neo4jHttpPorts = new Map();
    this.fixtureMountpointIdentity = undefined;
    this.phaseGeneration = 0;
    this.phase = Object.freeze({ generation: 0, signal: undefined });
  }

  setAbortSignal(signal) {
    this.phaseGeneration += 1;
    this.phase = Object.freeze({ generation: this.phaseGeneration, signal });
    return this.phase;
  }

  assertActive(category = "operation", phase = this.phase) {
    if (phase !== this.phase || phase?.signal?.aborted === true) throw new Failure(category);
  }

  name(kind) {
    if (!["neo4j-a", "neo4j-b", "cartography-a", "cartography-b"].includes(kind)) {
      throw new Failure("configuration");
    }
    return `${this.prefix}-${kind}`;
  }

  hasDockerConfigCreationStarted() {
    return this.dockerConfigCreationStarted;
  }

  async initialize(phase = this.phase) {
    this.assertActive("configuration", phase);
    let canonicalParent;
    let canonicalProof;
    try {
      [canonicalParent, canonicalProof] = await Promise.all([
        this.canonicalPath(this.tempParent), this.canonicalPath(this.proofDirectory),
      ]);
    } catch {
      throw new Failure("configuration");
    }
    if (
      typeof canonicalParent !== "string" || !isAbsolute(canonicalParent) || resolve(canonicalParent) !== canonicalParent ||
      canonicalProof !== this.proofDirectory
    ) {
      throw new Failure("configuration");
    }
    this.assertActive("configuration", phase);
    this.tempParent = canonicalParent;
    if (this.dockerConfigCreationStarted) throw new Failure("configuration");
    this.dockerConfigCreationStarted = true;
    this.dockerConfigCreation = Promise.resolve()
      .then(() => this.makeTemp(join(this.tempParent, `${this.prefix}-docker-config-`)))
      .then((candidate) => {
        this.dockerConfigCandidate = candidate;
        return candidate;
      });
    const candidate = await this.dockerConfigCreation;
    this.assertActive("configuration", phase);
    const identity = await this.ownedEmptyTemporaryDirectory(candidate, "configuration", phase);
    this.assertActive("configuration", phase);
    if (identity === undefined) throw new Failure("configuration");
    this.dockerConfigIdentity = identity;
    this.assertActive("operation", phase);
  }

  async ownedEmptyTemporaryDirectory(value, category = "configuration", phase = this.phase) {
    this.assertActive(category, phase);
    if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value) return undefined;
    const requiredPrefix = join(this.tempParent, `${this.prefix}-docker-config-`);
    if (dirname(value) !== this.tempParent || !value.startsWith(requiredPrefix) || value.length === requiredPrefix.length) return undefined;
    try {
      const [canonical, status, entries] = await Promise.all([
        this.canonicalPath(value), this.statPath(value), this.readDirectory(value),
      ]);
      this.assertActive(category, phase);
      if (
        canonical !== value || !status?.isDirectory?.() || status?.isSymbolicLink?.() ||
        !Number.isSafeInteger(status.dev) || !Number.isSafeInteger(status.ino) ||
        !Array.isArray(entries) || entries.length !== 0
      ) return undefined;
      return { path: value, dev: status.dev, ino: status.ino };
    } catch {
      return undefined;
    }
  }

  async cleanupDockerConfig(phase = this.phase) {
    this.assertActive("cleanup", phase);
    if (this.dockerConfigRemoved) return;
    if (this.dockerConfigIdentity === undefined && this.dockerConfigCreationStarted) {
      let candidate;
      try { candidate = await this.dockerConfigCreation; } catch { candidate = undefined; }
      this.assertActive("cleanup", phase);
      if (candidate !== undefined) {
        const identity = await this.ownedEmptyTemporaryDirectory(candidate, "cleanup", phase);
        this.assertActive("cleanup", phase);
        if (identity === undefined) throw new Failure("cleanup");
        this.dockerConfigIdentity = identity;
      }
    }
    if (this.dockerConfigIdentity === undefined) return;
    const current = await this.ownedEmptyTemporaryDirectory(this.dockerConfigIdentity.path, "cleanup", phase);
    this.assertActive("cleanup", phase);
    if (
      current === undefined || current.dev !== this.dockerConfigIdentity.dev ||
      current.ino !== this.dockerConfigIdentity.ino
    ) {
      throw new Failure("cleanup");
    }
    this.assertActive("cleanup", phase);
    try {
      await this.removeTemp(current.path, { recursive: true, force: false, maxRetries: 0 });
    } catch {
      throw new Failure("cleanup");
    }
    this.assertActive("cleanup", phase);
    try {
      await this.statPath(current.path);
      throw new Failure("cleanup");
    } catch (error) {
      if (error instanceof Failure || error?.code !== "ENOENT") throw new Failure("cleanup");
    }
    this.assertActive("cleanup", phase);
    this.dockerConfigIdentity = undefined;
    this.dockerConfigCandidate = undefined;
    this.dockerConfigRemoved = true;
  }

  async requireTemporaryPrefixAbsent(category = "cleanup", phase = this.phase) {
    this.assertActive(category, phase);
    let entries;
    try { entries = await this.readDirectory(this.tempParent); } catch { throw new Failure(category); }
    this.assertActive(category, phase);
    if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string" || entry.startsWith("zasp-m0-10-"))) {
      throw new Failure(category);
    }
  }

  dockerOptions(options = {}, phase = this.phase) {
    this.assertActive(options.category ?? "provider", phase);
    if (this.dockerConfigIdentity === undefined) throw new Failure(options.category ?? "provider");
    return {
      env: { PATH: this.path, DOCKER_CONFIG: this.dockerConfigIdentity.path },
      timeoutMs: options.timeoutMs ?? dockerTimeoutMs,
      outputLimit: options.outputLimit ?? outputLimit,
      category: options.category ?? "provider",
      ...(phase.signal === undefined ? {} : { signal: phase.signal }),
    };
  }

  async dockerRead(args, options = {}, phase = this.phase) {
    this.assertActive(options.category ?? "provider", phase);
    const result = await this.command("docker", args, this.dockerOptions(options, phase), this.spawnProcess);
    this.assertActive(options.category ?? "provider", phase);
    return result;
  }

  async readDocker(args, options = {}, phase = this.phase) {
    let result;
    const category = options.category ?? "provider";
    this.assertActive(category, phase);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        result = await this.dockerRead(args, options, phase);
        this.assertActive(category, phase);
      } catch {
        this.assertActive(category, phase);
        if (attempt === 1) throw new Failure(category);
        try { await this.wait(250, phase.signal); } catch { throw new Failure(category); }
        this.assertActive(category, phase);
        continue;
      }
      if (result?.status === 0 && result?.signal === null) return result;
      if (attempt === 0) {
        this.assertActive(category, phase);
        try { await this.wait(250, phase.signal); } catch { throw new Failure(category); }
        this.assertActive(category, phase);
      }
    }
    return result;
  }

  async dockerMutation(args, options = {}, phase = this.phase) {
    const category = options.category ?? "provider";
    this.assertActive(category, phase);
    const result = await this.command("docker", args, this.dockerOptions(options, phase), this.spawnProcess);
    this.assertActive(category, phase);
    return result;
  }

  async preflight(phase = this.phase) {
    this.assertActive("provider", phase);
    await this.requirePrefixAbsent("ownership", phase);
    this.assertActive("provider", phase);
    let entries;
    try { entries = await this.readDirectory(this.tempParent); } catch { throw new Failure("provider"); }
    this.assertActive("provider", phase);
    const admitted = basename(this.dockerConfigIdentity?.path ?? "");
    if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string" || (entry.startsWith("zasp-m0-10-") && entry !== admitted))) {
      throw new Failure("ownership");
    }
  }

  async resolveImages(phase = this.phase) {
    this.assertActive("provider", phase);
    await this.resolveImage(NEO4J_IMAGE, phase);
    this.assertActive("provider", phase);
    await this.resolveImage(CARTOGRAPHY_IMAGE, phase);
    this.assertActive("provider", phase);
  }

  async resolveImage(image, phase = this.phase) {
    this.assertActive("provider", phase);
    const inspectArguments = [
      "image", "inspect", "--format",
      "[{{json .Id}},{{json .Config.Env}},{{json .Config.Entrypoint}},{{json .Config.Cmd}},{{json (index .Config \"ExposedPorts\")}},{{json (index .Config \"Volumes\")}}]",
      image,
    ];
    let inspected = await this.readDocker(inspectArguments, { category: "provider" }, phase);
    this.assertActive("provider", phase);
    if (inspected?.status !== 0 || inspected?.signal !== null) {
      const pulled = await this.dockerMutation(["pull", image], {
        category: "provider", timeoutMs: imagePullTimeoutMs,
      }, phase);
      this.assertActive("provider", phase);
      if (pulled?.status !== 0 || pulled?.signal !== null) throw new Failure("provider");
      inspected = await this.readDocker(inspectArguments, { category: "provider" }, phase);
      this.assertActive("provider", phase);
    }
    const metadata = parseImageRuntimeMetadata(inspected?.stdout);
    if (inspected?.status !== 0 || inspected?.signal !== null || inspected?.stderr !== "" || metadata === undefined) {
      throw new Failure("provider");
    }
    this.assertActive("provider", phase);
    this.imageIDs.set(image, metadata.identifier);
    this.imageRuntimeMetadata.set(image, metadata.runtime);
    return metadata.identifier;
  }

  async requirePrefixAbsent(category = "ownership", phase = this.phase) {
    this.assertActive(category, phase);
    const containers = await this.readDocker([
      "ps", "--all", "--no-trunc", "--filter", "name=^/zasp-m0-10-", "--format", "{{.ID}}|{{.Names}}",
    ], { category }, phase);
    const networks = await this.readDocker([
      "network", "ls", "--no-trunc", "--filter", "name=^zasp-m0-10-", "--format", "{{.ID}}|{{.Name}}",
    ], { category }, phase);
    this.assertActive(category, phase);
    if (containers?.status !== 0 || networks?.status !== 0 || containers?.stderr !== "" || networks?.stderr !== "") {
      throw new Failure(category);
    }
    for (const [identifier, name] of [...parsePairs(containers.stdout), ...parsePairs(networks.stdout)]) {
      if (!objectIDPattern.test(identifier)) throw new Failure(category);
      if (name.startsWith("zasp-m0-10-")) throw new Failure(category);
    }
  }

  async createNetwork(phase = this.phase) {
    this.assertActive("provider", phase);
    this.networkAttempted = true;
    let created;
    try {
      created = await this.dockerMutation(buildNetworkCreateArguments(this.networkName), { category: "provider" }, phase);
    } catch {
      this.assertActive("provider", phase);
    }
    this.assertActive("provider", phase);
    const direct = singleLine(created?.stdout);
    if (objectIDPattern.test(direct)) this.networkToken = direct;
    if (created?.status !== 0 || created?.signal !== null || !objectIDPattern.test(direct)) {
      const candidates = await this.namedNetworkCandidates("ownership", phase);
      this.assertActive("ownership", phase);
      if (candidates.length !== 1) throw new Failure("ownership");
      this.networkToken = candidates[0];
    }
    await this.verifyNetwork("ownership", undefined, phase);
    this.assertActive("ownership", phase);
    return this.networkToken;
  }

  async namedNetworkCandidates(category, phase = this.phase) {
    this.assertActive(category, phase);
    const listed = await this.readDocker([
      "network", "ls", "--no-trunc", "--filter", `name=^${this.networkName}$`, "--format", "{{.ID}}|{{.Name}}",
    ], { category }, phase);
    this.assertActive(category, phase);
    if (listed?.status !== 0 || listed?.stderr !== "") throw new Failure(category);
    const pairs = parsePairs(listed.stdout);
    if (pairs.some(([identifier, name]) => !objectIDPattern.test(identifier) || name !== this.networkName)) {
      throw new Failure(category);
    }
    return pairs.map(([identifier]) => identifier);
  }

  async inspectNetwork(token, category, phase = this.phase) {
    this.assertActive(category, phase);
    if (!objectIDPattern.test(token ?? "")) throw new Failure(category);
    return this.readDocker([
      "network", "inspect", "--format",
      "{{.Id}}|{{.Name}}|{{index .Labels \"zasp.proof\"}}|{{index .Labels \"zasp.marker\"}}",
      token,
    ], { category }, phase);
  }

  async verifyNetwork(category = "ownership", inspectedResult, phase = this.phase) {
    this.assertActive(category, phase);
    const inspected = inspectedResult ?? await this.inspectNetwork(this.networkToken, category, phase);
    this.assertActive(category, phase);
    const fields = singleLine(inspected?.stdout).split("|");
    if (
      inspected?.status !== 0 || inspected?.stderr !== "" || fields.length !== 4 ||
      fields[0] !== this.networkToken || fields[1] !== this.networkName ||
      fields[2] !== "m0-10" || fields[3] !== this.marker
    ) throw new Failure(category);
    return this.networkToken;
  }

  async startNeo4j(slot, phase = this.phase) {
    this.assertActive("provider", phase);
    validateSlot(slot);
    const kind = `neo4j-${slot}`;
    const name = this.name(kind);
    this.containerAttempts.add(kind);
    let started;
    try {
      started = await this.dockerMutation(buildNeo4jRunArguments(name, this.networkName), { category: "provider" }, phase);
    } catch {
      this.assertActive("provider", phase);
    }
    this.assertActive("provider", phase);
    return this.resolveContainerCreate(kind, started, phase);
  }

  async ensureProofDirectory(phase = this.phase) {
    this.assertActive("ownership", phase);
    try {
      const [canonical, status] = await Promise.all([
        this.canonicalPath(this.proofDirectory), this.statPath(this.proofDirectory),
      ]);
      this.assertActive("ownership", phase);
      if (
        canonical !== this.proofDirectory || !status?.isDirectory?.() || status?.isSymbolicLink?.() ||
        !Number.isSafeInteger(status.dev) || !Number.isSafeInteger(status.ino)
      ) throw new Error("invalid");
    } catch {
      throw new Failure("ownership");
    }
  }

  async ensureFixtureFile(slot, phase = this.phase) {
    this.assertActive("ownership", phase);
    validateSlot(slot);
    const fixture = join(this.proofDirectory, "fixtures", `org-${slot}.json`);
    try {
      const [canonical, status] = await Promise.all([
        this.canonicalPath(fixture), this.statPath(fixture),
      ]);
      this.assertActive("ownership", phase);
      if (
        canonical !== fixture || !status?.isFile?.() || status?.isSymbolicLink?.() ||
        !Number.isSafeInteger(status.dev) || !Number.isSafeInteger(status.ino)
      ) throw new Error("invalid");
    } catch {
      throw new Failure("ownership");
    }
    return fixture;
  }

  async ensureFixtureMountpoint(category = "ownership", phase = this.phase) {
    this.assertActive(category, phase);
    const mountpoint = join(this.proofDirectory, "fixture.json");
    let canonical;
    let status;
    let bytes;
    try {
      [canonical, status, bytes] = await Promise.all([
        this.canonicalPath(mountpoint), this.statPath(mountpoint), this.readPath(mountpoint),
      ]);
      this.assertActive(category, phase);
    } catch {
      throw new Failure(category);
    }
    const digest = Buffer.isBuffer(bytes)
      ? createHash("sha256").update(bytes).digest("hex")
      : "";
    const current = { path: mountpoint, dev: status?.dev, ino: status?.ino, digest };
    if (
      canonical !== mountpoint || !status?.isFile?.() || status?.isSymbolicLink?.() ||
      !Number.isSafeInteger(current.dev) || !Number.isSafeInteger(current.ino) ||
      !Buffer.isBuffer(bytes) || !isDeepStrictEqual(bytes, fixtureMountpointBytes) ||
      digest !== fixtureMountpointDigest
    ) throw new Failure(category);
    if (this.fixtureMountpointIdentity === undefined) {
      this.fixtureMountpointIdentity = current;
    } else if (!isDeepStrictEqual(current, this.fixtureMountpointIdentity)) {
      throw new Failure(category);
    }
    return mountpoint;
  }

  async createCartography(slot, phase = this.phase) {
    this.assertActive("provider", phase);
    validateSlot(slot);
    await this.ensureProofDirectory(phase);
    await this.ensureFixtureMountpoint("ownership", phase);
    await this.ensureFixtureFile(slot, phase);
    this.assertActive("provider", phase);
    const kind = `cartography-${slot}`;
    const name = this.name(kind);
    this.containerAttempts.add(kind);
    let created;
    try {
      created = await this.dockerMutation(buildCartographyCreateArguments(
        name, this.name(`neo4j-${slot}`), this.networkName, this.proofDirectory, slot,
      ), { category: "provider" }, phase);
    } catch {
      this.assertActive("provider", phase);
    }
    this.assertActive("provider", phase);
    return this.resolveContainerCreate(kind, created, phase);
  }

  async resolveContainerCreate(kind, created, phase = this.phase) {
    this.assertActive("ownership", phase);
    const direct = singleLine(created?.stdout);
    if (objectIDPattern.test(direct)) this.containerTokens.set(kind, direct);
    if (created?.status !== 0 || created?.signal !== null || !objectIDPattern.test(direct)) {
      const candidates = await this.namedContainerCandidates(kind, "ownership", phase);
      this.assertActive("ownership", phase);
      if (candidates.length !== 1) throw new Failure("ownership");
      this.containerTokens.set(kind, candidates[0]);
    }
    await this.verifyContainer(kind, "ownership", undefined, phase);
    this.assertActive("ownership", phase);
    return this.containerTokens.get(kind);
  }

  async namedContainerCandidates(kind, category, phase = this.phase) {
    this.assertActive(category, phase);
    const name = this.name(kind);
    const listed = await this.readDocker([
      "ps", "--all", "--no-trunc", "--filter", `name=^/${name}$`, "--format", "{{.ID}}|{{.Names}}",
    ], { category }, phase);
    this.assertActive(category, phase);
    if (listed?.status !== 0 || listed?.stderr !== "") throw new Failure(category);
    const pairs = parsePairs(listed.stdout);
    if (pairs.some(([identifier, candidateName]) => !objectIDPattern.test(identifier) || candidateName !== name)) {
      throw new Failure(category);
    }
    return pairs.map(([identifier]) => identifier);
  }

  async inspectContainer(token, category, phase = this.phase) {
    this.assertActive(category, phase);
    if (!objectIDPattern.test(token ?? "")) throw new Failure(category);
    return this.readDocker([
      "inspect", "--format",
      "{{.Id}}|{{.Name}}|{{.Config.Hostname}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels \"zasp.proof\"}}|{{index .Config.Labels \"zasp.marker\"}}|{{.HostConfig.NetworkMode}}|{{json .NetworkSettings.Networks}}|{{json .Config.Env}}|{{json .HostConfig.PortBindings}}|{{json .NetworkSettings.Ports}}|{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{json .Mounts}}|{{json (index .HostConfig \"Binds\")}}|{{json (index .HostConfig \"Mounts\")}}|{{json (index .HostConfig \"Tmpfs\")}}",
      token,
    ], { category }, phase);
  }

  async verifyContainer(kind, category = "ownership", inspectedResult, phase = this.phase) {
    this.assertActive(category, phase);
    const token = this.containerTokens.get(kind);
    if (!objectIDPattern.test(token ?? "") || !objectIDPattern.test(this.networkToken ?? "")) {
      throw new Failure(category);
    }
    const expectedImage = kind.startsWith("neo4j-") ? NEO4J_IMAGE : CARTOGRAPHY_IMAGE;
    const imageID = this.imageIDs.get(expectedImage);
    if (!imageIDPattern.test(imageID ?? "")) throw new Failure(category);
    const inspected = inspectedResult ?? await this.inspectContainer(token, category, phase);
    this.assertActive(category, phase);
    const fields = singleLine(inspected?.stdout).split("|");
    if (inspected?.status !== 0 || inspected?.stderr !== "" || fields.length !== 18) throw new Failure(category);
    let networks;
    let environment;
    let portBindings;
    let ports;
    let entrypoint;
    let command;
    let mounts;
    let binds;
    let hostMounts;
    let tmpfs;
    try {
      networks = JSON.parse(fields[8]);
      environment = JSON.parse(fields[9]);
      portBindings = JSON.parse(fields[10]);
      ports = JSON.parse(fields[11]);
      entrypoint = JSON.parse(fields[12]);
      command = JSON.parse(fields[13]);
      mounts = JSON.parse(fields[14]);
      binds = JSON.parse(fields[15]);
      hostMounts = JSON.parse(fields[16]);
      tmpfs = JSON.parse(fields[17]);
    } catch {
      throw new Failure(category);
    }
    const attachedNetworkID = networks?.[this.networkName]?.NetworkID;
    const preStartCartographyNetwork = !kind.startsWith("neo4j-") && attachedNetworkID === "";
    if (
      fields[0] !== token || fields[1] !== `/${this.name(kind)}` ||
      fields[2] !== (kind.startsWith("neo4j-") ? token.slice(0, 12) : this.name(kind)) ||
      fields[3] !== imageID || fields[4] !== expectedImage ||
      fields[5] !== "m0-10" || fields[6] !== this.marker ||
      fields[7] !== this.networkName || !plainObject(networks) ||
      Object.keys(networks).length !== 1 ||
      (attachedNetworkID !== this.networkToken && !preStartCartographyNetwork) ||
      !Array.isArray(environment) || environment.some((value) => typeof value !== "string") ||
      !plainObject(portBindings) || !plainObject(ports) || !Array.isArray(mounts)
    ) throw new Failure(category);

    if (kind.startsWith("neo4j-")) {
      const imageRuntime = this.imageRuntimeMetadata.get(NEO4J_IMAGE);
      const imageEnvironment = exactEnvironment(imageRuntime?.environment);
      const imageEntrypoint = exactStringArray(imageRuntime?.entrypoint);
      const imageCommand = exactStringArray(imageRuntime?.command);
      const imageExposedPorts = exactPortArray(imageRuntime?.exposedPorts);
      const imageVolumes = exactVolumeArray(imageRuntime?.volumes);
      const retainedVolumes = exactIntrinsicVolumes(mounts, imageVolumes);
      const existingVolumes = this.containerVolumes.get(kind);
      const portKeys = Object.keys(ports).sort();
      const httpBindings = ports["7474/tcp"];
      const boltBindings = ports["7687/tcp"];
      if (
        !exactNeo4jEnvironment(environment, imageEnvironment) ||
        imageEntrypoint === undefined || !isDeepStrictEqual(entrypoint, imageEntrypoint) ||
        imageCommand === undefined || !isDeepStrictEqual(command, imageCommand) ||
        imageExposedPorts === undefined || imageVolumes === undefined || retainedVolumes === undefined ||
        !isDeepStrictEqual(Object.keys(portBindings).sort(), ["7474/tcp", "7687/tcp"]) ||
        !isDeepStrictEqual(portBindings["7474/tcp"], [{ HostIp: "127.0.0.1", HostPort: "" }]) ||
        !isDeepStrictEqual(portBindings["7687/tcp"], [{ HostIp: "127.0.0.1", HostPort: "" }]) ||
        !isDeepStrictEqual(portKeys, imageExposedPorts) ||
        imageExposedPorts.some((port) => !["7474/tcp", "7687/tcp"].includes(port) && ports[port] !== null) ||
        binds !== null || hostMounts !== null || tmpfs !== null ||
        !Array.isArray(httpBindings) || httpBindings.length !== 1 ||
        !plainObject(httpBindings[0]) ||
        !isDeepStrictEqual(Object.keys(httpBindings[0]).sort(), ["HostIp", "HostPort"]) ||
        httpBindings[0].HostIp !== "127.0.0.1" || !highPort(httpBindings[0].HostPort) ||
        !Array.isArray(boltBindings) || boltBindings.length !== 1 ||
        !plainObject(boltBindings[0]) ||
        !isDeepStrictEqual(Object.keys(boltBindings[0]).sort(), ["HostIp", "HostPort"]) ||
        boltBindings[0].HostIp !== "127.0.0.1" || !highPort(boltBindings[0].HostPort) ||
        httpBindings[0].HostPort === boltBindings[0].HostPort
      ) throw new Failure(category);
      if (existingVolumes === undefined) {
        this.assertActive(category, phase);
        this.containerVolumes.set(kind, retainedVolumes);
      } else if (!isDeepStrictEqual(existingVolumes, retainedVolumes)) {
        throw new Failure(category);
      }
    } else if (
      !exactCartographyRuntime({
        environment, portBindings, ports, entrypoint, command, mounts, binds, hostMounts, tmpfs,
        imageRuntime: this.imageRuntimeMetadata.get(CARTOGRAPHY_IMAGE),
        name: this.name(kind),
        neo4jName: this.name(`neo4j-${kind.at(-1)}`),
        proofDirectory: this.proofDirectory,
        slot: kind.at(-1),
      })
    ) throw new Failure(category);
    else {
      await this.ensureFixtureMountpoint(category, phase);
      if (preStartCartographyNetwork) await this.verifyCartographyNetworkBoundary(category, phase);
      this.assertActive(category, phase);
    }
    return token;
  }

  async neo4jPort(slot, phase = this.phase) {
    this.assertActive("ownership", phase);
    validateSlot(slot);
    const kind = `neo4j-${slot}`;
    const token = await this.verifyContainer(kind, "ownership", undefined, phase);
    const bolt = await this.readDocker(["port", token, "7687/tcp"], { category: "provider" }, phase);
    const http = await this.readDocker(["port", token, "7474/tcp"], { category: "provider" }, phase);
    this.assertActive("provider", phase);
    const boltMatch = /^127\.0\.0\.1:([0-9]{4,5})\n?$/.exec(String(bolt?.stdout ?? ""));
    const httpMatch = /^127\.0\.0\.1:([0-9]{4,5})\n?$/.exec(String(http?.stdout ?? ""));
    if (
      bolt?.status !== 0 || bolt?.stderr !== "" || boltMatch === null || !highPort(boltMatch[1]) ||
      http?.status !== 0 || http?.stderr !== "" || httpMatch === null || !highPort(httpMatch[1]) ||
      boltMatch[1] === httpMatch[1]
    ) {
      throw new Failure("ownership");
    }
    const boltPort = Number(boltMatch[1]);
    this.neo4jPorts.set(slot, boltPort);
    this.neo4jHttpPorts.set(slot, Number(httpMatch[1]));
    return boltPort;
  }

  async isNeo4jReady(slot, phase = this.phase) {
    this.assertActive("provider", phase);
    validateSlot(slot);
    const boltPort = this.neo4jPorts.get(slot);
    const httpPort = this.neo4jHttpPorts.get(slot);
    if (
      !Number.isInteger(boltPort) || boltPort < 1024 || boltPort > 65_535 ||
      !Number.isInteger(httpPort) || httpPort < 1024 || httpPort > 65_535 ||
      boltPort === httpPort
    ) throw new Failure("ownership");
    try {
      const ready = await this.readinessProbe(httpPort, {
        signal: phase.signal,
        timeoutMs: readinessTimeoutMs,
      });
      this.assertActive("provider", phase);
      return ready === true;
    } catch {
      this.assertActive("provider", phase);
      return false;
    }
  }

  async attachCartography(slot, phase = this.phase) {
    this.assertActive("operation", phase);
    validateSlot(slot);
    const kind = `cartography-${slot}`;
    const token = this.containerTokens.get(kind);
    if (!objectIDPattern.test(token ?? "")) throw new Failure("normalization");
    const attached = await this.dockerMutation(["start", "--attach", token], {
      category: "operation", timeoutMs: bridgeTimeoutMs, outputLimit,
    }, phase);
    this.assertActive("operation", phase);
    const stdout = typeof attached?.stdout === "string" ? attached.stdout : "";
    const stderr = typeof attached?.stderr === "string" ? attached.stderr : "";
    if (
      attached?.status !== 0 || attached?.signal !== null || stderr !== "" ||
      Buffer.byteLength(stdout) > outputLimit || !stdout.endsWith("\n") || stdout.slice(0, -1).includes("\n")
    ) throw new Failure("normalization");
    const document = stdout.slice(0, -1);
    try { JSON.parse(document); } catch { throw new Failure("normalization"); }
    return document;
  }

  hasCandidate(kind) {
    if (kind === "network") return this.networkAttempted || objectIDPattern.test(this.networkToken ?? "");
    return this.containerAttempts.has(kind) || objectIDPattern.test(this.containerTokens.get(kind) ?? "");
  }

  async removeContainer(kind, phase = this.phase) {
    this.assertActive("cleanup", phase);
    const known = this.containerTokens.get(kind);
    let token;
    let inspected;
    if (objectIDPattern.test(known ?? "")) {
      inspected = await this.inspectContainer(known, "cleanup", phase);
      this.assertActive("cleanup", phase);
      if (inspected?.status === 0) {
        token = known;
      } else {
        if (!exactMissingContainer(inspected, known)) throw new Failure("cleanup");
        const candidates = await this.namedContainerCandidates(kind, "cleanup", phase);
        this.assertActive("cleanup", phase);
        if (candidates.length === 0) {
          await this.requireContainerVolumesAbsent(kind, phase);
          return;
        }
        if (candidates.length !== 1 || candidates[0] !== known) throw new Failure("cleanup");
        token = known;
        inspected = undefined;
      }
    } else {
      const candidates = await this.namedContainerCandidates(kind, "cleanup", phase);
      this.assertActive("cleanup", phase);
      if (candidates.length === 0) {
        await this.requireContainerVolumesAbsent(kind, phase);
        return;
      }
      if (candidates.length !== 1) throw new Failure("cleanup");
      token = candidates[0];
      this.containerTokens.set(kind, token);
    }
    await this.verifyContainer(kind, "cleanup", inspected?.status === 0 ? inspected : undefined, phase);
    this.assertActive("cleanup", phase);
    let removed;
    try {
      removed = await this.dockerMutation([
        "rm", "--force", ...(kind.startsWith("neo4j-") ? ["--volumes"] : []), token,
      ], { category: "cleanup" }, phase);
    } catch {
      this.assertActive("cleanup", phase);
      await this.requireContainerAbsent(kind, phase);
      return;
    }
    this.assertActive("cleanup", phase);
    if (removed?.status !== 0 || removed?.signal !== null || singleLine(removed?.stdout) !== token) {
      await this.requireContainerAbsent(kind, phase);
    } else {
      await this.requireContainerVolumesAbsent(kind, phase);
    }
    this.assertActive("cleanup", phase);
  }

  async requireContainerVolumesAbsent(kind, phase = this.phase) {
    this.assertActive("cleanup", phase);
    if (!kind.startsWith("neo4j-")) return;
    const volumes = this.containerVolumes.get(kind);
    if (volumes === undefined) return;
    if (!Array.isArray(volumes) || volumes.length === 0 || volumes.some((name) => !objectIDPattern.test(name))) {
      throw new Failure("cleanup");
    }
    for (const name of volumes) {
      const inspected = await this.readDocker(["volume", "inspect", name], { category: "cleanup" }, phase);
      this.assertActive("cleanup", phase);
      if (
        inspected?.status !== 1 || inspected?.signal !== null || inspected?.stdout !== "[]\n" ||
        inspected?.stderr !== `Error response from daemon: get ${name}: no such volume\n`
      ) throw new Failure("cleanup");
    }
  }

  async requireContainerAbsent(kind, phase = this.phase) {
    this.assertActive("cleanup", phase);
    const token = this.containerTokens.get(kind);
    if (objectIDPattern.test(token ?? "")) {
      const inspected = await this.inspectContainer(token, "cleanup", phase);
      this.assertActive("cleanup", phase);
      if (inspected?.status === 0) throw new Failure("cleanup");
      if (!exactMissingContainer(inspected, token)) throw new Failure("cleanup");
    }
    const candidates = await this.namedContainerCandidates(kind, "cleanup", phase);
    this.assertActive("cleanup", phase);
    if (candidates.length !== 0) throw new Failure("cleanup");
    await this.requireContainerVolumesAbsent(kind, phase);
    this.assertActive("cleanup", phase);
  }

  async removeNetwork(phase = this.phase) {
    this.assertActive("cleanup", phase);
    const known = this.networkToken;
    let token;
    let inspected;
    if (objectIDPattern.test(known ?? "")) {
      inspected = await this.inspectNetwork(known, "cleanup", phase);
      this.assertActive("cleanup", phase);
      if (inspected?.status === 0) token = known;
      else {
        if (!exactMissingNetwork(inspected, known)) throw new Failure("cleanup");
        const candidates = await this.namedNetworkCandidates("cleanup", phase);
        this.assertActive("cleanup", phase);
        if (candidates.length === 0) return;
        if (candidates.length !== 1 || candidates[0] !== known) throw new Failure("cleanup");
        token = known;
        inspected = undefined;
      }
    } else {
      const candidates = await this.namedNetworkCandidates("cleanup", phase);
      this.assertActive("cleanup", phase);
      if (candidates.length === 0) return;
      if (candidates.length !== 1) throw new Failure("cleanup");
      token = candidates[0];
      this.networkToken = token;
    }
    await this.verifyNetwork("cleanup", inspected, phase);
    this.assertActive("cleanup", phase);
    this.networkRemovalAttempted = true;
    let removed;
    try {
      removed = await this.dockerMutation(["network", "rm", token], { category: "cleanup" }, phase);
    } catch {
      this.assertActive("cleanup", phase);
      await this.requireNetworkAbsent(phase);
      return;
    }
    this.assertActive("cleanup", phase);
    if (removed?.status !== 0 || removed?.signal !== null || singleLine(removed?.stdout) !== token) {
      await this.requireNetworkAbsent(phase);
    }
  }

  async requireNetworkAbsent(phase = this.phase) {
    this.assertActive("cleanup", phase);
    if (objectIDPattern.test(this.networkToken ?? "")) {
      const inspected = await this.inspectNetwork(this.networkToken, "cleanup", phase);
      this.assertActive("cleanup", phase);
      if (inspected?.status === 0) throw new Failure("cleanup");
      if (!exactMissingNetwork(inspected, this.networkToken)) throw new Failure("cleanup");
    }
    if ((await this.namedNetworkCandidates("cleanup", phase)).length !== 0) throw new Failure("cleanup");
    this.assertActive("cleanup", phase);
  }

  async verifyCartographyNetworkBoundary(category, phase = this.phase) {
    this.assertActive(category, phase);
    if (category !== "cleanup" || !this.networkRemovalAttempted) {
      await this.verifyNetwork(category, undefined, phase);
      return;
    }
    const inspected = await this.inspectNetwork(this.networkToken, category, phase);
    this.assertActive(category, phase);
    if (inspected?.status === 0) {
      await this.verifyNetwork(category, inspected, phase);
      return;
    }
    if (!exactMissingNetwork(inspected, this.networkToken)) throw new Failure(category);
    const candidates = await this.namedNetworkCandidates(category, phase);
    this.assertActive(category, phase);
    if (candidates.length !== 0) throw new Failure(category);
  }
}

export async function orchestrate(runtime, options = {}) {
  const readinessAttempts = options.readinessAttempts ?? 120;
  const wait = options.wait ?? waitWithSignal;
  const withDeadline = options.withDeadline ?? withAbsoluteDeadline;
  const runtimeFactory = options.runtimeFactory ?? (() => new DockerRuntime());
  let selected = runtime;
  let mainFailure;
  let cleanupFailed = false;
  let preflightPassed = false;
  const candidates = new Set();
  try {
    await withDeadline(async (signal) => {
      const step = (operation) => phaseStep(signal, operation, "operation");
      throwIfAborted(signal, "operation");
      selected ??= runtimeFactory();
      if (!runtimeContract(selected) || !Number.isInteger(readinessAttempts) || readinessAttempts < 1) {
        throw new Failure("configuration");
      }
      selected.setAbortSignal?.(signal);
      await step(() => selected.initialize());
      await step(() => selected.preflight());
      preflightPassed = true;
      await step(() => selected.resolveImages());
      throwIfAborted(signal, "operation");
      candidates.add("network");
      await step(() => selected.createNetwork());
      for (const slot of ["a", "b"]) {
        throwIfAborted(signal, "operation");
        candidates.add(`neo4j-${slot}`);
        await step(() => selected.startNeo4j(slot));
        await step(() => selected.verifyContainer(`neo4j-${slot}`));
        await step(() => selected.neo4jPort(slot));
      }
      for (const slot of ["a", "b"]) {
        let ready = false;
        for (let attempt = 0; attempt < readinessAttempts; attempt += 1) {
          if (await step(() => selected.isNeo4jReady(slot))) { ready = true; break; }
          if (attempt + 1 < readinessAttempts) await step(() => wait(250, signal));
        }
        if (!ready) throw new Failure("provider");
      }
      const rawGraphs = [];
      for (const slot of ["a", "b"]) {
        throwIfAborted(signal, "operation");
        candidates.add(`cartography-${slot}`);
        await step(() => selected.createCartography(slot));
        await step(() => selected.verifyContainer(`cartography-${slot}`));
      }
      for (const slot of ["a", "b"]) {
        rawGraphs.push(await step(() => selected.attachCartography(slot)));
      }
      await step(() => validateAndMerge(rawGraphs));
    }, mainTimeoutMs);
  } catch (error) {
    mainFailure = error instanceof Failure ? error : new Failure("operation");
  } finally {
    if (selected !== undefined) {
      try {
        await withDeadline(async (signal) => {
          selected.setAbortSignal?.(signal);
          const cleanupStep = async (operation) => {
            throwIfAborted(signal, "cleanup");
            let succeeded = true;
            try { await operation(); } catch { cleanupFailed = true; succeeded = false; }
            throwIfAborted(signal, "cleanup");
            return succeeded;
          };
          let containersAbsent = true;
          for (const kind of ["cartography-b", "cartography-a", "neo4j-b", "neo4j-a"]) {
            if (!candidates.has(kind)) continue;
            await cleanupStep(() => selected.removeContainer(kind));
            const absent = await cleanupStep(() => selected.requireContainerAbsent(kind));
            containersAbsent = containersAbsent && absent;
          }
          if (candidates.has("network")) {
            if (containersAbsent) await cleanupStep(() => selected.removeNetwork());
            await cleanupStep(() => selected.requireNetworkAbsent());
          }
          if (preflightPassed) {
            await cleanupStep(() => selected.requirePrefixAbsent("cleanup"));
          }
          await cleanupStep(() => selected.cleanupDockerConfig());
          if (preflightPassed || selected.hasDockerConfigCreationStarted()) {
            await cleanupStep(() => selected.requireTemporaryPrefixAbsent("cleanup"));
          }
        }, cleanupTimeoutMs);
      } catch {
        cleanupFailed = true;
      }
    }
  }
  if (cleanupFailed) return { code: 1, line: fixedFailure("cleanup") };
  if (mainFailure !== undefined) return { code: 1, line: fixedFailure(mainFailure.category) };
  return { code: 0, line: SUCCESS_LINE };
}

async function validateAndMerge(documents) {
  try {
    const fixtures = await Promise.all(["a", "b"].map(async (slot) => {
      const bytes = await readFile(new URL(`./fixtures/org-${slot}.json`, import.meta.url));
      if (bytes.byteLength > outputLimit) throw new Error("fixture too large");
      return JSON.parse(bytes.toString("utf8"));
    }));
    const normalized = documents.map((document, index) => {
      if (typeof document !== "string" || Buffer.byteLength(document) > outputLimit) throw new Error("invalid bridge");
      const raw = JSON.parse(document);
      const parsed = parseRawGraph(raw);
      const organization = organizationBySlot[index === 0 ? "a" : "b"];
      const graph = normalizeGraph(organization, parsed);
      const expected = normalizeGraph(organization, parseRawGraph(fixtures[index]));
      if (!isDeepStrictEqual(graph, expected)) throw new Error("graph mismatch");
      return graph;
    });
    const merged = mergeNormalizedGraphs(normalized);
    const safeValues = [
      ...merged.nodes.map((node) => node.kind),
      ...merged.relationships.map((relationship) => relationship.kind),
    ];
    const isolated = new Set(merged.nodes.map((node) => node.id)).size === 8 &&
      new Set(merged.relationships.map((relationship) => relationship.id)).size === 4 &&
      normalized.every((graph, index) => graph.organization_id === organizationBySlot[index === 0 ? "a" : "b"]);
    if (
      documents.length !== 2 || merged.nodes.length !== 8 || merged.relationships.length !== 4 ||
      !isolated || safeValues.some((value) => /cartography|neo4j|aws|github/i.test(value))
    ) throw new Error("invalid normalized proof");
  } catch {
    throw new Failure("normalization");
  }
}

export async function runMain(runtime, options = {}) {
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const setExitCode = options.setExitCode ?? ((code) => { process.exitCode = code; });
  let result;
  try {
    result = await orchestrate(runtime, {
      ...(options.orchestrateOptions ?? {}),
      runtimeFactory: options.runtimeFactory,
    });
  } catch (error) {
    result = { code: 1, line: fixedFailure(error instanceof Failure ? error.category : "operation") };
  }
  try {
    (result.code === 0 ? stdout : stderr).write(`${result.line}\n`);
  } catch {
    result = { code: 1, line: fixedFailure("operation") };
    try { stderr.write(`${result.line}\n`); } catch { /* fixed boundary is best effort */ }
  }
  try { setExitCode(result.code); } catch { return 1; }
  return result.code;
}

async function withAbsoluteDeadline(operation, timeoutMs) {
  const controller = new AbortController();
  let timer;
  try {
    const operationResult = Promise.resolve()
      .then(() => operation(controller.signal))
      .then(
        (value) => ({ state: "fulfilled", value }),
        (error) => ({ state: "rejected", error }),
      );
    const winner = await Promise.race([
      operationResult,
      new Promise((resolvePromise) => {
        timer = setTimeout(() => {
          controller.abort();
          resolvePromise({ state: "timeout" });
        }, timeoutMs);
      }),
    ]);
    if (winner.state === "timeout") {
      throw new Failure("operation");
    }
    if (winner.state === "rejected") throw winner.error;
    return winner.value;
  } finally {
    clearTimeout(timer);
  }
}

async function phaseStep(signal, operation, category) {
  throwIfAborted(signal, category);
  const value = await operation();
  throwIfAborted(signal, category);
  return value;
}

function throwIfAborted(signal, category) {
  if (signal?.aborted === true) throw new Failure(category);
}

function waitWithSignal(milliseconds, signal) {
  return new Promise((resolvePromise, rejectPromise) => {
    let timer;
    const abort = () => {
      clearTimeout(timer);
      rejectPromise(new Failure("operation"));
    };
    signal?.addEventListener?.("abort", abort, { once: true });
    timer = setTimeout(() => {
      signal?.removeEventListener?.("abort", abort);
      resolvePromise();
    }, milliseconds);
    if (signal?.aborted === true) abort();
  });
}

function runtimeContract(runtime) {
  return runtime !== null && typeof runtime === "object" && [
    "initialize", "preflight", "resolveImages", "createNetwork", "startNeo4j", "verifyContainer",
    "neo4jPort", "isNeo4jReady", "createCartography", "attachCartography", "removeContainer",
    "requireContainerAbsent", "removeNetwork", "requireNetworkAbsent", "requirePrefixAbsent", "cleanupDockerConfig",
    "requireTemporaryPrefixAbsent", "hasDockerConfigCreationStarted",
  ].every((name) => typeof runtime[name] === "function");
}

function singleLine(value) {
  if (typeof value !== "string") return "";
  const trimmed = value.endsWith("\n") ? value.slice(0, -1) : value;
  return trimmed.includes("\n") ? "" : trimmed;
}

function exactMissingContainer(result, token) {
  return result?.status === 1 && result?.signal === null && result?.stdout === "\n" &&
    result?.stderr === `error: no such object: ${token}\n`;
}

function exactMissingNetwork(result, token) {
  return result?.status === 1 && result?.signal === null && result?.stdout === "\n" &&
    result?.stderr === `Error response from daemon: network ${token} not found\n`;
}

function parseImageRuntimeMetadata(value) {
  let document;
  try { document = JSON.parse(singleLine(value)); } catch { return undefined; }
  if (!Array.isArray(document) || document.length !== 6 || !imageIDPattern.test(document[0] ?? "")) return undefined;
  const environment = exactEnvironment(document[1]);
  const entrypoint = exactStringArray(document[2]);
  const command = exactStringArray(document[3]);
  const exposedPorts = exactImageObjectKeys(document[4], exactPortArray);
  const volumes = exactImageObjectKeys(document[5], exactVolumeArray);
  if (
    environment === undefined || entrypoint === undefined || command === undefined ||
    exposedPorts === undefined || volumes === undefined
  ) return undefined;
  return {
    identifier: document[0],
    runtime: Object.freeze({ environment, entrypoint, command, exposedPorts, volumes }),
  };
}

function exactImageObjectKeys(value, validator) {
  if (value === null) return Object.freeze([]);
  if (
    !plainObject(value) ||
    Object.values(value).some((entry) => !plainObject(entry) || Object.keys(entry).length !== 0)
  ) return undefined;
  return validator(Object.keys(value));
}

function exactEnvironment(value) {
  const entries = exactStringArray(value);
  if (entries === undefined) return undefined;
  const keys = new Set();
  for (const entry of entries) {
    const separator = entry.indexOf("=");
    const key = separator > 0 ? entry.slice(0, separator) : "";
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || keys.has(key)) return undefined;
    keys.add(key);
  }
  return entries;
}

function exactStringArray(value, allowEmpty = false) {
  if (
    !Array.isArray(value) || (!allowEmpty && value.length === 0) || value.length > 128 ||
    value.some((entry) => typeof entry !== "string" || entry.length === 0 || Buffer.byteLength(entry) > 4_096 || hasControlCharacter(entry))
  ) return undefined;
  return Object.freeze([...value]);
}

function exactPortArray(value) {
  const ports = exactStringArray(value, true);
  if (ports === undefined || ports.some((port) => {
    const match = /^([0-9]{1,5})\/(tcp|udp)$/.exec(port);
    return match === null || Number(match[1]) < 1 || Number(match[1]) > 65_535;
  })) return undefined;
  const sorted = [...ports].sort();
  return new Set(sorted).size === sorted.length ? Object.freeze(sorted) : undefined;
}

function exactVolumeArray(value) {
  const volumes = exactStringArray(value, true);
  if (
    volumes === undefined ||
    volumes.some((destination) => !isAbsolute(destination) || resolve(destination) !== destination || destination === "/")
  ) return undefined;
  const sorted = [...volumes].sort();
  return new Set(sorted).size === sorted.length ? Object.freeze(sorted) : undefined;
}

function exactNeo4jEnvironment(environment, imageEnvironment) {
  const runtimeEnvironment = exactEnvironment(environment);
  if (
    runtimeEnvironment === undefined || imageEnvironment === undefined ||
    runtimeEnvironment.length !== neo4jProofEnvironment.length + imageEnvironment.length
  ) return false;
  const proofPrefix = [...runtimeEnvironment.slice(0, neo4jProofEnvironment.length)].sort();
  return isDeepStrictEqual(proofPrefix, [...neo4jProofEnvironment].sort()) &&
    isDeepStrictEqual(runtimeEnvironment.slice(neo4jProofEnvironment.length), imageEnvironment);
}

function exactCartographyRuntime({
  environment, portBindings, ports, entrypoint, command, mounts, binds, hostMounts, tmpfs,
  imageRuntime, name, neo4jName, proofDirectory: selectedProofDirectory, slot,
}) {
  const imageEnvironment = exactEnvironment(imageRuntime?.environment);
  const imageEntrypoint = exactStringArray(imageRuntime?.entrypoint);
  const imageCommand = exactStringArray(imageRuntime?.command);
  const imageExposedPorts = exactPortArray(imageRuntime?.exposedPorts);
  const imageVolumes = exactVolumeArray(imageRuntime?.volumes);
  const fixture = join(selectedProofDirectory, "fixtures", `org-${slot}.json`);
  const sortedMounts = Array.isArray(mounts)
    ? [...mounts].sort((left, right) => String(left?.Destination).localeCompare(String(right?.Destination)))
    : mounts;
  const sortedBinds = Array.isArray(binds) ? [...binds].sort() : binds;
  return (
    imageEnvironment !== undefined && imageEntrypoint !== undefined && imageCommand !== undefined &&
    imageExposedPorts !== undefined && imageVolumes !== undefined && imageVolumes.length === 0 &&
    isDeepStrictEqual(exactEnvironment(environment), imageEnvironment) &&
    isDeepStrictEqual(Object.keys(portBindings).sort(), []) &&
    isDeepStrictEqual(Object.keys(ports).sort(), imageExposedPorts) &&
    imageExposedPorts.every((port) => ports[port] === null) &&
    isDeepStrictEqual(entrypoint, ["python"]) &&
    isDeepStrictEqual(command, [
      "-I", "-c", CARTOGRAPHY_BOOTSTRAP, name, "/proof/fixture_runner.py",
      "--fixture", "/proof/fixture.json", "--neo4j-uri", `bolt://${neo4jName}:7687`,
    ]) &&
    isDeepStrictEqual(sortedMounts, [
      {
        Type: "bind", Source: selectedProofDirectory, Destination: "/proof",
        Mode: "ro", RW: false, Propagation: "rprivate",
      },
      {
        Type: "bind", Source: fixture, Destination: "/proof/fixture.json",
        Mode: "ro", RW: false, Propagation: "rprivate",
      },
    ]) &&
    isDeepStrictEqual(sortedBinds, [
      `${selectedProofDirectory}:/proof:ro`, `${fixture}:/proof/fixture.json:ro`,
    ].sort()) && hostMounts === null && tmpfs === null
  );
}

function exactIntrinsicVolumes(mounts, expectedDestinations) {
  if (!Array.isArray(mounts) || expectedDestinations === undefined || mounts.length !== expectedDestinations.length) {
    return undefined;
  }
  const ordered = [...mounts].sort((left, right) => String(left?.Destination).localeCompare(String(right?.Destination)));
  if (!isDeepStrictEqual(ordered.map((mount) => mount?.Destination), expectedDestinations)) return undefined;
  const names = [];
  for (const mount of ordered) {
    if (
      !plainObject(mount) ||
      !isDeepStrictEqual(Object.keys(mount).sort(), [
        "Destination", "Driver", "Mode", "Name", "Propagation", "RW", "Source", "Type",
      ]) ||
      mount.Type !== "volume" || mount.Driver !== "local" || mount.Mode !== "" ||
      mount.RW !== true || mount.Propagation !== "" || !objectIDPattern.test(mount.Name ?? "") ||
      mount.Source !== `/var/lib/docker/volumes/${mount.Name}/_data`
    ) return undefined;
    names.push(mount.Name);
  }
  return new Set(names).size === names.length ? Object.freeze(names) : undefined;
}

function parsePairs(value) {
  if (typeof value !== "string" || value === "") return [];
  const lines = value.endsWith("\n") ? value.slice(0, -1).split("\n") : value.split("\n");
  if (lines.some((line) => line === "" || line.split("|").length !== 2)) throw new Failure("ownership");
  return lines.map((line) => line.split("|"));
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function highPort(value) {
  return typeof value === "string" && /^[0-9]{4,5}$/.test(value) && Number(value) >= 1024 && Number(value) <= 65_535;
}

if (process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await runMain();
}
