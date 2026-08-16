import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

export const IMAGE = "neo4j:5.26.28-community@sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357";
export const SUCCESS_LINE = "Neo4j GraphStore proof passed: nodes=3 edges=2 replay=true scoped=true cross_organization_zero=true cleanup=true audit=true.";
const proofLabel = "com.zasp.proof=neo4j-graphstore";
const markerLabel = "com.zasp.marker";
const namePrefix = "zasp-m1-16-";
const markerPattern = /^[0-9a-f]{16}$/;
const fullIDPattern = /^[0-9a-f]{64}$/;
const outputLimit = 4 * 1024;
const dockerOutputLimit = 256 * 1024;
const proofDirectory = dirname(fileURLToPath(import.meta.url));
const proofEnvironment = Object.freeze([
  "NEO4J_AUTH=none",
  "NEO4J_db_tx__log_preallocate=false",
  "NEO4J_db_tx__log_rotation_size=128K",
]);
const forbiddenEnvironment = /^(?:AWS_|AZURE_|GOOGLE_|HTTP_PROXY$|HTTPS_PROXY$|ALL_PROXY$|NO_PROXY$|DOCKER_AUTH_CONFIG$|NEO4J_(?:URI|USERNAME|PASSWORD)$)/i;
const nativeFileSystem = Object.freeze({
  tmpdir,
  realpath: realpathSync,
  readdir: readdirSync,
  mkdtemp: mkdtempSync,
  mkdir: mkdirSync,
  lstat: lstatSync,
  remove: rmSync,
});

class Failure extends Error {
  constructor(category) {
    super(category);
    this.category = category;
  }
}

export function buildCreateArguments(name, marker) {
  if (name !== `${namePrefix}${marker}-neo4j` || !markerPattern.test(marker)) throw new Failure("configuration");
  return [
    "create", "--name", name,
    "--label", proofLabel, "--label", `${markerLabel}=${marker}`,
    "--publish", "127.0.0.1::7474", "--publish", "127.0.0.1::7687",
    ...proofEnvironment.flatMap((value) => ["--env", value]),
    "--security-opt", "no-new-privileges:true",
    "--pids-limit", "512",
    "--memory", "1g",
    "--cpus", "2",
    IMAGE,
  ];
}

export function buildEnvironment(path, home) {
  return {
    PATH: path,
    HOME: home,
    GOENV: "off",
    GOPROXY: "off",
    GOSUMDB: "off",
    GOTOOLCHAIN: "local",
    CGO_ENABLED: "0",
  };
}

export function classifyMutation(result) {
  if (result?.status !== 0) return result?.status !== null && result?.signal === null && !result?.thrown ? "definitive" : "ambiguous";
  if (result.signal !== null || result.thrown || result.stderr !== "") return "ambiguous";
  return fullIDPattern.test(result.stdout.trim()) ? "applied" : "ambiguous";
}

export function classifyCommandMutation(result, acknowledgement = "") {
  if (result?.status !== 0) return result?.status !== null && result?.signal === null && !result?.thrown ? "definitive" : "ambiguous";
  if (result.signal !== null || result.thrown) return "ambiguous";
  if (acknowledgement === "any") return "applied";
  return result.stderr === "" && result.stdout.trim() === acknowledgement ? "applied" : "ambiguous";
}

function classifyEmptyMutation(result) {
  if (result?.status !== 0) return result?.status !== null && result?.signal === null && !result?.thrown ? "definitive" : "ambiguous";
  return result.signal === null && !result.thrown && result.stdout === "" && result.stderr === "" ? "applied" : "ambiguous";
}

export function parseReadiness(status, body) {
  if (status !== 200 || !Buffer.isBuffer(body) || body.length === 0 || body.length > 16 * 1024) return false;
  let value;
  try {
    value = parseUniqueJson(body.toString("utf8"));
  } catch {
    return false;
  }
  if (!plainObject(value) || !isDeepStrictEqual(Object.keys(value).sort(), ["errors", "lastBookmarks", "results"])) return false;
  const result = value.results?.[0];
  const data = result?.data?.[0];
  const bookmark = value.lastBookmarks?.[0];
  return Array.isArray(value.errors) && value.errors.length === 0
    && Array.isArray(value.results) && value.results.length === 1 && plainObject(result)
    && isDeepStrictEqual(Object.keys(result).sort(), ["columns", "data"])
    && isDeepStrictEqual(result.columns, ["ready"])
    && Array.isArray(result.data) && result.data.length === 1 && plainObject(data)
    && isDeepStrictEqual(Object.keys(data).sort(), ["meta", "row"])
    && isDeepStrictEqual(data.row, [1]) && isDeepStrictEqual(data.meta, [null])
    && Array.isArray(value.lastBookmarks) && value.lastBookmarks.length === 1
    && typeof bookmark === "string" && bookmark.length > 0 && bookmark.length <= 4_096
    && !hasControlCharacter(bookmark);
}

export function runBounded(command, arguments_, options, spawnImplementation = spawn) {
  return new Promise((resolvePromise) => {
    let child;
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let settled = false;
    let thrown = false;
    let forcedSignal = null;
    let timer;
    const abort = () => kill();
    const finish = (status, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener?.("abort", abort);
      resolvePromise({ status, signal: forcedSignal ?? signal ?? null, thrown, stdout: stdout.toString("utf8"), stderr: stderr.toString("utf8") });
    };
    const kill = () => {
      if (forcedSignal !== null) return;
      forcedSignal = "SIGKILL";
      try { child?.kill("SIGKILL"); } catch { thrown = true; finish(null, "SIGKILL"); }
    };
    const append = (stream, chunk) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (stdout.length + stderr.length + bytes.length > options.outputLimit) {
        kill();
        return;
      }
      if (stream === "stdout") stdout = Buffer.concat([stdout, bytes]);
      else stderr = Buffer.concat([stderr, bytes]);
    };
    timer = setTimeout(kill, options.timeoutMs);
    try {
      child = spawnImplementation(command, arguments_, { cwd: options.cwd, env: options.env, stdio: ["ignore", "pipe", "pipe"] });
      child.stdout.on("data", (chunk) => append("stdout", chunk));
      child.stderr.on("data", (chunk) => append("stderr", chunk));
      child.stdout.once("error", () => { thrown = true; kill(); });
      child.stderr.once("error", () => { thrown = true; kill(); });
      child.once("error", () => { thrown = true; kill(); });
      child.once("close", finish);
      options.signal?.addEventListener?.("abort", abort, { once: true });
      if (options.signal?.aborted) abort();
    } catch {
      thrown = true;
      finish(null, null);
    }
  });
}

export async function orchestrate(runtime, options = {}) {
  const mainTimeoutMs = options.mainTimeoutMs ?? 120_000;
  const cleanupTimeoutMs = options.cleanupTimeoutMs ?? 60_000;
  let category = null;
  let cleanupFailed = false;
  let absenceProved = false;
  try {
    await phase(mainTimeoutMs, async (signal) => {
      await runtime.preflight(signal);
      await runtime.initialize(signal);
      await runtime.dockerPreflight(signal);
      await runtime.fingerprintShared("before", signal);
      await runtime.resolveImage(signal);
      await runtime.create(signal);
      await runtime.verify("created", signal);
      await runtime.start(signal);
      await runtime.verify("running", signal);
      await runtime.ports(signal);
      await runtime.ready(signal);
      await runtime.build(signal);
      await runtime.proof(signal);
    });
  } catch (error) {
    category = failureCategory(error);
  }
  try {
    await phase(cleanupTimeoutMs, async (signal) => {
      await stepCleanup(() => runtime.settle(signal), () => { cleanupFailed = true; });
      await stepCleanup(() => runtime.remove(signal), () => { cleanupFailed = true; });
      await stepCleanup(() => runtime.absent(signal), () => { cleanupFailed = true; });
      await stepCleanup(() => runtime.prefixAbsent(signal), () => { cleanupFailed = true; });
      await stepCleanup(() => runtime.fingerprintShared("after", signal), () => { cleanupFailed = true; });
      absenceProved = !cleanupFailed;
      await stepCleanup(() => runtime.removeTemp(absenceProved), () => { cleanupFailed = true; });
      await stepCleanup(() => runtime.tempPrefixAbsent(signal), () => { cleanupFailed = true; });
    });
  } catch {
    cleanupFailed = true;
  }
  if (cleanupFailed) return { code: 1, line: "Neo4j GraphStore proof failed: cleanup rejected." };
  if (category !== null) return { code: 1, line: `Neo4j GraphStore proof failed: ${category} rejected.` };
  return { code: 0, line: SUCCESS_LINE };
}

export async function runMain(runtime, options = {}) {
  let result;
  try {
    const selected = runtime ?? (options.runtimeFactory ?? (() => new DockerRuntime()))();
    result = await orchestrate(selected, options);
  } catch (error) {
    result = { code: 1, line: `Neo4j GraphStore proof failed: ${failureCategory(error)} rejected.` };
  }
  (options.write ?? ((value) => process.stdout.write(value)))(`${result.line}\n`);
  return result.code;
}

export class DockerRuntime {
  constructor({
    path = process.env.PATH,
    home = process.env.HOME,
    marker = randomBytes(8).toString("hex"),
    environment = process.env,
    command = runBounded,
    fileSystem = nativeFileSystem,
  } = {}) {
    if (typeof path !== "string" || path === "" || typeof home !== "string" || home === "" || !markerPattern.test(marker)
        || !plainObject(environment) || typeof command !== "function"
        || !validFileSystem(fileSystem)
        || Object.keys(environment).some((key) => forbiddenEnvironment.test(key))) throw new Failure("configuration");
    this.path = path;
    this.home = home;
    this.marker = marker;
    this.name = `${namePrefix}${marker}-neo4j`;
    this.dockerConfig = null;
    this.dockerConfigIdentity = null;
    this.buildIdentity = null;
    this.tempRoot = null;
    this.tempParent = null;
    this.tempIdentity = null;
    this.tempReady = false;
    this.image = null;
    this.token = null;
    this.volumeTokens = [];
    this.httpPort = null;
    this.boltPort = null;
    this.shared = null;
    this.createUncertain = false;
    this.pending = new Set();
    this.command = command;
    this.fileSystem = fileSystem;
  }

  async docker(arguments_, timeoutMs = 30_000, signal) {
    if (this.dockerConfig === null) throw new Failure("configuration");
    if (this.dockerConfigIdentity !== null) this.requireDockerConfig();
    return this.command("docker", arguments_, { timeoutMs, outputLimit: dockerOutputLimit, signal, env: { PATH: this.path, DOCKER_CONFIG: this.dockerConfig } });
  }

  async preflight() {
    if (this.fileSystem.readdir(this.fileSystem.tmpdir()).some((entry) => entry.startsWith(namePrefix))) throw new Failure("ownership");
  }

  async initialize(signal) {
    assertActive(signal);
    const parent = this.fileSystem.realpath(this.fileSystem.tmpdir());
    const candidate = this.fileSystem.mkdtemp(join(parent, namePrefix));
    this.tempRoot = candidate;
    this.tempParent = parent;
    this.tempIdentity = ownedDirectory(candidate, parent, this.fileSystem);
    this.dockerConfig = join(candidate, "docker");
    this.fileSystem.mkdir(this.dockerConfig, { mode: 0o700 });
    this.dockerConfigIdentity = ownedChildDirectory(this.dockerConfig, this.tempIdentity, "docker", this.fileSystem);
    const build = join(candidate, "build");
    this.fileSystem.mkdir(build, { mode: 0o700 });
    this.buildIdentity = ownedChildDirectory(build, this.tempIdentity, "build", this.fileSystem);
    this.tempReady = true;
    assertActive(signal);
  }

  async dockerPreflight(signal) {
    await this.prefixAbsent(signal, "ownership");
  }

  async resolveImage(signal) {
    assertActive(signal);
    let inspected = await this.docker(["image", "inspect", IMAGE, "--format", "{{json .}}"], 30_000, signal);
    if (inspected.status !== 0) {
      if (inspected.signal !== null || inspected.thrown || !/No such image/i.test(inspected.stderr)) throw new Failure("provider");
      let pulled;
      try {
        pulled = await this.mutate(() => this.docker(["pull", IMAGE], 180_000, signal));
      } catch {
        pulled = { status: null, signal: null, thrown: true, stdout: "", stderr: "" };
      }
      if (classifyCommandMutation(pulled, "any") === "definitive") throw new Failure("provider");
      inspected = await this.docker(["image", "inspect", IMAGE, "--format", "{{json .}}"], 30_000, signal);
    }
    if (inspected.status !== 0 || inspected.signal !== null || inspected.thrown || inspected.stderr !== "") throw new Failure("provider");
    const value = parseOneJsonLine(inspected.stdout);
    if (!plainObject(value) || typeof value.Id !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value.Id)
        || !Array.isArray(value.RepoDigests)
        || !value.RepoDigests.some((digest) => typeof digest === "string" && digest.endsWith(`@${IMAGE.split("@")[1]}`))
        || !plainObject(value.Config)) throw new Failure("ownership");
    this.image = {
      id: value.Id,
      env: arrayOfStrings(value.Config.Env ?? []),
      entrypoint: nullableStrings(value.Config.Entrypoint),
      cmd: nullableStrings(value.Config.Cmd),
      labels: plainObject(value.Config.Labels) ? value.Config.Labels : {},
      exposed: sortedKeys(value.Config.ExposedPorts),
      volumes: sortedKeys(value.Config.Volumes),
    };
  }

  async create(signal) {
    assertActive(signal);
    this.createUncertain = true;
    let result;
    try {
      result = await this.mutate(() => this.docker(buildCreateArguments(this.name, this.marker), 30_000, signal));
    } catch {
      result = { status: null, signal: null, thrown: true, stdout: "", stderr: "" };
    }
    const classification = classifyMutation(result);
    if (classification === "definitive") {
      this.createUncertain = false;
      throw new Failure("provider");
    }
    if (classification === "applied") this.token = result.stdout.trim();
    else this.token = await this.findName(signal);
    if (!fullIDPattern.test(this.token ?? "")) throw new Failure("ownership");
    assertActive(signal);
  }

  async start(signal) {
    await this.verify("created", signal);
    assertActive(signal);
    const result = await this.mutate(() => this.docker(["start", this.token], 30_000, signal));
    const classification = classifyCommandMutation(result, this.token);
    if (classification === "definitive") throw new Failure("provider");
    if (classification === "ambiguous") await this.verify("running", signal);
  }

  async verify(state, signal) {
    assertActive(signal);
    if (!fullIDPattern.test(this.token ?? "") || this.image === null) throw new Failure("ownership");
    const inspected = await this.docker(["container", "inspect", this.token, "--format", "{{json .}}"], 30_000, signal);
    if (inspected.status !== 0 || inspected.signal !== null || inspected.thrown || inspected.stderr !== "") throw new Failure("ownership");
    const value = parseOneJsonLine(inspected.stdout);
    const tokens = validateContainerMetadata(value, {
      token: this.token,
      marker: this.marker,
      name: this.name,
      image: this.image,
      state,
    });
    if (this.volumeTokens.length === 0) this.volumeTokens = tokens;
    else if (!isDeepStrictEqual(tokens, this.volumeTokens)) throw new Failure("ownership");
  }

  async ports(signal) {
    await this.verify("running", signal);
    const inspected = await this.docker(["container", "inspect", this.token, "--format", "{{json .NetworkSettings.Ports}}"], 30_000, signal);
    if (!exactReadSuccess(inspected)) throw new Failure("ownership");
    const value = parseOneJsonLine(inspected.stdout);
    if (!plainObject(value)) throw new Failure("ownership");
    const exposed = Object.keys(value).sort();
    if (!isDeepStrictEqual(exposed, this.image.exposed)) throw new Failure("ownership");
    this.httpPort = exactLoopbackPort(value["7474/tcp"]);
    this.boltPort = exactLoopbackPort(value["7687/tcp"]);
    for (const key of exposed) {
      if (key !== "7474/tcp" && key !== "7687/tcp" && value[key] !== null) throw new Failure("ownership");
    }
  }

  async ready(signal) {
    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline) {
      assertActive(signal);
      if (await readinessProbe(this.httpPort, signal)) return;
      await wait(250, signal);
    }
    throw new Failure("provider");
  }

  async build(signal) {
    this.requireTemp();
    assertActive(signal);
    const binary = join(this.tempRoot, "build", "proof");
    const result = await runBounded("go", ["build", "-C", proofDirectory, "-o", binary, "."], {
      timeoutMs: 120_000, outputLimit, env: buildEnvironment(this.path, this.home),
      signal,
    });
    if (classifyEmptyMutation(result) !== "applied") throw new Failure("operation");
    this.binary = binary;
  }

  async proof(signal) {
    this.requireTemp();
    await this.verify("running", signal);
    assertActive(signal);
    const result = await runBounded(this.binary, [], {
      timeoutMs: 300_000, outputLimit, env: { NEO4J_GRAPHSTORE_URI: `bolt://127.0.0.1:${this.boltPort}` },
      signal,
    });
    if (result.status !== 0 || result.signal !== null || result.thrown || result.stderr !== "" || result.stdout !== `${SUCCESS_LINE}\n`) {
      throw new Failure(fixedChildCategory(result.stdout));
    }
  }

  async settle() {
    await Promise.allSettled([...this.pending]);
  }

  async remove(signal) {
    if (this.token === null && this.createUncertain) {
      this.token = await this.findName(signal);
      if (this.token === null) {
        this.createUncertain = false;
        return;
      }
    }
    if (this.token === null) return;
    await this.verifyAnyOwned(signal);
    assertActive(signal);
    let result;
    try {
      result = await this.mutate(() => this.docker(["rm", "--force", "--volumes", this.token], 30_000, signal));
    } catch {
      result = { status: null, signal: null, thrown: true, stdout: "", stderr: "" };
    }
    const classification = classifyCommandMutation(result, this.token);
    if (classification === "definitive") throw new Failure("cleanup");
    await this.absent(signal);
    this.createUncertain = false;
  }

  async absent(signal) {
    assertActive(signal);
    if (this.token !== null) {
      const result = await this.docker(["container", "inspect", this.token, "--format", "{{json .Id}}"], 30_000, signal);
      if (!exactMissing(result, "container")) throw new Failure("cleanup");
    }
    for (const volume of this.volumeTokens) {
      const result = await this.docker(["volume", "inspect", volume, "--format", "{{json .Name}}"], 30_000, signal);
      if (!exactMissing(result, "volume")) throw new Failure("cleanup");
    }
  }

  async prefixAbsent(signal, category = "cleanup") {
    assertActive(signal);
    const byName = await this.docker(["ps", "-aq", "--no-trunc", "--filter", `name=^/${namePrefix}`], 30_000, signal);
    const byLabel = await this.docker(["ps", "-aq", "--no-trunc", "--filter", `label=${proofLabel}`], 30_000, signal);
    const byMarker = await this.docker(["ps", "-aq", "--no-trunc", "--filter", `label=${markerLabel}=${this.marker}`], 30_000, signal);
    if (![byName, byLabel, byMarker].every((result) => result.status === 0 && result.signal === null && !result.thrown && result.stderr === "" && result.stdout.trim() === "")) {
      throw new Failure(category);
    }
  }

  async fingerprintShared(when, signal) {
    if (this.dockerConfig === null) {
      if (when === "before") return;
      throw new Failure("cleanup");
    }
    const listed = await this.docker(["ps", "-a", "--no-trunc", "--format", "{{json .}}"], 30_000, signal);
    if (!exactReadSuccess(listed)) throw new Failure(when === "before" ? "provider" : "cleanup");
    const fingerprints = [];
    for (const line of listed.stdout.trim().split("\n").filter(Boolean)) {
      const entry = parseUniqueJson(line);
      if (!plainObject(entry) || typeof entry.Image !== "string" || typeof entry.Names !== "string" || !fullIDPattern.test(entry.ID ?? "")) throw new Failure("ownership");
      if (!entry.Image.startsWith("neo4j:") || entry.Names.startsWith(namePrefix)) continue;
      const inspected = await this.docker(["container", "inspect", entry.ID, "--format", "{{json .State.StartedAt}}|{{json .RestartCount}}|{{json .Image}}|{{json .State.Status}}"], 30_000, signal);
      if (!exactReadSuccess(inspected)) throw new Failure("ownership");
      fingerprints.push(JSON.stringify({ id: entry.ID, name: entry.Names, state: inspected.stdout.trim() }));
    }
    fingerprints.sort();
    if (when === "before") this.shared = fingerprints;
    else if (!isDeepStrictEqual(fingerprints, this.shared)) throw new Failure("cleanup");
  }

  async removeTemp(allowed) {
    if (this.tempRoot === null) return;
    if (!allowed) return;
    if (this.tempIdentity === null) {
      if (this.tempParent === null) throw new Failure("cleanup");
      this.tempIdentity = ownedDirectory(this.tempRoot, this.tempParent, this.fileSystem);
    }
    if (this.tempReady) this.requireTemp();
    else if (!sameOwnedDirectory(this.tempRoot, this.tempIdentity, this.fileSystem)) throw new Failure("cleanup");
    this.fileSystem.remove(this.tempRoot, { recursive: true, force: false, maxRetries: 0 });
    this.tempRoot = null;
  }

  async tempPrefixAbsent() {
    if (this.fileSystem.readdir(this.fileSystem.tmpdir()).some((entry) => entry.startsWith(namePrefix))) throw new Failure("cleanup");
  }

  async verifyAnyOwned(signal) {
    for (const state of ["running", "exited", "created"]) {
      try { await this.verify(state, signal); return; } catch (error) { if (!(error instanceof Failure)) throw error; }
    }
    throw new Failure("cleanup");
  }

  async findName(signal) {
    const result = await this.docker(["ps", "-aq", "--no-trunc", "--filter", `name=^/${this.name}$`], 30_000, signal);
    const tokens = result.stdout.trim().split("\n").filter(Boolean);
    if (result.status !== 0 || result.signal !== null || result.thrown || result.stderr !== "" || tokens.length > 1
        || (tokens.length === 1 && !fullIDPattern.test(tokens[0]))) throw new Failure("ownership");
    if (tokens.length === 0) return null;
    return tokens[0];
  }

  async mutate(call) {
    const promise = Promise.resolve().then(call);
    this.pending.add(promise);
    try { return await promise; } finally { this.pending.delete(promise); }
  }

  requireTemp() {
    if (!this.tempReady || this.tempRoot === null || this.tempIdentity === null || this.dockerConfigIdentity === null || this.buildIdentity === null
        || !sameOwnedDirectory(this.tempRoot, this.tempIdentity, this.fileSystem)
        || !sameOwnedDirectory(this.dockerConfig, this.dockerConfigIdentity, this.fileSystem)
        || !sameOwnedDirectory(join(this.tempRoot, "build"), this.buildIdentity, this.fileSystem)) throw new Failure("ownership");
  }

  requireDockerConfig() {
    if (this.tempRoot === null || this.tempIdentity === null || this.dockerConfig === null || this.dockerConfigIdentity === null
        || !sameOwnedDirectory(this.tempRoot, this.tempIdentity, this.fileSystem)
        || !sameOwnedDirectory(this.dockerConfig, this.dockerConfigIdentity, this.fileSystem)
        || !emptyDirectory(this.dockerConfig, this.fileSystem)) throw new Failure("ownership");
  }
}

async function phase(timeoutMs, operation) {
  const controller = new AbortController();
  let timeout;
  const deadline = new Promise((_, rejectPromise) => {
    timeout = setTimeout(() => {
      controller.abort();
      rejectPromise(new Failure("operation"));
    }, timeoutMs);
  });
  const pending = Promise.resolve().then(() => operation(controller.signal));
  pending.catch(() => {});
  try {
    return await Promise.race([pending, deadline]);
  } finally {
    clearTimeout(timeout);
  }
}

async function stepCleanup(call, onFailure) {
  try { await call(); } catch { onFailure(); }
}

function failureCategory(error) {
  const category = error instanceof Failure ? error.category : error instanceof Error ? error.message : "operation";
  return ["configuration", "provider", "ownership", "operation", "cleanup"].includes(category) ? category : "operation";
}

function fixedChildCategory(stdout) {
  const match = /^Neo4j GraphStore proof failed: (configuration|provider|ownership|operation|cleanup) rejected\.\n$/.exec(stdout);
  return match?.[1] ?? "operation";
}

function assertActive(signal) {
  if (signal?.aborted) throw new Failure("operation");
}

function ownedDirectory(path, parent, fileSystem) {
  if (!isAbsolute(path) || fileSystem.realpath(dirname(path)) !== parent || !basename(path).startsWith(namePrefix)) throw new Failure("ownership");
  const stat = fileSystem.lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || fileSystem.realpath(path) !== path) throw new Failure("ownership");
  return { dev: stat.dev, ino: stat.ino, path };
}

function ownedChildDirectory(path, parent, name, fileSystem) {
  if (dirname(path) !== parent.path || basename(path) !== name) throw new Failure("ownership");
  const stat = fileSystem.lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || fileSystem.realpath(path) !== path || !emptyDirectory(path, fileSystem)) throw new Failure("ownership");
  return { dev: stat.dev, ino: stat.ino, path };
}

function sameOwnedDirectory(path, identity, fileSystem) {
  try {
    const stat = fileSystem.lstat(path);
    return stat.isDirectory() && !stat.isSymbolicLink() && fileSystem.realpath(path) === identity.path && stat.dev === identity.dev && stat.ino === identity.ino;
  } catch { return false; }
}

function emptyDirectory(path, fileSystem) {
  try {
    const entries = fileSystem.readdir(path);
    return Array.isArray(entries) && entries.length === 0;
  } catch { return false; }
}

function validFileSystem(value) {
  return plainObject(value) && ["tmpdir", "realpath", "readdir", "mkdtemp", "mkdir", "lstat", "remove"].every((key) => typeof value[key] === "function");
}

export function validateContainerMetadata(value, expected) {
  try {
    const labels = { ...expected.image.labels, "com.zasp.proof": "neo4j-graphstore", "com.zasp.marker": expected.marker };
    const environment = arrayOfStrings(value?.Config?.Env).sort();
    const wantedEnvironment = [...proofEnvironment, ...expected.image.env].sort();
    const host = value?.HostConfig;
    if (!plainObject(value) || !plainObject(value.Config) || !plainObject(value.State) || !plainObject(host)
        || value.Id !== expected.token || value.Name !== `/${expected.name}` || value.Image !== expected.image.id
        || value.Config.Image !== IMAGE || value.State.Status !== expected.state
        || value.State.Running !== (expected.state === "running")
        || !isDeepStrictEqual(value.Config.Labels, labels)
        || !isDeepStrictEqual(environment, wantedEnvironment)
        || !isDeepStrictEqual(nullableStrings(value.Config.Entrypoint), expected.image.entrypoint)
        || !isDeepStrictEqual(nullableStrings(value.Config.Cmd), expected.image.cmd)
        || host.Privileged !== false || host.ReadonlyRootfs !== false || host.NetworkMode !== "bridge"
        || host.Binds !== null || Object.hasOwn(host, "Mounts") || Object.hasOwn(host, "Tmpfs")
        || !isDeepStrictEqual(host.SecurityOpt, ["no-new-privileges:true"])
        || host.PidsLimit !== 512 || host.Memory !== 1_073_741_824 || host.NanoCpus !== 2_000_000_000
        || !Array.isArray(value.Mounts) || value.Mounts.length !== expected.image.volumes.length) throw new Error("invalid container");
    const mountKeys = ["Destination", "Driver", "Mode", "Name", "Propagation", "RW", "Source", "Type"];
    const destinations = [];
    const tokens = [];
    for (const mount of value.Mounts) {
      if (!plainObject(mount) || !isDeepStrictEqual(Object.keys(mount).sort(), mountKeys)
          || mount.Type !== "volume" || !fullIDPattern.test(mount.Name ?? "")
          || mount.Source !== `/var/lib/docker/volumes/${mount.Name}/_data`
          || mount.Driver !== "local" || mount.Mode !== "" || mount.RW !== true || mount.Propagation !== ""
          || typeof mount.Destination !== "string") throw new Error("invalid mount");
      tokens.push(mount.Name);
      destinations.push(mount.Destination);
    }
    if (!isDeepStrictEqual(destinations.sort(), [...expected.image.volumes].sort()) || new Set(tokens).size !== tokens.length) throw new Error("invalid mounts");
    return tokens.sort();
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new Failure("ownership");
  }
}

function exactLoopbackPort(value) {
  if (!Array.isArray(value) || value.length !== 1 || !plainObject(value[0]) || Object.keys(value[0]).sort().join("|") !== "HostIp|HostPort"
      || value[0].HostIp !== "127.0.0.1" || !/^[1-9][0-9]{0,4}$/.test(value[0].HostPort)) throw new Failure("ownership");
  const port = Number(value[0].HostPort);
  if (port > 65535) throw new Failure("ownership");
  return port;
}

function exactMissing(result, kind) {
  if (result.status === 0 || result.signal !== null || result.thrown || result.stdout.trim() !== "") return false;
  return kind === "container" ? /No such (?:object|container)/i.test(result.stderr) : /no such volume/i.test(result.stderr);
}

function exactReadSuccess(result) {
  return result?.status === 0 && result.signal === null && !result.thrown && result.stderr === "";
}

async function readinessProbe(port, parentSignal) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  parentSignal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(abort, 500);
  try {
    const response = await fetch(`http://127.0.0.1:${port}/db/neo4j/tx/commit`, {
      method: "POST", redirect: "error", signal: controller.signal,
      headers: { "content-type": "application/json", accept: "application/json" },
      body: '{"statements":[{"statement":"RETURN 1 AS ready"}]}',
    });
    const reader = response.body?.getReader();
    if (!reader) return false;
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > 16 * 1024) { await reader.cancel(); return false; }
      chunks.push(Buffer.from(value));
    }
    return parseReadiness(response.status, Buffer.concat(chunks));
  } catch { return false; }
  finally {
    clearTimeout(timer);
    parentSignal?.removeEventListener("abort", abort);
  }
}

function wait(milliseconds, signal) {
  return new Promise((resolvePromise, rejectPromise) => {
    const timer = setTimeout(resolvePromise, milliseconds);
    signal?.addEventListener("abort", () => { clearTimeout(timer); rejectPromise(new Failure("operation")); }, { once: true });
  });
}

function parseOneJsonLine(stdout) {
  if (typeof stdout !== "string" || Buffer.byteLength(stdout) > 256 * 1024 || !stdout.endsWith("\n") || stdout.slice(0, -1).includes("\n")) throw new Failure("ownership");
  return parseUniqueJson(stdout.slice(0, -1));
}

function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function hasControlCharacter(value) {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}
function arrayOfStrings(value) { if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) throw new Failure("ownership"); return [...value]; }
function nullableStrings(value) { return value === null ? null : arrayOfStrings(value); }
function sortedKeys(value) { if (value === null || value === undefined) return []; if (!plainObject(value)) throw new Failure("ownership"); return Object.keys(value).sort(); }

function parseUniqueJson(source) {
  if (typeof source !== "string") throw new SyntaxError("invalid JSON");
  let index = 0;
  const whitespace = () => { while (index < source.length && /[\t\n\r ]/.test(source[index])) index += 1; };
  const string = () => {
    if (source[index] !== '"') throw new SyntaxError("invalid JSON string");
    const start = index++;
    while (index < source.length) {
      const character = source[index];
      if (character === '"') { index += 1; return JSON.parse(source.slice(start, index)); }
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError("invalid JSON string");
      if (character !== "\\") { index += 1; continue; }
      index += 1;
      const escape = source[index];
      if ('"\\/bfnrt'.includes(escape ?? "")) index += 1;
      else if (escape === "u" && /^[a-fA-F0-9]{4}$/.test(source.slice(index + 1, index + 5))) index += 5;
      else throw new SyntaxError("invalid JSON escape");
    }
    throw new SyntaxError("unterminated JSON string");
  };
  const value = () => {
    whitespace();
    if (source[index] === "{") {
      index += 1; whitespace(); const keys = new Set();
      if (source[index] === "}") { index += 1; return; }
      while (true) {
        const key = string(); if (keys.has(key)) throw new SyntaxError("duplicate JSON key"); keys.add(key); whitespace();
        if (source[index] !== ":") throw new SyntaxError("invalid JSON object"); index += 1; value(); whitespace();
        if (source[index] === "}") { index += 1; return; }
        if (source[index] !== ",") throw new SyntaxError("invalid JSON object"); index += 1; whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1; whitespace(); if (source[index] === "]") { index += 1; return; }
      while (true) { value(); whitespace(); if (source[index] === "]") { index += 1; return; } if (source[index] !== ",") throw new SyntaxError("invalid JSON array"); index += 1; }
    }
    if (source[index] === '"') { string(); return; }
    for (const literal of ["true", "false", "null"]) { if (source.startsWith(literal, index)) { index += literal.length; return; } }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(index));
    if (!number) throw new SyntaxError("invalid JSON value"); index += number[0].length;
  };
  value(); whitespace(); if (index !== source.length) throw new SyntaxError("invalid trailing JSON");
  return JSON.parse(source);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runMain();
}
