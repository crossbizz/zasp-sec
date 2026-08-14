import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { lstat, mkdtemp, readdir, realpath, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { mergeNormalizedGraphs, normalizeGraph, parseRawGraph } from "./normalizer.mjs";

export const CARTOGRAPHY_IMAGE = "ghcr.io/cartography-cncf/cartography:0.139.1@sha256:f1d7c1f46a8a2137b9a955327d3cd47e8340c7d537d0447467d2e952af8bb8f0";
export const NEO4J_IMAGE = "neo4j:5.26-community@sha256:d9dd3dc7d1c78fa959191ff02dbdcbefadceaf83eee23428fb92a58cac8ad3fe";
export const SUCCESS_LINE = "Cartography scope proof passed: fixtures=2 nodes=8 relationships=4 isolated=true labels_safe=true cleanup=true.";
export const CARTOGRAPHY_BOOTSTRAP = 'import os,re,runpy,sys;h=os.environ.get("HOSTNAME","");e=sys.argv[1];(h==e and re.fullmatch(r"zasp-m0-10-[0-9a-f]{16}-cartography-[ab]",h)) or sys.exit(1);os.environ.clear();os.environ.update({"PATH":"/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","HOME":"/tmp","LANG":"C.UTF-8","PYTHONUNBUFFERED":"1","HOSTNAME":h});sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name="__main__")';

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
const forbiddenCredentialEnvironmentPattern = /^(AWS_|GITHUB_|DOCKER_|HTTP_PROXY=|HTTPS_PROXY=|ALL_PROXY=|NO_PROXY=)/i;
const organizationBySlot = Object.freeze({
  a: "org_aaaaaaaaaaaaaaaa",
  b: "org_bbbbbbbbbbbbbbbb",
});

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
    "--env", "NEO4J_AUTH=none",
    "--label", "zasp.proof=m0-10",
    "--label", `zasp.marker=${marker}`,
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
    CARTOGRAPHY_IMAGE,
    "-I", "-c", CARTOGRAPHY_BOOTSTRAP,
    name,
    "/proof/fixture_runner.py",
    "--fixture", `/proof/fixtures/org-${slot}.json`,
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
  } = {}) {
    if (
      typeof path !== "string" || path.length === 0 ||
      !markerPattern.test(marker) ||
      typeof selectedProofDirectory !== "string" || !isAbsolute(selectedProofDirectory) || resolve(selectedProofDirectory) !== selectedProofDirectory ||
      typeof tempParent !== "string" || !isAbsolute(tempParent) || resolve(tempParent) !== tempParent ||
      ![command, spawnProcess, makeTemp, removeTemp, canonicalPath, statPath, readDirectory, wait].every((value) => typeof value === "function")
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
    this.dockerConfigIdentity = undefined;
    this.networkToken = undefined;
    this.networkAttempted = false;
    this.containerTokens = new Map();
    this.containerAttempts = new Set();
    this.imageIDs = new Map();
    this.signal = undefined;
  }

  setAbortSignal(signal) {
    this.signal = signal;
  }

  name(kind) {
    if (!["neo4j-a", "neo4j-b", "cartography-a", "cartography-b"].includes(kind)) {
      throw new Failure("configuration");
    }
    return `${this.prefix}-${kind}`;
  }

  async initialize() {
    let canonicalParent;
    let canonicalProof;
    try {
      canonicalParent = await this.canonicalPath(this.tempParent);
      canonicalProof = await this.canonicalPath(this.proofDirectory);
    } catch {
      throw new Failure("configuration");
    }
    if (canonicalParent !== this.tempParent || canonicalProof !== this.proofDirectory) {
      throw new Failure("configuration");
    }
    const candidate = await this.makeTemp(join(this.tempParent, `${this.prefix}-docker-config-`));
    const identity = await this.ownedEmptyTemporaryDirectory(candidate);
    if (identity === undefined) throw new Failure("configuration");
    this.dockerConfigIdentity = identity;
  }

  async ownedEmptyTemporaryDirectory(value) {
    if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value) return undefined;
    const requiredPrefix = join(this.tempParent, `${this.prefix}-docker-config-`);
    if (dirname(value) !== this.tempParent || !value.startsWith(requiredPrefix) || value.length === requiredPrefix.length) return undefined;
    try {
      const [canonical, status, entries] = await Promise.all([
        this.canonicalPath(value), this.statPath(value), this.readDirectory(value),
      ]);
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

  async cleanupDockerConfig() {
    if (this.dockerConfigIdentity === undefined) return;
    const current = await this.ownedEmptyTemporaryDirectory(this.dockerConfigIdentity.path);
    if (
      current === undefined || current.dev !== this.dockerConfigIdentity.dev ||
      current.ino !== this.dockerConfigIdentity.ino
    ) {
      throw new Failure("cleanup");
    }
    try {
      await this.removeTemp(current.path, { recursive: true, force: false, maxRetries: 0 });
    } catch {
      throw new Failure("cleanup");
    }
    try {
      await this.statPath(current.path);
      throw new Failure("cleanup");
    } catch (error) {
      if (error instanceof Failure || error?.code !== "ENOENT") throw new Failure("cleanup");
    }
    this.dockerConfigIdentity = undefined;
  }

  async requireTemporaryPrefixAbsent(category = "cleanup") {
    let entries;
    try { entries = await this.readDirectory(this.tempParent); } catch { throw new Failure(category); }
    if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string" || entry.startsWith("zasp-m0-10-"))) {
      throw new Failure(category);
    }
  }

  dockerOptions(options = {}) {
    if (this.dockerConfigIdentity === undefined) throw new Failure(options.category ?? "provider");
    return {
      env: { PATH: this.path, DOCKER_CONFIG: this.dockerConfigIdentity.path },
      timeoutMs: options.timeoutMs ?? dockerTimeoutMs,
      outputLimit: options.outputLimit ?? outputLimit,
      category: options.category ?? "provider",
      ...(this.signal === undefined ? {} : { signal: this.signal }),
    };
  }

  async dockerRead(args, options = {}) {
    return this.command("docker", args, this.dockerOptions(options), this.spawnProcess);
  }

  async readDocker(args, options = {}) {
    let result;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      result = await this.dockerRead(args, options);
      if (result?.status === 0 && result?.signal === null) return result;
      if (attempt === 0) await this.wait(250);
    }
    return result;
  }

  async dockerMutation(args, options = {}) {
    return this.command("docker", args, this.dockerOptions(options), this.spawnProcess);
  }

  async preflight() {
    await this.requirePrefixAbsent();
    let entries;
    try { entries = await this.readDirectory(this.tempParent); } catch { throw new Failure("provider"); }
    const admitted = basename(this.dockerConfigIdentity?.path ?? "");
    if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string" || (entry.startsWith("zasp-m0-10-") && entry !== admitted))) {
      throw new Failure("ownership");
    }
  }

  async resolveImages() {
    await this.resolveImage(NEO4J_IMAGE);
    await this.resolveImage(CARTOGRAPHY_IMAGE);
  }

  async resolveImage(image) {
    const inspectArguments = ["image", "inspect", "--format", "{{.Id}}", image];
    let inspected = await this.readDocker(inspectArguments, { category: "provider" });
    if (inspected?.status !== 0 || inspected?.signal !== null) {
      const pulled = await this.dockerMutation(["pull", image], {
        category: "provider", timeoutMs: imagePullTimeoutMs,
      });
      if (pulled?.status !== 0 || pulled?.signal !== null) throw new Failure("provider");
      inspected = await this.readDocker(inspectArguments, { category: "provider" });
    }
    const identifier = singleLine(inspected?.stdout);
    if (inspected?.status !== 0 || inspected?.signal !== null || inspected?.stderr !== "" || !imageIDPattern.test(identifier)) {
      throw new Failure("provider");
    }
    this.imageIDs.set(image, identifier);
    return identifier;
  }

  async requirePrefixAbsent(category = "ownership") {
    const containers = await this.readDocker([
      "ps", "--all", "--no-trunc", "--filter", "name=^/zasp-m0-10-", "--format", "{{.ID}}|{{.Names}}",
    ], { category });
    const networks = await this.readDocker([
      "network", "ls", "--no-trunc", "--filter", "name=^zasp-m0-10-", "--format", "{{.ID}}|{{.Name}}",
    ], { category });
    if (containers?.status !== 0 || networks?.status !== 0 || containers?.stderr !== "" || networks?.stderr !== "") {
      throw new Failure(category);
    }
    for (const [identifier, name] of [...parsePairs(containers.stdout), ...parsePairs(networks.stdout)]) {
      if (!objectIDPattern.test(identifier)) throw new Failure(category);
      if (name.startsWith("zasp-m0-10-")) throw new Failure(category);
    }
  }

  async createNetwork() {
    this.networkAttempted = true;
    const created = await this.dockerMutation(buildNetworkCreateArguments(this.networkName), { category: "provider" });
    const direct = singleLine(created?.stdout);
    if (objectIDPattern.test(direct)) this.networkToken = direct;
    if (created?.status !== 0 || created?.signal !== null || !objectIDPattern.test(direct)) {
      const candidates = await this.namedNetworkCandidates("ownership");
      if (candidates.length !== 1) throw new Failure("ownership");
      this.networkToken = candidates[0];
    }
    await this.verifyNetwork("ownership");
    return this.networkToken;
  }

  async namedNetworkCandidates(category) {
    const listed = await this.readDocker([
      "network", "ls", "--no-trunc", "--filter", `name=^${this.networkName}$`, "--format", "{{.ID}}|{{.Name}}",
    ], { category });
    if (listed?.status !== 0 || listed?.stderr !== "") throw new Failure(category);
    const pairs = parsePairs(listed.stdout);
    if (pairs.some(([identifier, name]) => !objectIDPattern.test(identifier) || name !== this.networkName)) {
      throw new Failure(category);
    }
    return pairs.map(([identifier]) => identifier);
  }

  async inspectNetwork(token, category) {
    if (!objectIDPattern.test(token ?? "")) throw new Failure(category);
    return this.readDocker([
      "network", "inspect", "--format",
      "{{.Id}}|{{.Name}}|{{index .Labels \"zasp.proof\"}}|{{index .Labels \"zasp.marker\"}}",
      token,
    ], { category });
  }

  async verifyNetwork(category = "ownership", inspectedResult) {
    const inspected = inspectedResult ?? await this.inspectNetwork(this.networkToken, category);
    const fields = singleLine(inspected?.stdout).split("|");
    if (
      inspected?.status !== 0 || inspected?.stderr !== "" || fields.length !== 4 ||
      fields[0] !== this.networkToken || fields[1] !== this.networkName ||
      fields[2] !== "m0-10" || fields[3] !== this.marker
    ) throw new Failure(category);
    return this.networkToken;
  }

  async startNeo4j(slot) {
    validateSlot(slot);
    const kind = `neo4j-${slot}`;
    const name = this.name(kind);
    this.containerAttempts.add(kind);
    const started = await this.dockerMutation(buildNeo4jRunArguments(name, this.networkName), { category: "provider" });
    return this.resolveContainerCreate(kind, started);
  }

  async ensureProofDirectory() {
    try {
      const [canonical, status] = await Promise.all([
        this.canonicalPath(this.proofDirectory), this.statPath(this.proofDirectory),
      ]);
      if (
        canonical !== this.proofDirectory || !status?.isDirectory?.() || status?.isSymbolicLink?.() ||
        !Number.isSafeInteger(status.dev) || !Number.isSafeInteger(status.ino)
      ) throw new Error("invalid");
    } catch {
      throw new Failure("ownership");
    }
  }

  async createCartography(slot) {
    validateSlot(slot);
    await this.ensureProofDirectory();
    const kind = `cartography-${slot}`;
    const name = this.name(kind);
    this.containerAttempts.add(kind);
    const created = await this.dockerMutation(buildCartographyCreateArguments(
      name, this.name(`neo4j-${slot}`), this.networkName, this.proofDirectory, slot,
    ), { category: "provider" });
    return this.resolveContainerCreate(kind, created);
  }

  async resolveContainerCreate(kind, created) {
    const direct = singleLine(created?.stdout);
    if (objectIDPattern.test(direct)) this.containerTokens.set(kind, direct);
    if (created?.status !== 0 || created?.signal !== null || !objectIDPattern.test(direct)) {
      const candidates = await this.namedContainerCandidates(kind, "ownership");
      if (candidates.length !== 1) throw new Failure("ownership");
      this.containerTokens.set(kind, candidates[0]);
    }
    await this.verifyContainer(kind, "ownership");
    return this.containerTokens.get(kind);
  }

  async namedContainerCandidates(kind, category) {
    const name = this.name(kind);
    const listed = await this.readDocker([
      "ps", "--all", "--no-trunc", "--filter", `name=^/${name}$`, "--format", "{{.ID}}|{{.Names}}",
    ], { category });
    if (listed?.status !== 0 || listed?.stderr !== "") throw new Failure(category);
    const pairs = parsePairs(listed.stdout);
    if (pairs.some(([identifier, candidateName]) => !objectIDPattern.test(identifier) || candidateName !== name)) {
      throw new Failure(category);
    }
    return pairs.map(([identifier]) => identifier);
  }

  async inspectContainer(token, category) {
    if (!objectIDPattern.test(token ?? "")) throw new Failure(category);
    return this.readDocker([
      "inspect", "--format",
      "{{.Id}}|{{.Name}}|{{.Config.Hostname}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels \"zasp.proof\"}}|{{index .Config.Labels \"zasp.marker\"}}|{{.HostConfig.NetworkMode}}|{{json .NetworkSettings.Networks}}|{{json .Config.Env}}|{{json .NetworkSettings.Ports}}|{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{json .Mounts}}",
      token,
    ], { category });
  }

  async verifyContainer(kind, category = "ownership", inspectedResult) {
    const token = this.containerTokens.get(kind);
    if (!objectIDPattern.test(token ?? "") || !objectIDPattern.test(this.networkToken ?? "")) {
      throw new Failure(category);
    }
    const expectedImage = kind.startsWith("neo4j-") ? NEO4J_IMAGE : CARTOGRAPHY_IMAGE;
    const imageID = this.imageIDs.get(expectedImage);
    if (!imageIDPattern.test(imageID ?? "")) throw new Failure(category);
    const inspected = inspectedResult ?? await this.inspectContainer(token, category);
    const fields = singleLine(inspected?.stdout).split("|");
    if (inspected?.status !== 0 || inspected?.stderr !== "" || fields.length !== 14) throw new Failure(category);
    let networks;
    let environment;
    let ports;
    let entrypoint;
    let command;
    let mounts;
    try {
      networks = JSON.parse(fields[8]);
      environment = JSON.parse(fields[9]);
      ports = JSON.parse(fields[10]);
      entrypoint = JSON.parse(fields[11]);
      command = JSON.parse(fields[12]);
      mounts = JSON.parse(fields[13]);
    } catch {
      throw new Failure(category);
    }
    if (
      fields[0] !== token || fields[1] !== `/${this.name(kind)}` ||
      fields[2] !== (kind.startsWith("neo4j-") ? token.slice(0, 12) : this.name(kind)) ||
      fields[3] !== imageID || fields[4] !== expectedImage ||
      fields[5] !== "m0-10" || fields[6] !== this.marker ||
      fields[7] !== this.networkName || !plainObject(networks) ||
      Object.keys(networks).length !== 1 || networks[this.networkName]?.NetworkID !== this.networkToken ||
      !Array.isArray(environment) || environment.some((value) => typeof value !== "string") ||
      !plainObject(ports) || !Array.isArray(mounts)
    ) throw new Failure(category);

    if (kind.startsWith("neo4j-")) {
      const auth = environment.filter((value) => value.startsWith("NEO4J_AUTH="));
      const bindings = ports["7687/tcp"];
      if (
        auth.length !== 1 || auth[0] !== "NEO4J_AUTH=none" ||
        environment.some((value) => value !== "NEO4J_AUTH=none" && forbiddenCredentialEnvironmentPattern.test(value)) ||
        Object.entries(ports).some(([port, value]) => port !== "7687/tcp" && value !== null) ||
        !Array.isArray(bindings) || bindings.length !== 1 ||
        bindings[0]?.HostIp !== "127.0.0.1" || !highPort(bindings[0]?.HostPort)
      ) throw new Failure(category);
    } else if (
      environment.some((value) => forbiddenCredentialEnvironmentPattern.test(value)) ||
      Object.values(ports).some((value) => value !== null) ||
      !isDeepStrictEqual(entrypoint, ["python"]) ||
      !isDeepStrictEqual(command, [
        "-I", "-c", CARTOGRAPHY_BOOTSTRAP, this.name(kind), "/proof/fixture_runner.py",
        "--fixture", `/proof/fixtures/org-${kind.at(-1)}.json`,
        "--neo4j-uri", `bolt://${this.name(`neo4j-${kind.at(-1)}`)}:7687`,
      ]) ||
      mounts.length !== 1 || mounts[0]?.Source !== this.proofDirectory ||
      mounts[0]?.Destination !== "/proof" || mounts[0]?.RW !== false || mounts[0]?.Type !== "bind"
    ) throw new Failure(category);
    return token;
  }

  async neo4jPort(slot) {
    validateSlot(slot);
    const kind = `neo4j-${slot}`;
    const token = await this.verifyContainer(kind, "ownership");
    const port = await this.readDocker(["port", token, "7687/tcp"], { category: "provider" });
    const match = /^127\.0\.0\.1:([0-9]{4,5})\n?$/.exec(String(port?.stdout ?? ""));
    if (port?.status !== 0 || port?.stderr !== "" || match === null || !highPort(match[1])) {
      throw new Failure("ownership");
    }
    return Number(match[1]);
  }

  async isNeo4jReady(slot) {
    validateSlot(slot);
    const token = await this.verifyContainer(`neo4j-${slot}`, "ownership");
    const ready = await this.dockerRead([
      "exec", token, "cypher-shell", "--format", "plain", "-a", "bolt://localhost:7687", "RETURN 1 AS ready",
    ], { category: "provider", timeoutMs: readinessTimeoutMs, outputLimit });
    return ready?.status === 0 && ready?.signal === null && ready?.stdout === "ready\n1\n" && ready?.stderr === "";
  }

  async attachCartography(slot) {
    validateSlot(slot);
    const kind = `cartography-${slot}`;
    const token = this.containerTokens.get(kind);
    if (!objectIDPattern.test(token ?? "")) throw new Failure("normalization");
    const attached = await this.dockerMutation(["start", "--attach", token], {
      category: "operation", timeoutMs: bridgeTimeoutMs, outputLimit,
    });
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

  async removeContainer(kind) {
    const known = this.containerTokens.get(kind);
    let token;
    let inspected;
    if (objectIDPattern.test(known ?? "")) {
      inspected = await this.inspectContainer(known, "cleanup");
      if (inspected?.status === 0) {
        token = known;
      } else {
        const candidates = await this.namedContainerCandidates(kind, "cleanup");
        if (candidates.length === 0) return;
        if (candidates.length !== 1 || candidates[0] !== known) throw new Failure("cleanup");
        token = known;
        inspected = undefined;
      }
    } else {
      const candidates = await this.namedContainerCandidates(kind, "cleanup");
      if (candidates.length === 0) return;
      if (candidates.length !== 1) throw new Failure("cleanup");
      token = candidates[0];
      this.containerTokens.set(kind, token);
    }
    await this.verifyContainer(kind, "cleanup", inspected?.status === 0 ? inspected : undefined);
    const removed = await this.dockerMutation(["rm", "--force", token], { category: "cleanup" });
    if (removed?.status !== 0 || removed?.signal !== null || singleLine(removed?.stdout) !== token) {
      await this.requireContainerAbsent(kind);
    }
  }

  async requireContainerAbsent(kind) {
    const token = this.containerTokens.get(kind);
    if (objectIDPattern.test(token ?? "")) {
      const inspected = await this.inspectContainer(token, "cleanup");
      if (inspected?.status === 0) throw new Failure("cleanup");
    }
    const candidates = await this.namedContainerCandidates(kind, "cleanup");
    if (candidates.length !== 0) throw new Failure("cleanup");
  }

  async removeNetwork() {
    const known = this.networkToken;
    let token;
    let inspected;
    if (objectIDPattern.test(known ?? "")) {
      inspected = await this.inspectNetwork(known, "cleanup");
      if (inspected?.status === 0) token = known;
      else {
        const candidates = await this.namedNetworkCandidates("cleanup");
        if (candidates.length === 0) return;
        if (candidates.length !== 1 || candidates[0] !== known) throw new Failure("cleanup");
        token = known;
        inspected = undefined;
      }
    } else {
      const candidates = await this.namedNetworkCandidates("cleanup");
      if (candidates.length === 0) return;
      if (candidates.length !== 1) throw new Failure("cleanup");
      token = candidates[0];
      this.networkToken = token;
    }
    await this.verifyNetwork("cleanup", inspected);
    const removed = await this.dockerMutation(["network", "rm", token], { category: "cleanup" });
    if (removed?.status !== 0 || removed?.signal !== null || singleLine(removed?.stdout) !== token) {
      await this.requireNetworkAbsent();
    }
  }

  async requireNetworkAbsent() {
    if (objectIDPattern.test(this.networkToken ?? "")) {
      const inspected = await this.inspectNetwork(this.networkToken, "cleanup");
      if (inspected?.status === 0) throw new Failure("cleanup");
    }
    if ((await this.namedNetworkCandidates("cleanup")).length !== 0) throw new Failure("cleanup");
  }
}

export async function orchestrate(runtime, options = {}) {
  const readinessAttempts = options.readinessAttempts ?? 120;
  const wait = options.wait ?? ((milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds)));
  const withDeadline = options.withDeadline ?? withAbsoluteDeadline;
  const runtimeFactory = options.runtimeFactory ?? (() => new DockerRuntime());
  let selected = runtime;
  let mainFailure;
  let cleanupFailed = false;
  let preflightPassed = false;
  const candidates = new Set();
  try {
    await withDeadline(async (signal) => {
      selected ??= runtimeFactory();
      if (!runtimeContract(selected) || !Number.isInteger(readinessAttempts) || readinessAttempts < 1) {
        throw new Failure("configuration");
      }
      selected.setAbortSignal?.(signal);
      await selected.initialize();
      await selected.preflight();
      preflightPassed = true;
      await selected.resolveImages();
      candidates.add("network");
      await selected.createNetwork();
      for (const slot of ["a", "b"]) {
        candidates.add(`neo4j-${slot}`);
        await selected.startNeo4j(slot);
        await selected.verifyContainer(`neo4j-${slot}`);
        await selected.neo4jPort(slot);
      }
      for (const slot of ["a", "b"]) {
        let ready = false;
        for (let attempt = 0; attempt < readinessAttempts; attempt += 1) {
          if (await selected.isNeo4jReady(slot)) { ready = true; break; }
          if (attempt + 1 < readinessAttempts) await wait(250);
        }
        if (!ready) throw new Failure("provider");
      }
      const rawGraphs = [];
      for (const slot of ["a", "b"]) {
        candidates.add(`cartography-${slot}`);
        await selected.createCartography(slot);
        await selected.verifyContainer(`cartography-${slot}`);
      }
      for (const slot of ["a", "b"]) {
        rawGraphs.push(await selected.attachCartography(slot));
      }
      await validateAndMerge(rawGraphs);
    }, mainTimeoutMs);
  } catch (error) {
    mainFailure = error instanceof Failure ? error : new Failure("operation");
  } finally {
    if (selected !== undefined) {
      try {
        await withDeadline(async (signal) => {
          selected.setAbortSignal?.(signal);
          for (const kind of ["cartography-b", "cartography-a", "neo4j-b", "neo4j-a"]) {
            if (!candidates.has(kind)) continue;
            try { await selected.removeContainer(kind); } catch { cleanupFailed = true; }
            try { await selected.requireContainerAbsent(kind); } catch { cleanupFailed = true; }
          }
          if (candidates.has("network")) {
            try { await selected.removeNetwork(); } catch { cleanupFailed = true; }
            try { await selected.requireNetworkAbsent(); } catch { cleanupFailed = true; }
          }
          if (preflightPassed) {
            try { await selected.requirePrefixAbsent("cleanup"); } catch { cleanupFailed = true; }
          }
          try { await selected.cleanupDockerConfig(); } catch { cleanupFailed = true; }
          if (preflightPassed) {
            try { await selected.requireTemporaryPrefixAbsent("cleanup"); } catch { cleanupFailed = true; }
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
    return await Promise.race([
      Promise.resolve().then(() => operation(controller.signal)),
      new Promise((_, rejectPromise) => {
        timer = setTimeout(() => {
          controller.abort();
          rejectPromise(new Failure("operation"));
        }, timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function runtimeContract(runtime) {
  return runtime !== null && typeof runtime === "object" && [
    "initialize", "preflight", "resolveImages", "createNetwork", "startNeo4j", "verifyContainer",
    "neo4jPort", "isNeo4jReady", "createCartography", "attachCartography", "removeContainer",
    "requireContainerAbsent", "removeNetwork", "requireNetworkAbsent", "requirePrefixAbsent", "cleanupDockerConfig",
    "requireTemporaryPrefixAbsent",
  ].every((name) => typeof runtime[name] === "function");
}

function singleLine(value) {
  if (typeof value !== "string") return "";
  const trimmed = value.endsWith("\n") ? value.slice(0, -1) : value;
  return trimmed.includes("\n") ? "" : trimmed;
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
