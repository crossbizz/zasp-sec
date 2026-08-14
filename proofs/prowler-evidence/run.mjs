import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdtemp, open, readdir, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { normalizeProwlerEvidence } from "./normalizer.mjs";

export const LOCALSTACK_IMAGE = "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c";
export const PROWLER_IMAGE = "prowlercloud/prowler:5.39.0@sha256:58c8a0eb0c947517bd89b6214cde0cc1d5f59df4eebbb99a87475ab741914959";
export const SUCCESS_LINE = "Prowler evidence proof passed: findings=1 resources=1 evidence=1 linked=true cleanup=true.";

const failureCategories = new Set([
  "configuration", "provider", "ownership", "normalization", "cleanup", "operation",
]);
const markerPattern = /^[a-f0-9]{16}$/;
const objectIDPattern = /^[a-f0-9]{64}$/;
const imageIDPattern = /^sha256:[a-f0-9]{64}$/;
const roleIDPattern = /^AROA[A-Z0-9]{17}$/;
const utcInstantPartsPattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:Z|\+00:00)$/;
const processOutputLimit = 16_384;
const artifactLimit = 64 * 1024;
const dockerTimeoutMs = 30_000;
const imagePullTimeoutMs = 120_000;
const scannerTimeoutMs = 90_000;
const mainTimeoutMs = 300_000;
const cleanupTimeoutMs = 60_000;
const proofDirectory = dirname(fileURLToPath(import.meta.url));
const artifactName = "prowler.ocsf.json";
const globalTemporaryPrefix = "zasp-m0-11-";
const organizationID = "org_aaaaaaaaaaaaaaaa";
const observationInstant = "2026-08-14T00:00:00.000Z";
const accountID = "000000000000";
const localstackRootUserID = "AKIAIOSFODNN7EXAMPLE";
const region = "us-east-1";
const roleName = "shared-fixture-role";
const roleArn = `arn:aws:iam::${accountID}:role/${roleName}`;
const bridgeLine = "Prowler fixture bridge produced one FAIL finding.\n";

const localstackProofEnvironment = Object.freeze([
  "SERVICES=iam,sts",
  "ENFORCE_IAM=1",
  "PERSISTENCE=0",
]);

const syntheticAwsEnvironment = Object.freeze([
  "AWS_ACCESS_KEY_ID=zasp_fixture_access",
  "AWS_SECRET_ACCESS_KEY=zasp_fixture_secret",
  "AWS_SESSION_TOKEN=zasp_fixture_session",
  "AWS_DEFAULT_REGION=us-east-1",
  "AWS_REGION=us-east-1",
  "AWS_EC2_METADATA_DISABLED=true",
]);

const bridgeBaseEnvironment = Object.freeze([
  "PATH=/home/prowler/.local/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  "LANG=C.UTF-8",
  "GPG_KEY=7169605F62C75135" + "6D054A26A821E680E5FA6305",
  "PYTHON_VERSION=3.12.13",
  "PYTHON_SHA256=c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684",
  "POWERSHELL_VERSION=7.5.9",
  "POWERSHELL_TELEMETRY_OPTOUT=1",
  "TRIVY_VERSION=0.72.0",
  "ZIZMOR_VERSION=1.24.1",
  "HOME=/tmp",
  "PYTHONUNBUFFERED=1",
]);

const trustPolicy = Object.freeze({
  Version: "2012-10-17",
  Statement: Object.freeze([Object.freeze({
    Effect: "Allow",
    Principal: Object.freeze({ Service: "lambda.amazonaws.com" }),
    Action: "sts:AssumeRole",
  })]),
});
const trustPolicyArgument = JSON.stringify(trustPolicy);

export class Failure extends Error {
  constructor(category) {
    super("fixed Prowler orchestrator failure");
    this.category = failureCategories.has(category) ? category : "operation";
  }
}

function fixedFailure(category) {
  const safe = failureCategories.has(category) ? category : "operation";
  return `Prowler evidence proof failed: ${safe} rejected.`;
}

function markerFromName(name, suffix) {
  const match = typeof name === "string"
    ? new RegExp(`^zasp-m0-11-([a-f0-9]{16})-${suffix}$`).exec(name)
    : null;
  if (match === null) throw new Failure("configuration");
  return match[1];
}

export function buildNetworkCreateArguments(name) {
  const marker = markerFromName(name, "network");
  return [
    "network", "create", "--internal",
    "--label", "zasp.proof=m0-11",
    "--label", `zasp.marker=${marker}`,
    name,
  ];
}

export function buildLocalStackRunArguments(name, network) {
  const marker = markerFromName(name, "localstack");
  if (markerFromName(network, "network") !== marker) throw new Failure("configuration");
  return [
    "run", "--detach", "--rm", "--name", name, "--hostname", name,
    "--network", network,
    ...localstackProofEnvironment.flatMap((entry) => ["--env", entry]),
    "--label", "zasp.proof=m0-11",
    "--label", `zasp.marker=${marker}`,
    LOCALSTACK_IMAGE,
  ];
}

export function buildProwlerCreateArguments(name, localstackName, network, selectedProofDirectory, outputDirectory) {
  const marker = markerFromName(name, "prowler");
  if (
    markerFromName(localstackName, "localstack") !== marker ||
    markerFromName(network, "network") !== marker ||
    !exactAbsolutePath(selectedProofDirectory) || !exactAbsolutePath(outputDirectory)
  ) throw new Failure("configuration");
  const scannerEnvironment = [
    ...syntheticAwsEnvironment,
    `AWS_ENDPOINT_URL=http://${localstackName}:4566`,
    "AWS_SHARED_CREDENTIALS_FILE=/nonexistent",
    "AWS_CONFIG_FILE=/nonexistent",
  ];
  const bridgeEnvironment = [...bridgeBaseEnvironment, `HOSTNAME=${name}`];
  return [
    "create", "--rm", "--name", name, "--hostname", name,
    "--network", network,
    ...scannerEnvironment.flatMap((entry) => ["--env", entry]),
    "--label", "zasp.proof=m0-11",
    "--label", `zasp.marker=${marker}`,
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "64",
    "--memory", "768m",
    "--cpus", "1",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m",
    "--volume", `${selectedProofDirectory}:/proof:ro`,
    "--volume", `${outputDirectory}:/proof/output:rw`,
    "--entrypoint", "/usr/bin/env",
    PROWLER_IMAGE,
    "-i", ...bridgeEnvironment,
    "/home/prowler/.venv/bin/python",
    "/proof/fixture_runner.py",
    "--fixture", "/proof/fixture.json",
    "--output", "/proof/output/prowler.ocsf.json",
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
      child === null || typeof child !== "object" || typeof child.once !== "function" ||
      typeof child.kill !== "function" || typeof child.stdout?.on !== "function" ||
      typeof child.stderr?.on !== "function"
    ) {
      rejectPromise(new Failure(options.category));
      return;
    }
    let settled = false;
    let failureRequested = false;
    let killed = false;
    let bytes = 0;
    let timer;
    const stdout = [];
    const stderr = [];
    const signal = options.signal;
    function stop() {
      if (killed) return;
      killed = true;
      child.stdout?.destroy?.();
      child.stderr?.destroy?.();
      try { child.kill("SIGKILL"); } catch { /* close/error remains the reap boundary */ }
    }
    function requestFailure() {
      if (settled || failureRequested) return;
      failureRequested = true;
      stop();
    }
    function abort() { requestFailure(); }
    function consume(target) {
      return (chunk) => {
        if (settled) return;
        let value;
        try { value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); }
        catch { requestFailure(); return; }
        bytes += value.byteLength;
        if (bytes > options.outputLimit) { requestFailure(); return; }
        target.push(value);
      };
    }
    const stdoutData = consume(stdout);
    const stderrData = consume(stderr);
    function cleanupListeners() {
      child.stdout?.removeListener?.("data", stdoutData);
      child.stdout?.removeListener?.("error", requestFailure);
      child.stderr?.removeListener?.("data", stderrData);
      child.stderr?.removeListener?.("error", requestFailure);
      child.removeListener?.("error", requestFailure);
      child.removeListener?.("close", close);
      signal?.removeEventListener?.("abort", abort);
    }
    function finish(callback) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      cleanupListeners();
      callback();
    }
    function close(status, closeSignal) { finish(() => {
      if (failureRequested) { rejectPromise(new Failure(options.category)); return; }
      resolvePromise({
        status,
        signal: closeSignal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    }); }
    child.stdout.on("data", stdoutData);
    child.stdout.on("error", requestFailure);
    child.stderr.on("data", stderrData);
    child.stderr.on("error", requestFailure);
    child.once("error", requestFailure);
    child.once("close", close);
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
    chmodPath = chmod,
    removeTemp = rm,
    canonicalPath = realpath,
    statPath = lstat,
    readDirectory = readdir,
    readPath = readFile,
    openPath = open,
    wait = waitWithSignal,
    normalize = normalizeProwlerEvidence,
  } = {}) {
    if (
      typeof path !== "string" || path.length === 0 || !markerPattern.test(marker) ||
      !exactAbsolutePath(selectedProofDirectory) || !exactAbsolutePath(tempParent) ||
      ![command, spawnProcess, makeTemp, chmodPath, removeTemp, canonicalPath, statPath, readDirectory, readPath, openPath, wait, normalize]
        .every((value) => typeof value === "function")
    ) throw new Failure("configuration");
    this.path = path;
    this.marker = marker;
    this.prefix = `zasp-m0-11-${marker}`;
    this.networkName = `${this.prefix}-network`;
    this.proofDirectory = selectedProofDirectory;
    this.tempParent = tempParent;
    this.command = command;
    this.spawnProcess = spawnProcess;
    this.makeTemp = makeTemp;
    this.chmodPath = chmodPath;
    this.removeTemp = removeTemp;
    this.canonicalPath = canonicalPath;
    this.statPath = statPath;
    this.readDirectory = readDirectory;
    this.readPath = readPath;
    this.openPath = openPath;
    this.wait = wait;
    this.normalize = normalize;
    this.phaseGeneration = 0;
    this.phase = Object.freeze({ generation: 0, signal: undefined });
    this.temporary = new Map([
      ["docker-config", { started: false, creation: undefined, candidate: undefined, identity: undefined, removed: false }],
      ["output", { started: false, creation: undefined, candidate: undefined, identity: undefined, removed: false }],
    ]);
    this.dockerConfigIdentity = undefined;
    this.outputIdentity = undefined;
    this.networkAttempted = false;
    this.networkToken = undefined;
    this.containerAttempts = new Set();
    this.containerTokens = new Map();
    this.containerVolumes = new Map();
    this.imageIDs = new Map();
    this.imageRuntimeMetadata = new Map();
    this.roleIdentity = undefined;
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
    if (!new Set(["localstack", "prowler"]).has(kind)) throw new Failure("configuration");
    return `${this.prefix}-${kind}`;
  }

  hasTemporaryCreationStarted() {
    return [...this.temporary.values()].some((state) => state.started);
  }

  async initialize(phase = this.phase) {
    this.assertActive("configuration", phase);
    let canonicalParent;
    let canonicalProof;
    try {
      [canonicalParent, canonicalProof] = await Promise.all([
        this.canonicalPath(this.tempParent), this.canonicalPath(this.proofDirectory),
      ]);
    } catch { throw new Failure("configuration"); }
    this.assertActive("configuration", phase);
    if (!exactAbsolutePath(canonicalParent) || canonicalProof !== this.proofDirectory) {
      throw new Failure("configuration");
    }
    this.tempParent = canonicalParent;
    await this.createTemporary("docker-config", phase);
    await this.createTemporary("output", phase);
    this.assertActive("operation", phase);
  }

  async createTemporary(kind, phase = this.phase) {
    this.assertActive("configuration", phase);
    const state = this.temporary.get(kind);
    if (state === undefined || state.started) throw new Failure("configuration");
    state.started = true;
    state.creation = Promise.resolve()
      .then(() => this.makeTemp(join(this.tempParent, `${this.prefix}-${kind}-`)))
      .then((candidate) => { state.candidate = candidate; return candidate; });
    const candidate = await state.creation;
    this.assertActive("configuration", phase);
    const identity = await this.ownedTemporaryDirectory(candidate, kind, "configuration", phase, false);
    this.assertActive("configuration", phase);
    if (identity === undefined) throw new Failure("configuration");
    if (kind === "output") {
      try { await this.chmodPath(identity.path, 0o777); } catch { throw new Failure("configuration"); }
      this.assertActive("configuration", phase);
      const reproved = await this.ownedTemporaryDirectory(identity.path, kind, "configuration", phase, false);
      if (reproved === undefined || reproved.dev !== identity.dev || reproved.ino !== identity.ino) {
        throw new Failure("configuration");
      }
    }
    state.identity = identity;
    if (kind === "docker-config") this.dockerConfigIdentity = identity;
    else this.outputIdentity = identity;
  }

  async ownedTemporaryDirectory(value, kind, category, phase = this.phase, allowArtifact = false) {
    this.assertActive(category, phase);
    if (!exactAbsolutePath(value)) return undefined;
    const prefix = join(this.tempParent, `${this.prefix}-${kind}-`);
    if (dirname(value) !== this.tempParent || !value.startsWith(prefix) || value.length === prefix.length) return undefined;
    let canonical;
    let status;
    let entries;
    try {
      [canonical, status, entries] = await Promise.all([
        this.canonicalPath(value), this.statPath(value), this.readDirectory(value),
      ]);
    } catch { return undefined; }
    this.assertActive(category, phase);
    const allowedEntries = allowArtifact && kind === "output" ? new Set([artifactName]) : new Set();
    if (
      canonical !== value || !status?.isDirectory?.() || status?.isSymbolicLink?.() ||
      !Number.isSafeInteger(status.dev) || !Number.isSafeInteger(status.ino) ||
      !Array.isArray(entries) || entries.some((entry) => typeof entry !== "string" || !allowedEntries.has(entry)) ||
      new Set(entries).size !== entries.length
    ) return undefined;
    return { path: value, dev: status.dev, ino: status.ino };
  }

  async reproveTemporary(kind, category, phase = this.phase, allowArtifact = false) {
    this.assertActive(category, phase);
    const retained = kind === "docker-config" ? this.dockerConfigIdentity : this.outputIdentity;
    if (retained === undefined) throw new Failure(category);
    const current = await this.ownedTemporaryDirectory(retained.path, kind, category, phase, allowArtifact);
    if (current === undefined || current.dev !== retained.dev || current.ino !== retained.ino) {
      throw new Failure(category);
    }
    return current;
  }

  async cleanupTemporary(kind, phase = this.phase) {
    this.assertActive("cleanup", phase);
    const state = this.temporary.get(kind);
    if (state === undefined || state.removed) return;
    if (state.identity === undefined && state.started) {
      let candidate;
      try { candidate = await state.creation; } catch { candidate = undefined; }
      this.assertActive("cleanup", phase);
      if (candidate !== undefined) {
        const identity = await this.ownedTemporaryDirectory(candidate, kind, "cleanup", phase, kind === "output");
        if (identity === undefined) throw new Failure("cleanup");
        state.identity = identity;
      }
    }
    if (state.identity === undefined) return;
    const current = await this.ownedTemporaryDirectory(
      state.identity.path, kind, "cleanup", phase, kind === "output",
    );
    this.assertActive("cleanup", phase);
    if (current === undefined || current.dev !== state.identity.dev || current.ino !== state.identity.ino) {
      throw new Failure("cleanup");
    }
    if (kind === "output" && (await this.readDirectory(current.path)).includes(artifactName)) {
      await this.verifyArtifactFile("cleanup", phase);
    }
    this.assertActive("cleanup", phase);
    try { await this.removeTemp(current.path, { recursive: true, force: false, maxRetries: 0 }); }
    catch { throw new Failure("cleanup"); }
    this.assertActive("cleanup", phase);
    try {
      await this.statPath(current.path);
      throw new Failure("cleanup");
    } catch (error) {
      if (error instanceof Failure || error?.code !== "ENOENT") throw new Failure("cleanup");
    }
    state.identity = undefined;
    state.candidate = undefined;
    state.removed = true;
    if (kind === "docker-config") this.dockerConfigIdentity = undefined;
    else this.outputIdentity = undefined;
  }

  async cleanupOutput(phase = this.phase) { return this.cleanupTemporary("output", phase); }
  async cleanupDockerConfig(phase = this.phase) { return this.cleanupTemporary("docker-config", phase); }

  async requireTemporaryPrefixAbsent(category = "cleanup", phase = this.phase) {
    this.assertActive(category, phase);
    let entries;
    try { entries = await this.readDirectory(this.tempParent); } catch { throw new Failure(category); }
    this.assertActive(category, phase);
    if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string" || entry.startsWith(globalTemporaryPrefix))) {
      throw new Failure(category);
    }
  }

  dockerOptions(options = {}, phase = this.phase) {
    const category = options.category ?? "provider";
    this.assertActive(category, phase);
    if (this.dockerConfigIdentity === undefined) throw new Failure(category);
    return {
      env: { PATH: this.path, DOCKER_CONFIG: this.dockerConfigIdentity.path },
      timeoutMs: options.timeoutMs ?? dockerTimeoutMs,
      outputLimit: options.outputLimit ?? processOutputLimit,
      category,
      ...(phase.signal === undefined ? {} : { signal: phase.signal }),
    };
  }

  async dockerRead(args, options = {}, phase = this.phase) {
    const category = options.category ?? "provider";
    this.assertActive(category, phase);
    await this.reproveTemporary("docker-config", category, phase, false);
    const value = await this.command("docker", args, this.dockerOptions(options, phase), this.spawnProcess);
    this.assertActive(category, phase);
    return value;
  }

  async readDocker(args, options = {}, phase = this.phase) {
    const category = options.category ?? "provider";
    this.assertActive(category, phase);
    let value;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        value = await this.dockerRead(args, options, phase);
        this.assertActive(category, phase);
      } catch {
        this.assertActive(category, phase);
        if (attempt === 1) throw new Failure(category);
        await this.wait(250, phase.signal);
        this.assertActive(category, phase);
        continue;
      }
      if (value?.status === 0 && value?.signal === null) return value;
      if (attempt === 0) {
        await this.wait(250, phase.signal);
        this.assertActive(category, phase);
      }
    }
    return value;
  }

  async dockerMutation(args, options = {}, phase = this.phase) {
    const category = options.category ?? "provider";
    this.assertActive(category, phase);
    await this.reproveTemporary("docker-config", category, phase, false);
    if (options.requireEmptyOutput === true) {
      await this.reproveTemporary("output", category, phase, false);
    }
    const value = await this.command("docker", args, this.dockerOptions(options, phase), this.spawnProcess);
    this.assertActive(category, phase);
    return value;
  }

  async preflight(phase = this.phase) {
    this.assertActive("ownership", phase);
    await this.reproveTemporary("docker-config", "ownership", phase, false);
    await this.reproveTemporary("output", "ownership", phase, false);
    await this.requirePrefixAbsent("ownership", phase);
    let entries;
    try { entries = await this.readDirectory(this.tempParent); } catch { throw new Failure("ownership"); }
    this.assertActive("ownership", phase);
    const admitted = [
      basename(this.dockerConfigIdentity?.path ?? ""), basename(this.outputIdentity?.path ?? ""),
    ].sort();
    const ownedEntries = Array.isArray(entries)
      ? entries.filter((entry) => typeof entry === "string" && entry.startsWith(globalTemporaryPrefix)).sort()
      : undefined;
    if (
      !Array.isArray(entries) || entries.some((entry) => typeof entry !== "string") ||
      !isDeepStrictEqual(ownedEntries, admitted)
    ) {
      throw new Failure("ownership");
    }
  }

  async requirePrefixAbsent(category = "ownership", phase = this.phase) {
    this.assertActive(category, phase);
    const containers = await this.readDocker([
      "ps", "--all", "--no-trunc", "--filter", "name=^/zasp-m0-11-", "--format", "{{.ID}}|{{.Names}}",
    ], { category }, phase);
    const networks = await this.readDocker([
      "network", "ls", "--no-trunc", "--filter", "name=^zasp-m0-11-", "--format", "{{.ID}}|{{.Name}}",
    ], { category }, phase);
    this.assertActive(category, phase);
    if (
      containers?.status !== 0 || containers?.signal !== null || containers?.stderr !== "" ||
      networks?.status !== 0 || networks?.signal !== null || networks?.stderr !== ""
    ) throw new Failure(category);
    for (const [identifier, name] of [...parsePairs(containers?.stdout), ...parsePairs(networks?.stdout)]) {
      if (!objectIDPattern.test(identifier) || name.startsWith("zasp-m0-11-")) throw new Failure(category);
    }
  }

  async resolveImages(phase = this.phase) {
    await this.resolveImage(LOCALSTACK_IMAGE, phase);
    await this.resolveImage(PROWLER_IMAGE, phase);
  }

  async resolveImage(image, phase = this.phase) {
    this.assertActive("provider", phase);
    const args = [
      "image", "inspect", "--format",
      "[{{json .Id}},{{json .Config.Env}},{{json .Config.Entrypoint}},{{json (index .Config \"Cmd\")}},{{json (index .Config \"ExposedPorts\")}},{{json (index .Config \"Volumes\")}},{{json (index .Config \"User\")}},{{json .Config.WorkingDir}}]",
      image,
    ];
    let inspected = await this.readDocker(args, { category: "provider" }, phase);
    if (inspected?.status !== 0 || inspected?.signal !== null) {
      if (!exactMissingImage(inspected, image)) throw new Failure("provider");
      let pulled;
      try {
        pulled = await this.dockerMutation(["pull", image], {
          category: "provider", timeoutMs: imagePullTimeoutMs,
        }, phase);
      } catch {
        this.assertActive("provider", phase);
      }
      if (pulled !== undefined && (
        pulled?.status !== 0 || pulled?.signal !== null || pulled?.stderr !== ""
      )) throw new Failure("provider");
      inspected = await this.readDocker(args, { category: "provider" }, phase);
    }
    const metadata = parseImageMetadata(inspected?.stdout);
    if (inspected?.status !== 0 || inspected?.signal !== null || inspected?.stderr !== "" || metadata === undefined) {
      throw new Failure("provider");
    }
    this.imageIDs.set(image, metadata.identifier);
    this.imageRuntimeMetadata.set(image, metadata.runtime);
    return metadata.identifier;
  }

  async createNetwork(phase = this.phase) {
    this.assertActive("provider", phase);
    this.networkAttempted = true;
    let created;
    try { created = await this.dockerMutation(buildNetworkCreateArguments(this.networkName), { category: "provider" }, phase); }
    catch { this.assertActive("provider", phase); }
    const direct = singleLine(created?.stdout);
    if (objectIDPattern.test(direct)) this.networkToken = direct;
    if (created?.status !== 0 || created?.signal !== null || !objectIDPattern.test(direct)) {
      const candidates = await this.namedNetworkCandidates("ownership", phase);
      if (candidates.length !== 1) throw new Failure("ownership");
      this.networkToken = candidates[0];
    }
    await this.verifyNetwork("ownership", undefined, phase);
    return this.networkToken;
  }

  async namedNetworkCandidates(category, phase = this.phase) {
    const listed = await this.readDocker([
      "network", "ls", "--no-trunc", "--filter", `name=^${this.networkName}$`, "--format", "{{.ID}}|{{.Name}}",
    ], { category }, phase);
    if (listed?.status !== 0 || listed?.signal !== null || listed?.stderr !== "") throw new Failure(category);
    const pairs = parsePairs(listed?.stdout);
    if (pairs.some(([identifier, name]) => !objectIDPattern.test(identifier) || name !== this.networkName)) throw new Failure(category);
    return pairs.map(([identifier]) => identifier);
  }

  async inspectNetwork(token, category, phase = this.phase) {
    if (!objectIDPattern.test(token ?? "")) throw new Failure(category);
    return this.readDocker([
      "network", "inspect", "--format",
      "{{.Id}}|{{.Name}}|{{index .Labels \"zasp.proof\"}}|{{index .Labels \"zasp.marker\"}}|{{.Internal}}|{{.Driver}}|{{.Scope}}|{{.Attachable}}|{{.Ingress}}",
      token,
    ], { category }, phase);
  }

  async verifyNetwork(category = "ownership", inspectedResult, phase = this.phase) {
    const inspected = inspectedResult ?? await this.inspectNetwork(this.networkToken, category, phase);
    const fields = singleLine(inspected?.stdout).split("|");
    if (
      inspected?.status !== 0 || inspected?.signal !== null || inspected?.stderr !== "" || fields.length !== 9 ||
      !isDeepStrictEqual(fields, [
        this.networkToken, this.networkName, "m0-11", this.marker, "true", "bridge", "local", "false", "false",
      ])
    ) throw new Failure(category);
    return this.networkToken;
  }

  async startLocalStack(phase = this.phase) {
    return this.createContainer("localstack", buildLocalStackRunArguments(this.name("localstack"), this.networkName), phase);
  }

  async createProwler(phase = this.phase) {
    await this.ensureFixture(phase);
    if (this.roleIdentity?.arn !== roleArn || !roleIDPattern.test(this.roleIdentity?.role_id ?? "")) {
      throw new Failure("ownership");
    }
    await this.reproveTemporary("output", "ownership", phase, false);
    const token = await this.createContainer("prowler", buildProwlerCreateArguments(
      this.name("prowler"), this.name("localstack"), this.networkName,
      this.proofDirectory, this.outputIdentity?.path,
    ), phase);
    await this.reproveTemporary("output", "ownership", phase, false);
    return token;
  }

  async createContainer(kind, args, phase = this.phase) {
    this.assertActive("provider", phase);
    this.containerAttempts.add(kind);
    let created;
    try {
      created = await this.dockerMutation(args, {
        category: "provider", ...(kind === "prowler" ? { requireEmptyOutput: true } : {}),
      }, phase);
    }
    catch { this.assertActive("provider", phase); }
    if (kind === "prowler") await this.reproveTemporary("output", "ownership", phase, false);
    const direct = singleLine(created?.stdout);
    if (objectIDPattern.test(direct)) this.containerTokens.set(kind, direct);
    if (created?.status !== 0 || created?.signal !== null || !objectIDPattern.test(direct)) {
      const candidates = await this.namedContainerCandidates(kind, "ownership", phase);
      if (candidates.length !== 1) throw new Failure("ownership");
      this.containerTokens.set(kind, candidates[0]);
    }
    await this.verifyContainer(kind, "ownership", undefined, phase);
    return this.containerTokens.get(kind);
  }

  async namedContainerCandidates(kind, category, phase = this.phase) {
    const name = this.name(kind);
    const listed = await this.readDocker([
      "ps", "--all", "--no-trunc", "--filter", `name=^/${name}$`, "--format", "{{.ID}}|{{.Names}}",
    ], { category }, phase);
    if (listed?.status !== 0 || listed?.signal !== null || listed?.stderr !== "") throw new Failure(category);
    const pairs = parsePairs(listed?.stdout);
    if (pairs.some(([identifier, candidate]) => !objectIDPattern.test(identifier) || candidate !== name)) throw new Failure(category);
    return pairs.map(([identifier]) => identifier);
  }

  async inspectContainer(token, category, phase = this.phase) {
    if (!objectIDPattern.test(token ?? "")) throw new Failure(category);
    return this.readDocker([
      "inspect", "--format",
      "{{.Id}}|{{.Name}}|{{.Config.Hostname}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels \"zasp.proof\"}}|{{index .Config.Labels \"zasp.marker\"}}|{{.HostConfig.NetworkMode}}|{{json .NetworkSettings.Networks}}|{{json .Config.Env}}|{{json .HostConfig.PortBindings}}|{{json .NetworkSettings.Ports}}|{{json .Config.Entrypoint}}|{{json (index .Config \"Cmd\")}}|{{json .Mounts}}|{{json (index .HostConfig \"Binds\")}}|{{json (index .HostConfig \"Mounts\")}}|{{json (index .HostConfig \"Tmpfs\")}}|{{json .HostConfig.ReadonlyRootfs}}|{{json (index .HostConfig \"CapDrop\")}}|{{json (index .HostConfig \"SecurityOpt\")}}|{{json .HostConfig.PidsLimit}}|{{json .HostConfig.Memory}}|{{json .HostConfig.NanoCpus}}|{{json .Config.User}}|{{json .Config.WorkingDir}}",
      token,
    ], { category }, phase);
  }

  async verifyContainer(kind, category = "ownership", inspectedResult, phase = this.phase) {
    this.assertActive(category, phase);
    const token = this.containerTokens.get(kind);
    if (!objectIDPattern.test(token ?? "") || !objectIDPattern.test(this.networkToken ?? "")) throw new Failure(category);
    const image = kind === "localstack" ? LOCALSTACK_IMAGE : PROWLER_IMAGE;
    const imageID = this.imageIDs.get(image);
    const imageRuntime = this.imageRuntimeMetadata.get(image);
    if (!imageIDPattern.test(imageID ?? "") || imageRuntime === undefined) throw new Failure(category);
    const inspected = inspectedResult ?? await this.inspectContainer(token, category, phase);
    this.assertActive(category, phase);
    const fields = singleLine(inspected?.stdout).split("|");
    if (inspected?.status !== 0 || inspected?.signal !== null || inspected?.stderr !== "" || fields.length !== 26) {
      throw new Failure(category);
    }
    const parsed = fields.slice(8).map((field) => {
      try { return parseUniqueJson(field); } catch { throw new Failure(category); }
    });
    const [networks, environment, portBindings, ports, entrypoint, command, mounts, binds, hostMounts, tmpfs,
      readonlyRootfs, capDrop, securityOpt, pidsLimit, memory, nanoCpus, user, workingDirectory] = parsed;
    const attachedNetworkID = networks?.[this.networkName]?.NetworkID;
    const preStartProwler = kind === "prowler" && attachedNetworkID === "";
    if (
      fields[0] !== token || fields[1] !== `/${this.name(kind)}` || fields[2] !== this.name(kind) ||
      fields[3] !== imageID || fields[4] !== image || fields[5] !== "m0-11" || fields[6] !== this.marker ||
      fields[7] !== this.networkName || !plainObject(networks) || Object.keys(networks).length !== 1 ||
      (attachedNetworkID !== this.networkToken && !preStartProwler)
    ) throw new Failure(category);
    const common = { environment, portBindings, ports, entrypoint, command, mounts, binds, hostMounts, tmpfs,
      readonlyRootfs, capDrop, securityOpt, pidsLimit, memory, nanoCpus, user, workingDirectory, imageRuntime };
    if (kind === "localstack") {
      const volumes = exactLocalStackRuntime(common);
      if (volumes === undefined) throw new Failure(category);
      const retained = this.containerVolumes.get(kind);
      if (retained === undefined) this.containerVolumes.set(kind, volumes);
      else if (!isDeepStrictEqual(retained, volumes)) throw new Failure(category);
    } else {
      if (!exactProwlerRuntime({
        ...common,
        name: this.name("prowler"), localstackName: this.name("localstack"),
        proofDirectory: this.proofDirectory, outputDirectory: this.outputIdentity?.path,
      })) throw new Failure(category);
      if (preStartProwler) await this.verifyNetwork(category, undefined, phase);
    }
    return token;
  }

  awsExecArguments(serviceArguments) {
    const token = this.containerTokens.get("localstack");
    if (!objectIDPattern.test(token ?? "") || !Array.isArray(serviceArguments) || serviceArguments.length === 0) {
      throw new Failure("configuration");
    }
    return [
      "exec",
      ...syntheticAwsEnvironment.flatMap((entry) => ["--env", entry]),
      token,
      "awslocal",
      ...serviceArguments,
      "--output", "json",
    ];
  }

  async isLocalStackReady(phase = this.phase) {
    await this.verifyContainer("localstack", "ownership", undefined, phase);
    const response = await this.readDocker(this.awsExecArguments(["sts", "get-caller-identity"]), { category: "provider" }, phase);
    if (response?.status !== 0 || response?.signal !== null || response?.stderr !== "") return false;
    let document;
    try { document = parseUniqueJson(response.stdout); } catch { return false; }
    return plainObject(document) && isDeepStrictEqual(Object.keys(document).sort(), ["Account", "Arn", "UserId"]) &&
      document.Account === accountID && document.Arn === `arn:aws:iam::${accountID}:root` &&
      document.UserId === localstackRootUserID;
  }

  async createAndVerifyRole(phase = this.phase) {
    await this.verifyContainer("localstack", "ownership", undefined, phase);
    const tags = [`Key=zasp.marker,Value=${this.marker}`, "Key=zasp.proof,Value=m0-11"];
    let createdRole;
    try {
      const created = await this.dockerMutation(this.awsExecArguments([
        "iam", "create-role", "--role-name", roleName,
        "--assume-role-policy-document", trustPolicyArgument,
        "--tags", ...tags,
      ]), { category: "provider" }, phase);
      this.assertActive("provider", phase);
      if (created?.status === 0 && created?.signal === null && created?.stderr === "") {
        try { createdRole = parseRoleEnvelope(created.stdout, this.marker, true); }
        catch { createdRole = undefined; }
      }
    } catch {
      this.assertActive("provider", phase);
    }
    const fetched = await this.readDocker(this.awsExecArguments([
      "iam", "get-role", "--role-name", roleName,
    ]), { category: "provider" }, phase);
    const listedTags = await this.readDocker(this.awsExecArguments([
      "iam", "list-role-tags", "--role-name", roleName,
    ]), { category: "provider" }, phase);
    if (fetched?.status !== 0 || fetched?.signal !== null || fetched?.stderr !== "" || listedTags?.status !== 0 || listedTags?.signal !== null || listedTags?.stderr !== "") {
      throw new Failure("provider");
    }
    const fetchedRole = parseRoleEnvelope(fetched.stdout, this.marker, true);
    let tagEnvelope;
    try { tagEnvelope = parseUniqueJson(listedTags.stdout); } catch { throw new Failure("ownership"); }
    if (
      !plainObject(tagEnvelope) || !isDeepStrictEqual(Object.keys(tagEnvelope), ["Tags"]) ||
      normalizeTags(tagEnvelope.Tags, this.marker) === undefined
    ) {
      throw new Failure("ownership");
    }
    if (createdRole !== undefined && !isDeepStrictEqual(createdRole, fetchedRole)) throw new Failure("ownership");
    this.roleIdentity = Object.freeze({ arn: fetchedRole.Arn, role_id: fetchedRole.RoleId });
    return this.roleIdentity;
  }

  async ensureFixture(phase = this.phase) {
    this.assertActive("ownership", phase);
    const path = join(this.proofDirectory, "fixture.json");
    let canonical;
    let status;
    let bytes;
    try { [canonical, status, bytes] = await Promise.all([this.canonicalPath(path), this.statPath(path), this.readPath(path)]); }
    catch { throw new Failure("ownership"); }
    this.assertActive("ownership", phase);
    if (
      canonical !== path || !status?.isFile?.() || status?.isSymbolicLink?.() ||
      !Number.isSafeInteger(status.dev) || !Number.isSafeInteger(status.ino) ||
      !Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > processOutputLimit
    ) throw new Failure("ownership");
    let fixture;
    try { fixture = parseUniqueJson(bytes.toString("utf8")); } catch { throw new Failure("ownership"); }
    const role = fixture?.role;
    if (
      !plainObject(fixture) || !isDeepStrictEqual(Object.keys(fixture), ["schema_version", "account_id", "region", "partition", "role"]) ||
      fixture.schema_version !== 1 || fixture.account_id !== accountID || fixture.region !== region || fixture.partition !== "aws" ||
      !plainObject(role) || role.name !== roleName || role.arn !== roleArn || !isDeepStrictEqual(role.assume_role_policy, trustPolicy) ||
      role.is_service_role !== true || !isDeepStrictEqual(role.attached_policies, []) || !isDeepStrictEqual(role.inline_policies, []) ||
      role.permissions_boundary !== null || !isDeepStrictEqual(role.tags, [])
    ) throw new Failure("ownership");
    return path;
  }

  async runProwler(phase = this.phase) {
    const token = await this.verifyContainer("prowler", "ownership", undefined, phase);
    const executed = await this.dockerMutation(["start", "--attach", token], {
      category: "operation", timeoutMs: scannerTimeoutMs, outputLimit: processOutputLimit,
      requireEmptyOutput: true,
    }, phase);
    await this.reproveTemporary("output", "ownership", phase, true);
    if (executed?.status !== 3 || executed?.signal !== null || executed?.stdout !== bridgeLine || executed?.stderr !== "") {
      throw new Failure("normalization");
    }
  }

  async verifyArtifactFile(category, phase = this.phase) {
    this.assertActive(category, phase);
    const identity = this.outputIdentity ?? this.temporary.get("output")?.identity;
    if (identity === undefined) throw new Failure(category);
    const directory = await this.ownedTemporaryDirectory(identity.path, "output", category, phase, true);
    if (directory === undefined || directory.dev !== identity.dev || directory.ino !== identity.ino) throw new Failure(category);
    const entries = await this.readDirectory(directory.path);
    if (!isDeepStrictEqual(entries, [artifactName])) throw new Failure(category);
    const path = join(directory.path, artifactName);
    let status;
    try { status = await this.statPath(path); } catch { throw new Failure(category); }
    if (
      !status?.isFile?.() || status?.isSymbolicLink?.() || !Number.isSafeInteger(status.dev) || !Number.isSafeInteger(status.ino) ||
      !Number.isSafeInteger(status.size) || status.size < 1 || status.size > artifactLimit
    ) throw new Failure(category);
    return { path, dev: status.dev, ino: status.ino, size: status.size };
  }

  async readArtifact(phase = this.phase) {
    const identity = await this.verifyArtifactFile("normalization", phase);
    let handle;
    let artifact;
    try {
      const flags = constants.O_RDONLY | constants.O_CLOEXEC | constants.O_NOFOLLOW | constants.O_NONBLOCK;
      handle = await this.openPath(identity.path, flags);
      this.assertActive("normalization", phase);
      const opened = await handle.stat();
      if (
        !opened?.isFile?.() || opened?.isSymbolicLink?.() || opened.dev !== identity.dev || opened.ino !== identity.ino ||
        opened.size !== identity.size || opened.size < 1 || opened.size > artifactLimit
      ) throw new Failure("normalization");
      const buffer = Buffer.alloc(artifactLimit + 1);
      let offset = 0;
      while (offset < buffer.length) {
        const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
        if (!Number.isInteger(bytesRead) || bytesRead < 0 || bytesRead > buffer.length - offset) throw new Failure("normalization");
        if (bytesRead === 0) break;
        offset += bytesRead;
      }
      const closedStatus = await handle.stat();
      if (
        offset !== identity.size || offset > artifactLimit || closedStatus.dev !== identity.dev ||
        closedStatus.ino !== identity.ino || closedStatus.size !== identity.size
      ) throw new Failure("normalization");
      this.assertActive("normalization", phase);
      artifact = buffer.subarray(0, offset);
    } catch (error) {
      if (error instanceof Failure) throw error;
      throw new Failure("normalization");
    } finally {
      try { await handle?.close?.(); } catch { /* read already fails closed */ }
    }
    await this.reproveTemporary("output", "normalization", phase, true);
    return artifact;
  }

  async normalizeArtifact(phase = this.phase) {
    let normalized;
    try {
      normalized = this.normalize(organizationID, await this.readArtifact(phase), observationInstant);
      await this.reproveTemporary("output", "normalization", phase, true);
    }
    catch (error) { if (error instanceof Failure) throw error; throw new Failure("normalization"); }
    const resource = normalized?.resources?.[0];
    const finding = normalized?.findings?.[0];
    const evidence = normalized?.evidence?.[0];
    if (
      normalized?.organization_id !== organizationID || normalized?.resources?.length !== 1 ||
      normalized?.findings?.length !== 1 || normalized?.evidence?.length !== 1 ||
      resource?.source_id !== roleArn || resource?.organization_id !== organizationID ||
      finding?.organization_id !== organizationID || evidence?.organization_id !== organizationID ||
      finding?.resource_id !== resource?.id || evidence?.resource_id !== resource?.id
    ) throw new Failure("normalization");
    return normalized;
  }

  async removeContainer(kind, phase = this.phase) {
    this.assertActive("cleanup", phase);
    const known = this.containerTokens.get(kind);
    let token;
    let inspected;
    if (objectIDPattern.test(known ?? "")) {
      inspected = await this.inspectContainer(known, "cleanup", phase);
      if (inspected?.status === 0) token = known;
      else {
        if (!exactMissingContainer(inspected, known)) throw new Failure("cleanup");
        const candidates = await this.namedContainerCandidates(kind, "cleanup", phase);
        if (candidates.length === 0) { await this.requireContainerVolumesAbsent(kind, phase); return; }
        if (candidates.length !== 1 || candidates[0] !== known) throw new Failure("cleanup");
        token = known;
        inspected = undefined;
      }
    } else {
      const candidates = await this.namedContainerCandidates(kind, "cleanup", phase);
      if (candidates.length === 0) return;
      if (candidates.length !== 1) throw new Failure("cleanup");
      token = candidates[0];
      this.containerTokens.set(kind, token);
    }
    await this.verifyContainer(kind, "cleanup", inspected?.status === 0 ? inspected : undefined, phase);
    let removed;
    try {
      removed = await this.dockerMutation([
        "rm", "--force", ...(kind === "localstack" ? ["--volumes"] : []), token,
      ], { category: "cleanup" }, phase);
    } catch {
      this.assertActive("cleanup", phase);
      await this.requireContainerAbsent(kind, phase);
      return;
    }
    if (removed?.status !== 0 || removed?.signal !== null || singleLine(removed?.stdout) !== token) {
      await this.requireContainerAbsent(kind, phase);
    } else await this.requireContainerVolumesAbsent(kind, phase);
  }

  async requireContainerVolumesAbsent(kind, phase = this.phase) {
    if (kind !== "localstack") return;
    const volumes = this.containerVolumes.get(kind);
    if (volumes === undefined) return;
    if (!Array.isArray(volumes) || volumes.length !== 1 || !objectIDPattern.test(volumes[0] ?? "")) throw new Failure("cleanup");
    for (const name of volumes) {
      const inspected = await this.readDocker(["volume", "inspect", name], { category: "cleanup" }, phase);
      if (!exactMissingVolume(inspected, name)) throw new Failure("cleanup");
    }
  }

  async requireContainerAbsent(kind, phase = this.phase) {
    const token = this.containerTokens.get(kind);
    if (objectIDPattern.test(token ?? "")) {
      const inspected = await this.inspectContainer(token, "cleanup", phase);
      if (inspected?.status === 0 || !exactMissingContainer(inspected, token)) throw new Failure("cleanup");
    }
    if ((await this.namedContainerCandidates(kind, "cleanup", phase)).length !== 0) throw new Failure("cleanup");
    await this.requireContainerVolumesAbsent(kind, phase);
  }

  async removeNetwork(phase = this.phase) {
    const known = this.networkToken;
    let token;
    let inspected;
    if (objectIDPattern.test(known ?? "")) {
      inspected = await this.inspectNetwork(known, "cleanup", phase);
      if (inspected?.status === 0) token = known;
      else {
        if (!exactMissingNetwork(inspected, known)) throw new Failure("cleanup");
        const candidates = await this.namedNetworkCandidates("cleanup", phase);
        if (candidates.length === 0) return;
        if (candidates.length !== 1 || candidates[0] !== known) throw new Failure("cleanup");
        token = known;
        inspected = undefined;
      }
    } else {
      const candidates = await this.namedNetworkCandidates("cleanup", phase);
      if (candidates.length === 0) return;
      if (candidates.length !== 1) throw new Failure("cleanup");
      token = candidates[0];
      this.networkToken = token;
    }
    await this.verifyNetwork("cleanup", inspected, phase);
    let removed;
    try { removed = await this.dockerMutation(["network", "rm", token], { category: "cleanup" }, phase); }
    catch { await this.requireNetworkAbsent(phase); return; }
    if (removed?.status !== 0 || removed?.signal !== null || singleLine(removed?.stdout) !== token) await this.requireNetworkAbsent(phase);
  }

  async requireNetworkAbsent(phase = this.phase) {
    if (objectIDPattern.test(this.networkToken ?? "")) {
      const inspected = await this.inspectNetwork(this.networkToken, "cleanup", phase);
      if (inspected?.status === 0 || !exactMissingNetwork(inspected, this.networkToken)) throw new Failure("cleanup");
    }
    if ((await this.namedNetworkCandidates("cleanup", phase)).length !== 0) throw new Failure("cleanup");
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
      const step = (operation, category = "operation") => phaseStep(signal, operation, category);
      selected ??= runtimeFactory();
      if (!runtimeContract(selected) || !Number.isInteger(readinessAttempts) || readinessAttempts < 1) throw new Failure("configuration");
      selected.setAbortSignal?.(signal);
      await step(() => selected.initialize());
      await step(() => selected.preflight());
      preflightPassed = true;
      await step(() => selected.resolveImages());
      candidates.add("network");
      await step(() => selected.createNetwork());
      candidates.add("localstack");
      await step(() => selected.startLocalStack());
      let ready = false;
      for (let attempt = 0; attempt < readinessAttempts; attempt += 1) {
        if (await step(() => selected.isLocalStackReady(), "provider")) { ready = true; break; }
        if (attempt + 1 < readinessAttempts) await step(() => wait(250, signal), "provider");
      }
      if (!ready) throw new Failure("provider");
      await step(() => selected.createAndVerifyRole(), "provider");
      candidates.add("prowler");
      await step(() => selected.createProwler());
      await step(() => selected.runProwler(), "normalization");
      await step(() => selected.normalizeArtifact(), "normalization");
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
            let passed = true;
            try { await operation(); } catch { cleanupFailed = true; passed = false; }
            throwIfAborted(signal, "cleanup");
            return passed;
          };
          let containersAbsent = true;
          for (const kind of ["prowler", "localstack"]) {
            if (!candidates.has(kind)) continue;
            await cleanupStep(() => selected.removeContainer(kind));
            const absent = await cleanupStep(() => selected.requireContainerAbsent(kind));
            containersAbsent = containersAbsent && absent;
          }
          if (candidates.has("network")) {
            if (containersAbsent) await cleanupStep(() => selected.removeNetwork());
            await cleanupStep(() => selected.requireNetworkAbsent());
          }
          await cleanupStep(() => selected.cleanupOutput());
          if (preflightPassed) await cleanupStep(() => selected.requirePrefixAbsent("cleanup"));
          await cleanupStep(() => selected.cleanupDockerConfig());
          if (preflightPassed || selected.hasTemporaryCreationStarted()) {
            await cleanupStep(() => selected.requireTemporaryPrefixAbsent("cleanup"));
          }
        }, cleanupTimeoutMs);
      } catch { cleanupFailed = true; }
    }
  }
  if (cleanupFailed) return { code: 1, line: fixedFailure("cleanup") };
  if (mainFailure !== undefined) return { code: 1, line: fixedFailure(mainFailure.category) };
  return { code: 0, line: SUCCESS_LINE };
}

export async function runMain(runtime, options = {}) {
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const setExitCode = options.setExitCode ?? ((code) => { process.exitCode = code; });
  let proof;
  try {
    proof = await orchestrate(runtime, {
      ...(options.orchestrateOptions ?? {}),
      runtimeFactory: options.runtimeFactory,
    });
  } catch (error) {
    proof = { code: 1, line: fixedFailure(error instanceof Failure ? error.category : "operation") };
  }
  try { (proof.code === 0 ? stdout : stderr).write(`${proof.line}\n`); }
  catch {
    proof = { code: 1, line: fixedFailure("operation") };
    try { stderr.write(`${proof.line}\n`); } catch { /* fixed boundary is best effort */ }
  }
  try { setExitCode(proof.code); } catch { return 1; }
  return proof.code;
}

function exactLocalStackRuntime({
  environment, portBindings, ports, entrypoint, command, mounts, binds, hostMounts, tmpfs,
  readonlyRootfs, capDrop, securityOpt, pidsLimit, memory, nanoCpus, user, workingDirectory, imageRuntime,
}) {
  if (
    !exactEnvironmentWithPrefix(environment, localstackProofEnvironment, imageRuntime?.environment) ||
    !isDeepStrictEqual(entrypoint, imageRuntime?.entrypoint) || command !== imageRuntime?.command ||
    !isDeepStrictEqual(Object.keys(portBindings ?? {}).sort(), []) ||
    !plainObject(ports) || !isDeepStrictEqual(Object.keys(ports).sort(), imageRuntime?.exposedPorts) ||
    imageRuntime.exposedPorts.some((port) => ports[port] !== null) || binds !== null || hostMounts !== null || tmpfs !== null ||
    readonlyRootfs !== false || capDrop !== null || securityOpt !== null || pidsLimit !== null || memory !== 0 || nanoCpus !== 0 ||
    user !== imageRuntime?.user || workingDirectory !== imageRuntime?.workingDirectory ||
    !isDeepStrictEqual(imageRuntime?.volumes, ["/var/lib/localstack"])
  ) return undefined;
  return exactIntrinsicVolumes(mounts, imageRuntime.volumes);
}

function exactProwlerRuntime({
  environment, portBindings, ports, entrypoint, command, mounts, binds, hostMounts, tmpfs,
  readonlyRootfs, capDrop, securityOpt, pidsLimit, memory, nanoCpus, user, workingDirectory, imageRuntime,
  name, localstackName, proofDirectory: selectedProofDirectory, outputDirectory,
}) {
  const proofEnvironment = [
    ...syntheticAwsEnvironment,
    `AWS_ENDPOINT_URL=http://${localstackName}:4566`,
    "AWS_SHARED_CREDENTIALS_FILE=/nonexistent",
    "AWS_CONFIG_FILE=/nonexistent",
  ];
  const expectedCommand = [
    "-i", ...bridgeBaseEnvironment, `HOSTNAME=${name}`,
    "/home/prowler/.venv/bin/python", "/proof/fixture_runner.py",
    "--fixture", "/proof/fixture.json", "--output", "/proof/output/prowler.ocsf.json",
  ];
  const sortedMounts = Array.isArray(mounts)
    ? [...mounts].sort((left, right) => String(left?.Destination).localeCompare(String(right?.Destination)))
    : mounts;
  const sortedBinds = Array.isArray(binds) ? [...binds].sort() : binds;
  return (
    exactEnvironmentWithPrefix(environment, proofEnvironment, imageRuntime?.environment) &&
    isDeepStrictEqual(imageRuntime?.entrypoint, ["/home/prowler/.venv/bin/prowler"]) && imageRuntime?.command === null &&
    isDeepStrictEqual(imageRuntime?.exposedPorts, []) && isDeepStrictEqual(imageRuntime?.volumes, []) &&
    isDeepStrictEqual(entrypoint, ["/usr/bin/env"]) && isDeepStrictEqual(command, expectedCommand) &&
    isDeepStrictEqual(Object.keys(portBindings ?? {}).sort(), []) && isDeepStrictEqual(Object.keys(ports ?? {}).sort(), []) &&
    isDeepStrictEqual(sortedMounts, [
      { Type: "bind", Source: selectedProofDirectory, Destination: "/proof", Mode: "ro", RW: false, Propagation: "rprivate" },
      { Type: "bind", Source: outputDirectory, Destination: "/proof/output", Mode: "rw", RW: true, Propagation: "rprivate" },
    ]) &&
    isDeepStrictEqual(sortedBinds, [`${selectedProofDirectory}:/proof:ro`, `${outputDirectory}:/proof/output:rw`].sort()) &&
    hostMounts === null && isDeepStrictEqual(tmpfs, { "/tmp": "rw,noexec,nosuid,nodev,size=32m" }) &&
    readonlyRootfs === true && isDeepStrictEqual(capDrop, ["ALL"]) && isDeepStrictEqual(securityOpt, ["no-new-privileges"]) &&
    pidsLimit === 64 && memory === 805_306_368 && nanoCpus === 1_000_000_000 &&
    user === "prowler" && workingDirectory === "/home/prowler"
  );
}

function exactIntrinsicVolumes(mounts, destinations) {
  if (!Array.isArray(mounts) || !Array.isArray(destinations) || mounts.length !== destinations.length) return undefined;
  const ordered = [...mounts].sort((left, right) => String(left?.Destination).localeCompare(String(right?.Destination)));
  if (!isDeepStrictEqual(ordered.map((mount) => mount?.Destination), destinations)) return undefined;
  const names = [];
  for (const mount of ordered) {
    if (
      !plainObject(mount) || !isDeepStrictEqual(Object.keys(mount).sort(), [
        "Destination", "Driver", "Mode", "Name", "Propagation", "RW", "Source", "Type",
      ]) || mount.Type !== "volume" || mount.Driver !== "local" || mount.Mode !== "" || mount.RW !== true ||
      mount.Propagation !== "" || !objectIDPattern.test(mount.Name ?? "") ||
      mount.Source !== `/var/lib/docker/volumes/${mount.Name}/_data`
    ) return undefined;
    names.push(mount.Name);
  }
  return new Set(names).size === names.length ? Object.freeze(names) : undefined;
}

function parseImageMetadata(value) {
  let document;
  try { document = parseUniqueJson(singleLine(value)); } catch { return undefined; }
  if (!Array.isArray(document) || document.length !== 8 || !imageIDPattern.test(document[0] ?? "")) return undefined;
  const environment = exactEnvironment(document[1]);
  const entrypoint = exactStringArray(document[2]);
  const command = document[3] === null ? null : exactStringArray(document[3]);
  const exposedPorts = exactImageObjectKeys(document[4], exactPortArray);
  const volumes = exactImageObjectKeys(document[5], exactVolumeArray);
  const user = document[6] === null ? "" : document[6];
  if (
    environment === undefined || entrypoint === undefined || command === undefined || exposedPorts === undefined || volumes === undefined ||
    typeof user !== "string" || typeof document[7] !== "string"
  ) return undefined;
  return {
    identifier: document[0],
    runtime: Object.freeze({
      environment, entrypoint, command, exposedPorts, volumes,
      user, workingDirectory: document[7],
    }),
  };
}

function exactEnvironmentWithPrefix(value, prefix, imageEnvironment) {
  const environment = exactEnvironment(value);
  const image = exactEnvironment(imageEnvironment);
  if (environment === undefined || image === undefined || environment.length !== prefix.length + image.length) return false;
  return isDeepStrictEqual([...environment.slice(0, prefix.length)].sort(), [...prefix].sort()) &&
    isDeepStrictEqual(environment.slice(prefix.length), image);
}

function exactEnvironment(value) {
  const entries = exactStringArray(value, true);
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
    !Array.isArray(value) || (!allowEmpty && value.length === 0) || value.length > 256 ||
    value.some((entry) => typeof entry !== "string" || entry.length === 0 || Buffer.byteLength(entry) > 8_192 || hasControlCharacter(entry))
  ) return undefined;
  return Object.freeze([...value]);
}

function exactImageObjectKeys(value, validator) {
  if (value === null) return Object.freeze([]);
  if (!plainObject(value) || Object.values(value).some((entry) => !plainObject(entry) || Object.keys(entry).length !== 0)) return undefined;
  return validator(Object.keys(value));
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
  if (volumes === undefined || volumes.some((path) => !exactAbsolutePath(path) || path === "/")) return undefined;
  const sorted = [...volumes].sort();
  return new Set(sorted).size === sorted.length ? Object.freeze(sorted) : undefined;
}

function parseRoleEnvelope(source, marker, requireTags) {
  let envelope;
  try { envelope = parseUniqueJson(source); } catch { throw new Failure("ownership"); }
  if (!plainObject(envelope) || !isDeepStrictEqual(Object.keys(envelope), ["Role"]) || !plainObject(envelope.Role)) {
    throw new Failure("ownership");
  }
  const role = envelope.Role;
  const requiredKeys = ["Path", "RoleName", "RoleId", "Arn", "CreateDate", "AssumeRolePolicyDocument", "MaxSessionDuration", ...(requireTags ? ["Tags"] : [])].sort();
  const keys = Object.keys(role).sort();
  const hasExactRoleLastUsed = isDeepStrictEqual(keys, [...requiredKeys, "RoleLastUsed"].sort()) &&
    plainObject(role.RoleLastUsed) && Object.keys(role.RoleLastUsed).length === 0;
  if (
    (!isDeepStrictEqual(keys, requiredKeys) && !hasExactRoleLastUsed) || role.Path !== "/" || role.RoleName !== roleName ||
    !roleIDPattern.test(role.RoleId ?? "") || role.Arn !== roleArn || !utcInstant(role.CreateDate) ||
    !isDeepStrictEqual(role.AssumeRolePolicyDocument, trustPolicy) || role.MaxSessionDuration !== 3600 ||
    (requireTags && normalizeTags(role.Tags, marker) === undefined)
  ) throw new Failure("ownership");
  const normalized = { ...role };
  delete normalized.RoleLastUsed;
  return requireTags ? { ...normalized, Tags: normalizeTags(role.Tags, marker) } : normalized;
}

function exactTags(marker) {
  return [
    { Key: "zasp.marker", Value: marker },
    { Key: "zasp.proof", Value: "m0-11" },
  ];
}

function normalizeTags(value, marker) {
  if (
    !Array.isArray(value) || value.length !== 2 ||
    value.some((tag) => !plainObject(tag) || !isDeepStrictEqual(Object.keys(tag).sort(), ["Key", "Value"]) ||
      typeof tag.Key !== "string" || typeof tag.Value !== "string")
  ) return undefined;
  const sorted = [...value].sort((left, right) => left.Key.localeCompare(right.Key));
  return isDeepStrictEqual(sorted, exactTags(marker)) ? sorted : undefined;
}

function utcInstant(value) {
  if (typeof value !== "string" || value.length > 64 || hasControlCharacter(value)) return false;
  const match = utcInstantPartsPattern.exec(value);
  if (match === null) return false;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map((part) => Number(part));
  if (year < 1) return false;
  const millisecond = Number(`${match[7] ?? ""}000`.slice(0, 3));
  const candidate = new Date(0);
  candidate.setUTCFullYear(year, month - 1, day);
  candidate.setUTCHours(hour, minute, second, millisecond);
  return candidate.getUTCFullYear() === year && candidate.getUTCMonth() === month - 1 &&
    candidate.getUTCDate() === day && candidate.getUTCHours() === hour &&
    candidate.getUTCMinutes() === minute && candidate.getUTCSeconds() === second &&
    candidate.getUTCMilliseconds() === millisecond;
}

function parseUniqueJson(source) {
  if (typeof source !== "string" || Buffer.byteLength(source) > processOutputLimit) throw new SyntaxError("invalid JSON");
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
        const key = string();
        if (keys.has(key)) throw new SyntaxError("duplicate JSON key");
        keys.add(key); whitespace();
        if (source[index] !== ":") throw new SyntaxError("invalid JSON object");
        index += 1; value(); whitespace();
        if (source[index] === "}") { index += 1; return; }
        if (source[index] !== ",") throw new SyntaxError("invalid JSON object");
        index += 1; whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1; whitespace();
      if (source[index] === "]") { index += 1; return; }
      while (true) {
        value(); whitespace();
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
  value(); whitespace();
  if (index !== source.length) throw new SyntaxError("invalid trailing JSON");
  return JSON.parse(source);
}

async function withAbsoluteDeadline(operation, timeoutMs) {
  const controller = new AbortController();
  let timer;
  try {
    const operationResult = Promise.resolve().then(() => operation(controller.signal)).then(
      (value) => ({ state: "fulfilled", value }),
      (error) => ({ state: "rejected", error }),
    );
    const winner = await Promise.race([
      operationResult,
      new Promise((resolvePromise) => {
        timer = setTimeout(() => { controller.abort(); resolvePromise({ state: "timeout" }); }, timeoutMs);
      }),
    ]);
    if (winner.state === "timeout") throw new Failure("operation");
    if (winner.state === "rejected") throw winner.error;
    return winner.value;
  } finally { clearTimeout(timer); }
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
    const abort = () => { clearTimeout(timer); rejectPromise(new Failure("operation")); };
    signal?.addEventListener?.("abort", abort, { once: true });
    timer = setTimeout(() => { signal?.removeEventListener?.("abort", abort); resolvePromise(); }, milliseconds);
    if (signal?.aborted === true) abort();
  });
}

function runtimeContract(runtime) {
  return runtime !== null && typeof runtime === "object" && [
    "initialize", "preflight", "resolveImages", "createNetwork", "startLocalStack", "isLocalStackReady",
    "createAndVerifyRole", "createProwler", "runProwler", "normalizeArtifact", "removeContainer",
    "requireContainerAbsent", "removeNetwork", "requireNetworkAbsent", "cleanupOutput", "cleanupDockerConfig",
    "requirePrefixAbsent", "requireTemporaryPrefixAbsent", "hasTemporaryCreationStarted",
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

function exactMissingContainer(value, token) {
  return value?.status === 1 && value?.signal === null && value?.stdout === "\n" && value?.stderr === `error: no such object: ${token}\n`;
}

function exactMissingNetwork(value, token) {
  return value?.status === 1 && value?.signal === null && value?.stdout === "\n" && value?.stderr === `Error response from daemon: network ${token} not found\n`;
}

function exactMissingVolume(value, token) {
  return value?.status === 1 && value?.signal === null && value?.stdout === "[]\n" && value?.stderr === `Error response from daemon: get ${token}: no such volume\n`;
}

function exactMissingImage(value, image) {
  return value?.status === 1 && value?.signal === null && value?.stdout === "\n" &&
    value?.stderr === `Error response from daemon: No such image: ${image}\n`;
}

function exactAbsolutePath(value) {
  return typeof value === "string" && isAbsolute(value) && resolve(value) === value;
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function hasControlCharacter(value) {
  for (const character of value) {
    const point = character.codePointAt(0);
    if (point <= 0x1f || point === 0x7f) return true;
  }
  return false;
}

if (process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await runMain();
}
