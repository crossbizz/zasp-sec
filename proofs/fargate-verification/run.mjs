import { spawn } from "node:child_process";
import { access, lstat, mkdtemp, readdir, realpath, rm } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const publicEnvironmentNames = Object.freeze([
  "AWS_M018_ISOLATED_TEST",
  "AWS_M018_KUBECONFIG",
  "AWS_M018_KUBE_CONTEXT",
  "AWS_M018_CLUSTER_NAME",
  "AWS_M018_REGION",
  "AWS_M018_FARGATE_PROFILE",
  "AWS_M018_PROFILE_NAMESPACE_PREFIX",
  "AWS_M018_PROFILE_LABEL_KEY",
  "AWS_M018_PROFILE_LABEL_VALUE",
  "AWS_M018_PROXY_URL",
  "AWS_M018_CANARY_TOKEN",
]);
const attestation = "I_UNDERSTAND_THIS_MUTATES_A_DISPOSABLE_EKS_PROFILE";
const successLine = "EKS Fargate proof passed: scheduled=true canary=true cleanup=true.";
const outputLimit = 16 * 1024;
const buildTimeoutMs = 90_000;
const proofSupervisorTimeoutMs = 960_000;
const workspacePrefix = "zasp-m018-build-";
const proofDirectory = dirname(fileURLToPath(import.meta.url));

export class SafeFailure extends Error {
  constructor(category) {
    super("fixed Fargate proof failure");
    this.category = category;
  }
}

function reject(category = "provider") {
  throw new SafeFailure(category);
}

export function validateProofEnvironment(environment) {
  if (environment === null || typeof environment !== "object") reject("configuration");
  const result = Object.create(null);
  for (const name of publicEnvironmentNames) {
    const value = environment[name];
    if (typeof value !== "string" || value.length === 0 || value.length > 16_384 || /[\0\r\n]/u.test(value)) reject("configuration");
    result[name] = value;
  }
  if (result.AWS_M018_ISOLATED_TEST !== attestation ||
      result.AWS_M018_PROFILE_NAMESPACE_PREFIX !== "zasp-m018-" ||
      result.AWS_M018_PROFILE_LABEL_KEY !== "zasp.agentsec.dev/fargate" ||
      result.AWS_M018_PROFILE_LABEL_VALUE !== "true") reject("configuration");
  return result;
}

export function buildBuildEnvironment(environment) {
  if (environment === null || typeof environment !== "object") reject("configuration");
  const result = Object.create(null);
  for (const name of ["PATH", "HOME", "GOCACHE", "GOMODCACHE"]) {
    const value = environment[name];
    if (typeof value !== "string" || value.length === 0 || (name !== "PATH" && !isAbsolute(value))) reject("configuration");
    result[name] = value;
  }
  const temporaryDirectory = environment.TMPDIR ?? tmpdir();
  if (typeof temporaryDirectory !== "string" || temporaryDirectory.length === 0 || !isAbsolute(temporaryDirectory)) reject("configuration");
  result.TMPDIR = temporaryDirectory;
  Object.assign(result, {
    CGO_ENABLED: "0",
    GOENV: "off",
    GOFLAGS: "-mod=readonly",
    GOPROXY: "off",
    GOSUMDB: "off",
    GOTOOLCHAIN: "local",
  });
  return result;
}

async function ensureGoCaches(environment, runImplementation, spawnImplementation) {
  if (typeof environment.GOCACHE === "string" && isAbsolute(environment.GOCACHE) &&
      typeof environment.GOMODCACHE === "string" && isAbsolute(environment.GOMODCACHE)) return environment;
  if (typeof environment.PATH !== "string" || typeof environment.HOME !== "string" || !isAbsolute(environment.HOME)) reject("configuration");
  const result = await runImplementation("go", ["env", "-json", "GOCACHE", "GOMODCACHE"], {
    cwd: proofDirectory,
    env: { PATH: environment.PATH, HOME: environment.HOME, GOENV: "off" },
    outputLimit: 4096,
    timeoutMs: 10_000,
  }, spawnImplementation);
  if (result?.code !== 0 || result?.signal !== null || result?.stderr !== "" || typeof result?.stdout !== "string") reject("configuration");
  let parsed;
  try { parsed = JSON.parse(result.stdout); } catch { reject("configuration"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) ||
      Object.keys(parsed).sort().join(",") !== "GOCACHE,GOMODCACHE" ||
      typeof parsed.GOCACHE !== "string" || !isAbsolute(parsed.GOCACHE) ||
      typeof parsed.GOMODCACHE !== "string" || !isAbsolute(parsed.GOMODCACHE)) reject("configuration");
  return { ...environment, GOCACHE: parsed.GOCACHE, GOMODCACHE: parsed.GOMODCACHE };
}

export function runBounded(command, arguments_, options, spawnImplementation = spawn) {
  return new Promise((resolvePromise, rejectPromise) => {
    if (typeof command !== "string" || command.length === 0 || !Array.isArray(arguments_) ||
        !Number.isSafeInteger(options?.outputLimit) || options.outputLimit < 1 ||
        !Number.isSafeInteger(options?.timeoutMs) || options.timeoutMs < 1) {
      rejectPromise(new SafeFailure("operation"));
      return;
    }
    let child;
    try {
      child = spawnImplementation(command, arguments_, { cwd: options.cwd, env: options.env, stdio: ["ignore", "pipe", "pipe"] });
    } catch {
      rejectPromise(new SafeFailure("operation"));
      return;
    }
    if (child === null || typeof child !== "object" || child.stdout === undefined || child.stderr === undefined ||
        typeof child.once !== "function" || typeof child.kill !== "function") {
      rejectPromise(new SafeFailure("operation"));
      return;
    }
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    let terminalFailure;
    let closed = false;
    let stopRequested = false;
    const timer = setTimeout(() => requestStop(), options.timeoutMs);
    const finish = (callback) => {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      child.stdout?.removeAllListeners?.();
      child.stderr?.removeAllListeners?.();
      callback();
    };
    function requestStop() {
      terminalFailure = new SafeFailure("operation");
      if (stopRequested) return;
      stopRequested = true;
      try { child.stdout?.destroy?.(); } catch { /* fixed failure */ }
      try { child.stderr?.destroy?.(); } catch { /* fixed failure */ }
      try { child.kill("SIGKILL"); } catch { /* close/error still decides */ }
    }
    const consume = (target) => (chunk) => {
      if (terminalFailure !== undefined) return;
      const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += value.byteLength;
      if (bytes > options.outputLimit) {
        requestStop();
        return;
      }
      target.push(value);
    };
    child.stdout.on("data", consume(stdout));
    child.stderr.on("data", consume(stderr));
    child.stdout.once("error", requestStop);
    child.stderr.once("error", requestStop);
    child.once("error", requestStop);
    child.once("close", (code, signal) => finish(() => {
      if (terminalFailure !== undefined) {
        rejectPromise(terminalFailure);
        return;
      }
      resolvePromise({ code, signal, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") });
    }));
  });
}

export class OwnedWorkspace {
  constructor({ parent = tmpdir(), makeDirectory = mkdtemp, listDirectory = readdir, statPath = lstat, canonicalPath = realpath, removeDirectory = rm } = {}) {
    if (typeof parent !== "string" || !isAbsolute(parent)) reject("configuration");
    this.parentInput = parent;
    this.makeDirectory = makeDirectory;
    this.listDirectory = listDirectory;
    this.statPath = statPath;
    this.canonicalPath = canonicalPath;
    this.removeDirectory = removeDirectory;
    this.parent = undefined;
    this.candidate = undefined;
    this.identity = undefined;
  }

  hasCandidate() { return this.candidate !== undefined; }

  async initializeParent() {
    const parent = await this.canonicalPath(this.parentInput);
    if (typeof parent !== "string" || !isAbsolute(parent) || resolve(parent) !== parent) reject("configuration");
    const status = await this.statPath(parent);
    if (!status.isDirectory() || status.isSymbolicLink()) reject("configuration");
    this.parent = parent;
  }

  async requireGlobalAbsence() {
    if (this.parent === undefined) await this.initializeParent();
    const entries = await this.listDirectory(this.parent, { withFileTypes: true });
    if (!Array.isArray(entries) || entries.some((entry) => typeof entry?.name !== "string" || entry.name.startsWith(workspacePrefix))) reject("ownership");
  }

  async validateCandidate(candidate) {
    if (this.parent === undefined || typeof candidate !== "string" || !isAbsolute(candidate) || resolve(candidate) !== candidate ||
        dirname(candidate) !== this.parent || !basename(candidate).startsWith(workspacePrefix) || basename(candidate) === workspacePrefix) reject("ownership");
    const [status, canonical] = await Promise.all([this.statPath(candidate), this.canonicalPath(candidate)]);
    if (!status.isDirectory() || status.isSymbolicLink() || canonical !== candidate || !Number.isSafeInteger(status.dev) || !Number.isSafeInteger(status.ino)) reject("ownership");
    return { path: candidate, dev: status.dev, ino: status.ino };
  }

  async create() {
    await this.requireGlobalAbsence();
    this.candidate = await this.makeDirectory(join(this.parent, workspacePrefix));
    this.identity = await this.validateCandidate(this.candidate);
    return this.identity;
  }

  async cleanup() {
    if (this.candidate === undefined) return;
    const current = await this.validateCandidate(this.candidate);
    if (this.identity !== undefined && (current.path !== this.identity.path || current.dev !== this.identity.dev || current.ino !== this.identity.ino)) reject("cleanup");
    await this.removeDirectory(current.path, { recursive: true, force: false, maxRetries: 0 });
    try {
      await this.statPath(current.path);
      reject("cleanup");
    } catch (error) {
      if (error instanceof SafeFailure || error?.code !== "ENOENT") reject("cleanup");
    }
    this.candidate = undefined;
    this.identity = undefined;
    await this.requireGlobalAbsence();
  }
}

export async function resolveKubectlExecutable(environment, dependencies = {}) {
  const statPath = dependencies.statPath ?? lstat;
  const canonicalPath = dependencies.canonicalPath ?? realpath;
  const checkAccess = dependencies.checkAccess ?? access;
  const pathValue = environment?.PATH;
  if (typeof pathValue !== "string" || pathValue.length === 0) reject("configuration");
  const matches = [];
  for (const directory of pathValue.split(delimiter)) {
    if (!isAbsolute(directory) || resolve(directory) !== directory) continue;
    const candidate = join(directory, "kubectl");
    try {
      const canonical = await canonicalPath(candidate);
      const status = await statPath(canonical);
      await checkAccess(canonical, fsConstants.X_OK);
      if (isAbsolute(canonical) && resolve(canonical) === canonical && status.isFile() && !status.isSymbolicLink()) matches.push(canonical);
    } catch { /* not a candidate */ }
  }
  const unique = [...new Set(matches)];
  if (unique.length !== 1) reject("configuration");
  return unique[0];
}

export async function orchestrate({
  environment = process.env,
  resolveKubectl = resolveKubectlExecutable,
  workspace = new OwnedWorkspace(),
  runImplementation = runBounded,
  spawnImplementation = spawn,
} = {}) {
  const publicEnvironment = validateProofEnvironment(environment);
  const kubectl = await resolveKubectl(environment);
  const environmentWithCaches = await ensureGoCaches(environment, runImplementation, spawnImplementation);
  const buildEnvironment = buildBuildEnvironment(environmentWithCaches);
  let failure;
  let resultLine;
  try {
    const identity = await workspace.create();
    if (identity === null || typeof identity !== "object" || typeof identity.path !== "string") reject("ownership");
    const executable = join(identity.path, "fargate-proof");
    const build = await runImplementation("go", ["build", "-trimpath", "-mod=readonly", "-o", executable, "."], {
      cwd: proofDirectory, env: buildEnvironment, outputLimit, timeoutMs: buildTimeoutMs,
    }, spawnImplementation);
    if (build?.code !== 0 || build?.signal !== null || build?.stdout !== "" || build?.stderr !== "") reject("provider");
    const proofEnvironment = Object.assign(Object.create(null), publicEnvironment, { ZASP_M018_KUBECTL_EXECUTABLE: kubectl });
    const proof = await runImplementation(executable, [], {
      cwd: proofDirectory, env: proofEnvironment, outputLimit, timeoutMs: proofSupervisorTimeoutMs,
    }, spawnImplementation);
    if (proof?.code === 0 && proof?.signal === null && proof?.stdout === `${successLine}\n` && proof?.stderr === "") {
      resultLine = successLine;
    } else {
      const match = proof?.code !== 0 && proof?.signal === null && proof?.stdout === "" && typeof proof?.stderr === "string"
        ? /^EKS Fargate proof failed: (configuration|provider|scheduling|canary|ownership|cleanup|deadline|panic) rejected\.\n$/u.exec(proof.stderr)
        : null;
      reject(match?.[1] ?? "provider");
    }
  } catch (error) {
    failure = error instanceof SafeFailure ? error : new SafeFailure("provider");
  } finally {
    if (workspace?.hasCandidate?.() === true) {
      try { await workspace.cleanup(); } catch { failure = new SafeFailure("cleanup"); }
    }
  }
  if (failure !== undefined) throw failure;
  if (resultLine !== successLine) reject("provider");
  return resultLine;
}

export function fixedFailureLine(error) {
  const allowed = ["configuration", "provider", "scheduling", "canary", "ownership", "cleanup", "deadline", "panic"];
  const category = error instanceof SafeFailure && allowed.includes(error.category) ? error.category : "provider";
  return `EKS Fargate proof failed: ${category} rejected.`;
}

export async function runCLI({
  environment = process.env,
  writeOut = process.stdout.write.bind(process.stdout),
  writeErr = process.stderr.write.bind(process.stderr),
  ...dependencies
} = {}) {
  try {
    const line = await orchestrate({ environment, ...dependencies });
    writeOut(`${line}\n`);
    return 0;
  } catch (error) {
    writeErr(`${fixedFailureLine(error)}\n`);
    return 1;
  }
}

if (process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await runCLI();
}
