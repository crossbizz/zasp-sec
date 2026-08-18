import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { lstatSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Replaced with the locally verified official 4.7.0 repository digest before
// the live proof. Runtime ownership checks also match the resolved image ID.
export const LOCALSTACK_IMAGE = "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c";
export const successLine = "LocalStack storage proof passed: kms=true s3=true secret=true round_trip=true cleanup=true audit=true container_cleanup=true.";
export const artifactSuccessLine = "LocalStack artifact store passed: put=true get=true delete=true scoped=true encrypted=true cleanup=true audit=true container_cleanup=true.";
export const jobQueueSuccessLine = "LocalStack job queue passed: publish=2 consume=2 acknowledge=2 scoped=true redrive=true empty=true cleanup=true audit=true container_cleanup=true.";
export const queueDefinitionsSuccessLine = "LocalStack queue definitions passed: queues=3 dlqs=3 schemas=3 retention=true redrive=true cleanup=true audit=true container_cleanup=true.";
export const artifactProofTimeoutMilliseconds = 150_000;
export const queueDefinitionsProofTimeoutMilliseconds = 300_000;
export const STORAGE_MODE = "storage";
export const ARTIFACT_MODE = "artifact";
export const JOB_QUEUE_MODE = "job-queue";
export const QUEUE_DEFINITIONS_MODE = "queue-definitions";
const fixedFailure = (category) => `LocalStack storage proof failed: ${category} rejected.`;
const artifactFailure = (category) => `LocalStack artifact store failed: ${category} rejected.`;
const jobQueueFailure = (category) => `LocalStack job queue failed: ${category} rejected.`;
const queueDefinitionsFailure = (category) => `LocalStack queue definitions failed: ${category} rejected.`;
const idPattern = /^[a-f0-9]{64}$/;
const storageProofDirectory = fileURLToPath(new URL(".", import.meta.url));
const sqsProofDirectory = fileURLToPath(new URL("../localstack-sqs/", import.meta.url));
const readinessBodyLimit = 16_384;
const readinessDeadlineMilliseconds = 500;
const commandCombinedOutputLimit = 1024 * 1024;
const commandPerStreamOutputLimit = commandCombinedOutputLimit / 2;
const environmentCombinedOutputLimit = 16_384;

const modeConfigurations = Object.freeze({
  [STORAGE_MODE]: Object.freeze({
    namePrefix: "zasp-m0-07-",
    proofLabel: "m0-07",
    services: ["s3", "kms", "secretsmanager"],
    successLine,
    failureLine: fixedFailure,
    proofArguments: [],
    childSuccess: "LocalStack storage proof passed: kms=true s3=true secret=true round_trip=true cleanup=true audit=true.",
    temporaryPrefix: "zasp-m0-07-",
    executable: "storage-proof",
    proofTimeoutMilliseconds: 90_000,
    proofDirectory: storageProofDirectory,
    extraEnvironment: [],
  }),
  [ARTIFACT_MODE]: Object.freeze({
    namePrefix: "zasp-m1-12-",
    proofLabel: "m1-12",
    services: ["s3", "kms"],
    successLine: artifactSuccessLine,
    failureLine: artifactFailure,
    proofArguments: ["artifact-store"],
    childSuccess: "LocalStack artifact store passed: put=true get=true delete=true scoped=true encrypted=true cleanup=true audit=true.",
    temporaryPrefix: "zasp-m1-12-",
    executable: "artifact-store-proof",
    proofTimeoutMilliseconds: artifactProofTimeoutMilliseconds,
    proofDirectory: storageProofDirectory,
    extraEnvironment: [],
  }),
  [JOB_QUEUE_MODE]: Object.freeze({
    namePrefix: "zasp-m1-13-",
    proofLabel: "m1-13",
    services: ["sqs"],
    successLine: jobQueueSuccessLine,
    failureLine: jobQueueFailure,
    proofArguments: ["job-queue"],
    childSuccess: "LocalStack job queue passed: publish=2 consume=2 acknowledge=2 scoped=true redrive=true empty=true cleanup=true audit=true.",
    temporaryPrefix: "zasp-m1-13-",
    executable: "job-queue-proof",
    proofTimeoutMilliseconds: 150_000,
    proofDirectory: sqsProofDirectory,
    extraEnvironment: ["SQS_ENDPOINT_STRATEGY=dynamic"],
  }),
  [QUEUE_DEFINITIONS_MODE]: Object.freeze({
    namePrefix: "zasp-m1-33-",
    proofLabel: "m1-33",
    services: ["sqs"],
    successLine: queueDefinitionsSuccessLine,
    failureLine: queueDefinitionsFailure,
    proofArguments: ["queue-definitions"],
    childSuccess: "LocalStack queue definitions passed: queues=3 dlqs=3 schemas=3 retention=true redrive=true cleanup=true audit=true.",
    temporaryPrefix: "zasp-m1-33-",
    executable: "queue-definitions-proof",
    proofTimeoutMilliseconds: queueDefinitionsProofTimeoutMilliseconds,
    proofDirectory: sqsProofDirectory,
    extraEnvironment: ["SQS_ENDPOINT_STRATEGY=dynamic"],
  }),
});

function modeConfiguration(mode) {
  const configuration = modeConfigurations[mode];
  if (configuration === undefined) throw categorized("configuration");
  return configuration;
}

export function buildDockerRunArguments(name, mode = STORAGE_MODE) {
  const configuration = modeConfiguration(mode);
  const namePattern = new RegExp(`^${configuration.namePrefix}[a-f0-9]{16}$`);
  if (!namePattern.test(name)) throw categorized("configuration");
  const marker = name.slice(configuration.namePrefix.length);
  const arguments_ = [
    "run", "--detach", "--rm", "--name", name,
    "--publish", "127.0.0.1::4566",
    "--env", `SERVICES=${configuration.services.join(",")}`,
    "--env", "PERSISTENCE=0",
  ];
  for (const value of configuration.extraEnvironment) arguments_.push("--env", value);
  arguments_.push(
    "--label", `zasp.proof=${configuration.proofLabel}`,
    "--label", `zasp.marker=${marker}`,
    LOCALSTACK_IMAGE,
  );
  return arguments_;
}

export function buildProofEnvironment(endpoint, path) {
  return { AWS_ENDPOINT_URL: endpoint, PATH: path };
}

export function buildGoToolEnvironment(path, buildCache, moduleCache) {
  return {
    PATH: path,
    GOCACHE: buildCache,
    GOMODCACHE: moduleCache,
    GOENV: "off",
    GOPROXY: "off",
    GOSUMDB: "off",
    GOTOOLCHAIN: "local",
    CGO_ENABLED: "0",
  };
}

function categorized(category) {
  const error = new Error("fixed orchestrator failure");
  error.category = category;
  return error;
}

function resultCode(result) {
  return Number.isInteger(result.status) && result.status > 0 && result.status <= 125 ? result.status : 1;
}

export async function orchestrate(runtime, options = {}) {
  const readinessAttempts = options.readinessAttempts ?? 120;
  const wait = options.wait ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
  const runtimeSuccessLine = runtime.successLine ?? successLine;
  const runtimeFailureLine = runtime.failureLine ?? fixedFailure;
  let started = false;
  let proofCode = 1;
  let line = runtimeFailureLine("operation");
  let cleanupFailed = false;
  try {
    await runtime.ensureAbsent();
    const token = await runtime.start();
    started = true;
    await runtime.verifyOwned(token);
    const endpoint = await runtime.endpoint(token);
    let ready = false;
    for (let attempt = 0; attempt < readinessAttempts; attempt += 1) {
      if (await runtime.isReady(endpoint)) { ready = true; break; }
      if (attempt + 1 < readinessAttempts) await wait(250);
    }
    if (!ready) throw categorized("readiness");
    proofCode = await runtime.runProof(endpoint);
    line = proofCode === 0 ? runtimeSuccessLine : runtimeFailureLine("operation");
  } catch (error) {
    proofCode = 1;
    line = runtimeFailureLine(error?.category === "readiness" ? "readiness" : "operation");
  } finally {
    if (started || runtime.hasCandidate?.() === true) {
      try { await runtime.remove(); } catch { cleanupFailed = true; }
      try { await runtime.requireAbsent(); } catch { cleanupFailed = true; }
    }
  }
  if (cleanupFailed) return { code: 1, line: runtimeFailureLine("cleanup") };
  return { code: proofCode, line };
}

export class DockerRuntime {
  static image = LOCALSTACK_IMAGE;

  constructor({
    path = process.env.PATH,
    home = process.env.HOME,
    marker,
    randomBytesSource = randomBytes,
    mode = STORAGE_MODE,
    command = spawnSync,
    makeTemp = mkdtempSync,
    removeTemp = rmSync,
    tempParent = tmpdir(),
    canonicalPath = realpathSync,
    statPath = lstatSync,
  } = {}) {
    const configuration = modeConfiguration(mode);
    if (marker === undefined) marker = randomBytesSource(8).toString("hex");
    if (typeof path !== "string" || path.length === 0 || !isAbsolute(home ?? "") || !isAbsolute(tempParent ?? "") ||
      !/^[a-f0-9]{16}$/.test(marker) || typeof command !== "function" || typeof makeTemp !== "function" ||
      typeof removeTemp !== "function" || typeof canonicalPath !== "function" || typeof statPath !== "function") {
      throw categorized("configuration");
    }
    let canonicalTempParent;
    try { canonicalTempParent = canonicalPath(tempParent); } catch { throw categorized("configuration"); }
    if (typeof canonicalTempParent !== "string" || !isAbsolute(canonicalTempParent) || resolve(canonicalTempParent) !== canonicalTempParent) {
      throw categorized("configuration");
    }
    this.path = path;
    this.home = home;
    this.mode = mode;
    this.configuration = configuration;
    this.name = `${configuration.namePrefix}${marker}`;
    this.marker = marker;
    this.successLine = configuration.successLine;
    this.failureLine = configuration.failureLine;
    this.command = command;
    this.makeTemp = makeTemp;
    this.removeTemp = removeTemp;
    this.tempParent = canonicalTempParent;
    this.canonicalPath = canonicalPath;
    this.statPath = statPath;
    this.token = undefined;
    this.startUncertain = false;
    this.resolvedImageID = undefined;
  }

  ownedTemporaryDirectory(value) {
    if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value) return undefined;
    let status;
    let canonical;
    try { status = this.statPath(value); canonical = this.canonicalPath(value); } catch { return undefined; }
    if (!status?.isDirectory?.() || status?.isSymbolicLink?.() || !Number.isSafeInteger(status.dev) ||
      !Number.isSafeInteger(status.ino) || canonical !== value || !isAbsolute(canonical) || resolve(canonical) !== canonical) {
      return undefined;
    }
    const prefix = join(this.tempParent, this.configuration.temporaryPrefix);
    if (dirname(canonical) !== this.tempParent || !canonical.startsWith(prefix) || canonical.length === prefix.length) return undefined;
    return { path: canonical, dev: status.dev, ino: status.ino };
  }

  stillOwnsTemporaryDirectory(identity) {
    const current = this.ownedTemporaryDirectory(identity?.path);
    return current !== undefined && current.path === identity.path && current.dev === identity.dev && current.ino === identity.ino;
  }

  docker(args) {
    return this.command("docker", args, { env: { PATH: this.path }, encoding: "utf8", timeout: 30_000, killSignal: "SIGKILL", maxBuffer: commandPerStreamOutputLimit });
  }

  hasCandidate() { return this.startUncertain || idPattern.test(this.token ?? ""); }

  namedCandidates() {
    const result = this.docker(["ps", "--all", "--no-trunc", "--filter", `name=^/${this.name}$`, "--format", "{{.ID}}"]) ?? {};
    return { result, candidates: String(result.stdout ?? "").trim().split("\n").filter(Boolean) };
  }

  retainedIDCandidates() {
    if (!idPattern.test(this.token ?? "")) return { result: { status: 0 }, candidates: [] };
    const result = this.docker(["ps", "--all", "--no-trunc", "--filter", `id=${this.token}`, "--format", "{{.ID}}"]) ?? {};
    return { result, candidates: String(result.stdout ?? "").trim().split("\n").filter(Boolean) };
  }

  async ensureAbsent() {
    const existing = this.namedCandidates();
    if (existing.result.status !== 0 || existing.candidates.length !== 0) throw categorized("operation");
    const image = this.docker(["image", "inspect", "--format", "{{.Id}}", LOCALSTACK_IMAGE]);
    const imageID = String(image?.stdout ?? "").trim();
    if (image.status !== 0 || !/^sha256:[a-f0-9]{64}$/.test(imageID)) throw categorized("operation");
    this.resolvedImageID = imageID;
  }

  async start() {
    this.startUncertain = true;
    const result = this.docker(buildDockerRunArguments(this.name, this.mode)) ?? {};
    const token = String(result.stdout ?? "").trim();
    if (idPattern.test(token)) this.token = token;
    if (result.status === 0 && idPattern.test(token)) {
      this.startUncertain = false;
      return token;
    }
    if (Number.isInteger(result.status) && result.status !== 0 && result.signal == null && result.error == null) {
      this.startUncertain = false;
      this.token = undefined;
      throw categorized("operation");
    }
    const listed = this.namedCandidates();
    if (listed.result.status !== 0 || listed.candidates.length !== 1 || !idPattern.test(listed.candidates[0])) throw categorized("operation");
    this.token = listed.candidates[0];
    await this.verifyOwned(this.token);
    this.startUncertain = false;
    return this.token;
  }

  async verifyOwned(token = this.token) {
    if (!idPattern.test(token ?? "") || this.resolvedImageID === undefined) throw categorized("operation");
    const format = "{{.Id}}|{{.Name}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels \"zasp.proof\"}}|{{index .Config.Labels \"zasp.marker\"}}";
    const result = this.docker(["inspect", "--format", format, token]);
    if (result.status !== 0) throw categorized("operation");
    const fields = result.stdout.trim().split("|");
    if (fields.length !== 6 || fields[0] !== token || fields[1] !== `/${this.name}` || fields[2] !== this.resolvedImageID || fields[3] !== LOCALSTACK_IMAGE || fields[4] !== this.configuration.proofLabel || fields[5] !== this.marker) throw categorized("operation");
    if (this.mode === JOB_QUEUE_MODE || this.mode === QUEUE_DEFINITIONS_MODE) {
      const environmentResult = this.docker(["inspect", "--format", "{{json .Config.Env}}", token]);
      let environment;
      try { environment = JSON.parse(String(environmentResult?.stdout ?? "")); } catch { throw categorized("operation"); }
      if (environmentResult?.status !== 0 || !Array.isArray(environment) ||
        environment.some((value) => typeof value !== "string")) throw categorized("operation");
      const expected = [
        `SERVICES=${this.configuration.services.join(",")}`,
        "PERSISTENCE=0",
        ...this.configuration.extraEnvironment,
      ];
      const reserved = ["SERVICES=", "PERSISTENCE=", "SQS_ENDPOINT_STRATEGY="];
      const forbiddenAuthority = new Set([
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
      ]);
      if (expected.some((value) => environment.filter((entry) => entry === value).length !== 1) ||
        environment.some((entry) => reserved.some((prefix) => entry.startsWith(prefix)) && !expected.includes(entry)) ||
        environment.some((entry) => {
          const key = entry.slice(0, Math.max(0, entry.indexOf("="))).toUpperCase();
          return forbiddenAuthority.has(key) || key.startsWith("AWS_CONTAINER_CREDENTIALS_");
        })) {
        throw categorized("operation");
      }
    }
  }

  async endpoint(token = this.token) {
    await this.verifyOwned(token);
    const result = this.docker(["port", token, "4566/tcp"]);
    const match = /^127\.0\.0\.1:([0-9]{4,5})$/.exec(result.stdout.trim());
    const port = match === null ? 0 : Number(match[1]);
    if (result.status !== 0 || port < 1024 || port > 65535) throw categorized("operation");
    return `http://127.0.0.1:${port}`;
  }

  async isReady(endpoint) {
    return new Promise((resolve) => {
      let request;
      let response;
      let settled = false;
      const finish = (accepted) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        if (!accepted) {
          response?.destroy();
          request?.destroy();
        }
        resolve(accepted);
      };
      const deadline = setTimeout(() => finish(false), readinessDeadlineMilliseconds);
      try {
        request = http.get(`${endpoint}/_localstack/health`, (incoming) => {
          response = incoming;
          const chunks = [];
          let bytes = 0;
          response.on("data", (chunk) => {
            if (settled) return;
            bytes += Buffer.byteLength(chunk);
            if (bytes > readinessBodyLimit) {
              finish(false);
              return;
            }
            chunks.push(chunk);
          });
          response.on("end", () => {
            try {
              const parsed = JSON.parse(Buffer.concat(chunks, bytes).toString("utf8"));
              const accepted = new Set(["available", "running"]);
              finish(response.statusCode === 200 && this.configuration.services.every((service) => accepted.has(parsed.services?.[service])));
            } catch { finish(false); }
          });
          response.on("error", () => finish(false));
        });
        request.on("error", () => finish(false));
      } catch {
        finish(false);
      }
    });
  }

  async runProof(endpoint) {
    const goEnvironment = this.command("go", ["env", "-json", "GOCACHE", "GOMODCACHE"], {
      env: { PATH: this.path, HOME: this.home, GOENV: "off" }, encoding: "utf8", timeout: 10_000, killSignal: "SIGKILL", maxBuffer: environmentCombinedOutputLimit / 2,
    });
    if (goEnvironment?.status !== 0) return 1;
    let caches;
    try { caches = JSON.parse(goEnvironment.stdout); } catch { return 1; }
    if (!isAbsolute(caches.GOCACHE ?? "") || !isAbsolute(caches.GOMODCACHE ?? "")) return 1;
    let temporaryDirectory;
    let temporaryIdentity;
    let code = 1;
    try {
      const candidate = this.makeTemp(join(this.tempParent, this.configuration.temporaryPrefix));
      temporaryIdentity = this.ownedTemporaryDirectory(candidate);
      if (temporaryIdentity === undefined) return 1;
      temporaryDirectory = temporaryIdentity.path;
      const executable = join(temporaryDirectory, this.configuration.executable);
      const build = this.command("go", ["build", "-trimpath", "-mod=readonly", "-o", executable, "."], {
        cwd: this.configuration.proofDirectory,
        env: buildGoToolEnvironment(this.path, caches.GOCACHE, caches.GOMODCACHE),
        encoding: "utf8",
        timeout: 90_000,
        killSignal: "SIGKILL",
        maxBuffer: commandPerStreamOutputLimit,
      });
      if (build?.status !== 0 || build.stdout !== "" || build.stderr !== "") return resultCode(build);
      const result = this.command(executable, this.configuration.proofArguments, {
        cwd: this.configuration.proofDirectory,
        env: buildProofEnvironment(endpoint, this.path),
        encoding: "utf8",
        timeout: this.configuration.proofTimeoutMilliseconds,
        killSignal: "SIGKILL",
        maxBuffer: commandPerStreamOutputLimit,
      });
      if (result?.status === 0 && result.stdout === `${this.configuration.childSuccess}\n` && result.stderr === "") code = 0;
      else code = resultCode(result);
    } catch {
      code = 1;
    } finally {
      if (temporaryIdentity !== undefined) {
        try {
          if (!this.stillOwnsTemporaryDirectory(temporaryIdentity)) code = 1;
          else this.removeTemp(temporaryDirectory, { recursive: true, force: false, maxRetries: 0 });
        } catch { code = 1; }
      }
    }
    return code;
  }

  async remove() {
    if (!idPattern.test(this.token ?? "")) {
      const listed = this.namedCandidates();
      if (listed.result.status !== 0 || listed.candidates.length > 1 ||
        (listed.candidates.length === 1 && !idPattern.test(listed.candidates[0]))) throw categorized("cleanup");
      if (listed.candidates.length === 0) return;
      this.token = listed.candidates[0];
    }
    await this.verifyOwned(this.token);
    const result = this.docker(["rm", "--force", this.token]);
    if (result.status !== 0 || result.stdout.trim() !== this.token) throw categorized("cleanup");
  }

  async requireAbsent() {
    if (idPattern.test(this.token ?? "") && this.docker(["inspect", this.token]).status === 0) throw categorized("cleanup");
    const byID = this.retainedIDCandidates();
    if (byID.result.status !== 0 || byID.candidates.length !== 0) throw categorized("cleanup");
    const byName = this.namedCandidates();
    if (byName.result.status !== 0 || byName.candidates.length !== 0) throw categorized("cleanup");
  }
}

export async function runMain({
  runtimeFactory,
  mode = STORAGE_MODE,
  stdout = process.stdout,
  stderr = process.stderr,
  setExitCode = (code) => { process.exitCode = code; },
} = {}) {
  const configuration = modeConfiguration(mode);
  if (runtimeFactory === undefined) runtimeFactory = () => new DockerRuntime({ mode });
  let runtime;
  let result;
  try {
    runtime = runtimeFactory();
  } catch {
    result = { code: 1, line: configuration.failureLine("configuration") };
  }
  if (result === undefined) {
    try {
      result = await orchestrate(runtime);
    } catch {
      result = { code: 1, line: configuration.failureLine("operation") };
    }
  }
  (result.code === 0 ? stdout : stderr).write(`${result.line}\n`);
  setExitCode(result.code);
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await runMain();
