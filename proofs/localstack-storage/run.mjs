import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

// Replaced with the locally verified official 4.7.0 repository digest before
// the live proof. Runtime ownership checks also match the resolved image ID.
export const LOCALSTACK_IMAGE = "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c";
export const successLine = "LocalStack storage proof passed: kms=true s3=true secret=true round_trip=true cleanup=true audit=true container_cleanup=true.";
export const artifactSuccessLine = "LocalStack artifact store passed: put=true get=true delete=true scoped=true encrypted=true cleanup=true audit=true container_cleanup=true.";
export const artifactProofTimeoutMilliseconds = 150_000;
export const STORAGE_MODE = "storage";
export const ARTIFACT_MODE = "artifact";
const fixedFailure = (category) => `LocalStack storage proof failed: ${category} rejected.`;
const artifactFailure = (category) => `LocalStack artifact store failed: ${category} rejected.`;
const idPattern = /^[a-f0-9]{64}$/;
const proofDirectory = fileURLToPath(new URL(".", import.meta.url));
const readinessBodyLimit = 16_384;
const readinessDeadlineMilliseconds = 500;

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
  return [
    "run", "--detach", "--rm", "--name", name,
    "--publish", "127.0.0.1::4566",
    "--env", `SERVICES=${configuration.services.join(",")}`,
    "--env", "PERSISTENCE=0",
    "--label", `zasp.proof=${configuration.proofLabel}`,
    "--label", `zasp.marker=${marker}`,
    LOCALSTACK_IMAGE,
  ];
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

  constructor({ path = process.env.PATH, marker, randomBytesSource = randomBytes, mode = STORAGE_MODE } = {}) {
    const configuration = modeConfiguration(mode);
    if (marker === undefined) marker = randomBytesSource(8).toString("hex");
    if (typeof path !== "string" || path.length === 0 || !/^[a-f0-9]{16}$/.test(marker)) throw categorized("configuration");
    this.path = path;
    this.mode = mode;
    this.configuration = configuration;
    this.name = `${configuration.namePrefix}${marker}`;
    this.marker = marker;
    this.successLine = configuration.successLine;
    this.failureLine = configuration.failureLine;
    this.token = undefined;
    this.resolvedImageID = undefined;
  }

  docker(args) {
    return spawnSync("docker", args, { env: { PATH: this.path }, encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024 });
  }

  hasCandidate() { return idPattern.test(this.token ?? ""); }

  async ensureAbsent() {
    const result = this.docker(["ps", "--all", "--filter", `name=^/${this.name}$`, "--format", "{{.ID}}"]);
    if (result.status !== 0 || result.stdout.trim() !== "") throw categorized("operation");
    const image = this.docker(["image", "inspect", "--format", "{{.Id}}", LOCALSTACK_IMAGE]);
    const imageID = image.stdout.trim();
    if (image.status !== 0 || !/^sha256:[a-f0-9]{64}$/.test(imageID)) throw categorized("operation");
    this.resolvedImageID = imageID;
  }

  async start() {
    const result = this.docker(buildDockerRunArguments(this.name, this.mode));
    const token = result.stdout.trim();
    if (result.status === 0 && idPattern.test(token)) {
      this.token = token;
      return token;
    }
    const listed = this.docker(["ps", "--all", "--filter", `name=^/${this.name}$`, "--format", "{{.ID}}"]);
    const candidates = listed.stdout.trim().split("\n").filter(Boolean);
    if (listed.status !== 0 || candidates.length !== 1 || !idPattern.test(candidates[0])) throw categorized("operation");
    this.token = candidates[0];
    await this.verifyOwned(this.token);
    return this.token;
  }

  async verifyOwned(token = this.token) {
    if (!idPattern.test(token ?? "") || this.resolvedImageID === undefined) throw categorized("operation");
    const format = "{{.Id}}|{{.Name}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels \"zasp.proof\"}}|{{index .Config.Labels \"zasp.marker\"}}";
    const result = this.docker(["inspect", "--format", format, token]);
    if (result.status !== 0) throw categorized("operation");
    const fields = result.stdout.trim().split("|");
    if (fields.length !== 6 || fields[0] !== token || fields[1] !== `/${this.name}` || fields[2] !== this.resolvedImageID || fields[3] !== LOCALSTACK_IMAGE || fields[4] !== this.configuration.proofLabel || fields[5] !== this.marker) throw categorized("operation");
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
    const goEnvironment = spawnSync("go", ["env", "-json", "GOCACHE", "GOMODCACHE"], {
      env: { PATH: this.path, HOME: process.env.HOME, GOENV: "off" }, encoding: "utf8", timeout: 10_000, maxBuffer: 16_384,
    });
    if (goEnvironment.status !== 0) return 1;
    let caches;
    try { caches = JSON.parse(goEnvironment.stdout); } catch { return 1; }
    if (!isAbsolute(caches.GOCACHE ?? "") || !isAbsolute(caches.GOMODCACHE ?? "")) return 1;
    const temporaryDirectory = mkdtempSync(join(tmpdir(), this.configuration.temporaryPrefix));
    const executable = join(temporaryDirectory, this.configuration.executable);
    let code = 1;
    try {
      const build = spawnSync("go", ["build", "-mod=readonly", "-o", executable, "."], {
        cwd: proofDirectory,
        env: buildGoToolEnvironment(this.path, caches.GOCACHE, caches.GOMODCACHE),
        encoding: "utf8",
        timeout: this.configuration.proofTimeoutMilliseconds,
        maxBuffer: 1024 * 1024,
      });
      if (build.status !== 0 || build.stdout.trim() !== "" || build.stderr.trim() !== "") return resultCode(build);
      const result = spawnSync(executable, this.configuration.proofArguments, {
        cwd: proofDirectory,
        env: buildProofEnvironment(endpoint, this.path),
        encoding: "utf8",
        timeout: 90_000,
        maxBuffer: 1024 * 1024,
      });
      if (result.status === 0 && result.stdout.trim() === this.configuration.childSuccess && result.stderr.trim() === "") code = 0;
      else code = resultCode(result);
    } finally {
      try { rmSync(temporaryDirectory, { recursive: true, force: false }); } catch { code = 1; }
    }
    return code;
  }

  async remove() {
    await this.verifyOwned(this.token);
    const result = this.docker(["rm", "--force", this.token]);
    if (result.status !== 0 || result.stdout.trim() !== this.token) throw categorized("cleanup");
  }

  async requireAbsent() {
    const byID = this.docker(["inspect", this.token]);
    const byName = this.docker(["ps", "--all", "--filter", `name=^/${this.name}$`, "--format", "{{.ID}}"]);
    if (byID.status === 0 || byName.status !== 0 || byName.stdout.trim() !== "") throw categorized("cleanup");
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
