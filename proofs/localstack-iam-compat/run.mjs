import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { lstatSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const LOCALSTACK_IMAGE = "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c";
export const successLine = "LocalStack IAM compatibility proof passed: namespaces=true assumed=true allowed_read=true explicit_deny=true cleanup=true audit=true container_cleanup=true.";

const namePattern = /^zasp-prov-01-([a-f0-9]{16})$/;
const containerIDPattern = /^[a-f0-9]{64}$/;
const imageIDPattern = /^sha256:[a-f0-9]{64}$/;
const readinessBodyLimit = 16_384;
const readinessDeadlineMilliseconds = 500;
const processOutputLimit = 4096;
const proofDirectory = fileURLToPath(new URL(".", import.meta.url));

function categorized(category) {
  const error = new Error("fixed orchestrator failure");
  error.category = category;
  return error;
}

function failureLine(category) { return `LocalStack IAM compatibility proof failed: ${category} rejected.`; }

function validateProofName(name) {
  const match = typeof name === "string" ? namePattern.exec(name) : null;
  if (match === null) throw categorized("configuration");
  return match[1];
}

export function buildDockerRunArguments(name) {
  const marker = validateProofName(name);
  return [
    "run", "--detach", "--rm", "--name", name,
    "--publish", "127.0.0.1::4566",
    "--env", "SERVICES=iam,sts",
    "--env", "ENFORCE_IAM=1",
    "--env", "PERSISTENCE=0",
    "--label", "zasp.proof=prov-01",
    "--label", `zasp.marker=${marker}`,
    LOCALSTACK_IMAGE,
  ];
}

export function buildProofEnvironment(endpoint, path) {
  if (typeof endpoint !== "string" || endpoint.length === 0 || typeof path !== "string" || path.length === 0) throw categorized("configuration");
  return { AWS_ENDPOINT_URL: endpoint, PATH: path };
}

export function buildGoToolEnvironment(path, buildCache, moduleCache) {
  if (![path, buildCache, moduleCache].every((value) => typeof value === "string" && value.length > 0)) throw categorized("configuration");
  return { PATH: path, GOCACHE: buildCache, GOMODCACHE: moduleCache, GOENV: "off", GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local", CGO_ENABLED: "0" };
}

function resultCode(result) {
  return Number.isInteger(result?.status) && result.status > 0 && result.status <= 125 ? result.status : 1;
}

function boundedOutput(result) {
  const stdout = typeof result?.stdout === "string" ? result.stdout : "";
  const stderr = typeof result?.stderr === "string" ? result.stderr : "";
  return Buffer.byteLength(stdout) + Buffer.byteLength(stderr) <= processOutputLimit;
}

export function runBounded(command, arguments_, options, spawnImplementation = spawn) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnImplementation(command, arguments_, { cwd: options.cwd, env: options.env, stdio: ["ignore", "pipe", "pipe"] });
    } catch { reject(categorized("operation")); return; }
    if (!child || !child.stdout || !child.stderr || typeof child.stdout.on !== "function" || typeof child.stderr.on !== "function") {
      reject(categorized("operation")); return;
    }
    let settled = false; let total = 0; let timer;
    const finish = (callback) => {
      if (settled) return;
      settled = true; clearTimeout(timer); callback();
    };
    const stop = () => {
      child.stdout.destroy?.(); child.stderr.destroy?.(); child.kill?.("SIGKILL");
    };
    const consume = (target) => (chunk) => {
      const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += value.byteLength;
      if (total > options.outputLimit) { stop(); finish(() => reject(categorized("operation"))); return; }
      target.push(value);
    };
    const stdout = []; const stderr = [];
    child.stdout.on("data", consume(stdout)); child.stderr.on("data", consume(stderr));
    child.once("error", () => finish(() => reject(categorized("operation"))));
    child.once("close", (status, signal) => finish(() => resolve({ status, signal, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") })));
    timer = setTimeout(() => { stop(); finish(() => reject(categorized("operation"))); }, options.timeoutMs);
  });
}

export class DockerRuntime {
  constructor({ path = process.env.PATH, home = process.env.HOME, marker, randomBytesSource = randomBytes, command = spawnSync, spawnProcess = spawn, makeTemp = mkdtempSync, removeTemp = rmSync, tempParent = tmpdir(), canonicalPath = realpathSync, statPath = lstatSync } = {}) {
    if (marker === undefined) marker = randomBytesSource(8).toString("hex");
    if (typeof path !== "string" || path.length === 0 || !isAbsolute(home ?? "") || !isAbsolute(tempParent ?? "") || !/^[a-f0-9]{16}$/.test(marker) || typeof command !== "function" || typeof spawnProcess !== "function" || typeof makeTemp !== "function" || typeof removeTemp !== "function" || typeof canonicalPath !== "function" || typeof statPath !== "function") throw categorized("configuration");
    let canonicalTempParent;
    try { canonicalTempParent = canonicalPath(tempParent); } catch { throw categorized("configuration"); }
    if (typeof canonicalTempParent !== "string" || !isAbsolute(canonicalTempParent) || resolve(canonicalTempParent) !== canonicalTempParent) throw categorized("configuration");
    this.path = path;
    this.home = home;
    this.marker = marker;
    this.name = `zasp-prov-01-${marker}`;
    this.command = command;
    this.spawnProcess = spawnProcess;
    this.makeTemp = makeTemp;
    this.removeTemp = removeTemp;
    this.tempParent = canonicalTempParent;
    this.canonicalPath = canonicalPath;
    this.statPath = statPath;
    this.token = undefined;
    this.startAttempted = false;
    this.resolvedImageID = undefined;
  }

  ownedTemporaryDirectory(value) {
    if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value) return undefined;
    let status; let canonical;
    try { status = this.statPath(value); canonical = this.canonicalPath(value); } catch { return undefined; }
    if (!status?.isDirectory?.() || status?.isSymbolicLink?.() || typeof canonical !== "string" || value !== canonical || !isAbsolute(canonical) || resolve(canonical) !== canonical) return undefined;
    const prefix = join(this.tempParent, "zasp-prov-01-");
    if (dirname(canonical) !== this.tempParent || !canonical.startsWith(prefix) || canonical.length === prefix.length) return undefined;
    return canonical;
  }

  docker(args) {
    return this.command("docker", args, { env: { PATH: this.path }, encoding: "utf8", timeout: 30_000, maxBuffer: readinessBodyLimit });
  }

  hasCandidate() { return this.startAttempted || containerIDPattern.test(this.token ?? ""); }

  namedCandidates() {
    const listed = this.docker(["ps", "--all", "--no-trunc", "--filter", `name=^/${this.name}$`, "--format", "{{.ID}}"]);
    return { listed, values: String(listed?.stdout ?? "").trim().split("\n").filter(Boolean) };
  }

  async ensureAbsent() {
    const existing = this.namedCandidates();
    if (existing.listed?.status !== 0 || existing.values.length !== 0) throw categorized("operation");
    const image = this.docker(["image", "inspect", "--format", "{{.Id}}", LOCALSTACK_IMAGE]);
    const id = String(image?.stdout ?? "").trim();
    if (image?.status !== 0 || !imageIDPattern.test(id)) throw categorized("operation");
    this.resolvedImageID = id;
  }

  async start() {
    this.startAttempted = true;
    const started = this.docker(buildDockerRunArguments(this.name));
    const direct = String(started?.stdout ?? "").trim();
    if (containerIDPattern.test(direct)) this.token = direct;
    if (started?.status === 0 && containerIDPattern.test(direct)) {
      return direct;
    }
    const listed = this.namedCandidates();
    if (listed.listed?.status !== 0 || listed.values.length !== 1 || !containerIDPattern.test(listed.values[0])) throw categorized("operation");
    this.token = listed.values[0];
    await this.verifyOwned(this.token);
    return this.token;
  }

  async verifyOwned(token = this.token) {
    if (!containerIDPattern.test(token ?? "") || !imageIDPattern.test(this.resolvedImageID ?? "")) throw categorized("operation");
    const format = "{{.Id}}|{{.Name}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels \"zasp.proof\"}}|{{index .Config.Labels \"zasp.marker\"}}";
    const inspected = this.docker(["inspect", "--format", format, token]);
    if (inspected?.status !== 0) throw categorized("operation");
    const fields = String(inspected.stdout ?? "").trim().split("|");
    if (fields.length !== 6 || fields[0] !== token || fields[1] !== `/${this.name}` || fields[2] !== this.resolvedImageID || fields[3] !== LOCALSTACK_IMAGE || fields[4] !== "prov-01" || fields[5] !== this.marker) throw categorized("operation");
  }

  async endpoint(token = this.token) {
    await this.verifyOwned(token);
    const port = this.docker(["port", token, "4566/tcp"]);
    const match = /^127\.0\.0\.1:([0-9]{4,5})$/.exec(String(port?.stdout ?? "").trim());
    const number = match === null ? 0 : Number(match[1]);
    if (port?.status !== 0 || number < 1024 || number > 65535) throw categorized("operation");
    return `http://127.0.0.1:${number}`;
  }

  async isReady(endpoint) {
    return new Promise((resolve) => {
      let request; let response; let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true; clearTimeout(deadline);
        if (!value) { response?.destroy(); request?.destroy(); }
        resolve(value);
      };
      const deadline = setTimeout(() => finish(false), readinessDeadlineMilliseconds);
      try {
        request = http.get(`${endpoint}/_localstack/health`, (incoming) => {
          response = incoming;
          const chunks = []; let bytes = 0;
          response.on("data", (chunk) => {
            if (settled) return;
            bytes += Buffer.byteLength(chunk);
            if (bytes > readinessBodyLimit) { finish(false); return; }
            chunks.push(chunk);
          });
          response.on("end", () => {
            try {
              const health = JSON.parse(Buffer.concat(chunks, bytes).toString("utf8"));
              const available = new Set(["available", "running"]);
              finish(response.statusCode === 200 && ["iam", "sts"].every((service) => available.has(health.services?.[service])));
            } catch { finish(false); }
          });
          response.on("error", () => finish(false));
        });
        request.on("error", () => finish(false));
      } catch { finish(false); }
    });
  }

  async runProof(endpoint) {
    const goEnvironment = this.command("go", ["env", "-json", "GOCACHE", "GOMODCACHE"], { env: { PATH: this.path, HOME: this.home }, encoding: "utf8", timeout: 10_000, maxBuffer: processOutputLimit });
    if (goEnvironment?.status !== 0 || !boundedOutput(goEnvironment)) return 1;
    let caches;
    try { caches = JSON.parse(goEnvironment.stdout); } catch { return 1; }
    if (!isAbsolute(caches.GOCACHE ?? "") || !isAbsolute(caches.GOMODCACHE ?? "")) return 1;
    let directory;
    let code = 1;
    try {
      const candidate = this.makeTemp(join(this.tempParent, "zasp-prov-01-"));
      directory = this.ownedTemporaryDirectory(candidate);
      if (directory === undefined) return 1;
      const executable = join(directory, "iam-proof");
      const build = await runBounded("go", ["build", "-trimpath", "-mod=readonly", "-o", executable, "."], { cwd: proofDirectory, env: buildGoToolEnvironment(this.path, caches.GOCACHE, caches.GOMODCACHE), timeoutMs: 90_000, outputLimit: processOutputLimit }, this.spawnProcess);
      if (build?.status !== 0 || !boundedOutput(build) || String(build?.stdout ?? "") !== "" || String(build?.stderr ?? "") !== "") return resultCode(build);
      const proof = await runBounded(executable, [], { cwd: proofDirectory, env: buildProofEnvironment(endpoint, this.path), timeoutMs: 180_000, outputLimit: processOutputLimit }, this.spawnProcess);
      if (proof?.status === 0 && boundedOutput(proof) && proof.stdout === `${successLine}\n` && proof.stderr === "") code = 0;
      else code = resultCode(proof);
    } catch { code = 1; }
    finally {
      if (directory !== undefined) {
        try { this.removeTemp(directory, { recursive: true, force: false, maxRetries: 0 }); } catch { code = 1; }
      }
    }
    return code;
  }

  async remove() {
    if (!containerIDPattern.test(this.token ?? "")) {
      const candidate = this.namedCandidates();
      if (candidate.listed?.status !== 0 || candidate.values.length > 1 || (candidate.values.length === 1 && !containerIDPattern.test(candidate.values[0]))) throw categorized("cleanup");
      if (candidate.values.length === 0) return;
      this.token = candidate.values[0];
    }
    await this.verifyOwned(this.token);
    const removed = this.docker(["rm", "--force", this.token]);
    if (removed?.status !== 0 || String(removed.stdout ?? "").trim() !== this.token) throw categorized("cleanup");
  }

  async requireAbsent() {
    if (containerIDPattern.test(this.token ?? "") && this.docker(["inspect", this.token])?.status === 0) throw categorized("cleanup");
    const byName = this.namedCandidates();
    if (byName.listed?.status !== 0 || byName.values.length !== 0) throw categorized("cleanup");
  }
}

export async function orchestrate(runtime, options = {}) {
  const readinessAttempts = options.readinessAttempts ?? 120;
  const wait = options.wait ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
  let started = false; let proofCode = 1; let line = failureLine("operation"); let cleanupFailed = false;
  try {
    if (!runtime || !Number.isInteger(readinessAttempts) || readinessAttempts < 1) throw categorized("configuration");
    await runtime.ensureAbsent();
    const token = await runtime.start(); started = true;
    await runtime.verifyOwned(token);
    const endpoint = await runtime.endpoint(token);
    let ready = false;
    for (let attempt = 0; attempt < readinessAttempts; attempt += 1) {
      if (await runtime.isReady(endpoint)) { ready = true; break; }
      if (attempt + 1 < readinessAttempts) await wait(250);
    }
    if (!ready) throw categorized("readiness");
    proofCode = await runtime.runProof(endpoint);
    line = proofCode === 0 ? successLine : failureLine("operation");
  } catch (error) {
    proofCode = 1;
    line = failureLine(error?.category === "readiness" ? "readiness" : "operation");
  } finally {
    let candidate = false;
    try { candidate = runtime?.hasCandidate?.() === true; } catch { cleanupFailed = true; }
    if (started || candidate) {
      try { await runtime.remove(); } catch { cleanupFailed = true; }
      try { await runtime.requireAbsent(); } catch { cleanupFailed = true; }
    }
  }
  return cleanupFailed ? { code: 1, line: failureLine("cleanup") } : { code: proofCode, line };
}

export async function runMain({ runtime, runtimeFactory = () => new DockerRuntime(), stdout = process.stdout, stderr = process.stderr, setExitCode = (code) => { process.exitCode = code; } } = {}) {
  let result;
  try {
    const selected = runtime ?? runtimeFactory();
    result = await orchestrate(selected);
  } catch (error) {
    result = { code: 1, line: failureLine(error?.category === "configuration" ? "configuration" : "operation") };
  }
  const stream = result.code === 0 ? stdout : stderr;
  try { stream.write(`${result.line}\n`); } catch { result = { code: 1, line: failureLine("operation") }; }
  setExitCode(result.code);
  return result.code;
}

if (process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url) process.exitCode = await runMain();
