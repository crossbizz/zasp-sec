import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { lstatSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const OPENSEARCH_IMAGE = "opensearchproject/opensearch:3.8.0@sha256:bcc1797519726ceb6d651d4a3e60b7c30da91793914a8dfe75fd441d4f641509";
export const successLine = "OpenSearch event projection proof passed: indexed=true scoped_query=true cross_organization_zero=true cleanup=true audit=true container_cleanup=true.";
export const eventStoreSuccessLine = "OpenSearch event store passed: index=true search=true scoped=true cross_organization_zero=true cleanup=true audit=true container_cleanup=true.";
const fixedFailure = (category) => `OpenSearch event projection proof failed: ${category} rejected.`;
const eventStoreFailure = (category) => `OpenSearch event store failed: ${category} rejected.`;
const identities = {
  projection: { prefix: "zasp-m0-08-", proof: "m0-08" },
  "event-store": { prefix: "zasp-m1-14-", proof: "m1-14" },
};
const idPattern = /^[a-f0-9]{64}$/;
const proofDirectory = fileURLToPath(new URL(".", import.meta.url));
const readinessBodyLimit = 16_384;
const readinessDeadlineMilliseconds = 500;
const processOutputLimit = 4096;
const proofSupervisorTimeoutMilliseconds = 300_000;

function identityFor(mode) {
  const identity = identities[mode];
  if (identity === undefined) throw categorized("configuration");
  return identity;
}

function failureFor(mode, category) {
  return mode === "event-store" ? eventStoreFailure(category) : fixedFailure(category);
}

export function buildDockerRunArguments(name, mode = "projection") {
  const identity = identityFor(mode);
  const namePattern = new RegExp(`^${identity.prefix}[a-f0-9]{16}$`);
  if (!namePattern.test(name)) throw categorized("configuration");
  const marker = name.slice(identity.prefix.length);
  return [
    "run", "--detach", "--rm", "--name", name,
    "--publish", "127.0.0.1::9200",
    "--env", "discovery.type=single-node",
    "--env", "DISABLE_SECURITY_PLUGIN=true",
    "--env", "DISABLE_INSTALL_DEMO_CONFIG=true",
    "--env", "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m",
    "--label", `zasp.proof=${identity.proof}`,
    "--label", `zasp.marker=${marker}`,
    OPENSEARCH_IMAGE,
  ];
}

export function buildProofEnvironment(endpoint, path) {
  return { OPENSEARCH_ENDPOINT: endpoint, PATH: path };
}

export function buildGoToolEnvironment(path, buildCache, moduleCache) {
  return {
    PATH: path, GOCACHE: buildCache, GOMODCACHE: moduleCache,
    GOENV: "off", GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local", CGO_ENABLED: "0",
  };
}

function categorized(category) {
  const error = new Error("fixed orchestrator failure");
  error.category = category;
  return error;
}

function resultCode(result) {
  return Number.isInteger(result?.status) && result.status > 0 && result.status <= 125 ? result.status : 1;
}

function boundedOutput(result) {
  const stdout = typeof result?.stdout === "string" ? result.stdout : "";
  const stderr = typeof result?.stderr === "string" ? result.stderr : "";
  return Buffer.byteLength(stdout) + Buffer.byteLength(stderr) <= processOutputLimit;
}

export function proofExecutableArguments(mode) {
  identityFor(mode);
  return mode === "event-store" ? ["event-store"] : [];
}

export function runBounded(command, arguments_, options, spawnImplementation = spawn) {
  return new Promise((resolvePromise, rejectPromise) => {
    let child;
    try {
      child = spawnImplementation(command, arguments_, { cwd: options.cwd, env: options.env, stdio: ["ignore", "pipe", "pipe"] });
    } catch {
      rejectPromise(categorized("operation"));
      return;
    }
    if (!child?.stdout || !child?.stderr || typeof child.stdout.on !== "function" || typeof child.stderr.on !== "function") {
      rejectPromise(categorized("operation"));
      return;
    }
    const stdout = [];
    const stderr = [];
    let total = 0;
    let settled = false;
    let timer;
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback();
    };
    const stop = () => {
      child.stdout.destroy?.();
      child.stderr.destroy?.();
      child.kill?.("SIGKILL");
    };
    const consume = (target) => (chunk) => {
      const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += value.byteLength;
      if (total > options.outputLimit) {
        stop();
        finish(() => rejectPromise(categorized("operation")));
        return;
      }
      target.push(value);
    };
    child.stdout.on("data", consume(stdout));
    child.stderr.on("data", consume(stderr));
    child.stdout.on("error", () => { stop(); finish(() => rejectPromise(categorized("operation"))); });
    child.stderr.on("error", () => { stop(); finish(() => rejectPromise(categorized("operation"))); });
    child.once("error", () => finish(() => rejectPromise(categorized("operation"))));
    child.once("close", (status, signal) => finish(() => resolvePromise({
      status, signal, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8"),
    })));
    timer = setTimeout(() => {
      stop();
      finish(() => rejectPromise(categorized("operation")));
    }, options.timeoutMs);
  });
}

export async function orchestrate(runtime, options = {}) {
  const mode = options.mode ?? "projection";
  identityFor(mode);
  const readinessAttempts = options.readinessAttempts ?? 240;
  const wait = options.wait ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
  let started = false;
  let proofCode = 1;
  let line = failureFor(mode, "operation");
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
    proofCode = await runtime.runProof(endpoint, mode);
    line = proofCode === 0 ? (mode === "event-store" ? eventStoreSuccessLine : successLine) : failureFor(mode, "operation");
  } catch (error) {
    proofCode = 1;
    line = failureFor(mode, error?.category === "readiness" ? "readiness" : "operation");
  } finally {
    let candidate = started;
    if (!candidate) {
      try { candidate = runtime.hasCandidate?.() === true; } catch { candidate = false; }
    }
    if (candidate) {
      try { await runtime.remove(); } catch { cleanupFailed = true; }
      try { await runtime.requireAbsent(); } catch { cleanupFailed = true; }
    }
  }
  if (cleanupFailed) return { code: 1, line: failureFor(mode, "cleanup") };
  return { code: proofCode, line };
}

export class DockerRuntime {
  constructor({
    path = process.env.PATH, home = process.env.HOME, marker, mode = "projection", randomBytesSource = randomBytes,
    command = spawnSync, spawnProcess = spawn, makeTemp = mkdtempSync, removeTemp = rmSync,
    tempParent = tmpdir(), canonicalPath = realpathSync, statPath = lstatSync,
  } = {}) {
    if (marker === undefined) marker = randomBytesSource(8).toString("hex");
    const identity = identityFor(mode);
    if (typeof path !== "string" || path.length === 0 || !isAbsolute(home ?? "") || !isAbsolute(tempParent ?? "") ||
        !/^[a-f0-9]{16}$/.test(marker) || typeof command !== "function" || typeof spawnProcess !== "function" ||
        typeof makeTemp !== "function" || typeof removeTemp !== "function" || typeof canonicalPath !== "function" || typeof statPath !== "function") {
      throw categorized("configuration");
    }
    let canonicalTempParent;
    try { canonicalTempParent = canonicalPath(tempParent); } catch { throw categorized("configuration"); }
    if (typeof canonicalTempParent !== "string" || !isAbsolute(canonicalTempParent) || resolve(canonicalTempParent) !== canonicalTempParent) throw categorized("configuration");
    this.path = path;
    this.home = home;
    this.mode = mode;
    this.identity = identity;
    this.name = `${identity.prefix}${marker}`;
    this.marker = marker;
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
    let status;
    let canonical;
    try { status = this.statPath(value); canonical = this.canonicalPath(value); } catch { return undefined; }
    if (!status?.isDirectory?.() || status?.isSymbolicLink?.() || !Number.isSafeInteger(status.dev) || !Number.isSafeInteger(status.ino) ||
        typeof canonical !== "string" || value !== canonical || !isAbsolute(canonical) || resolve(canonical) !== canonical) return undefined;
    const prefix = join(this.tempParent, this.identity.prefix);
    if (dirname(canonical) !== this.tempParent || !canonical.startsWith(prefix) || canonical.length === prefix.length) return undefined;
    return { path: canonical, dev: status.dev, ino: status.ino };
  }

  stillOwnsTemporaryDirectory(identity) {
    const current = this.ownedTemporaryDirectory(identity?.path);
    return current !== undefined && current.path === identity.path && current.dev === identity.dev && current.ino === identity.ino;
  }

  docker(args, timeout = 60_000) {
    return this.command("docker", args, { env: { PATH: this.path }, encoding: "utf8", timeout, maxBuffer: 1024 * 1024 });
  }

  hasCandidate() { return this.startAttempted || idPattern.test(this.token ?? ""); }

  namedCandidates() {
    const listed = this.docker(["ps", "--all", "--no-trunc", "--filter", `name=^/${this.name}$`, "--format", "{{.ID}}"]);
    return { listed, values: String(listed?.stdout ?? "").trim().split("\n").filter(Boolean) };
  }

  async ensureAbsent() {
    const existing = this.namedCandidates();
    if (existing.listed?.status !== 0 || existing.values.length !== 0) throw categorized("operation");
    let image = this.docker(["image", "inspect", "--format", "{{.Id}}", OPENSEARCH_IMAGE]);
    if (image.status !== 0) {
      const pull = this.docker(["pull", OPENSEARCH_IMAGE], 180_000);
      if (pull.status !== 0) throw categorized("operation");
      image = this.docker(["image", "inspect", "--format", "{{.Id}}", OPENSEARCH_IMAGE]);
    }
    const imageID = image.stdout.trim();
    if (image.status !== 0 || !/^sha256:[a-f0-9]{64}$/.test(imageID)) throw categorized("operation");
    this.resolvedImageID = imageID;
  }

  async start() {
    this.startAttempted = true;
    const result = this.docker(buildDockerRunArguments(this.name, this.mode));
    const direct = String(result?.stdout ?? "").trim();
    if (idPattern.test(direct)) this.token = direct;
    if (result?.status === 0 && idPattern.test(direct)) {
      return direct;
    }
    const listed = this.namedCandidates().listed;
    const candidates = String(listed?.stdout ?? "").trim().split("\n").filter(Boolean);
    if (listed?.status !== 0 || candidates.length !== 1 || !idPattern.test(candidates[0])) throw categorized("operation");
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
    if (fields.length !== 6 || fields[0] !== token || fields[1] !== `/${this.name}` || fields[2] !== this.resolvedImageID ||
        fields[3] !== OPENSEARCH_IMAGE || fields[4] !== this.identity.proof || fields[5] !== this.marker) throw categorized("operation");
  }

  async endpoint(token = this.token) {
    await this.verifyOwned(token);
    const result = this.docker(["port", token, "9200/tcp"]);
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
        if (!accepted) { response?.destroy(); request?.destroy(); }
        resolve(accepted);
      };
      const deadline = setTimeout(() => finish(false), readinessDeadlineMilliseconds);
      try {
        request = http.get(`${endpoint}/_cluster/health?wait_for_status=yellow&timeout=1s`, (incoming) => {
          response = incoming;
          const chunks = [];
          let bytes = 0;
          response.on("data", (chunk) => {
            if (settled) return;
            bytes += Buffer.byteLength(chunk);
            if (bytes > readinessBodyLimit) { finish(false); return; }
            chunks.push(chunk);
          });
          response.on("end", () => {
            try {
              const parsed = JSON.parse(Buffer.concat(chunks, bytes).toString("utf8"));
              finish(response.statusCode === 200 && ["yellow", "green"].includes(parsed.status) && parsed.timed_out === false && parsed.number_of_nodes === 1);
            } catch { finish(false); }
          });
          response.on("error", () => finish(false));
        });
        request.on("error", () => finish(false));
      } catch { finish(false); }
    });
  }

  async runProof(endpoint, mode = this.mode) {
    if (mode !== this.mode) return 1;
    const goEnvironment = this.command("go", ["env", "-json", "GOCACHE", "GOMODCACHE"], {
      env: { PATH: this.path, HOME: this.home, GOENV: "off" }, encoding: "utf8", timeout: 10_000, maxBuffer: processOutputLimit,
    });
    if (goEnvironment?.status !== 0 || !boundedOutput(goEnvironment)) return 1;
    let caches;
    try { caches = JSON.parse(goEnvironment.stdout); } catch { return 1; }
    if (!isAbsolute(caches.GOCACHE ?? "") || !isAbsolute(caches.GOMODCACHE ?? "")) return 1;
    let temporaryCandidate;
    let temporaryIdentity;
    let temporaryDirectory;
    let code = 1;
    try {
      temporaryCandidate = this.makeTemp(join(this.tempParent, this.identity.prefix));
      temporaryIdentity = this.ownedTemporaryDirectory(temporaryCandidate);
      if (temporaryIdentity === undefined) throw categorized("operation");
      temporaryDirectory = temporaryIdentity.path;
      const executable = join(temporaryDirectory, "opensearch-event-proof");
      const build = await runBounded("go", ["build", "-trimpath", "-mod=readonly", "-o", executable, "."], {
        cwd: proofDirectory, env: buildGoToolEnvironment(this.path, caches.GOCACHE, caches.GOMODCACHE),
        timeoutMs: 90_000, outputLimit: processOutputLimit,
      }, this.spawnProcess);
      if (build?.status !== 0 || !boundedOutput(build) || build.stdout !== "" || build.stderr !== "") {
        code = resultCode(build);
      } else {
        const result = await runBounded(executable, proofExecutableArguments(mode), {
          cwd: proofDirectory, env: buildProofEnvironment(endpoint, this.path),
          timeoutMs: proofSupervisorTimeoutMilliseconds, outputLimit: processOutputLimit,
        }, this.spawnProcess);
        const proofLine = mode === "event-store"
          ? "OpenSearch event store passed: index=true search=true scoped=true cross_organization_zero=true cleanup=true audit=true."
          : "OpenSearch event projection proof passed: indexed=true scoped_query=true cross_organization_zero=true cleanup=true audit=true.";
        if (result?.status === 0 && boundedOutput(result) && result.stdout === `${proofLine}\n` && result.stderr === "") code = 0;
        else code = resultCode(result);
      }
    } catch {
      code = 1;
    } finally {
      if (temporaryIdentity === undefined && temporaryCandidate !== undefined) {
        temporaryIdentity = this.ownedTemporaryDirectory(temporaryCandidate);
        temporaryDirectory = temporaryIdentity?.path;
      }
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
      const candidate = this.namedCandidates();
      if (candidate.listed?.status !== 0 || candidate.values.length > 1 ||
          (candidate.values.length === 1 && !idPattern.test(candidate.values[0]))) throw categorized("cleanup");
      if (candidate.values.length === 0) return;
      this.token = candidate.values[0];
    }
    await this.verifyOwned(this.token);
    const result = this.docker(["rm", "--force", this.token]);
    if (result.status !== 0 || result.stdout.trim() !== this.token) throw categorized("cleanup");
  }

  async requireAbsent() {
    if (idPattern.test(this.token ?? "") && this.docker(["inspect", this.token])?.status === 0) throw categorized("cleanup");
    const byName = this.namedCandidates();
    if (byName.listed?.status !== 0 || byName.values.length !== 0) throw categorized("cleanup");
  }
}

export async function runMain({
  arguments: argumentsValue = process.argv.slice(2), runtimeFactory = (mode) => new DockerRuntime({ mode }), stdout = process.stdout, stderr = process.stderr,
  setExitCode = (code) => { process.exitCode = code; },
} = {}) {
  let result;
  const requestedEventStore = Array.isArray(argumentsValue) && argumentsValue[0] === "--event-store";
  const mode = requestedEventStore ? "event-store" : "projection";
  try {
    if (!Array.isArray(argumentsValue) || (argumentsValue.length !== 0 && !(argumentsValue.length === 1 && argumentsValue[0] === "--event-store"))) {
      throw categorized("configuration");
    }
    const runtime = runtimeFactory(mode);
    result = await orchestrate(runtime, { mode });
  } catch (error) {
    result = { code: 1, line: failureFor(mode, error?.category === "configuration" ? "configuration" : "operation") };
  }
  (result.code === 0 ? stdout : stderr).write(`${result.line}\n`);
  setExitCode(result.code);
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await runMain();
