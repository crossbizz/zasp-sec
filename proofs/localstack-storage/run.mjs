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
const fixedFailure = (category) => `LocalStack storage proof failed: ${category} rejected.`;
const namePattern = /^zasp-m0-07-[a-f0-9]{16}$/;
const idPattern = /^[a-f0-9]{64}$/;
const proofDirectory = fileURLToPath(new URL(".", import.meta.url));

export function buildDockerRunArguments(name) {
  if (!namePattern.test(name)) throw categorized("configuration");
  const marker = name.slice("zasp-m0-07-".length);
  return [
    "run", "--detach", "--rm", "--name", name,
    "--publish", "127.0.0.1::4566",
    "--env", "SERVICES=s3,kms,secretsmanager",
    "--env", "PERSISTENCE=0",
    "--label", "zasp.proof=m0-07",
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
  let started = false;
  let proofCode = 1;
  let line = fixedFailure("operation");
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
    line = proofCode === 0 ? successLine : fixedFailure("operation");
  } catch (error) {
    proofCode = 1;
    line = fixedFailure(error?.category === "readiness" ? "readiness" : "operation");
  } finally {
    if (started || runtime.hasCandidate?.() === true) {
      try { await runtime.remove(); } catch { cleanupFailed = true; }
      try { await runtime.requireAbsent(); } catch { cleanupFailed = true; }
    }
  }
  if (cleanupFailed) return { code: 1, line: fixedFailure("cleanup") };
  return { code: proofCode, line };
}

export class DockerRuntime {
  constructor({ path = process.env.PATH, marker = randomBytes(8).toString("hex") } = {}) {
    if (typeof path !== "string" || path.length === 0 || !/^[a-f0-9]{16}$/.test(marker)) throw categorized("configuration");
    this.path = path;
    this.name = `zasp-m0-07-${marker}`;
    this.marker = marker;
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
    const result = this.docker(buildDockerRunArguments(this.name));
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
    if (fields.length !== 6 || fields[0] !== token || fields[1] !== `/${this.name}` || fields[2] !== this.resolvedImageID || fields[3] !== LOCALSTACK_IMAGE || fields[4] !== "m0-07" || fields[5] !== this.marker) throw categorized("operation");
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
      const request = http.get(`${endpoint}/_localstack/health`, { timeout: 500 }, (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => { if (body.length <= 16_384) body += chunk; });
        response.on("end", () => {
          try {
            const parsed = JSON.parse(body);
            const accepted = new Set(["available", "running"]);
            resolve(response.statusCode === 200 && body.length <= 16_384 && ["s3", "kms", "secretsmanager"].every((service) => accepted.has(parsed.services?.[service])));
          } catch { resolve(false); }
        });
      });
      request.on("timeout", () => request.destroy());
      request.on("error", () => resolve(false));
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
    const temporaryDirectory = mkdtempSync(join(tmpdir(), "zasp-m0-07-"));
    const executable = join(temporaryDirectory, "storage-proof");
    let code = 1;
    try {
      const build = spawnSync("go", ["build", "-mod=readonly", "-o", executable, "."], {
        cwd: proofDirectory,
        env: buildGoToolEnvironment(this.path, caches.GOCACHE, caches.GOMODCACHE),
        encoding: "utf8",
        timeout: 90_000,
        maxBuffer: 1024 * 1024,
      });
      if (build.status !== 0 || build.stdout.trim() !== "" || build.stderr.trim() !== "") return resultCode(build);
      const result = spawnSync(executable, [], {
        cwd: proofDirectory,
        env: buildProofEnvironment(endpoint, this.path),
        encoding: "utf8",
        timeout: 90_000,
        maxBuffer: 1024 * 1024,
      });
      if (result.status === 0 && result.stdout.trim() === "LocalStack storage proof passed: kms=true s3=true secret=true round_trip=true cleanup=true audit=true." && result.stderr.trim() === "") code = 0;
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

async function main() {
  const runtime = new DockerRuntime();
  const result = await orchestrate(runtime);
  const stream = result.code === 0 ? process.stdout : process.stderr;
  stream.write(`${result.line}\n`);
  process.exitCode = result.code;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
