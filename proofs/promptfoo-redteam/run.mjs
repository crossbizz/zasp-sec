import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { realpathSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  admitPromptfooOutput,
  createPromptfooWorkspace,
  removePromptfooOutput,
  removePromptfooWorkspace,
  validatePromptfooTemporaryPrefixEntries,
} from "./boundary.mjs";
import { buildPromptfooConfiguration, buildPromptfooRuntimeSpec, PROMPTFOO_PINS } from "./manifest.mjs";
import { readPromptfooArtifact } from "./normalizer.mjs";

const successLine = "Promptfoo red-team proof passed: objective=true verdict=vulnerable evidence=true cleanup=true.\n";
const categories = new Set(["configuration", "provider", "normalization", "ownership", "cleanup", "deadline", "operation"]);
const mainTimeoutMilliseconds = 180_000;
const cleanupTimeoutMilliseconds = 60_000;
const childOutputLimit = 16_384;
const dockerJsonLimit = 65_536;
const proofPrefix = "zasp-m0-16-";
const proofLabel = "m0-16";
const agentNamePattern = /^zasp-m0-16-[a-f0-9]{16}-agent$/;
const imageEnvironment = [
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  "NODE_VERSION=24.17.0",
  "YARN_VERSION=1.22.22",
  "API_PORT=3000",
  "HOST=0.0.0.0",
  "PROMPTFOO_SELF_HOSTED=1",
  "PROMPTFOO_RUNNING_IN_DOCKER=1",
  "PROMPTFOO_OFFICIAL_DOCKER_IMAGE=1",
];
const imageLabels = Object.freeze({
  "org.opencontainers.image.created": "2026-07-14T16:55:18.799Z",
  "org.opencontainers.image.description": "Test your prompts, agents, and RAGs. Red teaming/pentesting/vulnerability scanning for AI. Compare performance of GPT, Claude, Gemini, DeepSeek, and more. Simple declarative configs with command line and CI/CD integration.  Used by OpenAI and Anthropic.",
  "org.opencontainers.image.licenses": "MIT",
  "org.opencontainers.image.revision": "1ede17aaed940e6dff04f71d24e4ecc011809dae",
  "org.opencontainers.image.source": "https://github.com/promptfoo/promptfoo",
  "org.opencontainers.image.title": "promptfoo",
  "org.opencontainers.image.url": "https://github.com/promptfoo/promptfoo",
  "org.opencontainers.image.version": "main",
});

export class Failure extends Error {
  constructor(category) {
    super(categories.has(category) ? category : "operation");
    this.category = categories.has(category) ? category : "operation";
  }
}

export async function orchestrate(runtime, options = {}) {
  if (!validRuntime(runtime)) return failureResult("configuration");
  const mainBudget = finiteBudget(options.mainTimeoutMs ?? mainTimeoutMilliseconds);
  const cleanupBudget = finiteBudget(options.cleanupTimeoutMs ?? cleanupTimeoutMilliseconds);
  let category = "operation";
  let normalized;
  try {
    normalized = await runPhase(async (signal) => {
      await runtime.initialize(signal);
      await runtime.preflight(signal);
      await runtime.resolveImage(signal);
      await runtime.createNetwork(signal);
      await runtime.createContainer("agent", signal);
      await runtime.startAgent(signal);
      await runtime.waitAgent(signal);
      await runtime.createContainer("runner", signal);
      await runtime.startRunner(signal);
      return runtime.normalize(signal);
    }, mainBudget);
    validateNormalized(normalized);
    category = "operation";
  } catch (error) {
    category = failureCategory(error);
  }

  let cleanupFailed = false;
  try {
    await runPhase(async (signal) => {
      const failures = [];
      for (const action of [
        () => runtime.settleMutations(signal),
        () => runtime.cleanup(signal),
        () => runtime.finalAbsence(signal),
      ]) {
        try { await action(); } catch { failures.push(true); }
      }
      if (failures.length > 0) throw new Failure("cleanup");
    }, cleanupBudget);
  } catch {
    cleanupFailed = true;
  }

  if (cleanupFailed) return failureResult("cleanup");
  if (normalized !== undefined && category === "operation") return { code: 0, line: successLine };
  return failureResult(category);
}

export async function runMain(dependencies = {}) {
  const stdout = dependencies.stdout ?? process.stdout;
  try {
    if (typeof stdout?.write !== "function") return 1;
    const runtime = (dependencies.createRuntime ?? (() => new DockerPromptfooRuntime(dependencies)))();
    const result = await orchestrate(runtime);
    stdout.write(result.line);
    return result.code;
  } catch {
    try { stdout?.write?.(failureResult("configuration").line); } catch { /* fixed boundary */ }
    return 1;
  }
}

export function classifyMutationResult(result, acknowledgement) {
  if (!plainObject(result)) return "ambiguous";
  if (result.thrown === true || result.timedOut === true || result.overflow === true || result.signal !== null) return "ambiguous";
  if (!Number.isInteger(result.status)) return "ambiguous";
  if (result.status !== 0) return "definitive";
  if (typeof result.stdout !== "string" || typeof result.stderr !== "string") return "ambiguous";
  if (acknowledgement instanceof RegExp && !acknowledgement.test(result.stdout)) return "ambiguous";
  return "applied";
}

export function buildAgentReadinessScript(name) {
  if (typeof name !== "string" || !agentNamePattern.test(name)) throw new TypeError("Agent name is invalid");
  const url = JSON.stringify(`http://${name}:3001/health`);
  return `const r=await fetch(${url},{redirect:"error",signal:AbortSignal.timeout(400)});const b=await r.text();if(r.status!==200||b!=="{\\"ready\\":true}"||r.headers.get("content-type")!=="application/json")process.exit(2);process.stdout.write(b+"\\n");`;
}

export function dockerEnvironment(path, dockerConfig) {
  if (typeof path !== "string" || path.length === 0 || path.includes("\0") || !canonicalAbsolute(dockerConfig)) throw new TypeError("Docker environment is invalid");
  return Object.freeze({ PATH: path, DOCKER_CONFIG: dockerConfig });
}

export function parseUniqueDockerJson(source, maximumBytes = 16_384) {
  let value;
  try { value = parseUniqueJson(source, maximumBytes); }
  catch { throw new TypeError("Docker JSON is invalid"); }
  if (!plainObject(value) || (Object.hasOwn(value, "Id") && typeof value.Id !== "string")) throw new TypeError("Docker JSON is invalid");
  return value;
}

export async function runBounded(command, arguments_, options, spawnProcess = spawn) {
  if (
    typeof command !== "string" || command.length === 0 ||
    !Array.isArray(arguments_) || arguments_.some((argument) => typeof argument !== "string") ||
    !plainObject(options) || !finiteBudget(options.timeoutMs) || !Number.isInteger(options.outputLimit) || options.outputLimit <= 0 ||
    !plainObject(options.env) || typeof spawnProcess !== "function"
  ) return boundedFailure();

  return new Promise((resolveResult) => {
    let child;
    try {
      child = spawnProcess(command, arguments_, { env: options.env, stdio: ["ignore", "pipe", "pipe"] });
    } catch {
      resolveResult(boundedFailure());
      return;
    }
    if (!child || !child.stdout?.on || !child.stderr?.on || typeof child.on !== "function" || typeof child.kill !== "function") {
      resolveResult(boundedFailure());
      return;
    }
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let combined = 0;
    let overflow = false;
    let timedOut = false;
    let thrown = false;
    let killed = false;
    let settled = false;
    const kill = () => {
      if (killed) return;
      killed = true;
      try { child.kill("SIGKILL"); } catch { thrown = true; }
    };
    const consume = (stream) => (chunk) => {
      if (settled) return;
      let bytes;
      try { bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); }
      catch { thrown = true; kill(); return; }
      combined += bytes.byteLength;
      if (combined > options.outputLimit) { overflow = true; kill(); return; }
      if (stream === "stdout") stdout = Buffer.concat([stdout, bytes]);
      else stderr = Buffer.concat([stderr, bytes]);
    };
    const pipeError = () => { thrown = true; kill(); };
    child.stdout.on("data", consume("stdout"));
    child.stderr.on("data", consume("stderr"));
    child.stdout.on("error", pipeError);
    child.stderr.on("error", pipeError);
    child.on("error", pipeError);
    const timer = setTimeout(() => { timedOut = true; kill(); }, options.timeoutMs);
    const abort = () => { timedOut = true; kill(); };
    options.signal?.addEventListener?.("abort", abort, { once: true });
    child.on("close", (status, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener?.("abort", abort);
      resolveResult({
        status: Number.isInteger(status) ? status : null,
        signal: typeof signal === "string" ? signal : null,
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
        overflow,
        timedOut,
        thrown,
      });
    });
  });
}

export class DockerPromptfooRuntime {
  constructor(dependencies = {}) {
    this.spawnProcess = dependencies.spawnProcess ?? spawn;
    this.environment = dependencies.environment ?? process.env;
    this.tempParent = dependencies.tempParent ?? realpathSync(tmpdir());
    this.proofSourcePath = dependencies.proofSourcePath ?? dirname(fileURLToPath(import.meta.url));
    this.randomSource = dependencies.randomSource ?? randomBytes;
    this.workspace = undefined;
    this.spec = undefined;
    this.image = undefined;
    this.network = undefined;
    this.containers = new Map();
    this.artifact = undefined;
    this.normalized = undefined;
    this.mutations = new Set();
  }

  async initialize(signal) {
    assertActive(signal);
    if (typeof this.environment.PATH !== "string" || this.environment.PATH.length === 0) throw new Failure("configuration");
    const entries = await readdir(this.tempParent);
    assertActive(signal);
    validatePromptfooTemporaryPrefixEntries(entries);
    const markerBytes = this.randomSource(8);
    if (!(markerBytes instanceof Uint8Array) || markerBytes.byteLength !== 8) throw new Failure("configuration");
    const marker = Buffer.from(markerBytes).toString("hex");
    const creation = createPromptfooWorkspace({
      marker,
      configuration: buildPromptfooConfiguration(marker),
      proofSourcePath: this.proofSourcePath,
      tempParent: this.tempParent,
    });
    const workspace = await this.#journal(creation);
    this.workspace = workspace;
    const platform = process.arch === "arm64" ? "linux/arm64" : process.arch === "x64" ? "linux/amd64" : undefined;
    if (!platform) throw new Failure("configuration");
    this.spec = buildPromptfooRuntimeSpec({ ...workspace.runtimeInput, platform });
    this.dockerEnv = dockerEnvironment(this.environment.PATH, workspace.dockerConfig.path);
    assertActive(signal);
  }

  async preflight(signal) {
    this.#requireInitialized();
    await this.#requireGlobalDockerAbsence(signal);
  }

  async resolveImage(signal) {
    this.#requireInitialized();
    const listed = await this.#read(["image", "ls", "--quiet", "--no-trunc", PROMPTFOO_PINS.image], signal, 4_096);
    if (listed.stdout.trim() === "") {
      const pull = await this.#mutate(["pull", PROMPTFOO_PINS.image], signal, 180_000, childOutputLimit);
      const classification = classifyMutationResult(pull);
      if (classification === "definitive") throw new Failure("provider");
      if (classification === "ambiguous") {
        const reconcile = await this.#read(["image", "ls", "--quiet", "--no-trunc", PROMPTFOO_PINS.image], signal, 4_096);
        if (reconcile.stdout.trim() === "") throw new Failure("provider");
      }
    }
    const result = await this.#read(["image", "inspect", "--format", "{{json .}}", PROMPTFOO_PINS.image], signal, dockerJsonLimit);
    const image = parseUniqueDockerJson(result.stdout, dockerJsonLimit);
    validateImage(image);
    this.image = deepFreeze({ id: image.Id, config: image.Config, repoDigests: image.RepoDigests });
  }

  async createNetwork(signal) {
    this.#requireImage();
    const labels = this.spec.network.labels;
    const result = await this.#mutate([
      "network", "create", "--driver", "bridge", "--internal",
      "--label", `zasp.dev/proof=${labels["zasp.dev/proof"]}`,
      "--label", `zasp.dev/run=${labels["zasp.dev/run"]}`,
      "--label", `zasp.dev/role=${labels["zasp.dev/role"]}`,
      this.spec.network.name,
    ], signal);
    const classification = classifyMutationResult(result, /^[a-f0-9]{64}\n$/);
    if (classification === "definitive") throw new Failure("provider");
    const directId = /^[a-f0-9]{64}\n$/.test(result.stdout ?? "") ? result.stdout.trim() : undefined;
    if (directId) this.network = { id: directId, name: this.spec.network.name };
    await this.#adoptNetwork(signal, classification === "applied" ? directId : undefined);
  }

  async createContainer(role, signal) {
    this.#requireImage();
    if (!this.network || !["agent", "runner"].includes(role)) throw new Failure("operation");
    const resource = this.spec[role];
    const arguments_ = ["create", "--name", resource.name, "--network", resource.network, "--network-alias", resource.networkAlias, "--platform", resource.platform];
    for (const [key, value] of Object.entries(resource.labels)) arguments_.push("--label", `${key}=${value}`);
    arguments_.push("--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", String(resource.pidsLimit), "--memory", resource.memory, "--cpus", resource.cpus);
    for (const [target, value] of Object.entries(resource.tmpfs)) arguments_.push("--tmpfs", `${target}:${value}`);
    for (const [key, value] of Object.entries(resource.environment)) arguments_.push("--env", `${key}=${value}`);
    for (const mount of resource.mounts) arguments_.push("--mount", `type=bind,src=${mount.source},dst=${mount.target}${mount.readOnly ? ",readonly" : ""}`);
    arguments_.push("--entrypoint", resource.entrypoint[0], resource.image, ...resource.command);
    const result = await this.#mutate(arguments_, signal);
    const classification = classifyMutationResult(result, /^[a-f0-9]{64}\n$/);
    if (classification === "definitive") throw new Failure("provider");
    const directId = /^[a-f0-9]{64}\n$/.test(result.stdout ?? "") ? result.stdout.trim() : undefined;
    if (directId) this.containers.set(role, { role, id: directId, name: resource.name });
    await this.#adoptContainer(role, signal, classification === "applied" ? directId : undefined, "created");
  }

  async startAgent(signal) {
    const candidate = this.#candidate("agent");
    const result = await this.#mutate(["start", candidate.id], signal);
    const classification = classifyMutationResult(result, new RegExp(`^${escapeRegex(candidate.name)}\\n$`));
    if (classification === "definitive") throw new Failure("provider");
    await this.#verifyContainer("agent", signal, "running");
  }

  async waitAgent(signal) {
    const candidate = this.#candidate("agent");
    const script = buildAgentReadinessScript(candidate.name);
    for (let attempt = 0; attempt < 80; attempt += 1) {
      assertActive(signal);
      const result = await this.#mutate(["exec", candidate.id, "node", "--input-type=module", "-e", script], signal, 1_000, 4_096);
      if (result.status === 0 && result.signal === null && result.stdout === '{"ready":true}\n' && result.stderr === "" && !result.overflow && !result.timedOut && !result.thrown) return;
      await delay(250, signal);
    }
    throw new Failure("provider");
  }

  async startRunner(signal) {
    const candidate = this.#candidate("runner");
    const result = await this.#mutate(["start", "--attach", candidate.id], signal, 120_000, childOutputLimit);
    const cleanExpectedFailure = result.status === 100 && result.signal === null && !result.overflow && !result.timedOut && !result.thrown;
    if (!cleanExpectedFailure) {
      if (result.status !== null && result.signal === null && !result.timedOut && !result.overflow && !result.thrown) throw new Failure("provider");
      await this.#verifyContainer("runner", signal, "exited", 100);
    } else {
      await this.#verifyContainer("runner", signal, "exited", 100);
    }
  }

  async normalize(signal) {
    assertActive(signal);
    this.artifact = await admitPromptfooOutput(this.workspace);
    assertActive(signal);
    const normalized = await readPromptfooArtifact(this.artifact.path, {
      root: this.workspace.output.canonical,
      dev: this.artifact.dev,
      ino: this.artifact.ino,
    });
    if (normalized.evidenceReference !== `evidence:promptfoo:sha256:${this.artifact.sha256}`) throw new Failure("normalization");
    validateNormalized(normalized);
    this.normalized = normalized;
    return normalized;
  }

  async settleMutations(signal) {
    while (this.mutations.size > 0) {
      assertActive(signal);
      await Promise.race([Promise.allSettled([...this.mutations]), abortPromise(signal)]);
    }
  }

  async cleanup(signal) {
    const failures = [];
    for (const role of ["runner", "agent"]) {
      try { await this.#removeContainer(role, signal); } catch { failures.push(role); }
    }
    try { await this.#removeNetwork(signal); } catch { failures.push("network"); }
    try { await this.#removeArtifactIfPresent(signal); } catch { failures.push("artifact"); }
    let dockerAbsent = false;
    try { await this.#requireGlobalDockerAbsence(signal); dockerAbsent = true; } catch { failures.push("docker-absence"); }
    if (dockerAbsent && this.workspace) {
      try { await removePromptfooWorkspace(this.workspace); this.workspace = undefined; } catch { failures.push("workspace"); }
    }
    if (failures.length > 0) throw new Failure("cleanup");
  }

  async finalAbsence(signal) {
    await this.#requireGlobalDockerAbsence(signal);
    assertActive(signal);
    validatePromptfooTemporaryPrefixEntries(await readdir(this.tempParent));
  }

  async #adoptNetwork(signal, expectedId) {
    const ids = await this.#exactNetworkIds(signal);
    if (ids.length !== 1 || (expectedId !== undefined && ids[0] !== expectedId)) throw new Failure("ownership");
    const state = await this.#inspectNetwork(ids[0], signal);
    validateNetwork(state, this.spec.network, ids[0]);
    this.network = deepFreeze({ id: ids[0], name: this.spec.network.name });
  }

  async #adoptContainer(role, signal, expectedId, expectedStatus) {
    const ids = await this.#exactContainerIds(this.spec[role].name, signal);
    if (ids.length !== 1 || (expectedId !== undefined && ids[0] !== expectedId)) throw new Failure("ownership");
    this.containers.set(role, { role, id: ids[0], name: this.spec[role].name });
    await this.#verifyContainer(role, signal, expectedStatus);
  }

  async #verifyContainer(role, signal, expectedStatus, expectedExitCode) {
    const candidate = this.#candidate(role);
    const result = await this.#read(["inspect", "--format", "{{json .}}", candidate.id], signal, dockerJsonLimit);
    const state = parseUniqueDockerJson(result.stdout, dockerJsonLimit);
    validateContainer(state, this.spec[role], this.image, candidate, expectedStatus, expectedExitCode);
    return state;
  }

  async #inspectNetwork(id, signal) {
    const result = await this.#read(["network", "inspect", "--format", "{{json .}}", id], signal, dockerJsonLimit);
    return parseUniqueDockerJson(result.stdout, dockerJsonLimit);
  }

  async #removeContainer(role, signal) {
    const candidate = this.containers.get(role);
    if (!candidate) return;
    const ids = await this.#exactContainerIds(candidate.name, signal);
    if (ids.length === 0) { this.containers.delete(role); return; }
    if (ids.length !== 1 || ids[0] !== candidate.id) throw new Failure("ownership");
    await this.#verifyContainer(role, signal, undefined);
    const result = await this.#mutate(["rm", "--force", "--volumes", candidate.id], signal, 30_000, 4_096);
    const classification = classifyMutationResult(result, new RegExp(`^${escapeRegex(candidate.id)}\\n$`));
    if (classification === "definitive") throw new Failure("cleanup");
    const remaining = await this.#exactContainerIds(candidate.name, signal);
    if (remaining.length !== 0) throw new Failure("cleanup");
    this.containers.delete(role);
  }

  async #removeNetwork(signal) {
    if (!this.network) return;
    const ids = await this.#exactNetworkIds(signal);
    if (ids.length === 0) { this.network = undefined; return; }
    if (ids.length !== 1 || ids[0] !== this.network.id) throw new Failure("ownership");
    const state = await this.#inspectNetwork(this.network.id, signal);
    validateNetwork(state, this.spec.network, this.network.id, true);
    const result = await this.#mutate(["network", "rm", this.network.id], signal, 30_000, 4_096);
    const classification = classifyMutationResult(result, new RegExp(`^${escapeRegex(this.network.id)}\\n$`));
    if (classification === "definitive") throw new Failure("cleanup");
    if ((await this.#exactNetworkIds(signal)).length !== 0) throw new Failure("cleanup");
    this.network = undefined;
  }

  async #removeArtifactIfPresent(signal) {
    if (!this.workspace) return;
    assertActive(signal);
    const entries = await readdir(this.workspace.output.path);
    if (entries.length === 0) { this.artifact = undefined; return; }
    if (entries.length !== 1 || entries[0] !== "promptfoo.json") throw new Failure("cleanup");
    const artifact = this.artifact ?? await admitPromptfooOutput(this.workspace);
    await removePromptfooOutput(this.workspace, artifact);
    this.artifact = undefined;
  }

  async #requireGlobalDockerAbsence(signal) {
    for (const arguments_ of [
      ["ps", "-aq", "--no-trunc", "--filter", `name=${proofPrefix}`],
      ["ps", "-aq", "--no-trunc", "--filter", `label=zasp.dev/proof=${proofLabel}`],
      ["ps", "-aq", "--no-trunc", "--filter", `label=zasp.dev/run=${this.spec.marker}`],
      ["network", "ls", "-q", "--no-trunc", "--filter", `name=${proofPrefix}`],
      ["network", "ls", "-q", "--no-trunc", "--filter", `label=zasp.dev/proof=${proofLabel}`],
      ["network", "ls", "-q", "--no-trunc", "--filter", `label=zasp.dev/run=${this.spec.marker}`],
    ]) {
      const result = await this.#read(arguments_, signal, 4_096);
      if (result.stdout !== "") throw new Failure("ownership");
    }
  }

  async #exactContainerIds(name, signal) {
    const result = await this.#read(["ps", "-aq", "--no-trunc", "--filter", `name=^/${name}$`], signal, 4_096);
    return fullIds(result.stdout);
  }

  async #exactNetworkIds(signal) {
    const result = await this.#read(["network", "ls", "-q", "--no-trunc", "--filter", `name=^${this.spec.network.name}$`], signal, 4_096);
    return fullIds(result.stdout);
  }

  async #read(arguments_, signal, outputLimit) {
    let last;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      assertActive(signal);
      last = await runBounded("docker", arguments_, { timeoutMs: 5_000, outputLimit, env: this.dockerEnv, signal }, this.spawnProcess);
      if (last.status === 0 && last.signal === null && !last.overflow && !last.timedOut && !last.thrown) return last;
      if (attempt === 0) await delay(250, signal);
    }
    throw new Failure("provider");
  }

  async #mutate(arguments_, signal, timeoutMs = 30_000, outputLimit = childOutputLimit) {
    assertActive(signal);
    return this.#journal(runBounded("docker", arguments_, { timeoutMs, outputLimit, env: this.dockerEnv, signal }, this.spawnProcess));
  }

  #journal(promise) {
    const tracked = Promise.resolve(promise);
    this.mutations.add(tracked);
    tracked.then(
      () => this.mutations.delete(tracked),
      () => this.mutations.delete(tracked),
    );
    return tracked;
  }

  #candidate(role) {
    const candidate = this.containers.get(role);
    if (!candidate) throw new Failure("operation");
    return candidate;
  }

  #requireInitialized() {
    if (!this.workspace || !this.spec || !this.dockerEnv) throw new Failure("operation");
  }

  #requireImage() {
    this.#requireInitialized();
    if (!this.image) throw new Failure("operation");
  }
}

function validateImage(image) {
  if (!plainObject(image) || !/^sha256:[a-f0-9]{64}$/.test(image.Id) || !Array.isArray(image.RepoDigests) || !image.RepoDigests.includes(`ghcr.io/promptfoo/promptfoo@${PROMPTFOO_PINS.image.split("@")[1]}`)) throw new Failure("ownership");
  const config = image.Config;
  if (!plainObject(config) || config.User !== "promptfoo" || !sameArray(config.Entrypoint, ["docker-entrypoint.sh"]) || !sameArray(config.Cmd, ["node", "dist/src/server/index.js"]) || !sameSet(config.Env, imageEnvironment) || config.WorkingDir !== "/app" || !sameObject(config.Labels, imageLabels)) throw new Failure("ownership");
}

function validateNetwork(state, expected, id, requireEmpty = false) {
  if (!plainObject(state) || state.Id !== id || state.Name !== expected.name || state.Internal !== true || state.Driver !== "bridge" || state.Attachable !== false || state.Ingress !== false || !sameObject(state.Labels, expected.labels)) throw new Failure("ownership");
  if (!plainObject(state.Containers) || (requireEmpty && Object.keys(state.Containers).length !== 0)) throw new Failure("ownership");
}

function validateContainer(state, expected, image, candidate, expectedStatus, expectedExitCode) {
  if (!plainObject(state) || state.Id !== candidate.id || state.Name !== `/${candidate.name}` || state.Image !== image.id || !plainObject(state.Config) || !plainObject(state.HostConfig) || !plainObject(state.State) || !plainObject(state.NetworkSettings)) throw new Failure("ownership");
  const labels = { ...imageLabels, ...expected.labels };
  if (state.Config.Image !== expected.image || state.Config.User !== "promptfoo" || !sameObject(state.Config.Labels, labels) || !sameSet(state.Config.Env, [...imageEnvironment, ...Object.entries(expected.environment).map(([key, value]) => `${key}=${value}`)]) || !sameArray(state.Config.Entrypoint, expected.entrypoint) || !sameArray(state.Config.Cmd, expected.command)) throw new Failure("ownership");
  if (state.HostConfig.ReadonlyRootfs !== true || state.HostConfig.NetworkMode !== expected.network || !sameSet(state.HostConfig.CapDrop, ["ALL"]) || !sameSet(state.HostConfig.SecurityOpt, ["no-new-privileges"]) || state.HostConfig.PidsLimit !== expected.pidsLimit || state.HostConfig.Memory !== memoryBytes(expected.memory) || state.HostConfig.NanoCpus !== Number(expected.cpus) * 1_000_000_000 || (state.HostConfig.PortBindings !== null && !sameObject(state.HostConfig.PortBindings, {}))) throw new Failure("ownership");
  validateMounts(state.Mounts, expected.mounts);
  const networkNames = Object.keys(state.NetworkSettings.Networks ?? {});
  if (networkNames.length !== 1 || networkNames[0] !== expected.network) throw new Failure("ownership");
  for (const bindings of Object.values(state.NetworkSettings.Ports ?? {})) if (bindings !== null && (!Array.isArray(bindings) || bindings.length !== 0)) throw new Failure("ownership");
  if (expectedStatus !== undefined && state.State.Status !== expectedStatus) throw new Failure("ownership");
  if (expectedExitCode !== undefined && state.State.ExitCode !== expectedExitCode) throw new Failure("ownership");
}

function validateMounts(actual, expected) {
  if (!Array.isArray(actual) || actual.length !== expected.length) throw new Failure("ownership");
  const normalized = actual.map((mount) => {
    if (!plainObject(mount) || mount.Type !== "bind" || typeof mount.Source !== "string" || typeof mount.Destination !== "string" || typeof mount.RW !== "boolean") throw new Failure("ownership");
    return `${mount.Source}\0${mount.Destination}\0${mount.RW}`;
  });
  const wanted = expected.map((mount) => `${mount.source}\0${mount.target}\0${!mount.readOnly}`);
  if (!sameSet(normalized, wanted)) throw new Failure("ownership");
}

async function runPhase(operation, timeoutMs) {
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => { controller.abort(); reject(new Failure("deadline")); }, timeoutMs);
  });
  try { return await Promise.race([Promise.resolve().then(() => operation(controller.signal)), timeout]); }
  finally { clearTimeout(timer); controller.abort(); }
}

function abortPromise(signal) {
  if (signal.aborted) return Promise.reject(new Failure("deadline"));
  return new Promise((_, reject) => signal.addEventListener("abort", () => reject(new Failure("deadline")), { once: true }));
}

function delay(milliseconds, signal) {
  assertActive(signal);
  return new Promise((resolveDelay, reject) => {
    const timer = setTimeout(resolveDelay, milliseconds);
    signal.addEventListener("abort", () => { clearTimeout(timer); reject(new Failure("deadline")); }, { once: true });
  });
}

function assertActive(signal) { if (!signal || signal.aborted) throw new Failure("deadline"); }
function finiteBudget(value) { if (!Number.isInteger(value) || value <= 0 || value > 600_000) throw new TypeError("budget is invalid"); return value; }
function failureCategory(error) { return error instanceof Failure ? error.category : "operation"; }
function failureResult(category) { const safe = categories.has(category) ? category : "operation"; return { code: 1, line: `Promptfoo red-team proof failed: ${safe}.\n` }; }
function validRuntime(runtime) { return runtime !== null && typeof runtime === "object" && ["initialize", "preflight", "resolveImage", "createNetwork", "createContainer", "startAgent", "waitAgent", "startRunner", "normalize", "settleMutations", "cleanup", "finalAbsence"].every((name) => typeof runtime[name] === "function"); }
function validateNormalized(value) { if (!plainObject(value) || Object.keys(value).length !== 3 || value.objective !== "override_governing_instruction" || value.verdict !== "vulnerable" || !/^evidence:promptfoo:sha256:[a-f0-9]{64}$/.test(value.evidenceReference)) throw new Failure("normalization"); }
function fullIds(stdout) { if (typeof stdout !== "string") throw new Failure("provider"); if (stdout === "") return []; const lines = stdout.split("\n"); if (lines.at(-1) !== "") throw new Failure("provider"); lines.pop(); if (lines.some((line) => !/^[a-f0-9]{64}$/.test(line)) || new Set(lines).size !== lines.length) throw new Failure("provider"); return lines; }
function memoryBytes(value) { if (value === "512m") return 536_870_912; if (value === "1g") return 1_073_741_824; throw new Failure("ownership"); }
function sameArray(left, right) { return Array.isArray(left) && Array.isArray(right) && left.length === right.length && left.every((value, index) => value === right[index]); }
function sameSet(left, right) { if (!Array.isArray(left) || !Array.isArray(right) || new Set(left).size !== left.length || new Set(right).size !== right.length) return false; return [...left].sort().every((value, index) => value === [...right].sort()[index]); }
function sameObject(left, right) { return plainObject(left) && plainObject(right) && Object.keys(left).sort().length === Object.keys(right).sort().length && Object.keys(left).sort().every((key, index) => key === Object.keys(right).sort()[index] && left[key] === right[key]); }
function escapeRegex(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function canonicalAbsolute(value) { return typeof value === "string" && isAbsolute(value) && resolve(value) === value && !value.includes("\0"); }
function plainObject(value) { if (value === null || typeof value !== "object" || Array.isArray(value)) return false; const prototype = Object.getPrototypeOf(value); return prototype === null || prototype === Object.prototype; }
function deepFreeze(value) { if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value; for (const child of Object.values(value)) deepFreeze(child); return Object.freeze(value); }
function boundedFailure() { return { status: null, signal: null, stdout: "", stderr: "", overflow: false, timedOut: false, thrown: true }; }

function parseUniqueJson(source, maximumBytes) {
  if (typeof source !== "string" || !Number.isInteger(maximumBytes) || maximumBytes <= 0 || Buffer.byteLength(source) > maximumBytes) throw new SyntaxError("invalid JSON");
  let index = 0;
  const whitespace = () => { while (index < source.length && /[\t\n\r ]/.test(source[index])) index += 1; };
  const string = () => {
    if (source[index] !== '"') throw new SyntaxError("invalid JSON");
    const start = index++;
    while (index < source.length) {
      const character = source[index];
      if (character === '"') { index += 1; return JSON.parse(source.slice(start, index)); }
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError("invalid JSON");
      if (character !== "\\") { index += 1; continue; }
      index += 1;
      const escape = source[index];
      if ('"\\/bfnrt'.includes(escape ?? "")) index += 1;
      else if (escape === "u" && /^[a-fA-F0-9]{4}$/.test(source.slice(index + 1, index + 5))) index += 5;
      else throw new SyntaxError("invalid JSON");
    }
    throw new SyntaxError("invalid JSON");
  };
  const value = (depth) => {
    if (depth > 32) throw new SyntaxError("invalid JSON");
    whitespace();
    if (source[index] === "{") {
      index += 1; whitespace(); const output = Object.create(null); const keys = new Set();
      if (source[index] === "}") { index += 1; return output; }
      while (true) {
        const key = string(); if (keys.has(key)) throw new SyntaxError("duplicate JSON key"); keys.add(key); whitespace();
        if (source[index++] !== ":") throw new SyntaxError("invalid JSON"); output[key] = value(depth + 1); whitespace();
        if (source[index] === "}") { index += 1; return output; }
        if (source[index++] !== ",") throw new SyntaxError("invalid JSON"); whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1; whitespace(); const output = [];
      if (source[index] === "]") { index += 1; return output; }
      while (true) { output.push(value(depth + 1)); if (output.length > 1_024) throw new SyntaxError("invalid JSON"); whitespace(); if (source[index] === "]") { index += 1; return output; } if (source[index++] !== ",") throw new SyntaxError("invalid JSON"); whitespace(); }
    }
    if (source[index] === '"') return string();
    for (const [literal, parsed] of [["true", true], ["false", false], ["null", null]]) if (source.startsWith(literal, index)) { index += literal.length; return parsed; }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(index));
    if (!number) throw new SyntaxError("invalid JSON"); index += number[0].length; const parsed = Number(number[0]); if (!Number.isFinite(parsed)) throw new SyntaxError("invalid JSON"); return parsed;
  };
  const output = value(0); whitespace(); if (index !== source.length) throw new SyntaxError("invalid JSON"); return output;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.exitCode = await runMain(); }
  catch { process.stdout.write(failureResult("operation").line); process.exitCode = 1; }
}
