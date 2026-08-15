import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildFixture } from "./manifests.mjs";
import { normalizeTetragonProof, parseTetragonMetrics } from "./normalizer.mjs";

export const SUCCESS_LINE = "Tetragon signal proof passed: process=true file=true network=true identity=true capability=true drops=0 cleanup=true.";
export const FAILURE_CATEGORIES = Object.freeze([
  "capability",
  "cleanup",
  "configuration",
  "normalization",
  "operation",
  "ownership",
  "provider",
]);

const mainTimeoutMilliseconds = 600_000;
const cleanupTimeoutMilliseconds = 120_000;
const namePattern = /^zasp-m0-12-[0-9a-f]{16}$/;
const markerPattern = /^[0-9a-f]{16}$/;
const organizationPattern = /^org_[a-z0-9]{16}$/;
const ipv4Pattern = /^(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])(?:\.(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])){3}$/;
const objectIdPattern = /^[0-9a-f]{64}$/;
const globalTemporaryPrefix = "zasp-m0-12-";
const processOutputLimit = 1_048_576;
const smallOutputLimit = 65_536;
const downloadLimit = 134_217_728;
export const fixtureSettleMilliseconds = 30_000;

export class Failure extends Error {
  constructor(category = "operation", message = "proof operation failed") {
    super(message);
    this.name = "Failure";
    this.category = FAILURE_CATEGORIES.includes(category) ? category : "operation";
  }
}

export function buildNetworkCreateArguments(name, marker) {
  validateProofName(name);
  validateMarker(marker);
  return [
    "network", "create", "--driver", "bridge",
    "--label", "zasp.dev/proof=m0-12", "--label", `zasp.dev/run=${marker}`,
    name,
  ];
}

export function buildKindCreateArguments(names, paths) {
  validateNames(names);
  expectExactObject(paths, ["config", "kubeconfig", "nodeImage"], "kind paths");
  validateAbsolutePath(paths.config, "kind config path");
  validateAbsolutePath(paths.kubeconfig, "kubeconfig path");
  validateBoundedString(paths.nodeImage, "node image");
  return [
    "create", "cluster", "--name", names.cluster,
    "--config", paths.config,
    "--kubeconfig", paths.kubeconfig,
    "--image", paths.nodeImage,
    "--wait", "180s",
  ];
}

export function buildHelmInstallArguments(paths) {
  expectExactObject(paths, ["chart", "kubeconfig", "values"], "Helm paths");
  for (const [name, value] of Object.entries(paths)) validateAbsolutePath(value, `Helm ${name} path`);
  return [
    "upgrade", "--install", "tetragon", paths.chart,
    "--namespace", "kube-system",
    "--kubeconfig", paths.kubeconfig,
    "--values", paths.values,
    "--wait", "--timeout", "180s",
  ];
}

export function fixtureTriggerCommands(names, sinkAddress) {
  validateNames(names);
  if (typeof sinkAddress !== "string" || !ipv4Pattern.test(sinkAddress)) {
    throw new TypeError("sink address is invalid");
  }
  const prefix = ["exec", "--namespace", names.namespace, names.workloadPod, "--"];
  return [
    [...prefix, "/bin/echo", "zasp-m0-12-exec"],
    [...prefix, "/bin/sh", "-c", "printf zasp-m0-12 > /tmp/zasp-m0-12-proof.txt && cat /tmp/zasp-m0-12-proof.txt >/dev/null"],
    [...prefix, "/bin/nc", "-w", "2", sinkAddress, "18080"],
  ];
}

export function buildEventCaptureArguments(tetragonPod) {
  validateBoundedString(tetragonPod, "Tetragon pod name");
  if (!/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(tetragonPod)) {
    throw new TypeError("Tetragon pod name is invalid");
  }
  return [
    "exec", "--namespace", "kube-system", tetragonPod, "--container", "tetragon",
    "--", "/bin/cat", "/var/run/cilium/tetragon/tetragon.log",
  ];
}

export function buildKprobeEventCaptureArguments(tetragonPod, names) {
  validateBoundedString(tetragonPod, "Tetragon pod name");
  if (!/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(tetragonPod)) {
    throw new TypeError("Tetragon pod name is invalid");
  }
  validateNames(names);
  const script = "set -eu\n" +
    "/usr/bin/tetra getevents --server-address unix:///var/run/tetragon/tetragon.sock --event-types PROCESS_KPROBE --policy-names \"$1\" --policy-names \"$2\" --output json &\n" +
    "capture_pid=$!\n/bin/sleep 40\nstatus=0\n" +
    "/bin/kill -INT \"$capture_pid\" 2>/dev/null || true\n" +
    "wait \"$capture_pid\" || status=$?\n" +
    "case \"$status\" in 0|130) exit 0 ;; *) exit 1 ;; esac\n";
  return [
    "exec", "--namespace", "kube-system", tetragonPod, "--container", "tetragon",
    "--", "/bin/sh", "-c", script, "zasp-m0-12-capture", names.filePolicy, names.networkPolicy,
  ];
}

export function buildNodeImagePullArguments(nodeToken, platform, reference) {
  if (!objectIdPattern.test(nodeToken ?? "")) throw new TypeError("node token is invalid");
  if (!new Set(["linux/amd64", "linux/arm64"]).has(platform)) throw new TypeError("node platform is invalid");
  validateBoundedString(reference, "image reference");
  return [
    "exec", nodeToken, "ctr", "--namespace", "k8s.io", "images", "pull",
    "--platform", platform, reference,
  ];
}

export function validateTetragonHealthPod(pod, expectedNodeName) {
  if (!isPlainObject(pod) || typeof expectedNodeName !== "string" || expectedNodeName.length === 0) {
    throw new Failure("capability");
  }
  const podName = pod.metadata?.name;
  const containers = pod.spec?.containers;
  const statuses = pod.status?.containerStatuses;
  const tetragon = Array.isArray(containers) ? containers.filter((entry) => entry?.name === "tetragon") : [];
  const status = Array.isArray(statuses) ? statuses.filter((entry) => entry?.name === "tetragon") : [];
  const probe = tetragon[0]?.livenessProbe;
  if (
    typeof podName !== "string" || !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(podName) ||
    pod.spec?.nodeName !== expectedNodeName || pod.status?.phase !== "Running" ||
    tetragon.length !== 1 || status.length !== 1 || status[0].ready !== true || status[0].restartCount !== 0 ||
    !isPlainObject(probe) || !isPlainObject(probe.grpc) ||
    probe.grpc.port !== 6789 || probe.grpc.service !== "liveness" || probe.timeoutSeconds !== 60
  ) throw new Failure("capability");
  return podName;
}

export function buildToolEnvironment(input) {
  expectExactObject(input, ["dockerConfig", "home", "kubeconfig", "network", "path"], "tool environment input");
  validateAbsolutePath(input.dockerConfig, "Docker config path");
  validateAbsolutePath(input.home, "tool home path");
  validateAbsolutePath(input.kubeconfig, "tool kubeconfig path");
  validateProofName(input.network);
  validateAbsolutePathList(input.path);
  return {
    DOCKER_CONFIG: input.dockerConfig,
    HOME: input.home,
    KIND_EXPERIMENTAL_DOCKER_NETWORK: input.network,
    KUBECONFIG: input.kubeconfig,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATH: input.path,
  };
}

export function classifyMutationOutcome(result, validatesSuccess) {
  if (typeof validatesSuccess !== "function") throw new TypeError("success validator is required");
  if (result === undefined) return "ambiguous";
  expectExactObject(result, ["signal", "status", "stderr", "stdout"], "mutation result");
  if (result.signal !== null) return "ambiguous";
  if (result.status !== 0) return "definitive";
  try {
    return validatesSuccess(result) === true ? "success" : "ambiguous";
  } catch {
    return "ambiguous";
  }
}

export function runBounded(command, arguments_, options, spawnImplementation = spawn) {
  validateBoundedString(command, "command");
  if (!Array.isArray(arguments_) || arguments_.some((value) => typeof value !== "string")) {
    throw new TypeError("command arguments are invalid");
  }
  expectAllowedDataObject(options, new Set(["env", "maximumBytes", "signal", "timeoutMs"]), "bounded process options");
  if (!["env", "maximumBytes", "timeoutMs"].every((key) => Object.hasOwn(options, key))) {
    throw new TypeError("bounded process options keys are invalid");
  }
  expectDataEnvironment(options.env);
  if (!Number.isSafeInteger(options.maximumBytes) || options.maximumBytes < 1 || options.maximumBytes > 16_777_216) {
    throw new TypeError("process byte bound is invalid");
  }
  if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 900_000) {
    throw new TypeError("process timeout is invalid");
  }
  if (typeof spawnImplementation !== "function") throw new TypeError("spawn implementation is invalid");
  if (Object.hasOwn(options, "signal") && (
    options.signal === null || typeof options.signal !== "object" ||
    typeof options.signal.addEventListener !== "function" ||
    typeof options.signal.removeEventListener !== "function" ||
    typeof options.signal.aborted !== "boolean"
  )) throw new TypeError("process signal is invalid");

  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnImplementation(command, [...arguments_], {
        env: { ...options.env },
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      reject(new Failure("operation"));
      return;
    }
    if (!child || !child.stdout || !child.stderr || typeof child.kill !== "function") {
      reject(new Failure("operation"));
      return;
    }

    const stdoutChunks = [];
    const stderrChunks = [];
    let byteCount = 0;
    let terminalError;
    let settled = false;
    let killed = false;

    const cleanupListeners = () => {
      clearTimeout(timer);
      child.stdout.off("data", onStdout);
      child.stderr.off("data", onStderr);
      child.stdout.off("error", onPipeError);
      child.stderr.off("error", onPipeError);
      child.off("error", onChildError);
      child.off("close", onClose);
      options.signal?.removeEventListener("abort", onAbort);
    };
    const kill = () => {
      if (killed) return;
      killed = true;
      try { child.kill("SIGKILL"); } catch { /* fixed failure below */ }
    };
    const fail = (category) => {
      terminalError ??= new Failure(category);
      kill();
    };
    const append = (chunks, chunk) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      byteCount += bytes.byteLength;
      if (byteCount > options.maximumBytes) {
        fail("operation");
        return;
      }
      chunks.push(bytes);
    };
    const onStdout = (chunk) => append(stdoutChunks, chunk);
    const onStderr = (chunk) => append(stderrChunks, chunk);
    const onPipeError = () => fail("operation");
    const onChildError = () => fail("operation");
    const onAbort = () => fail("operation");
    const decode = (chunks) => {
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
      } catch {
        throw new Failure("operation");
      }
    };
    const onClose = (status, signal) => {
      if (settled) return;
      settled = true;
      cleanupListeners();
      if (terminalError) {
        reject(terminalError);
        return;
      }
      try {
        resolve({ status, signal, stdout: decode(stdoutChunks), stderr: decode(stderrChunks) });
      } catch (error) {
        reject(error);
      }
    };
    const timer = setTimeout(() => fail("operation"), options.timeoutMs);
    child.stdout.on("data", onStdout);
    child.stderr.on("data", onStderr);
    child.stdout.on("error", onPipeError);
    child.stderr.on("error", onPipeError);
    child.on("error", onChildError);
    child.on("close", onClose);
    options.signal?.addEventListener("abort", onAbort, { once: true });
    if (options.signal?.aborted === true) onAbort();
  });
}

export async function orchestrate(runtime, options = {}) {
  validateRuntime(runtime);
  const limits = validateOrchestrationOptions(options);
  let result;
  let mainError;
  try {
    result = await runPhase(limits.mainTimeoutMs, async (phase) => {
      await runtime.preflight(phase);
      await runtime.createCluster(phase);
      await runtime.installTetragon(phase);
      await runtime.runFixture(phase);
      const captured = await runtime.captureEvidence(phase);
      validateProofResult(captured);
      return captured;
    });
  } catch (error) {
    mainError = normalizeFailure(error);
  }

  let joinError;
  let cleanupError;
  let auditError;
  try {
    await runPhase(limits.cleanupTimeoutMs, async (phase) => {
      try { await runtime.joinMutations(phase); } catch (error) { joinError = normalizeFailure(error); }
      try { await runtime.cleanup(phase); } catch (error) { cleanupError = normalizeFailure(error, "cleanup"); }
      try { await runtime.auditAbsence(phase); } catch (error) { auditError = normalizeFailure(error, "cleanup"); }
    });
  } catch (error) {
    cleanupError ??= normalizeFailure(error, "cleanup");
  }

  if (cleanupError) throw cleanupError;
  if (auditError) throw auditError;
  if (joinError) throw joinError;
  if (mainError) throw mainError;
  validateProofResult(result);
  return { ...result, cleanup: true };
}

export async function runMain(runtime, options = {}) {
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const setExitCode = options.setExitCode ?? ((value) => { process.exitCode = value; });
  let selectedRuntime = runtime;
  try {
    if (selectedRuntime === undefined) {
      const runtimeFactory = options.runtimeFactory ?? (() => DockerKindRuntime.fromProcess());
      selectedRuntime = runtimeFactory();
    }
    const result = await orchestrate(selectedRuntime, {
      mainTimeoutMs: options.mainTimeoutMs ?? mainTimeoutMilliseconds,
      cleanupTimeoutMs: options.cleanupTimeoutMs ?? cleanupTimeoutMilliseconds,
    });
    validateProofResult(result);
    stdout.write(`${SUCCESS_LINE}\n`);
    setExitCode(0);
    return 0;
  } catch (error) {
    const failure = normalizeFailure(error);
    stderr.write(`Tetragon signal proof failed: ${failure.category} rejected.\n`);
    setExitCode(1);
    return 1;
  }
}

export class DockerKindRuntime {
  constructor(input, dependencies = undefined) {
    validateRuntimeInput(input);
    const selectedDependencies = dependencies ?? { lifecycle: new DockerKindLifecycle(input) };
    expectExactObject(selectedDependencies, ["lifecycle"], "runtime dependencies");
    validateRuntime(selectedDependencies.lifecycle);
    this.input = Object.freeze({ ...input });
    this.lifecycle = selectedDependencies.lifecycle;
  }

  static fromProcess() {
    const hostArch = process.arch === "arm64" ? "arm64" : process.arch === "x64" ? "amd64" : "unsupported";
    const hostOs = process.platform === "darwin" ? "darwin" : process.platform === "linux" ? "linux" : "unsupported";
    const path = process.env.PATH;
    return new DockerKindRuntime({
      marker: randomBytes(8).toString("hex"),
      organizationId: "org_aaaaaaaaaaaaaaaa",
      path,
      hostPlatform: `${hostOs}/${hostArch}`,
      nodePlatform: `linux/${hostArch}`,
    });
  }

  async preflight(phase) { return this.lifecycle.preflight(phase); }
  async createCluster(phase) { return this.lifecycle.createCluster(phase); }
  async installTetragon(phase) { return this.lifecycle.installTetragon(phase); }
  async runFixture(phase) { return this.lifecycle.runFixture(phase); }
  async captureEvidence(phase) { return this.lifecycle.captureEvidence(phase); }
  async joinMutations(phase) { return this.lifecycle.joinMutations(phase); }
  async cleanup(phase) { return this.lifecycle.cleanup(phase); }
  async auditAbsence(phase) { return this.lifecycle.auditAbsence(phase); }
  hasCandidate() { return this.lifecycle.hasCandidate(); }
}

export class DockerKindLifecycle {
  constructor(input, dependencies = undefined) {
    validateRuntimeInput(input);
    const selectedDependencies = dependencies ?? { system: new DockerKindSystem(input) };
    expectExactObject(selectedDependencies, ["system"], "lifecycle dependencies");
    validateSystem(selectedDependencies.system);
    this.system = selectedDependencies.system;
  }

  async preflight(phase) {
    phase.assertActive();
    await this.system.initialize(phase);
    phase.assertActive();
    await this.system.preflight(phase);
    phase.assertActive();
    await this.system.resolveAssets(phase);
  }
  async createCluster(phase) {
    phase.assertActive();
    await this.system.createNetwork(phase);
    phase.assertActive();
    await this.system.createCluster(phase);
  }
  async installTetragon(phase) { return this.system.installTetragon(phase); }
  async runFixture(phase) { return this.system.runFixture(phase); }
  async captureEvidence(phase) { return this.system.captureEvidence(phase); }
  async joinMutations(phase) { return this.system.joinMutations(phase); }
  async cleanup(phase) { return this.system.cleanup(phase); }
  async auditAbsence(phase) { return this.system.auditAbsence(phase); }
  hasCandidate() { return this.system.hasCandidate(); }
}

export class DockerKindSystem {
  constructor(input, dependencies = {}) {
    validateRuntimeInput(input);
    const allowedDependencyKeys = new Set([
      "canonicalPath", "changeMode", "command", "fetchBytes", "makeDirectory",
      "makeTemp", "normalize", "readDirectory", "readPath", "removePath",
      "statPath", "tempParent", "wait", "writePath",
    ]);
    expectAllowedDataObject(dependencies, allowedDependencyKeys, "system dependencies");
    this.input = Object.freeze({ ...input });
    this.fixture = buildFixture({
      marker: input.marker,
      hostPlatform: input.hostPlatform,
      platform: input.nodePlatform,
    });
    this.command = dependencies.command ?? runBounded;
    this.fetchBytes = dependencies.fetchBytes ?? fetchBounded;
    this.makeTemp = dependencies.makeTemp ?? mkdtemp;
    this.makeDirectory = dependencies.makeDirectory ?? mkdir;
    this.writePath = dependencies.writePath ?? writeFile;
    this.readPath = dependencies.readPath ?? readFile;
    this.changeMode = dependencies.changeMode ?? chmod;
    this.removePath = dependencies.removePath ?? rm;
    this.canonicalPath = dependencies.canonicalPath ?? realpath;
    this.statPath = dependencies.statPath ?? lstat;
    this.readDirectory = dependencies.readDirectory ?? readdir;
    this.wait = dependencies.wait ?? waitWithSignal;
    this.normalize = dependencies.normalize ?? normalizeTetragonProof;
    this.tempParent = dependencies.tempParent ?? tmpdir();
    for (const method of [
      this.command, this.fetchBytes, this.makeTemp, this.makeDirectory, this.writePath,
      this.readPath, this.changeMode, this.removePath, this.canonicalPath, this.statPath,
      this.readDirectory, this.wait, this.normalize,
    ]) {
      if (typeof method !== "function") throw new TypeError("system dependency is invalid");
    }
    validateAbsolutePath(this.tempParent, "temporary parent");
    this.temporaryStarted = false;
    this.temporaryCandidate = undefined;
    this.temporaryIdentity = undefined;
    this.paths = undefined;
    this.environment = undefined;
    this.imageMetadata = new Map();
    this.networkMayHaveApplied = false;
    this.networkToken = undefined;
    this.clusterMayHaveApplied = false;
    this.nodeToken = undefined;
    this.chartInstalled = false;
    this.resourcesApplied = false;
    this.expected = undefined;
    this.metricsBefore = undefined;
    this.eventBaseline = undefined;
    this.eventCapture = undefined;
    this.mutationSettlements = [];
  }

  hasCandidate() {
    return this.temporaryStarted || this.networkMayHaveApplied || this.clusterMayHaveApplied ||
      this.chartInstalled || this.resourcesApplied;
  }

  async initialize(phase) {
    assertPhase(phase, "configuration");
    let parent;
    let entries;
    try {
      parent = await this.canonicalPath(this.tempParent);
      entries = await this.readDirectory(parent);
    } catch { throw new Failure("configuration"); }
    assertPhase(phase, "configuration");
    if (!isAbsolute(parent) || !Array.isArray(entries) || entries.some((entry) =>
      typeof entry !== "string" || entry.startsWith(globalTemporaryPrefix))) {
      throw new Failure("configuration");
    }
    this.tempParent = parent;
    this.temporaryStarted = true;
    let candidate;
    try { candidate = await this.makeTemp(join(parent, `${this.fixture.names.prefix}-runtime-`)); }
    catch { throw new Failure("configuration"); }
    this.temporaryCandidate = candidate;
    assertPhase(phase, "configuration");
    const identity = await this.inspectOwnedTemporary(candidate, false, "configuration", phase);
    if (identity === undefined) throw new Failure("configuration");
    this.temporaryIdentity = identity;
    const paths = {
      root: identity.path,
      home: join(identity.path, "home"),
      dockerConfig: join(identity.path, "docker"),
      kubeconfig: join(identity.path, "kubeconfig"),
      kind: join(identity.path, "kind"),
      kindConfig: join(identity.path, "kind.json"),
      chart: join(identity.path, "tetragon.tgz"),
      values: join(identity.path, "values.json"),
      resources: join(identity.path, "resources.json"),
    };
    try {
      await this.makeDirectory(paths.home, { mode: 0o700 });
      await this.makeDirectory(paths.dockerConfig, { mode: 0o700 });
      await this.writePath(paths.kindConfig, `${JSON.stringify(this.fixture.kindConfig)}\n`, { mode: 0o600 });
      await this.writePath(paths.values, `${JSON.stringify(this.fixture.helmValues)}\n`, { mode: 0o600 });
      await this.writePath(paths.resources, `${JSON.stringify({
        apiVersion: "v1", kind: "List", items: this.fixture.resources,
      })}\n`, { mode: 0o600 });
    } catch { throw new Failure("configuration"); }
    assertPhase(phase, "configuration");
    this.paths = Object.freeze(paths);
    this.environment = Object.freeze(buildToolEnvironment({
      dockerConfig: paths.dockerConfig,
      home: paths.home,
      kubeconfig: paths.kubeconfig,
      network: this.fixture.names.prefix,
      path: this.input.path,
    }));
  }

  async preflight(phase) {
    assertPhase(phase, "ownership");
    await this.reproveTemporary("ownership", phase, true);
    await this.requireDockerPrefixAbsent("ownership", phase);
    for (const [command, arguments_] of [
      ["docker", ["version", "--format", "{{.Server.Version}}"]],
      ["kubectl", ["version", "--client=true", "--output=json"]],
      ["helm", ["version", "--template", "{{.Version}}"]],
    ]) {
      const result = await this.readCommand(command, arguments_, "configuration", phase, smallOutputLimit, 15_000);
      if (!successfulNonempty(result)) throw new Failure("configuration");
    }
  }

  async resolveAssets(phase) {
    assertPhase(phase, "provider");
    const [kindBytes, chartBytes] = await Promise.all([
      this.fetchBytes(this.fixture.kindBinary.url, downloadLimit, phase.signal),
      this.fetchBytes(this.fixture.pins.chart.url, downloadLimit, phase.signal),
    ]).catch(() => { throw new Failure("provider"); });
    assertPhase(phase, "provider");
    if (
      sha256(kindBytes) !== this.fixture.kindBinary.sha256 ||
      sha256(chartBytes) !== this.fixture.pins.chart.sha256
    ) throw new Failure("provider");
    try {
      await this.writePath(this.paths.kind, kindBytes, { mode: 0o700 });
      await this.changeMode(this.paths.kind, 0o700);
      await this.writePath(this.paths.chart, chartBytes, { mode: 0o600 });
    } catch { throw new Failure("provider"); }
    await this.reproveTemporary("provider", phase, true);
    for (const [kind, pin] of [
      ["node", this.fixture.pins.node],
      ["tetragon", this.fixture.pins.tetragon],
      ["operator", this.fixture.pins.operator],
      ["busybox", this.fixture.pins.busybox],
    ]) {
      await this.resolveImage(kind, pin, phase);
    }
  }

  async createNetwork(phase) {
    assertPhase(phase, "provider");
    this.networkMayHaveApplied = true;
    let result;
    let thrown = false;
    try {
      result = await this.mutation("docker", buildNetworkCreateArguments(
        this.fixture.names.prefix, this.input.marker,
      ), "provider", phase, smallOutputLimit, 30_000);
    } catch { thrown = true; }
    assertPhase(phase, "provider");
    const outcome = thrown ? "ambiguous" : classifyMutationOutcome(result, (value) =>
      objectIdPattern.test(singleLine(value.stdout)) && value.stderr === "");
    if (outcome === "definitive") throw new Failure("provider");
    if (outcome === "success") this.networkToken = singleLine(result.stdout);
    await this.verifyNetwork("ownership", phase, true);
  }

  async createCluster(phase) {
    assertPhase(phase, "provider");
    await this.verifyNetwork("ownership", phase, true);
    this.clusterMayHaveApplied = true;
    let result;
    let thrown = false;
    try {
      result = await this.mutation(this.paths.kind, buildKindCreateArguments(this.fixture.names, {
        config: this.paths.kindConfig,
        kubeconfig: this.paths.kubeconfig,
        nodeImage: this.fixture.pins.node.reference,
      }), "provider", phase, processOutputLimit, 240_000);
    } catch { thrown = true; }
    assertPhase(phase, "provider");
    const outcome = thrown ? "ambiguous" : classifyMutationOutcome(result, (value) =>
      value.stderr.length <= processOutputLimit && value.stdout.length <= processOutputLimit);
    if (outcome === "definitive") throw new Failure("provider");
    await this.verifyCluster("ownership", phase);
  }

  async installTetragon(phase) {
    assertPhase(phase, "provider");
    await this.verifyCluster("ownership", phase);
    for (const pin of [this.fixture.pins.tetragon, this.fixture.pins.operator, this.fixture.pins.busybox]) {
      const loaded = await this.mutation("docker", buildNodeImagePullArguments(
        this.nodeToken, this.input.nodePlatform, pin.reference,
      ), "provider", phase, processOutputLimit, 180_000);
      if (!successful(loaded)) throw new Failure("provider");
      const listed = await this.readCommand("docker", [
        "exec", this.nodeToken, "ctr", "--namespace", "k8s.io", "images", "list", "--quiet",
      ], "provider", phase, processOutputLimit, 30_000);
      if (!successful(listed) || !listed.stdout.split("\n").includes(pin.reference)) throw new Failure("provider");
    }
    const installed = await this.mutation("helm", buildHelmInstallArguments({
      chart: this.paths.chart,
      kubeconfig: this.paths.kubeconfig,
      values: this.paths.values,
    }),
      "provider", phase, processOutputLimit, 240_000);
    if (classifyMutationOutcome(installed, () => true) !== "success") throw new Failure("provider");
    this.chartInstalled = true;
    const applied = await this.mutation("kubectl", [
      "apply", "--kubeconfig", this.paths.kubeconfig, "--filename", this.paths.resources,
    ], "provider", phase, processOutputLimit, 90_000);
    if (classifyMutationOutcome(applied, () => true) !== "success") throw new Failure("provider");
    this.resourcesApplied = true;
    for (const arguments_ of [
      ["rollout", "status", "daemonset/tetragon", "--namespace", "kube-system", "--timeout", "180s"],
      ["wait", "--namespace", this.fixture.names.namespace, "--for=condition=Ready", "pod/workload", "--timeout", "120s"],
      ["wait", "--namespace", this.fixture.names.namespace, "--for=condition=Ready", "pod/sink", "--timeout", "120s"],
    ]) {
      const ready = await this.readKubectl(arguments_, "capability", phase, processOutputLimit, 200_000);
      if (!successful(ready)) throw new Failure("capability");
    }
    await this.prepareEvidence(phase);
  }

  async runFixture(phase) {
    assertPhase(phase, "operation");
    if (this.expected === undefined || this.metricsBefore === undefined) throw new Failure("operation");
    for (const arguments_ of fixtureTriggerCommands(this.fixture.names, this.expected.sinkAddress)) {
      const result = await this.mutation("kubectl", ["--kubeconfig", this.paths.kubeconfig, ...arguments_],
        "operation", phase, smallOutputLimit, 30_000);
      if (classifyMutationOutcome(result, () => true) !== "success") throw new Failure("operation");
    }
    await this.wait(fixtureSettleMilliseconds, phase.signal);
    assertPhase(phase, "operation");
  }

  async captureEvidence(phase) {
    assertPhase(phase, "normalization");
    const metricsAfter = await this.captureMetrics(phase);
    const kprobes = await this.consumeKprobeCapture("normalization", phase);
    if (!successful(kprobes) || kprobes.stderr !== "" || kprobes.stdout.length === 0) {
      throw new Failure("normalization");
    }
    const log = await this.readKubectl(buildEventCaptureArguments(this.expected.tetragonPod),
      "normalization", phase, 16_777_216, 30_000);
    if (!successful(log) || log.stderr !== "") throw new Failure("normalization");
    const completeLog = Buffer.from(log.stdout);
    if (
      !Buffer.isBuffer(this.eventBaseline) || completeLog.byteLength <= this.eventBaseline.byteLength ||
      !completeLog.subarray(0, this.eventBaseline.byteLength).equals(this.eventBaseline)
    ) throw new Failure("normalization");
    const execBytes = completeLog.subarray(this.eventBaseline.byteLength);
    if (execBytes.at(-1) !== 0x0a || !kprobes.stdout.endsWith("\n")) throw new Failure("normalization");
    const eventBytes = Buffer.concat([execBytes, Buffer.from(kprobes.stdout)]);
    let normalized;
    try {
      const expected = Object.fromEntries(Object.entries(this.expected).filter(([key]) => key !== "tetragonPod"));
      normalized = this.normalize({
        organizationId: this.input.organizationId,
        expected,
        events: eventBytes,
        metricsBefore: this.metricsBefore,
        metricsAfter,
      });
    } catch { throw new Failure("normalization"); }
    return normalized;
  }

  async inspectOwnedTemporary(value, allowAssets, category, phase) {
    assertPhase(phase, category);
    if (typeof value !== "string" || !isAbsolute(value) || dirname(value) !== this.tempParent) return undefined;
    const prefix = join(this.tempParent, `${this.fixture.names.prefix}-runtime-`);
    if (!value.startsWith(prefix) || value.length === prefix.length) return undefined;
    let canonical;
    let status;
    let entries;
    try {
      [canonical, status, entries] = await Promise.all([
        this.canonicalPath(value), this.statPath(value), this.readDirectory(value),
      ]);
    } catch { return undefined; }
    assertPhase(phase, category);
    const allowed = allowAssets
      ? new Set(["docker", "home", "kind", "kind.json", "kubeconfig", "resources.json", "tetragon.tgz", "values.json"])
      : new Set();
    if (
      canonical !== value || !status?.isDirectory?.() || status?.isSymbolicLink?.() ||
      !Number.isSafeInteger(status.dev) || !Number.isSafeInteger(status.ino) ||
      !Array.isArray(entries) || entries.some((entry) => typeof entry !== "string" || !allowed.has(entry)) ||
      new Set(entries).size !== entries.length
    ) return undefined;
    return Object.freeze({ path: value, dev: status.dev, ino: status.ino });
  }

  async reproveTemporary(category, phase, allowAssets) {
    const retained = this.temporaryIdentity;
    if (retained === undefined) throw new Failure(category);
    const current = await this.inspectOwnedTemporary(retained.path, allowAssets, category, phase);
    if (current === undefined || current.dev !== retained.dev || current.ino !== retained.ino) {
      throw new Failure(category);
    }
    return current;
  }

  async cleanupTemporary(phase) {
    let retained = this.temporaryIdentity;
    if (retained === undefined && this.temporaryStarted && this.temporaryCandidate !== undefined) {
      retained = await this.inspectOwnedTemporary(this.temporaryCandidate, true, "cleanup", phase);
      if (retained === undefined) throw new Failure("cleanup");
      this.temporaryIdentity = retained;
    }
    if (retained === undefined) return;
    await this.reproveTemporary("cleanup", phase, true);
    try { await this.removePath(retained.path, { recursive: true, force: false, maxRetries: 0 }); }
    catch { throw new Failure("cleanup"); }
    try {
      await this.statPath(retained.path);
      throw new Failure("cleanup");
    } catch (error) {
      if (error instanceof Failure || error?.code !== "ENOENT") throw new Failure("cleanup");
    }
    this.temporaryIdentity = undefined;
    this.temporaryCandidate = undefined;
    this.temporaryStarted = false;
    this.paths = undefined;
    this.environment = undefined;
  }

  async execute(command, arguments_, category, phase, maximumBytes, timeoutMs) {
    assertPhase(phase, category);
    if (this.environment === undefined) throw new Failure(category);
    await this.reproveTemporary(category, phase, true);
    try {
      const result = await this.command(command, arguments_, {
        env: this.environment,
        maximumBytes,
        signal: phase.signal,
        timeoutMs,
      });
      assertPhase(phase, category);
      return result;
    } catch (error) {
      assertPhase(phase, category);
      throw error instanceof Failure ? error : new Failure(category);
    }
  }

  async readCommand(command, arguments_, category, phase, maximumBytes, timeoutMs) {
    let result;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try { result = await this.execute(command, arguments_, category, phase, maximumBytes, timeoutMs); }
      catch {
        if (attempt === 1) throw new Failure(category);
        await this.wait(250, phase.signal);
        continue;
      }
      if (successful(result)) return result;
      if (attempt === 0) await this.wait(250, phase.signal);
    }
    return result;
  }

  async readKubectl(arguments_, category, phase, maximumBytes = processOutputLimit, timeoutMs = 30_000) {
    return this.readCommand("kubectl", ["--kubeconfig", this.paths.kubeconfig, ...arguments_],
      category, phase, maximumBytes, timeoutMs);
  }

  async mutation(command, arguments_, category, phase, maximumBytes, timeoutMs) {
    assertPhase(phase, category);
    const operation = Promise.resolve().then(() =>
      this.execute(command, arguments_, category, phase, maximumBytes, timeoutMs));
    const settlement = operation.then(
      (value) => ({ state: "fulfilled", value }),
      (error) => ({ state: "rejected", error }),
    );
    this.mutationSettlements.push(settlement);
    return operation;
  }

  async resolveImage(kind, pin, phase) {
    const inspectArguments = [
      "image", "inspect", "--format",
      "[{{json .Id}},{{json .RepoDigests}},{{json .Os}},{{json .Architecture}}]",
      pin.reference,
    ];
    let inspected = await this.readCommand("docker", inspectArguments, "provider", phase, smallOutputLimit, 30_000);
    if (!successful(inspected)) {
      const pulled = await this.mutation("docker", ["pull", "--platform", this.input.nodePlatform, pin.reference],
        "provider", phase, processOutputLimit, 300_000);
      if (classifyMutationOutcome(pulled, () => true) !== "success") throw new Failure("provider");
      inspected = await this.readCommand("docker", inspectArguments, "provider", phase, smallOutputLimit, 30_000);
    }
    if (!successful(inspected) || inspected.stderr !== "") throw new Failure("provider");
    let document;
    try { document = parseUniqueJson(singleLine(inspected.stdout)); } catch { throw new Failure("provider"); }
    const expectedDigest = pin.reference.slice(pin.reference.indexOf("@") + 1);
    if (
      !Array.isArray(document) || document.length !== 4 ||
      !/^sha256:[0-9a-f]{64}$/.test(document[0] ?? "") ||
      !Array.isArray(document[1]) || document[1].length < 1 ||
      document[1].some((entry) => typeof entry !== "string") ||
      !document[1].some((entry) => entry.endsWith(`@${expectedDigest}`)) ||
      `${document[2]}/${document[3] === "x86_64" ? "amd64" : document[3]}` !== this.input.nodePlatform
    ) throw new Failure("provider");
    this.imageMetadata.set(kind, Object.freeze({ id: document[0], reference: pin.reference }));
  }

  async networkCandidates(category, phase) {
    const values = new Map();
    for (const filter of [
      `name=^${this.fixture.names.prefix}$`,
      "label=zasp.dev/proof=m0-12",
      `label=zasp.dev/run=${this.input.marker}`,
    ]) {
      const result = await this.readCommand("docker", [
        "network", "ls", "--no-trunc", "--filter", filter, "--format", "{{.ID}}|{{.Name}}",
      ], category, phase, smallOutputLimit, 15_000);
      if (!successful(result) || result.stderr !== "") throw new Failure(category);
      for (const [identifier, name] of parsePairs(result.stdout)) values.set(identifier, name);
    }
    return [...values].filter(([, name]) => name === this.fixture.names.prefix);
  }

  async verifyNetwork(category, phase, requireEmpty) {
    const candidates = await this.networkCandidates(category, phase);
    if (candidates.length !== 1) throw new Failure(category);
    const [token, name] = candidates[0];
    if (!objectIdPattern.test(token) || name !== this.fixture.names.prefix) throw new Failure(category);
    const inspected = await this.readCommand("docker", [
      "network", "inspect", "--format",
      "[{{json .Id}},{{json .Name}},{{json .Driver}},{{json .Internal}},{{json .Labels}},{{json .Containers}},{{json .Options}}]",
      token,
    ], category, phase, smallOutputLimit, 15_000);
    if (!successful(inspected) || inspected.stderr !== "") throw new Failure(category);
    let document;
    try { document = parseUniqueJson(singleLine(inspected.stdout)); } catch { throw new Failure(category); }
    const labels = document?.[4];
    const containers = document?.[5];
    const options = document?.[6];
    if (
      !Array.isArray(document) || document.length !== 7 || document[0] !== token ||
      document[1] !== name || document[2] !== "bridge" || document[3] !== false ||
      !isExactStringMap(labels, {
        "zasp.dev/proof": "m0-12", "zasp.dev/run": this.input.marker,
      }) || !isPlainObject(containers) || (requireEmpty && Object.keys(containers).length !== 0) ||
      !isExactStringMap(options, {})
    ) throw new Failure(category);
    this.networkToken = token;
    return document;
  }

  async nodeCandidates(category, phase) {
    const expectedName = `${this.fixture.names.cluster}-control-plane`;
    const result = await this.readCommand("docker", [
      "ps", "--all", "--no-trunc", "--filter", `name=${expectedName}`,
      "--format", "{{.ID}}|{{.Names}}",
    ], category, phase, smallOutputLimit, 15_000);
    if (!successful(result) || result.stderr !== "") throw new Failure(category);
    return parsePairs(result.stdout).filter(([, name]) => name === expectedName);
  }

  async verifyCluster(category, phase) {
    const candidates = await this.nodeCandidates(category, phase);
    if (candidates.length !== 1) throw new Failure(category);
    const [token, name] = candidates[0];
    if (!objectIdPattern.test(token)) throw new Failure(category);
    const inspected = await this.readCommand("docker", [
      "inspect", "--format",
      "[{{json .Id}},{{json .Name}},{{json .Config.Image}},{{json .Config.Labels}},{{json .Mounts}},{{json .NetworkSettings.Networks}}]",
      token,
    ], category, phase, processOutputLimit, 15_000);
    if (!successful(inspected) || inspected.stderr !== "") throw new Failure(category);
    let document;
    try { document = parseUniqueJson(singleLine(inspected.stdout)); } catch { throw new Failure(category); }
    const labels = document?.[3];
    const mounts = document?.[4];
    const networks = document?.[5];
    if (
      !Array.isArray(document) || document.length !== 6 || document[0] !== token ||
      document[1] !== `/${name}` || document[2] !== this.fixture.pins.node.reference ||
      !isPlainObject(labels) || labels["io.x-k8s.kind.cluster"] !== this.fixture.names.cluster ||
      labels["io.x-k8s.kind.role"] !== "control-plane" || !Array.isArray(mounts) ||
      mounts.filter((mount) => isPlainObject(mount) && mount.Source === "/proc" &&
        mount.Destination === "/procHost" && mount.RW === false).length !== 1 ||
      !isPlainObject(networks) || !Object.hasOwn(networks, this.fixture.names.prefix)
    ) throw new Failure(category);
    let kubeconfig;
    let status;
    try {
      [kubeconfig, status] = await Promise.all([this.readPath(this.paths.kubeconfig), this.statPath(this.paths.kubeconfig)]);
    } catch { throw new Failure(category); }
    if (
      !Buffer.isBuffer(kubeconfig) || kubeconfig.byteLength < 1 || kubeconfig.byteLength > smallOutputLimit ||
      !status?.isFile?.() || status?.isSymbolicLink?.()
    ) throw new Failure(category);
    this.nodeToken = token;
  }

  async prepareEvidence(phase) {
    const [workloadResult, serviceResult, tetragonResult] = await Promise.all([
      this.readKubectl(["get", "pod", this.fixture.names.workloadPod, "--namespace", this.fixture.names.namespace, "--output=json"],
        "capability", phase),
      this.readKubectl(["get", "service", this.fixture.names.sinkService, "--namespace", this.fixture.names.namespace, "--output=json"],
        "capability", phase),
      this.readKubectl(["get", "pods", "--namespace", "kube-system", "--selector", "app.kubernetes.io/name=tetragon", "--output=json"],
        "capability", phase),
    ]);
    if (![workloadResult, serviceResult, tetragonResult].every((value) => successful(value) && value.stderr === "")) {
      throw new Failure("capability");
    }
    let workload;
    let service;
    let tetragonList;
    try {
      workload = parseUniqueJson(workloadResult.stdout);
      service = parseUniqueJson(serviceResult.stdout);
      tetragonList = parseUniqueJson(tetragonResult.stdout);
    } catch { throw new Failure("capability"); }
    const status = workload?.status?.containerStatuses;
    const specification = workload?.spec?.containers;
    const items = tetragonList?.items;
    if (
      workload?.metadata?.name !== this.fixture.names.workloadPod ||
      workload?.metadata?.namespace !== this.fixture.names.namespace ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(workload?.metadata?.uid ?? "") ||
      !Array.isArray(status) || status.length !== 1 || status[0]?.name !== "workload" || status[0]?.ready !== true ||
      status[0]?.restartCount !== 0 || !/^containerd:\/\/[0-9a-f]{64}$/.test(status[0]?.containerID ?? "") ||
      !Array.isArray(specification) || specification.length !== 1 ||
      !Array.isArray(items) || items.length !== 1 ||
      !ipv4Pattern.test(service?.spec?.clusterIP ?? "")
    ) throw new Failure("capability");
    const tetragonPod = validateTetragonHealthPod(items[0], workload.spec.nodeName);
    const btf = await this.readCommand("docker", ["exec", this.nodeToken, "test", "-r", "/sys/kernel/btf/vmlinux"],
      "capability", phase, smallOutputLimit, 15_000);
    if (!successful(btf)) throw new Failure("capability");
    const imageId = String(status[0].imageID ?? "").replace(/^docker-pullable:\/\//, "").replace(/^docker:\/\//, "");
    this.expected = Object.freeze({
      namespace: this.fixture.names.namespace,
      podName: this.fixture.names.workloadPod,
      podUid: workload.metadata.uid,
      containerName: "workload",
      containerId: status[0].containerID,
      imageId,
      imageName: this.imageMetadata.get("busybox")?.id,
      nodeName: workload.spec.nodeName,
      labels: Object.freeze({
        "app.kubernetes.io/name": "zasp-m0-12-workload",
        "zasp.dev/proof": "m0-12",
        "zasp.dev/run": this.input.marker,
      }),
      execBinary: "/bin/echo",
      execArgument: "zasp-m0-12-exec",
      fileBinary: "/bin/sh",
      filePath: "/tmp/zasp-m0-12-proof.txt",
      filePolicyName: this.fixture.names.filePolicy,
      networkBinary: "/bin/nc",
      networkPolicyName: this.fixture.names.networkPolicy,
      sinkAddress: service.spec.clusterIP,
      sinkPort: 18080,
      sensorVersion: "v1.7.0",
      sensorCommit: "1de2ed8ebea18e56257dc59597aa13bf8f0e471e",
      policyCount: 2,
      tetragonPod,
    });
    this.metricsBefore = await this.captureMetrics(phase);
    try {
      const expected = Object.fromEntries(Object.entries(this.expected).filter(([key]) => key !== "tetragonPod"));
      parseTetragonMetrics(this.metricsBefore, expected);
    } catch { throw new Failure("capability"); }
    const baseline = await this.readKubectl(buildEventCaptureArguments(this.expected.tetragonPod),
      "capability", phase, 16_777_216, 30_000);
    if (successful(baseline) && baseline.stderr === "") {
      this.eventBaseline = Buffer.from(baseline.stdout);
    } else if (exactMissingTetragonLog(baseline)) {
      this.eventBaseline = Buffer.alloc(0);
    } else {
      throw new Failure("capability");
    }
    this.startKprobeCapture(phase);
    await this.wait(2_000, phase.signal);
    assertPhase(phase, "capability");
    if (this.eventCapture?.settled !== false) throw new Failure("capability");
  }

  startKprobeCapture(phase) {
    if (this.eventCapture !== undefined) throw new Failure("capability");
    const retained = { error: undefined, promise: undefined, result: undefined, settled: false };
    retained.promise = this.readKubectl(
      buildKprobeEventCaptureArguments(this.expected.tetragonPod, this.fixture.names),
      "capability", phase, processOutputLimit, 50_000,
    ).then((result) => {
      retained.result = result;
      retained.settled = true;
    }, (error) => {
      retained.error = error;
      retained.settled = true;
    });
    this.eventCapture = retained;
  }

  async consumeKprobeCapture(category, phase) {
    const retained = this.eventCapture;
    if (retained === undefined) throw new Failure(category);
    await retained.promise;
    assertPhase(phase, category);
    this.eventCapture = undefined;
    if (retained.error !== undefined || retained.result === undefined) throw new Failure(category);
    return retained.result;
  }

  async drainKprobeCapture() {
    const retained = this.eventCapture;
    if (retained === undefined) return;
    await retained.promise;
    this.eventCapture = undefined;
  }

  async captureMetrics(phase) {
    if (this.expected === undefined) throw new Failure("capability");
    const result = await this.readKubectl([
      "get", "--raw", `/api/v1/namespaces/kube-system/pods/${this.expected.tetragonPod}:2112/proxy/metrics`,
    ], "capability", phase, processOutputLimit, 30_000);
    if (!successful(result) || result.stderr !== "") throw new Failure("capability");
    return Buffer.from(result.stdout);
  }

  async requireClusterAbsent(phase) {
    const candidates = await this.nodeCandidates("cleanup", phase);
    if (candidates.length !== 0) throw new Failure("cleanup");
    if (objectIdPattern.test(this.nodeToken ?? "")) {
      const result = await this.readCommand("docker", ["inspect", this.nodeToken],
        "cleanup", phase, smallOutputLimit, 15_000);
      if (!exactMissingDockerObject(result, this.nodeToken)) throw new Failure("cleanup");
    }
  }

  async requireNetworkAbsent(phase) {
    const candidates = await this.networkCandidates("cleanup", phase);
    if (candidates.length !== 0) throw new Failure("cleanup");
    if (objectIdPattern.test(this.networkToken ?? "")) {
      const result = await this.readCommand("docker", ["network", "inspect", this.networkToken],
        "cleanup", phase, smallOutputLimit, 15_000);
      if (!exactMissingDockerObject(result, this.networkToken)) throw new Failure("cleanup");
    }
  }

  async requireDockerPrefixAbsent(category, phase) {
    for (const [kind, base] of [
      ["container", ["ps", "--all", "--no-trunc"]],
      ["network", ["network", "ls", "--no-trunc"]],
    ]) {
      for (const filter of [
        `name=${globalTemporaryPrefix}`,
        "label=zasp.dev/proof=m0-12",
        `label=zasp.dev/run=${this.input.marker}`,
      ]) {
        const result = await this.readCommand("docker", [
          ...base, "--filter", filter,
          "--format", kind === "container" ? "{{.ID}}|{{.Names}}" : "{{.ID}}|{{.Name}}",
        ], category, phase, smallOutputLimit, 15_000);
        if (!successful(result) || result.stderr !== "" || parsePairs(result.stdout).length !== 0) {
          throw new Failure(category);
        }
      }
    }
  }

  async joinMutations(phase) {
    assertPhase(phase, "cleanup");
    await this.drainKprobeCapture();
    assertPhase(phase, "cleanup");
    let joined = 0;
    while (joined < this.mutationSettlements.length) {
      const pending = this.mutationSettlements.slice(joined);
      await Promise.all(pending);
      joined += pending.length;
      assertPhase(phase, "cleanup");
    }
  }

  async cleanup(phase) {
    assertPhase(phase, "cleanup");
    let failed = false;
    const step = async (operation) => {
      try { await operation(); } catch { failed = true; }
      assertPhase(phase, "cleanup");
    };
    await step(async () => this.drainKprobeCapture());
    if (this.resourcesApplied && this.paths !== undefined) {
      await step(async () => {
        const value = await this.mutation("kubectl", [
          "delete", "--kubeconfig", this.paths.kubeconfig, "--filename", this.paths.resources,
          "--ignore-not-found=true", "--wait=true", "--timeout=60s",
        ], "cleanup", phase, processOutputLimit, 75_000);
        if (!successful(value)) throw new Failure("cleanup");
        this.resourcesApplied = false;
      });
    }
    if (this.chartInstalled && this.paths !== undefined) {
      await step(async () => {
        const value = await this.mutation("helm", [
          "uninstall", "tetragon", "--namespace", "kube-system", "--kubeconfig", this.paths.kubeconfig,
          "--wait", "--timeout", "60s",
        ], "cleanup", phase, processOutputLimit, 75_000);
        if (!successful(value)) throw new Failure("cleanup");
        this.chartInstalled = false;
      });
    }
    if (this.clusterMayHaveApplied && this.paths !== undefined) {
      await step(async () => {
        const value = await this.mutation(this.paths.kind, [
          "delete", "cluster", "--name", this.fixture.names.cluster,
          "--kubeconfig", this.paths.kubeconfig,
        ], "cleanup", phase, processOutputLimit, 90_000);
        if (!successful(value)) await this.requireClusterAbsent(phase);
        await this.requireClusterAbsent(phase);
        this.clusterMayHaveApplied = false;
        this.nodeToken = undefined;
      });
    }
    if (this.networkMayHaveApplied) {
      await step(async () => {
        await this.verifyNetwork("cleanup", phase, false);
        const token = this.networkToken;
        if (!objectIdPattern.test(token ?? "")) throw new Failure("cleanup");
        const value = await this.mutation("docker", ["network", "rm", token],
          "cleanup", phase, smallOutputLimit, 30_000);
        if (!successful(value) || singleLine(value.stdout) !== token) await this.requireNetworkAbsent(phase);
        await this.requireNetworkAbsent(phase);
        this.networkMayHaveApplied = false;
        this.networkToken = undefined;
      });
    }
    if (failed) throw new Failure("cleanup");
  }

  async auditAbsence(phase) {
    assertPhase(phase, "cleanup");
    let failed = false;
    if (this.environment !== undefined) {
      try { await this.requireDockerPrefixAbsent("cleanup", phase); } catch { failed = true; }
    }
    if (this.temporaryStarted) {
      try { await this.cleanupTemporary(phase); } catch { failed = true; }
    }
    let entries;
    try { entries = await this.readDirectory(this.tempParent); } catch { failed = true; }
    if (!Array.isArray(entries) || entries.some((entry) =>
      typeof entry !== "string" || entry.startsWith(globalTemporaryPrefix))) {
      failed = true;
    }
    if (failed) throw new Failure("cleanup");
  }
}

async function runPhase(timeoutMs, operation) {
  const controller = new AbortController();
  let active = true;
  const phase = Object.freeze({
    signal: controller.signal,
    assertActive() {
      if (!active || controller.signal.aborted) throw new Failure("operation");
    },
  });
  let timeout;
  let timedOut = false;
  const deadline = new Promise((_, reject) => {
    timeout = setTimeout(() => {
      timedOut = true;
      active = false;
      controller.abort();
      reject(new Failure("operation"));
    }, timeoutMs);
  });
  const pending = Promise.resolve().then(() => operation(phase));
  try {
    return await Promise.race([pending, deadline]);
  } catch (error) {
    if (timedOut) await pending.catch(() => {});
    throw error;
  } finally {
    clearTimeout(timeout);
    active = false;
    controller.abort();
  }
}

function validateRuntime(runtime) {
  if (runtime === null || typeof runtime !== "object") throw new TypeError("runtime is invalid");
  for (const method of [
    "preflight", "createCluster", "installTetragon", "runFixture",
    "captureEvidence", "joinMutations", "cleanup", "auditAbsence",
  ]) {
    if (typeof runtime[method] !== "function") throw new TypeError(`runtime ${method} is invalid`);
  }
}

function validateSystem(system) {
  if (system === null || typeof system !== "object") throw new TypeError("lifecycle system is invalid");
  for (const method of [
    "initialize", "preflight", "resolveAssets", "createNetwork", "createCluster",
    "installTetragon", "runFixture", "captureEvidence", "joinMutations",
    "cleanup", "auditAbsence", "hasCandidate",
  ]) {
    if (typeof system[method] !== "function") throw new TypeError(`lifecycle system ${method} is invalid`);
  }
}

function validateRuntimeInput(input) {
  expectExactObject(input, ["hostPlatform", "marker", "nodePlatform", "organizationId", "path"], "runtime input");
  validateMarker(input.marker);
  if (typeof input.organizationId !== "string" || !organizationPattern.test(input.organizationId)) {
    throw new TypeError("organization ID is invalid");
  }
  validateAbsolutePathList(input.path);
  if (!new Set(["darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"]).has(input.hostPlatform)) {
    throw new TypeError("host platform is invalid");
  }
  if (!new Set(["linux/amd64", "linux/arm64"]).has(input.nodePlatform)) {
    throw new TypeError("node platform is invalid");
  }
}

function validateOrchestrationOptions(value) {
  expectExactObject(value, ["cleanupTimeoutMs", "mainTimeoutMs"], "orchestration options");
  for (const name of ["mainTimeoutMs", "cleanupTimeoutMs"]) {
    if (!Number.isSafeInteger(value[name]) || value[name] < 1 || value[name] > 900_000) {
      throw new TypeError(`${name} is invalid`);
    }
  }
  return value;
}

function validateProofResult(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Failure("normalization");
  if (
    value.process !== true || value.file !== true || value.network !== true ||
    value.identity !== true || value.capability !== true || value.drops !== 0 ||
    !Array.isArray(value.events) || value.events.length !== 3 ||
    value.workload === null || typeof value.workload !== "object" ||
    value.sensor === null || typeof value.sensor !== "object"
  ) {
    throw new Failure("normalization");
  }
}

function normalizeFailure(error, fallbackCategory = "operation") {
  return error instanceof Failure ? error : new Failure(fallbackCategory);
}

function validateNames(value) {
  expectExactObject(value, ["cluster", "filePolicy", "namespace", "networkPolicy", "prefix", "sinkPod", "sinkService", "workloadPod"], "fixture names");
  for (const [key, entry] of Object.entries(value)) {
    validateBoundedString(entry, `fixture name ${key}`);
  }
  validateProofName(value.cluster);
  if (value.prefix !== value.cluster || value.namespace !== value.cluster) throw new TypeError("fixture scope names are invalid");
}

function validateProofName(value) {
  if (typeof value !== "string" || !namePattern.test(value) || value.length > 63) {
    throw new TypeError("proof name is invalid");
  }
}

function validateMarker(value) {
  if (typeof value !== "string" || !markerPattern.test(value)) throw new TypeError("marker is invalid");
}

function validateAbsolutePath(value, context) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || !isAbsolute(value)) {
    throw new TypeError(`${context} is invalid`);
  }
}

function validateAbsolutePathList(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 16_384) throw new TypeError("PATH is invalid");
  for (const entry of value.split(":")) validateAbsolutePath(entry, "PATH entry");
}

function validateBoundedString(value, context) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096) {
    throw new TypeError(`${context} is invalid`);
  }
}

function expectDataEnvironment(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError("process environment is invalid");
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || typeof value[key] !== "string") throw new TypeError("process environment is invalid");
  }
}

function expectAllowedDataObject(value, allowedKeys, context) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${context} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError(`${context} must be a plain object`);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" || !allowedKeys.has(key) || !descriptor?.enumerable ||
      !("value" in descriptor)
    ) throw new TypeError(`${context} keys are invalid`);
  }
}

function assertPhase(phase, category) {
  try { phase?.assertActive?.(); } catch { throw new Failure(category); }
  if (phase === null || typeof phase !== "object" || phase.signal?.aborted === true ||
      typeof phase.assertActive !== "function") throw new Failure(category);
}

function successful(value) {
  return value !== null && typeof value === "object" && value.status === 0 && value.signal === null &&
    typeof value.stdout === "string" && typeof value.stderr === "string";
}

function successfulNonempty(value) {
  return successful(value) && value.stderr === "" && value.stdout.trim().length > 0;
}

function singleLine(value) {
  if (typeof value !== "string" || value.includes("\r")) throw new TypeError("output line is invalid");
  const normalized = value.endsWith("\n") ? value.slice(0, -1) : value;
  if (normalized.length === 0 || normalized.includes("\n")) throw new TypeError("output line is invalid");
  return normalized;
}

function parsePairs(value) {
  if (typeof value !== "string" || value.includes("\r") || value.length > smallOutputLimit) {
    throw new TypeError("Docker listing is invalid");
  }
  if (value === "" || value === "\n") return [];
  const lines = value.endsWith("\n") ? value.slice(0, -1).split("\n") : value.split("\n");
  const pairs = lines.map((line) => {
    const separator = line.indexOf("|");
    if (separator < 1 || separator !== line.lastIndexOf("|") || separator === line.length - 1) {
      throw new TypeError("Docker listing is invalid");
    }
    return [line.slice(0, separator), line.slice(separator + 1)];
  });
  if (new Set(pairs.map(([identifier]) => identifier)).size !== pairs.length) {
    throw new TypeError("Docker listing is invalid");
  }
  return pairs;
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isExactStringMap(value, expected) {
  if (!isPlainObject(value)) return false;
  const actualKeys = Object.keys(value).sort();
  const expectedKeys = Object.keys(expected).sort();
  return actualKeys.length === expectedKeys.length && actualKeys.every((key, index) =>
    key === expectedKeys[index] && value[key] === expected[key]);
}

function sha256(value) {
  if (!(value instanceof Uint8Array)) throw new TypeError("digest input is invalid");
  return createHash("sha256").update(value).digest("hex");
}

async function fetchBounded(url, maximumBytes, signal) {
  if (typeof url !== "string" || !url.startsWith("https://") ||
      !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > downloadLimit) {
    throw new TypeError("download input is invalid");
  }
  const response = await fetch(url, { redirect: "follow", signal });
  if (!response.ok || response.body === null) throw new Failure("provider");
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > maximumBytes)) throw new Failure("provider");
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    const bytes = Buffer.from(chunk);
    size += bytes.byteLength;
    if (size > maximumBytes) throw new Failure("provider");
    chunks.push(bytes);
  }
  if (size === 0) throw new Failure("provider");
  return Buffer.concat(chunks);
}

function waitWithSignal(milliseconds, signal) {
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0 || milliseconds > 60_000) {
    throw new TypeError("wait bound is invalid");
  }
  return new Promise((resolve, reject) => {
    let timer;
    const abort = () => {
      clearTimeout(timer);
      signal?.removeEventListener?.("abort", abort);
      reject(new Failure("operation"));
    };
    timer = setTimeout(() => {
      signal?.removeEventListener?.("abort", abort);
      resolve();
    }, milliseconds);
    signal?.addEventListener?.("abort", abort, { once: true });
    if (signal?.aborted === true) abort();
  });
}

export function exactMissingDockerObject(result, token) {
  if (
    result === null || typeof result !== "object" || result.status !== 1 || result.signal !== null ||
    result.stdout !== "[]\n" || typeof result.stderr !== "string" || result.stderr.includes("\r") ||
    !objectIdPattern.test(token)
  ) return false;
  return result.stderr === `error: no such object: ${token}\n` ||
    result.stderr === `Error response from daemon: network ${token} not found\n`;
}

export function exactMissingTetragonLog(result) {
  return result !== null && typeof result === "object" &&
    result.status === 1 && result.signal === null && result.stdout === "" &&
    result.stderr === "cat: can't open '/var/run/cilium/tetragon/tetragon.log': No such file or directory\ncommand terminated with exit code 1\n";
}

function parseUniqueJson(source) {
  if (typeof source !== "string" || source.length === 0 || source.length > processOutputLimit) {
    throw new SyntaxError("JSON size is invalid");
  }
  let index = 0;
  const whitespace = () => { while (index < source.length && /[\t\r\n ]/.test(source[index])) index += 1; };
  const parseString = () => {
    if (source[index] !== '"') throw new SyntaxError("invalid string");
    const start = index;
    index += 1;
    while (index < source.length) {
      const character = source[index];
      if (character === '"') {
        index += 1;
        const value = JSON.parse(source.slice(start, index));
        if (value.length > 65_536 || hasUnpairedSurrogate(value)) throw new SyntaxError("invalid string");
        return value;
      }
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError("invalid control character");
      if (character !== "\\") { index += 1; continue; }
      index += 1;
      const escape = source[index];
      if ('"\\/bfnrt'.includes(escape ?? "")) index += 1;
      else if (escape === "u" && /^[a-fA-F0-9]{4}$/.test(source.slice(index + 1, index + 5))) index += 5;
      else throw new SyntaxError("invalid escape");
    }
    throw new SyntaxError("unterminated string");
  };
  const parseValue = (depth) => {
    if (depth > 64) throw new SyntaxError("excessive depth");
    whitespace();
    if (source[index] === "{") {
      index += 1;
      whitespace();
      const output = Object.create(null);
      const keys = new Set();
      if (source[index] === "}") { index += 1; return output; }
      while (true) {
        const key = parseString();
        if (keys.has(key) || keys.size >= 100_000) throw new SyntaxError("duplicate or excessive object");
        keys.add(key);
        whitespace();
        if (source[index] !== ":") throw new SyntaxError("invalid object");
        index += 1;
        output[key] = parseValue(depth + 1);
        whitespace();
        if (source[index] === "}") { index += 1; return output; }
        if (source[index] !== ",") throw new SyntaxError("invalid object");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1;
      whitespace();
      const output = [];
      if (source[index] === "]") { index += 1; return output; }
      while (true) {
        output.push(parseValue(depth + 1));
        if (output.length > 100_000) throw new SyntaxError("excessive array");
        whitespace();
        if (source[index] === "]") { index += 1; return output; }
        if (source[index] !== ",") throw new SyntaxError("invalid array");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === '"') return parseString();
    for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, index)) { index += literal.length; return value; }
    }
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(source.slice(index));
    if (!match) throw new SyntaxError("invalid value");
    index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) throw new SyntaxError("invalid number");
    return value;
  };
  const output = parseValue(0);
  whitespace();
  if (index !== source.length) throw new SyntaxError("trailing JSON");
  return output;
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return true;
  }
  return false;
}

function expectExactObject(value, expectedKeys, context) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${context} must be an object`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError(`${context} must be a plain object`);
  const actual = Reflect.ownKeys(value);
  if (
    actual.some((key) => typeof key !== "string") ||
    actual.length !== expectedKeys.length ||
    expectedKeys.some((key) => !actual.includes(key))
  ) {
    throw new TypeError(`${context} keys are invalid`);
  }
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new TypeError(`${context} must contain data properties`);
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runMain();
}
