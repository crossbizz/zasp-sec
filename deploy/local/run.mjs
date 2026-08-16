import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { isAbsolute, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";

import { PRODUCTS, buildProductResources, renderProductManifest } from "./manifests.mjs";

export const SUCCESS_LINE = "Local product manifests passed: pods=4 ready=4 services=4 internal=true cleanup=true.";
export const FAILURE_CATEGORIES = Object.freeze([
  "build",
  "cleanup",
  "configuration",
  "deadline",
  "operation",
  "ownership",
  "panic",
  "provider",
  "readiness",
]);

const markerPattern = /^[0-9a-f]{16}$/;
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const forbiddenEnvironmentPattern = /^(?:AWS_|AZURE_|GOOGLE_|CLOUDSDK_|KUBE(?:CONFIG|TOKEN)|DOCKER_HOST$|DOCKER_CONTEXT$|HTTP_PROXY$|HTTPS_PROXY$|ALL_PROXY$|NO_PROXY$)/i;
const proofNamePattern = /^zasp-m1-30a-[0-9a-f]{16}$/;
const objectIdPattern = /^[0-9a-f]{64}$/;
const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const mainTimeoutMilliseconds = 600_000;
const cleanupTimeoutMilliseconds = 180_000;
const settlementTimeoutMilliseconds = 60_000;

export const KIND_PINS = deepFreeze({
  kind: {
    version: "v0.32.0",
    assets: {
      "darwin/amd64": {
        sha256: "55b3f27c325ec6cf37fa651f3f53e01954eb4b95c10827d91bfee46e0835f2fb",
        url: "https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-darwin-amd64",
      },
      "darwin/arm64": {
        sha256: "dca67911095a110c2b5c36e26df6cac860c602033e456c0db47be498cdef1ebb",
        url: "https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-darwin-arm64",
      },
      "linux/amd64": {
        sha256: "6e811cf0a7422033e7442f78b767464a8ba19b2d96c78659652077f67172192b",
        url: "https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-linux-amd64",
      },
      "linux/arm64": {
        sha256: "b92cd615e97585de8ddade28ed5cd7feb4248d717c233eea5b03c37298900f5d",
        url: "https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-linux-arm64",
      },
    },
  },
  node: {
    configDigests: {
      "linux/amd64": "sha256:caf23176b804ea639d96b2266829fdff42ca8f064bd9d32c00ad913b23ced7d9",
      "linux/arm64": "sha256:8b8d852fef3a95a2b04fd9e6890044bf6092c7810df66da4f9b503fb4341da60",
    },
    platformDigests: {
      "linux/amd64": "sha256:397bcc4ab091b9632fb3639d5cf020943ca40e90fe7bcc38409738a4a0d056ee",
      "linux/arm64": "sha256:625f4633a546aba1e159ab56e52f9111b1b5044a165cc64ffe46d15d3dd0b0bf",
    },
    reference: "kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95",
  },
});

export class Failure extends Error {
  constructor(category = "operation", message = "local product operation failed") {
    super(message);
    this.name = "Failure";
    this.category = FAILURE_CATEGORIES.includes(category) ? category : "operation";
  }
}

export function buildKindConfig() {
  return deepFreeze({
    apiVersion: "kind.x-k8s.io/v1alpha4",
    kind: "Cluster",
    networking: { apiServerAddress: "127.0.0.1" },
    nodes: [{ role: "control-plane" }],
  });
}

export function buildKindCreateArguments(input) {
  requireExactObject(input, ["cluster", "config", "kubeconfig"], "kind create input");
  if (!proofNamePattern.test(input.cluster)) throw new TypeError("cluster name is invalid");
  validateAbsolutePath(input.config, "kind config");
  validateAbsolutePath(input.kubeconfig, "kubeconfig");
  return Object.freeze([
    "create", "cluster", "--name", input.cluster,
    "--config", input.config, "--kubeconfig", input.kubeconfig,
    "--image", KIND_PINS.node.reference, "--wait", "180s",
  ]);
}

export function buildServicePlan(product, paths, marker, nodePlatform) {
  const expected = PRODUCTS.find((entry) => entry.name === product?.name);
  requireExactObject(product, ["image", "module", "name", "package"], "product");
  if (expected === undefined || !exactObject(product, expected)) throw new TypeError("product is invalid");
  requireExactObject(paths, [
    "contextRoot", "dockerConfig", "dockerfile", "goCache", "goModuleCache", "repositoryRoot",
  ], "build paths");
  for (const [name, value] of Object.entries(paths)) validateAbsolutePath(value, name);
  if (paths.dockerfile !== join(paths.repositoryRoot, "deploy/local/Dockerfile")) {
    throw new TypeError("Dockerfile path is invalid");
  }
  validateMarker(marker);
  if (nodePlatform !== "linux/amd64" && nodePlatform !== "linux/arm64") {
    throw new TypeError("node platform is invalid");
  }
  const architecture = nodePlatform.slice("linux/".length);

  const buildContext = join(paths.contextRoot, product.name);
  const binary = join(buildContext, "service");
  return Object.freeze({
    binary,
    buildContext,
    docker: Object.freeze({
      arguments: Object.freeze([
        "build", "--file", paths.dockerfile,
        "--build-arg", "BINARY=service",
        "--label", `zasp.dev/component=${product.name}`,
        "--label", "zasp.dev/proof=m1-30a",
        "--label", `zasp.dev/run=${marker}`,
        "--tag", product.image,
        buildContext,
      ]),
      command: "docker",
    }),
    go: Object.freeze({
      arguments: Object.freeze([
        "build", "-trimpath", "-ldflags=-s -w -X main.buildVersion=m1-30a",
        "-o", binary, product.package,
      ]),
      command: "go",
      cwd: join(paths.repositoryRoot, product.module),
      environment: Object.freeze({
        CGO_ENABLED: "0",
        GOCACHE: paths.goCache,
        GOARCH: architecture,
        GOENV: "off",
        GOOS: "linux",
        GOMODCACHE: paths.goModuleCache,
        GOWORK: "off",
      }),
    }),
    image: product.image,
    name: product.name,
  });
}

export function buildChildEnvironment(hostEnvironment, paths) {
  try {
    if (!isPlainObject(hostEnvironment)) throw new TypeError("host environment is invalid");
    requireExactObject(paths, [
      "contextRoot", "dockerConfig", "dockerfile", "goCache", "goModuleCache", "repositoryRoot",
    ], "build paths");
    for (const [name, value] of Object.entries(paths)) validateAbsolutePath(value, name);
    for (const [name, value] of Object.entries(hostEnvironment)) {
      if (forbiddenEnvironmentPattern.test(name) && value !== undefined && value !== "") {
        throw new TypeError("host environment is invalid");
      }
    }
    validateAbsolutePath(hostEnvironment.HOME, "HOME");
    if (typeof hostEnvironment.PATH !== "string" || hostEnvironment.PATH.length === 0 ||
        hostEnvironment.PATH.length > 4096 || hostEnvironment.PATH.split(":").some((entry) => !safeAbsolutePath(entry))) {
      throw new TypeError("PATH is invalid");
    }
    return Object.freeze({
      DOCKER_CONFIG: paths.dockerConfig,
      HOME: hostEnvironment.HOME,
      LANG: "C.UTF-8",
      PATH: hostEnvironment.PATH,
    });
  } catch {
    throw new Failure("configuration");
  }
}

export function validateImageInspection(document, product, marker, platform, retained = undefined) {
  try {
    requireExactObject(product, ["image", "module", "name", "package"], "product");
    const expected = PRODUCTS.find((entry) => entry.name === product.name);
    if (expected === undefined || !exactObject(product, expected)) throw new TypeError("product is invalid");
    validateMarker(marker);
    if (!new Set(["linux/amd64", "linux/arm64"]).has(platform)) throw new TypeError("platform is invalid");
    if (!Array.isArray(document) || document.length !== 1) throw new TypeError("image inspection is invalid");
    const image = document[0];
    requireExactObject(image, ["Architecture", "Config", "Id", "Os", "RepoDigests", "RepoTags", "RootFS"], "image");
    requireExactObject(image.Config, [
      "Entrypoint", "Env", "ExposedPorts", "Labels", "User",
    ], "image config");
    requireExactObject(image.Config.Labels, ["zasp.dev/component", "zasp.dev/proof", "zasp.dev/run"], "image labels");
    requireExactObject(image.Config.ExposedPorts, ["8081/tcp"], "image ports");
    requireExactObject(image.Config.ExposedPorts["8081/tcp"], [], "image port");
    requireExactObject(image.RootFS, ["Layers", "Type"], "image rootfs");
    const architecture = platform.slice("linux/".length);
    if (
      image.Architecture !== architecture || image.Os !== "linux" || !digestPattern.test(image.Id) ||
      !Array.isArray(image.RepoDigests) || image.RepoDigests.length !== 0 ||
      !exactArray(image.RepoTags, [product.image]) || !exactArray(image.Config.Entrypoint, ["/service"]) ||
      !exactArray(image.Config.Env, ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]) ||
      image.Config.User !== "65532:65532" ||
      image.Config.Labels["zasp.dev/component"] !== product.name ||
      image.Config.Labels["zasp.dev/proof"] !== "m1-30a" || image.Config.Labels["zasp.dev/run"] !== marker ||
      image.RootFS.Type !== "layers" || !Array.isArray(image.RootFS.Layers) || image.RootFS.Layers.length !== 1 ||
      !digestPattern.test(image.RootFS.Layers[0])
    ) throw new TypeError("image inspection is invalid");
    if (retained !== undefined && (
      !isPlainObject(retained) || retained.id !== image.Id || retained.reference !== product.image ||
      retained.architecture !== architecture
    )) throw new TypeError("image identity changed");
    return Object.freeze({ architecture, id: image.Id, reference: product.image });
  } catch {
    throw new Failure("ownership");
  }
}

export function classifyMutationResult(result) {
  if (!isPlainObject(result)) return "ambiguous";
  if (result.thrown === true || result.timedOut === true || result.signal !== null) return "ambiguous";
  if (Number.isInteger(result.status) && result.status !== 0) return "definitive";
  if (result.status === 0 && result.signal === null && result.stdout === "" && result.stderr === "") return "applied";
  return "ambiguous";
}

export async function runBounded(command, arguments_, options, spawnProcess = spawn) {
  if (typeof command !== "string" || command.length === 0 || !Array.isArray(arguments_) ||
      !isPlainObject(options) || !isPlainObject(options.environment) ||
      !Number.isSafeInteger(options.outputLimit) || options.outputLimit < 1 ||
      !Number.isSafeInteger(options.timeoutMilliseconds) || options.timeoutMilliseconds < 1 ||
      (options.signal !== undefined && (typeof options.signal?.addEventListener !== "function" ||
        typeof options.signal?.removeEventListener !== "function" || typeof options.signal?.aborted !== "boolean")) ||
      typeof spawnProcess !== "function") throw new TypeError("process request is invalid");

  return await new Promise((resolve) => {
    let child;
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let closed = false;
    let thrown = false;
    let timedOut = false;
    let killed = false;
    let timer;

    const kill = () => {
      if (killed || child === undefined) return;
      killed = true;
      try { child.kill("SIGKILL"); } catch { thrown = true; }
    };
    const append = (kind, chunk) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
      if (stdout.length + stderr.length + bytes.length > options.outputLimit) {
        thrown = true;
        kill();
        return;
      }
      if (kind === "stdout") stdout = Buffer.concat([stdout, bytes]);
      else stderr = Buffer.concat([stderr, bytes]);
    };
    const finish = (status, signal) => {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
      resolve(Object.freeze({
        signal: signal ?? null,
        status: Number.isInteger(status) ? status : null,
        stderr: stderr.toString("utf8"),
        stdout: stdout.toString("utf8"),
        thrown,
        timedOut,
      }));
    };
    const abort = () => kill();

    try {
      child = spawnProcess(command, arguments_, {
        cwd: options.cwd,
        env: options.environment,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });
      child.stdout.on("data", (chunk) => append("stdout", chunk));
      child.stderr.on("data", (chunk) => append("stderr", chunk));
      child.stdout.on("error", () => { thrown = true; kill(); });
      child.stderr.on("error", () => { thrown = true; kill(); });
      child.on("error", () => { thrown = true; kill(); });
      child.once("close", finish);
      options.signal?.addEventListener("abort", abort, { once: true });
      if (options.signal?.aborted === true) abort();
      timer = setTimeout(() => {
        timedOut = true;
        kill();
      }, options.timeoutMilliseconds);
    } catch {
      thrown = true;
      finish(null, null);
    }
  });
}

export function validateKubernetesState(value) {
  try {
    requireExactObject(value, ["deployments", "nodeName", "pods", "services"], "Kubernetes state");
    if (!proofNamePattern.test(value.nodeName.replace(/-control-plane$/, ""))) {
      throw new TypeError("node name is invalid");
    }
    if (!Array.isArray(value.deployments) || !Array.isArray(value.pods) || !Array.isArray(value.services) ||
        value.deployments.length !== PRODUCTS.length || value.pods.length !== PRODUCTS.length ||
        value.services.length !== PRODUCTS.length) throw new TypeError("Kubernetes resource count is invalid");

    for (const product of PRODUCTS) {
      validateDeployment(value.deployments, product);
      validatePod(value.pods, product, value.nodeName);
      validateService(value.services, product);
    }
    return Object.freeze({ internal: true, pods: 4, ready: 4, services: 4 });
  } catch {
    throw new Failure("readiness");
  }
}

export async function orchestrate(runtime, options = {}) {
  validateLifecycle(runtime);
  const limits = validateOrchestrationOptions(options);
  let result;
  let mainError;
  try {
    result = await runPhase(limits.mainTimeoutMilliseconds, limits.settlementTimeoutMilliseconds, async (phase) => {
      await runtime.initialize(phase);
      await runtime.preflight(phase);
      await runtime.buildImages(phase);
      await runtime.createNetwork(phase);
      await runtime.createCluster(phase);
      await runtime.loadImages(phase);
      await runtime.applyManifests(phase);
      return validateProofResult(await runtime.verifyReadiness(phase));
    });
  } catch (error) {
    mainError = normalizeFailure(error);
  }

  let joinError;
  let cleanupError;
  let auditError;
  try {
    await runPhase(limits.cleanupTimeoutMilliseconds, limits.settlementTimeoutMilliseconds, async (phase) => {
      try { await runtime.joinMutations(phase); } catch (error) { joinError = normalizeFailure(error, "cleanup"); }
      try { await runtime.cleanup(phase); } catch (error) { cleanupError = normalizeFailure(error, "cleanup"); }
      try { await runtime.auditAbsence(phase); } catch (error) { auditError = normalizeFailure(error, "cleanup"); }
    });
  } catch {
    cleanupError ??= new Failure("cleanup");
  }

  if (cleanupError) throw cleanupError;
  if (auditError) throw auditError;
  if (joinError) throw joinError;
  if (mainError) throw mainError;
  return Object.freeze({ ...validateProofResult(result), cleanup: true });
}

export async function runMain(runtime = undefined, options = {}) {
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const setExitCode = options.setExitCode ?? ((value) => { process.exitCode = value; });
  try {
    const selected = runtime ?? DockerKindRuntime.fromProcess();
    const result = await orchestrate(selected, {
      cleanupTimeoutMilliseconds: options.cleanupTimeoutMilliseconds ?? cleanupTimeoutMilliseconds,
      mainTimeoutMilliseconds: options.mainTimeoutMilliseconds ?? mainTimeoutMilliseconds,
      settlementTimeoutMilliseconds: options.settlementTimeoutMilliseconds ?? settlementTimeoutMilliseconds,
    });
    validateProofResult(result);
    stdout.write(`${SUCCESS_LINE}\n`);
    setExitCode(0);
    return 0;
  } catch (error) {
    const failure = normalizeFailure(error);
    stderr.write(`Local product manifests failed: ${failure.category} rejected.\n`);
    setExitCode(1);
    return 1;
  }
}

export class DockerKindRuntime {
  constructor(input, system = undefined) {
    requireExactObject(input, ["home", "hostPlatform", "marker", "nodePlatform", "path", "repositoryRoot"], "runtime input");
    validateMarker(input.marker);
    validateAbsolutePath(input.home, "runtime home");
    validateAbsolutePath(input.repositoryRoot, "repository root");
    if (typeof input.path !== "string" || input.path.split(":").some((entry) => !safeAbsolutePath(entry))) {
      throw new TypeError("runtime PATH is invalid");
    }
    if (KIND_PINS.kind.assets[input.hostPlatform] === undefined ||
        KIND_PINS.node.configDigests[input.nodePlatform] === undefined ||
        KIND_PINS.node.platformDigests[input.nodePlatform] === undefined) {
      throw new TypeError("runtime platform is invalid");
    }
    this.input = Object.freeze({ ...input });
    this.system = system ?? new LocalProductSystem(this.input);
    validateLifecycle(this.system);
  }

  static fromProcess(environment = process.env, systemFactory = (input) => new LocalProductSystem(input)) {
    if (!isEnvironmentObject(environment)) throw new Failure("configuration");
    for (const [name, value] of Object.entries(environment)) {
      if (forbiddenEnvironmentPattern.test(name) && value !== undefined && value !== "") {
        throw new Failure("configuration");
      }
    }
    const architecture = process.arch === "arm64" ? "arm64" : process.arch === "x64" ? "amd64" : "unsupported";
    const operatingSystem = process.platform === "darwin" ? "darwin" : process.platform === "linux" ? "linux" : "unsupported";
    const input = {
      home: environment.HOME,
      hostPlatform: `${operatingSystem}/${architecture}`,
      marker: randomBytes(8).toString("hex"),
      nodePlatform: `linux/${architecture}`,
      path: environment.PATH,
      repositoryRoot: normalize(fileURLToPath(new URL("../..", import.meta.url))),
    };
    const runtime = new DockerKindRuntime(input, systemFactory(input));
    return runtime;
  }

  initialize(phase) { return this.system.initialize(phase); }
  preflight(phase) { return this.system.preflight(phase); }
  buildImages(phase) { return this.system.buildImages(phase); }
  createNetwork(phase) { return this.system.createNetwork(phase); }
  createCluster(phase) { return this.system.createCluster(phase); }
  loadImages(phase) { return this.system.loadImages(phase); }
  applyManifests(phase) { return this.system.applyManifests(phase); }
  verifyReadiness(phase) { return this.system.verifyReadiness(phase); }
  joinMutations(phase) { return this.system.joinMutations(phase); }
  cleanup(phase) { return this.system.cleanup(phase); }
  auditAbsence(phase) { return this.system.auditAbsence(phase); }
}

export class LocalProductSystem {
  constructor(input, dependencies = undefined) {
    requireExactObject(input, ["home", "hostPlatform", "marker", "nodePlatform", "path", "repositoryRoot"], "runtime input");
    validateMarker(input.marker);
    this.input = Object.freeze({ ...input });
    this.cluster = `zasp-m1-30a-${input.marker}`;
    this.dependencies = dependencies ?? defaultSystemDependencies();
    requireExactObject(this.dependencies, [
      "canonicalPath", "changeMode", "command", "fetchBytes", "hashBytes", "makeDirectory", "makeTemp",
      "readDirectory", "readPath", "removePath", "statPath", "tempParent", "writePath",
    ], "system dependencies");
    for (const name of [
      "canonicalPath", "changeMode", "command", "fetchBytes", "makeDirectory", "makeTemp",
      "hashBytes", "readDirectory", "readPath", "removePath", "statPath", "writePath",
    ]) if (typeof this.dependencies[name] !== "function") throw new TypeError(`system ${name} is invalid`);
    validateAbsolutePath(this.dependencies.tempParent, "temporary parent");
    this.paths = undefined;
    this.environment = undefined;
    this.temporaryStarted = false;
    this.temporaryCandidate = undefined;
    this.temporaryIdentity = undefined;
    this.mutationSettlements = [];
    this.pathIdentities = new Map();
    this.imageIdentities = new Map();
    this.imageMayHaveApplied = new Set();
    this.networkMayHaveApplied = false;
    this.networkIdentity = undefined;
    this.clusterMayHaveApplied = false;
    this.nodeIdentity = undefined;
    this.resourcesMayHaveApplied = false;
  }

  async initialize(phase) {
    phase.assertActive("configuration");
    let parent;
    let entries;
    try {
      parent = await this.dependencies.canonicalPath(this.dependencies.tempParent);
      entries = await this.dependencies.readDirectory(parent);
    } catch {
      throw new Failure("configuration");
    }
    phase.assertActive("configuration");
    if (!safeAbsolutePath(parent) || !Array.isArray(entries) || entries.some((entry) =>
      typeof entry !== "string" || entry.startsWith("zasp-m1-30a-"))) {
      throw new Failure("configuration");
    }
    this.dependencies.tempParent = parent;
    this.temporaryStarted = true;
    let candidate;
    try {
      candidate = await this.dependencies.makeTemp(join(parent, `${this.cluster}-runtime-`));
    } catch {
      throw new Failure("configuration");
    }
    this.temporaryCandidate = candidate;
    phase.assertActive("configuration");
    const identity = await this.inspectOwnedTemporary(candidate, false, phase, "configuration");
    if (identity === undefined) throw new Failure("configuration");
    this.temporaryIdentity = identity;
    const paths = {
      root: identity.path,
      home: join(identity.path, "home"),
      dockerConfig: join(identity.path, "docker"),
      images: join(identity.path, "images"),
      goCache: join(identity.path, "go-build"),
      goModuleCache: join(identity.path, "go-mod"),
      kubeconfig: join(identity.path, "kubeconfig"),
      kind: join(identity.path, "kind"),
      kindConfig: join(identity.path, "kind.json"),
      manifest: join(identity.path, "manifests.yaml"),
    };
    try {
      for (const path of [paths.home, paths.dockerConfig, paths.images, paths.goCache, paths.goModuleCache]) {
        await this.dependencies.makeDirectory(path, { mode: 0o700 });
      }
      await this.dependencies.writePath(paths.kindConfig, `${JSON.stringify(buildKindConfig())}\n`, { mode: 0o600 });
      await this.dependencies.writePath(paths.manifest, renderProductManifest(buildProductResources()), { mode: 0o600 });
    } catch {
      throw new Failure("configuration");
    }
    phase.assertActive("configuration");
    this.paths = Object.freeze(paths);
    for (const [path, kind] of [
      [paths.home, "directory"], [paths.dockerConfig, "directory"], [paths.images, "directory"],
      [paths.goCache, "directory"], [paths.goModuleCache, "directory"],
      [paths.kindConfig, "file"], [paths.manifest, "file"],
    ]) await this.rememberOwnedPath(path, kind, phase, "configuration");
    const buildPaths = {
      contextRoot: paths.images,
      dockerConfig: paths.dockerConfig,
      dockerfile: join(this.input.repositoryRoot, "deploy/local/Dockerfile"),
      goCache: paths.goCache,
      goModuleCache: paths.goModuleCache,
      repositoryRoot: this.input.repositoryRoot,
    };
    this.environment = Object.freeze({
      ...buildChildEnvironment({ HOME: paths.home, PATH: this.input.path }, buildPaths),
      KIND_EXPERIMENTAL_DOCKER_NETWORK: this.cluster,
      KUBECONFIG: paths.kubeconfig,
    });
  }

  async inspectOwnedTemporary(value, allowFiles, phase, category) {
    phase.assertActive(category);
    const parent = this.dependencies.tempParent;
    const prefix = join(parent, `${this.cluster}-runtime-`);
    if (!safeAbsolutePath(value) || !value.startsWith(prefix) || value.length === prefix.length) return undefined;
    let canonical;
    let status;
    let entries;
    try {
      [canonical, status, entries] = await Promise.all([
        this.dependencies.canonicalPath(value),
        this.dependencies.statPath(value),
        this.dependencies.readDirectory(value),
      ]);
    } catch {
      return undefined;
    }
    phase.assertActive(category);
    const allowed = allowFiles ? new Set([
      "docker", "go-build", "go-mod", "home", "images", "kind", "kind.json", "kubeconfig", "manifests.yaml",
    ]) : new Set();
    if (canonical !== value || !status?.isDirectory?.() || status?.isSymbolicLink?.() ||
        !Number.isSafeInteger(status.dev) || !Number.isSafeInteger(status.ino) ||
        !Array.isArray(entries) || entries.some((entry) => typeof entry !== "string" || !allowed.has(entry)) ||
        new Set(entries).size !== entries.length) return undefined;
    return Object.freeze({ dev: status.dev, ino: status.ino, path: value });
  }

  async preflight(phase) {
    await this.requireTemporaryOwnership(phase, "ownership");
    const absenceChecks = [
      ["docker", ["ps", "--all", "--quiet", "--no-trunc", "--filter", "name=^/zasp-m1-30a-"]],
      ["docker", ["ps", "--all", "--quiet", "--no-trunc", "--filter", "label=zasp.dev/proof=m1-30a"]],
      ["docker", ["network", "ls", "--quiet", "--no-trunc", "--filter", "name=^zasp-m1-30a-"]],
      ["docker", ["network", "ls", "--quiet", "--no-trunc", "--filter", "label=zasp.dev/proof=m1-30a"]],
      ...PRODUCTS.map((product) => [
        "docker", ["image", "ls", "--quiet", "--no-trunc", "--filter", `reference=${product.image}`],
      ]),
      ["docker", ["image", "ls", "--quiet", "--no-trunc", "--filter", "label=zasp.dev/proof=m1-30a"]],
    ];
    for (const [command, arguments_] of absenceChecks) {
      const result = await this.runRead(command, arguments_, phase, "configuration");
      if (result.stdout !== "") throw new Failure("configuration");
    }
    const docker = await this.runRead(
      "docker", ["version", "--format", "{{.Server.Version}}"], phase, "configuration",
    );
    if (!/^\d+\.\d+\.\d+\n$/.test(docker.stdout)) throw new Failure("configuration");
    const kubectl = await this.runRead(
      "kubectl", ["version", "--client=true", "--output=json"], phase, "configuration",
    );
    let document;
    try { document = parseBoundedJson(kubectl.stdout, 16_384); } catch { throw new Failure("configuration"); }
    if (!isPlainObject(document) || !isPlainObject(document.clientVersion) ||
        typeof document.clientVersion.gitVersion !== "string" ||
        !/^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(document.clientVersion.gitVersion)) {
      throw new Failure("configuration");
    }
    await this.requireTemporaryOwnership(phase, "ownership");
  }

  async requireTemporaryOwnership(phase, category) {
    if (this.temporaryIdentity === undefined || this.paths === undefined) throw new Failure(category);
    const current = await this.inspectOwnedTemporary(this.paths.root, true, phase, category);
    if (current === undefined || current.dev !== this.temporaryIdentity.dev ||
        current.ino !== this.temporaryIdentity.ino) throw new Failure(category);
    return current;
  }

  async inspectOwnedPath(path, kind, phase, category) {
    phase.assertActive(category);
    if (this.paths === undefined || !safeAbsolutePath(path) || !path.startsWith(`${this.paths.root}/`) ||
        !new Set(["directory", "file"]).has(kind)) return undefined;
    let canonical;
    let status;
    try {
      [canonical, status] = await Promise.all([
        this.dependencies.canonicalPath(path), this.dependencies.statPath(path),
      ]);
    } catch {
      return undefined;
    }
    phase.assertActive(category);
    const matchesKind = kind === "directory" ? status?.isDirectory?.() : status?.isFile?.();
    if (canonical !== path || !matchesKind || status?.isSymbolicLink?.() ||
        !Number.isSafeInteger(status.dev) || !Number.isSafeInteger(status.ino) ||
        (kind === "file" && (!Number.isSafeInteger(status.size) || status.size < 1 || status.size > 134_217_728))) {
      return undefined;
    }
    return Object.freeze({ dev: status.dev, ino: status.ino, kind, path });
  }

  async rememberOwnedPath(path, kind, phase, category) {
    const identity = await this.inspectOwnedPath(path, kind, phase, category);
    if (identity === undefined) throw new Failure(category);
    this.pathIdentities.set(path, identity);
    return identity;
  }

  async requireOwnedPath(path, phase, category) {
    const retained = this.pathIdentities.get(path);
    if (retained === undefined) throw new Failure(category);
    const current = await this.inspectOwnedPath(path, retained.kind, phase, category);
    if (current === undefined || current.dev !== retained.dev || current.ino !== retained.ino) {
      throw new Failure(category);
    }
    return current;
  }

  async runRead(command, arguments_, phase, category, timeoutMilliseconds = 10_000, outputLimit = 16_384) {
    phase.assertActive(category);
    let result;
    try {
      result = await this.dependencies.command(command, arguments_, {
        environment: this.environment,
        outputLimit,
        signal: phase.signal,
        timeoutMilliseconds,
      });
    } catch {
      throw new Failure(category);
    }
    phase.assertActive(category);
    if (!isPlainObject(result) || result.status !== 0 || result.signal !== null || result.thrown === true ||
        result.timedOut === true || result.stderr !== "" || typeof result.stdout !== "string" ||
        Buffer.byteLength(result.stdout) > outputLimit) throw new Failure(category);
    return result;
  }

  async runMutation(command, arguments_, phase, category, options) {
    phase.assertActive(category);
    const settlement = Promise.resolve().then(async () => {
      try {
        return await this.dependencies.command(command, arguments_, {
          cwd: options.cwd,
          environment: options.environment,
          outputLimit: options.outputLimit,
          signal: phase.signal,
          timeoutMilliseconds: options.timeoutMilliseconds,
        });
      } catch {
        return Object.freeze({
          signal: null, status: null, stderr: "", stdout: "", thrown: true, timedOut: false,
        });
      }
    });
    this.mutationSettlements.push(settlement.then(() => {}, () => {}));
    const result = await settlement;
    phase.assertActive(category);
    return Object.freeze({ outcome: classifyMutationResult(result), result });
  }

  async exactRegularFile(path, phase, category) {
    phase.assertActive(category);
    let status;
    try { status = await this.dependencies.statPath(path); } catch { return false; }
    phase.assertActive(category);
    return status?.isFile?.() && !status?.isSymbolicLink?.() && Number.isSafeInteger(status.size) && status.size > 0;
  }

  async buildImages(phase) {
    await this.requireTemporaryOwnership(phase, "ownership");
    const pin = KIND_PINS.kind.assets[this.input.hostPlatform];
    let bytes;
    try { bytes = await this.dependencies.fetchBytes(pin.url, 134_217_728, phase.signal); }
    catch { throw new Failure("provider"); }
    phase.assertActive("provider");
    if (!Buffer.isBuffer(bytes) || bytes.byteLength < 1 || bytes.byteLength > 134_217_728 ||
        this.dependencies.hashBytes(bytes) !== pin.sha256) throw new Failure("provider");
    try {
      await this.dependencies.writePath(this.paths.kind, bytes, { mode: 0o700 });
      await this.dependencies.changeMode(this.paths.kind, 0o700);
    } catch {
      throw new Failure("provider");
    }
    await this.rememberOwnedPath(this.paths.kind, "file", phase, "provider");

    const buildPaths = {
      contextRoot: this.paths.images,
      dockerConfig: this.paths.dockerConfig,
      dockerfile: join(this.input.repositoryRoot, "deploy/local/Dockerfile"),
      goCache: this.paths.goCache,
      goModuleCache: this.paths.goModuleCache,
      repositoryRoot: this.input.repositoryRoot,
    };
    for (const product of PRODUCTS) {
      const plan = buildServicePlan(product, buildPaths, this.input.marker, this.input.nodePlatform);
      try { await this.dependencies.makeDirectory(plan.buildContext, { mode: 0o700 }); }
      catch { throw new Failure("build"); }
      await this.rememberOwnedPath(plan.buildContext, "directory", phase, "build");
      const compiled = await this.runMutation(plan.go.command, plan.go.arguments, phase, "build", {
        cwd: plan.go.cwd,
        environment: Object.freeze({ ...this.environment, ...plan.go.environment }),
        outputLimit: 4_194_304,
        timeoutMilliseconds: 180_000,
      });
      if (compiled.outcome === "definitive" || !await this.exactRegularFile(plan.binary, phase, "build")) {
        throw new Failure("build");
      }
      await this.rememberOwnedPath(plan.binary, "file", phase, "build");
      await this.requireOwnedPath(plan.buildContext, phase, "ownership");
      await this.requireOwnedPath(plan.binary, phase, "ownership");

      this.imageMayHaveApplied.add(product.name);
      const built = await this.runMutation(plan.docker.command, plan.docker.arguments, phase, "build", {
        environment: this.environment,
        outputLimit: 4_194_304,
        timeoutMilliseconds: 180_000,
      });
      if (built.outcome === "definitive") {
        this.imageMayHaveApplied.delete(product.name);
        throw new Failure("build");
      }
      const inspected = await this.runRead(
        "docker", ["image", "inspect", product.image], phase, "ownership", 15_000, 262_144,
      );
      let document;
      try { document = projectRawImageInspection(parseBoundedJson(inspected.stdout, 262_144)); }
      catch { throw new Failure("ownership"); }
      const identity = validateImageInspection(document, product, this.input.marker, this.input.nodePlatform);
      if ([...this.imageIdentities.values()].some((value) => value.id === identity.id)) {
        throw new Failure("ownership");
      }
      this.imageIdentities.set(product.name, identity);
    }
    await this.requireTemporaryOwnership(phase, "ownership");
  }
  async createNetwork(phase) {
    await this.requireTemporaryOwnership(phase, "ownership");
    this.networkMayHaveApplied = true;
    const created = await this.runMutation("docker", [
      "network", "create", "--driver", "bridge",
      "--label", "zasp.dev/proof=m1-30a", "--label", `zasp.dev/run=${this.input.marker}`,
      this.cluster,
    ], phase, "provider", {
      environment: this.environment, outputLimit: 16_384, timeoutMilliseconds: 30_000,
    });
    if (created.outcome === "definitive") {
      this.networkMayHaveApplied = false;
      throw new Failure("provider");
    }
    const direct = singleLine(created.result.stdout);
    if (created.result.status === 0 && created.result.signal === null && created.result.stderr === "" &&
        created.result.thrown !== true && created.result.timedOut !== true && objectIdPattern.test(direct)) {
      this.networkIdentity = Object.freeze({ id: direct, name: this.cluster });
    }
    await this.verifyNetwork(phase, "ownership", true);
  }

  async networkCandidates(phase, category) {
    const found = new Map();
    for (const filter of [
      `name=^${this.cluster}$`, "label=zasp.dev/proof=m1-30a", `label=zasp.dev/run=${this.input.marker}`,
    ]) {
      const result = await this.runRead("docker", [
        "network", "ls", "--no-trunc", "--filter", filter, "--format", "{{.ID}}|{{.Name}}",
      ], phase, category);
      for (const [id, name] of parsePairs(result.stdout)) if (name === this.cluster) found.set(id, name);
    }
    return [...found].map(([id, name]) => ({ id, name }));
  }

  async verifyNetwork(phase, category, requireEmpty) {
    let retained = this.networkIdentity;
    if (retained === undefined) {
      const candidates = await this.networkCandidates(phase, category);
      if (candidates.length !== 1) throw new Failure(category);
      retained = candidates[0];
    }
    if (!objectIdPattern.test(retained.id) || retained.name !== this.cluster) throw new Failure(category);
    const result = await this.runRead("docker", [
      "network", "inspect", "--format",
      "[{{json .Id}},{{json .Name}},{{json .Driver}},{{json .Internal}},{{json .Labels}},{{json .Options}},{{json .Containers}},{{json .IPAM}}]",
      retained.id,
    ], phase, category);
    let document;
    try { document = parseBoundedJson(singleLine(result.stdout), 16_384); } catch { throw new Failure(category); }
    if (!Array.isArray(document) || document.length !== 8 || document[0] !== retained.id ||
        document[1] !== this.cluster || document[2] !== "bridge" || document[3] !== false ||
        !exactStringMap(document[4], { "zasp.dev/proof": "m1-30a", "zasp.dev/run": this.input.marker }) ||
        !exactStringMap(document[5], {}) || !isPlainObject(document[6]) ||
        (requireEmpty && Object.keys(document[6]).length !== 0) || !validNetworkIPAM(document[7])) {
      throw new Failure(category);
    }
    if (this.networkIdentity !== undefined && this.networkIdentity.id !== retained.id) throw new Failure(category);
    this.networkIdentity = Object.freeze({ id: retained.id, name: retained.name });
    return document;
  }

  async createCluster(phase) {
    await this.requireTemporaryOwnership(phase, "ownership");
    await this.requireOwnedPath(this.paths.kind, phase, "ownership");
    await this.requireOwnedPath(this.paths.kindConfig, phase, "ownership");
    await this.verifyNetwork(phase, "ownership", true);
    this.clusterMayHaveApplied = true;
    const created = await this.runMutation(this.paths.kind, buildKindCreateArguments({
      cluster: this.cluster, config: this.paths.kindConfig, kubeconfig: this.paths.kubeconfig,
    }), phase, "provider", {
      environment: this.environment, outputLimit: 4_194_304, timeoutMilliseconds: 240_000,
    });
    if (created.outcome === "definitive") {
      this.clusterMayHaveApplied = false;
      throw new Failure("provider");
    }
    await this.verifyCluster(phase, "ownership");
  }

  async nodeCandidates(phase, category) {
    const name = `${this.cluster}-control-plane`;
    const result = await this.runRead("docker", [
      "ps", "--all", "--no-trunc", "--filter", `name=^/${name}$`, "--format", "{{.ID}}|{{.Names}}",
    ], phase, category);
    return parsePairs(result.stdout).filter(([id, candidate]) => objectIdPattern.test(id) && candidate === name);
  }

  async verifyCluster(phase, category) {
    const candidates = await this.nodeCandidates(phase, category);
    if (candidates.length !== 1) throw new Failure(category);
    const [token, name] = candidates[0];
    if (this.nodeIdentity !== undefined && this.nodeIdentity.token !== token) throw new Failure(category);
    const result = await this.runRead("docker", ["inspect", token], phase, category, 15_000, 262_144);
    let document;
    try { document = parseBoundedJson(result.stdout, 262_144); }
    catch { throw new Failure(category); }
    const identity = validateKindNodeInspection(document, {
      cluster: this.cluster,
      hostPlatform: this.input.hostPlatform,
      imageId: KIND_PINS.node.configDigests[this.input.nodePlatform],
      name,
      networkId: this.networkIdentity?.id,
      reference: KIND_PINS.node.reference,
      token,
    }, this.nodeIdentity);
    if (this.pathIdentities.has(this.paths.kubeconfig)) {
      await this.requireOwnedPath(this.paths.kubeconfig, phase, category);
    } else {
      await this.rememberOwnedPath(this.paths.kubeconfig, "file", phase, category);
    }
    this.nodeIdentity = identity;
    return identity;
  }
  async loadImages(phase) {
    await this.requireTemporaryOwnership(phase, "ownership");
    await this.verifyCluster(phase, "ownership");
    for (const product of PRODUCTS) {
      const retained = this.imageIdentities.get(product.name);
      if (retained === undefined) throw new Failure("ownership");
      await this.verifyProductImage(product, retained, phase, "ownership");
      const loaded = await this.runMutation(this.paths.kind, [
        "load", "docker-image", product.image, "--name", this.cluster,
      ], phase, "provider", {
        environment: this.environment, outputLimit: 4_194_304, timeoutMilliseconds: 120_000,
      });
      if (loaded.outcome === "definitive") throw new Failure("provider");
      const listed = await this.runRead("docker", [
        "exec", this.nodeIdentity.token, "ctr", "--namespace", "k8s.io", "images", "list", "--quiet",
      ], phase, "provider", 30_000, 4_194_304);
      const references = listed.stdout.endsWith("\n") ? listed.stdout.slice(0, -1).split("\n") : [];
      if (!references.includes(`docker.io/${product.image}`)) throw new Failure("provider");
    }
    await this.verifyCluster(phase, "ownership");
  }

  async verifyProductImage(product, retained, phase, category) {
    const result = await this.runRead(
      "docker", ["image", "inspect", retained.id], phase, category, 15_000, 262_144,
    );
    let document;
    try { document = projectRawImageInspection(parseBoundedJson(result.stdout, 262_144)); }
    catch { throw new Failure(category); }
    return validateImageInspection(document, product, this.input.marker, this.input.nodePlatform, retained);
  }

  async applyManifests(phase) {
    await this.requireTemporaryOwnership(phase, "ownership");
    await this.requireOwnedPath(this.paths.manifest, phase, "ownership");
    await this.requireOwnedPath(this.paths.kubeconfig, phase, "ownership");
    await this.verifyCluster(phase, "ownership");
    this.resourcesMayHaveApplied = true;
    const applied = await this.runMutation("kubectl", [
      "--kubeconfig", this.paths.kubeconfig, "apply", "--filename", this.paths.manifest,
    ], phase, "provider", {
      environment: this.environment, outputLimit: 4_194_304, timeoutMilliseconds: 90_000,
    });
    if (applied.outcome === "definitive") {
      this.resourcesMayHaveApplied = false;
      throw new Failure("provider");
    }
    await this.runRead("kubectl", [
      "--kubeconfig", this.paths.kubeconfig, "wait", "--namespace", "zasp-local",
      "--for=condition=Available", "deployment", "--all", "--timeout=180s",
    ], phase, "readiness", 200_000, 4_194_304);
  }

  async verifyReadiness(phase) {
    await this.requireTemporaryOwnership(phase, "ownership");
    await this.verifyCluster(phase, "ownership");
    const requests = [
      ["deployment", "apps/v1", "DeploymentList"],
      ["pod", "v1", "PodList"],
      ["service", "v1", "ServiceList"],
      ["ingress", "networking.k8s.io/v1", "IngressList"],
    ];
    const documents = new Map();
    for (const [resource, apiVersion, kind] of requests) {
      const result = await this.runRead("kubectl", [
        "--kubeconfig", this.paths.kubeconfig, "get", resource, "--namespace", "zasp-local", "--output=json",
      ], phase, "readiness", 30_000, 4_194_304);
      let document;
      try { document = parseBoundedJson(result.stdout, 4_194_304); } catch { throw new Failure("readiness"); }
      requireExactObject(document, ["apiVersion", "items", "kind", "metadata"], `${resource} list`);
      requireExactObject(document.metadata, ["resourceVersion"], `${resource} metadata`);
      if (document.apiVersion !== apiVersion || document.kind !== kind ||
          document.metadata.resourceVersion !== "" || !Array.isArray(document.items)) {
        throw new Failure("readiness");
      }
      documents.set(resource, document.items);
    }
    if (documents.get("ingress").length !== 0) throw new Failure("readiness");
    return validateKubernetesState({
      deployments: documents.get("deployment").map(projectDeployment),
      nodeName: `${this.cluster}-control-plane`,
      pods: documents.get("pod").map(projectPod),
      services: documents.get("service").map(projectService),
    });
  }

  async runRaw(command, arguments_, phase, category, timeoutMilliseconds = 15_000, outputLimit = 262_144) {
    phase.assertActive(category);
    let result;
    try {
      result = await this.dependencies.command(command, arguments_, {
        environment: this.environment, outputLimit, signal: phase.signal, timeoutMilliseconds,
      });
    } catch {
      throw new Failure(category);
    }
    phase.assertActive(category);
    if (!isPlainObject(result) || typeof result.stdout !== "string" || typeof result.stderr !== "string" ||
        Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) > outputLimit ||
        result.thrown === true || result.timedOut === true) throw new Failure(category);
    return result;
  }

  async joinMutations(phase) {
    phase.assertActive("cleanup");
    let joined = 0;
    while (joined < this.mutationSettlements.length) {
      const pending = this.mutationSettlements.slice(joined);
      await Promise.all(pending);
      joined += pending.length;
      phase.assertActive("cleanup");
    }
  }

  async cleanup(phase) {
    phase.assertActive("cleanup");
    let failed = false;
    let clusterAbsent = !this.clusterMayHaveApplied;
    let networkAbsent = !this.networkMayHaveApplied;
    const step = async (operation) => {
      try { await operation(); } catch { failed = true; }
      phase.assertActive("cleanup");
    };

    if (this.clusterMayHaveApplied) {
      await step(async () => {
        if (this.nodeIdentity === undefined) {
          const candidates = await this.nodeCandidates(phase, "cleanup");
          if (candidates.length === 0) {
            if ((await this.nodeCandidates(phase, "cleanup")).length !== 0) throw new Failure("cleanup");
            this.clusterMayHaveApplied = false;
            this.resourcesMayHaveApplied = false;
            clusterAbsent = true;
            return;
          }
          if (candidates.length !== 1) throw new Failure("cleanup");
        }
        await this.verifyCluster(phase, "cleanup");
        const token = this.nodeIdentity.token;
        const removed = await this.runMutation("docker", ["rm", "--force", "--volumes", token], phase,
          "cleanup", { environment: this.environment, outputLimit: 262_144, timeoutMilliseconds: 90_000 });
        if (removed.outcome === "definitive") throw new Failure("cleanup");
        await this.requireClusterAbsent(phase);
        clusterAbsent = true;
        this.clusterMayHaveApplied = false;
        this.resourcesMayHaveApplied = false;
      });
    }
    if (this.networkMayHaveApplied && clusterAbsent) {
      await step(async () => {
        if (this.networkIdentity === undefined) {
          const candidates = await this.networkCandidates(phase, "cleanup");
          if (candidates.length === 0) {
            if ((await this.networkCandidates(phase, "cleanup")).length !== 0) throw new Failure("cleanup");
            this.networkMayHaveApplied = false;
            networkAbsent = true;
            return;
          }
          if (candidates.length !== 1) throw new Failure("cleanup");
        }
        await this.verifyNetwork(phase, "cleanup", true);
        const token = this.networkIdentity.id;
        const removed = await this.runMutation("docker", ["network", "rm", token], phase, "cleanup", {
          environment: this.environment, outputLimit: 16_384, timeoutMilliseconds: 30_000,
        });
        if (removed.outcome === "definitive") throw new Failure("cleanup");
        await this.requireNetworkAbsent(phase);
        networkAbsent = true;
        this.networkMayHaveApplied = false;
      });
    }
    if (clusterAbsent && networkAbsent) {
      for (const product of [...PRODUCTS].reverse()) {
        let retained = this.imageIdentities.get(product.name);
        if (retained === undefined && this.imageMayHaveApplied.has(product.name)) {
          retained = await this.reconcileProductImage(product, phase);
          if (retained === undefined) {
            this.imageMayHaveApplied.delete(product.name);
            continue;
          }
        }
        if (retained === undefined) continue;
        await step(async () => {
          await this.verifyProductImage(product, retained, phase, "cleanup");
          const removed = await this.runMutation("docker", ["image", "rm", "--force", retained.id], phase,
            "cleanup", { environment: this.environment, outputLimit: 262_144, timeoutMilliseconds: 60_000 });
          if (removed.outcome === "definitive") throw new Failure("cleanup");
          await this.requireImageAbsent(product, retained, phase);
          this.imageIdentities.delete(product.name);
          this.imageMayHaveApplied.delete(product.name);
        });
      }
    }
    if (failed) throw new Failure("cleanup");
  }

  async requireClusterAbsent(phase) {
    const candidates = await this.nodeCandidates(phase, "cleanup");
    if (candidates.length !== 0 || this.nodeIdentity === undefined) throw new Failure("cleanup");
    const inspected = await this.runRaw("docker", ["inspect", this.nodeIdentity.token], phase, "cleanup");
    if (!exactMissingDockerObject(inspected, this.nodeIdentity.token)) throw new Failure("cleanup");
    const volume = await this.runRaw("docker", ["volume", "inspect", this.nodeIdentity.volumeToken], phase, "cleanup");
    if (!exactMissingDockerVolume(volume, this.nodeIdentity.volumeToken)) throw new Failure("cleanup");
    this.nodeIdentity = undefined;
  }

  async requireNetworkAbsent(phase) {
    const candidates = await this.networkCandidates(phase, "cleanup");
    if (candidates.length !== 0 || this.networkIdentity === undefined) throw new Failure("cleanup");
    const inspected = await this.runRaw("docker", ["network", "inspect", this.networkIdentity.id], phase, "cleanup");
    if (!exactMissingDockerObject(inspected, this.networkIdentity.id)) throw new Failure("cleanup");
    this.networkIdentity = undefined;
  }

  async requireImageAbsent(product, retained, phase) {
    const inspected = await this.runRaw("docker", ["image", "inspect", retained.id], phase, "cleanup");
    if (!exactMissingDockerImage(inspected, retained.id)) throw new Failure("cleanup");
    const listed = await this.runRead("docker", [
      "image", "ls", "--quiet", "--no-trunc", "--filter", `reference=${product.image}`,
    ], phase, "cleanup");
    if (listed.stdout !== "") throw new Failure("cleanup");
  }

  async reconcileProductImage(product, phase) {
    const list = async () => {
      const result = await this.runRead("docker", [
        "image", "ls", "--quiet", "--no-trunc", "--filter", `reference=${product.image}`,
      ], phase, "cleanup");
      if (result.stdout === "") return [];
      if (!result.stdout.endsWith("\n")) throw new Failure("cleanup");
      const values = result.stdout.slice(0, -1).split("\n");
      if (new Set(values).size !== values.length || values.some((value) => !digestPattern.test(value))) {
        throw new Failure("cleanup");
      }
      return values;
    };
    let candidates = await list();
    if (candidates.length === 0) candidates = await list();
    if (candidates.length === 0) return undefined;
    if (candidates.length !== 1) throw new Failure("cleanup");
    const result = await this.runRead(
      "docker", ["image", "inspect", candidates[0]], phase, "cleanup", 15_000, 262_144,
    );
    let document;
    try { document = projectRawImageInspection(parseBoundedJson(result.stdout, 262_144)); }
    catch { throw new Failure("cleanup"); }
    const identity = validateImageInspection(document, product, this.input.marker, this.input.nodePlatform);
    if (identity.id !== candidates[0]) throw new Failure("cleanup");
    this.imageIdentities.set(product.name, identity);
    return identity;
  }

  async requireGlobalAbsence(phase, category) {
    const checks = [
      ["ps", "--all", "--quiet", "--no-trunc", "--filter", "name=^/zasp-m1-30a-"],
      ["ps", "--all", "--quiet", "--no-trunc", "--filter", "label=zasp.dev/proof=m1-30a"],
      ["network", "ls", "--quiet", "--no-trunc", "--filter", "name=^zasp-m1-30a-"],
      ["network", "ls", "--quiet", "--no-trunc", "--filter", "label=zasp.dev/proof=m1-30a"],
      ...PRODUCTS.map((product) => [
        "image", "ls", "--quiet", "--no-trunc", "--filter", `reference=${product.image}`,
      ]),
      ["image", "ls", "--quiet", "--no-trunc", "--filter", "label=zasp.dev/proof=m1-30a"],
    ];
    for (const arguments_ of checks) {
      const result = await this.runRead("docker", arguments_, phase, category);
      if (result.stdout !== "") throw new Failure(category);
    }
  }

  async cleanupTemporary(phase) {
    if (!this.temporaryStarted) return;
    let retained = this.temporaryIdentity;
    if (retained === undefined && this.temporaryCandidate !== undefined) {
      retained = await this.inspectOwnedTemporary(this.temporaryCandidate, true, phase, "cleanup");
      if (retained === undefined) throw new Failure("cleanup");
      this.temporaryIdentity = retained;
    }
    if (retained === undefined) throw new Failure("cleanup");
    const current = await this.inspectOwnedTemporary(retained.path, true, phase, "cleanup");
    if (current === undefined || current.dev !== retained.dev || current.ino !== retained.ino) {
      throw new Failure("cleanup");
    }
    try {
      await this.dependencies.removePath(retained.path, { recursive: true, force: false, maxRetries: 0 });
    } catch {
      throw new Failure("cleanup");
    }
    try {
      await this.dependencies.statPath(retained.path);
      throw new Failure("cleanup");
    } catch (error) {
      if (error instanceof Failure || error?.code !== "ENOENT") throw new Failure("cleanup");
    }
    this.temporaryStarted = false;
    this.temporaryCandidate = undefined;
    this.temporaryIdentity = undefined;
    this.paths = undefined;
    this.environment = undefined;
    this.pathIdentities.clear();
  }

  async auditAbsence(phase) {
    phase.assertActive("cleanup");
    let failed = false;
    if (this.environment !== undefined) {
      try { await this.requireGlobalAbsence(phase, "cleanup"); } catch { failed = true; }
    }
    if (!this.clusterMayHaveApplied && !this.networkMayHaveApplied && this.imageIdentities.size === 0 &&
        this.imageMayHaveApplied.size === 0) {
      try { await this.cleanupTemporary(phase); } catch { failed = true; }
    } else {
      failed = true;
    }
    let entries;
    try { entries = await this.dependencies.readDirectory(this.dependencies.tempParent); } catch { failed = true; }
    if (!Array.isArray(entries) || entries.some((entry) =>
      typeof entry !== "string" || entry.startsWith("zasp-m1-30a-"))) failed = true;
    if (failed) throw new Failure("cleanup");
  }
}

function defaultSystemDependencies() {
  return {
    canonicalPath: realpath,
    changeMode: chmod,
    command: (command, arguments_, options) => runBounded(command, arguments_, options),
    fetchBytes: fetchBoundedAsset,
    hashBytes: (value) => createHash("sha256").update(value).digest("hex"),
    makeDirectory: mkdir,
    makeTemp: mkdtemp,
    readDirectory: readdir,
    readPath: readFile,
    removePath: rm,
    statPath: lstat,
    tempParent: tmpdir(),
    writePath: writeFile,
  };
}

export async function fetchBoundedAsset(url, limit, signal, fetchImplementation = fetch) {
  if (typeof url !== "string" || !url.startsWith("https://") ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 134_217_728 ||
      typeof fetchImplementation !== "function") throw new Failure("provider");
  let response;
  try {
    response = await fetchImplementation(url, { redirect: "follow", signal });
  } catch {
    throw new Failure("provider");
  }
  if (!response.ok || response.status !== 200 || typeof response.url !== "string" ||
      !response.url.startsWith("https://")) throw new Failure("provider");
  const header = response.headers.get("content-length");
  const length = header === null ? undefined : Number(header);
  if (length !== undefined && (!Number.isSafeInteger(length) || length < 1 || length > limit)) {
    throw new Failure("provider");
  }
  const reader = response.body?.getReader();
  if (reader === undefined) throw new Failure("provider");
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => {});
      throw new Failure("provider");
    }
    chunks.push(Buffer.from(value));
  }
  if (total === 0) throw new Failure("provider");
  return Buffer.concat(chunks);
}

export function validateKindNodeInspection(document, expected, retained = undefined) {
  try {
    requireExactObject(expected, ["cluster", "hostPlatform", "imageId", "name", "networkId", "reference", "token"],
      "kind node expectation");
    const darwin = expected.hostPlatform === "darwin/amd64" || expected.hostPlatform === "darwin/arm64";
    const linux = expected.hostPlatform === "linux/amd64" || expected.hostPlatform === "linux/arm64";
    if (!darwin && !linux) throw new TypeError("kind host platform is invalid");
    const expectedBinds = darwin
      ? ["/lib/modules:/lib/modules:ro", "/dev/mapper:/dev/mapper"]
      : ["/lib/modules:/lib/modules:ro", "/dev/mapper:/dev/mapper", "/proc:/procHost:ro"];
    const expectedBindMounts = darwin
      ? [["/lib/modules", "/lib/modules", "ro", false, "rprivate"],
        ["/dev/mapper", "/dev/mapper", "", true, "rprivate"]]
      : [["/lib/modules", "/lib/modules", "ro", false, "rprivate"],
        ["/dev/mapper", "/dev/mapper", "", true, "rprivate"],
        ["/proc", "/procHost", "ro", false, "rprivate"]];
    const node = Array.isArray(document) && document.length === 1 ? document[0] : undefined;
    const config = node?.Config;
    const host = node?.HostConfig;
    const mounts = node?.Mounts;
    const networks = node?.NetworkSettings?.Networks;
    if (!isPlainObject(node) || node.Id !== expected.token || node.Name !== `/${expected.name}` ||
        node.Image !== expected.imageId || !isPlainObject(config) || config.Image !== expected.reference ||
        config.Hostname !== expected.name || config.User !== "" || config.Cmd !== null ||
        !exactArray(config.Entrypoint, ["/usr/local/bin/entrypoint", "/sbin/init"]) ||
        !exactStringMap(config.Labels, {
          "io.x-k8s.kind.cluster": expected.cluster, "io.x-k8s.kind.role": "control-plane",
        }) || !exactStringSet(config.Env, [
          "KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER",
          "KUBECONFIG=/etc/kubernetes/admin.conf",
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "container=docker", "HTTP_PROXY=", "HTTPS_PROXY=", "NO_PROXY=",
        ]) || !isPlainObject(host) || !exactStringSet(host.Binds, expectedBinds) ||
        !exactStringMap(host.Tmpfs, { "/run": "", "/tmp": "" }) || host.Privileged !== true ||
        host.CapAdd !== null || host.CapDrop !== null || !exactArray(host.Devices, []) ||
        host.DeviceRequests !== null || host.PidMode !== "" || host.IpcMode !== "private" ||
        host.UsernsMode !== "" || host.CgroupnsMode !== "private" || host.ReadonlyRootfs !== false ||
        !exactStringSet(host.SecurityOpt, ["seccomp=unconfined", "apparmor=unconfined", "label=disable"]) ||
        !Array.isArray(mounts) || mounts.length !== expectedBindMounts.length + 1 || !isPlainObject(networks) ||
        Object.keys(networks).length !== 1 || !Object.hasOwn(networks, expected.cluster)) {
      throw new TypeError("kind node metadata is invalid");
    }
    for (const [source, destination, mode, writable, propagation] of expectedBindMounts) {
      const matching = mounts.filter((mount) => isPlainObject(mount) && mount.Type === "bind" &&
        mount.Source === source && mount.Destination === destination && mount.Mode === mode &&
        mount.RW === writable && mount.Propagation === propagation);
      if (matching.length !== 1) throw new TypeError("kind node bind is invalid");
    }
    const volumes = mounts.filter((mount) => isPlainObject(mount) && mount.Type === "volume");
    if (volumes.length !== 1) throw new TypeError("kind node volume is invalid");
    const volume = volumes[0];
    if (!objectIdPattern.test(volume.Name ?? "") || typeof volume.Source !== "string" ||
        !volume.Source.endsWith(`/${volume.Name}/_data`) || volume.Destination !== "/var" ||
        volume.Driver !== "local" || volume.Mode !== "" || volume.RW !== true || volume.Propagation !== "") {
      throw new TypeError("kind node volume is invalid");
    }
    const network = networks[expected.cluster];
    if (!isPlainObject(network) || network.NetworkID !== expected.networkId || network.Aliases !== null ||
        network.DriverOpts !== null || !ipv4Pattern.test(network.Gateway ?? "") ||
        !ipv4Pattern.test(network.IPAddress ?? "") || network.IPPrefixLen !== 24 ||
        !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(network.MacAddress ?? "")) {
      throw new TypeError("kind node network is invalid");
    }
    const identity = Object.freeze({
      gateway: network.Gateway,
      imageId: expected.imageId,
      ipAddress: network.IPAddress,
      macAddress: network.MacAddress,
      networkId: expected.networkId,
      token: expected.token,
      volumeToken: volume.Name,
    });
    if (retained !== undefined && JSON.stringify(identity) !== JSON.stringify(retained)) {
      throw new TypeError("kind node identity changed");
    }
    return identity;
  } catch {
    throw new Failure("ownership");
  }
}

function validNetworkIPAM(value) {
  return isPlainObject(value) && exactStringSet(Object.keys(value), ["Config", "Driver", "Options"]) &&
    value.Driver === "default" && exactStringMap(value.Options, {}) &&
    Array.isArray(value.Config) && value.Config.length === 1 && isPlainObject(value.Config[0]) &&
    exactStringSet(Object.keys(value.Config[0]), ["Gateway", "Subnet"]) &&
    ipv4Pattern.test(value.Config[0].Gateway ?? "") &&
    /^(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.(?:\d{1,3}\.)?\d{1,3}\/\d{1,2}$/.test(value.Config[0].Subnet ?? "");
}

function exactStringMap(value, expected) {
  return isPlainObject(value) && Object.keys(value).length === Object.keys(expected).length &&
    Object.entries(expected).every(([key, expectedValue]) => value[key] === expectedValue);
}

function exactStringSet(value, expected) {
  return Array.isArray(value) && value.length === expected.length &&
    new Set(value).size === value.length && expected.every((entry) => value.includes(entry));
}

function parsePairs(value) {
  if (typeof value !== "string" || Buffer.byteLength(value) > 16_384) throw new Failure("ownership");
  if (value === "") return [];
  if (!value.endsWith("\n")) throw new Failure("ownership");
  return value.slice(0, -1).split("\n").map((line) => {
    const parts = line.split("|");
    if (parts.length !== 2 || parts.some((part) => part.length === 0)) throw new Failure("ownership");
    return parts;
  });
}

function singleLine(value) {
  return typeof value === "string" && value.endsWith("\n") && value.indexOf("\n") === value.length - 1
    ? value.slice(0, -1)
    : "";
}

export function parseBoundedJson(source, maximumBytes) {
  if (typeof source !== "string" || source.length === 0 ||
      !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 16_777_216 ||
      Buffer.byteLength(source, "utf8") > maximumBytes || Buffer.from(source, "utf8").toString("utf8") !== source) {
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
      const output = {};
      const keys = new Set();
      if (source[index] === "}") { index += 1; return output; }
      while (true) {
        const key = parseString();
        if (keys.has(key) || keys.size >= 100_000 ||
            ["__proto__", "constructor", "prototype"].includes(key)) {
          throw new SyntaxError("duplicate or unsafe object");
        }
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

export function projectRawImageInspection(document) {
  if (!Array.isArray(document) || document.length !== 1 || !isPlainObject(document[0])) {
    throw new TypeError("image inspection is invalid");
  }
  const image = document[0];
  requireExactKeySet(image, [
    "Architecture", "Config", "Created", "GraphDriver", "Id", "Metadata", "Os", "Parent",
    "RepoDigests", "RepoTags", "RootFS", "Size",
  ], "raw image");
  requireExactKeySet(image.Config, ["Entrypoint", "Env", "ExposedPorts", "Labels", "User"], "raw image config");
  requireExactKeySet(image.GraphDriver, ["Data", "Name"], "raw image graph driver");
  requireExactKeySet(image.Metadata, ["LastTagTime"], "raw image metadata");
  if (typeof image.Created !== "string" || image.Created.length < 20 || image.Created.length > 64 ||
      typeof image.GraphDriver.Name !== "string" || image.GraphDriver.Name.length === 0 ||
      !isPlainObject(image.GraphDriver.Data) && image.GraphDriver.Data !== null ||
      typeof image.Metadata.LastTagTime !== "string" || typeof image.Parent !== "string" ||
      !Number.isSafeInteger(image.Size) || image.Size < 1) throw new TypeError("raw image is invalid");
  return [{
    Architecture: image.Architecture,
    Config: image.Config,
    Id: image.Id,
    Os: image.Os,
    RepoDigests: image.RepoDigests,
    RepoTags: image.RepoTags,
    RootFS: image.RootFS,
  }];
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

function exactMissingDockerObject(result, token) {
  return isPlainObject(result) && result.status === 1 && result.signal === null && result.stdout === "[]\n" &&
    objectIdPattern.test(token) && (
      result.stderr === `Error: No such object: ${token}\n` ||
      result.stderr === `error: no such object: ${token}\n` ||
      result.stderr === `Error response from daemon: network ${token} not found\n`
    );
}

function exactMissingDockerVolume(result, token) {
  return isPlainObject(result) && result.status === 1 && result.signal === null && result.stdout === "[]\n" &&
    objectIdPattern.test(token) &&
    result.stderr === `Error response from daemon: get ${token}: no such volume\n`;
}

function exactMissingDockerImage(result, token) {
  return isPlainObject(result) && result.status === 1 && result.signal === null && result.stdout === "[]\n" &&
    digestPattern.test(token) && (
      result.stderr === `Error response from daemon: No such image: ${token}\n` ||
      result.stderr === `Error: No such image: ${token}\n`
    );
}

function validateDeployment(items, product) {
  const matches = items.filter((item) => item?.metadata?.name === product.name);
  if (matches.length !== 1) throw new TypeError("deployment identity is invalid");
  const item = matches[0];
  requireExactObject(item, ["apiVersion", "kind", "metadata", "spec", "status"], "deployment");
  requireExactObject(item.metadata, ["generation", "name", "namespace"], "deployment metadata");
  requireExactObject(item.spec, ["replicas", "selector"], "deployment spec");
  requireExactObject(item.spec.selector, ["matchLabels"], "deployment selector");
  requireExactObject(item.spec.selector.matchLabels, ["app.kubernetes.io/name"], "deployment labels");
  requireExactObject(item.status, [
    "availableReplicas", "conditions", "observedGeneration", "readyReplicas", "replicas",
    "unavailableReplicas", "updatedReplicas",
  ], "deployment status");
  if (item.apiVersion !== "apps/v1" || item.kind !== "Deployment" || item.metadata.name !== product.name ||
      item.metadata.namespace !== "zasp-local" || !Number.isSafeInteger(item.metadata.generation) ||
      item.metadata.generation < 1 || item.spec.replicas !== 1 ||
      item.spec.selector.matchLabels["app.kubernetes.io/name"] !== product.name ||
      item.status.observedGeneration !== item.metadata.generation || item.status.replicas !== 1 ||
      item.status.updatedReplicas !== 1 || item.status.readyReplicas !== 1 ||
      item.status.availableReplicas !== 1 || item.status.unavailableReplicas !== 0 ||
      !exactConditions(item.status.conditions, "Available")) throw new TypeError("deployment is not ready");
}

function projectDeployment(item) {
  return {
    apiVersion: item?.apiVersion,
    kind: item?.kind,
    metadata: {
      generation: item?.metadata?.generation,
      name: item?.metadata?.name,
      namespace: item?.metadata?.namespace,
    },
    spec: {
      replicas: item?.spec?.replicas,
      selector: { matchLabels: {
        "app.kubernetes.io/name": item?.spec?.selector?.matchLabels?.["app.kubernetes.io/name"],
      } },
    },
    status: {
      availableReplicas: item?.status?.availableReplicas ?? 0,
      conditions: Array.isArray(item?.status?.conditions) ? item.status.conditions
        .filter(({ type }) => type === "Available").map(({ status, type }) => ({ status, type })) : undefined,
      observedGeneration: item?.status?.observedGeneration,
      readyReplicas: item?.status?.readyReplicas ?? 0,
      replicas: item?.status?.replicas ?? 0,
      unavailableReplicas: item?.status?.unavailableReplicas ?? 0,
      updatedReplicas: item?.status?.updatedReplicas ?? 0,
    },
  };
}

function projectPod(item) {
  const container = Array.isArray(item?.spec?.containers) && item.spec.containers.length === 1
    ? item.spec.containers[0]
    : undefined;
  const status = Array.isArray(item?.status?.containerStatuses) && item.status.containerStatuses.length === 1
    ? item.status.containerStatuses[0]
    : undefined;
  return {
    apiVersion: item?.apiVersion,
    kind: item?.kind,
    metadata: {
      labels: {
        "app.kubernetes.io/name": item?.metadata?.labels?.["app.kubernetes.io/name"],
        "app.kubernetes.io/part-of": item?.metadata?.labels?.["app.kubernetes.io/part-of"],
        "pod-template-hash": item?.metadata?.labels?.["pod-template-hash"],
        "zasp.dev/environment": item?.metadata?.labels?.["zasp.dev/environment"],
      },
      name: item?.metadata?.name,
      namespace: item?.metadata?.namespace,
      uid: item?.metadata?.uid,
    },
    spec: {
      automountServiceAccountToken: item?.spec?.automountServiceAccountToken,
      containers: container === undefined ? [] : [projectContainer(container)],
      dnsPolicy: item?.spec?.dnsPolicy,
      enableServiceLinks: item?.spec?.enableServiceLinks,
      hostIPC: item?.spec?.hostIPC ?? false,
      hostNetwork: item?.spec?.hostNetwork ?? false,
      hostPID: item?.spec?.hostPID ?? false,
      nodeName: item?.spec?.nodeName,
      restartPolicy: item?.spec?.restartPolicy,
      securityContext: item?.spec?.securityContext,
      volumes: item?.spec?.volumes ?? [],
    },
    status: {
      conditions: Array.isArray(item?.status?.conditions) ? item.status.conditions
        .filter(({ type }) => type === "Ready").map(({ status: value, type }) => ({ status: value, type })) : undefined,
      containerStatuses: status === undefined ? [] : [{
        containerID: status.containerID,
        image: status.image,
        imageID: status.imageID,
        name: status.name,
        ready: status.ready,
        restartCount: status.restartCount,
        started: status.started,
        state: status.state?.running === undefined ? status.state : {
          running: { startedAt: status.state.running.startedAt },
        },
      }],
      phase: item?.status?.phase,
    },
  };
}

function projectContainer(value) {
  return {
    image: value?.image,
    imagePullPolicy: value?.imagePullPolicy,
    livenessProbe: value?.livenessProbe,
    name: value?.name,
    ports: value?.ports,
    readinessProbe: value?.readinessProbe,
    resources: value?.resources,
    securityContext: value?.securityContext,
    startupProbe: value?.startupProbe,
  };
}

function projectService(item) {
  return {
    apiVersion: item?.apiVersion,
    kind: item?.kind,
    metadata: { name: item?.metadata?.name, namespace: item?.metadata?.namespace },
    spec: {
      clusterIP: item?.spec?.clusterIP,
      clusterIPs: item?.spec?.clusterIPs,
      externalIPs: item?.spec?.externalIPs ?? [],
      ipFamilies: item?.spec?.ipFamilies,
      ipFamilyPolicy: item?.spec?.ipFamilyPolicy,
      ports: item?.spec?.ports,
      selector: item?.spec?.selector,
      sessionAffinity: item?.spec?.sessionAffinity,
      type: item?.spec?.type,
    },
    status: { loadBalancer: item?.status?.loadBalancer ?? {} },
  };
}

function validatePod(items, product, nodeName) {
  const matches = items.filter((item) => item?.metadata?.labels?.["app.kubernetes.io/name"] === product.name);
  if (matches.length !== 1) throw new TypeError("pod identity is invalid");
  const item = matches[0];
  requireExactObject(item, ["apiVersion", "kind", "metadata", "spec", "status"], "pod");
  requireExactObject(item.metadata, ["labels", "name", "namespace", "uid"], "pod metadata");
  requireExactObject(item.metadata.labels, [
    "app.kubernetes.io/name", "app.kubernetes.io/part-of", "pod-template-hash", "zasp.dev/environment",
  ], "pod labels");
  requireExactObject(item.spec, [
    "automountServiceAccountToken", "containers", "dnsPolicy", "enableServiceLinks", "hostIPC",
    "hostNetwork", "hostPID", "nodeName", "restartPolicy", "securityContext", "volumes",
  ], "pod spec");
  requireExactObject(item.status, ["conditions", "containerStatuses", "phase"], "pod status");
  const podName = new RegExp(`^${product.name}-([a-z0-9]{10})-[a-z0-9]{5}$`).exec(item.metadata.name ?? "");
  const deployment = buildProductResources().find((resource) =>
    resource.kind === "Deployment" && resource.metadata.name === product.name);
  if (item.apiVersion !== "v1" || item.kind !== "Pod" || item.metadata.namespace !== "zasp-local" ||
      podName === null ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(item.metadata.uid) ||
      item.metadata.labels["app.kubernetes.io/name"] !== product.name ||
      item.metadata.labels["app.kubernetes.io/part-of"] !== "zasp" ||
      item.metadata.labels["pod-template-hash"] !== podName[1] ||
      item.metadata.labels["zasp.dev/environment"] !== "local" ||
      item.spec.automountServiceAccountToken !== false || item.spec.nodeName !== nodeName ||
      !Array.isArray(item.spec.containers) || item.spec.containers.length !== 1 ||
      !exactData(item.spec.containers[0], deployment.spec.template.spec.containers[0]) ||
      item.spec.dnsPolicy !== "ClusterFirst" || item.spec.enableServiceLinks !== false ||
      item.spec.hostIPC !== false || item.spec.hostNetwork !== false || item.spec.hostPID !== false ||
      item.spec.restartPolicy !== "Always" ||
      !exactData(item.spec.securityContext, deployment.spec.template.spec.securityContext) ||
      !exactArray(item.spec.volumes, []) ||
      item.status.phase !== "Running" || !exactConditions(item.status.conditions, "Ready") ||
      !Array.isArray(item.status.containerStatuses) || item.status.containerStatuses.length !== 1) {
    throw new TypeError("pod is not ready");
  }
  const status = item.status.containerStatuses[0];
  requireExactObject(status, [
    "containerID", "image", "imageID", "name", "ready", "restartCount", "started", "state",
  ], "container status");
  requireExactObject(status.state, ["running"], "container state");
  requireExactObject(status.state.running, ["startedAt"], "running state");
  if (status.name !== product.name || status.image !== product.image || status.ready !== true ||
      status.started !== true || status.restartCount !== 0 ||
      !/^containerd:\/\/[0-9a-f]{64}$/.test(status.containerID) ||
      !new RegExp(`^docker-pullable://${escapeRegExp(product.image)}@sha256:[0-9a-f]{64}$`).test(status.imageID) ||
      !canonicalSecond(status.state.running.startedAt)) throw new TypeError("container is not ready");
}

function validateService(items, product) {
  const matches = items.filter((item) => item?.metadata?.name === product.name);
  if (matches.length !== 1) throw new TypeError("service identity is invalid");
  const item = matches[0];
  requireExactObject(item, ["apiVersion", "kind", "metadata", "spec", "status"], "service");
  requireExactObject(item.metadata, ["name", "namespace"], "service metadata");
  requireExactObject(item.spec, [
    "clusterIP", "clusterIPs", "externalIPs", "ipFamilies", "ipFamilyPolicy", "ports",
    "selector", "sessionAffinity", "type",
  ], "service spec");
  requireExactObject(item.status, ["loadBalancer"], "service status");
  requireExactObject(item.status.loadBalancer, [], "load balancer status");
  requireExactObject(item.spec.selector, ["app.kubernetes.io/name"], "service selector");
  const ip = item.spec.clusterIP;
  if (item.apiVersion !== "v1" || item.kind !== "Service" || item.metadata.name !== product.name ||
      item.metadata.namespace !== "zasp-local" || !ipv4Pattern.test(ip ?? "") || !ip.startsWith("10.") ||
      !exactArray(item.spec.clusterIPs, [ip]) || !exactArray(item.spec.externalIPs, []) ||
      !exactArray(item.spec.ipFamilies, ["IPv4"]) || item.spec.ipFamilyPolicy !== "SingleStack" ||
      item.spec.type !== "ClusterIP" || item.spec.sessionAffinity !== "None" ||
      item.spec.selector["app.kubernetes.io/name"] !== product.name ||
      !Array.isArray(item.spec.ports) || item.spec.ports.length !== 1 ||
      !exactObject(item.spec.ports[0], { name: "health", port: 8081, protocol: "TCP", targetPort: "health" })) {
    throw new TypeError("service is not internal");
  }
}

function exactConditions(value, type) {
  return Array.isArray(value) && value.length === 1 && isPlainObject(value[0]) &&
    exactObject(value[0], { status: "True", type });
}

function canonicalSecond(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) &&
    new Date(value).toISOString() === value.replace("Z", ".000Z");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function validateProofResult(value) {
  if (!isPlainObject(value) || value.pods !== 4 || value.ready !== 4 || value.services !== 4 ||
      value.internal !== true || ("cleanup" in value && value.cleanup !== true)) {
    throw new Failure("readiness");
  }
  return value;
}

function validateLifecycle(runtime) {
  if (runtime === null || typeof runtime !== "object") throw new TypeError("runtime is invalid");
  for (const method of [
    "initialize", "preflight", "buildImages", "createNetwork", "createCluster", "loadImages",
    "applyManifests", "verifyReadiness", "joinMutations", "cleanup", "auditAbsence",
  ]) if (typeof runtime[method] !== "function") throw new TypeError(`runtime ${method} is invalid`);
}

function validateOrchestrationOptions(value) {
  requireExactObject(value, [
    "cleanupTimeoutMilliseconds", "mainTimeoutMilliseconds", "settlementTimeoutMilliseconds",
  ], "orchestration options");
  for (const name of Object.keys(value)) {
    if (!Number.isSafeInteger(value[name]) || value[name] < 1 || value[name] > 900_000) {
      throw new TypeError(`${name} is invalid`);
    }
  }
  return value;
}

async function runPhase(timeoutMilliseconds, settlementMilliseconds, operation) {
  const controller = new AbortController();
  let active = true;
  let timedOut = false;
  const phase = Object.freeze({
    assertActive(category = "deadline") {
      if (!active || controller.signal.aborted) throw new Failure(category);
    },
    signal: controller.signal,
  });
  const pending = Promise.resolve().then(() => operation(phase));
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
      reject(new Failure("deadline"));
    }, timeoutMilliseconds);
  });
  try {
    return await Promise.race([pending, deadline]);
  } catch (error) {
    if (timedOut) await settleWithin(pending, settlementMilliseconds);
    throw error;
  } finally {
    clearTimeout(timer);
    active = false;
    controller.abort();
  }
}

async function settleWithin(pending, timeoutMilliseconds) {
  let timer;
  try {
    await Promise.race([
      pending.catch(() => {}),
      new Promise((resolve) => { timer = setTimeout(resolve, timeoutMilliseconds); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function normalizeFailure(error, category = "operation") {
  return error instanceof Failure ? error : new Failure(category);
}

function validateMarker(value) {
  if (typeof value !== "string" || !markerPattern.test(value)) throw new TypeError("marker is invalid");
}

function validateAbsolutePath(value, label) {
  if (!safeAbsolutePath(value)) throw new TypeError(`${label} is invalid`);
}

function safeAbsolutePath(value) {
  return typeof value === "string" && value.length > 1 && value.length <= 4096 &&
    isAbsolute(value) && normalize(value) === value && safePathCharacters(value);
}

function safePathCharacters(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return false;
  }
  return true;
}

function requireExactObject(value, keys, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} is invalid`);
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw new TypeError(`${label} is invalid`);
  }
}

function requireExactKeySet(value, keys, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} is invalid`);
  const actual = Object.keys(value);
  if (actual.length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) {
    throw new TypeError(`${label} is invalid`);
  }
}

function exactObject(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function exactData(value, expected) {
  if (Array.isArray(expected)) {
    return Array.isArray(value) && value.length === expected.length &&
      expected.every((item, index) => exactData(value[index], item));
  }
  if (isPlainObject(expected)) {
    return isPlainObject(value) && Object.keys(value).length === Object.keys(expected).length &&
      Object.keys(expected).every((key) => Object.hasOwn(value, key) && exactData(value[key], expected[key]));
  }
  return value === expected && typeof value === typeof expected;
}

function exactArray(value, expected) {
  return Array.isArray(value) && value.length === expected.length &&
    value.every((item, index) => item === expected[index]);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function isEnvironmentObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) return false;
  return keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && "value" in descriptor &&
      (descriptor.value === undefined || typeof descriptor.value === "string");
  });
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runMain();
}
