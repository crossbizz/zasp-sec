import { randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, realpath, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join } from "node:path";
import { spawnSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";

import {
  buildCollectorConfig,
  readStableArtifact,
  validateOwnedDirectory,
} from "./artifact.mjs";
import {
  FIXTURE,
  buildSyntheticOtlpTrace,
  normalizeOtlpTrace,
  parseStrictOtlpJson,
} from "./normalizer.mjs";

export const COLLECTOR_IMAGE = "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5";
export const SUCCESS_LINE = "OTLP ingest proof passed: traces=1 spans=1 identity=true cleanup=true.";

const proofLabel = "zasp.dev/proof=m0-13";
const namePrefix = "zasp-m0-13-";
const markerPattern = /^[0-9a-f]{16}$/;
const containerIdPattern = /^[0-9a-f]{64}$/;
const imageIdPattern = /^sha256:[0-9a-f]{64}$/;
const hostPortPattern = /^(?:[1-9][0-9]{0,4})$/;
const maximumCommandBytes = 65_536;

export function buildDockerEnvironment(pathValue, dockerConfig) {
  if (typeof pathValue !== "string" || pathValue.length === 0) {
    throw new TypeError("PATH is invalid");
  }
  if (typeof dockerConfig !== "string" || !isAbsolute(dockerConfig)) {
    throw new TypeError("DOCKER_CONFIG is invalid");
  }
  return { PATH: pathValue, DOCKER_CONFIG: dockerConfig };
}

export function buildDockerCreateArguments(expected) {
  validateExpected(expected, false);
  return [
    "create", "--name", expected.name,
    "--publish", "127.0.0.1::4318",
    "--network", "bridge",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "128",
    "--memory", "128m",
    "--cpus", "0.5",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
    "--user", expected.user,
    "--label", proofLabel,
    "--label", `zasp.dev/run=${expected.marker}`,
    "--mount", `type=bind,src=${expected.configPath},dst=/proof/config,readonly`,
    "--mount", `type=bind,src=${expected.outputPath},dst=/proof/output`,
    COLLECTOR_IMAGE,
    "--config=/proof/config/config.yaml",
  ];
}

export function classifyCreateResult(result) {
  if (!isPlainObject(result) || result.thrown === true || result.signal !== null) return "ambiguous";
  if (result.status !== 0) return "definitive";
  return exactContainerId(result.stdout) !== undefined && result.stderr === "" ? "applied" : "ambiguous";
}

export function isExactMissingImageResult(result, reference) {
  return isPlainObject(result) && typeof reference === "string" && reference === COLLECTOR_IMAGE &&
    result.status === 1 && result.signal === null &&
    (result.stdout === "" || result.stdout === "\n") &&
    result.stderr === `Error response from daemon: No such image: ${reference}\n`;
}

export function validateContainerDocument(document, expected) {
  return validateContainerState(document, expected, true);
}

export function validateCreatedContainerDocument(document, expected) {
  return validateContainerState(document, expected, false);
}

export function validateCleanupContainerDocument(document, expected) {
  expectPlainObject(document?.State, "container state");
  if (typeof document.State.Running !== "boolean") throw new TypeError("container state is invalid");
  const actualPort = document?.NetworkSettings?.Ports?.["4318/tcp"];
  const wantedPort = [{ HostIp: "127.0.0.1", HostPort: expected.hostPort }];
  if (document.State.Running ? !isDeepStrictEqual(actualPort, wantedPort) : actualPort !== null) {
    throw new TypeError("cleanup network state is invalid");
  }
  return validateContainerState({
    ...document,
    State: { ...document.State, Running: true },
    NetworkSettings: {
      ...document.NetworkSettings,
      Ports: { ...document.NetworkSettings.Ports, "4318/tcp": wantedPort },
    },
  }, expected, true);
}

function validateContainerState(document, expected, running) {
  validateExpected(expected, true, running);
  expectPlainObject(document, "container");
  if (
    document.Id !== expected.id || document.Name !== `/${expected.name}` ||
    document.Image !== expected.imageId
  ) throw new TypeError("container identity is invalid");

  const labels = {
    ...expected.imageLabels,
    "zasp.dev/proof": "m0-13",
    "zasp.dev/run": expected.marker,
  };
  const config = document.Config;
  expectPlainObject(config, "container configuration");
  expectExact({
    Image: config.Image,
    Labels: config.Labels,
    Env: config.Env,
    Entrypoint: config.Entrypoint,
    Cmd: config.Cmd,
    User: config.User,
    ExposedPorts: config.ExposedPorts,
  }, {
    Image: COLLECTOR_IMAGE,
    Labels: labels,
    Env: expected.imageEnvironment,
    Entrypoint: expected.imageEntrypoint,
    Cmd: ["--config=/proof/config/config.yaml"],
    User: expected.user,
    ExposedPorts: expected.imageExposedPorts,
  }, "container configuration");

  const host = document.HostConfig;
  expectPlainObject(host, "host configuration");
  expectExact({
    NetworkMode: host.NetworkMode,
    ReadonlyRootfs: host.ReadonlyRootfs,
    CapAdd: host.CapAdd,
    CapDrop: host.CapDrop,
    SecurityOpt: host.SecurityOpt,
    PidsLimit: host.PidsLimit,
    Memory: host.Memory,
    NanoCpus: host.NanoCpus,
    PortBindings: host.PortBindings,
    Binds: host.Binds,
    Mounts: host.Mounts,
    Tmpfs: host.Tmpfs,
    RestartPolicy: host.RestartPolicy,
    Privileged: host.Privileged,
    Devices: host.Devices,
    DeviceRequests: host.DeviceRequests,
    PidMode: host.PidMode,
    IpcMode: host.IpcMode,
    CgroupnsMode: host.CgroupnsMode,
    UsernsMode: host.UsernsMode,
  }, {
    NetworkMode: "bridge",
    ReadonlyRootfs: true,
    CapAdd: null,
    CapDrop: ["ALL"],
    SecurityOpt: ["no-new-privileges"],
    PidsLimit: 128,
    Memory: 134_217_728,
    NanoCpus: 500_000_000,
    PortBindings: { "4318/tcp": [{ HostIp: "127.0.0.1", HostPort: running ? expected.hostPort : "" }] },
    Binds: null,
    Mounts: [
      { Type: "bind", Source: expected.configPath, Target: "/proof/config", ReadOnly: true, BindOptions: { Propagation: "rprivate" } },
      { Type: "bind", Source: expected.outputPath, Target: "/proof/output", ReadOnly: false, BindOptions: { Propagation: "rprivate" } },
    ],
    Tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=16777216" },
    RestartPolicy: { Name: "no", MaximumRetryCount: 0 },
    Privileged: false,
    Devices: [],
    DeviceRequests: null,
    PidMode: "",
    IpcMode: "private",
    CgroupnsMode: "private",
    UsernsMode: "",
  }, "host configuration");

  expectExact(document.Mounts, [
    { Type: "bind", Source: expected.configPath, Destination: "/proof/config", Mode: "ro", RW: false, Propagation: "rprivate" },
    { Type: "bind", Source: expected.outputPath, Destination: "/proof/output", Mode: "rw", RW: true, Propagation: "rprivate" },
  ], "runtime mounts");
  expectPlainObject(document.State, "container state");
  expectExact({ Running: document.State.Running }, { Running: running }, "container state");
  expectPlainObject(document.NetworkSettings, "network settings");
  expectExact({ Ports: document.NetworkSettings.Ports }, {
    Ports: {
      "4317/tcp": null,
      "4318/tcp": running ? [{ HostIp: "127.0.0.1", HostPort: expected.hostPort }] : null,
    },
  }, "network settings");
  return true;
}

export async function runPhase(operation, timeoutMs, settlementMs = 1_000) {
  if (typeof operation !== "function" || !positiveInteger(timeoutMs) || !positiveInteger(settlementMs)) {
    throw new TypeError("phase inputs are invalid");
  }
  const controller = new AbortController();
  let timer;
  const operationPromise = Promise.resolve().then(() => operation(controller.signal));
  const deadlinePromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(Object.assign(new Error("phase deadline exceeded"), { category: "operation" }));
    }, timeoutMs);
  });
  try {
    return await Promise.race([operationPromise, deadlinePromise]);
  } catch (error) {
    if (!controller.signal.aborted) throw error;
    await Promise.race([
      operationPromise.catch(() => undefined),
      new Promise((resolve) => setTimeout(resolve, settlementMs)),
    ]);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export async function orchestrate(runtime, options = {}) {
  const mainTimeoutMs = options.mainTimeoutMs ?? 90_000;
  const cleanupTimeoutMs = options.cleanupTimeoutMs ?? 30_000;
  let mainError;
  let cleanupError;
  let evidence;
  try {
    evidence = await runPhase(async (signal) => {
      await runtime.initialize(signal);
      await runtime.requireInitialAbsence(signal);
      await runtime.resolveImage(signal);
      await runtime.create(signal);
      await runtime.verifyOwned(signal);
      const endpoint = await runtime.endpoint(signal);
      await runtime.waitReady(signal, endpoint);
      await runtime.sendTrace(signal, endpoint);
      const value = await runtime.readEvidence(signal);
      if (!isPlainObject(value) || value.identity !== true) {
        throw Object.assign(new Error("normalized evidence is invalid"), { category: "normalization" });
      }
      return value;
    }, mainTimeoutMs, Math.min(cleanupTimeoutMs, 1_000));
  } catch (error) {
    mainError = error;
  }

  try {
    await runPhase(async (signal) => {
      let firstError;
      if (runtime.hasCandidate()) {
        try {
          await runtime.cleanup(signal);
        } catch (error) {
          firstError = error;
        }
      }
      try {
        await runtime.requireFinalAbsence(signal);
      } catch (error) {
        if (firstError === undefined) firstError = error;
      }
      if (firstError !== undefined) throw firstError;
    }, cleanupTimeoutMs, 1_000);
  } catch (error) {
    cleanupError = error;
  }

  if (cleanupError !== undefined) return { code: 1, line: failureLine("cleanup") };
  if (mainError !== undefined) return { code: 1, line: failureLine(categoryOf(mainError)) };
  if (evidence?.identity !== true) return { code: 1, line: failureLine("normalization") };
  return { code: 0, line: SUCCESS_LINE };
}

export async function runMain(options = {}) {
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const setExitCode = options.setExitCode ?? ((value) => { process.exitCode = value; });
  let result = { code: 1, line: failureLine("operation") };
  try {
    const runtime = options.runtime ?? (options.runtimeFactory ?? (() => new DockerCollectorRuntime()))();
    result = await orchestrate(runtime, {
      mainTimeoutMs: options.mainTimeoutMs,
      cleanupTimeoutMs: options.cleanupTimeoutMs,
    });
  } catch {
    result = { code: 1, line: failureLine("operation") };
  }
  try {
    const stream = result.code === 0 ? stdout : stderr;
    stream.write(`${result.line}\n`);
  } catch {
    result = { code: 1, line: failureLine("operation") };
  }
  try {
    setExitCode(result.code);
  } catch {
    return 1;
  }
  return result.code;
}

export class DockerCollectorRuntime {
  constructor(options = {}) {
    this.path = options.path ?? process.env.PATH;
    this.parent = options.parent ?? tmpdir();
    this.uid = options.uid ?? process.getuid?.();
    this.gid = options.gid ?? process.getgid?.();
    this.marker = options.marker ?? randomBytes(8).toString("hex");
    this.spawn = options.spawn ?? spawnSync;
    this.io = options.io ?? { chmod, lstat, mkdir, realpath, rm, writeFile };
    this.httpRequest = options.httpRequest ?? request;
    this.tcpConnect = options.tcpConnect ?? connect;
    if (
      typeof this.path !== "string" || this.path.length === 0 ||
      typeof this.parent !== "string" || !isAbsolute(this.parent) ||
      !Number.isInteger(this.uid) || this.uid < 0 || !Number.isInteger(this.gid) || this.gid < 0 ||
      !markerPattern.test(this.marker)
    ) throw new TypeError("runtime configuration is invalid");
    this.name = `${namePrefix}${this.marker}`;
    this.containerId = undefined;
    this.expected = undefined;
    this.identities = {};
  }

  hasCandidate() { return this.containerId !== undefined; }

  async initialize() {
    const parentCanonical = await this.io.realpath(this.parent);
    this.parent = parentCanonical;
    for (const [key, prefix] of [
      ["config", `${namePrefix}config-`],
      ["output", `${namePrefix}output-`],
      ["docker", `${namePrefix}docker-`],
    ]) {
      const path = join(this.parent, `${prefix}${this.marker}`);
      await this.io.mkdir(path, { mode: 0o700 });
      await this.io.chmod(path, 0o700);
      this.identities[key] = await validateOwnedDirectory(path, this.parent, prefix);
    }
    await this.io.writeFile(join(this.identities.config.path, "config.yaml"), buildCollectorConfig(), {
      mode: 0o600,
      flag: "wx",
    });
    this.environment = buildDockerEnvironment(this.path, this.identities.docker.path);
  }

  async requireInitialAbsence() {
    const ids = this.#listProofContainers();
    if (ids.length !== 0) throw ownershipError();
  }

  async resolveImage() {
    let result = this.#docker(["image", "inspect", "--format", "{{json .}}", COLLECTOR_IMAGE]);
    if (result.status !== 0) {
      if (!isExactMissingImageResult(result, COLLECTOR_IMAGE)) throw providerError();
      result = this.#docker(["pull", COLLECTOR_IMAGE], 180_000);
      if (result.status !== 0) throw providerError();
      result = this.#docker(["image", "inspect", "--format", "{{json .}}", COLLECTOR_IMAGE]);
      if (result.status !== 0) throw providerError();
    }
    const image = parseCommandJson(result.stdout);
    if (!imageIdPattern.test(image.Id)) throw providerError();
    expectPlainObject(image.Config, "image configuration");
    const imageLabels = plainClone(image.Config.Labels ?? {});
    if (Object.hasOwn(imageLabels, "zasp.dev/proof") || Object.hasOwn(imageLabels, "zasp.dev/run")) {
      throw ownershipError();
    }
    this.expected = {
      marker: this.marker,
      name: this.name,
      imageId: image.Id,
      imageEnvironment: plainArray(image.Config.Env),
      imageEntrypoint: plainArray(image.Config.Entrypoint),
      imageLabels,
      imageExposedPorts: plainClone(image.Config.ExposedPorts ?? {}),
      user: `${this.uid}:${this.gid}`,
      configPath: this.identities.config.path,
      outputPath: this.identities.output.path,
      hostPort: undefined,
    };
  }

  async create() {
    await this.#reproveDirectories();
    const result = this.#docker(buildDockerCreateArguments(this.expected));
    const classification = classifyCreateResult(result);
    if (classification === "definitive") throw definitiveError();
    const directId = exactContainerId(result.stdout);
    if (directId !== undefined) this.containerId = directId;
    if (classification === "ambiguous") {
      const ids = this.#listExactName();
      if (ids.length !== 1) throw ownershipError();
      this.containerId = ids[0];
    }
    const inspected = this.#docker(["inspect", "--format", "{{json .}}", this.containerId]);
    if (inspected.status !== 0 || inspected.stderr !== "") throw ownershipError();
    validateCreatedContainerDocument(parseCommandJson(inspected.stdout), {
      ...this.expected,
      id: this.containerId,
    });
    const started = this.#docker(["start", this.containerId]);
    if (
      started.status !== 0 || started.signal !== null ||
      started.stdout !== `${this.containerId}\n` || started.stderr !== ""
    ) throw providerError();
  }

  async verifyOwned() {
    if (!containerIdPattern.test(this.containerId ?? "")) throw ownershipError();
    const result = this.#docker(["inspect", "--format", "{{json .}}", this.containerId]);
    if (result.status !== 0) throw ownershipError();
    const document = parseCommandJson(result.stdout);
    const port = document?.NetworkSettings?.Ports?.["4318/tcp"]?.[0]?.HostPort;
    if (!hostPortPattern.test(port ?? "") || Number(port) > 65_535) throw ownershipError();
    this.expected = { ...this.expected, id: this.containerId, hostPort: port };
    validateContainerDocument(document, this.expected);
  }

  async endpoint() {
    return `http://127.0.0.1:${this.expected.hostPort}`;
  }

  async waitReady(signal) {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      if (signal.aborted) throw operationError();
      if (await this.#tcpReady(Number(this.expected.hostPort), signal)) return;
      await abortableDelay(250, signal);
    }
    throw Object.assign(new Error("readiness failed"), { category: "readiness" });
  }

  async sendTrace(signal) {
    const body = buildSyntheticOtlpTrace(FIXTURE);
    const response = await this.#post(Number(this.expected.hostPort), body, signal);
    if (response.status !== 200 || response.body.toString("utf8") !== "{}") throw providerError();
  }

  async readEvidence(signal) {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      if (signal.aborted) throw operationError();
      try {
        const bytes = await readStableArtifact(this.identities.output);
        return normalizeOtlpTrace(bytes, FIXTURE);
      } catch {
        await abortableDelay(250, signal);
      }
    }
    throw Object.assign(new Error("artifact did not stabilize"), { category: "normalization" });
  }

  async cleanup() {
    let cleanupError;
    if (this.containerId !== undefined) {
      try {
        const inspected = this.#docker(["inspect", "--format", "{{json .}}", this.containerId]);
        if (inspected.status !== 0 || inspected.stderr !== "") throw ownershipError();
        validateCleanupContainerDocument(parseCommandJson(inspected.stdout), this.expected);
        const result = this.#docker(["rm", "--force", this.containerId]);
        if (result.status !== 0 || result.stdout !== `${this.containerId}\n` || result.stderr !== "") {
          throw ownershipError();
        }
        this.containerId = undefined;
      } catch (error) {
        cleanupError = error;
      }
    }
    if (cleanupError !== undefined) throw cleanupError;
  }

  async requireFinalAbsence() {
    let firstError;
    try {
      if (this.environment !== undefined && this.#listProofContainers().length !== 0) throw ownershipError();
    } catch (error) {
      firstError = error;
    }
    for (const key of ["output", "config", "docker"]) {
      const identity = this.identities[key];
      if (identity === undefined) continue;
      try {
        const current = await validateOwnedDirectory(
          identity.path,
          identity.parent,
          basename(identity.path).slice(0, -16),
        );
        if (!sameDirectoryIdentity(identity, current)) throw ownershipError();
        await this.io.rm(identity.path, { recursive: true, force: false, maxRetries: 0 });
        delete this.identities[key];
      } catch (error) {
        if (firstError === undefined) firstError = error;
      }
    }
    if (firstError !== undefined) throw firstError;
  }

  #docker(args, timeout = 15_000) {
    try {
      const result = this.spawn("docker", args, {
        env: this.environment,
        encoding: "utf8",
        timeout,
        killSignal: "SIGKILL",
        maxBuffer: maximumCommandBytes,
      });
      return {
        status: result.status,
        signal: result.signal,
        stdout: typeof result.stdout === "string" ? result.stdout : "",
        stderr: typeof result.stderr === "string" ? result.stderr : "",
      };
    } catch {
      return { thrown: true, status: null, signal: null, stdout: "", stderr: "" };
    }
  }

  #listProofContainers() {
    const byPrefix = this.#list(["ps", "-a", "--no-trunc", "--filter", `name=^/${namePrefix}`, "--format", "{{.ID}}"]).ids;
    const byLabel = this.#list(["ps", "-a", "--no-trunc", "--filter", `label=${proofLabel}`, "--format", "{{.ID}}"]).ids;
    return [...new Set([...byPrefix, ...byLabel])];
  }

  #listExactName() {
    return this.#list(["ps", "-a", "--no-trunc", "--filter", `name=^/${this.name}$`, "--format", "{{.ID}}"]).ids;
  }

  #list(args) {
    const result = this.#docker(args);
    if (result.status !== 0 || result.stderr !== "") throw providerError();
    const lines = result.stdout.trim() === "" ? [] : result.stdout.trim().split("\n");
    if (lines.some((line) => !containerIdPattern.test(line)) || new Set(lines).size !== lines.length) {
      throw providerError();
    }
    return { ids: lines };
  }

  async #reproveDirectories() {
    for (const identity of Object.values(this.identities)) {
      const current = await validateOwnedDirectory(
        identity.path,
        identity.parent,
        basename(identity.path).slice(0, -16),
      );
      if (!sameDirectoryIdentity(identity, current)) throw ownershipError();
    }
  }

  #tcpReady(port, signal) {
    return new Promise((resolve) => {
      const socket = this.tcpConnect({ host: "127.0.0.1", port });
      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal.removeEventListener("abort", onAbort);
        socket.destroy();
        resolve(value);
      };
      const onAbort = () => finish(false);
      const timer = setTimeout(() => finish(false), 500);
      socket.once("connect", () => finish(true));
      socket.once("error", () => finish(false));
      signal.addEventListener("abort", onAbort, { once: true });
    });
  }

  #post(port, body, signal) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let bytes = 0;
      const req = this.httpRequest({
        host: "127.0.0.1",
        port,
        path: "/v1/traces",
        method: "POST",
        headers: { "content-type": "application/json", "content-length": body.byteLength },
        signal,
      }, (res) => {
        res.on("data", (chunk) => {
          bytes += chunk.byteLength;
          if (bytes > 1_024) req.destroy(new Error("response exceeds bound"));
          else chunks.push(chunk);
        });
        res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
      });
      req.setTimeout(1_000, () => req.destroy(new Error("request deadline")));
      req.on("error", reject);
      req.end(body);
    });
  }
}

function validateExpected(value, requireRuntime, requireHostPort = requireRuntime) {
  expectPlainObject(value, "expected container");
  if (
    !markerPattern.test(value.marker) || value.name !== `${namePrefix}${value.marker}` ||
    (requireRuntime && (!containerIdPattern.test(value.id) || !imageIdPattern.test(value.imageId))) ||
    !Array.isArray(value.imageEnvironment) || !Array.isArray(value.imageEntrypoint) ||
    !isPlainObject(value.imageLabels) || !isPlainObject(value.imageExposedPorts) ||
    typeof value.user !== "string" || !isAbsolute(value.configPath) || !isAbsolute(value.outputPath) ||
    (requireHostPort && (!hostPortPattern.test(value.hostPort) || Number(value.hostPort) > 65_535))
  ) throw new TypeError("expected container is invalid");
}

function expectExact(actual, expected, context) {
  if (!isDeepStrictEqual(actual, expected)) throw new TypeError(`${context} is not exact`);
}

function parseCommandJson(value) {
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value) > maximumCommandBytes) {
    throw providerError();
  }
  return parseStrictOtlpJson(Buffer.from(value.trimEnd()));
}

function exactContainerId(value) {
  if (typeof value !== "string") return undefined;
  const candidate = value.endsWith("\n") ? value.slice(0, -1) : value;
  return containerIdPattern.test(candidate) ? candidate : undefined;
}

function failureLine(category) {
  const allowed = new Set(["operation", "provider", "readiness", "normalization", "ownership", "cleanup"]);
  return `OTLP ingest proof failed: ${allowed.has(category) ? category : "operation"} rejected.`;
}

function categoryOf(error) {
  return typeof error?.category === "string" ? error.category : "operation";
}

function operationError() { return Object.assign(new Error("operation rejected"), { category: "operation" }); }
function providerError() { return Object.assign(new Error("provider rejected"), { category: "provider" }); }
function ownershipError() { return Object.assign(new Error("ownership rejected"), { category: "ownership" }); }
function definitiveError() { return Object.assign(providerError(), { definitive: true }); }

function positiveInteger(value) { return Number.isInteger(value) && value > 0; }

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function expectPlainObject(value, context) {
  if (!isPlainObject(value)) throw new TypeError(`${context} must be a plain object`);
}

function plainArray(value) {
  if (value === null || value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) throw providerError();
  return [...value];
}

function plainClone(value) {
  if (!isPlainObject(value)) throw providerError();
  return structuredClone(value);
}

function sameDirectoryIdentity(left, right) {
  return left.path === right.path && left.parent === right.parent && left.canonical === right.canonical &&
    left.dev === right.dev && left.ino === right.ino;
}

function abortableDelay(milliseconds, signal) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    signal.addEventListener("abort", () => {
      clearTimeout(timer);
      reject(operationError());
    }, { once: true });
  });
}

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  await runMain();
}
