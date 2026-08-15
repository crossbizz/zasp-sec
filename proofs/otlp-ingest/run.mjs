import { randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join } from "node:path";
import { spawn } from "node:child_process";
import { isDeepStrictEqual } from "node:util";

import {
  buildCollectorConfig,
  readStableArtifact,
  validateOwnedDirectory,
} from "./artifact.mjs";
import {
  FIXTURE,
  buildSyntheticOtlpTrace,
  normalizeCollectorOtlpTrace,
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
const containerInspectionFormat = [
  "{\"inspection\":[[{{json .Id}},{{json .Name}},{{json .Image}}]",
  ",[{{json .Config.Image}},{{json .Config.Labels}},{{json .Config.Env}},{{json .Config.Entrypoint}},{{json .Config.Cmd}},{{json .Config.User}},{{json .Config.ExposedPorts}}]",
  ",[{{json .HostConfig.NetworkMode}},{{json .HostConfig.ReadonlyRootfs}},{{json .HostConfig.CapAdd}},{{json .HostConfig.CapDrop}},{{json .HostConfig.SecurityOpt}},{{json .HostConfig.PidsLimit}},{{json .HostConfig.Memory}},{{json .HostConfig.NanoCpus}},{{json .HostConfig.PortBindings}},{{json .HostConfig.Binds}},{{json .HostConfig.Mounts}},{{json .HostConfig.Tmpfs}},{{json .HostConfig.RestartPolicy}},{{json .HostConfig.Privileged}},{{json .HostConfig.Devices}},{{json .HostConfig.DeviceRequests}},{{json .HostConfig.PidMode}},{{json .HostConfig.IpcMode}},{{json .HostConfig.CgroupnsMode}},{{json .HostConfig.UsernsMode}}]",
  ",{{json .Mounts}}",
  ",[{{json .State.Running}}]",
  ",[{{json .NetworkSettings.Ports}}]]}",
].join("");

export function buildDockerEnvironment(pathValue, dockerConfig) {
  if (typeof pathValue !== "string" || pathValue.length === 0) {
    throw new TypeError("PATH is invalid");
  }
  if (typeof dockerConfig !== "string" || !isAbsolute(dockerConfig)) {
    throw new TypeError("DOCKER_CONFIG is invalid");
  }
  return { PATH: pathValue, DOCKER_CONFIG: dockerConfig };
}

export function runBoundedProcess(command, arguments_, options, spawnImplementation = spawn) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnImplementation(command, arguments_, {
        env: options.env,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      reject(operationError());
      return;
    }
    if (
      child === null || typeof child !== "object" || typeof child.once !== "function" ||
      typeof child.kill !== "function" || typeof child.stdout?.on !== "function" ||
      typeof child.stderr?.on !== "function" || !positiveInteger(options.timeoutMs) ||
      !positiveInteger(options.outputLimit)
    ) {
      reject(operationError());
      return;
    }
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    let failed = false;
    let settled = false;
    let killed = false;
    let timer;
    const signal = options.signal;
    const stop = () => {
      if (killed) return;
      killed = true;
      child.stdout.destroy?.();
      child.stderr.destroy?.();
      try { child.kill("SIGKILL"); } catch { /* close/error is still the reap boundary */ }
    };
    const requestFailure = () => {
      if (settled) return;
      failed = true;
      stop();
    };
    const consume = (target) => (chunk) => {
      if (settled) return;
      let value;
      try { value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); }
      catch { requestFailure(); return; }
      bytes += value.byteLength;
      if (bytes > options.outputLimit) requestFailure();
      else target.push(value);
    };
    const stdoutData = consume(stdout);
    const stderrData = consume(stderr);
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.stdout.removeListener?.("data", stdoutData);
      child.stdout.removeListener?.("error", requestFailure);
      child.stderr.removeListener?.("data", stderrData);
      child.stderr.removeListener?.("error", requestFailure);
      child.removeListener?.("error", requestFailure);
      child.removeListener?.("close", close);
      signal?.removeEventListener?.("abort", requestFailure);
      callback();
    };
    const close = (status, closeSignal) => finish(() => {
      if (failed) { reject(operationError()); return; }
      resolve({
        status,
        signal: closeSignal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
    child.stdout.on("data", stdoutData);
    child.stdout.on("error", requestFailure);
    child.stderr.on("data", stderrData);
    child.stderr.on("error", requestFailure);
    child.once("error", requestFailure);
    child.once("close", close);
    signal?.addEventListener?.("abort", requestFailure, { once: true });
    timer = setTimeout(requestFailure, options.timeoutMs);
    if (signal?.aborted === true) requestFailure();
  });
}

export function validateTemporaryPrefixEntries(entries) {
  if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string")) {
    throw new TypeError("temporary prefix entries are invalid");
  }
  if (entries.some((entry) => entry.startsWith(namePrefix))) {
    throw new TypeError("stale M0-13 temporary root exists");
  }
  return true;
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

export function parseContainerInspectionResult(source) {
  const envelope = parseCommandJson(source);
  if (!isPlainObject(envelope) || !isDeepStrictEqual(Object.keys(envelope), ["inspection"])) {
    throw providerError();
  }
  const value = toPlainData(envelope.inspection);
  if (
    !Array.isArray(value) || value.length !== 6 ||
    !Array.isArray(value[0]) || value[0].length !== 3 ||
    !Array.isArray(value[1]) || value[1].length !== 7 ||
    !Array.isArray(value[2]) || value[2].length !== 20 ||
    !Array.isArray(value[3]) || !Array.isArray(value[4]) || value[4].length !== 1 ||
    !Array.isArray(value[5]) || value[5].length !== 1
  ) throw providerError();
  const [identity, config, host, mounts, state, network] = value;
  return {
    Id: identity[0], Name: identity[1], Image: identity[2],
    Config: {
      Image: config[0], Labels: config[1], Env: config[2], Entrypoint: config[3],
      Cmd: config[4], User: config[5], ExposedPorts: config[6],
    },
    HostConfig: {
      NetworkMode: host[0], ReadonlyRootfs: host[1], CapAdd: host[2], CapDrop: host[3],
      SecurityOpt: host[4], PidsLimit: host[5], Memory: host[6], NanoCpus: host[7],
      PortBindings: host[8], Binds: host[9], Mounts: host[10], Tmpfs: host[11],
      RestartPolicy: host[12], Privileged: host[13], Devices: host[14],
      DeviceRequests: host[15], PidMode: host[16], IpcMode: host[17],
      CgroupnsMode: host[18], UsernsMode: host[19],
    },
    Mounts: mounts,
    State: { Running: state[0] },
    NetworkSettings: { Ports: network[0] },
  };
}

export function validateReadinessResponse(response) {
  if (
    !isPlainObject(response) || response.status !== 405 || response.contentType !== "text/plain" ||
    !(response.body instanceof Uint8Array) ||
    Buffer.from(response.body).toString("utf8") !== "405 method not allowed, supported: [POST]"
  ) throw new TypeError("OTLP HTTP readiness response is invalid");
  return true;
}

export function validateSubmissionResponse(response) {
  if (
    !isPlainObject(response) || response.status !== 200 ||
    response.contentType !== "application/json" || !(response.body instanceof Uint8Array) ||
    Buffer.from(response.body).toString("utf8") !== '{"partialSuccess":{}}'
  ) throw new TypeError("OTLP HTTP submission response is invalid");
  return true;
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
  const wantedPorts = expectedRuntimePorts(expected.imageExposedPorts, expected.hostPort);
  if (document.State.Running ? !isDeepStrictEqual(document?.NetworkSettings?.Ports, wantedPorts) :
    !isDeepStrictEqual(document?.NetworkSettings?.Ports, {})) {
    throw new TypeError("cleanup network state is invalid");
  }
  return validateContainerState({
    ...document,
    State: { ...document.State, Running: true },
    NetworkSettings: {
      ...document.NetworkSettings,
      Ports: wantedPorts,
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
    PortBindings: { "4318/tcp": [{ HostIp: "127.0.0.1", HostPort: "" }] },
    Binds: null,
    Tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=16m" },
    RestartPolicy: { Name: "no", MaximumRetryCount: 0 },
    Privileged: false,
    Devices: [],
    DeviceRequests: null,
    PidMode: "",
    IpcMode: "private",
    CgroupnsMode: "private",
    UsernsMode: "",
  }, "host configuration");

  expectExactSet(host.Mounts, [
    { Type: "bind", Source: expected.configPath, Target: "/proof/config", ReadOnly: true },
    { Type: "bind", Source: expected.outputPath, Target: "/proof/output" },
  ], "host mounts");

  expectExactSet(document.Mounts, [
    { Type: "bind", Source: expected.configPath, Destination: "/proof/config", Mode: "", RW: false, Propagation: "rprivate" },
    { Type: "bind", Source: expected.outputPath, Destination: "/proof/output", Mode: "", RW: true, Propagation: "rprivate" },
  ], "runtime mounts");
  expectPlainObject(document.State, "container state");
  expectExact({ Running: document.State.Running }, { Running: running }, "container state");
  expectPlainObject(document.NetworkSettings, "network settings");
  expectExact({ Ports: document.NetworkSettings.Ports }, {
    Ports: running ? expectedRuntimePorts(expected.imageExposedPorts, expected.hostPort) : {},
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
      try {
        await runtime.settleMutations?.(signal);
      } catch (error) {
        firstError = error;
      }
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
    this.command = options.command ?? runBoundedProcess;
    this.spawnProcess = options.spawnProcess ?? spawn;
    this.io = options.io ?? { chmod, lstat, mkdir, readdir, realpath, rm, writeFile };
    this.httpRequest = options.httpRequest ?? request;
    this.http = options.http;
    if (
      typeof this.path !== "string" || this.path.length === 0 ||
      typeof this.parent !== "string" || !isAbsolute(this.parent) ||
      !Number.isInteger(this.uid) || this.uid < 0 || !Number.isInteger(this.gid) || this.gid < 0 ||
      !markerPattern.test(this.marker) || typeof this.command !== "function" ||
      typeof this.spawnProcess !== "function" ||
      (this.http !== undefined && typeof this.http !== "function")
    ) throw new TypeError("runtime configuration is invalid");
    this.name = `${namePrefix}${this.marker}`;
    this.containerId = undefined;
    this.expected = undefined;
    this.identities = {};
    this.candidates = {};
    this.containerMayHaveApplied = false;
    this.mutationSettlements = [];
  }

  hasCandidate() { return this.containerId !== undefined || this.containerMayHaveApplied; }

  async initialize(signal) {
    this.#assertActive(signal, "configuration");
    const parentCanonical = await this.io.realpath(this.parent);
    this.#assertActive(signal, "configuration");
    this.parent = parentCanonical;
    validateTemporaryPrefixEntries(await this.io.readdir(this.parent));
    this.#assertActive(signal, "configuration");
    for (const [key, prefix] of [
      ["config", `${namePrefix}config-`],
      ["output", `${namePrefix}output-`],
      ["docker", `${namePrefix}docker-`],
    ]) {
      const path = join(this.parent, `${prefix}${this.marker}`);
      this.candidates[key] = { path, prefix };
      await this.#filesystemMutation(() => this.io.mkdir(path, { mode: 0o700 }));
      this.#assertActive(signal, "configuration");
      await this.#filesystemMutation(() => this.io.chmod(path, 0o700));
      this.#assertActive(signal, "configuration");
      this.identities[key] = await validateOwnedDirectory(path, this.parent, prefix);
      this.#assertActive(signal, "configuration");
    }
    await this.#filesystemMutation(() => this.io.writeFile(
      join(this.identities.config.path, "config.yaml"), buildCollectorConfig(), {
      mode: 0o600,
      flag: "wx",
    }));
    this.#assertActive(signal, "configuration");
    this.environment = buildDockerEnvironment(this.path, this.identities.docker.path);
  }

  async requireInitialAbsence(signal) {
    this.#assertActive(signal, "ownership");
    const ids = await this.#listProofContainers(signal);
    if (ids.length !== 0) throw ownershipError();
  }

  async resolveImage(signal) {
    this.#assertActive(signal, "provider");
    let result = await this.#docker(["image", "inspect", "--format", "{{json .}}", COLLECTOR_IMAGE], 15_000, signal);
    if (result.status !== 0) {
      if (!isExactMissingImageResult(result, COLLECTOR_IMAGE)) throw providerError();
      result = await this.#dockerMutation(["pull", COLLECTOR_IMAGE], 180_000, signal);
      this.#assertActive(signal, "provider");
      if (result.status !== 0) throw providerError();
      result = await this.#docker(["image", "inspect", "--format", "{{json .}}", COLLECTOR_IMAGE], 15_000, signal);
      if (result.status !== 0) throw providerError();
    }
    this.#assertActive(signal, "provider");
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

  async create(signal) {
    this.#assertActive(signal, "ownership");
    await this.#reproveDirectories(signal);
    this.containerMayHaveApplied = true;
    const result = await this.#dockerMutation(buildDockerCreateArguments(this.expected), 15_000, signal);
    const classification = classifyCreateResult(result);
    if (classification === "definitive") {
      this.containerMayHaveApplied = false;
      throw definitiveError();
    }
    const directId = exactContainerId(result.stdout);
    if (directId !== undefined) this.containerId = directId;
    this.#assertActive(signal, "ownership");
    if (classification === "ambiguous") {
      const ids = await this.#listExactName(signal);
      if (ids.length !== 1) throw ownershipError();
      this.containerId = ids[0];
    }
    const inspected = await this.#docker(
      ["inspect", "--format", containerInspectionFormat, this.containerId], 15_000, signal,
    );
    if (inspected.status !== 0 || inspected.stderr !== "") throw ownershipError();
    validateCreatedContainerDocument(parseContainerInspectionResult(inspected.stdout), {
      ...this.expected,
      id: this.containerId,
    });
    this.#assertActive(signal, "ownership");
    const started = await this.#dockerMutation(["start", this.containerId], 15_000, signal);
    if (
      started.status !== 0 || started.signal !== null ||
      started.stdout !== `${this.containerId}\n` || started.stderr !== ""
    ) throw providerError();
  }

  async verifyOwned(signal) {
    this.#assertActive(signal, "ownership");
    if (!containerIdPattern.test(this.containerId ?? "")) throw ownershipError();
    const result = await this.#docker(
      ["inspect", "--format", containerInspectionFormat, this.containerId], 15_000, signal,
    );
    if (result.status !== 0) throw ownershipError();
    const document = parseContainerInspectionResult(result.stdout);
    const port = document?.NetworkSettings?.Ports?.["4318/tcp"]?.[0]?.HostPort;
    if (!hostPortPattern.test(port ?? "") || Number(port) > 65_535) throw ownershipError();
    this.expected = { ...this.expected, id: this.containerId, hostPort: port };
    validateContainerDocument(document, this.expected);
    this.containerMayHaveApplied = true;
  }

  async endpoint(signal) {
    this.#assertActive(signal, "operation");
    return `http://127.0.0.1:${this.expected.hostPort}`;
  }

  async waitReady(signal) {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      if (signal.aborted) throw operationError();
      try {
        validateReadinessResponse(await this.#http(
          Number(this.expected.hostPort), "GET", undefined, signal, 1_024,
        ));
        return;
      } catch {
        if (signal.aborted) throw operationError();
      }
      await abortableDelay(250, signal);
    }
    throw Object.assign(new Error("readiness failed"), { category: "readiness" });
  }

  async sendTrace(signal) {
    const body = buildSyntheticOtlpTrace(FIXTURE);
    const operation = this.#http(Number(this.expected.hostPort), "POST", body, signal, 1_024);
    this.#recordMutation(operation);
    const response = await operation;
    this.#assertActive(signal, "provider");
    try {
      validateSubmissionResponse(response);
    } catch {
      throw providerError();
    }
  }

  async readEvidence(signal) {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      if (signal.aborted) throw operationError();
      try {
        const bytes = await readStableArtifact(this.identities.output);
        return normalizeCollectorOtlpTrace(bytes, FIXTURE);
      } catch {
        await abortableDelay(250, signal);
      }
    }
    throw Object.assign(new Error("artifact did not stabilize"), { category: "normalization" });
  }

  async settleMutations(signal) {
    this.#assertActive(signal, "cleanup");
    let joined = 0;
    while (joined < this.mutationSettlements.length) {
      const pending = this.mutationSettlements.slice(joined);
      await Promise.all(pending);
      joined += pending.length;
      this.#assertActive(signal, "cleanup");
    }
  }

  async cleanup(signal) {
    this.#assertActive(signal, "cleanup");
    let cleanupError;
    if (this.containerId === undefined && this.containerMayHaveApplied) {
      try {
        const ids = await this.#listExactName(signal);
        if (ids.length > 1) throw ownershipError();
        if (ids.length === 1) this.containerId = ids[0];
        else this.containerMayHaveApplied = false;
      } catch (error) {
        cleanupError = error;
      }
    }
    if (this.containerId !== undefined) {
      try {
        const inspected = await this.#docker(
          ["inspect", "--format", containerInspectionFormat, this.containerId], 15_000, signal,
        );
        if (inspected.status !== 0 || inspected.stderr !== "") throw ownershipError();
        const document = parseContainerInspectionResult(inspected.stdout);
        if (this.expected.hostPort === undefined) {
          if (document.State.Running) {
            const port = document?.NetworkSettings?.Ports?.["4318/tcp"]?.[0]?.HostPort;
            if (!hostPortPattern.test(port ?? "") || Number(port) > 65_535) throw ownershipError();
            this.expected = { ...this.expected, id: this.containerId, hostPort: port };
            validateContainerDocument(document, this.expected);
          } else {
            validateCreatedContainerDocument(document, { ...this.expected, id: this.containerId });
          }
        } else {
          validateCleanupContainerDocument(document, this.expected);
        }
        this.#assertActive(signal, "cleanup");
        const result = await this.#dockerMutation(["rm", "--force", this.containerId], 15_000, signal);
        if (result.status !== 0 || result.stdout !== `${this.containerId}\n` || result.stderr !== "") {
          throw ownershipError();
        }
        this.containerId = undefined;
        this.containerMayHaveApplied = false;
      } catch (error) {
        if (cleanupError === undefined) cleanupError = error;
      }
    }
    if (cleanupError !== undefined) throw cleanupError;
  }

  async requireFinalAbsence(signal) {
    this.#assertActive(signal, "cleanup");
    let firstError;
    let containerAbsent = false;
    try {
      if (this.environment !== undefined && (await this.#listProofContainers(signal)).length !== 0) {
        throw ownershipError();
      }
      containerAbsent = true;
    } catch (error) {
      firstError = error;
    }
    if (containerAbsent) for (const key of ["output", "config", "docker"]) {
      try {
        let identity = this.identities[key];
        const candidate = this.candidates[key];
        if (identity === undefined && candidate !== undefined) {
          identity = await validateOwnedDirectory(candidate.path, this.parent, candidate.prefix);
          this.identities[key] = identity;
        }
        if (identity === undefined) continue;
        const current = await validateOwnedDirectory(
          identity.path,
          identity.parent,
          basename(identity.path).slice(0, -16),
        );
        if (!sameDirectoryIdentity(identity, current)) throw ownershipError();
        await this.#filesystemMutation(() => this.io.rm(
          identity.path, { recursive: true, force: false, maxRetries: 0 },
        ));
        delete this.identities[key];
        delete this.candidates[key];
      } catch (error) {
        if (firstError === undefined) firstError = error;
      }
    }
    try {
      validateTemporaryPrefixEntries(await this.io.readdir(this.parent));
    } catch (error) {
      if (firstError === undefined) firstError = error;
    }
    if (firstError !== undefined) throw firstError;
  }

  async #docker(args, timeout = 15_000, signal) {
    try {
      return await this.command("docker", args, {
        env: this.environment,
        timeoutMs: timeout,
        outputLimit: maximumCommandBytes,
        signal,
      }, this.spawnProcess);
    } catch {
      return { thrown: true, status: null, signal: null, stdout: "", stderr: "" };
    }
  }

  #dockerMutation(args, timeout, signal) {
    const operation = this.#docker(args, timeout, signal);
    this.#recordMutation(operation);
    return operation;
  }

  #filesystemMutation(factory) {
    const operation = Promise.resolve().then(factory);
    this.#recordMutation(operation);
    return operation;
  }

  #recordMutation(operation) {
    const settlement = operation.then(
      (value) => ({ state: "fulfilled", value }),
      (error) => ({ state: "rejected", error }),
    );
    this.mutationSettlements.push(settlement);
    return settlement;
  }

  async #listProofContainers(signal) {
    const byPrefix = (await this.#list(
      ["ps", "-a", "--no-trunc", "--filter", `name=^/${namePrefix}`, "--format", "{{.ID}}"], signal,
    )).ids;
    const byLabel = (await this.#list(
      ["ps", "-a", "--no-trunc", "--filter", `label=${proofLabel}`, "--format", "{{.ID}}"], signal,
    )).ids;
    return [...new Set([...byPrefix, ...byLabel])];
  }

  async #listExactName(signal) {
    return (await this.#list(
      ["ps", "-a", "--no-trunc", "--filter", `name=^/${this.name}$`, "--format", "{{.ID}}"], signal,
    )).ids;
  }

  async #list(args, signal) {
    const result = await this.#docker(args, 15_000, signal);
    if (result.status !== 0 || result.stderr !== "") throw providerError();
    const lines = result.stdout.trim() === "" ? [] : result.stdout.trim().split("\n");
    if (lines.some((line) => !containerIdPattern.test(line)) || new Set(lines).size !== lines.length) {
      throw providerError();
    }
    return { ids: lines };
  }

  async #reproveDirectories(signal) {
    for (const identity of Object.values(this.identities)) {
      this.#assertActive(signal, "ownership");
      const current = await validateOwnedDirectory(
        identity.path,
        identity.parent,
        basename(identity.path).slice(0, -16),
      );
      if (!sameDirectoryIdentity(identity, current)) throw ownershipError();
    }
  }

  #assertActive(signal, category) {
    if (signal?.aborted === true) {
      throw Object.assign(new Error(`${category} rejected`), { category });
    }
  }

  #http(port, method, body, signal, maximumBytes) {
    if (this.http !== undefined) {
      return Promise.resolve().then(() => this.http({ port, method, body, signal, maximumBytes }));
    }
    return new Promise((resolve, reject) => {
      const chunks = [];
      let bytes = 0;
      const headers = body === undefined ? undefined : {
        "content-type": "application/json",
        "content-length": body.byteLength,
      };
      const req = this.httpRequest({
        host: "127.0.0.1",
        port,
        path: "/v1/traces",
        method,
        headers,
        signal,
      }, (res) => {
        res.on("data", (chunk) => {
          bytes += chunk.byteLength;
          if (bytes > maximumBytes) req.destroy(new Error("response exceeds bound"));
          else chunks.push(chunk);
        });
        res.on("end", () => resolve({
          status: res.statusCode,
          contentType: res.headers["content-type"],
          body: Buffer.concat(chunks),
        }));
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

function expectExactSet(actual, expected, context) {
  if (!Array.isArray(actual) || actual.length !== expected.length) {
    throw new TypeError(`${context} is not exact`);
  }
  const unmatched = [...actual];
  for (const wanted of expected) {
    const index = unmatched.findIndex((candidate) => isDeepStrictEqual(candidate, wanted));
    if (index < 0) throw new TypeError(`${context} is not exact`);
    unmatched.splice(index, 1);
  }
}

function expectedRuntimePorts(exposedPorts, hostPort) {
  const result = {};
  for (const key of Object.keys(exposedPorts).sort()) result[key] = null;
  if (!Object.hasOwn(result, "4318/tcp")) throw new TypeError("OTLP HTTP port is absent");
  result["4318/tcp"] = [{ HostIp: "127.0.0.1", HostPort: hostPort }];
  return result;
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
  return toPlainData(value);
}

function toPlainData(value) {
  if (Array.isArray(value)) return value.map(toPlainData);
  if (isPlainObject(value)) {
    return Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, toPlainData(nested)]));
  }
  return value;
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
