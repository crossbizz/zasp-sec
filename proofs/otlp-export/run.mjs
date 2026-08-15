import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join } from "node:path";
import { spawn } from "node:child_process";
import { isDeepStrictEqual } from "node:util";

import { validateOwnedDirectory } from "../otlp-ingest/artifact.mjs";
import { buildSyntheticOtlpTrace, parseStrictOtlpJson } from "../otlp-ingest/normalizer.mjs";
import {
  buildDockerEnvironment,
  isExactMissingImageResult,
  parseContainerInspectionResult,
  runBoundedProcess,
} from "../otlp-ingest/run.mjs";
import {
  FIRST_FIXTURE,
  SECOND_FIXTURE,
  buildSinkCollectorConfig,
  buildSourceCollectorConfig,
  runApplicationOperation,
  validateDeliveredArtifact,
} from "./exporter.mjs";

export const COLLECTOR_IMAGE = "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5";
export const SUCCESS_LINE = "OTLP export proof passed: delivered=true bounded=true exporter_failed=true application_unblocked=true cleanup=true.";

const markerPattern = /^[0-9a-f]{16}$/;
const identifierPattern = /^[0-9a-f]{64}$/;
const proofLabel = "zasp.dev/proof=m0-22";
const namePrefix = "zasp-m0-22-";
const maximumCommandBytes = 65_536;
const maximumArtifactBytes = 65_536;
const containerInspectionFormat = [
  "{\"inspection\":[[{{json .Id}},{{json .Name}},{{json .Image}}]",
  ",[{{json .Config.Image}},{{json .Config.Labels}},{{json .Config.Env}},{{json .Config.Entrypoint}},{{json .Config.Cmd}},{{json .Config.User}},{{json .Config.ExposedPorts}}]",
  ",[{{json .HostConfig.NetworkMode}},{{json .HostConfig.ReadonlyRootfs}},{{json .HostConfig.CapAdd}},{{json .HostConfig.CapDrop}},{{json .HostConfig.SecurityOpt}},{{json .HostConfig.PidsLimit}},{{json .HostConfig.Memory}},{{json .HostConfig.NanoCpus}},{{json .HostConfig.PortBindings}},{{json .HostConfig.Binds}},{{json .HostConfig.Mounts}},{{json .HostConfig.Tmpfs}},{{json .HostConfig.RestartPolicy}},{{json .HostConfig.Privileged}},{{json .HostConfig.Devices}},{{json .HostConfig.DeviceRequests}},{{json .HostConfig.PidMode}},{{json .HostConfig.IpcMode}},{{json .HostConfig.CgroupnsMode}},{{json .HostConfig.UsernsMode}}]",
  ",{{json .Mounts}}",
  ",[{{json .State.Running}}]",
  ",[{{json .NetworkSettings.Ports}}]]}",
].join("");

export function buildNetworkCreateArguments(marker) {
  validateMarker(marker);
  return [
    "network", "create", "--internal", "--label", proofLabel,
    "--label", `zasp.dev/run=${marker}`, `zasp-m0-22-network-${marker}`,
  ];
}

export function buildContainerCreateArguments(input) {
  validateContainerInput(input);
  const name = `zasp-m0-22-${input.role}-${input.marker}`;
  const result = [
    "create", "--name", name,
    "--network", input.role === "source" ? "bridge" : input.networkName,
  ];
  if (input.role === "source") result.push("--publish", "127.0.0.1::4318");
  result.push(
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "128",
    "--memory", "128m",
    "--cpus", "0.5",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
    "--user", input.user,
    "--label", proofLabel,
    "--label", `zasp.dev/run=${input.marker}`,
    "--label", `zasp.dev/role=${input.role}`,
    "--mount", `type=bind,src=${input.configPath},dst=/proof/config,readonly`,
  );
  if (input.role === "sink") {
    result.push("--mount", `type=bind,src=${input.outputPath},dst=/proof/output`);
  }
  result.push(input.image, "--config=/proof/config/config.yaml");
  return result;
}

export function buildNetworkConnectArguments(input) {
  if (!isPlainObject(input) || !identifierPattern.test(input.networkId) ||
    !identifierPattern.test(input.containerId)) throw new TypeError("network attachment boundary is invalid");
  return ["network", "connect", input.networkId, input.containerId];
}

export function classifyMutationResult(result, kind) {
  if (!isPlainObject(result) || !["container", "network", "remove", "start", "stop"].includes(kind) ||
    result.thrown === true || result.signal !== null) return "ambiguous";
  if (result.status !== 0) return "definitive";
  if (typeof result.stderr !== "string" || result.stderr !== "") return "ambiguous";
  if (kind === "container" || kind === "network") {
    return exactIdentifier(result.stdout) === undefined ? "ambiguous" : "applied";
  }
  return "applied";
}

export function classifyAcknowledgedMutation(result, expectedOutput) {
  if (typeof expectedOutput !== "string" || !isPlainObject(result) ||
    result.thrown === true || result.signal !== null) return "ambiguous";
  if (result.status !== 0) return "definitive";
  return result.stdout === expectedOutput && result.stderr === "" ? "applied" : "ambiguous";
}

export function validateNetworkDocument(document, expected) {
  if (!isPlainObject(document) || !isPlainObject(expected) ||
    !identifierPattern.test(expected.id) || !markerPattern.test(expected.marker) ||
    document.Id !== expected.id || document.Name !== `zasp-m0-22-network-${expected.marker}` ||
    document.Internal !== true || !isDeepStrictEqual(document.Labels, {
      "zasp.dev/proof": "m0-22",
      "zasp.dev/run": expected.marker,
    }) || !isPlainObject(document.Containers) || !Array.isArray(expected.peers)) {
    throw new TypeError("proof network identity is invalid");
  }
  const actualPeers = Object.entries(document.Containers).map(([id, value]) => ({ id, name: value?.Name }));
  if (actualPeers.some(({ id, name }) => !identifierPattern.test(id) || typeof name !== "string") ||
    !exactSet(actualPeers, expected.peers)) {
    throw new TypeError("proof network peers are invalid");
  }
  return true;
}

export function parseDockerDocument(source) {
  return parseDockerJson(source);
}

export async function runPhase(operation, timeoutMs, settlementMs = 1_000) {
  if (typeof operation !== "function" || !positiveInteger(timeoutMs) || !positiveInteger(settlementMs)) {
    throw new TypeError("phase boundary is invalid");
  }
  const controller = new AbortController();
  let timer;
  const operationPromise = Promise.resolve().then(() => operation(controller.signal));
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(categoryError("operation"));
    }, timeoutMs);
  });
  try {
    return await Promise.race([operationPromise, deadline]);
  } catch (error) {
    if (controller.signal.aborted) {
      await Promise.race([
        operationPromise.catch(() => undefined),
        new Promise((resolve) => setTimeout(resolve, settlementMs)),
      ]);
    }
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
  let delivered;
  let failure;
  try {
    await runPhase(async (signal) => {
      await runtime.initialize(signal);
      await runtime.requireInitialAbsence(signal);
      await runtime.resolveImage(signal);
      await runtime.createNetwork(signal);
      await runtime.createSink(signal);
      await runtime.createSource(signal);
      delivered = await runtime.proveDelivery(signal);
      failure = await runtime.proveFailureBoundary(signal);
    }, mainTimeoutMs);
  } catch (error) {
    mainError = error;
  }
  try {
    await runPhase(async (signal) => {
      let firstError;
      for (const action of [
        () => runtime.settleMutations?.(signal),
        () => runtime.cleanup(signal),
        () => runtime.requireFinalAbsence(signal),
      ]) {
        try { await action(); }
        catch (error) { if (firstError === undefined) firstError = error; }
      }
      if (firstError !== undefined) throw firstError;
    }, cleanupTimeoutMs);
  } catch (error) {
    cleanupError = error;
  }
  if (cleanupError !== undefined) return { code: 1, line: failureLine("cleanup") };
  if (mainError !== undefined) return { code: 1, line: failureLine(mainError?.category) };
  if (delivered?.delivered !== true || failure?.bounded !== true ||
    failure?.exporterFailed !== true || failure?.applicationUnblocked !== true) {
    return { code: 1, line: failureLine("normalization") };
  }
  return { code: 0, line: SUCCESS_LINE };
}

export async function runMain(options = {}) {
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const setExitCode = options.setExitCode ?? ((value) => { process.exitCode = value; });
  let result = { code: 1, line: failureLine("operation") };
  try {
    const runtime = options.runtime ?? (options.runtimeFactory ?? (() => new DockerExportRuntime()))();
    result = await orchestrate(runtime, {
      mainTimeoutMs: options.mainTimeoutMs,
      cleanupTimeoutMs: options.cleanupTimeoutMs,
    });
  } catch {
    result = { code: 1, line: failureLine("operation") };
  }
  try {
    (result.code === 0 ? stdout : stderr).write(`${result.line}\n`);
  } catch {
    result = { code: 1, line: failureLine("operation") };
  }
  try { setExitCode(result.code); }
  catch { return 1; }
  return result.code;
}

export class DockerExportRuntime {
  constructor(options = {}) {
    this.path = options.path ?? process.env.PATH;
    this.parent = options.parent ?? tmpdir();
    this.uid = options.uid ?? process.getuid?.();
    this.gid = options.gid ?? process.getgid?.();
    this.marker = options.marker ?? randomBytes(8).toString("hex");
    this.command = options.command ?? runBoundedProcess;
    this.spawnProcess = options.spawnProcess ?? spawn;
    this.httpRequest = options.httpRequest ?? request;
    this.io = options.io ?? { chmod, lstat, mkdir, open, readdir, realpath, rm, writeFile };
    if (
      typeof this.path !== "string" || this.path.length === 0 ||
      typeof this.parent !== "string" || !isAbsolute(this.parent) ||
      !Number.isInteger(this.uid) || this.uid < 0 || !Number.isInteger(this.gid) || this.gid < 0 ||
      !markerPattern.test(this.marker) || typeof this.command !== "function" ||
      typeof this.spawnProcess !== "function"
    ) throw new TypeError("Docker export runtime configuration is invalid");
    this.networkName = `${namePrefix}network-${this.marker}`;
    this.names = {
      source: `${namePrefix}source-${this.marker}`,
      sink: `${namePrefix}sink-${this.marker}`,
    };
    this.environment = undefined;
    this.image = undefined;
    this.networkId = undefined;
    this.networkMayHaveApplied = false;
    this.containers = { source: undefined, sink: undefined };
    this.started = { source: false, sink: false };
    this.containerMayHaveApplied = { source: false, sink: false };
    this.candidates = {};
    this.identities = {};
    this.mutations = [];
  }

  async initialize(signal) {
    this.#assertActive(signal, "configuration");
    this.parent = await this.io.realpath(this.parent);
    this.#assertActive(signal, "configuration");
    validateTemporaryEntries(await this.io.readdir(this.parent));
    for (const [key, prefix] of [
      ["sourceConfig", `${namePrefix}source-config-`],
      ["sinkConfig", `${namePrefix}sink-config-`],
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
      join(this.identities.sourceConfig.path, "config.yaml"),
      buildSourceCollectorConfig(this.names.sink),
      { mode: 0o600, flag: "wx" },
    ));
    await this.#filesystemMutation(() => this.io.writeFile(
      join(this.identities.sinkConfig.path, "config.yaml"),
      buildSinkCollectorConfig(),
      { mode: 0o600, flag: "wx" },
    ));
    this.#assertActive(signal, "configuration");
    this.environment = buildDockerEnvironment(this.path, this.identities.docker.path);
  }

  async requireInitialAbsence(signal) {
    this.#assertActive(signal, "ownership");
    const [containers, networks] = await Promise.all([
      this.#listProofContainers(signal),
      this.#listProofNetworks(signal),
    ]);
    if (containers.length !== 0 || networks.length !== 0) throw ownershipError();
  }

  async resolveImage(signal) {
    this.#assertActive(signal, "provider");
    let result = await this.#docker([
      "image", "inspect", "--format", "{{json .}}", COLLECTOR_IMAGE,
    ], 15_000, signal);
    if (result.status !== 0) {
      if (!isExactMissingImageResult(result, COLLECTOR_IMAGE)) throw providerError();
      const pull = await this.#dockerMutation(["pull", COLLECTOR_IMAGE], 180_000, signal);
      if (classifyMutationResult(pull, "start") === "definitive") throw providerError();
      this.#assertActive(signal, "provider");
      result = await this.#docker([
        "image", "inspect", "--format", "{{json .}}", COLLECTOR_IMAGE,
      ], 15_000, signal);
      if (result.status !== 0) throw providerError();
    }
    const document = parseDockerJson(result.stdout);
    if (!identifierPattern.test(document?.Id?.replace(/^sha256:/, ""))) throw providerError();
    const labels = plainObject(document?.Config?.Labels ?? {});
    if (Object.hasOwn(labels, "zasp.dev/proof") || Object.hasOwn(labels, "zasp.dev/run") ||
      Object.hasOwn(labels, "zasp.dev/role")) throw ownershipError();
    this.image = Object.freeze({
      id: document.Id,
      labels,
      environment: plainStrings(document?.Config?.Env),
      entrypoint: plainStrings(document?.Config?.Entrypoint),
      exposedPorts: plainObject(document?.Config?.ExposedPorts ?? {}),
    });
  }

  async createNetwork(signal) {
    this.#assertActive(signal, "ownership");
    this.networkMayHaveApplied = true;
    const result = await this.#dockerMutation(buildNetworkCreateArguments(this.marker), 15_000, signal);
    const classification = classifyMutationResult(result, "network");
    if (classification === "definitive") {
      this.networkMayHaveApplied = false;
      throw providerError();
    }
    this.networkId = exactIdentifier(result.stdout);
    if (this.networkId === undefined) {
      const ids = await this.#listExactNetwork(signal);
      if (ids.length !== 1) throw ownershipError();
      [this.networkId] = ids;
    }
    await this.#requireNetwork(signal, []);
  }

  async createSink(signal) {
    await this.#createContainer("sink", signal);
  }

  async createSource(signal) {
    await this.#createContainer("source", signal);
  }

  async proveDelivery(signal) {
    this.#assertActive(signal, "operation");
    await this.#waitReady(signal);
    const response = await this.#postTrace(buildSyntheticOtlpTrace(FIRST_FIXTURE), signal, 2_000);
    validateSubmission(response);
    for (let attempt = 0; attempt < 120; attempt += 1) {
      this.#assertActive(signal, "normalization");
      try {
        const artifact = await this.#readArtifact();
        const normalized = validateDeliveredArtifact(artifact);
        return { delivered: normalized.identity === true };
      } catch {
        await abortableDelay(250, signal);
      }
    }
    throw categoryError("normalization");
  }

  async proveFailureBoundary(signal) {
    this.#assertActive(signal, "operation");
    await this.#requireContainer("sink", signal, true);
    const stopped = await this.#dockerMutation(["stop", "--time", "1", this.containers.sink], 5_000, signal);
    const classification = classifyAcknowledgedMutation(stopped, `${this.containers.sink}\n`);
    if (classification === "definitive") throw providerError();
    await this.#requireContainer("sink", signal, false);
    await this.#requireNetwork(signal, [{ id: this.containers.source, name: this.names.source }]);

    let revision = 0;
    const started = performance.now();
    const result = await runApplicationOperation({
      apply: () => { revision += 1; return { revision }; },
      submit: async ({ signal: submissionSignal }) => {
        const response = await this.#postTrace(buildSyntheticOtlpTrace(SECOND_FIXTURE), submissionSignal, 500);
        validateSubmission(response);
      },
      timeoutMs: 500,
    });
    const elapsed = performance.now() - started;
    this.#assertActive(signal, "operation");
    if (result.operation !== true || result.application?.revision !== 1 || revision !== 1 || elapsed > 750) {
      throw categoryError("operation");
    }
    const artifact = await this.#readArtifact();
    validateDeliveredArtifact(artifact);
    return {
      bounded: result.bounded === true,
      exporterFailed: true,
      applicationUnblocked: true,
    };
  }

  async settleMutations(signal) {
    this.#assertActive(signal, "cleanup");
    let joined = 0;
    while (joined < this.mutations.length) {
      const pending = this.mutations.slice(joined);
      await Promise.all(pending);
      joined += pending.length;
      this.#assertActive(signal, "cleanup");
    }
  }

  async cleanup(signal) {
    this.#assertActive(signal, "cleanup");
    let firstError;
    for (const role of ["source", "sink"]) {
      try { await this.#cleanupContainer(role, signal); }
      catch (error) { if (firstError === undefined) firstError = error; }
    }
    if (Object.values(this.containers).every((value) => value === undefined) &&
      Object.values(this.containerMayHaveApplied).every((value) => value === false)) {
      try { await this.#cleanupNetwork(signal); }
      catch (error) { if (firstError === undefined) firstError = error; }
    } else if (firstError === undefined) {
      firstError = ownershipError();
    }
    if (firstError !== undefined) throw firstError;
  }

  async requireFinalAbsence(signal) {
    this.#assertActive(signal, "cleanup");
    let firstError;
    let dockerAbsent = false;
    try {
      if (this.environment !== undefined) {
        const [containers, networks] = await Promise.all([
          this.#listProofContainers(signal), this.#listProofNetworks(signal),
        ]);
        if (containers.length !== 0 || networks.length !== 0) throw ownershipError();
      }
      dockerAbsent = true;
    } catch (error) {
      firstError = error;
    }
    if (dockerAbsent) {
      for (const key of ["output", "sourceConfig", "sinkConfig", "docker"]) {
        try { await this.#removeOwnedDirectory(key); }
        catch (error) { if (firstError === undefined) firstError = error; }
      }
    }
    try { validateTemporaryEntries(await this.io.readdir(this.parent)); }
    catch (error) { if (firstError === undefined) firstError = error; }
    if (firstError !== undefined) throw firstError;
  }

  async #createContainer(role, signal) {
    this.#assertActive(signal, "ownership");
    await this.#reproveDirectories(signal);
    this.containerMayHaveApplied[role] = true;
    const configKey = role === "source" ? "sourceConfig" : "sinkConfig";
    const result = await this.#dockerMutation(buildContainerCreateArguments({
      marker: this.marker,
      role,
      image: COLLECTOR_IMAGE,
      networkName: this.networkName,
      configPath: this.identities[configKey].path,
      outputPath: this.identities.output.path,
      user: `${this.uid}:${this.gid}`,
    }), 15_000, signal);
    const classification = classifyMutationResult(result, "container");
    if (classification === "definitive") {
      this.containerMayHaveApplied[role] = false;
      throw providerError();
    }
    this.containers[role] = exactIdentifier(result.stdout);
    if (this.containers[role] === undefined) {
      const ids = await this.#listExactContainer(role, signal);
      if (ids.length !== 1) throw ownershipError();
      [this.containers[role]] = ids;
    }
    await this.#requireContainer(role, signal, false);
    const priorPeers = role === "sink" ? [] : [
      { id: this.containers.sink, name: this.names.sink },
    ];
    const peers = role === "sink" ? [{ id: this.containers.sink, name: this.names.sink }] : [
      { id: this.containers.sink, name: this.names.sink },
      { id: this.containers.source, name: this.names.source },
    ];
    await this.#requireNetwork(signal, priorPeers);
    if (role === "source") {
      const connected = await this.#dockerMutation(buildNetworkConnectArguments({
        networkId: this.networkId,
        containerId: this.containers.source,
      }), 15_000, signal);
      const connectClass = classifyAcknowledgedMutation(connected, "");
      if (connectClass === "definitive") throw providerError();
      if (connectClass === "applied" && (connected.stdout !== "" || connected.stderr !== "")) {
        throw ownershipError();
      }
    }
    const started = await this.#dockerMutation(["start", this.containers[role]], 15_000, signal);
    const startClass = classifyAcknowledgedMutation(started, `${this.containers[role]}\n`);
    if (startClass === "definitive") throw providerError();
    await this.#requireContainer(role, signal, true);
    this.started[role] = true;
    await this.#requireNetwork(signal, peers);
  }

  async #requireContainer(role, signal, running) {
    const id = this.containers[role];
    if (!identifierPattern.test(id ?? "")) throw ownershipError();
    const result = await this.#docker(["inspect", "--format", containerInspectionFormat, id], 15_000, signal);
    if (result.status !== 0 || result.stderr !== "") throw ownershipError();
    const document = parseExportContainerInspection(result.stdout);
    if (role === "source" && running) {
      const port = document?.NetworkSettings?.Ports?.["4318/tcp"]?.[0]?.HostPort;
      if (!/^[1-9][0-9]{0,4}$/.test(port ?? "") || Number(port) > 65_535) throw ownershipError();
      this.sourcePort = Number(port);
    }
    validateRuntimeContainer(document, this.#expectedContainer(role), running);
  }

  async #requireNetwork(signal, peers) {
    if (!identifierPattern.test(this.networkId ?? "")) throw ownershipError();
    const result = await this.#docker([
      "network", "inspect", "--format", "{{json .}}", this.networkId,
    ], 15_000, signal);
    if (result.status !== 0 || result.stderr !== "") throw ownershipError();
    const document = parseDockerJson(result.stdout);
    validateNetworkDocument(document, { id: this.networkId, marker: this.marker, peers });
    if (
      document.Driver !== "bridge" || document.Scope !== "local" || document.Attachable !== false ||
      document.Ingress !== false || document.ConfigOnly !== false || document.EnableIPv6 !== false ||
      !isPlainObject(document.IPAM) || document.IPAM.Driver !== "default" ||
      !Array.isArray(document.IPAM.Config) || document.IPAM.Config.length !== 1
    ) throw ownershipError();
  }

  #expectedContainer(role) {
    const configKey = role === "source" ? "sourceConfig" : "sinkConfig";
    return {
      role,
      marker: this.marker,
      id: this.containers[role],
      name: this.names[role],
      image: this.image,
      networkId: this.networkId,
      networkName: role === "source" ? "bridge" : this.networkName,
      configPath: this.identities[configKey].path,
      outputPath: this.identities.output.path,
      user: `${this.uid}:${this.gid}`,
      sourcePort: this.sourcePort,
      networkAttached: this.started[role] || false,
    };
  }

  async #waitReady(signal) {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      this.#assertActive(signal, "readiness");
      try {
        const response = await this.#http("GET", undefined, signal, 1_024, 1_000);
        if (
          response.status === 405 && response.contentType === "text/plain" &&
          response.body.toString("utf8") === "405 method not allowed, supported: [POST]"
        ) return;
      } catch { /* bounded not-ready poll */ }
      await abortableDelay(250, signal);
    }
    throw categoryError("readiness");
  }

  #postTrace(body, signal, timeoutMs) {
    return this.#http("POST", body, signal, 1_024, timeoutMs);
  }

  #http(method, body, signal, maximumBytes, timeoutMs) {
    if (!Number.isInteger(this.sourcePort)) return Promise.reject(categoryError("operation"));
    return new Promise((resolve, reject) => {
      const chunks = [];
      let bytes = 0;
      const headers = body === undefined ? undefined : {
        "content-type": "application/json",
        "content-length": body.byteLength,
      };
      const req = this.httpRequest({
        host: "127.0.0.1",
        port: this.sourcePort,
        path: "/v1/traces",
        method,
        headers,
        signal,
      }, (res) => {
        res.on("data", (chunk) => {
          bytes += chunk.byteLength;
          if (bytes > maximumBytes) req.destroy(categoryError("provider"));
          else chunks.push(chunk);
        });
        res.on("end", () => resolve({
          status: res.statusCode,
          contentType: res.headers["content-type"],
          body: Buffer.concat(chunks),
        }));
      });
      req.setTimeout(timeoutMs, () => req.destroy(categoryError("operation")));
      req.on("error", reject);
      req.end(body);
    });
  }

  async #readArtifact() {
    const identity = this.identities.output;
    const current = await validateOwnedDirectory(identity.path, identity.parent, basename(identity.path).slice(0, -16));
    if (!sameDirectory(identity, current)) throw ownershipError();
    const artifactPath = join(identity.path, "export.json");
    const handle = await this.io.open(
      artifactPath,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
    let operationError;
    let result;
    try {
      const before = await handle.stat();
      if (!before.isFile() || before.isSymbolicLink() || before.size <= 0 || before.size > maximumArtifactBytes) {
        throw categoryError("normalization");
      }
      const buffer = Buffer.alloc(maximumArtifactBytes + 1);
      const read = await handle.read(buffer, 0, buffer.byteLength, 0);
      const after = await handle.stat();
      if (read.bytesRead !== before.size || before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
        throw categoryError("normalization");
      }
      const length = read.bytesRead - (buffer[read.bytesRead - 1] === 0x0a ? 1 : 0);
      result = Buffer.from(buffer.subarray(0, length));
    } catch (error) {
      operationError = error;
    }
    let closeError;
    try { await handle.close(); }
    catch (error) { closeError = error; }
    if (closeError !== undefined) throw categoryError("normalization");
    if (operationError !== undefined) throw operationError;
    return result;
  }

  async #cleanupContainer(role, signal) {
    if (this.containers[role] === undefined && this.containerMayHaveApplied[role]) {
      const ids = await this.#listExactContainer(role, signal);
      if (ids.length > 1) throw ownershipError();
      if (ids.length === 1) [this.containers[role]] = ids;
      else this.containerMayHaveApplied[role] = false;
    }
    const id = this.containers[role];
    if (id === undefined) return;
    const result = await this.#docker(["inspect", "--format", containerInspectionFormat, id], 15_000, signal);
    if (result.status !== 0 || result.stderr !== "") throw ownershipError();
    const document = parseExportContainerInspection(result.stdout);
    validateRuntimeContainer(document, this.#expectedContainer(role), document?.State?.Running === true);
    const removed = await this.#dockerMutation(["rm", "--force", id], 15_000, signal);
    const classification = classifyAcknowledgedMutation(removed, `${id}\n`);
    if (classification === "definitive") throw ownershipError();
    if (classification === "ambiguous") await this.#requireContainerAbsent(role, id, signal);
    this.containers[role] = undefined;
    this.containerMayHaveApplied[role] = false;
    this.started[role] = false;
  }

  async #cleanupNetwork(signal) {
    if (this.networkId === undefined && this.networkMayHaveApplied) {
      const ids = await this.#listExactNetwork(signal);
      if (ids.length > 1) throw ownershipError();
      if (ids.length === 1) [this.networkId] = ids;
      else this.networkMayHaveApplied = false;
    }
    if (this.networkId === undefined) return;
    await this.#requireNetwork(signal, []);
    const id = this.networkId;
    const result = await this.#dockerMutation(["network", "rm", id], 15_000, signal);
    const classification = classifyAcknowledgedMutation(result, `${id}\n`);
    if (classification === "definitive") throw ownershipError();
    if (classification === "ambiguous") await this.#requireNetworkAbsent(id, signal);
    this.networkId = undefined;
    this.networkMayHaveApplied = false;
  }

  async #requireContainerAbsent(role, id, signal) {
    const ids = await this.#listExactContainer(role, signal);
    if (ids.includes(id) || ids.length !== 0) throw ownershipError();
  }

  async #requireNetworkAbsent(id, signal) {
    const ids = await this.#listExactNetwork(signal);
    if (ids.includes(id) || ids.length !== 0) throw ownershipError();
  }

  async #removeOwnedDirectory(key) {
    let identity = this.identities[key];
    const candidate = this.candidates[key];
    if (identity === undefined && candidate !== undefined) {
      try { identity = await validateOwnedDirectory(candidate.path, this.parent, candidate.prefix); }
      catch (error) { if (error?.code === "ENOENT") return; throw error; }
    }
    if (identity === undefined) return;
    const current = await validateOwnedDirectory(identity.path, identity.parent, basename(identity.path).slice(0, -16));
    if (!sameDirectory(identity, current)) throw ownershipError();
    await this.#filesystemMutation(() => this.io.rm(identity.path, { recursive: true, force: false, maxRetries: 0 }));
    delete this.identities[key];
    delete this.candidates[key];
  }

  async #listProofContainers(signal) {
    const prefix = await this.#listIds([
      "ps", "-a", "--no-trunc", "--filter", `name=^/${namePrefix}`, "--format", "{{.ID}}",
    ], signal);
    const label = await this.#listIds([
      "ps", "-a", "--no-trunc", "--filter", `label=${proofLabel}`, "--format", "{{.ID}}",
    ], signal);
    return [...new Set([...prefix, ...label])];
  }

  async #listProofNetworks(signal) {
    const prefix = await this.#listIds([
      "network", "ls", "--no-trunc", "--filter", `name=^${namePrefix}`, "--format", "{{.ID}}",
    ], signal);
    const label = await this.#listIds([
      "network", "ls", "--no-trunc", "--filter", `label=${proofLabel}`, "--format", "{{.ID}}",
    ], signal);
    return [...new Set([...prefix, ...label])];
  }

  #listExactContainer(role, signal) {
    return this.#listIds([
      "ps", "-a", "--no-trunc", "--filter", `name=^/${this.names[role]}$`, "--format", "{{.ID}}",
    ], signal);
  }

  #listExactNetwork(signal) {
    return this.#listIds([
      "network", "ls", "--no-trunc", "--filter", `name=^${this.networkName}$`, "--format", "{{.ID}}",
    ], signal);
  }

  async #listIds(args, signal) {
    const result = await this.#docker(args, 15_000, signal);
    if (result.status !== 0 || result.stderr !== "") throw providerError();
    const ids = result.stdout.trim() === "" ? [] : result.stdout.trim().split("\n");
    if (ids.some((id) => !identifierPattern.test(id)) || new Set(ids).size !== ids.length) throw providerError();
    return ids;
  }

  async #reproveDirectories(signal) {
    for (const identity of Object.values(this.identities)) {
      this.#assertActive(signal, "ownership");
      const current = await validateOwnedDirectory(identity.path, identity.parent, basename(identity.path).slice(0, -16));
      if (!sameDirectory(identity, current)) throw ownershipError();
    }
  }

  async #docker(args, timeoutMs, signal) {
    if (!isPlainObject(this.environment) ||
      !isDeepStrictEqual(Object.keys(this.environment).sort(), ["DOCKER_CONFIG", "PATH"])) {
      return { thrown: true, status: null, signal: null, stdout: "", stderr: "" };
    }
    try {
      return await this.command("docker", args, {
        env: this.environment,
        timeoutMs,
        outputLimit: maximumCommandBytes,
        signal,
      }, this.spawnProcess);
    } catch {
      return { thrown: true, status: null, signal: null, stdout: "", stderr: "" };
    }
  }

  #dockerMutation(args, timeoutMs, signal) {
    const operation = this.#docker(args, timeoutMs, signal);
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
    this.mutations.push(settlement);
  }

  #assertActive(signal, category) {
    if (signal?.aborted === true) throw categoryError(category);
  }
}

export function validateRuntimeContainer(document, expected, running) {
  if (!isPlainObject(document) || !isPlainObject(expected) ||
    document.Id !== expected.id || document.Name !== `/${expected.name}` ||
    document.Image !== expected.image.id) throw ownershipError();
  const labels = {
    ...expected.image.labels,
    "zasp.dev/proof": "m0-22",
    "zasp.dev/run": expected.marker,
    "zasp.dev/role": expected.role,
  };
  const config = document.Config;
  if (!isPlainObject(config) || !isDeepStrictEqual({
    Image: config.Image,
    Labels: config.Labels,
    Env: config.Env ?? [],
    Entrypoint: config.Entrypoint ?? [],
    Cmd: config.Cmd,
    User: config.User,
    ExposedPorts: config.ExposedPorts ?? {},
  }, {
    Image: COLLECTOR_IMAGE,
    Labels: labels,
    Env: expected.image.environment,
    Entrypoint: expected.image.entrypoint,
    Cmd: ["--config=/proof/config/config.yaml"],
    User: expected.user,
    ExposedPorts: expected.image.exposedPorts,
  })) throw ownershipError();

  const source = expected.role === "source";
  const expectedMounts = [
    { Type: "bind", Source: expected.configPath, Target: "/proof/config", ReadOnly: true },
  ];
  if (!source) expectedMounts.push({ Type: "bind", Source: expected.outputPath, Target: "/proof/output", ReadOnly: false });
  const host = document.HostConfig;
  if (!isPlainObject(host) || !isDeepStrictEqual({
    NetworkMode: host.NetworkMode,
    ReadonlyRootfs: host.ReadonlyRootfs,
    CapAdd: host.CapAdd,
    CapDrop: host.CapDrop,
    SecurityOpt: host.SecurityOpt,
    PidsLimit: host.PidsLimit,
    Memory: host.Memory,
    NanoCpus: host.NanoCpus,
    PortBindings: host.PortBindings ?? {},
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
    NetworkMode: expected.networkName,
    ReadonlyRootfs: true,
    CapAdd: null,
    CapDrop: ["ALL"],
    SecurityOpt: ["no-new-privileges"],
    PidsLimit: 128,
    Memory: 134_217_728,
    NanoCpus: 500_000_000,
    PortBindings: source ? { "4318/tcp": [{ HostIp: "127.0.0.1", HostPort: "" }] } : {},
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
  })) throw ownershipError();
  if (!exactSet(mountProjection(host.Mounts), expectedMounts)) throw ownershipError();

  const runtimeMounts = expectedMounts.map((mount) => ({
    Type: "bind",
    Source: mount.Source,
    Destination: mount.Target,
    Mode: "",
    RW: !mount.ReadOnly,
    Propagation: "rprivate",
  }));
  if (!exactSet(runtimeMountProjection(document.Mounts), runtimeMounts)) throw ownershipError();
  if (!isPlainObject(document.State) || document.State.Running !== running) throw ownershipError();

  const ports = document?.NetworkSettings?.Ports ?? {};
  if (source && running) {
    const wanted = expectedRuntimePorts(expected.image.exposedPorts, expected.sourcePort);
    if (!isDeepStrictEqual(ports, wanted)) throw ownershipError();
  } else if (!source && running) {
    if (!isDeepStrictEqual(ports, expectedRuntimePorts(expected.image.exposedPorts, undefined))) throw ownershipError();
  } else if (!isDeepStrictEqual(ports, {})) {
    throw ownershipError();
  }
  return true;
}

function mountProjection(value) {
  if (!Array.isArray(value)) throw ownershipError();
  return value.map((mount) => ({
    Type: mount?.Type,
    Source: mount?.Source,
    Target: mount?.Target,
    ReadOnly: mount?.ReadOnly === true,
  }));
}

function runtimeMountProjection(value) {
  if (!Array.isArray(value)) throw ownershipError();
  return value.map((mount) => ({
    Type: mount?.Type,
    Source: mount?.Source,
    Destination: mount?.Destination,
    Mode: mount?.Mode,
    RW: mount?.RW,
    Propagation: mount?.Propagation,
  }));
}

function expectedRuntimePorts(exposedPorts, hostPort) {
  const result = Object.fromEntries(Object.keys(exposedPorts).sort().map((key) => [key, null]));
  if (!Object.hasOwn(result, "4318/tcp")) throw ownershipError();
  if (hostPort !== undefined) result["4318/tcp"] = [{ HostIp: "127.0.0.1", HostPort: String(hostPort) }];
  return result;
}

function validateTemporaryEntries(entries) {
  if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string")) {
    throw categoryError("configuration");
  }
  if (entries.some((entry) => entry.startsWith(namePrefix))) throw ownershipError();
  return true;
}

function validateSubmission(response) {
  if (!isPlainObject(response) || response.status !== 200 ||
    response.contentType !== "application/json" || !(response.body instanceof Uint8Array) ||
    response.body.toString("utf8") !== '{"partialSuccess":{}}') throw providerError();
  return true;
}

function parseDockerJson(source) {
  if (typeof source !== "string" || source.length === 0 || Buffer.byteLength(source) > maximumCommandBytes) {
    throw providerError();
  }
  return toPlainData(parseStrictOtlpJson(Buffer.from(source.trimEnd())));
}

function parseExportContainerInspection(source) {
  try { return parseContainerInspectionResult(source); }
  catch { throw providerError(); }
}

function plainStrings(value) {
  if (value === null || value === undefined) return [];
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) throw providerError();
  return [...value];
}

function plainObject(value) {
  if (!isPlainObject(value)) throw providerError();
  return toPlainData(value);
}

function toPlainData(value) {
  if (Array.isArray(value)) return value.map(toPlainData);
  if (isPlainObject(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, toPlainData(item)]));
  return value;
}

function sameDirectory(left, right) {
  return left.path === right.path && left.parent === right.parent && left.canonical === right.canonical &&
    left.dev === right.dev && left.ino === right.ino;
}

function abortableDelay(milliseconds, signal) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    signal.addEventListener("abort", () => {
      clearTimeout(timer);
      reject(categoryError("operation"));
    }, { once: true });
  });
}

function validateContainerInput(input) {
  if (!isPlainObject(input) || !markerPattern.test(input.marker) ||
    !["source", "sink"].includes(input.role) || input.image !== COLLECTOR_IMAGE ||
    input.networkName !== `zasp-m0-22-network-${input.marker}` ||
    typeof input.configPath !== "string" || !input.configPath.startsWith("/") ||
    typeof input.outputPath !== "string" || !input.outputPath.startsWith("/") ||
    !/^[0-9]+:[0-9]+$/.test(input.user)) {
    throw new TypeError("container creation boundary is invalid");
  }
}

function exactIdentifier(value) {
  if (typeof value !== "string") return undefined;
  const candidate = value.endsWith("\n") ? value.slice(0, -1) : value;
  return identifierPattern.test(candidate) ? candidate : undefined;
}

function exactSet(actual, expected) {
  if (!Array.isArray(actual) || !Array.isArray(expected) || actual.length !== expected.length) return false;
  const remaining = [...actual];
  for (const wanted of expected) {
    const index = remaining.findIndex((candidate) => isDeepStrictEqual(candidate, wanted));
    if (index < 0) return false;
    remaining.splice(index, 1);
  }
  return remaining.length === 0;
}

function validateMarker(value) {
  if (!markerPattern.test(value)) throw new TypeError("proof marker is invalid");
}

function failureLine(category) {
  const allowed = new Set(["operation", "provider", "readiness", "normalization", "ownership", "cleanup"]);
  return `OTLP export proof failed: ${allowed.has(category) ? category : "operation"} rejected.`;
}

function categoryError(category) { return Object.assign(new Error(`${category} rejected`), { category }); }
function providerError() { return categoryError("provider"); }
function ownershipError() { return categoryError("ownership"); }
function positiveInteger(value) { return Number.isInteger(value) && value > 0; }
function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  await runMain();
}
