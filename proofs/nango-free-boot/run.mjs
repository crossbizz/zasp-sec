import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { readdir, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  createOwnedWorkspace,
  removeOwnedWorkspace,
  reproveOwnedWorkspace,
  validateTemporaryPrefixEntries,
} from "./boundary.mjs";
import {
  PINS,
  PROOF_LABEL,
  buildRuntimeSpec,
  parseBoundedUniqueJson,
  parseReadyOutput,
  validateMarker,
} from "./manifest.mjs";

export const SUCCESS_LINE = "Nango free boot proof passed: services=2 ready=true product_network=true cleanup=true.";

const namePrefix = "zasp-m0-14a-";
const containerIdPattern = /^[0-9a-f]{64}$/;
const imageIdPattern = /^sha256:[0-9a-f]{64}$/;
const markerPattern = /^[0-9a-f]{16}$/;
const maximumCommandBytes = 65_536;
const mainTimeoutMilliseconds = 300_000;
const cleanupTimeoutMilliseconds = 60_000;
const commandTimeoutMilliseconds = 30_000;

export const IMAGE_INSPECTION_FORMAT = [
  "{\"image\":[{{json .Id}},{{json (index . \"RepoDigests\")}},{{json (index .Config \"Env\")}},",
  "{{json (index .Config \"Entrypoint\")}},{{json (index .Config \"Cmd\")}},{{json (index .Config \"User\")}},",
  "{{json (index .Config \"Labels\")}},{{json (index .Config \"ExposedPorts\")}},{{json (index .Config \"Volumes\")}},",
  "{{json .Os}},{{json .Architecture}}]}",
].join("");

export const CONTAINER_INSPECTION_FORMAT = [
  "{\"container\":[[{{json .Id}},{{json .Name}},{{json .Image}}],",
  "[{{json .Config.Image}},{{json (index .Config \"Labels\")}},{{json (index .Config \"Env\")}},{{json (index .Config \"Entrypoint\")}},{{json (index .Config \"Cmd\")}},{{json (index .Config \"User\")}},{{json (index .Config \"ExposedPorts\")}}],",
  "[{{json .HostConfig.NetworkMode}},{{json .HostConfig.ReadonlyRootfs}},{{json (index .HostConfig \"CapAdd\")}},{{json .HostConfig.CapDrop}},{{json .HostConfig.SecurityOpt}},{{json .HostConfig.PidsLimit}},{{json .HostConfig.Memory}},{{json .HostConfig.NanoCpus}},{{json .HostConfig.PortBindings}},{{json (index .HostConfig \"Binds\")}},{{json (index .HostConfig \"Mounts\")}},{{json .HostConfig.Tmpfs}},{{json .HostConfig.RestartPolicy}},{{json .HostConfig.Privileged}},{{json .HostConfig.Devices}},{{json (index .HostConfig \"DeviceRequests\")}},{{json .HostConfig.PidMode}},{{json .HostConfig.IpcMode}},{{json .HostConfig.CgroupnsMode}},{{json .HostConfig.UsernsMode}}],",
  "{{json .Mounts}},[{{json .State.Running}},{{json .State.Status}}],",
  "[{{json .NetworkSettings.Networks}},{{json .NetworkSettings.Ports}}]]}",
].join("");

export const NETWORK_INSPECTION_FORMAT = [
  "{\"network\":[{{json .Id}},{{json .Name}},{{json .Labels}},{{json .Internal}},",
  "{{json (index . \"EnableIPv4\")}},{{json .EnableIPv6}},{{json .Options}},{{json .IPAM}},{{json .Containers}}]}",
].join("");

export class Failure extends Error {
  constructor(category, options) {
    super(`${category} rejected`, options);
    this.category = category;
  }
}

export function buildDockerEnvironment(pathValue, dockerConfig) {
  if (typeof pathValue !== "string" || pathValue.length === 0 || pathValue.includes("\0")) {
    throw new TypeError("PATH is invalid");
  }
  if (typeof dockerConfig !== "string" || !isAbsolute(dockerConfig)) {
    throw new TypeError("DOCKER_CONFIG is invalid");
  }
  return { PATH: pathValue, DOCKER_CONFIG: dockerConfig };
}

export function classifyMutationResult(result) {
  if (!isPlainObject(result) || result.thrown === true || result.signal !== null) return "ambiguous";
  if (result.status !== 0) return "definitive";
  return exactId(result.stdout) !== undefined && result.stderr === "" ? "applied" : "ambiguous";
}

function classifyEmptyMutationResult(result) {
  if (!isPlainObject(result) || result.thrown === true || result.signal !== null) return "ambiguous";
  if (result.status !== 0) return "definitive";
  return result.stdout === "" && result.stderr === "" ? "applied" : "ambiguous";
}

function classifyExactMutationResult(result, expectedStdout) {
  if (!isPlainObject(result) || result.thrown === true || result.signal !== null) return "ambiguous";
  if (result.status !== 0) return "definitive";
  return result.stdout === expectedStdout && result.stderr === "" ? "applied" : "ambiguous";
}

export function classifyDatabaseReadinessResult(result) {
  if (!isPlainObject(result) || result.signal !== null || result.stdout !== "" || result.stderr !== "") return "provider";
  if (result.status === 0) return "ready";
  return result.status === 1 || result.status === 2 ? "wait" : "provider";
}

export function classifyDatabaseQueryReadinessResult(result) {
  if (!isPlainObject(result) || result.signal !== null || result.stderr !== "") return "provider";
  if (result.status === 0 && result.stdout === "1\n") return "ready";
  if (result.status === 2 && result.stdout === "") return "wait";
  return "provider";
}

export function runBounded(command, arguments_, options, spawnImplementation = spawn) {
  return new Promise((resolve, reject) => {
    if (
      typeof command !== "string" || !Array.isArray(arguments_) ||
      !positiveInteger(options?.timeoutMs) || !positiveInteger(options?.outputLimit) ||
      !isPlainObject(options.env)
    ) {
      reject(operationError());
      return;
    }
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
      !child || typeof child.once !== "function" || typeof child.kill !== "function" ||
      typeof child.stdout?.on !== "function" || typeof child.stderr?.on !== "function"
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
    const signal = options.signal;
    const stop = () => {
      if (killed) return;
      killed = true;
      child.stdout.destroy?.();
      child.stderr.destroy?.();
      try { child.kill("SIGKILL"); } catch { /* the close/error event remains the reap boundary */ }
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
    let timer;
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
      if (failed) reject(operationError());
      else resolve({ status, signal: closeSignal, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") });
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

export function buildNetworkCreateArguments(specification) {
  expectSpec(specification);
  return [
    "network", "create", "--internal",
    "--label", `zasp.dev/proof=${PROOF_LABEL}`,
    "--label", `zasp.dev/run=${specification.marker}`,
    "--label", "zasp.dev/role=network",
    specification.network.name,
  ];
}

export function buildDatabaseCreateArguments(specification) {
  expectSpec(specification);
  const expected = specification.database;
  return [
    "create", "--name", expected.name,
    "--platform", expected.platform,
    "--network", expected.network,
    "--network-alias", expected.networkAlias,
    "--read-only",
    "--cap-drop", "ALL",
    ...["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"].flatMap((capability) => ["--cap-add", capability]),
    "--security-opt", "no-new-privileges",
    "--pids-limit", "128",
    "--memory", "384m",
    "--cpus", "0.5",
    "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=256m",
    "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,size=16m",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
    ...labelArguments(expected.labels),
    ...environmentArguments(expected.environment),
    expected.image,
  ];
}

export function buildNangoCreateArguments(specification) {
  expectSpec(specification);
  const expected = specification.nango;
  return [
    "create", "--name", expected.name,
    "--platform", expected.platform,
    "--network", expected.network,
    "--network-alias", expected.networkAlias,
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "256",
    "--memory", "768m",
    "--cpus", "1.0",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m",
    ...labelArguments(expected.labels),
    ...environmentArguments(expected.environment),
    expected.image,
  ];
}

export function buildProbeCreateArguments(specification) {
  expectSpec(specification);
  const expected = specification.probe;
  return [
    "create", "--name", expected.name,
    "--platform", expected.platform,
    "--network", expected.network,
    "--network-alias", expected.networkAlias,
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "32",
    "--memory", "32m",
    "--cpus", "0.25",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m",
    ...labelArguments(expected.labels),
    expected.image,
    ...expected.command,
  ];
}

export function buildSchemaCommands(specification, databaseId) {
  expectSpec(specification);
  if (!containerIdPattern.test(databaseId ?? "")) throw new TypeError("database identity is invalid");
  const expected = specification.database;
  const base = [
    "exec", databaseId, "psql", "--no-psqlrc", "-qAt", "-v", "ON_ERROR_STOP=1",
    "-U", expected.user, "-d", expected.databaseName, "-c",
  ];
  return deepFreeze({
    inspect: [...base, `SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname IN ('${expected.schema}', '${expected.recordsSchema}') ORDER BY nspname;`],
    create: [...base, `CREATE SCHEMA "${expected.schema}" AUTHORIZATION "${expected.user}"; CREATE SCHEMA "${expected.recordsSchema}" AUTHORIZATION "${expected.user}";`],
    expected: `${expected.schema}\n${expected.recordsSchema}\n`,
  });
}

export function parseImageInspectionResult(source) {
  const value = parseProjection(source, "image", 11);
  return {
    Id: value[0], RepoDigests: value[1], Env: value[2], Entrypoint: value[3], Cmd: value[4],
    User: value[5] ?? "", Labels: value[6], ExposedPorts: value[7], Volumes: value[8],
    Os: value[9], Architecture: value[10],
  };
}

export function parseContainerInspectionResult(source) {
  const value = parseProjection(source, "container", 6);
  if (
    !arrayLength(value[0], 3) || !arrayLength(value[1], 7) || !arrayLength(value[2], 20) ||
    !Array.isArray(value[3]) || !arrayLength(value[4], 2) || !arrayLength(value[5], 2)
  ) throw providerError();
  return {
    Id: value[0][0], Name: value[0][1], Image: value[0][2],
    Config: { Image: value[1][0], Labels: value[1][1], Env: value[1][2] ?? [], Entrypoint: value[1][3], Cmd: value[1][4], User: value[1][5] ?? "", ExposedPorts: value[1][6] },
    HostConfig: {
      NetworkMode: value[2][0], ReadonlyRootfs: value[2][1], CapAdd: value[2][2], CapDrop: value[2][3], SecurityOpt: value[2][4],
      PidsLimit: value[2][5], Memory: value[2][6], NanoCpus: value[2][7], PortBindings: value[2][8], Binds: value[2][9],
      Mounts: value[2][10], Tmpfs: value[2][11], RestartPolicy: value[2][12], Privileged: value[2][13], Devices: value[2][14],
      DeviceRequests: value[2][15], PidMode: value[2][16], IpcMode: value[2][17], CgroupnsMode: value[2][18], UsernsMode: value[2][19],
    },
    Mounts: value[3], State: { Running: value[4][0], Status: value[4][1] },
    NetworkSettings: { Networks: value[5][0], Ports: value[5][1] },
  };
}

export function parseNetworkInspectionResult(source) {
  const value = parseProjection(source, "network", 9);
  return { Id: value[0], Name: value[1], Labels: value[2], Internal: value[3], EnableIPv4: value[4], EnableIPv6: value[5], Options: value[6], IPAM: value[7], Containers: value[8] };
}

export async function runPhase(timeoutMs, operation) {
  if (!positiveInteger(timeoutMs) || typeof operation !== "function") throw operationError();
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => operation(controller.signal)),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Failure("operation"));
        }, timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

export async function orchestrate(runtime, options = {}) {
  if (!runtime || typeof runtime !== "object") throw operationError();
  const mainTimeout = options.mainTimeoutMs ?? mainTimeoutMilliseconds;
  const cleanupTimeout = options.cleanupTimeoutMs ?? cleanupTimeoutMilliseconds;
  let mainError;
  let cleanupError;
  try {
    await runPhase(mainTimeout, async (signal) => {
      await runtime.initialize(signal);
      await runtime.requireInitialAbsence(signal);
      await runtime.resolveImages(signal);
      await runtime.createNetwork(signal);
      await runtime.createDatabase(signal);
      await runtime.startDatabase(signal);
      await runtime.waitDatabase(signal);
      await runtime.prepareDatabase(signal);
      await runtime.createNango(signal);
      await runtime.startNango(signal);
      await runtime.createProbe(signal);
      await runtime.startProbe(signal);
      await runtime.verifyReady(signal);
    });
  } catch (error) {
    mainError = error;
  }
  try {
    await runPhase(cleanupTimeout, async (signal) => {
      let firstError;
      try { await runtime.settleMutations?.(signal); }
      catch (error) { firstError = error; }
      try { await runtime.cleanup(signal); }
      catch (error) { firstError ??= error; }
      try { await runtime.settleMutations?.(signal); }
      catch (error) { firstError ??= error; }
      try { await runtime.requireFinalAbsence(signal); }
      catch (error) { firstError ??= error; }
      if (firstError !== undefined) throw firstError;
    });
  } catch (error) {
    cleanupError = error;
  }
  if (cleanupError !== undefined) throw cleanupError.category === "cleanup" ? cleanupError : cleanupErrorWithCause(cleanupError);
  if (mainError !== undefined) throw mainError;
  return { services: 2, ready: true, productNetwork: true, cleanup: true };
}

export async function runMain(dependencies = {}) {
  const writeLine = dependencies.writeLine ?? ((line) => process.stdout.write(`${line}\n`));
  try {
    const runtime = dependencies.runtime ?? new DockerNangoRuntime({
      pathValue: dependencies.pathValue ?? process.env.PATH,
      platform: dependencies.platform ?? (process.arch === "arm64" ? "linux/arm64" : "linux/amd64"),
      tempParent: dependencies.tempParent ?? tmpdir(),
      markerSource: dependencies.markerSource,
    });
    await orchestrate(runtime, dependencies.timeouts);
    writeLine(SUCCESS_LINE);
    return 0;
  } catch (error) {
    writeLine(failureLine(error?.category));
    return 1;
  }
}

export class DockerNangoRuntime {
  constructor({
    pathValue,
    platform,
    tempParent = tmpdir(),
    markerSource = () => randomBytes(8).toString("hex"),
    command = runBounded,
    spawnProcess = spawn,
    filesystem = {},
  } = {}) {
    if (typeof markerSource !== "function" || typeof command !== "function" || typeof tempParent !== "string") throw configurationError();
    this.pathValue = pathValue;
    this.platform = platform;
    this.tempParent = tempParent;
    this.markerSource = markerSource;
    this.command = command;
    this.spawnProcess = spawnProcess;
    this.filesystem = { readdir, realpath, ...filesystem };
    this.images = new Map();
    this.resources = new Map();
    this.mutationSettlements = [];
  }

  async initialize(signal) {
    return this.#journalOperation(() => this.#initialize(signal));
  }

  async #initialize(signal) {
    assertActive(signal, "operation");
    if (!["linux/amd64", "linux/arm64"].includes(this.platform)) throw configurationError();
    if (typeof this.pathValue !== "string" || this.pathValue.length === 0 || this.pathValue.includes("\0")) throw configurationError();
    this.tempParent = await this.filesystem.realpath(this.tempParent);
    assertActive(signal, "operation");
    if (typeof this.tempParent !== "string" || !isAbsolute(this.tempParent)) throw configurationError();
    const entries = await this.filesystem.readdir(this.tempParent);
    assertActive(signal, "operation");
    validateTemporaryPrefixEntries(entries);
    const marker = validateMarker(this.markerSource());
    const workspace = await createOwnedWorkspace({ marker, tempParent: this.tempParent });
    this.workspace = workspace;
    this.specification = buildRuntimeSpec({ ...workspace.runtimeInput, platform: this.platform });
    this.environment = buildDockerEnvironment(this.pathValue, workspace.dockerConfig.path);
    assertActive(signal, "operation");
  }

  async requireInitialAbsence(signal) {
    await this.#requireGlobalAbsence(signal);
  }

  async resolveImages(signal) {
    for (const [role, expected] of [
      ["database", this.specification.database], ["nango", this.specification.nango], ["probe", this.specification.probe],
    ]) {
      this.images.set(role, await this.#resolveImage(expected, signal));
    }
  }

  async createNetwork(signal) {
    await this.#journalOperation(() => this.#createResource("network", this.specification.network.name, buildNetworkCreateArguments(this.specification), signal));
    await this.#verifyNetwork(signal, []);
  }

  async createDatabase(signal) {
    await this.#journalOperation(() => this.#createResource("database", this.specification.database.name, buildDatabaseCreateArguments(this.specification), signal));
    await this.#verifyContainer("database", signal, false);
    await this.#verifyNetwork(signal, this.#activePeerRoles());
  }

  async startDatabase(signal) {
    await this.#startContainer("database", signal);
  }

  async waitDatabase(signal) {
    const expected = this.specification.database;
    for (let attempt = 0; attempt < 120; attempt += 1) {
      assertActive(signal, "readiness");
      const result = await this.#docker(["exec", this.resources.get("database").id, "pg_isready", "-q", "-U", expected.user, "-d", expected.databaseName], 5_000, signal);
      const state = classifyDatabaseReadinessResult(result);
      if (state === "ready") {
        const query = await this.#docker([
          "exec", this.resources.get("database").id, "psql", "--no-psqlrc", "-qAt", "-v", "ON_ERROR_STOP=1",
          "-U", expected.user, "-d", expected.databaseName, "-c", "SELECT 1;",
        ], 5_000, signal);
        const queryState = classifyDatabaseQueryReadinessResult(query);
        if (queryState === "ready") return;
        if (queryState !== "wait") throw providerError();
      } else if (state !== "wait") throw providerError();
      await delay(500, signal);
    }
    throw readinessError();
  }

  async prepareDatabase(signal) {
    return this.#journalOperation(() => this.#prepareDatabase(signal));
  }

  async #prepareDatabase(signal) {
    const commands = buildSchemaCommands(this.specification, this.resources.get("database").id);
    const before = await this.#readSchemaState(commands.inspect, signal);
    if (before.stdout !== "") throw ownershipError();
    const result = await this.#dockerMutation(commands.create, 10_000, signal);
    const classification = classifyEmptyMutationResult(result);
    if (classification === "definitive") throw providerError();
    const after = await this.#readSchemaState(commands.inspect, signal);
    if (after.stdout !== commands.expected) {
      throw classification === "applied" ? ownershipError() : providerError();
    }
  }

  async #readSchemaState(arguments_, signal) {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const result = await this.#docker(arguments_, 5_000, signal);
      if (result.status === 0 && result.signal === null && result.stderr === "") return result;
      if (attempt === 0) await delay(100, signal);
    }
    throw providerError();
  }

  async createNango(signal) {
    await this.#journalOperation(() => this.#createResource("nango", this.specification.nango.name, buildNangoCreateArguments(this.specification), signal));
    await this.#verifyContainer("nango", signal, false);
    await this.#verifyNetwork(signal, this.#activePeerRoles());
  }

  async startNango(signal) {
    await this.#startContainer("nango", signal);
  }

  async createProbe(signal) {
    await this.#journalOperation(() => this.#createResource("probe", this.specification.probe.name, buildProbeCreateArguments(this.specification), signal));
    await this.#verifyContainer("probe", signal, false);
    await this.#verifyNetwork(signal, this.#activePeerRoles());
  }

  async startProbe(signal) {
    return this.#journalOperation(() => this.#startProbe(signal));
  }

  async #startProbe(signal) {
    const resource = this.resources.get("probe");
    await this.#verifyContainer("probe", signal, false);
    const result = await this.#dockerMutation(["start", "--attach", resource.id], 270_000, signal);
    if (result.status !== 0 || result.signal !== null || result.stderr !== "") throw readinessError();
    // Docker releases the endpoint after the one-shot probe exits. Retain the
    // fact that it ran through the exact stopped attachment projection rather
    // than claiming it is still an active network peer.
    resource.attached = false;
    this.probeOutput = result.stdout;
    await this.#verifyContainer("probe", signal, false, true);
    await this.#verifyNetwork(signal, this.#activePeerRoles());
  }

  async verifyReady(signal) {
    assertActive(signal, "readiness");
    parseReadyOutput(Buffer.from(this.probeOutput ?? "", "utf8"));
    await this.#verifyContainer("database", signal, true);
    await this.#verifyContainer("nango", signal, true);
    await this.#verifyContainer("probe", signal, false, true);
  }

  async settleMutations(signal) {
    const settlements = this.mutationSettlements.splice(0);
    if (settlements.length === 0) return;
    await abortable(Promise.allSettled(settlements), signal);
  }

  async cleanup(signal) {
    let firstError;
    for (const role of ["probe", "nango", "database"]) {
      try { await this.#removeContainer(role, signal); }
      catch (error) { firstError ??= error; }
    }
    try { await this.#removeNetwork(signal); }
    catch (error) { firstError ??= error; }
    if (firstError !== undefined) throw cleanupErrorWithCause(firstError);
  }

  async requireFinalAbsence(signal) {
    let firstError;
    let globalAbsenceProved = false;
    try { await this.#requireGlobalAbsence(signal); }
    catch (error) { firstError = error; }
    if (firstError === undefined) globalAbsenceProved = true;
    if (globalAbsenceProved && this.workspace !== undefined) {
      try {
        await removeOwnedWorkspace(this.workspace);
        this.workspace = undefined;
      } catch (error) { firstError ??= error; }
    }
    try { validateTemporaryPrefixEntries(await this.filesystem.readdir(this.tempParent)); }
    catch (error) { firstError ??= error; }
    if (firstError !== undefined) throw cleanupErrorWithCause(firstError);
  }

  async #resolveImage(expected, signal) {
    let result = await this.#docker(["image", "inspect", "--format", IMAGE_INSPECTION_FORMAT, expected.image], commandTimeoutMilliseconds, signal);
    if (exactMissingImage(result, expected.image)) {
      const pull = await this.#dockerMutation(["pull", "--platform", expected.platform, expected.image], 180_000, signal);
      if (classifyMutationResult(pull) === "definitive") throw providerError();
      result = await this.#docker(["image", "inspect", "--format", IMAGE_INSPECTION_FORMAT, expected.image], commandTimeoutMilliseconds, signal);
    }
    if (result.status !== 0 || result.signal !== null || result.stderr !== "") throw providerError();
    const document = parseImageInspectionResult(result.stdout.trimEnd());
    if (
      !imageIdPattern.test(document.Id) || document.Os !== "linux" || `linux/${document.Architecture}` !== expected.platform ||
      !Array.isArray(document.Env) || !(document.Entrypoint === null || Array.isArray(document.Entrypoint)) ||
      !(document.Cmd === null || Array.isArray(document.Cmd)) ||
      typeof document.User !== "string" || !(document.Labels === null || isPlainObject(document.Labels)) ||
      !(document.ExposedPorts === null || isPlainObject(document.ExposedPorts)) ||
      !(document.Volumes === null || isPlainObject(document.Volumes)) ||
      (expected.role === "nango" && document.Id !== PINS.nango.configDigest)
    ) throw providerError();
    const expectedDigest = expected.image.slice(expected.image.lastIndexOf("@") + 1);
    if (!Array.isArray(document.RepoDigests) || !document.RepoDigests.some((entry) => entry.endsWith(`@${expectedDigest}`))) throw providerError();
    return deepFreeze(document);
  }

  async #createResource(role, name, arguments_, signal) {
    const candidate = { role, name, mayHaveApplied: true, attached: false };
    this.resources.set(role, candidate);
    const result = await this.#dockerMutation(arguments_, commandTimeoutMilliseconds, signal);
    const classification = classifyMutationResult(result);
    if (classification === "definitive") {
      this.resources.delete(role);
      throw providerError();
    }
    const directId = exactId(result.stdout);
    if (directId !== undefined) candidate.id = directId;
    if (classification === "ambiguous") await this.#reconcileResource(role, signal);
  }

  async #reconcileResource(role, signal) {
    const candidate = this.resources.get(role);
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const ids = await this.#listExactName(candidate.name, role === "network", signal);
      if (ids.length === 1) {
        candidate.id = ids[0];
        if (role === "network") await this.#verifyNetwork(signal, []);
        else await this.#verifyContainer(role, signal, false);
        return;
      }
      if (ids.length > 1) throw ownershipError();
      await delay(100, signal);
    }
    throw ownershipError();
  }

  async #startContainer(role, signal) {
    return this.#journalOperation(() => this.#startContainerOperation(role, signal));
  }

  async #startContainerOperation(role, signal) {
    await this.#verifyContainer(role, signal, false);
    const result = await this.#dockerMutation(["start", this.resources.get(role).id], commandTimeoutMilliseconds, signal);
    const classification = classifyExactMutationResult(result, `${this.resources.get(role).id}\n`);
    if (classification === "definitive") throw providerError();
    if (classification === "applied") {
      await this.#verifyContainer(role, signal, true);
    } else {
      let reconciled = false;
      for (let attempt = 0; attempt < 20; attempt += 1) {
        const document = await this.#verifyContainer(role, signal, undefined, false, true);
        if (document.State.Status === "running") { reconciled = true; break; }
        if (document.State.Status !== "created") throw providerError();
        if (attempt < 19) await delay(100, signal);
      }
      if (!reconciled) throw providerError();
    }
    await this.#verifyNetwork(signal, this.#activePeerRoles());
  }

  async #verifyContainer(role, signal, running, exited = false, cleanup = false) {
    const resource = this.resources.get(role);
    const result = await this.#docker(["container", "inspect", "--format", CONTAINER_INSPECTION_FORMAT, resource.id], commandTimeoutMilliseconds, signal);
    if (result.status !== 0 || result.signal !== null || result.stderr !== "") throw ownershipError();
    const document = parseContainerInspectionResult(result.stdout.trimEnd());
    const expected = this.specification[role];
    const image = this.images.get(role);
    validateContainerIdentity(document, {
      resource,
      expected,
      image,
      networkName: this.specification.network.name,
      networkId: this.resources.get("network")?.id,
      attached: resource.attached,
      running,
      exited,
      cleanup,
    });
    if (document.State.Status === "running") {
      const attachment = document.NetworkSettings.Networks[expected.network];
      const networkState = {
        NetworkID: attachment.NetworkID,
        EndpointID: attachment.EndpointID,
        Gateway: attachment.Gateway,
        MacAddress: attachment.MacAddress,
        IPv4Address: `${attachment.IPAddress}/${attachment.IPPrefixLen}`,
      };
      if (resource.networkState === undefined) resource.networkState = deepFreeze(networkState);
      else if (!isDeepStrictEqual(resource.networkState, networkState)) throw ownershipError();
    }
    resource.attached = document.State.Status === "running";
    return document;
  }

  async #verifyNetwork(signal, peerRoles) {
    const resource = this.resources.get("network");
    const result = await this.#docker(["network", "inspect", "--format", NETWORK_INSPECTION_FORMAT, resource.id], commandTimeoutMilliseconds, signal);
    if (result.status !== 0 || result.signal !== null || result.stderr !== "") throw ownershipError();
    const document = parseNetworkInspectionResult(result.stdout.trimEnd());
    validateNetworkIdentity(document, resource, this.specification.network, peerRoles.map((role) => this.resources.get(role)));
    const staticState = {
      Id: document.Id,
      Name: document.Name,
      Labels: document.Labels,
      Internal: document.Internal,
      EnableIPv4: document.EnableIPv4,
      EnableIPv6: document.EnableIPv6,
      Options: document.Options,
      IPAM: document.IPAM,
    };
    if (resource.staticState === undefined) resource.staticState = deepFreeze(staticState);
    else if (!isDeepStrictEqual(staticState, resource.staticState)) throw ownershipError();
  }

  #activePeerRoles() {
    return ["database", "nango", "probe"].filter((role) => this.resources.get(role)?.attached === true);
  }

  async #removeContainer(role, signal) {
    const resource = this.resources.get(role);
    if (resource === undefined) return;
    if (resource.id === undefined) {
      if (!await this.#recoverCleanupCandidate(resource, false, signal)) { this.resources.delete(role); return; }
    }
    const document = await this.#coherentCleanupSnapshot(role, signal);
    const result = await this.#dockerMutation(["rm", "--force", "--volumes", document.Id], commandTimeoutMilliseconds, signal);
    if (classifyExactMutationResult(result, `${document.Id}\n`) === "definitive") throw ownershipError();
    await this.#requireRemovedResource(resource, false, signal);
    this.resources.delete(role);
  }

  async #refreshCleanupContainerStates(signal) {
    const documents = new Map();
    for (const role of ["probe", "nango", "database"]) {
      const resource = this.resources.get(role);
      if (resource?.id === undefined) continue;
      documents.set(role, await this.#verifyContainer(role, signal, undefined, false, true));
    }
    return documents;
  }

  async #coherentCleanupSnapshot(role, signal) {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      try {
        const documents = await this.#refreshCleanupContainerStates(signal);
        const document = documents.get(role);
        if (document === undefined) throw ownershipError();
        await this.#verifyNetwork(signal, this.#activePeerRoles());
        return document;
      } catch (error) {
        if (attempt === 19) throw error;
        await delay(100, signal);
      }
    }
    throw ownershipError();
  }

  async #removeNetwork(signal) {
    const resource = this.resources.get("network");
    if (resource === undefined) return;
    if (resource.id === undefined) {
      if (!await this.#recoverCleanupCandidate(resource, true, signal)) { this.resources.delete("network"); return; }
    }
    await this.#verifyNetwork(signal, []);
    const result = await this.#dockerMutation(["network", "rm", resource.id], commandTimeoutMilliseconds, signal);
    if (classifyExactMutationResult(result, `${resource.id}\n`) === "definitive") throw ownershipError();
    await this.#requireRemovedResource(resource, true, signal);
    this.resources.delete("network");
  }

  async #requireGlobalAbsence(signal) {
    const commands = [
      ["ps", "-a", "--no-trunc", "--filter", `name=^/${namePrefix}`, "--format", "{{.ID}}"],
      ["ps", "-a", "--no-trunc", "--filter", `label=zasp.dev/proof=${PROOF_LABEL}`, "--format", "{{.ID}}"],
      ["network", "ls", "--no-trunc", "--filter", `name=^${namePrefix}`, "--format", "{{.ID}}"],
      ["network", "ls", "--no-trunc", "--filter", `label=zasp.dev/proof=${PROOF_LABEL}`, "--format", "{{.ID}}"],
    ];
    if (this.specification !== undefined) {
      commands.push(
        ["ps", "-a", "--no-trunc", "--filter", `label=zasp.dev/run=${this.specification.marker}`, "--format", "{{.ID}}"],
        ["network", "ls", "--no-trunc", "--filter", `label=zasp.dev/run=${this.specification.marker}`, "--format", "{{.ID}}"],
      );
    }
    for (const arguments_ of commands) {
      const result = await this.#docker(arguments_, commandTimeoutMilliseconds, signal);
      if (result.status !== 0 || result.signal !== null || result.stdout !== "" || result.stderr !== "") throw ownershipError();
    }
  }

  async #listExactName(name, network, signal) {
    const arguments_ = network
      ? ["network", "ls", "--no-trunc", "--filter", `name=^${name}$`, "--format", "{{.ID}}"]
      : ["ps", "-a", "--no-trunc", "--filter", `name=^/${name}$`, "--format", "{{.ID}}"];
    const result = await this.#docker(arguments_, commandTimeoutMilliseconds, signal);
    if (result.status !== 0 || result.signal !== null || result.stderr !== "") throw providerError();
    const ids = result.stdout === "" ? [] : result.stdout.trimEnd().split("\n");
    if (ids.some((id) => !containerIdPattern.test(id)) || new Set(ids).size !== ids.length) throw providerError();
    return ids;
  }

  async #recoverCleanupCandidate(resource, network, signal) {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const ids = await this.#listExactName(resource.name, network, signal);
      if (ids.length > 1) throw ownershipError();
      if (ids.length === 1) { resource.id = ids[0]; return true; }
      if (attempt < 29) await delay(100, signal);
    }
    return false;
  }

  async #requireRemovedResource(resource, network, signal) {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const names = await this.#listExactName(resource.name, network, signal);
      const arguments_ = network
        ? ["network", "ls", "--no-trunc", "--filter", `id=${resource.id}`, "--format", "{{.ID}}"]
        : ["ps", "-a", "--no-trunc", "--filter", `id=${resource.id}`, "--format", "{{.ID}}"];
      const result = await this.#docker(arguments_, commandTimeoutMilliseconds, signal);
      if (result.status !== 0 || result.signal !== null || result.stderr !== "") throw ownershipError();
      if (names.length === 0 && result.stdout === "") return;
      if (attempt < 19) await delay(100, signal);
    }
    throw ownershipError();
  }

  async #docker(arguments_, timeoutMs, signal) {
    assertActive(signal, "operation");
    await reproveOwnedWorkspace(this.workspace);
    try {
      return await this.command("docker", arguments_, { env: this.environment, timeoutMs, outputLimit: maximumCommandBytes, signal }, this.spawnProcess);
    } catch {
      return { thrown: true, status: null, signal: null, stdout: "", stderr: "" };
    }
  }

  #dockerMutation(arguments_, timeoutMs, signal) {
    const operation = this.#docker(arguments_, timeoutMs, signal);
    const settlement = operation.then(
      (value) => ({ state: "fulfilled", value }),
      (error) => ({ state: "rejected", error }),
    );
    this.mutationSettlements.push(settlement);
    return operation;
  }

  #journalOperation(factory) {
    const operation = Promise.resolve().then(factory);
    const settlement = operation.then(
      (value) => ({ state: "fulfilled", value }),
      (error) => ({ state: "rejected", error }),
    );
    this.mutationSettlements.push(settlement);
    return operation;
  }
}

export function validateContainerIdentity(document, { resource, expected, image, networkName, networkId, running, exited, cleanup }) {
  const stateIsExact = cleanup === true
    ? ((document.State.Running === true && document.State.Status === "running") ||
      (document.State.Running === false && ["created", "exited"].includes(document.State.Status)))
    : document.State.Running === running && document.State.Status === (running ? "running" : exited ? "exited" : "created");
  const attachmentIsExact = document.State.Status === "running"
    ? validActiveAttachment(document.NetworkSettings.Networks?.[networkName], expected.networkAlias, networkId, resource.id)
    : document.State.Status === "exited"
      ? validStoppedAttachment(document.NetworkSettings.Networks?.[networkName], expected.networkAlias, networkId, resource.id)
      : validInactiveAttachment(document.NetworkSettings.Networks?.[networkName], expected.networkAlias);
  if (
    document.Id !== resource.id || document.Name !== `/${resource.name}` || document.Image !== image.Id ||
    document.Config.Image !== expected.image || document.Config.User !== image.User ||
    !isDeepStrictEqual(document.Config.Entrypoint, image.Entrypoint) ||
    !isDeepStrictEqual(document.Config.Cmd, expected.role === "probe" ? expected.command : image.Cmd) ||
    !isDeepStrictEqual(document.Config.ExposedPorts, image.ExposedPorts) ||
    !exactMergedObject(document.Config.Labels, image.Labels, expected.labels) ||
    !exactEnvironment(document.Config.Env, image.Env, expected.environment) ||
    document.HostConfig.NetworkMode !== networkName || document.HostConfig.ReadonlyRootfs !== true ||
    !isDeepStrictEqual(document.HostConfig.CapDrop, ["ALL"]) ||
    !isDeepStrictEqual(document.HostConfig.SecurityOpt, ["no-new-privileges"]) ||
    !isDeepStrictEqual(document.HostConfig.PortBindings, {}) || document.HostConfig.Privileged !== false ||
    ![null, []].some((value) => isDeepStrictEqual(document.HostConfig.Binds, value)) ||
    ![null, []].some((value) => isDeepStrictEqual(document.HostConfig.Mounts, value)) ||
    !isDeepStrictEqual(document.HostConfig.RestartPolicy, { Name: "no", MaximumRetryCount: 0 }) ||
    !isDeepStrictEqual(document.HostConfig.Devices, []) || document.HostConfig.DeviceRequests !== null ||
    document.HostConfig.PidMode !== "" || !["", "private"].includes(document.HostConfig.IpcMode) ||
    !["", "private"].includes(document.HostConfig.CgroupnsMode) || document.HostConfig.UsernsMode !== "" ||
    !stateIsExact || !attachmentIsExact ||
    !isPlainObject(document.NetworkSettings.Networks) || !isDeepStrictEqual(Object.keys(document.NetworkSettings.Networks), [networkName]) ||
    !isDeepStrictEqual(document.NetworkSettings.Ports, document.State.Status === "created" ? {} : unpublishedPorts(image.ExposedPorts))
  ) throw ownershipError();
  const constraints = expected.role === "database"
    ? { pids: 128, memory: 402_653_184, nano: 500_000_000 }
    : expected.role === "nango"
      ? { pids: 256, memory: 805_306_368, nano: 1_000_000_000 }
      : { pids: 32, memory: 33_554_432, nano: 250_000_000 };
  if (document.HostConfig.PidsLimit !== constraints.pids || document.HostConfig.Memory !== constraints.memory || document.HostConfig.NanoCpus !== constraints.nano) throw ownershipError();
  const expectedCapabilities = expected.role === "database" ? ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID"] : null;
  if (!isDeepStrictEqual(document.HostConfig.CapAdd, expectedCapabilities)) throw ownershipError();
  const expectedTmpfs = expected.role === "database"
    ? {
        "/var/lib/postgresql/data": "rw,nosuid,nodev,size=256m",
        "/var/run/postgresql": "rw,nosuid,nodev,size=16m",
        "/tmp": "rw,noexec,nosuid,nodev,size=16m",
      }
    : expected.tmpfs;
  if (!isDeepStrictEqual(document.HostConfig.Tmpfs, expectedTmpfs)) throw ownershipError();
  if (!Array.isArray(document.Mounts) || document.Mounts.some((mount) => mount?.Type !== "tmpfs")) throw ownershipError();
}

function validActiveAttachment(value, alias, networkId, resourceId) {
  if (
    !isPlainObject(value) || !containerIdPattern.test(networkId ?? "") || !containerIdPattern.test(resourceId ?? "") ||
    !isDeepStrictEqual(Object.keys(value).sort(), [
      "Aliases", "DNSNames", "DriverOpts", "EndpointID", "Gateway", "GlobalIPv6Address",
      "GlobalIPv6PrefixLen", "GwPriority", "IPAMConfig", "IPAddress", "IPPrefixLen",
      "IPv6Gateway", "Links", "MacAddress", "NetworkID",
    ]) ||
    !isDeepStrictEqual(value.Aliases, [alias]) || !isDeepStrictEqual(value.DNSNames, [alias, resourceId.slice(0, 12)]) ||
    value.IPAMConfig !== null || value.Links !== null || value.DriverOpts !== null || value.GwPriority !== 0 ||
    value.NetworkID !== networkId || !containerIdPattern.test(value.EndpointID ?? "") || value.Gateway !== "" ||
    !validMacAddress(value.MacAddress) || value.IPv6Gateway !== "" || value.GlobalIPv6Address !== "" || value.GlobalIPv6PrefixLen !== 0
  ) return false;
  const address = ipv4Integer(value.IPAddress);
  const prefix = value.IPPrefixLen;
  if (address === undefined || !Number.isInteger(prefix) || prefix < 16 || prefix > 29 || !privateIPv4(address)) return false;
  return true;
}

function validInactiveAttachment(value, alias) {
  return isPlainObject(value) &&
    isDeepStrictEqual(Object.keys(value).sort(), [
      "Aliases", "DNSNames", "DriverOpts", "EndpointID", "Gateway", "GlobalIPv6Address",
      "GlobalIPv6PrefixLen", "GwPriority", "IPAMConfig", "IPAddress", "IPPrefixLen",
      "IPv6Gateway", "Links", "MacAddress", "NetworkID",
    ]) &&
    isDeepStrictEqual(value.Aliases, [alias]) && value.IPAMConfig === null && value.Links === null &&
    value.DriverOpts === null && value.DNSNames === null && value.GwPriority === 0 &&
    value.NetworkID === "" && value.EndpointID === "" && value.Gateway === "" &&
    value.IPAddress === "" && value.IPPrefixLen === 0 && value.MacAddress === "" &&
    value.IPv6Gateway === "" && value.GlobalIPv6Address === "" && value.GlobalIPv6PrefixLen === 0;
}

function validStoppedAttachment(value, alias, networkId, resourceId) {
  return isPlainObject(value) && containerIdPattern.test(networkId ?? "") && containerIdPattern.test(resourceId ?? "") &&
    isDeepStrictEqual(Object.keys(value).sort(), [
      "Aliases", "DNSNames", "DriverOpts", "EndpointID", "Gateway", "GlobalIPv6Address",
      "GlobalIPv6PrefixLen", "GwPriority", "IPAMConfig", "IPAddress", "IPPrefixLen",
      "IPv6Gateway", "Links", "MacAddress", "NetworkID",
    ]) &&
    isDeepStrictEqual(value.Aliases, [alias]) && isDeepStrictEqual(value.DNSNames, [alias, resourceId.slice(0, 12)]) &&
    value.IPAMConfig === null && value.Links === null && value.DriverOpts === null && value.GwPriority === 0 &&
    value.NetworkID === networkId && value.EndpointID === "" && value.Gateway === "" && value.IPAddress === "" &&
    value.IPPrefixLen === 0 && value.MacAddress === "" && value.IPv6Gateway === "" &&
    value.GlobalIPv6Address === "" && value.GlobalIPv6PrefixLen === 0;
}

export function validateNetworkIdentity(document, resource, expected, peers) {
  if (
    document.Id !== resource.id || document.Name !== resource.name || document.Internal !== true || document.EnableIPv4 !== true || document.EnableIPv6 !== false ||
    !isDeepStrictEqual(document.Labels, expected.labels) || !isPlainObject(document.Options) || Object.keys(document.Options).length !== 0 ||
    !validIPAM(document.IPAM) || !isPlainObject(document.Containers)
  ) throw ownershipError();
  const actualPeers = Object.entries(document.Containers);
  if (actualPeers.length !== peers.length) throw ownershipError();
  for (const peer of peers) {
    const value = document.Containers[peer.id];
    if (
      !isPlainObject(value) ||
      !isDeepStrictEqual(Object.keys(value).sort(), ["EndpointID", "IPv4Address", "IPv6Address", "MacAddress", "Name"]) ||
      value.Name !== peer.name || !containerIdPattern.test(value.EndpointID ?? "") ||
      !validMacAddress(value.MacAddress) || !validPeerAddress(value.IPv4Address, document.IPAM.Config[0]) ||
      value.IPv6Address !== "" || !isPlainObject(peer.networkState) ||
      !isDeepStrictEqual(Object.keys(peer.networkState).sort(), ["EndpointID", "Gateway", "IPv4Address", "MacAddress", "NetworkID"]) ||
      peer.networkState.Gateway !== "" ||
      peer.networkState.NetworkID !== document.Id || peer.networkState.EndpointID !== value.EndpointID ||
      peer.networkState.MacAddress !== value.MacAddress || peer.networkState.IPv4Address !== value.IPv4Address
    ) throw ownershipError();
  }
}

function validPeerAddress(value, config) {
  if (typeof value !== "string" || !isPlainObject(config)) return false;
  const match = /^([^/]+)\/([0-9]{1,2})$/.exec(value);
  const subnet = /^([^/]+)\/([0-9]{1,2})$/.exec(config.Subnet ?? "");
  if (match === null || subnet === null || match[2] !== subnet[2]) return false;
  const address = ipv4Integer(match[1]);
  const network = ipv4Integer(subnet[1]);
  const gateway = ipv4Integer(config.Gateway ?? "");
  const prefix = Number(match[2]);
  if (address === undefined || network === undefined || gateway === undefined || prefix < 16 || prefix > 29) return false;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return ((address & mask) >>> 0) === network && address !== network && address !== broadcast && address !== gateway;
}

function validMacAddress(value) {
  return typeof value === "string" && /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(value);
}

function validIPAM(value) {
  if (
    !isPlainObject(value) || value.Driver !== "default" ||
    !(value.Options === null || (isPlainObject(value.Options) && Object.keys(value.Options).length === 0)) ||
    !Array.isArray(value.Config) || value.Config.length !== 1 || !isPlainObject(value.Config[0])
  ) return false;
  const config = value.Config[0];
  return privateNetworkAndGateway(config.Subnet, config.Gateway) &&
    Object.keys(config).every((key) => ["Subnet", "Gateway"].includes(key));
}

function privateNetworkAndGateway(subnet, gateway) {
  if (typeof subnet !== "string" || typeof gateway !== "string") return false;
  const match = /^([0-9]{1,3}(?:\.[0-9]{1,3}){3})\/([0-9]{1,2})$/.exec(subnet);
  if (match === null) return false;
  const network = ipv4Integer(match[1]);
  const gatewayValue = ipv4Integer(gateway);
  const prefix = Number(match[2]);
  if (network === undefined || gatewayValue === undefined || prefix < 16 || prefix > 29 || !privateIPv4(network)) return false;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return ((network & mask) >>> 0) === network && ((gatewayValue & mask) >>> 0) === network && gatewayValue !== network && gatewayValue !== broadcast;
}

function ipv4Integer(value) {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(?:0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)) return undefined;
  return parts.reduce((output, part) => ((output << 8) | Number(part)) >>> 0, 0);
}

function privateIPv4(value) {
  return ((value & 0xff000000) >>> 0) === 0x0a000000 ||
    ((value & 0xfff00000) >>> 0) === 0xac100000 ||
    ((value & 0xffff0000) >>> 0) === 0xc0a80000;
}

function parseProjection(source, key, length) {
  if (typeof source !== "string" || source.length === 0 || Buffer.byteLength(source) > maximumCommandBytes) throw providerError();
  let envelope;
  try { envelope = parseBoundedUniqueJson(Buffer.from(source)); }
  catch { throw providerError(); }
  if (!isPlainObject(envelope) || !isDeepStrictEqual(Object.keys(envelope), [key]) || !arrayLength(envelope[key], length)) throw providerError();
  return envelope[key];
}

function exactMissingImage(result, reference) {
  return isPlainObject(result) && result.status === 1 && result.signal === null &&
    (result.stdout === "" || result.stdout === "\n") &&
    result.stderr === `Error response from daemon: No such image: ${reference}\n`;
}

function exactMergedObject(actual, base, overlay) {
  return isPlainObject(actual) && isDeepStrictEqual(actual, { ...(base ?? {}), ...overlay });
}

function exactEnvironment(actual, base, overlay) {
  if (!Array.isArray(actual) || actual.some((entry) => typeof entry !== "string" || !entry.includes("="))) return false;
  const expected = new Map();
  for (const entry of base ?? []) expected.set(entry.slice(0, entry.indexOf("=")), entry);
  for (const [key, value] of Object.entries(overlay)) expected.set(key, `${key}=${value}`);
  if (actual.length !== expected.size) return false;
  const actualMap = new Map(actual.map((entry) => [entry.slice(0, entry.indexOf("=")), entry]));
  return actualMap.size === expected.size && [...expected].every(([key, value]) => actualMap.get(key) === value);
}

function unpublishedPorts(exposedPorts) {
  if (exposedPorts === null || exposedPorts === undefined) return {};
  if (!isPlainObject(exposedPorts)) throw ownershipError();
  return Object.fromEntries(Object.keys(exposedPorts).sort().map((key) => [key, null]));
}

function labelArguments(labels) {
  return Object.entries(labels).sort(([left], [right]) => left.localeCompare(right)).flatMap(([key, value]) => ["--label", `${key}=${value}`]);
}

function environmentArguments(environment) {
  return Object.entries(environment).sort(([left], [right]) => left.localeCompare(right)).flatMap(([key, value]) => ["--env", `${key}=${value}`]);
}

function expectSpec(value) {
  if (!isPlainObject(value) || !markerPattern.test(value.marker) || value.prefix !== `${namePrefix}${value.marker}`) throw new TypeError("runtime specification is invalid");
}

function exactId(value) {
  if (typeof value !== "string") return undefined;
  const candidate = value.endsWith("\n") ? value.slice(0, -1) : value;
  return containerIdPattern.test(candidate) ? candidate : undefined;
}

function arrayLength(value, length) { return Array.isArray(value) && value.length === length; }
function positiveInteger(value) { return Number.isInteger(value) && value > 0; }
function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
function assertActive(signal, category) { if (signal?.aborted === true) throw new Failure(category); }
function delay(milliseconds, signal) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    signal?.addEventListener?.("abort", () => { clearTimeout(timer); reject(operationError()); }, { once: true });
  });
}
function abortable(operation, signal) {
  if (signal?.aborted === true) return Promise.reject(operationError());
  if (typeof signal?.addEventListener !== "function") return operation;
  return new Promise((resolve, reject) => {
    const aborted = () => reject(operationError());
    signal.addEventListener("abort", aborted, { once: true });
    operation.then(resolve, reject).finally(() => signal.removeEventListener("abort", aborted));
  });
}
function failureLine(category) {
  const allowed = new Set(["configuration", "provider", "readiness", "ownership", "cleanup", "operation"]);
  return `Nango free boot proof failed: ${allowed.has(category) ? category : "operation"} rejected.`;
}
function configurationError() { return new Failure("configuration"); }
function providerError() { return new Failure("provider"); }
function readinessError() { return new Failure("readiness"); }
function ownershipError() { return new Failure("ownership"); }
function operationError() { return new Failure("operation"); }
function cleanupErrorWithCause(cause) { return new Failure("cleanup", { cause }); }

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  process.exitCode = await runMain();
}
