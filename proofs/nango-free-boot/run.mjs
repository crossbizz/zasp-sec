import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { readdir } from "node:fs/promises";
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

const imageFormat = [
  "{\"image\":[{{json .Id}},{{json .RepoDigests}},{{json .Config.Env}},",
  "{{json .Config.Entrypoint}},{{json .Config.Cmd}},{{json .Config.User}},",
  "{{json .Config.Labels}},{{json .Config.ExposedPorts}},{{json .Config.Volumes}},",
  "{{json .Os}},{{json .Architecture}}]}",
].join("");

const containerFormat = [
  "{\"container\":[[{{json .Id}},{{json .Name}},{{json .Image}}],",
  "[{{json .Config.Image}},{{json .Config.Labels}},{{json .Config.Env}},{{json .Config.Entrypoint}},{{json .Config.Cmd}},{{json .Config.User}},{{json .Config.ExposedPorts}}],",
  "[{{json .HostConfig.NetworkMode}},{{json .HostConfig.ReadonlyRootfs}},{{json .HostConfig.CapAdd}},{{json .HostConfig.CapDrop}},{{json .HostConfig.SecurityOpt}},{{json .HostConfig.PidsLimit}},{{json .HostConfig.Memory}},{{json .HostConfig.NanoCpus}},{{json .HostConfig.PortBindings}},{{json .HostConfig.Binds}},{{json .HostConfig.Mounts}},{{json .HostConfig.Tmpfs}},{{json .HostConfig.RestartPolicy}},{{json .HostConfig.Privileged}},{{json .HostConfig.Devices}},{{json .HostConfig.DeviceRequests}},{{json .HostConfig.PidMode}},{{json .HostConfig.IpcMode}},{{json .HostConfig.CgroupnsMode}},{{json .HostConfig.UsernsMode}}],",
  "{{json .Mounts}},[{{json .State.Running}},{{json .State.Status}}],",
  "[{{json .NetworkSettings.Networks}},{{json .NetworkSettings.Ports}}]]}",
].join("");

const networkFormat = [
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

export function parseImageInspectionResult(source) {
  const value = parseProjection(source, "image", 11);
  return {
    Id: value[0], RepoDigests: value[1], Env: value[2], Entrypoint: value[3], Cmd: value[4],
    User: value[5], Labels: value[6], ExposedPorts: value[7], Volumes: value[8],
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
    Config: { Image: value[1][0], Labels: value[1][1], Env: value[1][2], Entrypoint: value[1][3], Cmd: value[1][4], User: value[1][5], ExposedPorts: value[1][6] },
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
    await runtime.settleMutations?.();
    await runPhase(cleanupTimeout, async (signal) => {
      let firstError;
      try { await runtime.cleanup(signal); }
      catch (error) { firstError = error; }
      try { await runtime.requireFinalAbsence(signal); }
      catch (error) { firstError ??= error; }
      if (firstError !== undefined) throw firstError;
    });
  } catch (error) {
    cleanupError = error;
  }
  await runtime.settleMutations?.();
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
    this.filesystem = { readdir, ...filesystem };
    this.images = new Map();
    this.resources = new Map();
    this.mutationSettlements = [];
  }

  async initialize(signal) {
    assertActive(signal, "operation");
    if (!["linux/amd64", "linux/arm64"].includes(this.platform)) throw configurationError();
    if (typeof this.pathValue !== "string" || this.pathValue.length === 0 || this.pathValue.includes("\0")) throw configurationError();
    const entries = await this.filesystem.readdir(this.tempParent);
    validateTemporaryPrefixEntries(entries);
    const marker = validateMarker(this.markerSource());
    this.workspace = await createOwnedWorkspace({ marker, tempParent: this.tempParent });
    this.specification = buildRuntimeSpec({ ...this.workspace.runtimeInput, platform: this.platform });
    this.environment = buildDockerEnvironment(this.pathValue, this.workspace.dockerConfig.path);
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
    await this.#verifyNetwork(signal, ["database"]);
  }

  async startDatabase(signal) {
    await this.#startContainer("database", signal);
  }

  async waitDatabase(signal) {
    const expected = this.specification.database;
    for (let attempt = 0; attempt < 120; attempt += 1) {
      assertActive(signal, "readiness");
      const result = await this.#docker(["exec", this.resources.get("database").id, "pg_isready", "-q", "-U", expected.user, "-d", expected.databaseName], 5_000, signal);
      if (result.status === 0 && result.signal === null && result.stdout === "" && result.stderr === "") return;
      if (result.status !== 1 || result.signal !== null || result.stdout !== "" || result.stderr !== "") throw providerError();
      await delay(500, signal);
    }
    throw readinessError();
  }

  async createNango(signal) {
    await this.#journalOperation(() => this.#createResource("nango", this.specification.nango.name, buildNangoCreateArguments(this.specification), signal));
    await this.#verifyContainer("nango", signal, false);
    await this.#verifyNetwork(signal, ["database", "nango"]);
  }

  async startNango(signal) {
    await this.#startContainer("nango", signal);
  }

  async createProbe(signal) {
    await this.#journalOperation(() => this.#createResource("probe", this.specification.probe.name, buildProbeCreateArguments(this.specification), signal));
    await this.#verifyContainer("probe", signal, false);
    await this.#verifyNetwork(signal, ["database", "nango", "probe"]);
  }

  async startProbe(signal) {
    return this.#journalOperation(() => this.#startProbe(signal));
  }

  async #startProbe(signal) {
    const resource = this.resources.get("probe");
    await this.#verifyContainer("probe", signal, false);
    const result = await this.#dockerMutation(["start", "--attach", resource.id], 270_000, signal);
    if (result.status !== 0 || result.signal !== null || result.stderr !== "") throw readinessError();
    this.probeOutput = result.stdout;
  }

  async verifyReady(signal) {
    assertActive(signal, "readiness");
    parseReadyOutput(Buffer.from(this.probeOutput ?? "", "utf8"));
    await this.#verifyContainer("database", signal, true);
    await this.#verifyContainer("nango", signal, true);
    await this.#verifyContainer("probe", signal, false, true);
  }

  async settleMutations() {
    const settlements = this.mutationSettlements.splice(0);
    await Promise.allSettled(settlements);
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
    try { await this.#requireGlobalAbsence(signal); }
    catch (error) { firstError = error; }
    if (this.workspace !== undefined) {
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
    let result = await this.#docker(["image", "inspect", "--format", imageFormat, expected.image], commandTimeoutMilliseconds, signal);
    if (exactMissingImage(result, expected.image)) {
      const pull = await this.#dockerMutation(["pull", "--platform", expected.platform, expected.image], 180_000, signal);
      if (pull.status !== 0 || pull.signal !== null || pull.stderr !== "") throw providerError();
      result = await this.#docker(["image", "inspect", "--format", imageFormat, expected.image], commandTimeoutMilliseconds, signal);
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
    const candidate = { role, name, mayHaveApplied: true };
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
    if (result.status !== 0 || result.signal !== null || result.stdout !== `${this.resources.get(role).id}\n` || result.stderr !== "") throw providerError();
    await this.#verifyContainer(role, signal, true);
  }

  async #verifyContainer(role, signal, running, exited = false, cleanup = false) {
    const resource = this.resources.get(role);
    const result = await this.#docker(["container", "inspect", "--format", containerFormat, resource.id], commandTimeoutMilliseconds, signal);
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
      running,
      exited,
      cleanup,
    });
    return document;
  }

  async #verifyNetwork(signal, peerRoles) {
    const resource = this.resources.get("network");
    const result = await this.#docker(["network", "inspect", "--format", networkFormat, resource.id], commandTimeoutMilliseconds, signal);
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

  async #removeContainer(role, signal) {
    const resource = this.resources.get(role);
    if (resource === undefined) return;
    if (resource.id === undefined) {
      if (!await this.#recoverCleanupCandidate(resource, false, signal)) { this.resources.delete(role); return; }
    }
    const document = await this.#verifyContainer(role, signal, undefined, false, true);
    const result = await this.#dockerMutation(["rm", "--force", "--volumes", document.Id], commandTimeoutMilliseconds, signal);
    if (result.status !== 0 || result.signal !== null || result.stdout !== `${document.Id}\n` || result.stderr !== "") throw ownershipError();
    await this.#requireRemovedResource(resource, false, signal);
    this.resources.delete(role);
  }

  async #removeNetwork(signal) {
    const resource = this.resources.get("network");
    if (resource === undefined) return;
    if (resource.id === undefined) {
      if (!await this.#recoverCleanupCandidate(resource, true, signal)) { this.resources.delete("network"); return; }
    }
    await this.#verifyNetwork(signal, []);
    const result = await this.#dockerMutation(["network", "rm", resource.id], commandTimeoutMilliseconds, signal);
    if (result.status !== 0 || result.signal !== null || result.stdout !== `${resource.id}\n` || result.stderr !== "") throw ownershipError();
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
    if ((await this.#listExactName(resource.name, network, signal)).length !== 0) throw ownershipError();
    const arguments_ = network
      ? ["network", "ls", "--no-trunc", "--filter", `id=${resource.id}`, "--format", "{{.ID}}"]
      : ["ps", "-a", "--no-trunc", "--filter", `id=${resource.id}`, "--format", "{{.ID}}"];
    const result = await this.#docker(arguments_, commandTimeoutMilliseconds, signal);
    if (result.status !== 0 || result.signal !== null || result.stdout !== "" || result.stderr !== "") throw ownershipError();
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
    !stateIsExact ||
    !isPlainObject(document.NetworkSettings.Networks) || !isDeepStrictEqual(Object.keys(document.NetworkSettings.Networks), [networkName]) ||
    !isDeepStrictEqual(document.NetworkSettings.Ports, unpublishedPorts(image.ExposedPorts))
  ) throw ownershipError();
  const attachment = document.NetworkSettings.Networks[networkName];
  if (
    !containerIdPattern.test(networkId ?? "") || !isPlainObject(attachment) || attachment.NetworkID !== networkId ||
    !containerIdPattern.test(attachment.EndpointID ?? "") || !Array.isArray(attachment.Aliases) ||
    !attachment.Aliases.includes(expected.networkAlias) || typeof attachment.IPAddress !== "string" || attachment.IPAddress.length === 0
  ) throw ownershipError();
  const constraints = expected.role === "database"
    ? { pids: 128, memory: 402_653_184, nano: 500_000_000 }
    : expected.role === "nango"
      ? { pids: 256, memory: 805_306_368, nano: 1_000_000_000 }
      : { pids: 32, memory: 33_554_432, nano: 250_000_000 };
  if (document.HostConfig.PidsLimit !== constraints.pids || document.HostConfig.Memory !== constraints.memory || document.HostConfig.NanoCpus !== constraints.nano) throw ownershipError();
  const expectedCapabilities = expected.role === "database" ? ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"] : null;
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
      typeof value.MacAddress !== "string" || !/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(value.MacAddress) ||
      typeof value.IPv4Address !== "string" || !/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(value.IPv4Address) ||
      value.IPv6Address !== ""
    ) throw ownershipError();
  }
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
  return ((network & mask) >>> 0) === network && ((gatewayValue & mask) >>> 0) === network && gatewayValue !== network;
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
