import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { readdir, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

import {
  CONTAINER_INSPECTION_FORMAT,
  IMAGE_INSPECTION_FORMAT,
  NETWORK_INSPECTION_FORMAT,
  classifyMutationResult,
  parseContainerInspectionResult,
  parseImageInspectionResult,
  parseNetworkInspectionResult,
  runBounded,
  runPhase,
  validateNetworkIdentity,
} from "../nango-free-boot/run.mjs";
import { parseBoundedUniqueJson } from "../nango-free-boot/manifest.mjs";
import {
  createProxyWorkspace,
  removeProxyWorkspace,
  reproveProxyWorkspace,
  validateProxyTemporaryPrefixEntries,
} from "./boundary.mjs";
import {
  PROXY_PROOF_LABEL,
  PROXY_PINS,
  buildProxyRuntimeSpec,
  validateProxyMarker,
} from "./manifest.mjs";

export { classifyMutationResult };

export const SUCCESS_LINE = "Nango proxy proof passed: get=true response=true product_state_safe=true cleanup=true.";

const mainTimeoutMilliseconds = 360_000;
const cleanupTimeoutMilliseconds = 90_000;
const commandTimeoutMilliseconds = 30_000;
const maximumCommandBytes = 65_536;
const idPattern = /^[0-9a-f]{64}$/;
const imageIdPattern = /^sha256:[0-9a-f]{64}$/;
const organizationPattern = /^org_[0-9a-f]{16}$/;
const integrationPattern = /^zasp-m0-15-[0-9a-f]{16}-1password-events$/;
const connectionPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function buildNetworkCreateArguments(specification) {
  expectSpecification(specification);
  return [
    "network", "create", "--internal",
    ...labelArguments(specification.network.labels),
    specification.network.name,
  ];
}

export function buildContainerCreateArguments(specification, role) {
  expectSpecification(specification);
  if (!specification.roles.includes(role)) throw new TypeError("proxy role is invalid");
  const expected = specification[role];
  const constraints = role === "database"
    ? { pids: "128", memory: "384m", cpus: "0.5", capabilities: ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"] }
    : role === "nango"
      ? { pids: "256", memory: "768m", cpus: "1.0", capabilities: [] }
      : { pids: "64", memory: "128m", cpus: "0.5", capabilities: [] };
  return [
    "create", "--name", expected.name,
    "--platform", expected.platform,
    "--network", expected.network,
    "--network-alias", expected.networkAlias,
    "--read-only",
    "--cap-drop", "ALL",
    ...constraints.capabilities.flatMap((capability) => ["--cap-add", capability]),
    "--security-opt", "no-new-privileges",
    "--pids-limit", constraints.pids,
    "--memory", constraints.memory,
    "--cpus", constraints.cpus,
    ...Object.entries(expected.tmpfs).sort(([left], [right]) => left.localeCompare(right)).flatMap(([target, value]) => ["--tmpfs", `${target}:${value}`]),
    ...expected.mounts.flatMap((mount) => ["--mount", `type=bind,src=${mount.source},dst=${mount.target},readonly`]),
    ...labelArguments(expected.labels),
    ...environmentArguments(expected.environment),
    ...(expected.entrypoint ? ["--entrypoint", expected.entrypoint[0]] : []),
    expected.image,
    ...(expected.command ?? []),
  ];
}

export function buildSchemaCommands(specification, databaseId) {
  expectSpecification(specification);
  if (!idPattern.test(databaseId)) throw new TypeError("database identity is invalid");
  const expected = specification.database;
  const common = ["exec", databaseId, "psql", "--no-psqlrc", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", expected.user, "-d", expected.databaseName, "-c"];
  return Object.freeze({
    inspect: [...common, `SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname IN ('${expected.schema}', '${expected.recordsSchema}') ORDER BY nspname;`],
    create: [...common, `CREATE SCHEMA "${expected.schema}" AUTHORIZATION "${expected.user}"; CREATE SCHEMA "${expected.recordsSchema}" AUTHORIZATION "${expected.user}";`],
    expected: `${expected.schema}\n${expected.recordsSchema}\n`,
  });
}

export function parseWrapperOutput(value) {
  if (!Buffer.isBuffer(value) || value.byteLength === 0 || value.byteLength > maximumCommandBytes) throw normalizationError();
  let parsed;
  try { parsed = parseBoundedUniqueJson(value); } catch { throw normalizationError(); }
  if (
    !plainObject(parsed) || !sameKeys(parsed, ["connectionId", "event", "integrationKey", "organizationId"]) ||
    !organizationPattern.test(parsed.organizationId) || !integrationPattern.test(parsed.integrationKey) ||
    !connectionPattern.test(parsed.connectionId) ||
    !plainObject(parsed.event) || !sameKeys(parsed.event, ["action", "id"]) ||
    parsed.event.id !== "11111111-1111-4111-8111-111111111111" || parsed.event.action !== "item.usage" ||
    parsed.integrationKey !== `zasp-m0-15-${parsed.organizationId.slice(4)}-1password-events`
  ) throw normalizationError();
  return Object.freeze({ ...parsed, event: Object.freeze({ ...parsed.event }) });
}

export async function orchestrate(runtime, options = {}) {
  if (!runtime || typeof runtime !== "object") throw operationError();
  const mainTimeout = options.mainTimeoutMs ?? mainTimeoutMilliseconds;
  const cleanupTimeout = options.cleanupTimeoutMs ?? cleanupTimeoutMilliseconds;
  let mainError;
  let cleanupError;
  try {
    await runPhase(mainTimeout, async (signal) => {
      for (const operation of [
        "initialize", "requireInitialAbsence", "resolveImages", "createNetwork",
        "createDatabase", "startDatabase", "waitDatabase", "prepareDatabase",
        "createNango", "startNango", "waitNango", "createFixture", "startFixture",
        "createWrapper", "startWrapper", "verifyReady",
      ]) await requireOperation(runtime, operation)(signal);
    });
  } catch (error) { mainError = error; }
  try {
    await runPhase(cleanupTimeout, async (signal) => {
      let firstError;
      for (const operation of ["settleMutations", "cleanup", "settleMutations", "requireFinalAbsence"]) {
        try { await requireOperation(runtime, operation)(signal); }
        catch (error) { firstError ??= error; }
      }
      if (firstError !== undefined) throw firstError;
    });
  } catch (error) { cleanupError = error; }
  if (cleanupError !== undefined) throw cleanupError.category === "cleanup" ? cleanupError : cleanupErrorWithCause(cleanupError);
  if (mainError !== undefined) throw mainError;
  return { proxy: true, reference: true, productStateSafe: true, cleanup: true };
}

export async function runMain(dependencies = {}) {
  const writeLine = dependencies.writeLine ?? ((line) => process.stdout.write(`${line}\n`));
  try {
    const runtime = dependencies.runtime ?? new DockerNangoProxyRuntime({
      pathValue: dependencies.pathValue ?? process.env.PATH,
      platform: dependencies.platform ?? (process.arch === "arm64" ? "linux/arm64" : "linux/amd64"),
      tempParent: dependencies.tempParent ?? tmpdir(),
      markerSource: dependencies.markerSource,
    });
    await orchestrate(runtime, dependencies.timeouts);
    writeLine(SUCCESS_LINE);
    return 0;
  } catch (error) {
    writeLine(`${allowedCategory(error?.category)} rejected.`);
    return 1;
  }
}

export class DockerNangoProxyRuntime {
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
    return this.#journal(() => this.#initialize(signal));
  }

  async #initialize(signal) {
    assertActive(signal);
    if (!isAbsolute(this.tempParent) || !["linux/amd64", "linux/arm64"].includes(this.platform) || typeof this.pathValue !== "string" || this.pathValue.length === 0 || this.pathValue.includes("\0")) throw configurationError();
    this.tempParent = await this.filesystem.realpath(this.tempParent);
    assertActive(signal);
    validateProxyTemporaryPrefixEntries(await this.filesystem.readdir(this.tempParent));
    const marker = validateProxyMarker(this.markerSource());
    const proofSourcePath = resolve(fileURLToPath(new URL("..", import.meta.url)));
    this.workspace = await createProxyWorkspace({ marker, tempParent: this.tempParent, proofSourcePath });
    this.environment = { PATH: this.pathValue, DOCKER_CONFIG: this.workspace.dockerConfig.path };
    this.specification = buildProxyRuntimeSpec({ ...this.workspace.runtimeInput, platform: this.platform });
    assertActive(signal);
  }

  async requireInitialAbsence(signal) { await this.#requireGlobalAbsence(signal); }

  async resolveImages(signal) {
    for (const role of this.specification.roles) {
      this.images.set(role, await this.#resolveImage(this.specification[role], signal));
    }
  }

  async createNetwork(signal) {
    await this.#journal(() => this.#createResource("network", buildNetworkCreateArguments(this.specification), signal));
    await this.#verifyNetwork(signal);
  }

  async createDatabase(signal) { await this.#createContainer("database", signal); }
  async startDatabase(signal) { await this.#startContainer("database", signal); }

  async waitDatabase(signal) {
    const expected = this.specification.database;
    for (let attempt = 0; attempt < 120; attempt += 1) {
      assertActive(signal);
      const ready = await this.#docker(["exec", this.resources.get("database").id, "pg_isready", "-q", "-U", expected.user, "-d", expected.databaseName], 5_000, signal);
      if (quietStatus(ready, 0)) {
        const query = await this.#docker(["exec", this.resources.get("database").id, "psql", "--no-psqlrc", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", expected.user, "-d", expected.databaseName, "-c", "SELECT 1;"], 5_000, signal);
        const state = classifyDatabaseQueryResult(query);
        if (state === "ready") return;
        if (state === "invalid") throw providerError();
      } else if (!(ready.signal === null && [1, 2].includes(ready.status) && ready.stdout === "" && ready.stderr === "")) throw providerError();
      await delay(500, signal);
    }
    throw proxyError();
  }

  async prepareDatabase(signal) { return this.#journal(() => this.#prepareDatabase(signal)); }

  async #prepareDatabase(signal) {
    const commands = buildSchemaCommands(this.specification, this.resources.get("database").id);
    const before = await this.#readSchema(commands.inspect, signal);
    if (before.stdout !== "") throw ownershipError();
    const result = await this.#dockerMutation(commands.create, 10_000, signal);
    if (emptyMutationClassification(result) === "definitive") throw providerError();
    const after = await this.#readSchema(commands.inspect, signal);
    if (after.stdout !== commands.expected) throw ownershipError();
  }

  async #readSchema(arguments_, signal) {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const result = await this.#docker(arguments_, 5_000, signal);
      if (result.status === 0 && result.signal === null && result.stderr === "") return result;
      if (attempt === 0) await delay(100, signal);
    }
    throw providerError();
  }

  async createNango(signal) { await this.#createContainer("nango", signal); }
  async startNango(signal) { await this.#startContainer("nango", signal); }

  async waitNango(signal) {
    const script = [
      "const http=require('node:http');",
      "const request=http.get('http://127.0.0.1:3003/ready',(response)=>{",
      "let body='';response.setEncoding('utf8');response.on('data',(value)=>body+=value);",
      "response.on('end',()=>process.exit(response.statusCode===200&&body==='\\\"result\\\":\\\"ok\\\"'.replace(/^/,'{').concat('}')?0:2));});",
      "request.setTimeout(2000,()=>request.destroy());request.on('error',()=>process.exit(1));",
    ].join("");
    for (let attempt = 0; attempt < 120; attempt += 1) {
      const result = await this.#docker(["exec", this.resources.get("nango").id, "node", "-e", script], 5_000, signal);
      if (result.status === 0 && result.signal === null && result.stdout === "" && result.stderr === "") return;
      if (!(result.signal === null && [1, 2].includes(result.status) && result.stdout === "" && result.stderr === "")) throw providerError();
      await delay(500, signal);
    }
    throw proxyError();
  }

  async createFixture(signal) { await this.#createContainer("fixture", signal); }

  async startFixture(signal) {
    await this.#startContainer("fixture", signal);
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const result = await this.#docker(["logs", this.resources.get("fixture").id], 5_000, signal);
      if (result.status === 0 && result.signal === null && result.stdout === "Nango proxy fixture ready.\n" && result.stderr === "") return;
      if (!(result.status === 0 && result.signal === null && result.stdout === "" && result.stderr === "")) throw providerError();
      await delay(100, signal);
    }
    throw proxyError();
  }

  async createWrapper(signal) { await this.#createContainer("wrapper", signal); }

  async startWrapper(signal) {
    return this.#journal(() => this.#startWrapper(signal));
  }

  async #startWrapper(signal) {
    const resource = this.resources.get("wrapper");
    await this.#verifyContainer("wrapper", signal, "created");
    const result = await this.#dockerMutation(["start", "--attach", resource.id], 240_000, signal);
    const classification = emptyMutationClassification(result);
    if (classification === "definitive") throw proxyError();
    if (result.status === 0 && result.signal === null && result.stderr === "") this.wrapperOutput = Buffer.from(result.stdout);
    else {
      await this.#reconcileStopped("wrapper", signal);
      const logs = await this.#docker(["logs", resource.id], commandTimeoutMilliseconds, signal);
      if (logs.status !== 0 || logs.signal !== null || logs.stderr !== "") throw proxyError();
      this.wrapperOutput = Buffer.from(logs.stdout);
    }
    resource.attached = false;
    await this.#verifyContainer("wrapper", signal, "exited");
    await this.#verifyNetwork(signal);
  }

  async verifyReady(signal) {
    assertActive(signal);
    const result = parseWrapperOutput(this.wrapperOutput);
    if (result.organizationId !== this.specification.wrapper.environment.NANGO_PROXY_ORGANIZATION_ID || result.integrationKey !== this.specification.wrapper.environment.NANGO_PROXY_INTEGRATION_KEY) throw normalizationError();
    await this.#verifyContainer("database", signal, "running");
    await this.#verifyContainer("nango", signal, "running");
    await this.#verifyContainer("fixture", signal, "running");
    await this.#verifyContainer("wrapper", signal, "exited");
    await this.#verifyNetwork(signal);
  }

  async settleMutations(signal) {
    const settlements = this.mutationSettlements.splice(0);
    if (settlements.length > 0) await abortable(Promise.allSettled(settlements), signal);
  }

  async cleanup(signal) {
    let firstError;
    for (const role of ["wrapper", "fixture", "nango", "database"]) {
      try { await this.#removeContainer(role, signal); }
      catch (error) { firstError ??= error; }
    }
    try { await this.#removeNetwork(signal); }
    catch (error) { firstError ??= error; }
    if (firstError !== undefined) throw cleanupErrorWithCause(firstError);
  }

  async requireFinalAbsence(signal) {
    let firstError;
    let globalAbsence = false;
    try { await this.#requireGlobalAbsence(signal); globalAbsence = true; }
    catch (error) { firstError = error; }
    if (globalAbsence && this.workspace !== undefined) {
      try { await removeProxyWorkspace(this.workspace); this.workspace = undefined; }
      catch (error) { firstError ??= error; }
    }
    try { validateProxyTemporaryPrefixEntries(await this.filesystem.readdir(this.tempParent)); }
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
    const digest = expected.image.slice(expected.image.lastIndexOf("@") + 1);
    if (
      !imageIdPattern.test(document.Id) || document.Os !== "linux" || `linux/${document.Architecture}` !== expected.platform ||
      !Array.isArray(document.RepoDigests) || !document.RepoDigests.some((value) => value.endsWith(`@${digest}`)) ||
      !Array.isArray(document.Env) || !(document.Entrypoint === null || Array.isArray(document.Entrypoint)) ||
      !(document.Cmd === null || Array.isArray(document.Cmd)) || typeof document.User !== "string" ||
      !(document.Labels === null || plainObject(document.Labels)) || !(document.ExposedPorts === null || plainObject(document.ExposedPorts)) ||
      !(document.Volumes === null || plainObject(document.Volumes)) ||
      (["nango", "fixture", "wrapper"].includes(expected.role) && document.Id !== PROXY_PINS.nango.configDigest)
    ) throw providerError();
    return document;
  }

  async #createContainer(role, signal) {
    await this.#journal(() => this.#createResource(role, buildContainerCreateArguments(this.specification, role), signal));
    await this.#verifyContainer(role, signal, "created");
    await this.#verifyNetwork(signal);
  }

  async #createResource(role, arguments_, signal) {
    const expected = role === "network" ? this.specification.network : this.specification[role];
    const resource = { role, name: expected.name, mayHaveApplied: true, attached: false };
    this.resources.set(role, resource);
    const result = await this.#dockerMutation(arguments_, commandTimeoutMilliseconds, signal);
    const classification = classifyMutationResult(result);
    if (classification === "definitive") { this.resources.delete(role); throw providerError(); }
    const directId = exactId(result.stdout);
    if (directId !== undefined) resource.id = directId;
    if (classification === "ambiguous") await this.#reconcileResource(role, signal);
  }

  async #reconcileResource(role, signal) {
    const resource = this.resources.get(role);
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const ids = await this.#listExactName(resource.name, role === "network", signal);
      if (ids.length > 1) throw ownershipError();
      if (ids.length === 1) {
        resource.id = ids[0];
        if (role === "network") await this.#verifyNetwork(signal);
        else await this.#verifyContainer(role, signal, "created");
        return;
      }
      if (attempt < 29) await delay(100, signal);
    }
    throw ownershipError();
  }

  async #startContainer(role, signal) {
    return this.#journal(() => this.#startContainerOperation(role, signal));
  }

  async #startContainerOperation(role, signal) {
    const resource = this.resources.get(role);
    await this.#verifyContainer(role, signal, "created");
    const result = await this.#dockerMutation(["start", resource.id], commandTimeoutMilliseconds, signal);
    const classification = exactMutationClassification(result, `${resource.id}\n`);
    if (classification === "definitive") throw providerError();
    if (classification === "ambiguous") await this.#reconcileRunning(role, signal);
    else await this.#verifyContainer(role, signal, "running");
    await this.#verifyNetwork(signal);
  }

  async #reconcileRunning(role, signal) {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const document = await this.#verifyContainer(role, signal, undefined, true);
      if (document.State.Status === "running") return;
      if (document.State.Status !== "created") throw providerError();
      if (attempt < 29) await delay(100, signal);
    }
    throw providerError();
  }

  async #reconcileStopped(role, signal) {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const document = await this.#verifyContainer(role, signal, undefined, true);
      if (document.State.Status === "exited") return;
      if (!["created", "running"].includes(document.State.Status)) throw proxyError();
      if (attempt < 29) await delay(100, signal);
    }
    throw proxyError();
  }

  async #verifyContainer(role, signal, expectedState, cleanup = false) {
    const resource = this.resources.get(role);
    if (resource?.id === undefined) throw ownershipError();
    const result = await this.#docker(["container", "inspect", "--format", CONTAINER_INSPECTION_FORMAT, resource.id], commandTimeoutMilliseconds, signal);
    if (result.status !== 0 || result.signal !== null || result.stderr !== "") throw ownershipError();
    const document = parseContainerInspectionResult(result.stdout.trimEnd());
    validateProxyContainerIdentity(document, {
      resource,
      expected: this.specification[role],
      image: this.images.get(role),
      networkName: this.specification.network.name,
      networkId: this.resources.get("network")?.id,
      expectedState,
      cleanup,
    });
    if (document.State.Status === "running") {
      const attachment = document.NetworkSettings.Networks[this.specification.network.name];
      const state = {
        NetworkID: attachment.NetworkID,
        EndpointID: attachment.EndpointID,
        Gateway: attachment.Gateway,
        MacAddress: attachment.MacAddress,
        IPv4Address: `${attachment.IPAddress}/${attachment.IPPrefixLen}`,
      };
      if (resource.networkState === undefined) resource.networkState = state;
      else if (!isDeepStrictEqual(resource.networkState, state)) throw ownershipError();
    }
    resource.attached = document.State.Status === "running";
    return document;
  }

  async #verifyNetwork(signal) {
    const resource = this.resources.get("network");
    if (resource?.id === undefined) throw ownershipError();
    const result = await this.#docker(["network", "inspect", "--format", NETWORK_INSPECTION_FORMAT, resource.id], commandTimeoutMilliseconds, signal);
    if (result.status !== 0 || result.signal !== null || result.stderr !== "") throw ownershipError();
    const document = parseNetworkInspectionResult(result.stdout.trimEnd());
    const peers = this.specification.roles.filter((role) => this.resources.get(role)?.attached === true).map((role) => this.resources.get(role));
    validateNetworkIdentity(document, resource, this.specification.network, peers);
    const staticState = { ...document, Containers: undefined };
    delete staticState.Containers;
    if (resource.staticState === undefined) resource.staticState = staticState;
    else if (!isDeepStrictEqual(resource.staticState, staticState)) throw ownershipError();
  }

  async #coherentCleanupSnapshot(role, signal) {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      try {
        const documents = new Map();
        for (const candidateRole of ["wrapper", "fixture", "nango", "database"]) {
          if (this.resources.get(candidateRole)?.id !== undefined) documents.set(candidateRole, await this.#verifyContainer(candidateRole, signal, undefined, true));
        }
        await this.#verifyNetwork(signal);
        const document = documents.get(role);
        if (document === undefined) throw ownershipError();
        return document;
      } catch (error) {
        if (attempt === 29) throw error;
        await delay(100, signal);
      }
    }
    throw ownershipError();
  }

  async #removeContainer(role, signal) {
    const resource = this.resources.get(role);
    if (resource === undefined) return;
    if (resource.id === undefined && !await this.#recoverCandidate(resource, false, signal)) { this.resources.delete(role); return; }
    const document = await this.#coherentCleanupSnapshot(role, signal);
    const result = await this.#dockerMutation(["rm", "--force", "--volumes", document.Id], commandTimeoutMilliseconds, signal);
    if (exactMutationClassification(result, `${document.Id}\n`) === "definitive") throw ownershipError();
    await this.#requireRemoved(resource, false, signal);
    this.resources.delete(role);
  }

  async #removeNetwork(signal) {
    const resource = this.resources.get("network");
    if (resource === undefined) return;
    if (resource.id === undefined && !await this.#recoverCandidate(resource, true, signal)) { this.resources.delete("network"); return; }
    await this.#verifyNetwork(signal);
    const result = await this.#dockerMutation(["network", "rm", resource.id], commandTimeoutMilliseconds, signal);
    if (exactMutationClassification(result, `${resource.id}\n`) === "definitive") throw ownershipError();
    await this.#requireRemoved(resource, true, signal);
    this.resources.delete("network");
  }

  async #recoverCandidate(resource, network, signal) {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const ids = await this.#listExactName(resource.name, network, signal);
      if (ids.length > 1) throw ownershipError();
      if (ids.length === 1) { resource.id = ids[0]; return true; }
      if (attempt < 29) await delay(100, signal);
    }
    return false;
  }

  async #requireRemoved(resource, network, signal) {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const names = await this.#listExactName(resource.name, network, signal);
      const result = await this.#docker(network
        ? ["network", "ls", "--no-trunc", "--filter", `id=${resource.id}`, "--format", "{{.ID}}"]
        : ["ps", "-a", "--no-trunc", "--filter", `id=${resource.id}`, "--format", "{{.ID}}"], commandTimeoutMilliseconds, signal);
      if (result.status !== 0 || result.signal !== null || result.stderr !== "") throw ownershipError();
      if (names.length === 0 && result.stdout === "") return;
      if (attempt < 29) await delay(100, signal);
    }
    throw ownershipError();
  }

  async #requireGlobalAbsence(signal) {
    const prefix = "zasp-m0-15-";
    const commands = [
      ["ps", "-a", "--no-trunc", "--filter", `name=^/${prefix}`, "--format", "{{.ID}}"],
      ["ps", "-a", "--no-trunc", "--filter", `label=zasp.dev/proof=${PROXY_PROOF_LABEL}`, "--format", "{{.ID}}"],
      ["network", "ls", "--no-trunc", "--filter", `name=^${prefix}`, "--format", "{{.ID}}"],
      ["network", "ls", "--no-trunc", "--filter", `label=zasp.dev/proof=${PROXY_PROOF_LABEL}`, "--format", "{{.ID}}"],
    ];
    if (this.specification !== undefined) commands.push(
      ["ps", "-a", "--no-trunc", "--filter", `label=zasp.dev/run=${this.specification.marker}`, "--format", "{{.ID}}"],
      ["network", "ls", "--no-trunc", "--filter", `label=zasp.dev/run=${this.specification.marker}`, "--format", "{{.ID}}"],
    );
    for (const arguments_ of commands) {
      const result = await this.#docker(arguments_, commandTimeoutMilliseconds, signal);
      if (result.status !== 0 || result.signal !== null || result.stdout !== "" || result.stderr !== "") throw ownershipError();
    }
  }

  async #listExactName(name, network, signal) {
    const result = await this.#docker(network
      ? ["network", "ls", "--no-trunc", "--filter", `name=^${name}$`, "--format", "{{.ID}}"]
      : ["ps", "-a", "--no-trunc", "--filter", `name=^/${name}$`, "--format", "{{.ID}}"], commandTimeoutMilliseconds, signal);
    if (result.status !== 0 || result.signal !== null || result.stderr !== "") throw providerError();
    const ids = result.stdout === "" ? [] : result.stdout.trimEnd().split("\n");
    if (new Set(ids).size !== ids.length || ids.some((id) => !idPattern.test(id))) throw providerError();
    return ids;
  }

  async #docker(arguments_, timeoutMs, signal) {
    assertActive(signal);
    if (this.workspace !== undefined) await reproveProxyWorkspace(this.workspace);
    try { return await this.command("docker", arguments_, { env: this.environment, timeoutMs, outputLimit: maximumCommandBytes, signal }, this.spawnProcess); }
    catch { return { thrown: true, status: null, signal: null, stdout: "", stderr: "" }; }
  }

  #dockerMutation(arguments_, timeoutMs, signal) {
    const operation = this.#docker(arguments_, timeoutMs, signal);
    this.mutationSettlements.push(operation.then(
      (value) => ({ state: "fulfilled", value }),
      (error) => ({ state: "rejected", error }),
    ));
    return operation;
  }

  #journal(factory) {
    const operation = Promise.resolve().then(factory);
    this.mutationSettlements.push(operation.then(
      (value) => ({ state: "fulfilled", value }),
      (error) => ({ state: "rejected", error }),
    ));
    return operation;
  }
}

export function validateProxyContainerIdentity(document, { resource, expected, image, networkName, networkId, expectedState, cleanup = false }) {
  if (!plainObject(document) || !plainObject(resource) || !plainObject(expected) || !plainObject(image)) throw ownershipError();
  const allowedState = cleanup
    ? [[true, "running"], [false, "created"], [false, "exited"]].some(([running, status]) => document.State?.Running === running && document.State?.Status === status)
    : expectedState === undefined
      ? [[true, "running"], [false, "created"], [false, "exited"]].some(([running, status]) => document.State?.Running === running && document.State?.Status === status)
      : document.State?.Running === (expectedState === "running") && document.State?.Status === expectedState;
  const expectedEntrypoint = expected.entrypoint ?? image.Entrypoint;
  const expectedCommand = expected.command ?? image.Cmd;
  const constraints = expected.role === "database"
    ? { pids: 128, memory: 402_653_184, nano: 500_000_000, capAdd: ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID"] }
    : expected.role === "nango"
      ? { pids: 256, memory: 805_306_368, nano: 1_000_000_000, capAdd: null }
      : { pids: 64, memory: 134_217_728, nano: 500_000_000, capAdd: null };
  if (
    document.Id !== resource.id || document.Name !== `/${resource.name}` || document.Image !== image.Id ||
    document.Config?.Image !== expected.image || document.Config?.User !== image.User ||
    !isDeepStrictEqual(document.Config?.Entrypoint, expectedEntrypoint) || !isDeepStrictEqual(document.Config?.Cmd, expectedCommand) ||
    !isDeepStrictEqual(document.Config?.ExposedPorts, image.ExposedPorts) ||
    !exactMergedObject(document.Config?.Labels, image.Labels, expected.labels) || !exactEnvironment(document.Config?.Env, image.Env, expected.environment) ||
    document.HostConfig?.NetworkMode !== networkName || document.HostConfig?.ReadonlyRootfs !== true ||
    !isDeepStrictEqual(document.HostConfig?.CapAdd, constraints.capAdd) || !isDeepStrictEqual(document.HostConfig?.CapDrop, ["ALL"]) ||
    !isDeepStrictEqual(document.HostConfig?.SecurityOpt, ["no-new-privileges"]) ||
    document.HostConfig?.PidsLimit !== constraints.pids || document.HostConfig?.Memory !== constraints.memory || document.HostConfig?.NanoCpus !== constraints.nano ||
    !isDeepStrictEqual(document.HostConfig?.PortBindings, {}) || ![null, []].some((value) => isDeepStrictEqual(document.HostConfig?.Binds, value)) ||
    !exactHostMounts(document.HostConfig?.Mounts, expected.mounts) || !isDeepStrictEqual(document.HostConfig?.Tmpfs, expected.tmpfs) ||
    !isDeepStrictEqual(document.HostConfig?.RestartPolicy, { Name: "no", MaximumRetryCount: 0 }) || document.HostConfig?.Privileged !== false ||
    !isDeepStrictEqual(document.HostConfig?.Devices, []) || document.HostConfig?.DeviceRequests !== null || document.HostConfig?.PidMode !== "" ||
    !["", "private"].includes(document.HostConfig?.IpcMode) || !["", "private"].includes(document.HostConfig?.CgroupnsMode) || document.HostConfig?.UsernsMode !== "" ||
    !allowedState || !plainObject(document.NetworkSettings?.Networks) || !isDeepStrictEqual(Object.keys(document.NetworkSettings.Networks), [networkName]) ||
    !validAttachment(document.NetworkSettings.Networks[networkName], expected.name, expected.networkAlias, networkId, resource.id, document.State.Status) ||
    !validUnpublishedPorts(document.NetworkSettings?.Ports, image.ExposedPorts, document.State.Status) ||
    !exactRuntimeMounts(document.Mounts, expected.mounts, expected.tmpfs, document.State.Status)
  ) throw ownershipError();
  return true;
}

function expectSpecification(value) {
  if (!plainObject(value) || value.prefix !== `zasp-m0-15-${value.marker}` || value.network?.labels?.["zasp.dev/proof"] !== PROXY_PROOF_LABEL || !Array.isArray(value.roles)) throw new TypeError("proxy runtime specification is invalid");
}

function labelArguments(labels) {
  return Object.entries(labels).sort(([left], [right]) => left.localeCompare(right)).flatMap(([key, value]) => ["--label", `${key}=${value}`]);
}

function environmentArguments(environment) {
  return Object.entries(environment).sort(([left], [right]) => left.localeCompare(right)).flatMap(([key, value]) => ["--env", `${key}=${value}`]);
}

function sameKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function exactMergedObject(actual, base, overlay) {
  return plainObject(actual) && isDeepStrictEqual(actual, { ...(base ?? {}), ...overlay });
}

function exactEnvironment(actual, base, overlay) {
  if (!Array.isArray(actual) || actual.some((entry) => typeof entry !== "string" || !entry.includes("="))) return false;
  const expected = new Map();
  for (const entry of base ?? []) expected.set(entry.slice(0, entry.indexOf("=")), entry);
  for (const [key, value] of Object.entries(overlay)) expected.set(key, `${key}=${value}`);
  const observed = new Map(actual.map((entry) => [entry.slice(0, entry.indexOf("=")), entry]));
  return actual.length === expected.size && observed.size === expected.size && [...expected].every(([key, value]) => observed.get(key) === value);
}

function exactHostMounts(actual, expected) {
  if (expected.length === 0) return actual === null || (Array.isArray(actual) && actual.length === 0);
  if (!Array.isArray(actual) || actual.length !== expected.length) return false;
  const normalize = (value) => plainObject(value) ? {
    Type: value.Type,
    Source: value.Source,
    Target: value.Target,
    ReadOnly: value.ReadOnly,
    Consistency: value.Consistency ?? "",
  } : undefined;
  const observed = actual.map(normalize).sort((left, right) => left?.Target.localeCompare(right?.Target));
  const wanted = expected.map((value) => ({ Type: "bind", Source: value.source, Target: value.target, ReadOnly: true, Consistency: "" })).sort((left, right) => left.Target.localeCompare(right.Target));
  return isDeepStrictEqual(observed, wanted);
}

function exactRuntimeMounts(actual, expectedBinds, expectedTmpfs) {
  if (!Array.isArray(actual)) return false;
  const binds = actual.filter((value) => value?.Type === "bind").map((value) => ({ Source: value.Source, Destination: value.Destination, RW: value.RW })).sort((left, right) => left.Destination.localeCompare(right.Destination));
  const wantedBinds = expectedBinds.map((value) => ({ Source: value.source, Destination: value.target, RW: false })).sort((left, right) => left.Destination.localeCompare(right.Destination));
  const tmpfs = actual.filter((value) => value?.Type === "tmpfs").map((value) => value.Destination).sort();
  const wantedTmpfs = Object.keys(expectedTmpfs).sort();
  // Docker Desktop may omit tmpfs entries from `.Mounts` even while the exact
  // HostConfig.Tmpfs map is active. Bind mounts remain authorization-relevant
  // here; tmpfs is exact through HostConfig and may be absent or duplicated in
  // the runtime projection.
  const tmpfsExact = tmpfs.length === 0 || isDeepStrictEqual(tmpfs, wantedTmpfs);
  return actual.every((value) => ["bind", "tmpfs"].includes(value?.Type)) && isDeepStrictEqual(binds, wantedBinds) && tmpfsExact;
}

function validAttachment(value, name, alias, networkId, resourceId, status) {
  if (!plainObject(value) || !exactAttachmentKeys(value) || !isDeepStrictEqual(value.Aliases, [alias]) || value.IPAMConfig !== null || value.Links !== null || value.DriverOpts !== null || value.GwPriority !== 0) return false;
  if (status === "created") {
    return value.DNSNames === null && value.NetworkID === "" && value.EndpointID === "" && value.Gateway === "" && value.IPAddress === "" && value.IPPrefixLen === 0 && value.MacAddress === "" && value.IPv6Gateway === "" && value.GlobalIPv6Address === "" && value.GlobalIPv6PrefixLen === 0;
  }
  if (!idPattern.test(networkId ?? "") || !idPattern.test(resourceId ?? "")) return false;
  const dnsNames = alias === name ? [name, resourceId.slice(0, 12)] : [name, alias, resourceId.slice(0, 12)];
  if (!isDeepStrictEqual(value.DNSNames, dnsNames) || value.NetworkID !== networkId || value.Gateway !== "" || value.IPv6Gateway !== "" || value.GlobalIPv6Address !== "" || value.GlobalIPv6PrefixLen !== 0) return false;
  if (status === "exited") return value.EndpointID === "" && value.IPAddress === "" && value.IPPrefixLen === 0 && value.MacAddress === "";
  const address = ipv4Integer(value.IPAddress);
  return status === "running" && idPattern.test(value.EndpointID ?? "") && address !== undefined && privateIPv4(address) && Number.isInteger(value.IPPrefixLen) && value.IPPrefixLen >= 16 && value.IPPrefixLen <= 29 && /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(value.MacAddress ?? "");
}

function exactAttachmentKeys(value) {
  return isDeepStrictEqual(Object.keys(value).sort(), [
    "Aliases", "DNSNames", "DriverOpts", "EndpointID", "Gateway", "GlobalIPv6Address",
    "GlobalIPv6PrefixLen", "GwPriority", "IPAMConfig", "IPAddress", "IPPrefixLen",
    "IPv6Gateway", "Links", "MacAddress", "NetworkID",
  ]);
}

function ipv4Integer(value) {
  if (typeof value !== "string") return undefined;
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(?:0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)) return undefined;
  return parts.reduce((output, part) => ((output << 8) | Number(part)) >>> 0, 0);
}

function privateIPv4(value) {
  return (value >= 0x0a000000 && value <= 0x0affffff) || (value >= 0xac100000 && value <= 0xac1fffff) || (value >= 0xc0a80000 && value <= 0xc0a8ffff);
}

function unpublishedPorts(value) {
  if (value === null || value === undefined) return {};
  if (!plainObject(value)) throw ownershipError();
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, null]));
}

function validUnpublishedPorts(actual, exposed, status) {
  if (status === "created") return isDeepStrictEqual(actual, {});
  const configured = unpublishedPorts(exposed);
  return isDeepStrictEqual(actual, configured) || (status === "exited" && isDeepStrictEqual(actual, {}));
}

function exactMissingImage(result, reference) {
  return plainObject(result) && result.status === 1 && result.signal === null && (result.stdout === "" || result.stdout === "\n") && result.stderr === `Error response from daemon: No such image: ${reference}\n`;
}

function exactId(value) {
  if (typeof value !== "string") return undefined;
  const candidate = value.endsWith("\n") ? value.slice(0, -1) : value;
  return idPattern.test(candidate) ? candidate : undefined;
}

function exactMutationClassification(result, stdout) {
  if (!plainObject(result) || result.thrown === true || result.signal !== null) return "ambiguous";
  if (result.status !== 0) return "definitive";
  return result.stdout === stdout && result.stderr === "" ? "applied" : "ambiguous";
}

function emptyMutationClassification(result) {
  if (!plainObject(result) || result.thrown === true || result.signal !== null) return "ambiguous";
  if (result.status !== 0) return "definitive";
  return result.stdout === "" && result.stderr === "" ? "applied" : "ambiguous";
}

function quietStatus(result, status) {
  return plainObject(result) && result.status === status && result.signal === null && result.stdout === "" && result.stderr === "";
}

export function classifyDatabaseQueryResult(result) {
  if (!plainObject(result) || typeof result.stdout !== "string" || typeof result.stderr !== "string" || result.stdout.length + result.stderr.length > maximumCommandBytes) return "invalid";
  if (result.status === 0 && result.signal === null && result.stdout === "1\n" && result.stderr === "") return "ready";
  if (result.status === 2 && result.signal === null && result.stdout === "") return "pending";
  return "invalid";
}

function requireOperation(runtime, name) {
  const operation = runtime[name];
  if (typeof operation !== "function") throw operationError();
  return operation.bind(runtime);
}

function allowedCategory(category) {
  return new Set(["configuration", "provider", "proxy", "normalization", "ownership", "cleanup", "operation"]).has(category) ? category : "operation";
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function assertActive(signal) { if (signal?.aborted === true) throw operationError(); }
function delay(milliseconds, signal) {
  return new Promise((resolve_, reject) => {
    const timer = setTimeout(resolve_, milliseconds);
    signal?.addEventListener?.("abort", () => { clearTimeout(timer); reject(operationError()); }, { once: true });
  });
}
function abortable(operation, signal) {
  if (signal?.aborted === true) return Promise.reject(operationError());
  if (typeof signal?.addEventListener !== "function") return operation;
  return new Promise((resolve_, reject) => {
    const aborted = () => reject(operationError());
    signal.addEventListener("abort", aborted, { once: true });
    operation.then(resolve_, reject).finally(() => signal.removeEventListener("abort", aborted));
  });
}
function configurationError() { return Object.assign(new Error("configuration rejected"), { category: "configuration" }); }
function providerError() { return Object.assign(new Error("provider rejected"), { category: "provider" }); }
function proxyError() { return Object.assign(new Error("proxy rejected"), { category: "proxy" }); }
function normalizationError() { return Object.assign(new Error("normalization rejected"), { category: "normalization" }); }
function ownershipError() { return Object.assign(new Error("ownership rejected"), { category: "ownership" }); }
function operationError() { return Object.assign(new Error("operation rejected"), { category: "operation" }); }
function cleanupErrorWithCause(cause) { return Object.assign(new Error("cleanup rejected", { cause }), { category: "cleanup" }); }

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  process.exitCode = await runMain();
}
