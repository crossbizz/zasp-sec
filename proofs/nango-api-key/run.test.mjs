import assert from "node:assert/strict";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  DockerNangoApiKeyRuntime,
  SUCCESS_LINE,
  buildContainerCreateArguments,
  buildNetworkCreateArguments,
  buildSchemaCommands,
  classifyMutationResult,
  orchestrate,
  parseWrapperOutput,
  runMain,
  validateApiKeyContainerIdentity,
} from "./run.mjs";
import { removeApiKeyWorkspace } from "./boundary.mjs";
import { API_KEY_PINS, buildApiKeyRuntimeSpec } from "./manifest.mjs";

const marker = "0123456789abcdef";
const containerId = "a".repeat(64);

function specification() {
  const root = `/private/tmp/zasp-m0-14c-${marker}-ABC123`;
  return buildApiKeyRuntimeSpec({
    marker,
    platform: "linux/arm64",
    password: "p".repeat(32),
    encryptionKey: Buffer.alloc(32, 7).toString("base64"),
    providerKey: `pk_${"a".repeat(32)}`,
    workspaceRoot: root,
    dockerConfigPath: `${root}/docker-config`,
    caCertificatePath: `${root}/tls/ca.crt`,
    fixtureCertificatePath: `${root}/tls/server.crt`,
    fixtureKeyPath: `${root}/tls/server.key`,
    proofSourcePath: "/safe/proofs",
  });
}

test("binds the fixed success line and strict mutation taxonomy", () => {
  assert.equal(SUCCESS_LINE, "Nango API key proof passed: api_key=true reference=true product_state_safe=true cleanup=true.");
  assert.equal(classifyMutationResult({ status: 0, signal: null, stdout: `${containerId}\n`, stderr: "" }), "applied");
  assert.equal(classifyMutationResult({ status: 1, signal: null, stdout: "", stderr: "rejected" }), "definitive");
  assert.equal(classifyMutationResult({ status: null, signal: "SIGKILL", stdout: "", stderr: "" }), "ambiguous");
  assert.equal(classifyMutationResult({ thrown: true }), "ambiguous");
});

test("builds one exact internal network and four hardened private containers", () => {
  const spec = specification();
  const network = buildNetworkCreateArguments(spec);
  assert.deepEqual(network, [
    "network", "create", "--internal",
    "--label", "zasp.dev/proof=m0-14c",
    "--label", "zasp.dev/role=network",
    "--label", `zasp.dev/run=${marker}`,
    spec.network.name,
  ]);
  for (const role of spec.roles) {
    const command = buildContainerCreateArguments(spec, role);
    assert.equal(command.includes("--publish"), false);
    assert.equal(command.includes("--network"), true);
    assert.equal(command.includes(spec.network.name), true);
    assert.equal(command.includes("--read-only"), true);
    assert.equal(command.includes("--cap-drop"), true);
    assert.equal(command.includes("ALL"), true);
    assert.equal(command.includes("--security-opt"), true);
    assert.equal(command.includes("no-new-privileges"), true);
    assert.equal(command.includes(spec[role].image), true);
  }
  assert.equal(buildContainerCreateArguments(spec, "fixture").includes("--network-alias"), true);
  assert.equal(buildContainerCreateArguments(spec, "wrapper").slice(-spec.wrapper.command.length).join("\0"), spec.wrapper.command.join("\0"));
  assert.throws(() => buildContainerCreateArguments(spec, "unknown"));
});

test("builds the exact M0-14c isolated schema inspect and mutation commands", () => {
  const spec = specification();
  const commands = buildSchemaCommands(spec, containerId);
  assert.deepEqual(commands.inspect.slice(0, 3), ["exec", containerId, "psql"]);
  assert.equal(commands.inspect.at(-1), "SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname IN ('nango', 'nango_records') ORDER BY nspname;");
  assert.equal(commands.create.at(-1), `CREATE SCHEMA "nango" AUTHORIZATION "${spec.database.user}"; CREATE SCHEMA "nango_records" AUTHORIZATION "${spec.database.user}";`);
  assert.equal(commands.expected, "nango\nnango_records\n");
});

test("accepts only the exact reference-only wrapper artifact", () => {
  const exact = JSON.stringify({ organizationId: `org_${marker}`, integrationKey: `zasp-m0-14c-${marker}-1password-events`, connectionId: "00000000-0000-4000-8000-0000000000b4" });
  assert.deepEqual(parseWrapperOutput(Buffer.from(`${exact}\n`)), JSON.parse(exact));
  for (const value of [
    `${exact}\ntrailing`,
    exact.replace("{", '{"organizationId":"duplicate",'),
    JSON.stringify({ ...JSON.parse(exact), accessToken: "forbidden" }),
    JSON.stringify({ ...JSON.parse(exact), organizationId: "wrong" }),
    JSON.stringify({ ...JSON.parse(exact), connectionId: `conn_${marker}` }),
    "not-json\n",
  ]) assert.throws(() => parseWrapperOutput(Buffer.from(value)));
});

test("binds complete fixture container security, environment, mounts, and inactive network state", () => {
  const spec = specification();
  const expected = spec.fixture;
  const image = {
    Id: `sha256:${"b".repeat(64)}`,
    Env: ["PATH=/usr/local/bin"],
    Entrypoint: ["/image-entrypoint"],
    Cmd: ["image-command"],
    User: "1000",
    Labels: { "org.opencontainers.image.title": "Nango" },
    ExposedPorts: { "3003/tcp": {} },
  };
  const hostMounts = expected.mounts.map((mount) => ({ Type: "bind", Source: mount.source, Target: mount.target, ReadOnly: true, Consistency: "" }));
  // Docker records bind mounts at create-time, but materializes tmpfs entries
  // in the runtime projection only after the container starts.
  const runtimeMounts = expected.mounts.map((mount) => ({ Type: "bind", Source: mount.source, Destination: mount.target, RW: false }));
  const document = {
    Id: containerId,
    Name: `/${expected.name}`,
    Image: image.Id,
    Config: {
      Image: expected.image,
      Labels: { ...image.Labels, ...expected.labels },
      Env: [...image.Env, ...Object.entries(expected.environment).map(([key, value]) => `${key}=${value}`)],
      Entrypoint: expected.entrypoint,
      Cmd: expected.command,
      User: image.User,
      ExposedPorts: image.ExposedPorts,
    },
    HostConfig: {
      NetworkMode: spec.network.name,
      ReadonlyRootfs: true,
      CapAdd: null,
      CapDrop: ["ALL"],
      SecurityOpt: ["no-new-privileges"],
      PidsLimit: 64,
      Memory: 134_217_728,
      NanoCpus: 500_000_000,
      PortBindings: {},
      Binds: null,
      Mounts: hostMounts,
      Tmpfs: expected.tmpfs,
      RestartPolicy: { Name: "no", MaximumRetryCount: 0 },
      Privileged: false,
      Devices: [],
      DeviceRequests: null,
      PidMode: "",
      IpcMode: "private",
      CgroupnsMode: "private",
      UsernsMode: "",
    },
    Mounts: runtimeMounts,
    State: { Running: false, Status: "created" },
    NetworkSettings: {
      Networks: { [spec.network.name]: {
        IPAMConfig: null,
        Links: null,
        Aliases: [expected.networkAlias],
        MacAddress: "",
        DriverOpts: null,
        GwPriority: 0,
        NetworkID: "",
        EndpointID: "",
        Gateway: "",
        IPAddress: "",
        IPPrefixLen: 0,
        IPv6Gateway: "",
        GlobalIPv6Address: "",
        GlobalIPv6PrefixLen: 0,
        DNSNames: null,
      } },
      Ports: {},
    },
  };
  const options = { resource: { id: containerId, name: expected.name }, expected, image, networkName: spec.network.name, networkId: "c".repeat(64), expectedState: "created" };
  assert.equal(validateApiKeyContainerIdentity(document, options), true);
  const running = structuredClone(document);
  running.State = { Running: true, Status: "running" };
  running.NetworkSettings.Networks[spec.network.name] = {
    IPAMConfig: null,
    Links: null,
    Aliases: [expected.networkAlias],
    DriverOpts: null,
    GwPriority: 0,
    NetworkID: options.networkId,
    EndpointID: "d".repeat(64),
    Gateway: "",
    IPAddress: "172.20.0.2",
    IPPrefixLen: 16,
    MacAddress: "02:42:ac:14:00:02",
    IPv6Gateway: "",
    GlobalIPv6Address: "",
    GlobalIPv6PrefixLen: 0,
    DNSNames: [expected.name, expected.networkAlias, containerId.slice(0, 12)],
  };
  running.NetworkSettings.Ports = { "3003/tcp": null };
  assert.equal(validateApiKeyContainerIdentity(running, { ...options, expectedState: "running" }), true);
  const exited = structuredClone(running);
  exited.State = { Running: false, Status: "exited" };
  exited.NetworkSettings.Networks[spec.network.name] = {
    IPAMConfig: null,
    Links: null,
    Aliases: [expected.networkAlias],
    DriverOpts: null,
    GwPriority: 0,
    NetworkID: options.networkId,
    EndpointID: "",
    Gateway: "",
    IPAddress: "",
    IPPrefixLen: 0,
    MacAddress: "",
    IPv6Gateway: "",
    GlobalIPv6Address: "",
    GlobalIPv6PrefixLen: 0,
    DNSNames: [expected.name, expected.networkAlias, containerId.slice(0, 12)],
  };
  exited.NetworkSettings.Ports = {};
  assert.equal(validateApiKeyContainerIdentity(exited, { ...options, expectedState: undefined, cleanup: true }), true);
  for (const mutate of [
    (value) => { value.HostConfig.Privileged = true; },
    (value) => { value.Config.Env.push("AWS_ACCESS_KEY_ID=ambient"); },
    (value) => { value.HostConfig.Mounts[0].Source = "/replacement"; },
    (value) => { value.Mounts.push({ Type: "bind", Source: "/extra", Destination: "/extra", RW: false }); },
    (value) => { value.NetworkSettings.Ports["443/tcp"] = null; },
    (value) => { value.NetworkSettings.Networks[spec.network.name].Aliases.push("unexpected"); },
    (value) => { value.NetworkSettings.Networks[spec.network.name].Unexpected = true; },
  ]) {
    const changed = structuredClone(document);
    mutate(changed);
    assert.throws(() => validateApiKeyContainerIdentity(changed, options));
  }
});

test("runs the exact dependency graph and reverse cleanup", async () => {
  const calls = [];
  const runtime = {};
  for (const name of [
    "initialize", "requireInitialAbsence", "resolveImages", "createNetwork",
    "createDatabase", "startDatabase", "waitDatabase", "prepareDatabase",
    "createNango", "startNango", "waitNango", "createFixture", "startFixture",
    "createWrapper", "startWrapper", "verifyReady",
    "settleMutations", "cleanup", "requireFinalAbsence",
  ]) runtime[name] = async () => { calls.push(name); };
  assert.deepEqual(await orchestrate(runtime, { mainTimeoutMs: 2_000, cleanupTimeoutMs: 2_000 }), {
    apiKey: true, reference: true, productStateSafe: true, cleanup: true,
  });
  assert.deepEqual(calls, [
    "initialize", "requireInitialAbsence", "resolveImages", "createNetwork",
    "createDatabase", "startDatabase", "waitDatabase", "prepareDatabase",
    "createNango", "startNango", "waitNango", "createFixture", "startFixture",
    "createWrapper", "startWrapper", "verifyReady",
    "settleMutations", "cleanup", "settleMutations", "requireFinalAbsence",
  ]);
});

test("continues cleanup and gives it precedence", async () => {
  const calls = [];
  const runtime = {
    initialize: async () => { throw Object.assign(new Error("main"), { category: "api_key" }); },
    settleMutations: async () => { calls.push("settle"); },
    cleanup: async () => { calls.push("cleanup"); throw Object.assign(new Error("cleanup"), { category: "cleanup" }); },
    requireFinalAbsence: async () => { calls.push("absence"); },
  };
  await assert.rejects(() => orchestrate(runtime, { mainTimeoutMs: 2_000, cleanupTimeoutMs: 2_000 }), (error) => error.category === "cleanup");
  assert.deepEqual(calls, ["settle", "cleanup", "settle", "absence"]);
});

test("keeps the top-level output fixed for success and failure", async () => {
  const lines = [];
  const runtime = {};
  for (const name of [
    "initialize", "requireInitialAbsence", "resolveImages", "createNetwork",
    "createDatabase", "startDatabase", "waitDatabase", "prepareDatabase",
    "createNango", "startNango", "waitNango", "createFixture", "startFixture",
    "createWrapper", "startWrapper", "verifyReady", "settleMutations", "cleanup", "requireFinalAbsence",
  ]) runtime[name] = async () => {};
  assert.equal(await runMain({ runtime, writeLine: (line) => lines.push(line) }), 0);
  assert.deepEqual(lines, [SUCCESS_LINE]);
  lines.length = 0;
  runtime.initialize = async () => { throw Object.assign(new Error("secret detail"), { category: "provider" }); };
  assert.equal(await runMain({ runtime, writeLine: (line) => lines.push(line) }), 1);
  assert.deepEqual(lines, ["provider rejected."]);
});

test("constructs the concrete runtime only from fixed dependencies", () => {
  assert.doesNotThrow(() => new DockerNangoApiKeyRuntime({
    pathValue: "/safe/bin",
    platform: "linux/arm64",
    tempParent: "/private/tmp",
  }));
});

test("concrete runtime reconciles ambiguous lifecycle mutations and coherent cleanup", async () => {
  const parent = await mkdtemp(join(tmpdir(), "zasp-m0-14c-runtime-test-"));
  const networkId = "c".repeat(64);
  const identifiers = {
    database: "d".repeat(64),
    nango: "e".repeat(64),
    fixture: "f".repeat(64),
    wrapper: "9".repeat(64),
  };
  const states = new Map();
  let networkPresent = false;
  let databaseImageInspections = 0;
  let schemaInspections = 0;
  let cleanupStarted = false;
  let cleanupExitInjected = false;
  let runtime;

  const result = (overrides = {}) => ({ status: 0, signal: null, stdout: "", stderr: "", ...overrides });
  const roleForId = (candidate) => Object.entries(identifiers).find(([, value]) => value === candidate)?.[0];
  const roleForName = (candidate) => Object.keys(identifiers).find((role) => runtime.specification[role].name === candidate);
  const imageFor = (role) => {
    const expected = runtime.specification[role];
    const nangoImage = role !== "database";
    return {
      Id: nangoImage ? API_KEY_PINS.nango.configDigest : `sha256:${"1".repeat(64)}`,
      RepoDigests: [`proof@${expected.image.slice(expected.image.lastIndexOf("@") + 1)}`],
      Env: [`IMAGE_ROLE=${nangoImage ? "nango" : "database"}`],
      Entrypoint: nangoImage ? ["/usr/local/bin/docker-entrypoint"] : ["docker-entrypoint.sh"],
      Cmd: nangoImage ? ["node", "packages/server/dist/server.js"] : ["postgres"],
      User: nangoImage ? "1000" : "",
      Labels: { [`image.${nangoImage ? "nango" : "database"}`]: "true" },
      ExposedPorts: nangoImage ? { "3003/tcp": {} } : { "5432/tcp": {} },
      Volumes: null,
      Os: "linux",
      Architecture: expected.platform.slice("linux/".length),
    };
  };
  const imageProjection = (image) => JSON.stringify({ image: [
    image.Id, image.RepoDigests, image.Env, image.Entrypoint, image.Cmd, image.User,
    image.Labels, image.ExposedPorts, image.Volumes, image.Os, image.Architecture,
  ] });
  const attachment = (role, state) => {
    const expected = runtime.specification[role];
    const common = {
      IPAMConfig: null,
      Links: null,
      Aliases: [expected.networkAlias],
      DriverOpts: null,
      GwPriority: 0,
      Gateway: "",
      IPv6Gateway: "",
      GlobalIPv6Address: "",
      GlobalIPv6PrefixLen: 0,
    };
    if (state === "created") return { ...common, MacAddress: "", NetworkID: "", EndpointID: "", IPAddress: "", IPPrefixLen: 0, DNSNames: null };
    if (state === "exited") return { ...common, MacAddress: "", NetworkID: networkId, EndpointID: "", IPAddress: "", IPPrefixLen: 0, DNSNames: expected.networkAlias === expected.name ? [expected.name, identifiers[role].slice(0, 12)] : [expected.name, expected.networkAlias, identifiers[role].slice(0, 12)] };
    const index = { database: 2, nango: 3, fixture: 4, wrapper: 5 }[role];
    return {
      ...common,
      MacAddress: `02:42:ac:14:00:0${index}`,
      NetworkID: networkId,
      EndpointID: identifiers[role],
      IPAddress: `172.20.0.${index}`,
      IPPrefixLen: 16,
      DNSNames: expected.networkAlias === expected.name ? [expected.name, identifiers[role].slice(0, 12)] : [expected.name, expected.networkAlias, identifiers[role].slice(0, 12)],
    };
  };
  const containerProjection = (role) => {
    const expected = runtime.specification[role];
    const image = imageFor(role);
    const state = states.get(role);
    const running = state === "running";
    const status = state === "exited" ? "exited" : running ? "running" : "created";
    const constraints = role === "database"
      ? [128, 402_653_184, 500_000_000, ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID"]]
      : role === "nango" ? [256, 805_306_368, 1_000_000_000, null] : [64, 134_217_728, 500_000_000, null];
    const hostMounts = expected.mounts.length === 0 ? null : expected.mounts.map((mount) => ({ Type: "bind", Source: mount.source, Target: mount.target, ReadOnly: true, Consistency: "" }));
    const runtimeMounts = expected.mounts.map((mount) => ({ Type: "bind", Source: mount.source, Destination: mount.target, RW: false }));
    const command = expected.command ?? image.Cmd;
    const entrypoint = expected.entrypoint ?? image.Entrypoint;
    const ports = status === "created" ? {} : Object.fromEntries(Object.keys(image.ExposedPorts).map((key) => [key, null]));
    return JSON.stringify({ container: [
      [identifiers[role], `/${expected.name}`, image.Id],
      [expected.image, { ...image.Labels, ...expected.labels }, [...image.Env, ...Object.entries(expected.environment).map(([key, value]) => `${key}=${value}`)], entrypoint, command, image.User, image.ExposedPorts],
      [expected.network, true, constraints[3], ["ALL"], ["no-new-privileges"], constraints[0], constraints[1], constraints[2], {}, null, hostMounts, expected.tmpfs, { Name: "no", MaximumRetryCount: 0 }, false, [], null, "", "private", "private", ""],
      runtimeMounts,
      [running, status],
      [{ [expected.network]: attachment(role, status) }, ports],
    ] });
  };
  const networkProjection = () => {
    const peers = {};
    for (const role of Object.keys(identifiers)) {
      if (states.get(role) !== "running") continue;
      const expected = runtime.specification[role];
      const current = attachment(role, "running");
      peers[identifiers[role]] = {
        Name: expected.name,
        EndpointID: current.EndpointID,
        MacAddress: current.MacAddress,
        IPv4Address: `${current.IPAddress}/${current.IPPrefixLen}`,
        IPv6Address: "",
      };
    }
    return JSON.stringify({ network: [
      networkId, runtime.specification.network.name, runtime.specification.network.labels,
      true, true, false, {}, { Driver: "default", Options: null, Config: [{ Subnet: "172.20.0.0/16", Gateway: "172.20.0.1" }] }, peers,
    ] });
  };
  const command = async (commandName, arguments_, options) => {
    assert.equal(commandName, "docker");
    assert.deepEqual(Object.keys(options.env).sort(), ["DOCKER_CONFIG", "PATH"]);
    if (arguments_[0] === "ps" || (arguments_[0] === "network" && arguments_[1] === "ls")) {
      const nameFilter = arguments_.find((value) => value.startsWith("name=^"));
      const idFilter = arguments_.find((value) => value.startsWith("id="));
      if (nameFilter) {
        const name = nameFilter.replace(/^name=\^\/?/, "").replace(/\$$/, "");
        if (name === runtime.specification.network.name) return result({ stdout: networkPresent ? `${networkId}\n` : "" });
        const role = roleForName(name);
        return result({ stdout: role && states.has(role) ? `${identifiers[role]}\n` : "" });
      }
      if (idFilter) {
        const candidate = idFilter.slice(3);
        return result({ stdout: candidate === networkId ? (networkPresent ? `${networkId}\n` : "") : (states.has(roleForId(candidate)) ? `${candidate}\n` : "") });
      }
      return result();
    }
    if (arguments_[0] === "image" && arguments_[1] === "inspect") {
      const nangoImage = arguments_.at(-1) === runtime.specification.nango.image;
      if (!nangoImage && databaseImageInspections++ === 0) return result({ status: 1, stderr: `Error response from daemon: No such image: ${arguments_.at(-1)}\n` });
      return result({ stdout: `${imageProjection(imageFor(nangoImage ? "nango" : "database"))}\n` });
    }
    if (arguments_[0] === "pull") return { thrown: true, status: null, signal: null, stdout: "", stderr: "" };
    if (arguments_[0] === "network" && arguments_[1] === "create") { networkPresent = true; return result({ status: null, signal: "SIGKILL" }); }
    if (arguments_[0] === "network" && arguments_[1] === "inspect") {
      if (cleanupStarted && !cleanupExitInjected) { states.set("nango", "exited"); cleanupExitInjected = true; }
      return networkPresent ? result({ stdout: `${networkProjection()}\n` }) : result({ status: 1, stderr: "Error: No such network\n" });
    }
    if (arguments_[0] === "create") {
      const role = roleForName(arguments_[arguments_.indexOf("--name") + 1]);
      states.set(role, "created");
      return role === "nango" ? result() : result({ stdout: `${identifiers[role]}\n` });
    }
    if (arguments_[0] === "container" && arguments_[1] === "inspect") {
      const role = roleForId(arguments_.at(-1));
      return states.has(role) ? result({ stdout: `${containerProjection(role)}\n` }) : result({ status: 1, stderr: "Error: No such container\n" });
    }
    if (arguments_[0] === "start" && arguments_[1] === "--attach") {
      states.set("wrapper", "exited");
      return { thrown: true, status: null, signal: null, stdout: "", stderr: "" };
    }
    if (arguments_[0] === "start") {
      const role = roleForId(arguments_[1]);
      states.set(role, "running");
      return role === "database" ? { thrown: true, status: null, signal: null, stdout: "", stderr: "" } : result({ stdout: `${arguments_[1]}\n` });
    }
    if (arguments_[0] === "logs") {
      if (arguments_[1] === identifiers.fixture) return result({ stdout: "Nango API-key fixture ready.\n" });
      if (arguments_[1] === identifiers.wrapper) return result({ stdout: `${JSON.stringify({ organizationId: `org_${marker}`, integrationKey: `zasp-m0-14c-${marker}-1password-events`, connectionId: "00000000-0000-4000-8000-0000000000b4" })}\n` });
    }
    if (arguments_[0] === "exec" && arguments_.includes("pg_isready")) return result();
    if (arguments_[0] === "exec" && arguments_.includes("psql")) {
      const query = arguments_.at(-1);
      if (query === "SELECT 1;") return result({ stdout: "1\n" });
      if (query.startsWith("CREATE SCHEMA")) { states.set("schemas", "created"); return { status: null, signal: "SIGKILL", stdout: "", stderr: "" }; }
      schemaInspections += 1;
      return result({ stdout: states.has("schemas") ? "nango\nnango_records\n" : "" });
    }
    if (arguments_[0] === "exec" && arguments_.includes("node")) return result();
    if (arguments_[0] === "rm") {
      const role = roleForId(arguments_.at(-1));
      states.delete(role);
      if (role === "database") states.delete("schemas");
      if (role === "wrapper") cleanupStarted = true;
      return { thrown: true, status: null, signal: null, stdout: "", stderr: "" };
    }
    if (arguments_[0] === "network" && arguments_[1] === "rm") { networkPresent = false; return { status: null, signal: "SIGKILL", stdout: "", stderr: "" }; }
    throw new Error(`unexpected Docker command: ${arguments_.join(" ")}`);
  };

  try {
    runtime = new DockerNangoApiKeyRuntime({
      pathValue: "/safe/bin",
      platform: "linux/arm64",
      tempParent: parent,
      markerSource: () => marker,
      command,
    });
    assert.deepEqual(await orchestrate(runtime, { mainTimeoutMs: 20_000, cleanupTimeoutMs: 20_000 }), {
      apiKey: true, reference: true, productStateSafe: true, cleanup: true,
    });
    assert.equal(networkPresent, false);
    assert.equal(states.size, 0);
    assert.equal(schemaInspections, 2);
    assert.equal(databaseImageInspections, 2);
    assert.deepEqual(await readdir(parent), []);
  } finally {
    if (runtime?.workspace !== undefined) await removeApiKeyWorkspace(runtime.workspace).catch(() => {});
    await rm(parent, { recursive: true, force: true });
  }
});
