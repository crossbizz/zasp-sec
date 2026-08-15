import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  DockerNangoRuntime,
  Failure,
  SUCCESS_LINE,
  buildDatabaseCreateArguments,
  buildDockerEnvironment,
  buildNangoCreateArguments,
  buildNetworkCreateArguments,
  buildProbeCreateArguments,
  classifyMutationResult,
  orchestrate,
  parseContainerInspectionResult,
  parseImageInspectionResult,
  parseNetworkInspectionResult,
  runBounded,
  runMain,
  runPhase,
  validateContainerIdentity,
  validateNetworkIdentity,
} from "./run.mjs";
import { PINS, buildRuntimeSpec } from "./manifest.mjs";

const marker = "0123456789abcdef";
const id = "a".repeat(64);
const spec = buildRuntimeSpec({
  marker,
  platform: "linux/arm64",
  password: "p".repeat(32),
  encryptionKey: Buffer.alloc(32, 7).toString("base64"),
});

test("pins the fixed lifecycle output and Docker environment boundary", () => {
  assert.equal(
    SUCCESS_LINE,
    "Nango free boot proof passed: services=2 ready=true product_network=true cleanup=true.",
  );
  assert.deepEqual(buildDockerEnvironment("/safe/bin", "/safe/docker"), {
    PATH: "/safe/bin",
    DOCKER_CONFIG: "/safe/docker",
  });
});

test("classifies only uncertain successful mutation outcomes as ambiguous", () => {
  assert.equal(classifyMutationResult({ status: 0, signal: null, stdout: `${id}\n`, stderr: "" }), "applied");
  assert.equal(classifyMutationResult({ status: 1, signal: null, stdout: "", stderr: "rejected" }), "definitive");
  assert.equal(classifyMutationResult({ status: 0, signal: null, stdout: "", stderr: "" }), "ambiguous");
  assert.equal(classifyMutationResult({ status: null, signal: "SIGKILL", stdout: "", stderr: "" }), "ambiguous");
  assert.equal(classifyMutationResult({ thrown: true }), "ambiguous");
});

test("builds exact private-network and hardened container create commands", () => {
  assert.deepEqual(buildNetworkCreateArguments(spec), [
    "network", "create", "--internal",
    "--label", "zasp.dev/proof=m0-14a",
    "--label", `zasp.dev/run=${marker}`,
    "--label", "zasp.dev/role=network",
    spec.network.name,
  ]);
  const database = buildDatabaseCreateArguments(spec);
  const nango = buildNangoCreateArguments(spec);
  const probe = buildProbeCreateArguments(spec);
  for (const command of [database, nango, probe]) {
    assert.equal(command.includes("--publish"), false);
    assert.equal(command.includes("--network"), true);
    assert.equal(command.includes(spec.network.name), true);
    assert.equal(command.includes("--cap-drop"), true);
    assert.equal(command.includes("ALL"), true);
    assert.equal(command.includes("--security-opt"), true);
    assert.equal(command.includes("no-new-privileges"), true);
  }
  assert.equal(database.includes("--read-only"), true);
  assert.equal(nango.includes("--read-only"), true);
  assert.equal(probe.includes("--read-only"), true);
  assert.equal(nango.includes("NANGO_CLOUD=false"), true);
  assert.equal(nango.includes("NANGO_ENTERPRISE=false"), true);
  assert.equal(nango.some((entry) => /REDIS|ELASTIC|ORCHESTRATOR|FUNCTION|WEBHOOK|MCP|WORKOS|RBAC/i.test(entry)), false);
  assert.deepEqual(probe.slice(-spec.probe.command.length), spec.probe.command);
});

test("strictly parses bounded image, container, and network projections", () => {
  const image = JSON.stringify({ image: [
    `sha256:${"b".repeat(64)}`, ["repo@sha256:digest"], ["PATH=/bin"], ["entry"], ["cmd"],
    "1000", { label: "value" }, { "3003/tcp": {} }, null, "linux", "amd64",
  ] });
  assert.equal(parseImageInspectionResult(image).Architecture, "amd64");

  const container = JSON.stringify({ container: [
    [id, "/name", `sha256:${"b".repeat(64)}`],
    ["image", {}, [], [], [], "", {}],
    ["network", true, null, ["ALL"], ["no-new-privileges"], 32, 1, 1, {}, null, [], {}, { Name: "no", MaximumRetryCount: 0 }, false, [], null, "", "private", "private", ""],
    [], [false, "created"], [{ network: {} }, {}],
  ] });
  assert.equal(parseContainerInspectionResult(container).State.Status, "created");

  const network = JSON.stringify({ network: [id, "name", {}, true, true, false, {}, { Driver: "default" }, {}] });
  assert.equal(parseNetworkInspectionResult(network).Internal, true);

  for (const malformed of [
    image.replace('"image"', '"image":"x","image"'),
    container.replace('"created"', '"created","created"'),
    network.replace('"network"', '"network":"x","network"'),
    `${image} trailing`,
  ]) {
    assert.throws(() => {
      if (malformed.includes('"container"')) parseContainerInspectionResult(malformed);
      else if (malformed.includes('"network"')) parseNetworkInspectionResult(malformed);
      else parseImageInspectionResult(malformed);
    });
  }
});

function exactNangoOwnership() {
  const networkId = "c".repeat(64);
  const image = {
    Id: `sha256:${"b".repeat(64)}`,
    Env: ["PATH=/usr/local/bin"],
    Entrypoint: ["docker-entrypoint.sh"],
    Cmd: ["packages/server/entrypoint.sh"],
    User: "1000",
    Labels: { "org.opencontainers.image.title": "Nango" },
    ExposedPorts: { "3003/tcp": {} },
  };
  const document = {
    Id: id,
    Name: `/${spec.nango.name}`,
    Image: image.Id,
    Config: {
      Image: spec.nango.image,
      Labels: { ...image.Labels, ...spec.nango.labels },
      Env: [...image.Env, ...Object.entries(spec.nango.environment).map(([key, value]) => `${key}=${value}`)],
      Entrypoint: image.Entrypoint,
      Cmd: image.Cmd,
      User: image.User,
      ExposedPorts: image.ExposedPorts,
    },
    HostConfig: {
      NetworkMode: spec.network.name,
      ReadonlyRootfs: true,
      CapAdd: null,
      CapDrop: ["ALL"],
      SecurityOpt: ["no-new-privileges"],
      PidsLimit: 256,
      Memory: 805_306_368,
      NanoCpus: 1_000_000_000,
      PortBindings: {},
      Binds: null,
      Mounts: null,
      Tmpfs: spec.nango.tmpfs,
      RestartPolicy: { Name: "no", MaximumRetryCount: 0 },
      Privileged: false,
      Devices: [],
      DeviceRequests: null,
      PidMode: "",
      IpcMode: "private",
      CgroupnsMode: "private",
      UsernsMode: "",
    },
    Mounts: [{ Type: "tmpfs", Destination: "/tmp" }],
    State: { Running: false, Status: "created" },
    NetworkSettings: {
      Networks: {
        [spec.network.name]: {
          NetworkID: networkId,
          EndpointID: "d".repeat(64),
          Aliases: [spec.nango.name],
          IPAddress: "172.20.0.3",
        },
      },
      Ports: { "3003/tcp": null },
    },
  };
  return { document, image, networkId, resource: { id, name: spec.nango.name } };
}

test("container ownership binds complete image, environment, security, network, and state metadata", () => {
  const values = exactNangoOwnership();
  assert.doesNotThrow(() => validateContainerIdentity(values.document, {
    ...values,
    expected: spec.nango,
    networkName: spec.network.name,
    running: false,
    exited: false,
    cleanup: false,
  }));
  for (const [label, mutate] of [
    ["extra environment", (value) => { value.Config.Env.push("REDIS_URL=redis://foreign"); }],
    ["marker replacement", (value) => { value.Config.Labels["zasp.dev/run"] = "f".repeat(16); }],
    ["privileged", (value) => { value.HostConfig.Privileged = true; }],
    ["capability", (value) => { value.HostConfig.CapAdd = ["SYS_ADMIN"]; }],
    ["tmpfs", (value) => { value.HostConfig.Tmpfs["/tmp"] = "rw,size=64m"; }],
    ["network", (value) => { value.NetworkSettings.Networks.foreign = {}; }],
    ["published port", (value) => { value.NetworkSettings.Ports["3003/tcp"] = [{ HostIp: "0.0.0.0", HostPort: "3003" }]; }],
    ["state", (value) => { value.State.Status = "paused"; }],
  ]) {
    const candidate = structuredClone(values.document);
    mutate(candidate);
    assert.throws(() => validateContainerIdentity(candidate, {
      ...values,
      document: undefined,
      expected: spec.nango,
      networkName: spec.network.name,
      running: false,
      exited: false,
      cleanup: false,
    }), undefined, label);
  }
});

test("network ownership requires exact private configuration and exact current peers", () => {
  const networkId = "c".repeat(64);
  const resource = { id: networkId, name: spec.network.name };
  const peer = { id, name: spec.nango.name };
  const document = {
    Id: networkId,
    Name: spec.network.name,
    Labels: spec.network.labels,
    Internal: true,
    EnableIPv4: true,
    EnableIPv6: false,
    Options: {},
    IPAM: { Driver: "default", Options: null, Config: [{ Subnet: "172.20.0.0/16", Gateway: "172.20.0.1" }] },
    Containers: { [id]: {
      Name: peer.name,
      EndpointID: "d".repeat(64),
      MacAddress: "02:42:ac:14:00:03",
      IPv4Address: "172.20.0.3/16",
      IPv6Address: "",
    } },
  };
  assert.doesNotThrow(() => validateNetworkIdentity(document, resource, spec.network, [peer]));
  for (const mutate of [
    (value) => { value.Internal = false; },
    (value) => { value.EnableIPv6 = true; },
    (value) => { value.Labels.foreign = "value"; },
    (value) => { value.Containers["e".repeat(64)] = { Name: "foreign", EndpointID: "f".repeat(64) }; },
    (value) => { value.IPAM.Config[0].Subnet = "10.0.0.0/8"; },
  ]) {
    const candidate = structuredClone(document);
    mutate(candidate);
    assert.throws(() => validateNetworkIdentity(candidate, resource, spec.network, [peer]));
  }
});

test("bounded child supervision caps combined output and SIGKILLs before reaping", async () => {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  const kills = [];
  child.kill = (signal) => { kills.push(signal); queueMicrotask(() => child.emit("close", null, signal)); };
  const operation = runBounded("docker", ["version"], {
    env: { PATH: "/safe", DOCKER_CONFIG: "/safe/docker" }, timeoutMs: 1_000, outputLimit: 4,
  }, () => child);
  child.stdout.write("123");
  child.stderr.write("45");
  await assert.rejects(operation, (error) => error.category === "operation");
  assert.deepEqual(kills, ["SIGKILL"]);
});

test("bounded child supervision treats stream errors as fixed operation failure", async () => {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = (signal) => queueMicrotask(() => child.emit("close", null, signal));
  const operation = runBounded("docker", [], {
    env: { PATH: "/safe", DOCKER_CONFIG: "/safe/docker" }, timeoutMs: 1_000, outputLimit: 16,
  }, () => child);
  child.stdout.emit("error", new Error("sensitive"));
  await assert.rejects(operation, (error) => error.category === "operation" && !error.message.includes("sensitive"));
});

function fakeRuntime(overrides = {}) {
  const calls = [];
  const runtime = {
    calls,
    async initialize() { calls.push("initialize"); },
    async requireInitialAbsence() { calls.push("initial"); },
    async resolveImages() { calls.push("images"); },
    async createNetwork() { calls.push("network"); },
    async createDatabase() { calls.push("database"); },
    async startDatabase() { calls.push("database-start"); },
    async waitDatabase() { calls.push("database-ready"); },
    async createNango() { calls.push("nango"); },
    async startNango() { calls.push("nango-start"); },
    async createProbe() { calls.push("probe"); },
    async startProbe() { calls.push("probe-start"); },
    async verifyReady() { calls.push("ready"); },
    async settleMutations() { calls.push("settle"); },
    async cleanup() { calls.push("cleanup"); },
    async requireFinalAbsence() { calls.push("absence"); },
    ...overrides,
  };
  return runtime;
}

test("orchestrates the exact dependency order and reverse cleanup boundary", async () => {
  const runtime = fakeRuntime();
  assert.deepEqual(await orchestrate(runtime, { mainTimeoutMs: 1_000, cleanupTimeoutMs: 1_000 }), {
    services: 2, ready: true, productNetwork: true, cleanup: true,
  });
  assert.deepEqual(runtime.calls, [
    "initialize", "initial", "images", "network", "database", "database-start", "database-ready",
    "nango", "nango-start", "probe", "probe-start", "ready", "settle", "cleanup", "absence", "settle",
  ]);
});

test("cleanup continues after main failure and cleanup failure has precedence", async () => {
  const runtime = fakeRuntime({
    async createNango() { this.calls.push("nango"); throw new Failure("provider"); },
    async cleanup() { this.calls.push("cleanup"); throw new Failure("ownership"); },
  });
  await assert.rejects(
    orchestrate(runtime, { mainTimeoutMs: 1_000, cleanupTimeoutMs: 1_000 }),
    (error) => error.category === "cleanup",
  );
  assert.deepEqual(runtime.calls.slice(-4), ["settle", "cleanup", "absence", "settle"]);
});

test("hard phase deadline revokes authority and still reaches cleanup", async () => {
  let aborted = false;
  const runtime = fakeRuntime({
    async resolveImages(signal) {
      this.calls.push("images");
      await new Promise((resolve) => signal.addEventListener("abort", () => { aborted = true; resolve(); }, { once: true }));
      throw new Failure("operation");
    },
  });
  await assert.rejects(orchestrate(runtime, { mainTimeoutMs: 5, cleanupTimeoutMs: 1_000 }));
  assert.equal(aborted, true);
  assert.deepEqual(runtime.calls.slice(-4), ["settle", "cleanup", "absence", "settle"]);
});

test("concrete Docker runtime executes the exact private lifecycle and proves final absence", async () => {
  const parent = await mkdtemp(join(tmpdir(), "zasp-nango-runtime-test-"));
  const networkId = "c".repeat(64);
  const identifiers = { database: "d".repeat(64), nango: "e".repeat(64), probe: "f".repeat(64) };
  const states = new Map();
  let networkPresent = false;
  let runtime;
  const calls = [];
  const imageFor = (role) => {
    const expected = runtime.specification[role];
    return {
      Id: role === "nango" ? PINS.nango.configDigest : `sha256:${role === "database" ? "1" : "2".repeat(1)}`.padEnd(71, role === "database" ? "1" : "2"),
      RepoDigests: [`proof@${expected.image.slice(expected.image.lastIndexOf("@") + 1)}`],
      Env: [`IMAGE_ROLE=${role}`],
      Entrypoint: role === "probe" ? null : ["docker-entrypoint.sh"],
      Cmd: role === "database" ? ["postgres"] : role === "nango" ? ["packages/server/entrypoint.sh"] : ["sh"],
      User: role === "nango" ? "1000" : "",
      Labels: { [`image.${role}`]: "true" },
      ExposedPorts: role === "database" ? { "5432/tcp": {} } : role === "nango" ? { "3003/tcp": {} } : null,
      Volumes: role === "database" ? { "/var/lib/postgresql/data": {} } : null,
      Os: "linux",
      Architecture: expected.platform.slice("linux/".length),
    };
  };
  const imageProjection = (image) => JSON.stringify({ image: [
    image.Id, image.RepoDigests, image.Env, image.Entrypoint, image.Cmd, image.User,
    image.Labels, image.ExposedPorts, image.Volumes, image.Os, image.Architecture,
  ] });
  const roleForId = (candidate) => Object.entries(identifiers).find(([, value]) => value === candidate)?.[0];
  const containerProjection = (role) => {
    const expected = runtime.specification[role];
    const image = imageFor(role);
    const state = states.get(role);
    const running = state === "running";
    const status = state === "exited" ? "exited" : running ? "running" : "created";
    const capabilities = role === "database" ? ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"] : null;
    const tmpfs = role === "database" ? {
      "/var/lib/postgresql/data": "rw,nosuid,nodev,size=256m",
      "/var/run/postgresql": "rw,nosuid,nodev,size=16m",
      "/tmp": "rw,noexec,nosuid,nodev,size=16m",
    } : expected.tmpfs;
    const limits = role === "database" ? [128, 402_653_184, 500_000_000] : role === "nango" ? [256, 805_306_368, 1_000_000_000] : [32, 33_554_432, 250_000_000];
    const ports = Object.fromEntries(Object.keys(image.ExposedPorts ?? {}).map((key) => [key, null]));
    return JSON.stringify({ container: [
      [identifiers[role], `/${expected.name}`, image.Id],
      [expected.image, { ...image.Labels, ...expected.labels }, [...image.Env, ...Object.entries(expected.environment).map(([key, value]) => `${key}=${value}`)], image.Entrypoint, role === "probe" ? expected.command : image.Cmd, image.User, image.ExposedPorts],
      [expected.network, true, capabilities, ["ALL"], ["no-new-privileges"], limits[0], limits[1], limits[2], {}, null, null, tmpfs, { Name: "no", MaximumRetryCount: 0 }, false, [], null, "", "private", "private", ""],
      Object.keys(tmpfs).map((destination) => ({ Type: "tmpfs", Destination: destination })),
      [running, status],
      [{ [expected.network]: { NetworkID: networkId, EndpointID: identifiers[role], Aliases: [expected.networkAlias], IPAddress: `172.20.0.${role === "database" ? 2 : role === "nango" ? 3 : 4}` } }, ports],
    ] });
  };
  const networkProjection = () => {
    const peers = {};
    let index = 2;
    for (const role of ["database", "nango", "probe"]) {
      if (!states.has(role)) continue;
      const expected = runtime.specification[role];
      peers[identifiers[role]] = {
        Name: expected.name,
        EndpointID: identifiers[role],
        MacAddress: `02:42:ac:14:00:0${index}`,
        IPv4Address: `172.20.0.${index}/16`,
        IPv6Address: "",
      };
      index += 1;
    }
    return JSON.stringify({ network: [
      networkId, runtime.specification.network.name, runtime.specification.network.labels,
      true, true, false, {}, { Driver: "default", Options: null, Config: [{ Subnet: "172.20.0.0/16", Gateway: "172.20.0.1" }] }, peers,
    ] });
  };
  const result = (overrides = {}) => ({ status: 0, signal: null, stdout: "", stderr: "", ...overrides });
  const command = async (commandName, args, options) => {
    calls.push(args);
    assert.equal(commandName, "docker");
    assert.deepEqual(Object.keys(options.env).sort(), ["DOCKER_CONFIG", "PATH"]);
    if (args[0] === "ps" || (args[0] === "network" && args[1] === "ls")) return result();
    if (args[0] === "image" && args[1] === "inspect") {
      const role = ["database", "nango", "probe"].find((candidate) => runtime.specification[candidate].image === args.at(-1));
      return result({ stdout: `${imageProjection(imageFor(role))}\n` });
    }
    if (args[0] === "network" && args[1] === "create") { networkPresent = true; return result({ stdout: `${networkId}\n` }); }
    if (args[0] === "network" && args[1] === "inspect") return networkPresent ? result({ stdout: `${networkProjection()}\n` }) : result({ status: 1, stderr: "Error: No such network\n" });
    if (args[0] === "create") {
      const name = args[args.indexOf("--name") + 1];
      const role = ["database", "nango", "probe"].find((candidate) => runtime.specification[candidate].name === name);
      states.set(role, "created");
      return result({ stdout: `${identifiers[role]}\n` });
    }
    if (args[0] === "container" && args[1] === "inspect") {
      const role = roleForId(args.at(-1));
      return states.has(role) ? result({ stdout: `${containerProjection(role)}\n` }) : result({ status: 1, stderr: "Error: No such container\n" });
    }
    if (args[0] === "start" && args[1] === "--attach") {
      states.set("probe", "exited");
      return result({ stdout: runtime.specification.probe.expectedOutput });
    }
    if (args[0] === "start") {
      const role = roleForId(args[1]);
      states.set(role, "running");
      return result({ stdout: `${args[1]}\n` });
    }
    if (args[0] === "exec") return result();
    if (args[0] === "rm") {
      const role = roleForId(args.at(-1));
      states.delete(role);
      return result({ stdout: `${args.at(-1)}\n` });
    }
    if (args[0] === "network" && args[1] === "rm") { networkPresent = false; return result({ stdout: `${networkId}\n` }); }
    throw new Error("unexpected command");
  };
  try {
    runtime = new DockerNangoRuntime({
      pathValue: "/safe/bin",
      platform: "linux/arm64",
      tempParent: parent,
      markerSource: () => marker,
      command,
    });
    assert.deepEqual(await orchestrate(runtime, { mainTimeoutMs: 10_000, cleanupTimeoutMs: 10_000 }), {
      services: 2, ready: true, productNetwork: true, cleanup: true,
    });
    assert.equal(networkPresent, false);
    assert.equal(states.size, 0);
    assert.equal(calls.some((args) => args.includes("--publish")), false);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("runMain emits exactly one fixed success or fixed category line", async () => {
  const success = [];
  assert.equal(await runMain({ runtime: fakeRuntime(), writeLine: (line) => success.push(line), timeouts: { mainTimeoutMs: 1_000, cleanupTimeoutMs: 1_000 } }), 0);
  assert.deepEqual(success, [SUCCESS_LINE]);

  const failure = [];
  assert.equal(await runMain({
    runtime: fakeRuntime({ async resolveImages() { throw new Error("provider secret"); } }),
    writeLine: (line) => failure.push(line), timeouts: { mainTimeoutMs: 1_000, cleanupTimeoutMs: 1_000 },
  }), 1);
  assert.deepEqual(failure, ["Nango free boot proof failed: operation rejected."]);
});

test("runtime constructor rejects incomplete dependencies before touching Docker", () => {
  assert.throws(() => new DockerNangoRuntime({ pathValue: "/safe", platform: "linux/amd64", markerSource: null }));
});

test("runPhase rejects malformed bounds without invoking work", async () => {
  let invoked = false;
  await assert.rejects(runPhase(0, () => { invoked = true; }), (error) => error.category === "operation");
  assert.equal(invoked, false);
});
