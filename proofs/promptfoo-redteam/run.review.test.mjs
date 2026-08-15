import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdir, mkdtemp, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { test } from "node:test";

import { buildPromptfooRuntimeSpec, PROMPTFOO_PINS } from "./manifest.mjs";
import * as runtimeModule from "./run.mjs";

const marker = "0123456789abcdef";
const root = "/private/tmp/zasp-m0-16-0123456789abcdef-ABC123";
const spec = buildPromptfooRuntimeSpec({
  marker,
  platform: "linux/arm64",
  workspaceRoot: root,
  dockerConfigPath: `${root}/docker-config`,
  configurationPath: `${root}/promptfooconfig.yaml`,
  outputPath: `${root}/output`,
  fakeAgentPath: "/proofs/promptfoo-redteam/fake_agent.mjs",
});
const imageId = `sha256:${"a".repeat(64)}`;
const networkId = "b".repeat(64);
const agentId = "c".repeat(64);
const runnerId = "d".repeat(64);
const endpointId = "e".repeat(64);
const imageEnvironment = [
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  "NODE_VERSION=24.17.0",
  "YARN_VERSION=1.22.22",
  "API_PORT=3000",
  "HOST=0.0.0.0",
  "PROMPTFOO_SELF_HOSTED=1",
  "PROMPTFOO_RUNNING_IN_DOCKER=1",
  "PROMPTFOO_OFFICIAL_DOCKER_IMAGE=1",
];
const imageLabels = {
  "org.opencontainers.image.created": "2026-07-14T16:55:18.799Z",
  "org.opencontainers.image.description": "Test your prompts, agents, and RAGs. Red teaming/pentesting/vulnerability scanning for AI. Compare performance of GPT, Claude, Gemini, DeepSeek, and more. Simple declarative configs with command line and CI/CD integration.  Used by OpenAI and Anthropic.",
  "org.opencontainers.image.licenses": "MIT",
  "org.opencontainers.image.revision": "1ede17aaed940e6dff04f71d24e4ecc011809dae",
  "org.opencontainers.image.source": "https://github.com/promptfoo/promptfoo",
  "org.opencontainers.image.title": "promptfoo",
  "org.opencontainers.image.url": "https://github.com/promptfoo/promptfoo",
  "org.opencontainers.image.version": "main",
};
const image = {
  id: imageId,
  config: {
    Env: imageEnvironment,
    Entrypoint: ["docker-entrypoint.sh"],
    Cmd: ["node", "dist/src/server/index.js"],
    User: "promptfoo",
    WorkingDir: "/app",
    Labels: imageLabels,
    ExposedPorts: { "3000/tcp": {} },
  },
  repoDigests: [`ghcr.io/promptfoo/promptfoo@${PROMPTFOO_PINS.image.split("@")[1]}`],
};

function attachment(role, phase) {
  const id = role === "agent" ? agentId : runnerId;
  const status = phase === true ? "running" : phase === false ? "created" : phase;
  const active = status === "running";
  const retainedNetworkIdentity = status !== "created";
  return {
    IPAMConfig: null,
    Links: null,
    Aliases: [spec[role].networkAlias],
    MacAddress: active ? "02:42:c0:a8:a4:02" : "",
    DriverOpts: null,
    GwPriority: 0,
    NetworkID: retainedNetworkIdentity ? networkId : "",
    EndpointID: active ? endpointId : "",
    Gateway: "",
    IPAddress: active ? "192.168.164.2" : "",
    IPPrefixLen: active ? 24 : 0,
    IPv6Gateway: "",
    GlobalIPv6Address: "",
    GlobalIPv6PrefixLen: 0,
    DNSNames: retainedNetworkIdentity ? [spec[role].name, id.slice(0, 12)] : null,
  };
}

function containerState(role, status = "created") {
  const expected = spec[role];
  const id = role === "agent" ? agentId : runnerId;
  return {
    Id: id,
    Name: `/${expected.name}`,
    Image: imageId,
    Config: {
      Image: expected.image,
      User: "promptfoo",
      Labels: { ...imageLabels, ...expected.labels },
      Env: [...imageEnvironment, ...Object.entries(expected.environment).map(([key, value]) => `${key}=${value}`)],
      Entrypoint: expected.entrypoint,
      Cmd: expected.command,
      WorkingDir: "/app",
      ExposedPorts: { "3000/tcp": {} },
    },
    HostConfig: {
      AutoRemove: false,
      Binds: null,
      CapAdd: null,
      CapDrop: ["ALL"],
      CgroupnsMode: "private",
      DeviceRequests: null,
      Devices: [],
      IpcMode: "private",
      Mounts: expected.mounts.map((mount) => mount.readOnly
        ? { Type: "bind", Source: mount.source, Target: mount.target, ReadOnly: true }
        : { Type: "bind", Source: mount.source, Target: mount.target }),
      NetworkMode: expected.network,
      PidMode: "",
      PidsLimit: expected.pidsLimit,
      PortBindings: {},
      Privileged: false,
      PublishAllPorts: false,
      ReadonlyRootfs: true,
      SecurityOpt: ["no-new-privileges"],
      Tmpfs: { ...expected.tmpfs },
      UsernsMode: "",
      Memory: expected.memory === "512m" ? 536_870_912 : 1_073_741_824,
      NanoCpus: Number(expected.cpus) * 1_000_000_000,
    },
    Mounts: expected.mounts.map((mount) => ({
      Type: "bind",
      Source: mount.source,
      Destination: mount.target,
      Mode: "",
      RW: !mount.readOnly,
      Propagation: "rprivate",
    })),
    State: { Status: status, ExitCode: status === "exited" ? 100 : 0 },
    NetworkSettings: {
      Networks: { [expected.network]: attachment(role, status) },
      Ports: status === "running" ? { "3000/tcp": null } : {},
    },
  };
}

function networkState(peers = {}) {
  return {
    Name: spec.network.name,
    Id: networkId,
    Created: "2026-08-15T00:00:00.000000000Z",
    Scope: "local",
    Driver: "bridge",
    EnableIPv4: true,
    EnableIPv6: false,
    IPAM: { Driver: "default", Options: {}, Config: [{ Subnet: "192.168.164.0/24", Gateway: "192.168.164.1" }] },
    Internal: true,
    Attachable: false,
    Ingress: false,
    ConfigFrom: { Network: "" },
    ConfigOnly: false,
    Containers: peers,
    Options: {},
    Labels: spec.network.labels,
    Status: {},
  };
}

function peer(role) {
  const id = role === "agent" ? agentId : runnerId;
  const value = attachment(role, true);
  return { Name: spec[role].name, EndpointID: value.EndpointID, MacAddress: value.MacAddress, IPv4Address: `${value.IPAddress}/${value.IPPrefixLen}`, IPv6Address: "" , id };
}

test("exports the whole-range ownership and absence validators", () => {
  for (const name of ["captureNetworkIdentity", "validateNetworkOwnership", "validateContainerOwnership", "validateTopology", "validateRetainedAbsence"]) {
    assert.equal(typeof runtimeModule[name], "function", `${name} must be exported`);
  }
});

test("rejects network configuration, peer, and cross-projection drift", () => {
  const identity = runtimeModule.captureNetworkIdentity(networkState(), spec.network, networkId);
  runtimeModule.validateNetworkOwnership(networkState(), spec.network, networkId, identity);
  const dynamicStatus = networkState();
  dynamicStatus.Status = { IPAM: { Subnets: { "192.168.164.0/24": { IPsInUse: 3, DynamicIPsAvailable: 253 } } } };
  runtimeModule.validateNetworkOwnership(dynamicStatus, spec.network, networkId, identity);
  const changedOptions = networkState();
  changedOptions.Options.hostile = "true";
  assert.throws(() => runtimeModule.validateNetworkOwnership(changedOptions, spec.network, networkId, identity));

  const agent = containerState("agent", "running");
  const exactPeer = peer("agent");
  const peers = { [agentId]: Object.fromEntries(Object.entries(exactPeer).filter(([key]) => key !== "id")) };
  runtimeModule.validateTopology(networkState(peers), [{ role: "agent", candidate: { id: agentId, name: spec.agent.name }, state: agent }], identity);
  const endpointDrift = networkState(peers);
  endpointDrift.Containers[agentId].EndpointID = "f".repeat(64);
  assert.throws(() => runtimeModule.validateTopology(endpointDrift, [{ role: "agent", candidate: { id: agentId, name: spec.agent.name }, state: agent }], identity));
  const extraPeer = networkState({ ...peers, [runnerId]: { ...peers[agentId], Name: spec.runner.name } });
  assert.throws(() => runtimeModule.validateTopology(extraPeer, [{ role: "agent", candidate: { id: agentId, name: spec.agent.name }, state: agent }], identity));
});

test("rejects dangerous or extra container runtime metadata", () => {
  const candidate = { id: agentId, name: spec.agent.name };
  runtimeModule.validateContainerOwnership(containerState("agent", "created"), spec.agent, image, candidate, "created");
  runtimeModule.validateContainerOwnership(containerState("agent", "running"), spec.agent, image, candidate, "running");
  runtimeModule.validateContainerOwnership(containerState("runner", "exited"), spec.runner, image, { id: runnerId, name: spec.runner.name }, "exited", 100);
  const identity = runtimeModule.captureNetworkIdentity(networkState(), spec.network, networkId);
  runtimeModule.validateTopology(networkState(), [{ role: "agent", candidate, state: containerState("agent", "created") }], identity);
  const exactAgentPeer = peer("agent");
  const activePeers = { [agentId]: Object.fromEntries(Object.entries(exactAgentPeer).filter(([key]) => key !== "id")) };
  runtimeModule.validateTopology(networkState(activePeers), [
    { role: "agent", candidate, state: containerState("agent", "running") },
    { role: "runner", candidate: { id: runnerId, name: spec.runner.name }, state: containerState("runner", "exited") },
  ], identity);
  const parsedContainer = runtimeModule.parseUniqueDockerJson(JSON.stringify(containerState("agent", "created")));
  const parsedImageState = runtimeModule.parseUniqueDockerJson(JSON.stringify({ Id: image.id, Config: image.config, RepoDigests: image.repoDigests }));
  const parsedImage = { id: parsedImageState.Id, config: parsedImageState.Config, repoDigests: parsedImageState.RepoDigests };
  const parsedNetwork = runtimeModule.parseUniqueDockerJson(JSON.stringify(networkState()));
  const parsedIdentity = runtimeModule.captureNetworkIdentity(parsedNetwork, spec.network, networkId);
  runtimeModule.validateContainerOwnership(parsedContainer, spec.agent, parsedImage, candidate, "created");
  runtimeModule.validateTopology(parsedNetwork, [{ role: "agent", candidate, state: parsedContainer }], parsedIdentity);
  for (const mutate of [
    (value) => { value.HostConfig.Privileged = true; },
    (value) => { value.HostConfig.CapAdd = ["SYS_ADMIN"]; },
    (value) => { value.HostConfig.Devices = [{ PathOnHost: "/dev/null" }]; },
    (value) => { value.HostConfig.DeviceRequests = [{ Driver: "hostile" }]; },
    (value) => { value.HostConfig.Binds = ["/host:/escape:rw"]; },
    (value) => { value.HostConfig.Tmpfs["/extra"] = "rw"; },
    (value) => { value.HostConfig.PortBindings["3000/tcp"] = [{ HostIp: "0.0.0.0", HostPort: "3000" }]; },
    (value) => { value.Mounts[0].Mode = "ro"; },
    (value) => { value.NetworkSettings.Ports["22/tcp"] = null; },
    (value) => { value.NetworkSettings.Networks.extra = attachment("agent", true); },
  ]) {
    const hostile = containerState("agent", "running");
    mutate(hostile);
    assert.throws(() => runtimeModule.validateContainerOwnership(hostile, spec.agent, image, candidate, "running"));
  }
});

test("requires retained full-ID absence independently of exact names", () => {
  assert.equal(runtimeModule.validateRetainedAbsence([], [], agentId), true);
  for (const [names, retained] of [[[], [agentId]], [[agentId], []], [[runnerId], []], [[], [runnerId]]]) {
    assert.throws(() => runtimeModule.validateRetainedAbsence(names, retained, agentId));
  }
});

test("requires a retained Docker-absence proof before the temp-only final audit", () => {
  assert.equal(typeof runtimeModule.validateFinalAbsenceAuthority, "function");
  assert.equal(runtimeModule.validateFinalAbsenceAuthority(true), true);
  for (const value of [false, undefined, null, 1, "true"]) {
    assert.throws(() => runtimeModule.validateFinalAbsenceAuthority(value));
  }
});

function dockerChild() {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = () => true;
  queueMicrotask(() => {
    child.stdout.end("");
    child.stderr.end("");
    child.emit("close", 0, null);
  });
  return child;
}

test("re-proves the retained workspace immediately before every Docker command", async () => {
  const parent = await mkdtemp(join(tmpdir(), "zasp-m0-16-review-parent-"));
  let spawnCalls = 0;
  try {
    const runtime = new runtimeModule.DockerPromptfooRuntime({
      tempParent: parent,
      proofSourcePath: join(process.cwd(), "proofs", "promptfoo-redteam"),
      randomSource: () => Buffer.from(marker, "hex"),
      spawnProcess: () => { spawnCalls += 1; return dockerChild(); },
    });
    await runtime.initialize(new AbortController().signal);
    const moved = `${runtime.workspace.dockerConfig.path}-retained`;
    await rename(runtime.workspace.dockerConfig.path, moved);
    await mkdir(runtime.workspace.dockerConfig.path, { mode: 0o700 });
    await assert.rejects(runtime.preflight(new AbortController().signal));
    assert.equal(spawnCalls, 0);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});
