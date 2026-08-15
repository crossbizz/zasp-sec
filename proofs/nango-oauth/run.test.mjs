import assert from "node:assert/strict";
import test from "node:test";

import {
  DockerNangoOAuthRuntime,
  SUCCESS_LINE,
  buildContainerCreateArguments,
  buildNetworkCreateArguments,
  classifyMutationResult,
  orchestrate,
  parseWrapperOutput,
  runMain,
  validateOAuthContainerIdentity,
} from "./run.mjs";
import { buildOAuthRuntimeSpec } from "./manifest.mjs";

const marker = "0123456789abcdef";
const containerId = "a".repeat(64);

function specification() {
  const root = `/private/tmp/zasp-m0-14b-${marker}-ABC123`;
  return buildOAuthRuntimeSpec({
    marker,
    platform: "linux/arm64",
    password: "p".repeat(32),
    encryptionKey: Buffer.alloc(32, 7).toString("base64"),
    clientId: "client_0123456789abcdef01234567",
    clientSecret: "secret_0123456789abcdef0123456789abcdef",
    code: "code_0123456789abcdef0123456789abcdef",
    accessToken: "token_0123456789abcdef0123456789abcdef",
    workspaceRoot: root,
    dockerConfigPath: `${root}/docker-config`,
    caCertificatePath: `${root}/tls/ca.crt`,
    fixtureCertificatePath: `${root}/tls/server.crt`,
    fixtureKeyPath: `${root}/tls/server.key`,
    proofSourcePath: "/safe/proofs",
  });
}

test("binds the fixed success line and strict mutation taxonomy", () => {
  assert.equal(SUCCESS_LINE, "Nango OAuth proof passed: oauth=true reference=true product_state_safe=true cleanup=true.");
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
    "--label", "zasp.dev/proof=m0-14b",
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

test("accepts only the exact reference-only wrapper artifact", () => {
  const exact = JSON.stringify({ organizationId: `org_${marker}`, integrationKey: `zasp-m0-14b-${marker}-github`, connectionId: `conn_${marker}` });
  assert.deepEqual(parseWrapperOutput(Buffer.from(`${exact}\n`)), JSON.parse(exact));
  for (const value of [
    `${exact}\ntrailing`,
    exact.replace("{", '{"organizationId":"duplicate",'),
    JSON.stringify({ ...JSON.parse(exact), accessToken: "forbidden" }),
    JSON.stringify({ ...JSON.parse(exact), organizationId: "wrong" }),
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
  const runtimeMounts = [
    ...expected.mounts.map((mount) => ({ Type: "bind", Source: mount.source, Destination: mount.target, RW: false })),
    ...Object.keys(expected.tmpfs).map((destination) => ({ Type: "tmpfs", Destination: destination, RW: true })),
  ];
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
      Networks: { [spec.network.name]: { Aliases: [expected.networkAlias], NetworkID: "", EndpointID: "", IPAddress: "" } },
      Ports: {},
    },
  };
  const options = { resource: { id: containerId, name: expected.name }, expected, image, networkName: spec.network.name, networkId: "c".repeat(64), expectedState: "created" };
  assert.equal(validateOAuthContainerIdentity(document, options), true);
  for (const mutate of [
    (value) => { value.HostConfig.Privileged = true; },
    (value) => { value.Config.Env.push("AWS_ACCESS_KEY_ID=ambient"); },
    (value) => { value.HostConfig.Mounts[0].Source = "/replacement"; },
    (value) => { value.Mounts.push({ Type: "bind", Source: "/extra", Destination: "/extra", RW: false }); },
    (value) => { value.NetworkSettings.Ports["443/tcp"] = null; },
  ]) {
    const changed = structuredClone(document);
    mutate(changed);
    assert.throws(() => validateOAuthContainerIdentity(changed, options));
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
    oauth: true, reference: true, productStateSafe: true, cleanup: true,
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
    initialize: async () => { throw Object.assign(new Error("main"), { category: "oauth" }); },
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
  assert.doesNotThrow(() => new DockerNangoOAuthRuntime({
    pathValue: "/safe/bin",
    platform: "linux/arm64",
    tempParent: "/private/tmp",
  }));
});
