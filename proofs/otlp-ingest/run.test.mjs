import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import {
  COLLECTOR_IMAGE,
  SUCCESS_LINE,
  buildDockerCreateArguments,
  buildDockerEnvironment,
  classifyCreateResult,
  isExactMissingImageResult,
  orchestrate,
  runMain,
  runPhase,
  validateCleanupContainerDocument,
  validateCreatedContainerDocument,
  validateContainerDocument,
} from "./run.mjs";

const marker = "0123456789abcdef";
const id = "a".repeat(64);
const imageId = `sha256:${"b".repeat(64)}`;

const expected = Object.freeze({
  marker,
  name: `zasp-m0-13-${marker}`,
  id,
  imageId,
  imageEnvironment: ["SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"],
  imageEntrypoint: ["/otelcol-contrib"],
  imageLabels: { "org.opencontainers.image.title": "OpenTelemetry Collector Contrib" },
  imageExposedPorts: { "4317/tcp": {}, "4318/tcp": {}, "55679/tcp": {} },
  user: "501:20",
  configPath: "/safe/config/config.yaml",
  outputPath: "/safe/output",
  hostPort: "54321",
});

function containerDocument(overrides = {}) {
  const document = {
    Id: expected.id,
    Name: `/${expected.name}`,
    Image: expected.imageId,
    Config: {
      Image: COLLECTOR_IMAGE,
      Labels: {
        ...expected.imageLabels,
        "zasp.dev/proof": "m0-13",
        "zasp.dev/run": expected.marker,
      },
      Env: expected.imageEnvironment,
      Entrypoint: expected.imageEntrypoint,
      Cmd: ["--config=/proof/config/config.yaml"],
      User: expected.user,
      ExposedPorts: expected.imageExposedPorts,
    },
    HostConfig: {
      NetworkMode: "bridge",
      ReadonlyRootfs: true,
      CapAdd: null,
      CapDrop: ["ALL"],
      SecurityOpt: ["no-new-privileges"],
      PidsLimit: 128,
      Memory: 134_217_728,
      NanoCpus: 500_000_000,
      PortBindings: { "4318/tcp": [{ HostIp: "127.0.0.1", HostPort: expected.hostPort }] },
      Binds: null,
      Mounts: [
        { Type: "bind", Source: expected.configPath, Target: "/proof/config", ReadOnly: true },
        { Type: "bind", Source: expected.outputPath, Target: "/proof/output" },
      ],
      Tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=16m" },
      RestartPolicy: { Name: "no", MaximumRetryCount: 0 },
      Privileged: false,
      Devices: [],
      DeviceRequests: null,
      PidMode: "",
      IpcMode: "private",
      CgroupnsMode: "private",
      UsernsMode: "",
    },
    Mounts: [
      { Type: "bind", Source: expected.outputPath, Destination: "/proof/output", Mode: "", RW: true, Propagation: "rprivate" },
      { Type: "bind", Source: expected.configPath, Destination: "/proof/config", Mode: "", RW: false, Propagation: "rprivate" },
    ],
    State: { Running: true },
    NetworkSettings: {
      Ports: {
        "4317/tcp": null,
        "4318/tcp": [{ HostIp: "127.0.0.1", HostPort: expected.hostPort }],
        "55679/tcp": null,
      },
    },
  };
  return Object.assign(document, overrides);
}

function fakeRuntime(overrides = {}) {
  const calls = [];
  const runtime = {
    calls,
    hasCandidate: () => true,
    async initialize() { calls.push("initialize"); },
    async requireInitialAbsence() { calls.push("initial-absence"); },
    async resolveImage() { calls.push("resolve-image"); },
    async create() { calls.push("create"); return id; },
    async verifyOwned() { calls.push("verify"); },
    async endpoint() { calls.push("endpoint"); return "http://127.0.0.1:54321"; },
    async waitReady() { calls.push("ready"); },
    async sendTrace() { calls.push("send"); },
    async readEvidence() { calls.push("evidence"); return { identity: true }; },
    async cleanup() { calls.push("cleanup"); },
    async requireFinalAbsence() { calls.push("final-absence"); },
    ...overrides,
  };
  return runtime;
}

test("pins the exact Collector image and exact hardened create arguments", () => {
  assert.equal(
    COLLECTOR_IMAGE,
    "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5",
  );
  assert.deepEqual(buildDockerCreateArguments(expected), [
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
    "--label", "zasp.dev/proof=m0-13",
    "--label", `zasp.dev/run=${expected.marker}`,
    "--mount", `type=bind,src=${expected.configPath},dst=/proof/config,readonly`,
    "--mount", `type=bind,src=${expected.outputPath},dst=/proof/output`,
    COLLECTOR_IMAGE,
    "--config=/proof/config/config.yaml",
  ]);
});

test("allows only PATH and exact-owned DOCKER_CONFIG into Docker commands", () => {
  assert.deepEqual(buildDockerEnvironment("/safe/bin", "/safe/docker"), {
    PATH: "/safe/bin",
    DOCKER_CONFIG: "/safe/docker",
  });
  for (const values of [["", "/safe/docker"], ["/safe/bin", "relative"], [null, "/safe/docker"]]) {
    assert.throws(() => buildDockerEnvironment(...values));
  }
});

test("classifies only thrown, signaled, or malformed-zero creates as ambiguous", () => {
  assert.equal(classifyCreateResult({ status: 0, signal: null, stdout: `${id}\n`, stderr: "" }), "applied");
  assert.equal(classifyCreateResult({ status: 1, signal: null, stdout: id, stderr: "rejected" }), "definitive");
  assert.equal(classifyCreateResult({ status: 0, signal: null, stdout: "", stderr: "" }), "ambiguous");
  assert.equal(classifyCreateResult({ status: null, signal: "SIGKILL", stdout: "", stderr: "" }), "ambiguous");
  assert.equal(classifyCreateResult({ thrown: true }), "ambiguous");
});

test("accepts only Docker's exact current missing-image envelope", () => {
  const reference = COLLECTOR_IMAGE;
  assert.equal(isExactMissingImageResult({
    status: 1,
    signal: null,
    stdout: "\n",
    stderr: `Error response from daemon: No such image: ${reference}\n`,
  }, reference), true);
  for (const result of [
    { status: 1, signal: null, stdout: "", stderr: "permission denied\n" },
    { status: 1, signal: null, stdout: "", stderr: `No such image: ${reference}\n` },
    { status: 2, signal: null, stdout: "", stderr: `Error response from daemon: No such image: ${reference}\n` },
  ]) assert.equal(isExactMissingImageResult(result, reference), false);
});

test("accepts only the complete exact container security and ownership document", () => {
  assert.doesNotThrow(() => validateContainerDocument(containerDocument(), expected));
  const mutations = [
    (value) => { value.Name = "/foreign"; },
    (value) => { value.Image = `sha256:${"c".repeat(64)}`; },
    (value) => { value.Config.Labels.extra = "foreign"; },
    (value) => { value.Config.Env.push("HTTP_PROXY=http://foreign"); },
    (value) => { value.Config.Cmd = ["--config=/foreign"]; },
    (value) => { value.Config.User = "0"; },
    (value) => { value.HostConfig.Privileged = true; },
    (value) => { value.HostConfig.CapAdd = ["SYS_ADMIN"]; },
    (value) => { value.HostConfig.SecurityOpt = []; },
    (value) => { value.HostConfig.PortBindings["4317/tcp"] = null; },
    (value) => { value.HostConfig.Mounts[0].Target = "/foreign"; },
    (value) => { value.Mounts[0].Source = "/foreign"; },
    (value) => { value.NetworkSettings.Ports["4318/tcp"][0].HostIp = "0.0.0.0"; },
    (value) => { value.State.Running = false; },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(containerDocument());
    mutate(value);
    assert.throws(() => validateContainerDocument(value, expected));
  }
});

test("accepts engine bookkeeping fields while binding every security-relevant field", () => {
  const value = containerDocument();
  value.Config.Hostname = expected.name;
  value.HostConfig.AutoRemove = false;
  value.State.Status = "running";
  value.NetworkSettings.Networks = { bridge: { NetworkID: "engine-owned" } };
  assert.doesNotThrow(() => validateContainerDocument(value, expected));
});

test("authorizes a created candidate before start without treating it as running", () => {
  const value = containerDocument();
  value.State.Running = false;
  value.NetworkSettings.Ports = {};
  value.HostConfig.PortBindings["4318/tcp"][0].HostPort = "";
  assert.doesNotThrow(() => validateCreatedContainerDocument(value, { ...expected, hostPort: undefined }));
  value.Config.Labels["zasp.dev/run"] = "ffffffffffffffff";
  assert.throws(() => validateCreatedContainerDocument(value, { ...expected, hostPort: undefined }));
});

test("re-authorizes an exact stopped container for cleanup", () => {
  const value = containerDocument();
  value.State.Running = false;
  value.NetworkSettings.Ports = {};
  assert.doesNotThrow(() => validateCleanupContainerDocument(value, expected));
  value.Config.Labels["zasp.dev/proof"] = "foreign";
  assert.throws(() => validateCleanupContainerDocument(value, expected));
});

test("orchestrates the exact main and independent cleanup sequence", async () => {
  const runtime = fakeRuntime();
  const result = await orchestrate(runtime, { mainTimeoutMs: 1_000, cleanupTimeoutMs: 1_000 });

  assert.deepEqual(result, { code: 0, line: SUCCESS_LINE });
  assert.deepEqual(runtime.calls, [
    "initialize", "initial-absence", "resolve-image", "create", "verify",
    "endpoint", "ready", "send", "evidence", "cleanup", "final-absence",
  ]);
});

test("cleanup continues and wins precedence after main and cleanup failures", async () => {
  const runtime = fakeRuntime({
    async sendTrace() { this.calls.push("send"); throw new Error("main detail"); },
    async cleanup() { this.calls.push("cleanup"); throw new Error("cleanup detail"); },
  });
  const result = await orchestrate(runtime, { mainTimeoutMs: 1_000, cleanupTimeoutMs: 1_000 });

  assert.deepEqual(result, { code: 1, line: "OTLP ingest proof failed: cleanup rejected." });
  assert.equal(runtime.calls.includes("final-absence"), true);
});

test("definitive create rejection is not reconciled or adopted", async () => {
  const runtime = fakeRuntime({
    hasCandidate: () => false,
    async create() { this.calls.push("create"); throw Object.assign(new Error("rejected"), { definitive: true }); },
  });
  const result = await orchestrate(runtime, { mainTimeoutMs: 1_000, cleanupTimeoutMs: 1_000 });

  assert.equal(result.code, 1);
  assert.deepEqual(runtime.calls, ["initialize", "initial-absence", "resolve-image", "create", "final-absence"]);
});

test("main deadline revokes authority before independent cleanup", async () => {
  const events = [];
  const runtime = fakeRuntime({
    async waitReady(signal) {
      this.calls.push("ready");
      await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
      events.push("main-aborted");
    },
    async cleanup() { events.push("cleanup"); this.calls.push("cleanup"); },
  });
  const result = await orchestrate(runtime, { mainTimeoutMs: 10, cleanupTimeoutMs: 1_000 });

  assert.equal(result.code, 1);
  assert.deepEqual(events, ["main-aborted", "cleanup"]);
});

test("runPhase bounds an operation that ignores cancellation", async () => {
  const never = new Promise(() => {});
  await assert.rejects(runPhase(() => never, 5, 5), /deadline/);
});

test("runMain emits exactly one fixed success or failure line", async () => {
  for (const [runtime, expectedCode, expectedOutput] of [
    [fakeRuntime(), 0, `${SUCCESS_LINE}\n`],
    [fakeRuntime({ async initialize() { throw new Error("sensitive"); } }), 1, "OTLP ingest proof failed: operation rejected.\n"],
  ]) {
    let stdout = "";
    let stderr = "";
    let exitCode;
    const code = await runMain({
      runtime,
      stdout: { write(value) { stdout += value; } },
      stderr: { write(value) { stderr += value; } },
      setExitCode(value) { exitCode = value; },
      mainTimeoutMs: 1_000,
      cleanupTimeoutMs: 1_000,
    });
    assert.equal(code, expectedCode);
    assert.equal(exitCode, expectedCode);
    assert.equal(expectedCode === 0 ? stdout : stderr, expectedOutput);
    assert.equal(expectedCode === 0 ? stderr : stdout, "");
    assert.doesNotMatch(`${stdout}${stderr}`, /sensitive/);
  }
});

test("runMain contains construction and output-stream failures", async () => {
  let exitCode;
  const stream = new EventEmitter();
  stream.write = () => { throw new Error("pipe detail"); };
  const code = await runMain({
    runtimeFactory() { throw new Error("constructor detail"); },
    stdout: stream,
    stderr: stream,
    setExitCode(value) { exitCode = value; },
  });
  assert.equal(code, 1);
  assert.equal(exitCode, 1);
});
