import assert from "node:assert/strict";
import test from "node:test";

import {
  COLLECTOR_IMAGE,
  SUCCESS_LINE,
  buildContainerCreateArguments,
  buildNetworkConnectArguments,
  buildNetworkCreateArguments,
  classifyAcknowledgedMutation,
  classifyMutationResult,
  orchestrate,
  parseDockerDocument,
  runMain,
  runPhase,
  validateNetworkDocument,
  validateRuntimeContainer,
} from "./run.mjs";

const marker = "0123456789abcdef";

test("pins the exact Collector and fixed output", () => {
  assert.equal(COLLECTOR_IMAGE, "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5");
  assert.equal(SUCCESS_LINE, "OTLP export proof passed: delivered=true bounded=true exporter_failed=true application_unblocked=true cleanup=true.");
});

test("builds an exact private internal network mutation", () => {
  assert.deepEqual(buildNetworkCreateArguments(marker), [
    "network", "create", "--internal", "--label", "zasp.dev/proof=m0-22",
    "--label", `zasp.dev/run=${marker}`, `zasp-m0-22-network-${marker}`,
  ]);
});

test("builds exact source and sink container mutations", () => {
  const common = {
    marker,
    image: COLLECTOR_IMAGE,
    networkName: `zasp-m0-22-network-${marker}`,
    configPath: "/safe/config",
    outputPath: "/safe/output",
    user: "501:20",
  };
  const source = buildContainerCreateArguments({ ...common, role: "source" });
  const sink = buildContainerCreateArguments({ ...common, role: "sink" });
  assert.deepEqual(source.slice(0, 7), ["create", "--name", `zasp-m0-22-source-${marker}`, "--network", "bridge", "--publish", "127.0.0.1::4318"]);
  assert.ok(source.includes("zasp.dev/role=source"));
  assert.ok(sink.includes("zasp.dev/role=sink"));
  assert.equal(sink.includes("--publish"), false);
  assert.equal(source.at(-1), "--config=/proof/config/config.yaml");
  assert.equal(sink.at(-1), "--config=/proof/config/config.yaml");
});

test("attaches only the exact source candidate to the private exporter network", () => {
  assert.deepEqual(buildNetworkConnectArguments({
    networkId: "b".repeat(64),
    containerId: "c".repeat(64),
  }), ["network", "connect", "b".repeat(64), "c".repeat(64)]);
  assert.throws(() => buildNetworkConnectArguments({ networkId: "bridge", containerId: "c".repeat(64) }), TypeError);
});

test("classifies definitive rejection separately from ambiguous mutation outcomes", () => {
  const id = "a".repeat(64);
  assert.equal(classifyMutationResult({ status: 0, signal: null, stdout: `${id}\n`, stderr: "" }, "container"), "applied");
  assert.equal(classifyMutationResult({ status: 0, signal: null, stdout: "malformed", stderr: "" }, "container"), "ambiguous");
  assert.equal(classifyMutationResult({ thrown: true, status: null, signal: null, stdout: "", stderr: "" }, "container"), "ambiguous");
  assert.equal(classifyMutationResult({ status: 1, signal: null, stdout: "", stderr: "rejected\n" }, "container"), "definitive");
});

test("reconciles malformed or lost acknowledgements but never definitive rejection", () => {
  const id = "a".repeat(64);
  assert.equal(classifyAcknowledgedMutation({ status: 0, signal: null, stdout: `${id}\n`, stderr: "" }, `${id}\n`), "applied");
  assert.equal(classifyAcknowledgedMutation({ status: 0, signal: null, stdout: "", stderr: "" }, `${id}\n`), "ambiguous");
  assert.equal(classifyAcknowledgedMutation({ thrown: true, status: null, signal: null, stdout: "", stderr: "" }, `${id}\n`), "ambiguous");
  assert.equal(classifyAcknowledgedMutation({ status: 1, signal: null, stdout: "", stderr: "rejected\n" }, `${id}\n`), "definitive");
});

test("validates exact internal network identity and peers", () => {
  const document = {
    Id: "b".repeat(64),
    Name: `zasp-m0-22-network-${marker}`,
    Internal: true,
    Labels: { "zasp.dev/proof": "m0-22", "zasp.dev/run": marker },
    Containers: {
      ["c".repeat(64)]: { Name: `zasp-m0-22-sink-${marker}` },
      ["d".repeat(64)]: { Name: `zasp-m0-22-source-${marker}` },
    },
  };
  assert.equal(validateNetworkDocument(document, {
    id: document.Id,
    marker,
    peers: [
      { id: "c".repeat(64), name: `zasp-m0-22-sink-${marker}` },
      { id: "d".repeat(64), name: `zasp-m0-22-source-${marker}` },
    ],
  }), true);
  assert.throws(() => validateNetworkDocument({ ...document, Internal: false }, { id: document.Id, marker, peers: [] }), TypeError);
  assert.throws(() => validateNetworkDocument({
    ...document,
    Containers: { ...document.Containers, ["e".repeat(64)]: { Name: "unrelated" } },
  }, {
    id: document.Id,
    marker,
    peers: [
      { id: "c".repeat(64), name: `zasp-m0-22-sink-${marker}` },
      { id: "d".repeat(64), name: `zasp-m0-22-source-${marker}` },
    ],
  }), TypeError);
});

test("normalizes duplicate-safe Docker JSON into plain exact-comparison data", () => {
  const parsed = parseDockerDocument('{"Labels":{"zasp.dev/proof":"m0-22"}}\n');
  assert.deepEqual(parsed, { Labels: { "zasp.dev/proof": "m0-22" } });
  assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
  assert.equal(Object.getPrototypeOf(parsed.Labels), Object.prototype);
  assert.throws(() => parseDockerDocument('{"Id":"a","Id":"b"}'), TypeError);
});

test("orchestration preserves cleanup precedence and the fixed success boundary", async () => {
  const calls = [];
  const runtime = {
    async initialize() { calls.push("initialize"); },
    async requireInitialAbsence() { calls.push("initial"); },
    async resolveImage() { calls.push("image"); },
    async createNetwork() { calls.push("network"); },
    async createSink() { calls.push("sink"); },
    async createSource() { calls.push("source"); },
    async proveDelivery() { calls.push("delivery"); return { delivered: true }; },
    async proveFailureBoundary() { calls.push("failure"); return { bounded: true, exporterFailed: true, applicationUnblocked: true }; },
    async settleMutations() { calls.push("settle"); },
    async cleanup() { calls.push("cleanup"); },
    async requireFinalAbsence() { calls.push("final"); },
  };
  assert.deepEqual(await orchestrate(runtime, { mainTimeoutMs: 1_000, cleanupTimeoutMs: 1_000 }), { code: 0, line: SUCCESS_LINE });
  assert.deepEqual(calls, ["initialize", "initial", "image", "network", "sink", "source", "delivery", "failure", "settle", "cleanup", "final"]);

  runtime.proveDelivery = async () => { throw Object.assign(new Error("provider"), { category: "provider" }); };
  runtime.cleanup = async () => { throw new Error("cleanup"); };
  const failed = await orchestrate(runtime, { mainTimeoutMs: 1_000, cleanupTimeoutMs: 1_000 });
  assert.equal(failed.line, "OTLP export proof failed: cleanup rejected.");
});

test("validates the exact live-derived source container projection", () => {
  const image = {
    id: `sha256:${"e".repeat(64)}`,
    labels: { "org.opencontainers.image.title": "otelcol-contrib" },
    environment: ["HOME=/home/otelcol-contrib"],
    entrypoint: ["/otelcol-contrib"],
    exposedPorts: { "4318/tcp": {} },
  };
  const expected = {
    role: "source",
    marker,
    id: "d".repeat(64),
    name: `zasp-m0-22-source-${marker}`,
    image,
    networkName: "bridge",
    configPath: "/safe/config",
    outputPath: "/safe/output",
    user: "501:20",
    sourcePort: 32_123,
  };
  const document = containerDocument(expected, true);
  assert.equal(validateRuntimeContainer(document, expected, true), true);
  assert.throws(() => validateRuntimeContainer({
    ...document,
    HostConfig: { ...document.HostConfig, Privileged: true },
  }, expected, true));
  assert.throws(() => validateRuntimeContainer({
    ...document,
    NetworkSettings: { Ports: { "4318/tcp": [{ HostIp: "0.0.0.0", HostPort: "32123" }] } },
  }, expected, true));
});

test("aborts a bounded phase and waits for cooperative settlement", async () => {
  let settled = false;
  await assert.rejects(() => runPhase(async (signal) => {
    await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
    settled = true;
  }, 10, 100), /operation rejected/);
  assert.equal(settled, true);
});

test("runMain emits only one fixed line and returns the exact code", async () => {
  const stdout = [];
  const stderr = [];
  let exitCode;
  const runtime = {
    async initialize() {}, async requireInitialAbsence() {}, async resolveImage() {},
    async createNetwork() {}, async createSink() {}, async createSource() {},
    async proveDelivery() { return { delivered: true }; },
    async proveFailureBoundary() { return { bounded: true, exporterFailed: true, applicationUnblocked: true }; },
    async settleMutations() {}, async cleanup() {}, async requireFinalAbsence() {},
  };
  assert.equal(await runMain({
    runtime,
    stdout: { write(value) { stdout.push(value); } },
    stderr: { write(value) { stderr.push(value); } },
    setExitCode(value) { exitCode = value; },
    mainTimeoutMs: 1_000,
    cleanupTimeoutMs: 1_000,
  }), 0);
  assert.deepEqual(stdout, [`${SUCCESS_LINE}\n`]);
  assert.deepEqual(stderr, []);
  assert.equal(exitCode, 0);
});

function containerDocument(expected, running) {
  return {
    Id: expected.id,
    Name: `/${expected.name}`,
    Image: expected.image.id,
    Config: {
      Image: COLLECTOR_IMAGE,
      Labels: {
        ...expected.image.labels,
        "zasp.dev/proof": "m0-22",
        "zasp.dev/run": expected.marker,
        "zasp.dev/role": expected.role,
      },
      Env: expected.image.environment,
      Entrypoint: expected.image.entrypoint,
      Cmd: ["--config=/proof/config/config.yaml"],
      User: expected.user,
      ExposedPorts: expected.image.exposedPorts,
    },
    HostConfig: {
      NetworkMode: expected.networkName,
      ReadonlyRootfs: true,
      CapAdd: null,
      CapDrop: ["ALL"],
      SecurityOpt: ["no-new-privileges"],
      PidsLimit: 128,
      Memory: 134_217_728,
      NanoCpus: 500_000_000,
      PortBindings: { "4318/tcp": [{ HostIp: "127.0.0.1", HostPort: "" }] },
      Binds: null,
      Mounts: [{ Type: "bind", Source: expected.configPath, Target: "/proof/config", ReadOnly: true }],
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
    Mounts: [{
      Type: "bind", Source: expected.configPath, Destination: "/proof/config",
      Mode: "", RW: false, Propagation: "rprivate",
    }],
    State: { Running: running },
    NetworkSettings: {
      Ports: { "4318/tcp": [{ HostIp: "127.0.0.1", HostPort: String(expected.sourcePort) }] },
    },
  };
}
