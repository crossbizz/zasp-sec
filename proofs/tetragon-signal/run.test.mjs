import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  FAILURE_CATEGORIES,
  SUCCESS_LINE,
  DockerKindLifecycle,
  DockerKindRuntime,
  DockerKindSystem,
  Failure,
  buildHelmInstallArguments,
  buildKindCreateArguments,
  buildNetworkCreateArguments,
  buildToolEnvironment,
  classifyMutationOutcome,
  fixtureTriggerCommands,
  orchestrate,
  runBounded,
  runMain,
} from "./run.mjs";

const marker = "0123456789abcdef";
const names = Object.freeze({
  prefix: `zasp-m0-12-${marker}`,
  cluster: `zasp-m0-12-${marker}`,
  namespace: `zasp-m0-12-${marker}`,
  sinkPod: "sink",
  sinkService: "sink",
  workloadPod: "workload",
  filePolicy: `zasp-m0-12-file-${marker}`,
  networkPolicy: `zasp-m0-12-connect-${marker}`,
});

function proofResult() {
  return {
    process: true,
    file: true,
    network: true,
    identity: true,
    capability: true,
    drops: 0,
    events: [{}, {}, {}],
    workload: { id: "org_aaaaaaaaaaaaaaaa:k8s_workload:fixture" },
    sensor: { version: "1.7.0" },
  };
}

class FakeRuntime {
  constructor(options = {}) {
    this.options = options;
    this.events = [];
    this.candidate = options.candidate ?? false;
  }

  async preflight(phase) {
    phase.assertActive();
    this.events.push("preflight");
    if (this.options.preflightError) throw this.options.preflightError;
  }

  async createCluster(phase) {
    phase.assertActive();
    this.events.push("createCluster");
    this.candidate = true;
    if (this.options.createError) throw this.options.createError;
  }

  async installTetragon(phase) {
    phase.assertActive();
    this.events.push("installTetragon");
    if (this.options.installError) throw this.options.installError;
  }

  async runFixture(phase) {
    phase.assertActive();
    this.events.push("runFixture");
    if (this.options.waitForAbort) {
      await new Promise((resolve) => phase.signal.addEventListener("abort", resolve, { once: true }));
      assert.throws(() => phase.assertActive(), Failure);
      return;
    }
    if (this.options.fixtureError) throw this.options.fixtureError;
  }

  async captureEvidence(phase) {
    phase.assertActive();
    this.events.push("captureEvidence");
    if (this.options.captureError) throw this.options.captureError;
    return proofResult();
  }

  async joinMutations() {
    this.events.push("joinMutations");
    if (this.options.joinError) throw this.options.joinError;
  }

  async cleanup(phase) {
    phase.assertActive();
    this.events.push("cleanup");
    if (this.options.cleanupError) throw this.options.cleanupError;
    this.candidate = false;
  }

  async auditAbsence(phase) {
    phase.assertActive();
    this.events.push("auditAbsence");
    if (this.options.auditError) throw this.options.auditError;
  }

  hasCandidate() {
    return this.candidate;
  }
}

function childProcess({ stdout = "", stderr = "", status = 0, signal = null, delay = 0, closeOnKill = true }) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kills = [];
  child.kill = (killSignal) => {
    child.kills.push(killSignal);
    if (closeOnKill) queueMicrotask(() => child.emit("close", null, killSignal));
    return true;
  };
  setTimeout(() => {
    if (stdout) child.stdout.write(stdout);
    if (stderr) child.stderr.write(stderr);
    child.stdout.end();
    child.stderr.end();
    child.emit("close", status, signal);
  }, delay);
  return child;
}

test("locks fixed output and failure categories", () => {
  assert.equal(SUCCESS_LINE, "Tetragon signal proof passed: process=true file=true network=true identity=true capability=true drops=0 cleanup=true.");
  assert.deepEqual(FAILURE_CATEGORIES, [
    "capability",
    "cleanup",
    "configuration",
    "normalization",
    "operation",
    "ownership",
    "provider",
  ]);
});

test("builds exact network, kind, Helm, and fixture command arguments", () => {
  assert.deepEqual(buildNetworkCreateArguments(names.cluster, marker), [
    "network", "create", "--driver", "bridge", "--internal",
    "--label", "zasp.dev/proof=m0-12", "--label", `zasp.dev/run=${marker}`,
    names.cluster,
  ]);
  assert.deepEqual(buildKindCreateArguments(names, {
    config: "/owned/kind.json",
    kubeconfig: "/owned/kubeconfig",
    nodeImage: "kindest/node:v1.35.5@sha256:fixture",
  }), [
    "create", "cluster", "--name", names.cluster, "--config", "/owned/kind.json",
    "--kubeconfig", "/owned/kubeconfig", "--image",
    "kindest/node:v1.35.5@sha256:fixture", "--wait", "180s",
  ]);
  assert.deepEqual(buildHelmInstallArguments({
    chart: "/owned/tetragon.tgz",
    kubeconfig: "/owned/kubeconfig",
    values: "/owned/values.json",
  }), [
    "upgrade", "--install", "tetragon", "/owned/tetragon.tgz", "--namespace",
    "kube-system", "--kubeconfig", "/owned/kubeconfig", "--values",
    "/owned/values.json", "--wait", "--timeout", "180s",
  ]);
  assert.deepEqual(fixtureTriggerCommands(names, "10.96.0.23"), [
    ["exec", "--namespace", names.namespace, names.workloadPod, "--", "/bin/echo", "zasp-m0-12-exec"],
    ["exec", "--namespace", names.namespace, names.workloadPod, "--", "/bin/sh", "-c", "printf zasp-m0-12 > /tmp/zasp-m0-12-proof.txt && cat /tmp/zasp-m0-12-proof.txt >/dev/null"],
    ["exec", "--namespace", names.namespace, names.workloadPod, "--", "/bin/nc", "-w", "2", "10.96.0.23", "18080"],
  ]);
});

test("builds an allowlisted tool environment without ambient credential or proxy state", () => {
  const environment = buildToolEnvironment({
    path: "/fixed/bin",
    home: "/owned/home",
    dockerConfig: "/owned/docker",
    kubeconfig: "/owned/kubeconfig",
    network: names.cluster,
  });

  assert.deepEqual(environment, {
    DOCKER_CONFIG: "/owned/docker",
    HOME: "/owned/home",
    KIND_EXPERIMENTAL_DOCKER_NETWORK: names.cluster,
    KUBECONFIG: "/owned/kubeconfig",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATH: "/fixed/bin",
  });
  for (const key of Object.keys(environment)) {
    assert.doesNotMatch(key, /AWS|GOOGLE|AZURE|TOKEN|PASSWORD|PROXY|KUBECONFIG_PATH/i);
  }
});

test("classifies only thrown, signaled, or malformed-zero mutations as ambiguous", () => {
  const valid = (value) => /^[0-9a-f]{64}\n$/.test(value.stdout);
  assert.equal(classifyMutationOutcome({ status: 0, signal: null, stdout: `${"a".repeat(64)}\n`, stderr: "" }, valid), "success");
  assert.equal(classifyMutationOutcome({ status: 1, signal: null, stdout: "", stderr: "rejected" }, valid), "definitive");
  assert.equal(classifyMutationOutcome({ status: 0, signal: "SIGKILL", stdout: "", stderr: "" }, valid), "ambiguous");
  assert.equal(classifyMutationOutcome({ status: 0, signal: null, stdout: "invalid\n", stderr: "" }, valid), "ambiguous");
  assert.equal(classifyMutationOutcome(undefined, valid), "ambiguous");
});

test("runBounded captures a successful child within one combined byte cap", async () => {
  let invocation;
  const result = await runBounded("tool", ["arg"], {
    env: { PATH: "/fixed" },
    timeoutMs: 1000,
    maximumBytes: 8,
  }, (command, arguments_, options) => {
    invocation = { command, arguments_, options };
    return childProcess({ stdout: "abcd", stderr: "efgh" });
  });

  assert.deepEqual(invocation, {
    command: "tool",
    arguments_: ["arg"],
    options: { env: { PATH: "/fixed" }, stdio: ["ignore", "pipe", "pipe"] },
  });
  assert.deepEqual(result, { status: 0, signal: null, stdout: "abcd", stderr: "efgh" });
});

test("runBounded SIGKILLs combined overflow and deadline without leaking listeners", async () => {
  let overflowChild;
  await assert.rejects(
    runBounded("tool", [], { env: {}, timeoutMs: 1000, maximumBytes: 7 }, () => {
      overflowChild = childProcess({ stdout: "abcd", stderr: "efgh", delay: 1 });
      return overflowChild;
    }),
    Failure,
  );
  assert.deepEqual(overflowChild.kills, ["SIGKILL"]);
  assert.equal(overflowChild.stdout.listenerCount("data"), 0);
  assert.equal(overflowChild.stderr.listenerCount("data"), 0);

  let timedChild;
  await assert.rejects(
    runBounded("tool", [], { env: {}, timeoutMs: 5, maximumBytes: 8 }, () => {
      timedChild = childProcess({ delay: 1000 });
      return timedChild;
    }),
    Failure,
  );
  assert.deepEqual(timedChild.kills, ["SIGKILL"]);
});

test("runBounded contains stdout and stderr pipe errors", async () => {
  let child;
  const promise = runBounded("tool", [], { env: {}, timeoutMs: 1000, maximumBytes: 8 }, () => {
    child = childProcess({ delay: 1000 });
    return child;
  });
  child.stdout.emit("error", new Error("sensitive pipe detail"));
  await assert.rejects(promise, Failure);
  assert.deepEqual(child.kills, ["SIGKILL"]);
});

test("runBounded SIGKILLs and reaps a child when its phase signal aborts", async () => {
  const controller = new AbortController();
  const child = childProcess({ delay: 1000 });
  const execution = runBounded("tool", [], {
    env: { PATH: "/fixed/bin" },
    maximumBytes: 4096,
    timeoutMs: 5000,
    signal: controller.signal,
  }, () => child);
  controller.abort();
  await assert.rejects(execution, Failure);
  assert.deepEqual(child.kills, ["SIGKILL"]);
  assert.equal(child.listenerCount("close"), 0);
});

test("orchestrates the exact main and independent cleanup sequence", async () => {
  const runtime = new FakeRuntime();
  const result = await orchestrate(runtime, { mainTimeoutMs: 1000, cleanupTimeoutMs: 1000 });

  assert.deepEqual(runtime.events, [
    "preflight", "createCluster", "installTetragon", "runFixture",
    "captureEvidence", "joinMutations", "cleanup", "auditAbsence",
  ]);
  assert.equal(result.cleanup, true);
  assert.equal(result.drops, 0);
});

test("cleanup continues and wins precedence after a main failure", async () => {
  const runtime = new FakeRuntime({
    captureError: new Failure("normalization"),
    cleanupError: new Failure("cleanup"),
  });

  await assert.rejects(
    orchestrate(runtime, { mainTimeoutMs: 1000, cleanupTimeoutMs: 1000 }),
    (error) => error instanceof Failure && error.category === "cleanup",
  );
  assert.deepEqual(runtime.events.slice(-3), ["joinMutations", "cleanup", "auditAbsence"]);
});

test("main deadline revokes authority before independent cleanup", async () => {
  const runtime = new FakeRuntime({ waitForAbort: true });

  await assert.rejects(
    orchestrate(runtime, { mainTimeoutMs: 5, cleanupTimeoutMs: 1000 }),
    (error) => error instanceof Failure && error.category === "operation",
  );
  assert.deepEqual(runtime.events, [
    "preflight", "createCluster", "installTetragon", "runFixture",
    "joinMutations", "cleanup", "auditAbsence",
  ]);
});

test("main deadline joins the revoked operation before cleanup begins", async () => {
  const events = [];
  const runtime = new FakeRuntime();
  runtime.runFixture = async (phase) => {
    events.push("main-start");
    await new Promise((resolve) => phase.signal.addEventListener("abort", () => {
      setTimeout(() => { events.push("main-settled"); resolve(); }, 10);
    }, { once: true }));
  };
  runtime.joinMutations = async () => { events.push("cleanup-start"); };

  await assert.rejects(
    orchestrate(runtime, { mainTimeoutMs: 5, cleanupTimeoutMs: 1000 }),
    (error) => error instanceof Failure && error.category === "operation",
  );
  assert.deepEqual(events, ["main-start", "main-settled", "cleanup-start"]);
});

test("mutation journal join failure still runs cleanup and absence audit", async () => {
  const runtime = new FakeRuntime({ joinError: new Failure("operation") });

  await assert.rejects(
    orchestrate(runtime, { mainTimeoutMs: 1000, cleanupTimeoutMs: 1000 }),
    (error) => error instanceof Failure && error.category === "operation",
  );
  assert.deepEqual(runtime.events.slice(-3), ["joinMutations", "cleanup", "auditAbsence"]);
});

test("runMain emits exactly one success line", async () => {
  let stdout = "";
  let stderr = "";
  let exitCode;
  const code = await runMain(new FakeRuntime(), {
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
    setExitCode: (value) => { exitCode = value; },
  });

  assert.equal(code, 0);
  assert.equal(exitCode, 0);
  assert.equal(stdout, `${SUCCESS_LINE}\n`);
  assert.equal(stderr, "");
});

test("runMain contains construction, panic, and provider details in fixed categories", async () => {
  for (const [name, runtimeFactory, category] of [
    ["construction", () => { throw new Error("secret construction detail"); }, "operation"],
    ["panic", () => new FakeRuntime({ createError: new Error("secret panic detail") }), "operation"],
    ["provider", () => new FakeRuntime({ installError: new Failure("provider", "provider payload") }), "provider"],
  ]) {
    let stdout = "";
    let stderr = "";
    const code = await runMain(undefined, {
      runtimeFactory,
      stdout: { write: (value) => { stdout += value; } },
      stderr: { write: (value) => { stderr += value; } },
      setExitCode: () => {},
    });
    assert.equal(code, 1, name);
    assert.equal(stdout, "", name);
    assert.equal(stderr, `Tetragon signal proof failed: ${category} rejected.\n`, name);
    assert.doesNotMatch(stderr, /secret|payload/, name);
  }
});

test("DockerKindRuntime refuses ambient input and requires injected exact tooling", () => {
  assert.throws(() => new DockerKindRuntime({}), TypeError);
  assert.throws(() => new DockerKindRuntime({
    marker,
    organizationId: "org_aaaaaaaaaaaaaaaa",
    path: "/fixed/bin",
    hostPlatform: "darwin/arm64",
    nodePlatform: "linux/arm64",
    ambient: { HTTP_PROXY: "http://foreign" },
  }), TypeError);
});

test("DockerKindRuntime drives an injected lifecycle with retained candidate state", async () => {
  const events = [];
  let candidate = false;
  const lifecycle = {
    async preflight() { events.push("preflight"); },
    async createCluster() { events.push("createCluster"); candidate = true; },
    async installTetragon() { events.push("installTetragon"); },
    async runFixture() { events.push("runFixture"); },
    async captureEvidence() { events.push("captureEvidence"); return proofResult(); },
    async joinMutations() { events.push("joinMutations"); },
    async cleanup() { events.push("cleanup"); candidate = false; },
    async auditAbsence() { events.push("auditAbsence"); },
    hasCandidate() { return candidate; },
  };
  const runtime = new DockerKindRuntime({
    marker,
    organizationId: "org_aaaaaaaaaaaaaaaa",
    path: "/fixed/bin",
    hostPlatform: "darwin/arm64",
    nodePlatform: "linux/arm64",
  }, { lifecycle });
  const phase = { signal: new AbortController().signal, assertActive() {} };

  await runtime.preflight(phase);
  await runtime.createCluster(phase);
  assert.equal(runtime.hasCandidate(), true);
  await runtime.installTetragon(phase);
  await runtime.runFixture(phase);
  assert.deepEqual(await runtime.captureEvidence(phase), proofResult());
  await runtime.joinMutations(phase);
  await runtime.cleanup(phase);
  assert.equal(runtime.hasCandidate(), false);
  await runtime.auditAbsence(phase);
  assert.deepEqual(events, [
    "preflight", "createCluster", "installTetragon", "runFixture",
    "captureEvidence", "joinMutations", "cleanup", "auditAbsence",
  ]);
});

test("DockerKindLifecycle drives the concrete system in dependency order", async () => {
  const events = [];
  let candidate = false;
  const system = {
    async initialize() { events.push("initialize"); },
    async preflight() { events.push("preflight"); },
    async resolveAssets() { events.push("resolveAssets"); },
    async createNetwork() { events.push("createNetwork"); candidate = true; },
    async createCluster() { events.push("createCluster"); },
    async installTetragon() { events.push("installTetragon"); },
    async runFixture() { events.push("runFixture"); },
    async captureEvidence() { events.push("captureEvidence"); return proofResult(); },
    async joinMutations() { events.push("joinMutations"); },
    async cleanup() { events.push("cleanup"); candidate = false; },
    async auditAbsence() { events.push("auditAbsence"); },
    hasCandidate() { return candidate; },
  };
  const lifecycle = new DockerKindLifecycle({
    marker,
    organizationId: "org_aaaaaaaaaaaaaaaa",
    path: "/fixed/bin",
    hostPlatform: "darwin/arm64",
    nodePlatform: "linux/arm64",
  }, { system });
  const phase = { signal: new AbortController().signal, assertActive() {} };

  await lifecycle.preflight(phase);
  await lifecycle.createCluster(phase);
  assert.equal(lifecycle.hasCandidate(), true);
  await lifecycle.installTetragon(phase);
  await lifecycle.runFixture(phase);
  assert.deepEqual(await lifecycle.captureEvidence(phase), proofResult());
  await lifecycle.joinMutations(phase);
  await lifecycle.cleanup(phase);
  assert.equal(lifecycle.hasCandidate(), false);
  await lifecycle.auditAbsence(phase);
  assert.deepEqual(events, [
    "initialize", "preflight", "resolveAssets", "createNetwork", "createCluster",
    "installTetragon", "runFixture", "captureEvidence", "joinMutations",
    "cleanup", "auditAbsence",
  ]);
});

test("DockerKindSystem retains and cleans an mkdtemp candidate after invalid initial proof", async () => {
  const parent = "/safe/tmp";
  const candidate = `${parent}/zasp-m0-12-${marker}-runtime-owned`;
  const removed = [];
  let candidateStats = 0;
  let candidateRemoved = false;
  const status = (symbolic = false) => ({
    dev: 7,
    ino: 9,
    isDirectory: () => true,
    isFile: () => false,
    isSymbolicLink: () => symbolic,
  });
  const system = new DockerKindSystem({
    marker,
    organizationId: "org_aaaaaaaaaaaaaaaa",
    path: "/fixed/bin",
    hostPlatform: "darwin/arm64",
    nodePlatform: "linux/arm64",
  }, {
    tempParent: parent,
    canonicalPath: async (value) => value,
    statPath: async (value) => {
      if (value !== candidate || candidateRemoved) throw Object.assign(new Error("missing"), { code: "ENOENT" });
      candidateStats += 1;
      return status(candidateStats === 1);
    },
    readDirectory: async (value) => value === parent ? [] : [],
    makeTemp: async () => candidate,
    makeDirectory: async () => {},
    writePath: async () => {},
    readPath: async () => Buffer.from("fixture"),
    changeMode: async () => {},
    removePath: async (value) => { removed.push(value); candidateRemoved = true; },
    command: async () => ({ status: 0, signal: null, stdout: "ok\n", stderr: "" }),
    fetchBytes: async () => Buffer.from("fixture"),
    normalize: () => proofResult(),
    wait: async () => {},
  });
  const phase = { signal: new AbortController().signal, assertActive() {} };

  await assert.rejects(system.initialize(phase), (error) => error instanceof Failure && error.category === "configuration");
  await system.cleanupTemporary(phase);
  assert.deepEqual(removed, [candidate]);
  assert.equal(system.hasCandidate(), false);
});
