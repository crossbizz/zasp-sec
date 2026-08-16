import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  DockerRuntime,
  buildDockerRunArguments,
  eventStoreSuccessLine,
  orchestrate,
  proofExecutableArguments,
  runBounded,
} from "./run.mjs";

const marker = "0123456789abcdef";
const productName = `zasp-m1-14-${marker}`;

test("binds the exact EventStore container and proof-child arguments", () => {
  const arguments_ = buildDockerRunArguments(productName, "event-store");
  assert.ok(arguments_.includes("zasp.proof=m1-14"));
  assert.ok(arguments_.includes(`zasp.marker=${marker}`));
  assert.deepEqual(proofExecutableArguments("event-store"), ["event-store"]);
  assert.deepEqual(proofExecutableArguments("projection"), []);
  assert.throws(() => proofExecutableArguments("raw-provider"));
  assert.throws(() => buildDockerRunArguments(`zasp-m0-08-${marker}`, "event-store"));
});

test("gives only the exact pinned image pull its bounded extended budget", async () => {
  const calls = [];
  const responses = [
    { status: 0, stdout: "", stderr: "" },
    { status: 1, stdout: "", stderr: "missing" },
    { status: 0, stdout: "pulled", stderr: "" },
    { status: 0, stdout: `sha256:${"b".repeat(64)}\n`, stderr: "" },
  ];
  const runtime = new DockerRuntime({
    path: "/safe/path", home: "/safe/home", marker, mode: "event-store", canonicalPath: (value) => value,
    command: (command, arguments_, options) => { calls.push({ command, arguments_, options }); return responses.shift(); },
  });
  await runtime.ensureAbsent();
  assert.deepEqual(calls[2].arguments_, ["pull", calls[3].arguments_.at(-1)]);
  assert.equal(calls[2].options.timeout, 180_000);
  assert.equal(calls[0].options.timeout, 60_000);
});

test("returns the exact EventStore success only after cleanup and absence", async () => {
  const calls = [];
  const runtime = {
    async ensureAbsent() { calls.push("ensure"); },
    async start() { calls.push("start"); return "owned"; },
    async verifyOwned(value) { assert.equal(value, "owned"); calls.push("verify"); },
    async endpoint() { calls.push("endpoint"); return "http://127.0.0.1:49152"; },
    async isReady() { calls.push("ready"); return true; },
    async runProof(endpoint, mode) { assert.equal(endpoint, "http://127.0.0.1:49152"); assert.equal(mode, "event-store"); calls.push("proof"); return 0; },
    async remove() { calls.push("remove"); },
    async requireAbsent() { calls.push("absent"); },
  };
  assert.deepEqual(await orchestrate(runtime, { mode: "event-store", readinessAttempts: 1 }), { code: 0, line: eventStoreSuccessLine });
  assert.deepEqual(calls, ["ensure", "start", "verify", "endpoint", "ready", "proof", "remove", "absent"]);
});

test("hard-kills uncooperative children and enforces one combined output cap", async () => {
  for (const child of [
    fakeChild({ neverClose: true }),
    fakeChild({ stdout: ["x".repeat(3000)], stderr: ["y".repeat(1100)], neverClose: true }),
  ]) {
    await assert.rejects(
      runBounded("proof", [], { cwd: "/safe", env: {}, timeoutMs: 20, outputLimit: 4096 }, () => child.child),
      (error) => error?.category === "operation",
    );
    assert.deepEqual(child.signals, ["SIGKILL"]);
  }
});

test("runs the exact EventStore child and removes only an unchanged owned temp directory", async () => {
  const parent = "/safe/tmp";
  const directory = `${parent}/zasp-m1-14-owned`;
  const calls = [];
  const removals = [];
  const processes = [
    () => fakeChild(),
    () => fakeChild({ stdout: ["OpenSearch event store passed: index=true search=true scoped=true cross_organization_zero=true cleanup=true audit=true.\n"] }),
  ];
  const runtime = temporaryRuntime({
    parent, directory,
    spawnProcess: (command, arguments_) => {
      calls.push({ command, arguments_ });
      return processes.shift()().child;
    },
    removeTemp: (value, options) => { removals.push({ value, options }); },
  });
  assert.equal(await runtime.runProof("http://127.0.0.1:49152", "event-store"), 0);
  assert.deepEqual(calls[0].arguments_.slice(0, 3), ["build", "-trimpath", "-mod=readonly"]);
  assert.deepEqual(calls[1].arguments_, ["event-store"]);
  assert.deepEqual(removals, [{ value: directory, options: { recursive: true, force: false, maxRetries: 0 } }]);
});

test("skips recursive removal after cleanup-time temp identity replacement", async () => {
  const parent = "/safe/tmp";
  const directory = `${parent}/zasp-m1-14-owned`;
  const identities = [identityStat(1, 10), identityStat(1, 11)];
  const removals = [];
  const runtime = temporaryRuntime({
    parent, directory,
    statPath: () => identities.shift(),
    spawnProcess: () => fakeChild({ code: 1 }).child,
    removeTemp: (value) => { removals.push(value); },
  });
  assert.equal(await runtime.runProof("http://127.0.0.1:49152", "event-store"), 1);
  assert.deepEqual(removals, []);
});

test("recovers an exact mkdtemp candidate after transient admission failure", async () => {
  const parent = "/safe/tmp";
  const directory = `${parent}/zasp-m1-14-owned`;
  const stats = [new Error("transient"), identityStat(1, 10), identityStat(1, 10)];
  const removals = [];
  const runtime = temporaryRuntime({
    parent, directory,
    statPath: () => {
      const value = stats.shift();
      if (value instanceof Error) throw value;
      return value;
    },
    spawnProcess: () => { throw new Error("build must not start"); },
    removeTemp: (value, options) => { removals.push({ value, options }); },
  });
  assert.equal(await runtime.runProof("http://127.0.0.1:49152", "event-store"), 1);
  assert.deepEqual(removals, [{ value: directory, options: { recursive: true, force: false, maxRetries: 0 } }]);
});

function temporaryRuntime({ parent, directory, statPath = () => identityStat(1, 10), spawnProcess, removeTemp }) {
  return new DockerRuntime({
    path: "/safe/path", home: "/safe/home", marker, mode: "event-store", tempParent: parent,
    canonicalPath: (value) => value, statPath,
    command: () => ({ status: 0, stdout: JSON.stringify({ GOCACHE: "/safe/cache", GOMODCACHE: "/safe/modcache" }), stderr: "" }),
    spawnProcess, makeTemp: () => directory, removeTemp,
  });
}

function identityStat(dev, ino) {
  return { dev, ino, isDirectory: () => true, isSymbolicLink: () => false };
}

function fakeChild({ stdout = [], stderr = [], code = 0, neverClose = false } = {}) {
  const child = new EventEmitter();
  const signals = [];
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = (signal) => { signals.push(signal); return true; };
  queueMicrotask(() => {
    for (const chunk of stdout) child.stdout.write(chunk);
    for (const chunk of stderr) child.stderr.write(chunk);
    if (!neverClose) {
      child.stdout.end();
      child.stderr.end();
      child.emit("close", code, null);
    }
  });
  return { child, signals };
}
