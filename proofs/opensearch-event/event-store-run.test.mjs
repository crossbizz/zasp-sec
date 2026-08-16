import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  OPENSEARCH_IMAGE,
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
    { status: 0, stdout: "", stderr: "" },
    { status: 1, signal: null, stdout: "", stderr: `Error response from daemon: No such image: ${OPENSEARCH_IMAGE}\n` },
    { status: 0, signal: null, stdout: "pulled", stderr: "" },
    { status: 0, signal: null, stdout: `sha256:${"b".repeat(64)}\n`, stderr: "" },
  ];
  const runtime = new DockerRuntime({
    path: "/safe/path", home: "/safe/home", marker, mode: "event-store", canonicalPath: (value) => value,
    command: (command, arguments_, options) => { calls.push({ command, arguments_, options }); return responses.shift(); },
  });
  await runtime.ensureAbsent();
  const pull = calls.find(({ arguments_ }) => arguments_[0] === "pull");
  assert.deepEqual(pull.arguments_, ["pull", OPENSEARCH_IMAGE]);
  assert.equal(pull.options.timeout, 180_000);
  assert.equal(calls[0].options.timeout, 60_000);
});

test("never pulls after a generic image inspection failure", async () => {
  const calls = [];
  const runtime = new DockerRuntime({
    path: "/safe/path", home: "/safe/home", marker, mode: "event-store", canonicalPath: (value) => value,
    command: (_command, arguments_) => {
      calls.push(arguments_);
      if (arguments_[0] === "ps") return { status: 0, signal: null, stdout: "", stderr: "" };
      if (arguments_[0] === "image") return { status: 1, signal: null, stdout: "", stderr: "daemon unavailable\n" };
      if (arguments_[0] === "pull") return { status: 0, signal: null, stdout: "pulled\n", stderr: "" };
      return { status: 0, signal: null, stdout: `sha256:${"b".repeat(64)}\n`, stderr: "" };
    },
  });
  await assert.rejects(runtime.ensureAbsent(), (error) => error?.category === "operation");
  assert.equal(calls.some((arguments_) => arguments_[0] === "pull"), false);
});

test("does not reconcile a definitive Docker start rejection", async () => {
  const token = "a".repeat(64);
  class RejectedRuntime extends DockerRuntime {
    constructor() {
      super({ path: "/safe/path", home: "/safe/home", marker, mode: "event-store", canonicalPath: (value) => value });
      this.resolvedImageID = `sha256:${"b".repeat(64)}`;
      this.calls = [];
    }
    docker(arguments_) {
      this.calls.push(arguments_);
      if (arguments_[0] === "run") return { status: 125, signal: null, stdout: "", stderr: "rejected\n" };
      return { status: 0, signal: null, stdout: `${token}\n`, stderr: "" };
    }
  }
  const runtime = new RejectedRuntime();
  await assert.rejects(runtime.start(), (error) => error?.category === "operation");
  assert.equal(runtime.calls.length, 1);
  assert.equal(runtime.hasCandidate(), false);
});

test("retains and re-proves a direct candidate from an abnormal Docker start", async () => {
  const token = "a".repeat(64);
  class AppliedRuntime extends DockerRuntime {
    constructor() {
      super({ path: "/safe/path", home: "/safe/home", marker, mode: "event-store", canonicalPath: (value) => value });
      this.resolvedImageID = `sha256:${"b".repeat(64)}`;
      this.calls = [];
    }
    docker(arguments_) {
      this.calls.push(arguments_);
      if (arguments_[0] === "run") return { status: 1, signal: null, stdout: `${token}\n`, stderr: "abnormal\n" };
      if (arguments_[0] === "inspect") {
        return {
          status: 0,
          signal: null,
          stdout: `${token}|/${productName}|${this.resolvedImageID}|${OPENSEARCH_IMAGE}|m1-14|${marker}\n`,
          stderr: "",
        };
      }
      throw new Error("unexpected provider call");
    }
  }
  const runtime = new AppliedRuntime();
  assert.equal(await runtime.start(), token);
  assert.equal(runtime.hasCandidate(), true);
  assert.deepEqual(runtime.calls.map((arguments_) => arguments_[0]), ["run", "inspect"]);
});

test("requires retained full-ID absence even if the generated name is absent", async () => {
  const token = "c".repeat(64);
  class RenamedRuntime extends DockerRuntime {
    constructor() {
      super({ path: "/safe/path", home: "/safe/home", marker, mode: "event-store", canonicalPath: (value) => value });
      this.token = token;
    }
    docker(arguments_) {
      if (arguments_.includes(`id=${token}`)) return { status: 0, signal: null, stdout: `${token}\n`, stderr: "" };
      if (arguments_[0] === "inspect") return { status: 1, signal: null, stdout: "", stderr: "missing\n" };
      return { status: 0, signal: null, stdout: "", stderr: "" };
    }
  }
  await assert.rejects(new RenamedRuntime().requireAbsent(), (error) => error?.category === "cleanup");
});

test("rejects stale proof containers and temporary directories across markers", async () => {
  const staleID = "d".repeat(64);
  for (const stale of ["container", "temporary directory"]) {
    const runtime = new DockerRuntime({
      path: "/safe/path", home: "/safe/home", marker, mode: "event-store", tempParent: "/safe/tmp",
      canonicalPath: (value) => value,
      readTemp: () => stale === "temporary directory" ? ["zasp-m1-14-fedcba9876543210"] : [],
      command: (_command, arguments_) => {
        const filter = arguments_[arguments_.indexOf("--filter") + 1];
        if (stale === "container" && arguments_[0] === "ps" && filter === "name=^/zasp-m1-14-") {
          return { status: 0, signal: null, stdout: `${staleID}\n`, stderr: "" };
        }
        if (arguments_[0] === "ps") return { status: 0, signal: null, stdout: "", stderr: "" };
        if (arguments_[0] === "image") return { status: 0, signal: null, stdout: `sha256:${"b".repeat(64)}\n`, stderr: "" };
        return { status: 0, signal: null, stdout: "", stderr: "" };
      },
    });
    await assert.rejects(runtime.ensureAbsent(), (error) => error?.category === "operation");
  }
});

test("uses SIGKILL for bounded synchronous provider commands", () => {
  let options;
  const runtime = new DockerRuntime({
    path: "/safe/path", home: "/safe/home", marker, mode: "event-store", canonicalPath: (value) => value,
    command: (_command, _arguments, value) => { options = value; return { status: 0, signal: null, stdout: "", stderr: "" }; },
  });
  runtime.docker(["version"]);
  assert.equal(options.killSignal, "SIGKILL");
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
      runBounded("proof", [], { cwd: "/safe", env: {}, timeoutMs: 20, terminationGraceMs: 10, outputLimit: 4096 }, () => child.child),
      (error) => error?.category === "operation",
    );
    assert.deepEqual(child.signals, ["SIGKILL"]);
  }
});

test("waits for the killed child to close before releasing cleanup", async () => {
  const child = fakeChild({ neverClose: true });
  let settled = false;
  const pending = runBounded(
    "proof", [], { cwd: "/safe", env: {}, timeoutMs: 5, terminationGraceMs: 100, outputLimit: 4096 },
    () => child.child,
  );
  pending.then(() => { settled = true; }, () => { settled = true; });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(child.signals, ["SIGKILL"]);
  assert.equal(settled, false);
  child.child.emit("close", null, "SIGKILL");
  await assert.rejects(pending, (error) => error?.category === "operation");
});

test("runs the exact EventStore child and removes only an unchanged owned temp directory", async () => {
  const parent = "/safe/tmp";
  const directory = `${parent}/zasp-m1-14-owned`;
  const calls = [];
  const removals = [];
  const stats = [identityStat(1, 10), identityStat(1, 10), missingPath()];
  const processes = [
    () => fakeChild(),
    () => fakeChild({ stdout: ["OpenSearch event store passed: index=true search=true scoped=true cross_organization_zero=true cleanup=true audit=true.\n"] }),
  ];
  const runtime = temporaryRuntime({
    parent, directory,
    statPath: () => {
      const value = stats.shift();
      if (value instanceof Error) throw value;
      return value;
    },
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
  const stats = [new Error("transient"), identityStat(1, 10), identityStat(1, 10), missingPath()];
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

test("fails when recursive temp removal returns without proving absence", async () => {
  const parent = "/safe/tmp";
  const directory = `${parent}/zasp-m1-14-owned`;
  const runtime = temporaryRuntime({
    parent, directory,
    statPath: () => identityStat(1, 10),
    spawnProcess: (() => {
      const processes = [
        () => fakeChild(),
        () => fakeChild({ stdout: ["OpenSearch event store passed: index=true search=true scoped=true cross_organization_zero=true cleanup=true audit=true.\n"] }),
      ];
      return () => processes.shift()().child;
    })(),
    removeTemp: () => {},
  });
  assert.equal(await runtime.runProof("http://127.0.0.1:49152", "event-store"), 1);
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

function missingPath() {
  return Object.assign(new Error("missing"), { code: "ENOENT" });
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
