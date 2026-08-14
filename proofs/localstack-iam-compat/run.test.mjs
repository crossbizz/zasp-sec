import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import http from "node:http";
import { tmpdir } from "node:os";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  LOCALSTACK_IMAGE,
  DockerRuntime,
  buildDockerRunArguments,
  buildGoToolEnvironment,
  buildProofEnvironment,
  orchestrate,
  runBounded,
  runMain,
  successLine,
} from "./run.mjs";

const marker = "0123456789abcdef";
const name = `zasp-prov-01-${marker}`;
const token = "a".repeat(64);
const imageID = `sha256:${"b".repeat(64)}`;

class FakeRuntime {
  constructor({ proofCode = 0, ready = true, cleanupFails = false, candidate = false } = {}) {
    this.proofCode = proofCode; this.ready = ready; this.cleanupFails = cleanupFails; this.candidate = candidate; this.calls = [];
  }
  async ensureAbsent() { this.calls.push("ensure-absent"); }
  async start() { this.calls.push("start"); if (this.candidate) throw new Error("start detail"); return token; }
  async verifyOwned(value) { assert.equal(value, token); this.calls.push("verify-owned"); }
  async endpoint() { this.calls.push("endpoint"); return "http://127.0.0.1:49152"; }
  async isReady() { this.calls.push("ready"); return this.ready; }
  async runProof(value) { assert.equal(value, "http://127.0.0.1:49152"); this.calls.push("proof"); return this.proofCode; }
  hasCandidate() { return this.candidate; }
  async remove() { this.calls.push("remove"); if (this.cleanupFails) throw new Error("cleanup secret"); }
  async requireAbsent() { this.calls.push("require-absent"); if (this.cleanupFails) throw new Error("absence secret"); }
}

class ScriptedRuntime extends DockerRuntime {
  constructor(responses) {
    super({ path: "/safe/path", marker });
    this.responses = responses; this.calls = [];
  }
  docker(args) { this.calls.push(args); return this.responses.shift() ?? result(1); }
}

function result(status = 0, stdout = "", stderr = "") { return { status, stdout, stderr }; }

test("builds the pinned isolated IAM/STS container command from an owned name", () => {
  assert.equal(LOCALSTACK_IMAGE, "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c");
  assert.deepEqual(buildDockerRunArguments(name), [
    "run", "--detach", "--rm", "--name", name, "--publish", "127.0.0.1::4566",
    "--env", "SERVICES=iam,sts", "--env", "ENFORCE_IAM=1", "--env", "PERSISTENCE=0",
    "--label", "zasp.proof=prov-01", "--label", `zasp.marker=${marker}`, LOCALSTACK_IMAGE,
  ]);
  for (const invalid of ["zasp-prov-01-short", "zasp-m0-07-0123456789abcdef", `${name}x`]) {
    assert.throws(() => buildDockerRunArguments(invalid));
  }
});

test("creates narrow proof and offline Go environments with no ambient credentials", () => {
  assert.deepEqual(buildProofEnvironment("http://127.0.0.1:49152", "/safe/bin"), { AWS_ENDPOINT_URL: "http://127.0.0.1:49152", PATH: "/safe/bin" });
  assert.deepEqual(buildGoToolEnvironment("/safe/bin", "/safe/cache", "/safe/modcache"), {
    PATH: "/safe/bin", GOCACHE: "/safe/cache", GOMODCACHE: "/safe/modcache", GOENV: "off", GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local", CGO_ENABLED: "0",
  });
});

test("rejects an absent pinned image and a prefixed container collision before start", async () => {
  for (const responses of [
    [result(0), result(1)],
    [result(0, `${token}\n`), result(0, imageID)],
  ]) {
    const runtime = new ScriptedRuntime(responses);
    await assert.rejects(runtime.ensureAbsent(), (error) => error?.category === "operation");
  }
});

test("does not accept wrong current container ownership fields", async () => {
  const expected = `${token}|/${name}|${imageID}|${LOCALSTACK_IMAGE}|prov-01|${marker}`;
  for (const received of [
    expected.replace(token, "c".repeat(64)), expected.replace(`/${name}`, "/wrong"), expected.replace(imageID, `sha256:${"d".repeat(64)}`),
    expected.replace(LOCALSTACK_IMAGE, "localstack/localstack:latest"), expected.replace("prov-01", "wrong"), expected.replace(marker, "fedcba9876543210"),
  ]) {
    const runtime = new ScriptedRuntime([result(0, `${received}\n`)]);
    runtime.resolvedImageID = imageID;
    await assert.rejects(runtime.verifyOwned(token), (error) => error?.category === "operation");
  }
});

test("reconciles an ambiguous start only through an exact owned candidate", async () => {
  const runtime = new ScriptedRuntime([
    result(1), result(0, `${token}\n`), result(0, `${token}|/${name}|${imageID}|${LOCALSTACK_IMAGE}|prov-01|${marker}\n`),
  ]);
  runtime.resolvedImageID = imageID;
  assert.equal(await runtime.start(), token);
  assert.equal(runtime.hasCandidate(), true);
});

test("keeps failed start attempts as exact-name cleanup candidates and uses untruncated IDs", async () => {
  const direct = new ScriptedRuntime([result(1, `${token}\n`), result(1)]);
  await assert.rejects(direct.start(), (error) => error?.category === "operation");
  assert.equal(direct.hasCandidate(), true);
  assert.ok(direct.calls[1].includes("--no-trunc"));
  const unnamed = new ScriptedRuntime([result(1), result(1)]);
  await assert.rejects(unnamed.start(), (error) => error?.category === "operation");
  assert.equal(unnamed.hasCandidate(), true);
  assert.ok(unnamed.calls[1].includes("--no-trunc"));
});

test("rejects published ports that are not numeric loopback high ports", async () => {
  for (const value of ["0.0.0.0:49152", "127.0.0.1:80", "[::1]:49152", "127.0.0.1:99999", "127.0.0.1:49152\n127.0.0.1:49153"]) {
    const runtime = new ScriptedRuntime([result(0, `${token}|/${name}|${imageID}|${LOCALSTACK_IMAGE}|prov-01|${marker}\n`), result(0, `${value}\n`)]);
    runtime.resolvedImageID = imageID;
    await assert.rejects(runtime.endpoint(token), (error) => error?.category === "operation");
  }
});

test("orchestrates readiness, proof, and exact final absence", async () => {
  const runtime = new FakeRuntime();
  assert.deepEqual(await orchestrate(runtime, { readinessAttempts: 1, wait: async () => {} }), { code: 0, line: successLine });
  assert.deepEqual(runtime.calls, ["ensure-absent", "start", "verify-owned", "endpoint", "ready", "proof", "remove", "require-absent"]);
});

test("propagates proof exit code while cleanup failure takes precedence", async () => {
  const failed = new FakeRuntime({ proofCode: 23 });
  assert.deepEqual(await orchestrate(failed, { readinessAttempts: 1, wait: async () => {} }), { code: 23, line: "LocalStack IAM compatibility proof failed: operation rejected." });
  const cleanup = new FakeRuntime({ proofCode: 23, cleanupFails: true });
  assert.deepEqual(await orchestrate(cleanup, { readinessAttempts: 1, wait: async () => {} }), { code: 1, line: "LocalStack IAM compatibility proof failed: cleanup rejected." });
});

test("cleans an owned candidate after ambiguous start and rejects service readiness exhaustion", async () => {
  const candidate = new FakeRuntime({ candidate: true });
  assert.deepEqual(await orchestrate(candidate, { readinessAttempts: 1, wait: async () => {} }), { code: 1, line: "LocalStack IAM compatibility proof failed: operation rejected." });
  assert.deepEqual(candidate.calls, ["ensure-absent", "start", "remove", "require-absent"]);
  const unready = new FakeRuntime({ ready: false });
  assert.deepEqual(await orchestrate(unready, { readinessAttempts: 2, wait: async () => {} }), { code: 1, line: "LocalStack IAM compatibility proof failed: readiness rejected." });
  assert.equal(unready.calls.filter((call) => call === "ready").length, 2);
});

async function withHealthServer(handler, assertion) {
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  try { await assertion(`http://127.0.0.1:${server.address().port}`); } finally { server.closeAllConnections?.(); await new Promise((resolve) => server.close(resolve)); }
}

test("bounds oversized and endless readiness bodies and requires both IAM and STS", async () => {
  await withHealthServer((_request, response) => { response.writeHead(200); response.write("x".repeat(16_385)); }, async (endpoint) => {
    const runtime = new DockerRuntime({ path: "/safe/path", marker });
    assert.equal(await runtime.isReady(endpoint), false);
  });
  await withHealthServer((_request, response) => { response.writeHead(200); const timer = setInterval(() => response.write("x"), 10); response.once("close", () => clearInterval(timer)); }, async (endpoint) => {
    const runtime = new DockerRuntime({ path: "/safe/path", marker });
    const observed = await Promise.race([runtime.isReady(endpoint), new Promise((resolve) => setTimeout(() => resolve("unbounded"), 800))]);
    assert.equal(observed, false);
  });
  await withHealthServer((_request, response) => { response.end(JSON.stringify({ services: { iam: "running", sts: "stopped" } })); }, async (endpoint) => {
    const runtime = new DockerRuntime({ path: "/safe/path", marker });
    assert.equal(await runtime.isReady(endpoint), false);
  });
});

test("uses an allowlisted HOME to discover real Go caches before an offline build", async () => {
  const calls = [];
  const directory = `${tmpdir()}/zasp-prov-01-owned`;
  const runtime = new DockerRuntime({
    path: "/safe/path", home: "/safe/home", marker,
    command: (...args) => { calls.push(args); return result(1); },
    makeTemp: () => directory, removeTemp: () => {},
  });
  assert.equal(await runtime.runProof("http://127.0.0.1:49152"), 1);
  assert.deepEqual(calls[0][2].env, { PATH: "/safe/path", HOME: "/safe/home" });
});

test("never removes malformed temporary factory results before strict canonical ownership", async () => {
  const parent = "/safe/tmp";
  const prefix = `${parent}/zasp-prov-01-`;
  const owned = `${prefix}owned`;
  const cases = [
    { name: "relative", value: "zasp-prov-01-owned" },
    { name: "bare prefix", value: prefix },
    { name: "traversal", value: `${owned}/../escape` },
    { name: "unowned parent", value: "/safe/elsewhere/zasp-prov-01-owned" },
    { name: "symlink", value: `${prefix}symlink`, link: true },
    { name: "realpath escape", value: `${prefix}escape`, real: "/safe/elsewhere/zasp-prov-01-escape" },
    { name: "not directory", value: `${prefix}file`, directory: false },
  ];
  for (const testCase of cases) {
    const removed = [];
    const runtime = temporaryRuntime({
      parent, value: testCase.value, real: testCase.real ?? testCase.value,
      stat: { isDirectory: () => testCase.directory !== false, isSymbolicLink: () => testCase.link === true },
      removeTemp: (value) => { removed.push(value); },
    });
    assert.equal(await runtime.runProof("http://127.0.0.1:49152"), 1, testCase.name);
    assert.deepEqual(removed, [], testCase.name);
  }
});

test("builds and removes only a canonical owned temporary directory", async () => {
  const parent = "/safe/tmp";
  const directory = `${parent}/zasp-prov-01-owned`;
  const removed = []; let spawned = false;
  const runtime = temporaryRuntime({
    parent, value: directory, real: directory,
    stat: { isDirectory: () => true, isSymbolicLink: () => false },
    spawnProcess: () => { spawned = true; return fakeChild({ code: 1 }).child; },
    removeTemp: (value, options) => { removed.push({ value, options }); },
  });
  assert.equal(await runtime.runProof("http://127.0.0.1:49152"), 1);
  assert.equal(spawned, true);
  assert.deepEqual(removed, [{ value: directory, options: { recursive: true, force: false, maxRetries: 0 } }]);
});

test("rejects Go build failure and proof output overflow while removing the exact temporary directory", async () => {
  for (const processes of [
    [() => fakeChild({ code: 1, stderr: ["build failure"] })],
    [() => fakeChild(), () => fakeChild({ stdout: [`${successLine}${"x".repeat(4096)}`] })],
  ]) {
    const calls = []; let removed;
    const directory = `${tmpdir()}/zasp-prov-01-owned`;
    const runtime = new DockerRuntime({ path: "/safe/path", marker, tempParent: tmpdir(), canonicalPath: (value) => value, statPath: () => ({ isDirectory: () => true, isSymbolicLink: () => false }), command: (...args) => { calls.push(args); return result(0, JSON.stringify({ GOCACHE: "/safe/cache", GOMODCACHE: "/safe/modcache" })); }, spawnProcess: () => processes.shift()().child, makeTemp: () => directory, removeTemp: (value) => { removed = value; } });
    assert.equal(await runtime.runProof("http://127.0.0.1:49152"), 1);
    assert.equal(removed, directory);
    assert.equal(calls.length, 1);
  }
});

test("kills an uncooperative child at its deadline and on combined split-stream overflow", async () => {
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

test("contains construction and orchestration details at the one-line fixed-output boundary", async () => {
  for (const runtimeFactory of [
    () => new DockerRuntime({ path: "" }),
    () => new DockerRuntime({ path: "/safe/path", marker: "not-a-marker" }),
    () => ({ async ensureAbsent() { throw new Error("sensitive provider data"); }, hasCandidate() { return false; } }),
  ]) {
    let stdout = "", stderr = "", exitCode;
    const result = await runMain({ runtimeFactory, stdout: { write: (line) => { stdout += line; } }, stderr: { write: (line) => { stderr += line; } }, setExitCode: (code) => { exitCode = code; } });
    assert.equal(result, 1);
    assert.equal(stdout, "");
    assert.match(stderr, /^LocalStack IAM compatibility proof failed: (configuration|operation) rejected\.\n$/);
    assert.equal(stderr.includes("sensitive"), false);
    assert.equal(exitCode, 1);
  }
});

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
      child.stdout.end(); child.stderr.end(); child.emit("close", code, null);
    }
  });
  return { child, signals };
}

function temporaryRuntime({ parent, value, real, stat, spawnProcess = () => { throw new Error("build must not start"); }, removeTemp }) {
  return new DockerRuntime({
    path: "/safe/path", home: "/safe/home", marker, tempParent: parent,
    canonicalPath: (path) => path === parent ? parent : real,
    statPath: () => stat,
    command: () => result(0, JSON.stringify({ GOCACHE: "/safe/cache", GOMODCACHE: "/safe/modcache" })),
    spawnProcess, makeTemp: () => value, removeTemp,
  });
}
