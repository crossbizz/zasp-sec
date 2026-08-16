import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  IMAGE,
  SUCCESS_LINE,
  DockerRuntime,
  buildEnvironment,
  buildCreateArguments,
  classifyCommandMutation,
  classifyMutation,
  validateContainerMetadata,
  orchestrate,
  parseReadiness,
  runBounded,
  runMain,
} from "./run.mjs";

test("create arguments bind one exact-owned loopback-only Neo4j target", () => {
  const args = buildCreateArguments("zasp-m1-16-0123456789abcdef-neo4j", "0123456789abcdef");
  assert.deepEqual(args, [
    "create", "--name", "zasp-m1-16-0123456789abcdef-neo4j",
    "--label", "com.zasp.proof=neo4j-graphstore", "--label", "com.zasp.marker=0123456789abcdef",
    "--publish", "127.0.0.1::7474", "--publish", "127.0.0.1::7687",
    "--env", "NEO4J_AUTH=none",
    "--env", "NEO4J_db_tx__log_preallocate=false",
    "--env", "NEO4J_db_tx__log_rotation_size=128K",
    "--security-opt", "no-new-privileges:true",
    "--pids-limit", "512",
    "--memory", "1g",
    "--cpus", "2",
    IMAGE,
  ]);
  assert.match(IMAGE, /^neo4j:5\.26\.28-community@sha256:[0-9a-f]{64}$/);
});

test("proof build is offline and ignores ambient Go configuration", () => {
  assert.deepEqual(buildEnvironment("/bin", "/safe/home"), {
    PATH: "/bin",
    HOME: "/safe/home",
    GOENV: "off",
    GOPROXY: "off",
    GOSUMDB: "off",
    GOTOOLCHAIN: "local",
    CGO_ENABLED: "0",
  });
});

test("Docker mutation acknowledgements preserve real CLI output semantics", () => {
  const token = "a".repeat(64);
  assert.equal(classifyCommandMutation({ status: 0, signal: null, thrown: false, stdout: "pull progress\n", stderr: "download progress\n" }, "any"), "applied");
  assert.equal(classifyCommandMutation({ status: 0, signal: null, thrown: false, stdout: `${token}\n`, stderr: "" }, token), "applied");
  assert.equal(classifyCommandMutation({ status: 0, signal: null, thrown: false, stdout: "unexpected\n", stderr: "" }, token), "ambiguous");
  assert.equal(classifyCommandMutation({ status: 1, signal: null, thrown: false, stdout: "", stderr: "rejected" }, token), "definitive");
  assert.equal(classifyCommandMutation({ status: null, signal: "SIGKILL", thrown: false, stdout: "", stderr: "" }, token), "ambiguous");
});

test("container ownership accepts only the exact Docker-created security and intrinsic mounts", () => {
  const marker = "0123456789abcdef";
  const token = "c".repeat(64);
  const firstVolume = "a".repeat(64);
  const secondVolume = "b".repeat(64);
  const image = {
    id: `sha256:${"d".repeat(64)}`,
    env: ["PATH=/bin"],
    entrypoint: ["tini"],
    cmd: ["neo4j"],
    labels: {},
    exposed: ["7473/tcp", "7474/tcp", "7687/tcp"],
    volumes: ["/data", "/logs"],
  };
  const mount = (name, destination) => ({
    Type: "volume",
    Name: name,
    Source: `/var/lib/docker/volumes/${name}/_data`,
    Destination: destination,
    Driver: "local",
    Mode: "",
    RW: true,
    Propagation: "",
  });
  const container = {
    Id: token,
    Name: `/zasp-m1-16-${marker}-neo4j`,
    Image: image.id,
    State: { Status: "created", Running: false },
    Config: {
      Image: IMAGE,
      Labels: { "com.zasp.proof": "neo4j-graphstore", "com.zasp.marker": marker },
      Env: ["PATH=/bin", "NEO4J_AUTH=none", "NEO4J_db_tx__log_preallocate=false", "NEO4J_db_tx__log_rotation_size=128K"],
      Entrypoint: ["tini"],
      Cmd: ["neo4j"],
    },
    HostConfig: {
      Privileged: false,
      ReadonlyRootfs: false,
      NetworkMode: "bridge",
      Binds: null,
      SecurityOpt: ["no-new-privileges:true"],
      PidsLimit: 512,
      Memory: 1_073_741_824,
      NanoCpus: 2_000_000_000,
    },
    Mounts: [mount(secondVolume, "/logs"), mount(firstVolume, "/data")],
  };
  assert.deepEqual(validateContainerMetadata(container, { token, marker, name: `zasp-m1-16-${marker}-neo4j`, image, state: "created" }), [firstVolume, secondVolume]);
  for (const mutate of [
    (value) => { value.HostConfig.NetworkMode = "default"; },
    (value) => { value.HostConfig.Mounts = []; },
    (value) => { value.HostConfig.Tmpfs = null; },
    (value) => { value.HostConfig.SecurityOpt = []; },
    (value) => { value.Config.Labels.extra = "forged"; },
    (value) => { value.Mounts.push(mount("e".repeat(64), "/extra")); },
  ]) {
    const hostile = structuredClone(container);
    mutate(hostile);
    assert.throws(() => validateContainerMetadata(hostile, { token, marker, name: `zasp-m1-16-${marker}-neo4j`, image, state: "created" }));
  }
});

test("Docker metadata commands use a separate bounded response cap", async () => {
  const calls = [];
  const runtime = new DockerRuntime({
    marker: "0123456789abcdef",
    path: "/bin",
    home: "/safe/home",
    environment: {},
    command: async (command, args, options) => {
      calls.push({ command, args, options });
      return { status: 0, signal: null, thrown: false, stdout: "", stderr: "" };
    },
  });
  runtime.dockerConfig = "/safe/docker";
  await runtime.docker(["container", "inspect", "candidate"]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "docker");
  assert.deepEqual(calls[0].args, ["container", "inspect", "candidate"]);
  assert.equal(calls[0].options.outputLimit, 256 * 1024);
  assert.deepEqual(calls[0].options.env, { PATH: "/bin", DOCKER_CONFIG: "/safe/docker" });
});

test("ambiguous image pull is accepted only after immutable reinspection", async () => {
  const calls = [];
  const digest = IMAGE.split("@")[1];
  const image = {
    Id: `sha256:${"d".repeat(64)}`,
    RepoDigests: [`neo4j@${digest}`],
    Config: { Env: [], Entrypoint: ["entry"], Cmd: ["neo4j"], Labels: null, ExposedPorts: null, Volumes: null },
  };
  const responses = [
    { status: 1, signal: null, thrown: false, stdout: "", stderr: "Error: No such image\n" },
    { status: null, signal: "SIGKILL", thrown: false, stdout: "", stderr: "" },
    { status: 0, signal: null, thrown: false, stdout: `${JSON.stringify(image)}\n`, stderr: "" },
  ];
  const runtime = new DockerRuntime({
    marker: "0123456789abcdef", path: "/bin", home: "/safe/home", environment: {},
    command: async (_command, args) => { calls.push(args); return responses.shift(); },
  });
  runtime.dockerConfig = "/safe/docker";
  await runtime.resolveImage(new AbortController().signal);
  assert.equal(calls.length, 3);
  assert.equal(runtime.image.id, image.Id);
});

test("thrown image pull is accepted only after immutable reinspection", async () => {
  const calls = [];
  const digest = IMAGE.split("@")[1];
  const image = {
    Id: `sha256:${"d".repeat(64)}`,
    RepoDigests: [`neo4j@${digest}`],
    Config: { Env: [], Entrypoint: ["entry"], Cmd: ["neo4j"], Labels: null, ExposedPorts: null, Volumes: null },
  };
  const runtime = new DockerRuntime({
    marker: "0123456789abcdef", path: "/bin", home: "/safe/home", environment: {},
    command: async (_command, args) => {
      calls.push(args);
      if (calls.length === 1) return { status: 1, signal: null, thrown: false, stdout: "", stderr: "Error: No such image\n" };
      if (calls.length === 2) throw new Error("ambiguous pull boundary");
      return { status: 0, signal: null, thrown: false, stdout: `${JSON.stringify(image)}\n`, stderr: "" };
    },
  });
  runtime.dockerConfig = "/safe/docker";
  await runtime.resolveImage(new AbortController().signal);
  assert.equal(calls.length, 3);
  assert.equal(runtime.image.id, image.Id);
});

test("initialization retains and removes an exact candidate after transient admission failure", async () => {
  const parent = realpathSync(tmpdir());
  let candidate;
  let rejectFirstCandidateStat = true;
  const fileSystem = {
    tmpdir: () => parent,
    realpath: realpathSync,
    readdir: readdirSync,
    mkdtemp: (prefix) => { candidate = mkdtempSync(prefix); return candidate; },
    mkdir: mkdirSync,
    lstat: (path) => {
      if (path === candidate && rejectFirstCandidateStat) {
        rejectFirstCandidateStat = false;
        throw new Error("transient admission failure");
      }
      return lstatSync(path);
    },
    remove: rmSync,
  };
  const runtime = new DockerRuntime({ marker: "0123456789abcdef", path: "/bin", home: "/safe/home", environment: {}, fileSystem });
  try {
    await assert.rejects(runtime.initialize(new AbortController().signal));
    assert.equal(existsSync(candidate), true);
    await runtime.removeTemp(true);
    assert.equal(existsSync(candidate), false);
  } finally {
    if (runtime.tempRoot && existsSync(runtime.tempRoot)) rmSync(runtime.tempRoot, { recursive: true, force: true });
    if (candidate && existsSync(candidate)) rmSync(candidate, { recursive: true, force: true });
  }
});

test("Docker and build boundaries reject replaced owned child directories", async () => {
  const runtime = new DockerRuntime({
    marker: "0123456789abcdef", path: "/bin", home: "/safe/home", environment: {},
    command: async () => ({ status: 0, signal: null, thrown: false, stdout: "", stderr: "" }),
  });
  const outside = mkdtempSync(join(realpathSync(tmpdir()), "zasp-review-m1-16-"));
  await runtime.initialize(new AbortController().signal);
  const dockerPath = runtime.dockerConfig;
  const dockerOriginal = `${dockerPath}-original`;
  const buildPath = join(runtime.tempRoot, "build");
  const buildOriginal = `${buildPath}-original`;
  let dockerRejected = false;
  let buildRejected = false;
  try {
    renameSync(dockerPath, dockerOriginal);
    symlinkSync(outside, dockerPath, "dir");
    try { await runtime.docker(["ps"]); } catch { dockerRejected = true; }
    rmSync(dockerPath);
    renameSync(dockerOriginal, dockerPath);

    renameSync(buildPath, buildOriginal);
    symlinkSync(outside, buildPath, "dir");
    try { runtime.requireTemp(); } catch { buildRejected = true; }
    rmSync(buildPath);
    renameSync(buildOriginal, buildPath);
    assert.equal(dockerRejected, true);
    assert.equal(buildRejected, true);
  } finally {
    if (existsSync(dockerPath) && lstatSync(dockerPath).isSymbolicLink()) rmSync(dockerPath);
    if (!existsSync(dockerPath) && existsSync(dockerOriginal)) renameSync(dockerOriginal, dockerPath);
    if (existsSync(buildPath) && lstatSync(buildPath).isSymbolicLink()) rmSync(buildPath);
    if (!existsSync(buildPath) && existsSync(buildOriginal)) renameSync(buildOriginal, buildPath);
    if (runtime.tempRoot && existsSync(runtime.tempRoot)) rmSync(runtime.tempRoot, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("Docker boundary rejects injected config contents without invoking Docker", async () => {
  let commandCalls = 0;
  const runtime = new DockerRuntime({
    marker: "0123456789abcdef", path: "/bin", home: "/safe/home", environment: {},
    command: async () => { commandCalls += 1; return { status: 0, signal: null, thrown: false, stdout: "", stderr: "" }; },
  });
  await runtime.initialize(new AbortController().signal);
  try {
    writeFileSync(join(runtime.dockerConfig, "config.json"), '{"auths":{"forged.example":{"auth":"forged"}}}');
    await assert.rejects(runtime.docker(["ps"]));
    assert.equal(commandCalls, 0);
  } finally {
    if (runtime.tempRoot && existsSync(runtime.tempRoot)) rmSync(runtime.tempRoot, { recursive: true, force: true });
  }
});

test("cleanup rearms delayed ambiguous create and reconciles thrown removal", async () => {
  const token = "a".repeat(64);
  let listCalls = 0;
  let removeCalls = 0;
  const runtime = new DockerRuntime({
    marker: "0123456789abcdef", path: "/bin", home: "/safe/home", environment: {},
    command: async (_command, args) => {
      if (args[0] === "create") return { status: null, signal: "SIGKILL", thrown: false, stdout: "", stderr: "" };
      if (args[0] === "ps") {
        listCalls += 1;
        return { status: 0, signal: null, thrown: false, stdout: listCalls === 1 ? "" : `${token}\n`, stderr: "" };
      }
      if (args[0] === "rm") { removeCalls += 1; throw new Error("ambiguous remove boundary"); }
      throw new Error(`unexpected command ${args.join(" ")}`);
    },
  });
  runtime.dockerConfig = "/safe/docker";
  runtime.image = { id: `sha256:${"d".repeat(64)}`, env: [], entrypoint: null, cmd: null, labels: {}, exposed: [], volumes: [] };
  runtime.verifyAnyOwned = async () => {};
  let absenceCalls = 0;
  runtime.absent = async () => { absenceCalls += 1; };
  await assert.rejects(runtime.create(new AbortController().signal));
  await runtime.settle();
  await runtime.remove(new AbortController().signal);
  assert.equal(runtime.token, token);
  assert.equal(removeCalls, 1);
  assert.equal(absenceCalls, 1);
});

test("shared fingerprint binds full container identity and name", async () => {
  let listCalls = 0;
  const runtime = new DockerRuntime({
    marker: "0123456789abcdef", path: "/bin", home: "/safe/home", environment: {},
    command: async (_command, args) => {
      if (args[0] === "ps") {
        listCalls += 1;
        const id = (listCalls === 1 ? "a" : "b").repeat(64);
        return { status: 0, signal: null, thrown: false, stdout: `${JSON.stringify({ ID: id, Image: "neo4j:shared", Names: "shared-neo4j" })}\n`, stderr: "" };
      }
      return { status: 0, signal: null, thrown: false, stdout: '"2026-08-15T00:00:00Z"|0|"sha256:shared"|"exited"\n', stderr: "" };
    },
  });
  runtime.dockerConfig = "/safe/docker";
  await runtime.fingerprintShared("before", new AbortController().signal);
  await assert.rejects(runtime.fingerprintShared("after", new AbortController().signal));
});

test("Docker read boundaries reject signaled successful output", async () => {
  const portsRuntime = new DockerRuntime({
    marker: "0123456789abcdef", path: "/bin", home: "/safe/home", environment: {},
    command: async () => ({
      status: 0, signal: "SIGKILL", thrown: false, stderr: "",
      stdout: `${JSON.stringify({ "7474/tcp": [{ HostIp: "127.0.0.1", HostPort: "47474" }], "7687/tcp": [{ HostIp: "127.0.0.1", HostPort: "47687" }] })}\n`,
    }),
  });
  portsRuntime.token = "a".repeat(64);
  portsRuntime.image = { exposed: ["7474/tcp", "7687/tcp"] };
  portsRuntime.verify = async () => {};
  portsRuntime.dockerConfig = "/safe/docker";
  await assert.rejects(portsRuntime.ports(new AbortController().signal));

  const sharedRuntime = new DockerRuntime({
    marker: "0123456789abcdef", path: "/bin", home: "/safe/home", environment: {},
    command: async () => ({ status: 0, signal: "SIGKILL", thrown: false, stdout: "", stderr: "" }),
  });
  sharedRuntime.dockerConfig = "/safe/docker";
  await assert.rejects(sharedRuntime.fingerprintShared("before", new AbortController().signal));
});

test("global absence includes current marker label", async () => {
  const calls = [];
  const runtime = new DockerRuntime({
    marker: "0123456789abcdef", path: "/bin", home: "/safe/home", environment: {},
    command: async (_command, args) => {
      calls.push(args);
      return { status: 0, signal: null, thrown: false, stdout: "", stderr: "" };
    },
  });
  runtime.dockerConfig = "/safe/docker";
  await runtime.prefixAbsent(new AbortController().signal);
  assert.equal(calls.length, 3);
  assert.deepEqual(calls[2], ["ps", "-aq", "--no-trunc", "--filter", "label=com.zasp.marker=0123456789abcdef"]);
});

test("mutation classification never reconciles definitive rejection", () => {
  assert.equal(classifyMutation({ status: 1, signal: null, thrown: false, stdout: "", stderr: "" }), "definitive");
  assert.equal(classifyMutation({ status: 0, signal: null, thrown: false, stdout: `${"a".repeat(64)}\n`, stderr: "" }), "applied");
  assert.equal(classifyMutation({ status: null, signal: "SIGKILL", thrown: false, stdout: "", stderr: "" }), "ambiguous");
  assert.equal(classifyMutation({ status: null, signal: null, thrown: true, stdout: "", stderr: "" }), "ambiguous");
  assert.equal(classifyMutation({ status: 0, signal: null, thrown: false, stdout: "malformed\n", stderr: "" }), "ambiguous");
});

test("semantic readiness rejects duplicate keys, errors, and oversized bodies", () => {
  const valid = Buffer.from('{"results":[{"columns":["ready"],"data":[{"row":[1],"meta":[null]}]}],"errors":[],"lastBookmarks":["test-bookmark"]}');
  assert.equal(parseReadiness(200, valid), true);
  assert.equal(parseReadiness(200, Buffer.from('{"results":[{"columns":["ready"],"data":[{"row":[1],"meta":[null]}]}],"errors":[]}')), false);
  assert.equal(parseReadiness(200, Buffer.from('{"results":[{"columns":["ready"],"data":[{"row":[1],"meta":[null]}]}],"errors":[],"lastBookmarks":[]}')), false);
  assert.equal(parseReadiness(200, Buffer.from('{"results":[{"columns":["ready"],"data":[{"row":[1],"meta":[null]}]}],"errors":[],"lastBookmarks":["bad\\u0000bookmark"]}')), false);
  assert.equal(parseReadiness(200, Buffer.from('{"results":[],"results":[],"errors":[]}')), false);
  assert.equal(parseReadiness(200, Buffer.from('{"results":[],"errors":[{}]}')), false);
  assert.equal(parseReadiness(302, valid), false);
  assert.equal(parseReadiness(200, Buffer.alloc(16 * 1024 + 1)), false);
});

test("orchestration succeeds only after proof and reverse cleanup", async () => {
  const runtime = new FakeRuntime();
  const result = await orchestrate(runtime, { mainTimeoutMs: 2_000, cleanupTimeoutMs: 2_000 });
  assert.deepEqual(result, { code: 0, line: SUCCESS_LINE });
  assert.deepEqual(runtime.events, [
    "preflight", "initialize", "docker-preflight", "shared-before", "image", "create", "verify-created", "start", "verify-running",
    "ports", "ready", "build", "proof", "settle", "remove", "absent", "prefix-absent", "shared-after", "temp-remove",
    "temp-prefix-absent",
  ]);
});

test("cleanup failure wins and later cleanup continues", async () => {
  const runtime = new FakeRuntime();
  runtime.failProof = true;
  runtime.failRemove = true;
  const result = await orchestrate(runtime, { mainTimeoutMs: 2_000, cleanupTimeoutMs: 2_000 });
  assert.deepEqual(result, { code: 1, line: "Neo4j GraphStore proof failed: cleanup rejected." });
  assert.deepEqual(runtime.events.slice(-6), ["remove", "absent", "prefix-absent", "shared-after", "temp-retain", "temp-prefix-absent"]);
});

test("main phase deadline returns and begins cleanup when an operation ignores abort", async () => {
  const runtime = new FakeRuntime();
  runtime.hangProof = true;
  const observed = await Promise.race([
    orchestrate(runtime, { mainTimeoutMs: 5, cleanupTimeoutMs: 100 }),
    new Promise((resolvePromise) => setTimeout(() => resolvePromise("still-pending"), 50)),
  ]);
  assert.deepEqual(observed, { code: 1, line: "Neo4j GraphStore proof failed: operation rejected." });
  assert.deepEqual(runtime.events.slice(-6), ["remove", "absent", "prefix-absent", "shared-after", "temp-remove", "temp-prefix-absent"]);
});

test("hard child supervisor SIGKILLs overflow and uncooperative children", async () => {
  const overflow = fakeChild();
  const overflowPromise = runBounded("proof", [], { timeoutMs: 1_000, outputLimit: 4_096 }, () => overflow.child);
  overflow.child.stdout.write(Buffer.alloc(3_000));
  overflow.child.stderr.write(Buffer.alloc(1_097));
  const overflowResult = await overflowPromise;
  assert.equal(overflowResult.signal, "SIGKILL");
  assert.deepEqual(overflow.kills, ["SIGKILL"]);

  const hanging = fakeChild();
  const hangingResult = await runBounded("proof", [], { timeoutMs: 5, outputLimit: 4_096 }, () => hanging.child);
  assert.equal(hangingResult.signal, "SIGKILL");
  assert.deepEqual(hanging.kills, ["SIGKILL"]);

  const aborted = fakeChild();
  const controller = new AbortController();
  const abortedPromise = runBounded("proof", [], {
    timeoutMs: 1_000,
    outputLimit: 4_096,
    signal: controller.signal,
  }, () => aborted.child);
  controller.abort();
  const abortedResult = await abortedPromise;
  assert.equal(abortedResult.signal, "SIGKILL");
  assert.deepEqual(aborted.kills, ["SIGKILL"]);
});

test("fixed output boundary emits one line and numeric status", async () => {
  const output = [];
  const code = await runMain(new FakeRuntime(), { write: (value) => output.push(value), mainTimeoutMs: 2_000, cleanupTimeoutMs: 2_000 });
  assert.equal(code, 0);
  assert.deepEqual(output, [`${SUCCESS_LINE}\n`]);

  output.length = 0;
  const failedCode = await runMain(undefined, {
    write: (value) => output.push(value),
    runtimeFactory: () => { throw new Error("seeded-secret"); },
  });
  assert.equal(failedCode, 1);
  assert.deepEqual(output, ["Neo4j GraphStore proof failed: operation rejected.\n"]);
  assert.equal(output[0].includes("seeded-secret"), false);
});

class FakeRuntime {
  constructor() {
    this.events = [];
    this.failProof = false;
    this.failRemove = false;
    this.hangProof = false;
  }
  async preflight() { this.events.push("preflight"); }
  async fingerprintShared(when) { this.events.push(`shared-${when}`); }
  async initialize() { this.events.push("initialize"); }
  async dockerPreflight() { this.events.push("docker-preflight"); }
  async resolveImage() { this.events.push("image"); }
  async create() { this.events.push("create"); }
  async verify(state) { this.events.push(`verify-${state}`); }
  async start() { this.events.push("start"); }
  async ports() { this.events.push("ports"); }
  async ready() { this.events.push("ready"); }
  async build() { this.events.push("build"); }
  async proof() {
    this.events.push("proof");
    if (this.hangProof) return new Promise(() => {});
    if (this.failProof) throw new Error("provider");
  }
  async settle() { this.events.push("settle"); }
  async remove() { this.events.push("remove"); if (this.failRemove) throw new Error("cleanup"); }
  async absent() { this.events.push("absent"); }
  async prefixAbsent() { this.events.push("prefix-absent"); }
  async removeTemp(allowed) { this.events.push(allowed ? "temp-remove" : "temp-retain"); }
  async tempPrefixAbsent() { this.events.push("temp-prefix-absent"); }
}

function fakeChild() {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  const kills = [];
  child.kill = (signal) => {
    kills.push(signal);
    queueMicrotask(() => child.emit("close", null, signal));
    return true;
  };
  return { child, kills };
}
