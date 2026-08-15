import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { PassThrough } from "node:stream";
import { pathToFileURL } from "node:url";
import { test } from "node:test";

import {
  Failure,
  DockerPromptfooRuntime,
  buildAgentReadinessScript,
  classifyMutationResult,
  dockerEnvironment,
  orchestrate,
  parseUniqueDockerJson,
  runBounded,
  runMain,
} from "./run.mjs";

const runModuleUrl = pathToFileURL(new URL("./run.mjs", import.meta.url).pathname).href;

const normalized = Object.freeze({
  objective: "override_governing_instruction",
  verdict: "vulnerable",
  evidenceReference: `evidence:promptfoo:sha256:${"a".repeat(64)}`,
});

function fakeRuntime(overrides = {}) {
  const calls = [];
  const runtime = {
    calls,
    preflight: async () => { calls.push("preflight"); },
    initialize: async () => { calls.push("initialize"); },
    resolveImage: async () => { calls.push("resolveImage"); },
    createNetwork: async () => { calls.push("createNetwork"); },
    createContainer: async (role) => { calls.push(`create:${role}`); },
    startAgent: async () => { calls.push("startAgent"); },
    waitAgent: async () => { calls.push("waitAgent"); },
    startRunner: async () => { calls.push("startRunner"); },
    normalize: async () => { calls.push("normalize"); return normalized; },
    settleMutations: async () => { calls.push("settleMutations"); },
    cleanup: async () => { calls.push("cleanup"); },
    finalAbsence: async () => { calls.push("finalAbsence"); },
    ...overrides,
  };
  return runtime;
}

test("runs the exact lifecycle and returns only the fixed success boundary", async () => {
  const runtime = fakeRuntime();
  const result = await orchestrate(runtime, { mainTimeoutMs: 2_000, cleanupTimeoutMs: 2_000 });
  assert.deepEqual(result, {
    code: 0,
    line: "Promptfoo red-team proof passed: objective=true verdict=vulnerable evidence=true cleanup=true.\n",
  });
  assert.deepEqual(runtime.calls, [
    "initialize", "preflight", "resolveImage", "createNetwork", "create:agent", "startAgent",
    "waitAgent", "create:runner", "startRunner", "normalize", "settleMutations", "cleanup", "finalAbsence",
  ]);
  assert.doesNotMatch(JSON.stringify(result), /ZASP|Ignore|eval-|container|promptfoo:sha256:[^a]/i);
});

test("cleanup continues independently and its failure takes precedence", async () => {
  const calls = [];
  const runtime = fakeRuntime({
    createNetwork: async () => { calls.push("main-failure"); throw new Failure("provider"); },
    settleMutations: async () => { calls.push("settle"); },
    cleanup: async () => { calls.push("cleanup"); throw new Failure("cleanup"); },
    finalAbsence: async () => { calls.push("absence"); },
  });
  const result = await orchestrate(runtime, { mainTimeoutMs: 2_000, cleanupTimeoutMs: 2_000 });
  assert.deepEqual(calls, ["main-failure", "settle", "cleanup", "absence"]);
  assert.deepEqual(result, { code: 1, line: "Promptfoo red-team proof failed: cleanup.\n" });
});

test("main deadline aborts, fences late work, and still performs cleanup", async () => {
  let lateMutation = false;
  const runtime = fakeRuntime({
    createNetwork: async (signal) => new Promise((resolve, reject) => {
      const timer = setTimeout(() => { lateMutation = true; resolve(); }, 100);
      signal.addEventListener("abort", () => { clearTimeout(timer); reject(new Failure("deadline")); }, { once: true });
    }),
  });
  const result = await orchestrate(runtime, { mainTimeoutMs: 10, cleanupTimeoutMs: 2_000 });
  await new Promise((resolve) => setTimeout(resolve, 120));
  assert.equal(lateMutation, false);
  assert.deepEqual(result, { code: 1, line: "Promptfoo red-team proof failed: deadline.\n" });
  assert.deepEqual(runtime.calls.slice(-3), ["settleMutations", "cleanup", "finalAbsence"]);
});

test("classifies exact acknowledgements, definitive rejection, and ambiguity", () => {
  assert.equal(classifyMutationResult({ status: 0, signal: null, stdout: "id\n", stderr: "" }, /^id\n$/), "applied");
  assert.equal(classifyMutationResult({ status: 17, signal: null, stdout: "", stderr: "rejected" }, /^id\n$/), "definitive");
  assert.equal(classifyMutationResult({ status: 0, signal: null, stdout: "other\n", stderr: "" }, /^id\n$/), "ambiguous");
  assert.equal(classifyMutationResult({ status: null, signal: "SIGKILL", stdout: "", stderr: "" }, /^id\n$/), "ambiguous");
  assert.equal(classifyMutationResult({ thrown: true, status: null, signal: null, stdout: "", stderr: "" }, /^id\n$/), "ambiguous");
});

test("parses one duplicate-free bounded Docker JSON value", () => {
  const parsed = parseUniqueDockerJson('{"Id":"abc","Labels":{"proof":"m0-16"}}\n');
  assert.deepEqual(Object.keys(parsed), ["Id", "Labels"]);
  assert.equal(parsed.Id, "abc");
  assert.deepEqual(Object.keys(parsed.Labels), ["proof"]);
  assert.equal(parsed.Labels.proof, "m0-16");
  for (const value of [
    '{"Id":"a","Id":"a"}',
    "null",
    "[]",
    '{"Id":true}',
    "{".padEnd(16_385, " "),
  ]) assert.throws(() => parseUniqueDockerJson(value), TypeError);
});

test("passes Docker only PATH and the exact owned config directory", () => {
  assert.deepEqual(dockerEnvironment("/usr/local/bin:/usr/bin", "/private/tmp/zasp-m0-16-owned/docker-config"), {
    PATH: "/usr/local/bin:/usr/bin",
    DOCKER_CONFIG: "/private/tmp/zasp-m0-16-owned/docker-config",
  });
  for (const [path, config] of [["", "/tmp/config"], ["/usr/bin", "relative"], ["/usr/bin", "/tmp/../config"]]) {
    assert.throws(() => dockerEnvironment(path, config), TypeError);
  }
});

function childFixture(onSpawn = () => {}) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killCalls = [];
  child.kill = (signal) => { child.killCalls.push(signal); return true; };
  queueMicrotask(() => onSpawn(child));
  return child;
}

test("bounds combined child output and hard-kills then reaps on timeout", async () => {
  const overflow = childFixture((child) => {
    child.stdout.write("a".repeat(3_000));
    child.stderr.write("b".repeat(1_200));
    child.emit("close", null, "SIGKILL");
  });
  const overflowResult = await runBounded("docker", ["version"], { timeoutMs: 500, outputLimit: 4_096, env: { PATH: "/usr/bin" } }, () => overflow);
  assert.equal(overflowResult.overflow, true);
  assert.deepEqual(overflow.killCalls, ["SIGKILL"]);

  const hung = childFixture(() => {});
  const pending = runBounded("docker", ["version"], { timeoutMs: 10, outputLimit: 4_096, env: { PATH: "/usr/bin" } }, () => hung);
  setTimeout(() => hung.emit("close", null, "SIGKILL"), 20);
  const timed = await pending;
  assert.equal(timed.timedOut, true);
  assert.deepEqual(hung.killCalls, ["SIGKILL"]);
});

test("contains pipe, construction, and runtime failures behind one fixed line", async () => {
  const child = childFixture((target) => {
    target.stdout.emit("error", new Error("provider-secret"));
    target.emit("close", 1, null);
  });
  const result = await runBounded("docker", ["version"], { timeoutMs: 500, outputLimit: 4_096, env: { PATH: "/usr/bin" } }, () => child);
  assert.equal(result.thrown, true);
  assert.doesNotMatch(JSON.stringify(result), /provider-secret/);

  const stdout = { text: "", write(value) { this.text += value; } };
  assert.equal(await runMain({ createRuntime: () => { throw new Error("sensitive"); }, stdout }), 1);
  assert.equal(stdout.text, "Promptfoo red-team proof failed: configuration.\n");
  assert.doesNotMatch(stdout.text, /sensitive/);
});

test("canonicalizes the default temporary parent and contains rejected journal entries", () => {
  const runtime = new DockerPromptfooRuntime();
  assert.equal(runtime.tempParent, realpathSync(tmpdir()));

  const source = `
    import { DockerPromptfooRuntime } from ${JSON.stringify(runModuleUrl)};
    const runtime = new DockerPromptfooRuntime({
      tempParent: ${JSON.stringify(realpathSync(tmpdir()))},
      proofSourcePath: "/definitely-missing-zasp-m0-16-proof-source",
    });
    try { await runtime.initialize(new AbortController().signal); } catch {}
    await new Promise((resolve) => setTimeout(resolve, 25));
    process.stdout.write("contained\\n");
  `;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", source], {
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "" },
    timeout: 2_000,
  });
  assert.equal(result.status, 0);
  assert.equal(result.signal, null);
  assert.equal(result.stdout, "contained\n");
  assert.equal(result.stderr, "");
});

test("binds agent readiness to the exact per-run DNS identity", () => {
  const name = "zasp-m0-16-0123456789abcdef-agent";
  const script = buildAgentReadinessScript(name);
  assert.match(script, /http:\/\/zasp-m0-16-0123456789abcdef-agent:3001\/health/);
  assert.doesNotMatch(script, /127\.0\.0\.1/);
  assert.match(script, /redirect:"error"/);
  for (const invalid of ["zasp-m0-16-agent", `${name}.example`, "127.0.0.1", `${name}:3001`]) {
    assert.throws(() => buildAgentReadinessScript(invalid), TypeError);
  }
});
