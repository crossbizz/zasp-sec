import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";
import assert from "node:assert/strict";

import {
  SafeFailure,
  buildChildEnvironment,
  fixedFailureLine,
  orchestrate,
  runBounded,
  runCLI,
  validateProofEnvironment,
} from "./run.mjs";

const successLine = "Real AWS IAM proof passed: cross_account=true assumed=true allowed_read=true denied_call=true cleanup=true audit=true.";

function validEnvironment() {
  return {
    PATH: "/fixed/bin",
    HOME: "/fixed/home",
    HTTPS_PROXY: "http://ambient.invalid",
    AWS_PROFILE: "ambient-profile",
    AWS_M009_ISOLATED_TEST: "isolated-disposable-aws-test-accounts-only",
    AWS_M009_REGION: "us-west-2",
    AWS_M009_SOURCE_ACCOUNT_ID: "111111111111",
    AWS_M009_TARGET_ACCOUNT_ID: "222222222222",
    AWS_M009_SOURCE_PRINCIPAL_ARN: "arn:aws:iam::111111111111:role/zasp-proof-source",
    AWS_M009_SOURCE_ACCESS_KEY_ID: "source-access",
    AWS_M009_SOURCE_SECRET_ACCESS_KEY: "source-secret",
    AWS_M009_TARGET_ADMIN_ACCESS_KEY_ID: "target-access",
    AWS_M009_TARGET_ADMIN_SECRET_ACCESS_KEY: "target-secret",
  };
}

test("environment gate requires every exact task input and literal isolation attestation", () => {
  const environment = validEnvironment();
  const proof = validateProofEnvironment(environment);
  assert.deepEqual(Object.keys(proof).sort(), Object.keys(environment).filter((name) => name.startsWith("AWS_M009_")).sort());
  for (const name of Object.keys(proof)) {
    const copy = { ...environment };
    delete copy[name];
    assert.throws(() => validateProofEnvironment(copy), (error) => error instanceof SafeFailure && error.category === "configuration");
  }
  assert.throws(
    () => validateProofEnvironment({ ...environment, AWS_M009_ISOLATED_TEST: "true" }),
    (error) => error instanceof SafeFailure && error.category === "capability",
  );
});

test("build and proof child environments exclude ambient AWS and proxy state", () => {
  const environment = validEnvironment();
  const build = buildChildEnvironment(environment);
  assert.deepEqual(Object.keys(build).sort(), ["CGO_ENABLED", "GOFLAGS", "HOME", "PATH"].sort());
  assert.equal(build.AWS_PROFILE, undefined);
  assert.equal(build.HTTPS_PROXY, undefined);
  const proof = validateProofEnvironment(environment);
  assert.equal(proof.AWS_PROFILE, undefined);
  assert.equal(proof.HTTPS_PROXY, undefined);
  assert.equal(proof.PATH, undefined);
});

test("bounded child rejects one oversized chunk and kills immediately", async () => {
  let killed = false;
  const child = fakeChild({ stdoutChunks: [Buffer.alloc(5)], neverClose: true, onKill: () => { killed = true; } });
  await assert.rejects(
    runBounded("proof", [], { cwd: "/fixed", env: {}, outputLimit: 4, timeoutMs: 1_000 }, () => child),
    (error) => error instanceof SafeFailure && error.category === "operation",
  );
  assert.equal(killed, true);
});

test("bounded child absolute timer stops an endless streaming body", async () => {
  let killed = false;
  const child = fakeChild({ neverClose: true, onKill: () => { killed = true; } });
  const interval = setInterval(() => child.stdout.write("x"), 1);
  try {
    await assert.rejects(
      runBounded("proof", [], { cwd: "/fixed", env: {}, outputLimit: 4096, timeoutMs: 15 }, () => child),
      (error) => error instanceof SafeFailure && error.category === "operation",
    );
  } finally {
    clearInterval(interval);
  }
  assert.equal(killed, true);
});

test("orchestrator builds with a narrow environment, runs exact proof env, and cleans temp", async () => {
  const calls = [];
  const spawnImplementation = (command, arguments_, options) => {
    calls.push({ command, arguments_, options });
    if (calls.length === 1) return fakeChild({ code: 0 });
    return fakeChild({ code: 0, stdoutChunks: [`${successLine}\n`] });
  };
  let removed;
  const result = await orchestrate({
    environment: validEnvironment(), spawnImplementation,
    makeTemp: async () => "/tmp/zasp-m009-test-owned",
    removeTemp: async (directory) => { removed = directory; },
  });
  assert.equal(result, successLine);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].command, "go");
  assert.equal(calls[0].options.env.AWS_PROFILE, undefined);
  assert.equal(calls[1].options.env.PATH, undefined);
  assert.equal(calls[1].options.env.AWS_M009_REGION, "us-west-2");
  assert.equal(removed, "/tmp/zasp-m009-test-owned");
});

test("cleanup failure takes precedence over proof failure", async () => {
  await assert.rejects(
    orchestrate({
      environment: validEnvironment(),
      spawnImplementation: () => fakeChild({ code: 1 }),
      makeTemp: async () => "/tmp/zasp-m009-test-owned",
      removeTemp: async () => { throw new Error("detail"); },
    }),
    (error) => error instanceof SafeFailure && error.category === "cleanup",
  );
});

test("orchestrator preserves only an exact fixed child failure category", async () => {
  let calls = 0;
  await assert.rejects(
    orchestrate({
      environment: validEnvironment(),
      spawnImplementation: () => {
        calls += 1;
        if (calls === 1) return fakeChild({ code: 0 });
        return fakeChild({ code: 1, stderrChunks: ["Real AWS IAM proof failed: authorization rejected.\n"] });
      },
      makeTemp: async () => "/tmp/zasp-m009-test-owned",
      removeTemp: async () => {},
    }),
    (error) => error instanceof SafeFailure && error.category === "authorization",
  );
});

test("top-level boundary emits exactly one fixed line with no stack or child detail", async () => {
  let stdout = "";
  let stderr = "";
  const code = await runCLI({
    environment: validEnvironment(),
    spawnImplementation: () => { throw new Error("sensitive child detail"); },
    makeTemp: async () => "/tmp/zasp-m009-test-owned",
    removeTemp: async () => {},
    writeOut: (value) => { stdout += value; },
    writeErr: (value) => { stderr += value; },
  });
  assert.equal(code, 1);
  assert.equal(stdout, "");
  assert.equal(stderr, "Real AWS IAM proof failed: operation rejected.\n");
  assert.equal(stderr.includes("sensitive"), false);
  assert.equal(stderr.split("\n").length, 2);
});

test("fixed failure formatter accepts only fixed categories", () => {
  assert.equal(fixedFailureLine(new SafeFailure("authorization")), "Real AWS IAM proof failed: authorization rejected.");
  assert.equal(fixedFailureLine(new SafeFailure("provider detail")), "Real AWS IAM proof failed: operation rejected.");
  assert.equal(fixedFailureLine(new Error("secret")), "Real AWS IAM proof failed: operation rejected.");
});

function fakeChild({ stdoutChunks = [], stderrChunks = [], code = 0, signal = null, neverClose = false, onKill = () => {} } = {}) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = () => {
    onKill();
    return true;
  };
  queueMicrotask(() => {
    for (const chunk of stdoutChunks) child.stdout.write(chunk);
    for (const chunk of stderrChunks) child.stderr.write(chunk);
    if (!neverClose) {
      child.stdout.end();
      child.stderr.end();
      child.emit("close", code, signal);
    }
  });
  return child;
}
