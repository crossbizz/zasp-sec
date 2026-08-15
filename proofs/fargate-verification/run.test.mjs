import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  SafeFailure,
  OwnedWorkspace,
  buildBuildEnvironment,
  fixedFailureLine,
  orchestrate,
  runBounded,
  runCLI,
  validateProofEnvironment,
} from "./run.mjs";

const successLine = "EKS Fargate proof passed: scheduled=true canary=true cleanup=true.";

function validEnvironment() {
  return {
    PATH: "/fixed/bin",
    HOME: "/fixed/home",
    TMPDIR: "/fixed/tmp",
    GOCACHE: "/fixed/go-build",
    GOMODCACHE: "/fixed/go-mod",
    HTTPS_PROXY: "http://ambient.invalid",
    KUBECONFIG: "/ambient/kubeconfig",
    AWS_PROFILE: "ambient",
    AWS_M018_ISOLATED_TEST: "I_UNDERSTAND_THIS_MUTATES_A_DISPOSABLE_EKS_PROFILE",
    AWS_M018_KUBECONFIG: "/owned/kubeconfig",
    AWS_M018_KUBE_CONTEXT: "proof-context",
    AWS_M018_CLUSTER_NAME: "proof-cluster",
    AWS_M018_REGION: "us-west-2",
    AWS_M018_FARGATE_PROFILE: "proof-profile",
    AWS_M018_PROFILE_NAMESPACE_PREFIX: "zasp-m018-",
    AWS_M018_PROFILE_LABEL_KEY: "zasp.agentsec.dev/fargate",
    AWS_M018_PROFILE_LABEL_VALUE: "true",
    AWS_M018_PROXY_URL: "https://proxy.example.test/canary",
    AWS_M018_CANARY_TOKEN: "synthetic-token",
  };
}

test("capability gate requires all eleven exact inputs before any work", async () => {
  const environment = validEnvironment();
  const proof = validateProofEnvironment(environment);
  assert.equal(Object.keys(proof).length, 11);
  for (const name of Object.keys(proof)) {
    const copy = { ...environment };
    delete copy[name];
    assert.throws(() => validateProofEnvironment(copy), (error) => error instanceof SafeFailure && error.category === "configuration");
  }
  assert.throws(
    () => validateProofEnvironment({ ...environment, AWS_M018_ISOLATED_TEST: "true" }),
    (error) => error instanceof SafeFailure && error.category === "configuration",
  );
  let resolved = false;
  await assert.rejects(
    orchestrate({ environment: {}, resolveKubectl: async () => { resolved = true; } }),
    (error) => error instanceof SafeFailure && error.category === "configuration",
  );
  assert.equal(resolved, false);
});

test("build and proof environments drop ambient cloud kube and proxy state", () => {
  const environment = validEnvironment();
  const build = buildBuildEnvironment(environment);
  assert.deepEqual(Object.keys(build).sort(), ["CGO_ENABLED", "GOCACHE", "GOENV", "GOFLAGS", "GOMODCACHE", "GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "HOME", "PATH", "TMPDIR"].sort());
  assert.equal(build.AWS_PROFILE, undefined);
  assert.equal(build.KUBECONFIG, undefined);
  assert.equal(build.HTTPS_PROXY, undefined);
  const proof = validateProofEnvironment(environment);
  assert.equal(proof.PATH, undefined);
  assert.equal(proof.KUBECONFIG, undefined);
});

test("build environment derives a safe temporary directory when TMPDIR is absent", () => {
  const environment = validEnvironment();
  delete environment.TMPDIR;
  const build = buildBuildEnvironment(environment);
  assert.equal(typeof build.TMPDIR, "string");
  assert.equal(build.TMPDIR.startsWith("/"), true);
});

test("bounded child enforces combined output and waits for SIGKILL close", async () => {
  let killed = false;
  let closed = false;
  const child = fakeChild({ stdoutChunks: [Buffer.alloc(9)], neverClose: true, onKill: () => {
    killed = true;
    queueMicrotask(() => { closed = true; child.emit("close", null, "SIGKILL"); });
  } });
  await assert.rejects(
    runBounded("proof", [], { cwd: "/fixed", env: {}, outputLimit: 8, timeoutMs: 1_000 }, () => child),
    (error) => error instanceof SafeFailure && error.category === "operation",
  );
  assert.equal(killed, true);
  assert.equal(closed, true);
});

test("bounded child hard deadline kills and reaps an endless process", async () => {
  let killed = false;
  const child = fakeChild({ neverClose: true, onKill: () => {
    killed = true;
    queueMicrotask(() => child.emit("close", null, "SIGKILL"));
  } });
  await assert.rejects(
    runBounded("proof", [], { cwd: "/fixed", env: {}, outputLimit: 16_384, timeoutMs: 10 }, () => child),
    (error) => error instanceof SafeFailure && error.category === "operation",
  );
  assert.equal(killed, true);
});

test("orchestrator builds offline runs exact proof environment and cleans identity", async () => {
  const calls = [];
  let cleaned = false;
  const workspace = fakeWorkspace(() => { cleaned = true; });
  const result = await orchestrate({
    environment: validEnvironment(),
    resolveKubectl: async () => "/owned/kubectl",
    workspace,
    runImplementation: async (command, arguments_, options) => {
      calls.push({ command, arguments_, options });
      if (calls.length === 1) return { code: 0, signal: null, stdout: "", stderr: "" };
      return { code: 0, signal: null, stdout: `${successLine}\n`, stderr: "" };
    },
  });
  assert.equal(result, successLine);
  assert.equal(cleaned, true);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].command, "go");
  assert.deepEqual(calls[0].arguments_.slice(0, 3), ["build", "-trimpath", "-mod=readonly"]);
  assert.equal(calls[0].options.env.GOPROXY, "off");
  assert.equal(calls[1].options.env.ZASP_M018_KUBECTL_EXECUTABLE, "/owned/kubectl");
  assert.equal(calls[1].options.env.PATH, undefined);
  assert.equal(calls[1].options.timeoutMs, 960_000);
});

test("cleanup failure wins and fixed CLI emits one redacted line", async () => {
  let stdout = "";
  let stderr = "";
  const code = await runCLI({
    environment: validEnvironment(),
    resolveKubectl: async () => "/owned/kubectl",
    workspace: fakeWorkspace(() => { throw new Error("sensitive path"); }),
    runImplementation: async () => { throw new Error("provider detail"); },
    writeOut: (value) => { stdout += value; },
    writeErr: (value) => { stderr += value; },
  });
  assert.equal(code, 1);
  assert.equal(stdout, "");
  assert.equal(stderr, "EKS Fargate proof failed: cleanup rejected.\n");
});

test("cleanup failure overrides an otherwise successful proof", async () => {
  await assert.rejects(
    orchestrate({
      environment: validEnvironment(),
      resolveKubectl: async () => "/owned/kubectl",
      workspace: fakeWorkspace(() => { throw new Error("cleanup detail"); }),
      runImplementation: async (command) => command === "go"
        ? { code: 0, signal: null, stdout: "", stderr: "" }
        : { code: 0, signal: null, stdout: `${successLine}\n`, stderr: "" },
    }),
    (error) => error instanceof SafeFailure && error.category === "cleanup",
  );
});

test("only fixed failure categories cross the outer boundary", () => {
  for (const category of ["configuration", "provider", "scheduling", "canary", "ownership", "cleanup", "deadline", "panic"]) {
    assert.equal(fixedFailureLine(new SafeFailure(category)), `EKS Fargate proof failed: ${category} rejected.`);
  }
  assert.equal(fixedFailureLine(new Error("secret")), "EKS Fargate proof failed: provider rejected.");
});

test("workspace rejects stale global prefixes before creation", async () => {
  let created = false;
  const workspace = new OwnedWorkspace({
    parent: "/safe/tmp",
    canonicalPath: async (value) => value,
    statPath: async () => fakeStat({ directory: true, dev: 1, ino: 1 }),
    listDirectory: async () => [{ name: "zasp-m018-build-stale" }],
    makeDirectory: async () => { created = true; return "/safe/tmp/zasp-m018-build-new"; },
  });
  await assert.rejects(workspace.create(), (error) => error instanceof SafeFailure && error.category === "ownership");
  assert.equal(created, false);
});

test("workspace replacement is never recursively removed", async () => {
  let candidateReads = 0;
  let removed = false;
  const workspace = new OwnedWorkspace({
    parent: "/safe/tmp",
    canonicalPath: async (value) => value,
    statPath: async (value) => {
      if (value === "/safe/tmp") return fakeStat({ directory: true, dev: 1, ino: 1 });
      candidateReads += 1;
      return fakeStat({ directory: true, dev: 2, ino: candidateReads === 1 ? 2 : 3 });
    },
    listDirectory: async () => [],
    makeDirectory: async () => "/safe/tmp/zasp-m018-build-owned",
    removeDirectory: async () => { removed = true; },
  });
  await workspace.create();
  await assert.rejects(workspace.cleanup(), (error) => error instanceof SafeFailure && error.category === "cleanup");
  assert.equal(removed, false);
});

test("post-mkdtemp validation failure retains candidate for later exact cleanup", async () => {
  let candidateReads = 0;
  let removed = false;
  const workspace = new OwnedWorkspace({
    parent: "/safe/tmp",
    canonicalPath: async (value) => value,
    statPath: async (value) => {
      if (value === "/safe/tmp") return fakeStat({ directory: true, dev: 1, ino: 1 });
      candidateReads += 1;
      if (candidateReads === 1) throw new Error("transient stat failure");
      if (removed) {
        const error = new Error("missing");
        error.code = "ENOENT";
        throw error;
      }
      return fakeStat({ directory: true, dev: 2, ino: 2 });
    },
    listDirectory: async () => [],
    makeDirectory: async () => "/safe/tmp/zasp-m018-build-owned",
    removeDirectory: async () => { removed = true; },
  });
  await assert.rejects(workspace.create());
  assert.equal(workspace.hasCandidate(), true);
  await workspace.cleanup();
  assert.equal(removed, true);
});

function fakeWorkspace(onCleanup) {
  return {
    hasCandidate: () => true,
    create: async () => ({ path: "/fixed/zasp-m018-owned", dev: 1, ino: 2 }),
    cleanup: async () => onCleanup(),
  };
}

function fakeChild({ stdoutChunks = [], stderrChunks = [], code = 0, signal = null, neverClose = false, onKill = () => {} } = {}) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = () => { onKill(); return true; };
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

function fakeStat({ directory, dev, ino }) {
  return {
    dev,
    ino,
    isDirectory: () => directory,
    isFile: () => !directory,
    isSymbolicLink: () => false,
  };
}
