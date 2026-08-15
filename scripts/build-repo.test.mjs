import assert from "node:assert/strict";
import test from "node:test";

import {
  buildRepository,
  createBuildTargets,
  failureLine,
  runMain,
  successLine,
} from "./build-repo.mjs";

const root = "/safe/repository";
const environment = {
  PATH: "/safe/bin",
  HOME: "/safe/home",
  LANG: "C.UTF-8",
  AWS_SECRET_ACCESS_KEY: "must-not-cross",
  HTTPS_PROXY: "http://must-not-cross.invalid",
  NODE_OPTIONS: "--require=must-not-cross",
};

function successfulResult(stdout = "", stderr = "") {
  return { error: undefined, status: 0, signal: null, stdout, stderr };
}

function resultFor(target) {
  if (target.name === "security-python") {
    return successfulResult("security-worker health ok\n");
  }
  if (target.name === "redteam-node") {
    return successfulResult("redteam-worker health ok\n");
  }
  return successfulResult();
}

test("builds the exact eight targets in dependency order", () => {
  const observed = [];
  const count = buildRepository({
    repositoryRoot: root,
    environment,
    nodeExecutable: "/safe/node",
    nullDevice: "/safe/null",
    execute(target) {
      observed.push(target);
      return resultFor(target);
    },
  });

  assert.equal(count, 8);
  assert.deepEqual(observed.map(({ name }) => name), [
    "agentsec-api",
    "agentsec-worker",
    "event-ingest",
    "runtime-gateway",
    "security-python",
    "redteam-node",
    "web",
    "agentsecctl",
  ]);
  assert.deepEqual(observed.map(({ command, args }) => [command, args]), [
    ["go", ["-C", "services/platform", "build", "-trimpath", "-o", "/safe/null", "./agentsec-api"]],
    ["go", ["-C", "services/platform", "build", "-trimpath", "-o", "/safe/null", "./agentsec-worker"]],
    ["go", ["-C", "services/event-ingest", "build", "-trimpath", "-o", "/safe/null", "."]],
    ["go", ["-C", "services/runtime-gateway", "build", "-trimpath", "-o", "/safe/null", "."]],
    ["python3", ["-m", "security_worker", "health"]],
    ["/safe/node", ["workers/redteam-node/health.mjs", "health"]],
    ["npm", ["--prefix", "apps/web", "run", "build"]],
    ["go", ["-C", "cmd/agentsecctl", "build", "-trimpath", "-o", "/safe/null", "."]],
  ]);
  assert.ok(observed.every(({ cwd, timeoutMilliseconds, maxOutputBytes }) =>
    cwd === root && timeoutMilliseconds === 120_000 && maxOutputBytes === 1_048_576));
});

test("passes only allowlisted target environment", () => {
  const targets = createBuildTargets({
    repositoryRoot: root,
    environment,
    nodeExecutable: "/safe/node",
    nullDevice: "/safe/null",
  });

  for (const target of targets) {
    assert.equal(target.environment.PATH, environment.PATH);
    assert.equal(target.environment.HOME, environment.HOME);
    assert.equal(target.environment.LANG, environment.LANG);
    assert.equal("AWS_SECRET_ACCESS_KEY" in target.environment, false);
    assert.equal("HTTPS_PROXY" in target.environment, false);
    assert.equal("NODE_OPTIONS" in target.environment, false);
  }
  for (const target of targets.filter(({ command }) => command === "go")) {
    assert.deepEqual(target.environment, {
      PATH: environment.PATH,
      HOME: environment.HOME,
      LANG: environment.LANG,
      GOENV: "off",
      GOTOOLCHAIN: "local",
      GOPROXY: "off",
      GOSUMDB: "off",
      GOWORK: "off",
      CGO_ENABLED: "0",
    });
  }
  assert.deepEqual(targets.find(({ name }) => name === "security-python")?.environment, {
    PATH: environment.PATH,
    HOME: environment.HOME,
    LANG: environment.LANG,
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONUNBUFFERED: "1",
    PYTHONPATH: "/safe/repository/workers/security-python",
  });
  assert.deepEqual(targets.find(({ name }) => name === "web")?.environment, {
    PATH: environment.PATH,
    HOME: environment.HOME,
    LANG: environment.LANG,
    NPM_CONFIG_AUDIT: "false",
    NPM_CONFIG_FUND: "false",
    NPM_CONFIG_OFFLINE: "true",
    NPM_CONFIG_UPDATE_NOTIFIER: "false",
  });
});

test("rejects missing execution environment before spawning", () => {
  for (const missing of ["PATH", "HOME"]) {
    const invalid = { ...environment };
    delete invalid[missing];
    assert.throws(() => createBuildTargets({
      repositoryRoot: root,
      environment: invalid,
      nodeExecutable: "/safe/node",
      nullDevice: "/safe/null",
    }));
  }
});

test("fails fast on rejected, thrown, signaled, oversized, or malformed child results", () => {
  const outcomes = [
    { error: undefined, status: 1, signal: null, stdout: "", stderr: "" },
    { error: undefined, status: null, signal: "SIGKILL", stdout: "", stderr: "" },
    { error: undefined, status: 0, signal: null, stdout: "x".repeat(1_048_577), stderr: "" },
    { error: undefined, status: 0, signal: null, stdout: null, stderr: "" },
  ];
  for (const outcome of outcomes) {
    let calls = 0;
    assert.throws(() => buildRepository({
      repositoryRoot: root,
      environment,
      nodeExecutable: "/safe/node",
      nullDevice: "/safe/null",
      execute() {
        calls += 1;
        return outcome;
      },
    }));
    assert.equal(calls, 1);
  }

  let calls = 0;
  assert.throws(() => buildRepository({
    repositoryRoot: root,
    environment,
    nodeExecutable: "/safe/node",
    nullDevice: "/safe/null",
    execute() {
      calls += 1;
      throw new Error("child failed");
    },
  }));
  assert.equal(calls, 1);
});

test("requires exact worker output", () => {
  for (const name of ["security-python", "redteam-node"]) {
    assert.throws(() => buildRepository({
      repositoryRoot: root,
      environment,
      nodeExecutable: "/safe/node",
      nullDevice: "/safe/null",
      execute(target) {
        if (target.name === name) {
          return successfulResult("almost\n");
        }
        return resultFor(target);
      },
    }));
  }
});

test("contains all outcomes behind one fixed process line", () => {
  const successOutput = [];
  const successErrors = [];
  assert.equal(runMain({
    arguments: [],
    stdout: { write: (value) => successOutput.push(value) },
    stderr: { write: (value) => successErrors.push(value) },
    runtime: {
      repositoryRoot: root,
      environment,
      nodeExecutable: "/safe/node",
      nullDevice: "/safe/null",
      execute: resultFor,
    },
  }), 0);
  assert.deepEqual(successOutput, [successLine]);
  assert.deepEqual(successErrors, []);

  for (const arguments_ of [["extra"], []]) {
    const output = [];
    const errors = [];
    const runtime = arguments_.length === 0 ? {
      repositoryRoot: root,
      environment,
      nodeExecutable: "/safe/node",
      nullDevice: "/safe/null",
      execute() {
        throw new Error("sensitive child detail");
      },
    } : undefined;
    assert.equal(runMain({
      arguments: arguments_,
      stdout: { write: (value) => output.push(value) },
      stderr: { write: (value) => errors.push(value) },
      runtime,
    }), 1);
    assert.deepEqual(output, []);
    assert.deepEqual(errors, [failureLine]);
  }
});

test("contains no installer, downloader, provider, shell, or remote target", () => {
  const targets = createBuildTargets({
    repositoryRoot: root,
    environment,
    nodeExecutable: "/safe/node",
    nullDevice: "/safe/null",
  });
  const serialized = JSON.stringify(targets.map(({ command, args }) => [command, args]));
  for (const forbidden of ["install", "ci", "get", "pip", "uv", "curl", "wget", "docker", "aws", "kubectl", "helm", "http://", "https://", "sh", "bash"]) {
    assert.equal(serialized.includes(`"${forbidden}"`), false);
  }
});
