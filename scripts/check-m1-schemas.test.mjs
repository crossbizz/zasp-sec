import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  checkSchemas,
  createSchemaTargets,
  failureLine,
  runMain,
  successLine,
} from "./check-m1-schemas.mjs";

const repositoryRoot = "/safe/repository";
const environment = {
  PATH: "/safe/bin",
  HOME: "/safe/home",
  LANG: "C.UTF-8",
  AWS_ACCESS_KEY_ID: "must-not-cross",
  DATABASE_URL: "must-not-cross",
  HTTPS_PROXY: "http://must-not-cross.invalid",
  NODE_OPTIONS: "--require=must-not-cross",
};

function successfulResult(stdout = "ok\n", stderr = "") {
  return { error: undefined, status: 0, signal: null, stdout, stderr };
}

test("runs the exact five schema authorities in dependency order", () => {
  const observed = [];
  const count = checkSchemas({
    repositoryRoot,
    environment,
    execute(target) {
      observed.push(target);
      return successfulResult();
    },
  });

  assert.equal(count, 5);
  assert.deepEqual(observed.map(({ name }) => name), [
    "database-migrations",
    "canonical-domain",
    "security-event",
    "event-index-template",
    "queue-message-schemas",
  ]);
  assert.deepEqual(observed.map(({ command, args }) => [command, args]), [
    ["go", ["-C", "services/platform", "test", "-race", "-count=1", "./migrations"]],
    ["go", ["-C", "services/platform", "test", "-race", "-count=1", "./domain"]],
    ["go", ["-C", "services/platform", "test", "-race", "-count=1", "./securityevent"]],
    ["go", ["-C", "services/platform", "test", "-race", "-count=1", "./eventindex"]],
    ["go", ["-C", "services/platform", "test", "-race", "-count=1", "./queuedefinition"]],
  ]);
  assert.ok(observed.every(({ cwd, timeoutMilliseconds, maxOutputBytes }) =>
    cwd === repositoryRoot && timeoutMilliseconds === 120_000 && maxOutputBytes === 1_048_576));
});

test("passes only the offline Go environment allowlist", () => {
  const targets = createSchemaTargets({ repositoryRoot, environment });
  const expected = {
    PATH: environment.PATH,
    HOME: environment.HOME,
    LANG: environment.LANG,
    GOENV: "off",
    GOTOOLCHAIN: "local",
    GOPROXY: "off",
    GOSUMDB: "off",
    GOWORK: "off",
  };

  assert.ok(targets.every((target) => JSON.stringify(target.environment) === JSON.stringify(expected)));
  for (const forbidden of ["AWS_ACCESS_KEY_ID", "DATABASE_URL", "HTTPS_PROXY", "NODE_OPTIONS"]) {
    assert.ok(targets.every((target) => !(forbidden in target.environment)));
  }
});

test("rejects invalid repository or missing execution authority before spawning", () => {
  for (const repository of ["relative", "", "/safe/repository\0forged"]) {
    assert.throws(() => createSchemaTargets({ repositoryRoot: repository, environment }));
  }
  for (const missing of ["PATH", "HOME"]) {
    const invalid = { ...environment };
    delete invalid[missing];
    assert.throws(() => createSchemaTargets({ repositoryRoot, environment: invalid }));
  }
});

test("fails fast on rejected, signaled, oversized, or malformed child results", () => {
  const outcomes = [
    { error: undefined, status: 1, signal: null, stdout: "", stderr: "rejected" },
    { error: undefined, status: null, signal: "SIGKILL", stdout: "", stderr: "" },
    { error: new Error("timeout detail"), status: null, signal: "SIGKILL", stdout: "", stderr: "" },
    { error: undefined, status: 0, signal: null, stdout: "x".repeat(1_048_577), stderr: "" },
    { error: undefined, status: 0, signal: null, stdout: "", stderr: "x".repeat(1_048_577) },
    { error: undefined, status: 0, signal: null, stdout: null, stderr: "" },
    null,
  ];
  for (const outcome of outcomes) {
    let calls = 0;
    assert.throws(() => checkSchemas({
      repositoryRoot,
      environment,
      execute() {
        calls += 1;
        return outcome;
      },
    }));
    assert.equal(calls, 1);
  }
});

test("fails fast when the executor throws", () => {
  let calls = 0;
  assert.throws(() => checkSchemas({
    repositoryRoot,
    environment,
    execute() {
      calls += 1;
      throw new Error("sensitive child detail");
    },
  }));
  assert.equal(calls, 1);
});

test("contains every outcome behind one fixed process line", () => {
  const output = [];
  const errors = [];
  assert.equal(runMain({
    arguments: [],
    stdout: { write: (value) => output.push(value) },
    stderr: { write: (value) => errors.push(value) },
    runtime: { repositoryRoot, environment, execute: () => successfulResult() },
  }), 0);
  assert.deepEqual(output, [successLine]);
  assert.deepEqual(errors, []);

  for (const scenario of [
    { arguments: ["extra"], runtime: undefined },
    { arguments: [], runtime: { repositoryRoot, environment, execute: () => { throw new Error("secret"); } } },
  ]) {
    const rejectedOutput = [];
    const rejectedErrors = [];
    assert.equal(runMain({
      ...scenario,
      stdout: { write: (value) => rejectedOutput.push(value) },
      stderr: { write: (value) => rejectedErrors.push(value) },
    }), 1);
    assert.deepEqual(rejectedOutput, []);
    assert.deepEqual(rejectedErrors, [failureLine]);
  }

  assert.equal(runMain({
    arguments: [],
    stdout: { write: () => false },
    stderr: { write: () => true },
    runtime: { repositoryRoot, environment, execute: () => successfulResult() },
  }), 1);
});

test("contains no generator, live database, provider, container, or remote target", () => {
  const serialized = JSON.stringify(createSchemaTargets({ repositoryRoot, environment })
    .map(({ command, args }) => [command, args]));
  for (const forbidden of [
    "generate", "drizzle", "neon", "docker", "kubectl", "aws", "localstack",
    "openapi", "curl", "wget", "http://", "https://", "sh", "bash",
  ]) {
    assert.equal(serialized.includes(`"${forbidden}"`), false);
  }
});

test("exposes exactly one root schema gate command", () => {
  const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(manifest.scripts["schema:check"], "node scripts/check-m1-schemas.mjs");
  assert.deepEqual(Object.keys(manifest.scripts).filter((name) => /^m1.*schema|schema.*check$/i.test(name)), ["schema:check"]);
});
