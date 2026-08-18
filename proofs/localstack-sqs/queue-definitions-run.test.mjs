import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { runQueueDefinitionsMain } from "./run-queue-definitions.mjs";
import {
  DockerRuntime,
  LOCALSTACK_IMAGE,
  QUEUE_DEFINITIONS_MODE,
  buildDockerRunArguments,
  queueDefinitionsProofTimeoutMilliseconds,
  queueDefinitionsSuccessLine,
} from "../localstack-storage/run.mjs";

class FakeRuntime {
  constructor({ proofCode = 0, cleanupFails = false } = {}) {
    this.proofCode = proofCode;
    this.cleanupFails = cleanupFails;
    this.calls = [];
    this.successLine = queueDefinitionsSuccessLine;
    this.failureLine = (category) => `LocalStack queue definitions failed: ${category} rejected.`;
  }
  async ensureAbsent() { this.calls.push("ensure"); }
  async start() { this.calls.push("start"); return "token"; }
  async verifyOwned() { this.calls.push("verify"); }
  async endpoint() { this.calls.push("endpoint"); return "http://127.0.0.1:49152"; }
  async isReady() { this.calls.push("ready"); return true; }
  async runProof() { this.calls.push("proof"); return this.proofCode; }
  async remove() {
    this.calls.push("remove");
    if (this.cleanupFails) throw new Error("private cleanup detail");
  }
  async requireAbsent() {
    this.calls.push("absent");
    if (this.cleanupFails) throw new Error("private absence detail");
  }
}

function directoryStat(dev, ino) {
  return { dev, ino, isDirectory: () => true, isSymbolicLink: () => false };
}

test("pins the isolated six-queue disposable LocalStack command", () => {
  assert.equal(QUEUE_DEFINITIONS_MODE, "queue-definitions");
  const name = "zasp-m1-33-0123456789abcdef";
  const args = buildDockerRunArguments(name, QUEUE_DEFINITIONS_MODE);
  assert.deepEqual(args.slice(0, 8), ["run", "--detach", "--rm", "--name", name, "--publish", "127.0.0.1::4566", "--env"]);
  for (const value of [
    "SERVICES=sqs",
    "PERSISTENCE=0",
    "SQS_ENDPOINT_STRATEGY=dynamic",
    "zasp.proof=m1-33",
    "zasp.marker=0123456789abcdef",
  ]) assert.ok(args.includes(value), value);
  assert.equal(args.at(-1), LOCALSTACK_IMAGE);
  assert.equal(args.some((value) => value.includes("zapp-dev-localstack-1")), false);
});

test("re-proves the exact queue-definition runtime environment", async () => {
  const token = "a".repeat(64);
  const imageID = `sha256:${"b".repeat(64)}`;
  const commands = [];
  const runtime = new DockerRuntime({
    path: "/safe/path",
    home: "/safe/home",
    marker: "0123456789abcdef",
    mode: QUEUE_DEFINITIONS_MODE,
    command: (_executable, args) => {
      commands.push(args);
      if (args[2].includes(".Config.Env")) {
        return {
          status: 0,
          stdout: JSON.stringify([
            "SERVICES=sqs",
            "PERSISTENCE=0",
            "SQS_ENDPOINT_STRATEGY=dynamic",
            "LOCALSTACK_BUILD_DATE=immutable-image-value",
          ]) + "\n",
        };
      }
      return {
        status: 0,
        stdout: [
          token,
          "/zasp-m1-33-0123456789abcdef",
          imageID,
          LOCALSTACK_IMAGE,
          "m1-33",
          "0123456789abcdef",
        ].join("|") + "\n",
      };
    },
  });
  runtime.resolvedImageID = imageID;
  await runtime.verifyOwned(token);
  assert.equal(commands.length, 2);

  runtime.command = (_executable, args) => {
    if (args[2].includes(".Config.Env")) {
      return { status: 0, stdout: JSON.stringify(["SERVICES=sqs", "PERSISTENCE=0"]) + "\n" };
    }
    return {
      status: 0,
      stdout: [token, `/${runtime.name}`, imageID, LOCALSTACK_IMAGE, "m1-33", runtime.marker].join("|") + "\n",
    };
  };
  await assert.rejects(runtime.verifyOwned(token));

  for (const hostile of ["AWS_PROFILE=private", "HTTPS_PROXY=http://127.0.0.1:9000"]) {
    runtime.command = (_executable, args) => {
      if (args[2].includes(".Config.Env")) {
        return {
          status: 0,
          stdout: JSON.stringify([
            "SERVICES=sqs",
            "PERSISTENCE=0",
            "SQS_ENDPOINT_STRATEGY=dynamic",
            hostile,
          ]) + "\n",
        };
      }
      return {
        status: 0,
        stdout: [token, `/${runtime.name}`, imageID, LOCALSTACK_IMAGE, "m1-33", runtime.marker].join("|") + "\n",
      };
    };
    await assert.rejects(runtime.verifyOwned(token), hostile);
  }
});

test("runs the exact child mode under the hard bounded proof supervisor", async () => {
  const directory = "/safe/tmp/zasp-m1-33-owned";
  const removals = [];
  const commands = [];
  const command = (executable, args, options) => {
    commands.push({ executable, args, options });
    if (executable === "go" && args[0] === "env") {
      return { status: 0, stdout: JSON.stringify({ GOCACHE: "/safe/cache", GOMODCACHE: "/safe/mod" }), stderr: "" };
    }
    if (executable === "go") return { status: 0, stdout: "", stderr: "" };
    return {
      status: 0,
      stdout: "LocalStack queue definitions passed: queues=3 dlqs=3 schemas=3 retention=true redrive=true cleanup=true audit=true.\n",
      stderr: "",
    };
  };
  const runtime = new DockerRuntime({
    path: "/safe/path", home: "/safe/home", marker: "0123456789abcdef", mode: QUEUE_DEFINITIONS_MODE,
    command, makeTemp: () => directory, removeTemp: (...args) => removals.push(args), tempParent: "/safe/tmp",
    canonicalPath: (value) => value, statPath: () => directoryStat(1, 2),
  });
  assert.equal(await runtime.runProof("http://127.0.0.1:49152"), 0);
  const child = commands.find(({ executable }) => executable.endsWith("queue-definitions-proof"));
  assert.deepEqual(child.args, ["queue-definitions"]);
  assert.equal(child.options.timeout, queueDefinitionsProofTimeoutMilliseconds);
  assert.equal(child.options.killSignal, "SIGKILL");
  const build = commands.find(({ executable, args }) => executable === "go" && args[0] === "build");
  for (const bounded of [build, child]) {
    assert.equal(bounded.options.maxBuffer * 2, 1024 * 1024);
    assert.equal(bounded.options.killSignal, "SIGKILL");
  }
  assert.deepEqual(child.options.env, { AWS_ENDPOINT_URL: "http://127.0.0.1:49152", PATH: "/safe/path" });
  assert.deepEqual(removals, [[directory, { recursive: true, force: false, maxRetries: 0 }]]);
});

test("leaves a hard supervisor margin beyond every Go cleanup phase", () => {
  const source = readFileSync(new URL("./main.go", import.meta.url), "utf8");
  const entrypoint = source.match(/func runQueueDefinitionsProofMain\(\) \{[\s\S]*?\n\}/)?.[0] ?? "";
  const mainSeconds = Number(entrypoint.match(/WithTimeout\(context\.Background\(\), ([0-9]+)\*time\.Second\)/)?.[1]);
  const cleanupSeconds = Number(entrypoint.match(/CleanupTimeout: ([0-9]+) \* time\.Second/)?.[1]);
  assert.ok(Number.isSafeInteger(mainSeconds) && Number.isSafeInteger(cleanupSeconds));
  const worstCaseSeconds = mainSeconds + (3 * cleanupSeconds);
  assert.ok(queueDefinitionsProofTimeoutMilliseconds >= (worstCaseSeconds + 60) * 1000);
});

test("emits only the fixed outer success line", async () => {
  const runtime = new FakeRuntime();
  let stdout = "";
  let stderr = "";
  let exitCode;
  const result = await runQueueDefinitionsMain({
    runtimeFactory: () => runtime,
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
    setExitCode: (value) => { exitCode = value; },
  });
  assert.deepEqual(result, { code: 0, line: queueDefinitionsSuccessLine });
  assert.equal(stdout, `${queueDefinitionsSuccessLine}\n`);
  assert.equal(stderr, "");
  assert.equal(exitCode, 0);
  assert.deepEqual(runtime.calls, ["ensure", "start", "verify", "endpoint", "ready", "proof", "remove", "absent"]);
});

test("cleanup failure wins without exposing runtime details", async () => {
  const runtime = new FakeRuntime({ cleanupFails: true });
  let stdout = "";
  let stderr = "";
  let exitCode;
  const result = await runQueueDefinitionsMain({
    runtimeFactory: () => runtime,
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
    setExitCode: (value) => { exitCode = value; },
  });
  assert.deepEqual(result, { code: 1, line: "LocalStack queue definitions failed: cleanup rejected." });
  assert.equal(stdout, "");
  assert.equal(stderr, "LocalStack queue definitions failed: cleanup rejected.\n");
  assert.equal(stderr.includes("private"), false);
  assert.equal(exitCode, 1);
});

test("rejects unknown modes without changing established mode commands", () => {
  assert.throws(() => buildDockerRunArguments("zasp-m1-33-0123456789abcdef", "unknown"));
  assert.ok(buildDockerRunArguments("zasp-m0-07-0123456789abcdef", "storage").includes("SERVICES=s3,kms,secretsmanager"));
  assert.ok(buildDockerRunArguments("zasp-m1-12-0123456789abcdef", "artifact").includes("SERVICES=s3,kms"));
  assert.ok(buildDockerRunArguments("zasp-m1-13-0123456789abcdef", "job-queue").includes("SERVICES=sqs"));
});
