import assert from "node:assert/strict";
import test from "node:test";

import { runJobQueueMain } from "./run-job-queue.mjs";
import {
  DockerRuntime,
  JOB_QUEUE_MODE,
  LOCALSTACK_IMAGE,
  buildDockerRunArguments,
  jobQueueSuccessLine,
} from "../localstack-storage/run.mjs";

class FakeRuntime {
  constructor({ proofCode = 0, cleanupFails = false } = {}) {
    this.proofCode = proofCode;
    this.cleanupFails = cleanupFails;
    this.calls = [];
    this.successLine = jobQueueSuccessLine;
    this.failureLine = (category) => `LocalStack job queue failed: ${category} rejected.`;
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

test("pins the isolated SQS-only disposable LocalStack command", () => {
  assert.equal(JOB_QUEUE_MODE, "job-queue");
  assert.match(LOCALSTACK_IMAGE, /^localstack\/localstack:4\.7\.0@sha256:[a-f0-9]{64}$/);
  const args = buildDockerRunArguments("zasp-m1-13-0123456789abcdef", JOB_QUEUE_MODE);
  assert.ok(args.includes("SERVICES=sqs"));
  assert.ok(args.includes("PERSISTENCE=0"));
  assert.ok(args.includes("SQS_ENDPOINT_STRATEGY=dynamic"));
  assert.ok(args.includes("zasp.proof=m1-13"));
  assert.ok(args.includes("zasp.marker=0123456789abcdef"));
  assert.equal(args.at(-1), LOCALSTACK_IMAGE);
  assert.equal(args.some((value) => value.includes("zapp-dev-localstack-1")), false);
});

test("re-proves the exact SQS runtime environment before ownership use", async () => {
  const token = "a".repeat(64);
  const imageID = "sha256:" + "b".repeat(64);
  const commands = [];
  const runtime = new DockerRuntime({
    path: "/safe/path",
    home: "/safe/home",
    marker: "0123456789abcdef",
    mode: JOB_QUEUE_MODE,
    command: (_executable, args) => {
      commands.push(args);
      if (args[0] !== "inspect") throw new Error("unexpected command");
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
          "/zasp-m1-13-0123456789abcdef",
          imageID,
          LOCALSTACK_IMAGE,
          "m1-13",
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
      stdout: [
        token,
        "/zasp-m1-13-0123456789abcdef",
        imageID,
        LOCALSTACK_IMAGE,
        "m1-13",
        "0123456789abcdef",
      ].join("|") + "\n",
    };
  };
  await assert.rejects(runtime.verifyOwned(token));
});

test("runs the fixed job queue mode and emits one exact success line", async () => {
  const runtime = new FakeRuntime();
  let stdout = "";
  let stderr = "";
  let exitCode;
  const result = await runJobQueueMain({
    runtimeFactory: () => runtime,
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
    setExitCode: (value) => { exitCode = value; },
  });
  assert.deepEqual(result, { code: 0, line: jobQueueSuccessLine });
  assert.equal(stdout, `${jobQueueSuccessLine}\n`);
  assert.equal(stderr, "");
  assert.equal(exitCode, 0);
  assert.deepEqual(runtime.calls, ["ensure", "start", "verify", "endpoint", "ready", "proof", "remove", "absent"]);
});

test("cleanup failure wins without exposing runtime details", async () => {
  const runtime = new FakeRuntime({ cleanupFails: true });
  let stdout = "";
  let stderr = "";
  let exitCode;
  const result = await runJobQueueMain({
    runtimeFactory: () => runtime,
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
    setExitCode: (value) => { exitCode = value; },
  });
  assert.deepEqual(result, { code: 1, line: "LocalStack job queue failed: cleanup rejected." });
  assert.equal(stdout, "");
  assert.equal(stderr, "LocalStack job queue failed: cleanup rejected.\n");
  assert.equal(stderr.includes("private"), false);
  assert.equal(exitCode, 1);
});
