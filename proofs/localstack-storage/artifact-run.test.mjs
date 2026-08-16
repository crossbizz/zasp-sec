import assert from "node:assert/strict";
import test from "node:test";

import { artifactRunMain } from "./run-artifact-store.mjs";
import {
  ARTIFACT_MODE,
  DockerRuntime,
  artifactProofTimeoutMilliseconds,
  artifactSuccessLine,
  buildDockerRunArguments,
  orchestrate,
} from "./run.mjs";

class ArtifactRuntime {
  constructor({ cleanupFails = false } = {}) {
    this.cleanupFails = cleanupFails;
    this.successLine = artifactSuccessLine;
    this.failureLine = (category) => `LocalStack artifact store failed: ${category} rejected.`;
    this.calls = [];
  }
  async ensureAbsent() { this.calls.push("ensure-absent"); }
  async start() { this.calls.push("start"); return "opaque-artifact-token"; }
  async verifyOwned(token) { assert.equal(token, "opaque-artifact-token"); this.calls.push("verify-owned"); }
  async endpoint() { this.calls.push("endpoint"); return "http://127.0.0.1:49152"; }
  async isReady() { this.calls.push("ready"); return true; }
  async runProof() { this.calls.push("proof"); return 0; }
  async remove() { this.calls.push("remove"); if (this.cleanupFails) throw new Error("suppressed"); }
  async requireAbsent() { this.calls.push("require-absent"); }
}

test("builds the exact isolated M1-12 LocalStack command", () => {
  const name = "zasp-m1-12-0123456789abcdef";
  const args = buildDockerRunArguments(name, ARTIFACT_MODE);
  assert.ok(args.includes("SERVICES=s3,kms"));
  assert.ok(args.includes("zasp.proof=m1-12"));
  assert.ok(args.includes("zasp.marker=0123456789abcdef"));
  assert.equal(args.some((value) => value.includes("secretsmanager")), false);
  assert.equal(args.at(-1), DockerRuntime.image);
  assert.equal(artifactProofTimeoutMilliseconds, 150_000);
});

test("uses the artifact fixed line and retains reverse cleanup", async () => {
  const runtime = new ArtifactRuntime();
  const result = await orchestrate(runtime, { readinessAttempts: 1, wait: async () => {} });
  assert.deepEqual(result, { code: 0, line: artifactSuccessLine });
  assert.deepEqual(runtime.calls, ["ensure-absent", "start", "verify-owned", "endpoint", "ready", "proof", "remove", "require-absent"]);
});

test("artifact CLI contains success and cleanup failure at one fixed line", async () => {
  for (const cleanupFails of [false, true]) {
    let stdout = "";
    let stderr = "";
    let exitCode;
    const result = await artifactRunMain({
      runtimeFactory: () => new ArtifactRuntime({ cleanupFails }),
      stdout: { write: (value) => { stdout += value; } },
      stderr: { write: (value) => { stderr += value; } },
      setExitCode: (value) => { exitCode = value; },
    });
    if (cleanupFails) {
      assert.deepEqual(result, { code: 1, line: "LocalStack artifact store failed: cleanup rejected." });
      assert.equal(stdout, "");
      assert.equal(stderr, "LocalStack artifact store failed: cleanup rejected.\n");
      assert.equal(exitCode, 1);
    } else {
      assert.deepEqual(result, { code: 0, line: artifactSuccessLine });
      assert.equal(stdout, `${artifactSuccessLine}\n`);
      assert.equal(stderr, "");
      assert.equal(exitCode, 0);
    }
  }
});
