import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import {
  OPENSEARCH_IMAGE,
  DockerRuntime,
  buildDockerRunArguments,
  buildGoToolEnvironment,
  buildProofEnvironment,
  eventStoreSuccessLine,
  orchestrate,
  runMain,
  successLine,
} from "./run.mjs";

class FakeRuntime {
  constructor({ proofCode = 0, ready = true, cleanupFails = false } = {}) {
    this.proofCode = proofCode;
    this.ready = ready;
    this.cleanupFails = cleanupFails;
    this.calls = [];
  }
  async ensureAbsent() { this.calls.push("ensure-absent"); }
  async start() { this.calls.push("start"); return "opaque-owned-token"; }
  async verifyOwned(token) { assert.equal(token, "opaque-owned-token"); this.calls.push("verify-owned"); }
  async endpoint() { this.calls.push("endpoint"); return "http://127.0.0.1:49152"; }
  async isReady() { this.calls.push("ready"); return this.ready; }
  async runProof(endpoint, mode) { assert.equal(endpoint, "http://127.0.0.1:49152"); this.calls.push(`proof:${mode}`); return this.proofCode; }
  async remove() { this.calls.push("remove"); if (this.cleanupFails) throw new Error("suppressed cleanup detail"); }
  async requireAbsent() { this.calls.push("require-absent"); if (this.cleanupFails) throw new Error("suppressed absence detail"); }
}

test("pins the exact disposable OpenSearch image and isolates the target", () => {
  assert.match(OPENSEARCH_IMAGE, /^opensearchproject\/opensearch:3\.8\.0@sha256:[a-f0-9]{64}$/);
  const args = buildDockerRunArguments("zasp-m0-08-0123456789abcdef");
  assert.deepEqual(args.slice(0, 8), ["run", "--detach", "--rm", "--name", "zasp-m0-08-0123456789abcdef", "--publish", "127.0.0.1::9200", "--env"]);
  assert.ok(args.includes("discovery.type=single-node"));
  assert.ok(args.includes("DISABLE_SECURITY_PLUGIN=true"));
  assert.ok(args.includes("DISABLE_INSTALL_DEMO_CONFIG=true"));
  assert.ok(args.includes("OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m"));
  assert.equal(args.at(-1), OPENSEARCH_IMAGE);
  assert.equal(args.some((value) => value.includes("zapp-dev")), false);
});

test("passes only the endpoint and PATH to the Go proof", () => {
  assert.deepEqual(buildProofEnvironment("http://127.0.0.1:49152", "/safe/path"), {
    OPENSEARCH_ENDPOINT: "http://127.0.0.1:49152",
    PATH: "/safe/path",
  });
});

test("builds with offline allowlisted Go caches", () => {
  assert.deepEqual(buildGoToolEnvironment("/safe/path", "/safe/build-cache", "/safe/module-cache"), {
    PATH: "/safe/path", GOCACHE: "/safe/build-cache", GOMODCACHE: "/safe/module-cache",
    GOENV: "off", GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local", CGO_ENABLED: "0",
  });
});

test("runs readiness and proof before exact cleanup and absence proof", async () => {
  const runtime = new FakeRuntime();
  const result = await orchestrate(runtime, { readinessAttempts: 1, wait: async () => {} });
  assert.deepEqual(result, { code: 0, line: successLine });
  assert.deepEqual(runtime.calls, ["ensure-absent", "start", "verify-owned", "endpoint", "ready", "proof:projection", "remove", "require-absent"]);
});

test("runs the product EventStore mode at a distinct exact boundary", async () => {
  const runtime = new FakeRuntime();
  const result = await orchestrate(runtime, { mode: "event-store", readinessAttempts: 1, wait: async () => {} });
  assert.deepEqual(result, { code: 0, line: eventStoreSuccessLine });
  assert.deepEqual(runtime.calls, ["ensure-absent", "start", "verify-owned", "endpoint", "ready", "proof:event-store", "remove", "require-absent"]);
});

test("uses an exact M1-14 disposable identity without changing the legacy identity", () => {
  const product = buildDockerRunArguments("zasp-m1-14-0123456789abcdef", "event-store");
  assert.ok(product.includes("zasp.proof=m1-14"));
  assert.ok(product.includes("zasp.marker=0123456789abcdef"));
  assert.equal(product.at(-1), OPENSEARCH_IMAGE);
  const legacy = buildDockerRunArguments("zasp-m0-08-0123456789abcdef");
  assert.ok(legacy.includes("zasp.proof=m0-08"));
  assert.equal(legacy.includes("zasp.proof=m1-14"), false);
});

test("cleanup failure takes precedence over success or proof failure", async () => {
  for (const proofCode of [0, 23]) {
    const runtime = new FakeRuntime({ proofCode, cleanupFails: true });
    assert.deepEqual(await orchestrate(runtime, { readinessAttempts: 1, wait: async () => {} }), {
      code: 1, line: "OpenSearch event projection proof failed: cleanup rejected.",
    });
  }
});

test("EventStore cleanup failure keeps the EventStore fixed line", async () => {
  const runtime = new FakeRuntime({ cleanupFails: true });
  assert.deepEqual(await orchestrate(runtime, { mode: "event-store", readinessAttempts: 1, wait: async () => {} }), {
    code: 1, line: "OpenSearch event store failed: cleanup rejected.",
  });
});

test("bounded readiness failure still removes the exact owned target", async () => {
  const runtime = new FakeRuntime({ ready: false });
  const result = await orchestrate(runtime, { readinessAttempts: 2, wait: async () => {} });
  assert.deepEqual(result, { code: 1, line: "OpenSearch event projection proof failed: readiness rejected." });
  assert.deepEqual(runtime.calls.slice(-2), ["remove", "require-absent"]);
});

test("reconciles an ambiguous start only through exact ownership", async () => {
  const token = "a".repeat(64);
  class ReconciledRuntime extends DockerRuntime {
    constructor() {
      super({ path: "/safe/path", marker: "0123456789abcdef" });
      this.resolvedImageID = `sha256:${"b".repeat(64)}`;
      this.responses = [
        { status: 1, stdout: "", stderr: "suppressed" },
        { status: 0, stdout: `${token}\n`, stderr: "" },
        { status: 0, stdout: `${token}|/${this.name}|${this.resolvedImageID}|${OPENSEARCH_IMAGE}|m0-08|${this.marker}\n`, stderr: "" },
      ];
    }
    docker() { return this.responses.shift(); }
  }
  const runtime = new ReconciledRuntime();
  assert.equal(await runtime.start(), token);
  assert.equal(runtime.responses.length, 0);
});

test("preflight fetches only the exact pin when the image is not local", async () => {
  class PullingRuntime extends DockerRuntime {
    constructor() {
      super({ path: "/safe/path", marker: "0123456789abcdef" });
      this.calls = [];
      this.responses = [
        { status: 0, stdout: "", stderr: "" },
        { status: 1, stdout: "", stderr: "suppressed" },
        { status: 0, stdout: "suppressed", stderr: "" },
        { status: 0, stdout: `sha256:${"b".repeat(64)}\n`, stderr: "" },
      ];
    }
    docker(args) { this.calls.push(args); return this.responses.shift(); }
  }
  const runtime = new PullingRuntime();
  await runtime.ensureAbsent();
  assert.deepEqual(runtime.calls[2], ["pull", OPENSEARCH_IMAGE]);
  assert.deepEqual(runtime.calls[3], ["image", "inspect", "--format", "{{.Id}}", OPENSEARCH_IMAGE]);
  assert.equal(runtime.responses.length, 0);
});

test("cleans a retained exact candidate after a post-start failure", async () => {
  class CandidateRuntime extends FakeRuntime {
    async start() { this.calls.push("start"); throw new Error("suppressed ownership detail"); }
    hasCandidate() { return true; }
  }
  const runtime = new CandidateRuntime();
  assert.deepEqual(await orchestrate(runtime, { readinessAttempts: 1, wait: async () => {} }), {
    code: 1, line: "OpenSearch event projection proof failed: operation rejected.",
  });
  assert.deepEqual(runtime.calls, ["ensure-absent", "start", "remove", "require-absent"]);
});

async function withReadinessServer(handler, assertion) {
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    assert.equal(typeof address, "object");
    await assertion(`http://127.0.0.1:${address.port}`);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
}

test("rejects an oversized readiness chunk immediately", async () => {
  await withReadinessServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.write("x".repeat(16_385));
  }, async (endpoint) => {
    const runtime = new DockerRuntime({ path: "/safe/path", marker: "0123456789abcdef" });
    assert.equal(await Promise.race([
      runtime.isReady(endpoint), new Promise((resolve) => setTimeout(() => resolve("unbounded"), 300)),
    ]), false);
  });
});

test("bounds an endlessly streaming readiness response and cleans", async () => {
  await withReadinessServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    const interval = setInterval(() => response.write("x"), 25);
    response.once("close", () => clearInterval(interval));
  }, async (endpoint) => {
    class StreamingRuntime extends FakeRuntime {
      async endpoint() { this.calls.push("endpoint"); return endpoint; }
      async isReady(value) { this.calls.push("ready"); return DockerRuntime.prototype.isReady.call(this, value); }
    }
    const runtime = new StreamingRuntime();
    const result = await Promise.race([
      orchestrate(runtime, { readinessAttempts: 1, wait: async () => {} }),
      new Promise((resolve) => setTimeout(() => resolve("unbounded"), 800)),
    ]);
    assert.deepEqual(result, { code: 1, line: "OpenSearch event projection proof failed: readiness rejected." });
    assert.deepEqual(runtime.calls.slice(-2), ["remove", "require-absent"]);
  });
});

test("contains construction and orchestration failures at one fixed-output boundary", async () => {
  const factories = [
    () => new DockerRuntime({ path: "" }),
    () => new DockerRuntime({ path: "/safe/path", marker: "invalid" }),
    () => new DockerRuntime({ path: "/safe/path", randomBytesSource: () => { throw new Error("suppressed random detail"); } }),
    () => ({ async ensureAbsent() { throw new Error("suppressed runtime detail"); }, hasCandidate() { throw new Error("suppressed finalizer detail"); } }),
  ];
  for (const runtimeFactory of factories) {
    let stdout = "";
    let stderr = "";
    let exitCode;
    const result = await runMain({
      runtimeFactory,
      stdout: { write: (value) => { stdout += value; } },
      stderr: { write: (value) => { stderr += value; } },
      setExitCode: (value) => { exitCode = value; },
    });
    assert.equal(result.code, 1);
    assert.equal(stdout, "");
    assert.match(stderr, /^OpenSearch event projection proof failed: (configuration|operation) rejected\.\n$/);
    assert.equal(exitCode, 1);
    assert.equal(stderr.includes("suppressed"), false);
    assert.equal(stderr.split("\n").filter(Boolean).length, 1);
  }
});

test("runMain accepts only the exact EventStore mode argument", async () => {
  for (const [argumentsValue, expectedFailure] of [
    [["--event-store"], ""],
    [["--event-store", "extra"], "OpenSearch event store failed: configuration rejected."],
    [["--Event-store"], "OpenSearch event projection proof failed: configuration rejected."],
  ]) {
    let stdout = "";
    let stderr = "";
    let exitCode;
    const result = await runMain({
      arguments: argumentsValue,
      runtimeFactory: (mode) => {
        assert.equal(mode, "event-store");
        return new FakeRuntime();
      },
      stdout: { write: (value) => { stdout += value; } },
      stderr: { write: (value) => { stderr += value; } },
      setExitCode: (value) => { exitCode = value; },
    });
    if (expectedFailure === "") {
      assert.deepEqual(result, { code: 0, line: eventStoreSuccessLine });
      assert.equal(stdout, `${eventStoreSuccessLine}\n`);
      assert.equal(stderr, "");
      assert.equal(exitCode, 0);
    } else {
      assert.deepEqual(result, { code: 1, line: expectedFailure });
      assert.equal(stdout, "");
      assert.equal(stderr, `${expectedFailure}\n`);
      assert.equal(exitCode, 1);
    }
  }
});
