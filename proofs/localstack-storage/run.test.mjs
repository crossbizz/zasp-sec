import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import {
  LOCALSTACK_IMAGE,
  DockerRuntime,
  artifactProofTimeoutMilliseconds,
  buildDockerRunArguments,
  buildGoToolEnvironment,
  buildProofEnvironment,
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
  async runProof(endpoint) { assert.equal(endpoint, "http://127.0.0.1:49152"); this.calls.push("proof"); return this.proofCode; }
  async remove() { this.calls.push("remove"); if (this.cleanupFails) throw new Error("sensitive cleanup detail"); }
  async requireAbsent() { this.calls.push("require-absent"); if (this.cleanupFails) throw new Error("sensitive absence detail"); }
}

test("pins the exact LocalStack version and digest in the disposable run command", () => {
  assert.match(LOCALSTACK_IMAGE, /^localstack\/localstack:4\.7\.0@sha256:[a-f0-9]{64}$/);
  const args = buildDockerRunArguments("zasp-m0-07-0123456789abcdef");
  assert.deepEqual(args.slice(0, 8), ["run", "--detach", "--rm", "--name", "zasp-m0-07-0123456789abcdef", "--publish", "127.0.0.1::4566", "--env"]);
  assert.ok(args.includes("SERVICES=s3,kms,secretsmanager"));
  assert.ok(args.includes("PERSISTENCE=0"));
  assert.equal(args.at(-1), LOCALSTACK_IMAGE);
  assert.equal(args.some((value) => value.includes("zapp-dev-localstack-1")), false);
});

test("passes only the process endpoint and PATH to the Go proof", () => {
  assert.deepEqual(buildProofEnvironment("http://127.0.0.1:49152", "/safe/path"), {
    AWS_ENDPOINT_URL: "http://127.0.0.1:49152",
    PATH: "/safe/path",
  });
});

test("builds with offline allowlisted Go tool caches and no ambient AWS configuration", () => {
  assert.deepEqual(buildGoToolEnvironment("/safe/path", "/safe/build-cache", "/safe/module-cache"), {
    PATH: "/safe/path",
    GOCACHE: "/safe/build-cache",
    GOMODCACHE: "/safe/module-cache",
    GOENV: "off",
    GOPROXY: "off",
    GOSUMDB: "off",
    GOTOOLCHAIN: "local",
    CGO_ENABLED: "0",
  });
});

test("runs readiness and proof before exact cleanup and absence proof", async () => {
  const runtime = new FakeRuntime();
  const result = await orchestrate(runtime, { readinessAttempts: 1, wait: async () => {} });
  assert.deepEqual(result, { code: 0, line: successLine });
  assert.deepEqual(runtime.calls, ["ensure-absent", "start", "verify-owned", "endpoint", "ready", "proof", "remove", "require-absent"]);
});

test("propagates proof failure after cleanup", async () => {
  const runtime = new FakeRuntime({ proofCode: 23 });
  const result = await orchestrate(runtime, { readinessAttempts: 1, wait: async () => {} });
  assert.equal(result.code, 23);
  assert.equal(result.line, "LocalStack storage proof failed: operation rejected.");
  assert.deepEqual(runtime.calls.slice(-2), ["remove", "require-absent"]);
});

test("cleanup failure overrides proof success or failure", async () => {
  for (const proofCode of [0, 23]) {
    const runtime = new FakeRuntime({ proofCode, cleanupFails: true });
    const result = await orchestrate(runtime, { readinessAttempts: 1, wait: async () => {} });
    assert.deepEqual(result, { code: 1, line: "LocalStack storage proof failed: cleanup rejected." });
  }
});

test("bounded readiness timeout still removes the exact owned container", async () => {
  const runtime = new FakeRuntime({ ready: false });
  const result = await orchestrate(runtime, { readinessAttempts: 2, wait: async () => {} });
  assert.deepEqual(result, { code: 1, line: "LocalStack storage proof failed: readiness rejected." });
  assert.equal(runtime.calls.filter((call) => call === "ready").length, 2);
  assert.deepEqual(runtime.calls.slice(-2), ["remove", "require-absent"]);
});

test("reconciles an ambiguous docker start only through exact current ownership", async () => {
  const token = "a".repeat(64);
  class ReconciledRuntime extends DockerRuntime {
    constructor() {
      super({ path: "/safe/path", marker: "0123456789abcdef" });
      this.resolvedImageID = `sha256:${"b".repeat(64)}`;
      this.responses = [
        { status: null, signal: "SIGKILL", stdout: "", stderr: "suppressed" },
        { status: 0, stdout: `${token}\n`, stderr: "" },
        { status: 0, stdout: `${token}|/${this.name}|${this.resolvedImageID}|${LOCALSTACK_IMAGE}|m0-07|${this.marker}\n`, stderr: "" },
      ];
    }
    docker() { return this.responses.shift(); }
  }
  const runtime = new ReconciledRuntime();
  assert.equal(await runtime.start(), token);
  assert.equal(runtime.responses.length, 0);
});

test("does not reconcile a definitive docker rejection and always lists full IDs", async () => {
  const token = "a".repeat(64);
  class RejectedRuntime extends DockerRuntime {
    constructor() {
      super({ path: "/safe/path", marker: "0123456789abcdef" });
      this.resolvedImageID = `sha256:${"b".repeat(64)}`;
      this.calls = [];
      this.responses = [
        { status: 125, signal: null, stdout: "", stderr: "suppressed" },
        { status: 0, signal: null, stdout: `${token}\n`, stderr: "" },
      ];
    }
    docker(args) { this.calls.push(args); return this.responses.shift(); }
  }
  const runtime = new RejectedRuntime();
  await assert.rejects(runtime.start());
  assert.equal(runtime.calls.length, 1);
  assert.equal(runtime.hasCandidate(), false);

  class ListingRuntime extends DockerRuntime {
    constructor() {
      super({ path: "/safe/path", marker: "0123456789abcdef" });
      this.calls = [];
    }
    docker(args) {
      this.calls.push(args);
      const stdout = args[0] === "image" ? `sha256:${"b".repeat(64)}\n` : "";
      return { status: 0, signal: null, stdout, stderr: "" };
    }
  }
  const listing = new ListingRuntime();
  listing.resolvedImageID = `sha256:${"b".repeat(64)}`;
  await listing.ensureAbsent();
  assert.ok(listing.calls[0].includes("--no-trunc"));
});

test("retains a direct candidate when docker start becomes ambiguous", async () => {
  const token = "c".repeat(64);
  class CandidateRuntime extends DockerRuntime {
    constructor() {
      super({ path: "/safe/path", marker: "0123456789abcdef" });
      this.resolvedImageID = `sha256:${"b".repeat(64)}`;
      this.responses = [
        { status: null, signal: "SIGKILL", stdout: `${token}\n`, stderr: "" },
        { status: 1, signal: null, stdout: "", stderr: "suppressed" },
      ];
    }
    docker() { return this.responses.shift(); }
  }
  const runtime = new CandidateRuntime();
  await assert.rejects(runtime.start());
  assert.equal(runtime.hasCandidate(), true);
  assert.equal(runtime.token, token);
});

test("requires retained full-ID absence even when the exact name is absent", async () => {
  const token = "d".repeat(64);
  class RenamedRuntime extends DockerRuntime {
    constructor() {
      super({ path: "/safe/path", marker: "0123456789abcdef" });
      this.token = token;
    }
    docker(args) {
      if (args[0] === "inspect") return { status: 1, signal: null, stdout: "", stderr: "not found" };
      if (args.includes(`id=${token}`)) return { status: 0, signal: null, stdout: `${token}\n`, stderr: "" };
      return { status: 0, signal: null, stdout: "", stderr: "" };
    }
  }
  await assert.rejects(new RenamedRuntime().requireAbsent());
});

function directoryStat(dev, ino) {
  return { dev, ino, isDirectory: () => true, isSymbolicLink: () => false };
}

test("revalidates exact temporary-directory identity before recursive removal", async () => {
  const directory = "/safe/tmp/zasp-m1-12-owned";
  const removals = [];
  let statCalls = 0;
  const commands = [];
  const command = (executable, args, options) => {
    commands.push({ executable, args, options });
    if (executable === "go" && args[0] === "env") {
      return { status: 0, signal: null, stdout: JSON.stringify({ GOCACHE: "/safe/cache", GOMODCACHE: "/safe/mod" }), stderr: "" };
    }
    if (executable === "go") return { status: 0, signal: null, stdout: "", stderr: "" };
    return { status: 0, signal: null, stdout: "LocalStack artifact store passed: put=true get=true delete=true scoped=true encrypted=true cleanup=true audit=true.\n", stderr: "" };
  };
  const runtime = new DockerRuntime({
    path: "/safe/path", home: "/safe/home", marker: "0123456789abcdef", mode: "artifact",
    command, makeTemp: () => directory, removeTemp: (...args) => removals.push(args), tempParent: "/safe/tmp",
    canonicalPath: (value) => value,
    statPath: () => (++statCalls === 1 ? directoryStat(1, 2) : directoryStat(1, 3)),
  });
  assert.equal(await runtime.runProof("http://127.0.0.1:49152"), 1);
  assert.equal(removals.length, 0);
  const proof = commands.find(({ executable }) => executable.includes("artifact-store-proof"));
  assert.equal(proof.options.timeout, artifactProofTimeoutMilliseconds);
  assert.equal(proof.options.killSignal, "SIGKILL");
});

test("removes only an unchanged exact owned temporary directory", async () => {
  const directory = "/safe/tmp/zasp-m1-12-owned";
  const removals = [];
  const command = (executable, args) => {
    if (executable === "go" && args[0] === "env") {
      return { status: 0, signal: null, stdout: JSON.stringify({ GOCACHE: "/safe/cache", GOMODCACHE: "/safe/mod" }), stderr: "" };
    }
    if (executable === "go") return { status: 0, signal: null, stdout: "", stderr: "" };
    return { status: 0, signal: null, stdout: "LocalStack artifact store passed: put=true get=true delete=true scoped=true encrypted=true cleanup=true audit=true.\n", stderr: "" };
  };
  const runtime = new DockerRuntime({
    path: "/safe/path", home: "/safe/home", marker: "0123456789abcdef", mode: "artifact",
    command, makeTemp: () => directory, removeTemp: (...args) => removals.push(args), tempParent: "/safe/tmp",
    canonicalPath: (value) => value, statPath: () => directoryStat(1, 2),
  });
  assert.equal(await runtime.runProof("http://127.0.0.1:49152"), 0);
  assert.deepEqual(removals, [[directory, { recursive: true, force: false, maxRetries: 0 }]]);
});

test("cleans a retained exact candidate when start ownership verification throws", async () => {
  class CandidateRuntime extends FakeRuntime {
    async start() { this.calls.push("start"); throw new Error("suppressed ownership read"); }
    hasCandidate() { return true; }
  }
  const runtime = new CandidateRuntime();
  const result = await orchestrate(runtime, { readinessAttempts: 1, wait: async () => {} });
  assert.deepEqual(result, { code: 1, line: "LocalStack storage proof failed: operation rejected." });
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
    const result = await Promise.race([
      runtime.isReady(endpoint),
      new Promise((resolve) => setTimeout(() => resolve("unbounded"), 300)),
    ]);
    assert.equal(result, false);
  });
});

test("bounds an endlessly streaming readiness response", async () => {
  await withReadinessServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    const interval = setInterval(() => response.write("x"), 25);
    response.once("close", () => clearInterval(interval));
  }, async (endpoint) => {
    class StreamingRuntime extends FakeRuntime {
      async endpoint() { this.calls.push("endpoint"); return endpoint; }
      async isReady(value) {
        this.calls.push("ready");
        return DockerRuntime.prototype.isReady.call(this, value);
      }
    }
    const runtime = new StreamingRuntime();
    const result = await Promise.race([
      orchestrate(runtime, { readinessAttempts: 1, wait: async () => {} }),
      new Promise((resolve) => setTimeout(() => resolve("unbounded"), 800)),
    ]);
    assert.deepEqual(result, { code: 1, line: "LocalStack storage proof failed: readiness rejected." });
    assert.deepEqual(runtime.calls.slice(-2), ["remove", "require-absent"]);
  });
});

test("contains every runtime construction failure at the fixed-output boundary", async () => {
  const factories = [
    () => new DockerRuntime({ path: "" }),
    () => new DockerRuntime({ path: "/safe/path", marker: "invalid" }),
    () => new DockerRuntime({ path: "/safe/path", randomBytesSource: () => { throw new Error("sensitive random source detail"); } }),
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
    assert.deepEqual(result, { code: 1, line: "LocalStack storage proof failed: configuration rejected." });
    assert.equal(stdout, "");
    assert.equal(stderr, "LocalStack storage proof failed: configuration rejected.\n");
    assert.equal(exitCode, 1);
    assert.equal(stderr.includes("sensitive"), false);
    assert.equal(stderr.split("\n").filter(Boolean).length, 1);
  }
});

test("contains an escaping orchestration failure at the fixed-output boundary", async () => {
  let stderr = "";
  let exitCode;
  const runtime = {
    async ensureAbsent() { throw new Error("sensitive orchestration detail"); },
    hasCandidate() { throw new Error("sensitive finalizer detail"); },
  };
  const result = await runMain({
    runtimeFactory: () => runtime,
    stdout: { write: () => { throw new Error("unexpected stdout"); } },
    stderr: { write: (value) => { stderr += value; } },
    setExitCode: (value) => { exitCode = value; },
  });
  assert.deepEqual(result, { code: 1, line: "LocalStack storage proof failed: operation rejected." });
  assert.equal(stderr, "LocalStack storage proof failed: operation rejected.\n");
  assert.equal(exitCode, 1);
  assert.equal(stderr.includes("sensitive"), false);
  assert.equal(stderr.split("\n").filter(Boolean).length, 1);
});
