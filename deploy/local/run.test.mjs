import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import { PRODUCTS } from "./manifests.mjs";
import {
  Failure,
  buildChildEnvironment,
  buildServicePlan,
  classifyMutationResult,
  runBounded,
  validateImageInspection,
} from "./run.mjs";

const owned = Object.freeze({
  contextRoot: "/owned/images",
  dockerConfig: "/owned/docker",
  dockerfile: "/repository/deploy/local/Dockerfile",
  goCache: "/owned/go-build",
  goModuleCache: "/owned/go-mod",
  repositoryRoot: "/repository",
});
const marker = "0123456789abcdef";

function imageDocument(product, overrides = {}) {
  const id = `sha256:${"a".repeat(64)}`;
  return [{
    Architecture: "arm64",
    Config: {
      AttachStderr: false,
      AttachStdin: false,
      AttachStdout: false,
      Cmd: null,
      Domainname: "",
      Entrypoint: ["/service"],
      Env: null,
      ExposedPorts: { "8081/tcp": {} },
      Healthcheck: null,
      Hostname: "",
      Image: "",
      Labels: {
        "zasp.dev/component": product.name,
        "zasp.dev/proof": "m1-30a",
        "zasp.dev/run": marker,
      },
      OnBuild: null,
      OpenStdin: false,
      StdinOnce: false,
      Tty: false,
      User: "65532:65532",
      Volumes: null,
      WorkingDir: "",
    },
    Id: id,
    Os: "linux",
    RepoDigests: [],
    RepoTags: [product.image],
    RootFS: { Layers: [`sha256:${"b".repeat(64)}`], Type: "layers" },
    ...overrides,
  }];
}

function fakeChild(action) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killedWith = [];
  child.kill = (signal) => { child.killedWith.push(signal); return true; };
  queueMicrotask(() => action(child));
  return child;
}

test("Dockerfile is an exact dependency-free non-root scratch boundary", async () => {
  const text = await readFile(join(import.meta.dirname, "Dockerfile"), "utf8");
  assert.equal(text, [
    "FROM scratch",
    "ARG BINARY=service",
    "COPY --chown=65532:65532 ${BINARY} /service",
    "USER 65532:65532",
    "EXPOSE 8081",
    "ENTRYPOINT [\"/service\"]",
    "",
  ].join("\n"));
  assert.doesNotMatch(text, /RUN|ADD|https?:|apk|apt|shell|latest/i);
});

test("builds exact host Go and Docker plans for all four real commands", () => {
  for (const product of PRODUCTS) {
    assert.deepEqual(buildServicePlan(product, owned, marker), {
      binary: `/owned/images/${product.name}/service`,
      buildContext: `/owned/images/${product.name}`,
      docker: {
        arguments: [
          "build", "--file", "/repository/deploy/local/Dockerfile",
          "--build-arg", "BINARY=service",
          "--label", `zasp.dev/component=${product.name}`,
          "--label", "zasp.dev/proof=m1-30a",
          "--label", `zasp.dev/run=${marker}`,
          "--tag", product.image,
          `/owned/images/${product.name}`,
        ],
        command: "docker",
      },
      go: {
        arguments: [
          "build", "-trimpath", "-ldflags=-s -w -X main.buildVersion=m1-30a",
          "-o", `/owned/images/${product.name}/service`, product.package,
        ],
        command: "go",
        cwd: `/repository/${product.module}`,
        environment: {
          CGO_ENABLED: "0",
          GOCACHE: "/owned/go-build",
          GOENV: "off",
          GOMODCACHE: "/owned/go-mod",
          GOWORK: "off",
        },
      },
      image: product.image,
      name: product.name,
    });
  }
});

test("rejects forged products, paths, and proof markers before building", () => {
  const cases = [
    [structuredClone(PRODUCTS[0]), { ...owned }, "short"],
    [{ ...PRODUCTS[0], image: "busybox:latest" }, { ...owned }, marker],
    [{ ...PRODUCTS[0], package: "../agentsec-worker" }, { ...owned }, marker],
    [{ ...PRODUCTS[0], unexpected: true }, { ...owned }, marker],
    [PRODUCTS[0], { ...owned, repositoryRoot: "relative" }, marker],
    [PRODUCTS[0], { ...owned, contextRoot: "/owned/../escape" }, marker],
    [PRODUCTS[0], { ...owned, dockerfile: "/other/Dockerfile" }, marker],
    [PRODUCTS[0], { ...owned, extra: "/owned/extra" }, marker],
  ];
  for (const value of cases) assert.throws(() => buildServicePlan(...value), { name: "TypeError" });
});

test("constructs an exact child environment and never forwards ambient authority", () => {
  const result = buildChildEnvironment({
    DOCKER_CONFIG: "/ambient/docker",
    HOME: "/Users/test",
    LANG: "en_US.UTF-8",
    PATH: "/usr/bin:/bin",
    RANDOM_VALUE: "ignored",
  }, owned);
  assert.deepEqual(result, {
    DOCKER_CONFIG: "/owned/docker",
    HOME: "/Users/test",
    LANG: "C.UTF-8",
    PATH: "/usr/bin:/bin",
  });
  assert.equal(Object.values(result).some((value) => value.includes("ambient")), false);
});

test("rejects absent or unsafe required host environment", () => {
  for (const environment of [
    {},
    { HOME: "/Users/test", PATH: "relative" },
    { HOME: "relative", PATH: "/usr/bin" },
    { HOME: "/Users/test", PATH: "/usr/bin", KUBECONFIG: "/ambient" },
    { HOME: "/Users/test", PATH: "/usr/bin", DOCKER_HOST: "tcp://remote" },
    { HOME: "/Users/test", PATH: "/usr/bin", AWS_PROFILE: "real" },
    { HOME: "/Users/test", PATH: "/usr/bin", HTTP_PROXY: "http://proxy.invalid" },
  ]) assert.throws(() => buildChildEnvironment(environment, owned), { name: "Failure" });
});

test("binds the complete immutable image identity and rejects drift", () => {
  const product = PRODUCTS[0];
  const document = imageDocument(product);
  const identity = validateImageInspection(document, product, marker, "linux/arm64");
  assert.deepEqual(identity, {
    architecture: "arm64",
    id: `sha256:${"a".repeat(64)}`,
    reference: product.image,
  });

  const mutations = [
    (value) => { value.push(structuredClone(value[0])); },
    (value) => { value[0].Id = "sha256:short"; },
    (value) => { value[0].RepoTags = ["zasp-local/agentsec-api:other"]; },
    (value) => { value[0].Config.User = "0"; },
    (value) => { value[0].Config.Entrypoint = ["/bin/sh"]; },
    (value) => { value[0].Config.Env = ["AWS_ACCESS_KEY_ID=seeded"]; },
    (value) => { value[0].Config.Labels["zasp.dev/run"] = "fedcba9876543210"; },
    (value) => { value[0].Config.Labels.extra = "value"; },
    (value) => { value[0].Config.ExposedPorts["80/tcp"] = {}; },
    (value) => { value[0].RootFS.Layers.push(`sha256:${"d".repeat(64)}`); },
    (value) => { value[0].Architecture = "amd64"; },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(document);
    mutate(value);
    assert.throws(() => validateImageInspection(value, product, marker, "linux/arm64"), { name: "Failure" });
  }
});

test("classifies only genuine mutation uncertainty as reconcilable", () => {
  assert.equal(classifyMutationResult({ status: 0, signal: null, stderr: "", stdout: "" }), "applied");
  for (const result of [
    { status: null, signal: "SIGKILL", stderr: "", stdout: "" },
    { status: 0, signal: null, stderr: "", stdout: "unexpected" },
    { status: null, signal: null, stderr: "", stdout: "", thrown: true },
    { status: null, signal: null, stderr: "", stdout: "", timedOut: true },
  ]) assert.equal(classifyMutationResult(result), "ambiguous");
  for (const result of [
    { status: 1, signal: null, stderr: "rejected", stdout: "" },
    { status: 125, signal: null, stderr: "rejected", stdout: "" },
  ]) assert.equal(classifyMutationResult(result), "definitive");
});

test("bounds combined process output and reaps successful children", async () => {
  const child = fakeChild((value) => {
    value.stdout.end("ready\n");
    value.stderr.end();
    value.emit("close", 0, null);
  });
  const result = await runBounded("fixture", ["ok"], {
    environment: { PATH: "/usr/bin" },
    outputLimit: 16,
    timeoutMilliseconds: 100,
  }, () => child);
  assert.deepEqual(result, {
    signal: null,
    status: 0,
    stderr: "",
    stdout: "ready\n",
    thrown: false,
    timedOut: false,
  });
  assert.deepEqual(child.killedWith, []);
});

test("kills and reaps timed-out, overflowing, and pipe-error children", async (context) => {
  await context.test("timeout", async () => {
    const child = fakeChild(() => {});
    const pending = runBounded("fixture", [], {
      environment: { PATH: "/usr/bin" }, outputLimit: 16, timeoutMilliseconds: 10,
    }, () => child);
    setTimeout(() => child.emit("close", null, "SIGKILL"), 20);
    const result = await pending;
    assert.equal(result.timedOut, true);
    assert.deepEqual(child.killedWith, ["SIGKILL"]);
  });

  await context.test("combined output", async () => {
    const child = fakeChild((value) => {
      value.stdout.write("123456789");
      value.stderr.write("abcdefghi");
      value.emit("close", null, "SIGKILL");
    });
    const result = await runBounded("fixture", [], {
      environment: { PATH: "/usr/bin" }, outputLimit: 16, timeoutMilliseconds: 100,
    }, () => child);
    assert.equal(result.status, null);
    assert.deepEqual(child.killedWith, ["SIGKILL"]);
  });

  await context.test("pipe error", async () => {
    const child = fakeChild((value) => {
      value.stdout.emit("error", new Error("pipe"));
      value.emit("close", null, "SIGKILL");
    });
    const result = await runBounded("fixture", [], {
      environment: { PATH: "/usr/bin" }, outputLimit: 16, timeoutMilliseconds: 100,
    }, () => child);
    assert.equal(result.thrown, true);
    assert.deepEqual(child.killedWith, ["SIGKILL"]);
  });
});

test("uses fixed failure categories without retaining provider text", () => {
  assert.equal(new Failure("build", "provider token abc").category, "build");
  assert.equal(new Failure("unknown", "provider token abc").category, "operation");
  assert.equal(String(new Failure("ownership", "provider token abc")), "Failure: provider token abc");
});
