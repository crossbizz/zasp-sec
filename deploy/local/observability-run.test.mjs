import assert from "node:assert/strict";
import { test } from "node:test";

import { buildKindConfig, buildKindCreateArguments } from "./run.mjs";
import { LocalGraphSystem } from "./graph-run.mjs";
import {
  OBSERVABILITY_FAILURE_CATEGORIES,
  OBSERVABILITY_SUCCESS_LINE,
  DockerKindObservabilityRuntime,
  LocalObservabilitySystem,
  ObservabilityFailure,
  buildCollectorImagePlan,
  buildObservabilityProfile,
  observabilityApplyPlan,
  runObservabilityMain,
  validateCollectorImageIndex,
  validateCollectorImageInspection,
  validateCollectorImageManifest,
} from "./observability-run.mjs";

const input = Object.freeze({
  home: "/safe/home",
  hostPlatform: "linux/amd64",
  marker: "0123456789abcdef",
  nodePlatform: "linux/amd64",
  path: "/usr/local/bin:/usr/bin:/bin",
  repositoryRoot: "/safe/repository",
});

function clone(value) {
  return structuredClone(value);
}

function collectorInspection(selected) {
  const facts = {
    "linux/amd64": {
      created: "2026-08-04T19:23:24Z",
      layers: [
        "sha256:b5440ec587ede814b7c8ebccb96bc5487401de66da7dfe450a202aa79c111166",
        "sha256:08b8e470b260dd54255ed6bf28dd03f47054a8b3a2709a1bc739087fdc4b958f",
        "sha256:8a565f28d3634fbc7e4589e52415632f74cf4f024dfc14d8a1a54dc3fa28327d",
      ],
    },
    "linux/arm64": {
      created: "2026-08-04T19:24:29Z",
      layers: [
        "sha256:0a16b43820c80185ecd6718a21d88ee191fa0b2a782ccd7a49ccab7c3be08962",
        "sha256:f3d42a646dc2f6c9a4b776f3de3efadcd278ba3de08b60331eb37776d54aef81",
        "sha256:dd866c2bf687864ac0789f16b4e9a2aac6c845ae260a4f09dc857962dfe7bec4",
      ],
    },
  }[selected.platform];
  return [
    selected.architecture,
    "linux",
    selected.configDigest,
    [selected.repoDigest],
    [],
    { Layers: facts.layers, Type: "layers" },
    ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    ["/otelcol-contrib"],
    ["--config", "/etc/otelcol-contrib/config.yaml"],
    { "4317/tcp": {}, "4318/tcp": {}, "55679/tcp": {} },
    null,
    {
      "org.opencontainers.image.created": facts.created,
      "org.opencontainers.image.licenses": "Apache-2.0",
      "org.opencontainers.image.name": "opentelemetry-collector-releases",
      "org.opencontainers.image.revision": "1400269f8ace841f8d0492f4f9c6c7f305f95268",
      "org.opencontainers.image.source": "https://github.com/open-telemetry/opentelemetry-collector-releases",
      "org.opencontainers.image.version": "0.158.0",
    },
    "10001:10001",
    "/",
  ];
}

function resolution(selected) {
  const layers = collectorInspection(selected)[5].Layers;
  return {
    index: { indexDigest: selected.indexDigest, selected: { digest: selected.manifestDigest } },
    manifest: {
      config: { digest: selected.configDigest },
      layers: layers.map((digest, index) => ({
        digest,
        mediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
        size: index + 1,
      })),
    },
  };
}

function collectorIndexDocument() {
  return {
    manifests: [
      {
        digest: "sha256:e290476fa9a75f7a84a28798832bde7068d27825745de67bc38957e22949a64c",
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        platform: { architecture: "amd64", os: "linux" },
        size: 1,
      },
      {
        digest: "sha256:51e1afc9d762a359387723170be5cecccad2c09e73a5a2061361c62c60855ccf",
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        platform: { architecture: "arm64", os: "linux" },
        size: 1,
      },
    ],
    mediaType: "application/vnd.oci.image.index.v1+json",
    schemaVersion: 2,
  };
}

function collectorManifestDocument(selected) {
  return {
    config: {
      digest: selected.configDigest,
      mediaType: "application/vnd.oci.image.config.v1+json",
      size: 1,
    },
    layers: collectorInspection(selected)[5].Layers.map((digest, index) => ({
      digest,
      mediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
      size: index + 1,
    })),
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    schemaVersion: 2,
  };
}

function fakeLifecycle(result, overrides = {}) {
  const calls = [];
  const runtime = {};
  for (const name of ["initialize", "preflight", "buildImages", "createNetwork", "createCluster", "loadImages", "applyManifests"]) {
    runtime[name] = async () => { calls.push(name); };
  }
  runtime.verifyReadiness = async () => { calls.push("verifyReadiness"); return result; };
  runtime.joinMutations = async () => { calls.push("joinMutations"); };
  runtime.cleanup = async () => { calls.push("cleanup"); };
  runtime.auditAbsence = async () => { calls.push("auditAbsence"); };
  Object.assign(runtime, overrides);
  return { calls, runtime };
}

test("defines the exact observability profile without changing prior profiles", () => {
  assert.deepEqual(OBSERVABILITY_FAILURE_CATEGORIES, [
    "build", "cleanup", "configuration", "deadline", "normalization", "ownership", "panic", "provider", "readiness",
  ]);
  assert.equal(OBSERVABILITY_SUCCESS_LINE, "Local observability manifest passed: ready=true internal=true no_egress=true spans=1 sink=true cleanup=true.");
  assert.deepEqual(observabilityApplyPlan(), {
    base: ["graphManifest", "observabilityCoreManifest"],
    staged: ["observabilitySpanManifest"],
  });
  const profile = buildObservabilityProfile();
  assert.equal(profile.proof, "m1-30c");
  assert.deepEqual(profile.manifests.map(({ name, pathKey }) => ({ name, pathKey })), [
    { name: "graph.yaml", pathKey: "graphManifest" },
    { name: "observability.yaml", pathKey: "observabilityCoreManifest" },
    { name: "observability-span.yaml", pathKey: "observabilitySpanManifest" },
  ]);
  assert.throws(() => buildObservabilityProfile("caller-input"), TypeError);
  assert.throws(() => observabilityApplyPlan({}), TypeError);
  assert.deepEqual(buildKindConfig(), {
    apiVersion: "kind.x-k8s.io/v1alpha4",
    kind: "Cluster",
    networking: { apiServerAddress: "127.0.0.1" },
    nodes: [{ role: "control-plane" }],
  });
  assert.deepEqual(buildKindCreateArguments({
    cluster: "zasp-m1-30c-0123456789abcdef",
    config: "/safe/kind.json",
    kubeconfig: "/safe/kubeconfig",
  }, "m1-30c").slice(0, 6), ["create", "cluster", "--name", "zasp-m1-30c-0123456789abcdef", "--config", "/safe/kind.json"]);

  const graph = new LocalGraphSystem(input);
  const observability = new LocalObservabilitySystem(input);
  assert.equal(graph.profile.proof, "m1-30b");
  assert.deepEqual([...graph.graphImagePlans.keys()], ["neo4j", "busybox"]);
  assert.equal(observability.profile.proof, "m1-30c");
  assert.deepEqual([...observability.graphImagePlans.keys()], ["neo4j", "busybox", "collector"]);

  const invalidProfiles = [
    (value) => { value.manifests.reverse(); },
    (value) => { value.manifests.push(clone(value.manifests[0])); },
    (value) => { value.manifests[1].name = "alternate.yaml"; },
    (value) => { value.manifests[1].pathKey = "graphManifest"; },
    (value) => { value.manifests[2].bytes = ""; },
  ];
  for (const mutate of invalidProfiles) {
    const value = clone(profile);
    mutate(value);
    assert.throws(() => new LocalGraphSystem(input, undefined, value), TypeError);
  }
  class ForgedManifests extends Array {}
  const forged = clone(profile);
  Object.setPrototypeOf(forged.manifests, ForgedManifests.prototype);
  assert.throws(() => new LocalGraphSystem(input, undefined, forged), TypeError);
  let reads = 0;
  const accessor = clone(profile);
  const first = accessor.manifests[0];
  Object.defineProperty(accessor.manifests, "0", {
    configurable: true,
    enumerable: true,
    get() { reads += 1; return first; },
  });
  assert.throws(() => new LocalGraphSystem(input, undefined, accessor), TypeError);
  assert.equal(reads, 0);
});

test("applies only product, graph, and Collector core descriptors before the staged Job", async () => {
  class RecordingSystem extends LocalObservabilitySystem {
    constructor() {
      super(input);
      this.inputs = [];
      this.paths = Object.freeze({
        graphManifest: "/safe/runtime/graph.yaml",
        kubeconfig: "/safe/runtime/kubeconfig",
        manifest: "/safe/runtime/manifests.yaml",
        observabilityCoreManifest: "/safe/runtime/observability.yaml",
        observabilitySpanManifest: "/safe/runtime/observability-span.yaml",
      });
      this.additionalManifestPaths = new Map([
        ["graphManifest", this.paths.graphManifest],
        ["observabilityCoreManifest", this.paths.observabilityCoreManifest],
        ["observabilitySpanManifest", this.paths.observabilitySpanManifest],
      ]);
    }

    async requireTemporaryOwnership() {}
    async verifyCluster() {}
    async requireOwnedPath() {}
    async verifyAdditionalManifestState() {}
    async withOwnedFiles(paths, _phase, _category, callback) {
      return await callback(paths.map((path, index) => ({
        handle: { fd: index + 3 },
        identity: { bytes: Buffer.from(path, "utf8") },
      })));
    }
    async runMutation(_executable, _arguments, _phase, _category, options) {
      this.inputs.push(options.input.toString("utf8"));
      return { outcome: "applied" };
    }
    async runRead() { return { stderr: "", stdout: "" }; }
  }

  const system = new RecordingSystem();
  await system.applyManifests({ assertActive() {} });
  assert.deepEqual(system.inputs, [
    "/safe/runtime/manifests.yaml",
    "/safe/runtime/graph.yaml",
    "/safe/runtime/observability.yaml",
  ]);
  assert.deepEqual([...system.additionalManifestPaths], [
    ["graphManifest", "/safe/runtime/graph.yaml"],
    ["observabilityCoreManifest", "/safe/runtime/observability.yaml"],
    ["observabilitySpanManifest", "/safe/runtime/observability-span.yaml"],
  ]);
});

test("binds complete Collector index, platform, and runtime metadata", () => {
  for (const platform of ["linux/amd64", "linux/arm64"]) {
    const selected = buildCollectorImagePlan(platform);
    assert.equal(selected.name, "collector");
    assert.equal(selected.indexDigest, "sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5");
    const identity = validateCollectorImageInspection(collectorInspection(selected), selected, resolution(selected));
    assert.equal(identity.id, selected.configDigest);
    assert.deepEqual(identity.exposedPorts, ["4317/tcp", "4318/tcp", "55679/tcp"]);
    assert.deepEqual(identity.intrinsicVolumes, []);
    assert.equal(identity.user, "10001:10001");
    assert.equal(identity.workingDirectory, "/");

    const drift = collectorInspection(selected);
    drift[11]["org.opencontainers.image.revision"] = "0000000000000000000000000000000000000000";
    assert.throws(() => validateCollectorImageInspection(drift, selected, resolution(selected)), { category: "ownership" });
    const layerDrift = resolution(selected);
    layerDrift.manifest.layers[0].digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert.throws(() => validateCollectorImageInspection(
      collectorInspection(selected), selected, layerDrift,
    ), { category: "ownership" });
  }
  for (const value of ["linux/386", "darwin/arm64", undefined]) {
    assert.throws(() => buildCollectorImagePlan(value), TypeError);
  }
});

test("resolves the Collector through profile-local OCI validation without widening the graph image map", async () => {
  const selected = buildCollectorImagePlan("linux/amd64");
  const index = collectorIndexDocument();
  const manifest = collectorManifestDocument(selected);
  const validatedIndex = validateCollectorImageIndex(index, selected);
  const validatedManifest = validateCollectorImageManifest(manifest, selected);
  assert.equal(validatedIndex.selected.digest, selected.manifestDigest);
  assert.deepEqual(validatedManifest.layers.map(({ digest }) => digest), collectorInspection(selected)[5].Layers);

  class ResolvingSystem extends LocalObservabilitySystem {
    async runRead(_executable, arguments_) {
      return { stderr: "", stdout: JSON.stringify(
        arguments_.at(-1) === selected.reference ? index : manifest,
      ) };
    }
  }
  const system = new ResolvingSystem(input);
  assert.deepEqual(await system.resolveGraphImage(selected, { assertActive() {} }), {
    index: validatedIndex,
    manifest: validatedManifest,
  });

  for (const mutate of [
    (value) => { value.manifests[0].digest = `sha256:${"0".repeat(64)}`; },
    (value) => { value.manifests.push(clone(value.manifests[0])); },
    (value) => { value.manifests[0].platform.os = "windows"; },
  ]) {
    const value = clone(index);
    mutate(value);
    assert.throws(() => validateCollectorImageIndex(value, selected), { category: "normalization" });
  }
  for (const mutate of [
    (value) => { value.config.digest = `sha256:${"0".repeat(64)}`; },
    (value) => { value.layers[0].digest = `sha256:${"0".repeat(64)}`; },
    (value) => { value.layers.push(clone(value.layers[0])); },
  ]) {
    const value = clone(manifest);
    mutate(value);
    assert.throws(() => validateCollectorImageManifest(value, selected), { category: "normalization" });
  }
});

test("emits fixed success and panic-normalized failure output", async () => {
  const result = {
    graph: { internal: true, persistent: true, ready: true },
    internal: true,
    observability: { internal: true, noEgress: true, ready: true, sink: true, spans: 1 },
    pods: 4,
    ready: 4,
    services: 4,
  };
  const success = fakeLifecycle(result);
  let stdout = "";
  let stderr = "";
  let exitCode;
  assert.equal(await runObservabilityMain(success.runtime, {
    stdout: { write(value) { stdout += value; } },
    stderr: { write(value) { stderr += value; } },
    setExitCode(value) { exitCode = value; },
    mainTimeoutMilliseconds: 100,
    cleanupTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 50,
  }), 0);
  assert.equal(stdout, `${OBSERVABILITY_SUCCESS_LINE}\n`);
  assert.equal(stderr, "");
  assert.equal(exitCode, 0);
  assert.deepEqual(success.calls, [
    "initialize", "preflight", "buildImages", "createNetwork", "createCluster", "loadImages",
    "applyManifests", "verifyReadiness", "joinMutations", "cleanup", "auditAbsence",
  ]);

  const failed = fakeLifecycle(result, { async verifyReadiness() { throw { category: "forged", secret: "provider" }; } });
  stdout = "";
  stderr = "";
  assert.equal(await runObservabilityMain(failed.runtime, {
    stdout: { write(value) { stdout += value; } },
    stderr: { write(value) { stderr += value; } },
    setExitCode() {},
    mainTimeoutMilliseconds: 100,
    cleanupTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 50,
  }), 1);
  assert.equal(stdout, "");
  assert.equal(stderr, "Local observability manifest failed: panic rejected.\n");
  assert.equal(new ObservabilityFailure("forged").category, "panic");
});

test("retains the validated observability system through the Docker runtime", () => {
  const system = new LocalObservabilitySystem(input);
  const runtime = new DockerKindObservabilityRuntime(input, system);
  assert.equal(runtime.system, system);
  assert.equal(runtime.system.profile.proof, "m1-30c");
  assert.throws(() => new DockerKindObservabilityRuntime({ ...input, nodePlatform: "linux/arm64" }, system), TypeError);
});
