import assert from "node:assert/strict";
import { test } from "node:test";

import {
  LOCALSTACK_IMAGE_PLAN,
  buildLocalStackImagePlan,
} from "./aws-emulator-image.mjs";
import {
  AWS_EMULATOR_FAILURE_CATEGORIES,
  AWS_EMULATOR_SUCCESS_LINE,
  AwsEmulatorFailure,
  DockerKindAwsEmulatorRuntime,
  LocalAwsEmulatorSystem,
  awsEmulatorApplyPlan,
  buildAwsEmulatorProfile,
  runAwsEmulatorMain,
  validateLocalStackImageIndex,
  validateLocalStackImageInspection,
  validateLocalStackImageManifest,
} from "./aws-emulator-run.mjs";
import { buildAwsEmulatorCoreResources, buildAwsEmulatorS3Resources, renderAwsEmulatorCoreManifest, renderAwsEmulatorS3Manifest } from "./aws-emulator-manifest.mjs";
import { buildGraphResources, renderGraphManifest } from "./graph-manifest.mjs";
import { isObservabilityProviderRead, projectGraphProviderResources } from "./graph-run.mjs";
import { buildObservabilityCoreResources, buildObservabilitySpanResources, renderObservabilityCoreManifest, renderObservabilitySpanManifest } from "./observability-manifest.mjs";
import { buildObservabilityProfile, observabilityApplyPlan } from "./observability-run.mjs";
import { LocalProductSystem } from "./run.mjs";

const image = "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c";
const armManifestDigest = "sha256:af47acfe2ed73a4984f73709b9f655ca255add4aa847dcbf3010301478890bb6";
const armConfigDigest = "sha256:ad4f76a02108f52479a33bbe0de40690d63ef51713971731f21f1de1e4eedb85";

function input() {
  return {
    home: "/safe/home",
    hostPlatform: "darwin/arm64",
    marker: "0123456789abcdef",
    nodePlatform: "linux/arm64",
    path: "/usr/bin:/bin",
    repositoryRoot: "/safe/repository",
  };
}

function successfulRuntime(overrides = {}) {
  const result = {
    cleanup: true,
    graph: { internal: true, persistent: true, ready: true },
    internal: true,
    observability: { internal: true, noEgress: true, ready: true, sink: true, spans: 1 },
    pods: 4,
    ready: 4,
    services: 4,
    awsEmulator: { endpoint: true, internal: true, ready: true, s3: true },
  };
  return {
    async initialize() {},
    async preflight() {},
    async buildImages() {},
    async createNetwork() {},
    async createCluster() {},
    async loadImages() {},
    async applyManifests() {},
    async verifyReadiness() { return structuredClone(result); },
    async joinMutations() {},
    async cleanup() {},
    async auditAbsence() {},
    ...overrides,
  };
}

test("pins one exact LocalStack image plan for each supported node platform", () => {
  assert.deepEqual(LOCALSTACK_IMAGE_PLAN, {
    indexDigest: "sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c",
    name: "localstack",
    platforms: {
      "linux/amd64": {
        configDigest: "sha256:9a201a5321f1519005b3a745e393c6c08d3d73d0163c4a78615eb4e0ac46c1f5",
        manifestDigest: "sha256:67739ef77133396bc952cee9140fe40ce8301a3d8036078a7709ea000e791a25",
      },
      "linux/arm64": { configDigest: armConfigDigest, manifestDigest: armManifestDigest },
    },
    reference: image,
    repository: "localstack/localstack",
  });
  assert.deepEqual(buildLocalStackImagePlan("linux/arm64"), {
    architecture: "arm64",
    configDigest: armConfigDigest,
    indexDigest: "sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c",
    manifestDigest: armManifestDigest,
    name: "localstack",
    platform: "linux/arm64",
    providerReference: "docker.io/localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c",
    reference: image,
    repoDigest: "localstack/localstack@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c",
    repository: "localstack/localstack",
    selectedReference: `localstack/localstack@${armManifestDigest}`,
    tag: "localstack/localstack:4.7.0",
  });
  assert.throws(() => buildLocalStackImagePlan("linux/s390x"), TypeError);
  assert.throws(() => buildLocalStackImagePlan(), TypeError);
  assert.throws(() => buildLocalStackImagePlan("linux/arm64", "extra"), TypeError);
});

test("composes only the exact reviewed M1-30d profile and staged apply plan", () => {
  const profile = buildAwsEmulatorProfile();
  assert.deepEqual(profile, {
    manifests: [
      { bytes: renderGraphManifest(buildGraphResources()), name: "graph.yaml", pathKey: "graphManifest" },
      { bytes: renderObservabilityCoreManifest(buildObservabilityCoreResources()), name: "observability.yaml", pathKey: "observabilityCoreManifest" },
      { bytes: renderObservabilitySpanManifest(buildObservabilitySpanResources()), name: "observability-span.yaml", pathKey: "observabilitySpanManifest" },
      { bytes: renderAwsEmulatorCoreManifest(buildAwsEmulatorCoreResources()), name: "aws-emulator.yaml", pathKey: "awsEmulatorCoreManifest" },
      { bytes: renderAwsEmulatorS3Manifest(buildAwsEmulatorS3Resources()), name: "aws-emulator-s3.yaml", pathKey: "awsEmulatorS3Manifest" },
    ],
    proof: "m1-30d",
  });
  assert.deepEqual(awsEmulatorApplyPlan(), {
    base: ["graphManifest", "observabilityCoreManifest", "awsEmulatorCoreManifest"],
    staged: ["observabilitySpanManifest", "awsEmulatorS3Manifest"],
  });
  assert.deepEqual(observabilityApplyPlan(), {
    base: ["graphManifest", "observabilityCoreManifest"],
    staged: ["observabilitySpanManifest"],
  });
  assert.equal(buildObservabilityProfile().proof, "m1-30c");
  assert.throws(() => buildAwsEmulatorProfile("input"), TypeError);
  assert.throws(() => awsEmulatorApplyPlan({}), TypeError);
});

test("rejects M1-30d manifest accessors and byte, order, name, path, or proof drift", () => {
  const profile = structuredClone(buildAwsEmulatorProfile());
  assert.doesNotThrow(() => new LocalProductSystem(input(), undefined, profile));
  const mutations = [
    (value) => { value.proof = "m1-30c"; },
    (value) => { value.manifests.reverse(); },
    (value) => { value.manifests[3].bytes += "# drift\n"; },
    (value) => { value.manifests[3].name = "aws.yaml"; },
    (value) => { value.manifests[3].pathKey = "manifest"; },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(profile);
    mutate(value);
    assert.throws(() => new LocalProductSystem(input(), undefined, value), TypeError);
  }
  const accessor = structuredClone(profile);
  let reads = 0;
  Object.defineProperty(accessor.manifests[3], "bytes", { enumerable: true, get() { reads += 1; return profile.manifests[3].bytes; } });
  assert.throws(() => new LocalProductSystem(input(), undefined, accessor), TypeError);
  assert.equal(reads, 0);
});

test("keeps AWS objects out of inherited product, graph, and observability projections", () => {
  const resources = [
    { metadata: { labels: { "app.kubernetes.io/component": "graph", "kubernetes.io/service-name": "neo4j" } } },
    { metadata: { labels: { "app.kubernetes.io/component": "observability", "kubernetes.io/service-name": "otel-collector" } } },
    { metadata: { labels: { "app.kubernetes.io/component": "aws-emulator", "kubernetes.io/service-name": "localstack" } } },
  ];
  assert.deepEqual(projectGraphProviderResources(resources, "deployments", "m1-30d"), [resources[0]]);
  assert.deepEqual(projectGraphProviderResources(resources, "endpointSlices", "m1-30d"), [resources[0]]);
  assert.deepEqual(projectGraphProviderResources(resources, "deployments", "m1-30c"), [resources[0], resources[2]]);
  assert.equal(isObservabilityProviderRead([
    "get", "deployment", "--namespace", "zasp-local",
    "--selector=app.kubernetes.io/component=observability", "--output=json",
  ], "m1-30d"), true);
  assert.equal(isObservabilityProviderRead([
    "get", "deployment", "--namespace", "zasp-local",
    "--selector=app.kubernetes.io/component=aws-emulator", "--output=json",
  ], "m1-30d"), false);
  assert.throws(() => projectGraphProviderResources(resources, "deployments", "m1-30e"), { category: "readiness" });
});

test("applies only product, graph, observability core, and AWS core before both staged Jobs", async () => {
  class RecordingSystem extends LocalAwsEmulatorSystem {
    constructor() {
      super(input());
      this.inputs = [];
      this.paths = Object.freeze({
        awsEmulatorCoreManifest: "/safe/runtime/aws-emulator.yaml",
        awsEmulatorS3Manifest: "/safe/runtime/aws-emulator-s3.yaml",
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
        ["awsEmulatorCoreManifest", this.paths.awsEmulatorCoreManifest],
        ["awsEmulatorS3Manifest", this.paths.awsEmulatorS3Manifest],
      ]);
    }
    async requireTemporaryOwnership() {}
    async verifyCluster() {}
    async requireOwnedPath() {}
    async verifyAdditionalManifestState() {}
    async withOwnedFiles(paths, _phase, _category, callback) {
      return await callback(paths.map((path, index) => ({
        handle: { fd: index + 3 }, identity: { bytes: Buffer.from(path, "utf8") },
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
    "/safe/runtime/aws-emulator.yaml",
  ]);
  assert.deepEqual([...system.additionalManifestPaths.keys()], [
    "graphManifest", "observabilityCoreManifest", "awsEmulatorCoreManifest",
    "observabilitySpanManifest", "awsEmulatorS3Manifest",
  ]);
  assert.equal(system.observabilityCoreMayHaveApplied, true);
});

test("re-proves each AWS descriptor through inherited graph and observability authority", async () => {
  class GuardedSystem extends LocalAwsEmulatorSystem {
    constructor() {
      super(input());
      this.paths = Object.freeze({
        awsEmulatorCoreManifest: "/safe/runtime/aws-emulator.yaml",
        awsEmulatorS3Manifest: "/safe/runtime/aws-emulator-s3.yaml",
        graphManifest: "/safe/runtime/graph.yaml",
        observabilityCoreManifest: "/safe/runtime/observability.yaml",
        observabilitySpanManifest: "/safe/runtime/observability-span.yaml",
      });
      this.graphNodeIdentity = Object.freeze({ token: "a".repeat(64) });
      this.graphPathIdentity = Object.freeze({ nodeToken: "a".repeat(64) });
      this.graphNodeImageInventory = "inventory\n";
      this.checked = [];
    }
    async requireTemporaryOwnership() {}
    async verifyCluster() { return { token: "a".repeat(64) }; }
    async readGraphNodeLabel() { return this.graphNodeIdentity; }
    async readGraphNodePath() { return this.graphPathIdentity; }
    async runNodeRead() { return { stderr: "", stdout: this.graphNodeImageInventory }; }
    async requireOwnedPath(path) { this.checked.push(path); }
  }
  const system = new GuardedSystem();
  await system.verifyAdditionalManifestState({ assertActive() {} }, system.paths.awsEmulatorCoreManifest);
  assert.deepEqual(system.checked, [
    system.paths.graphManifest, system.paths.observabilityCoreManifest, system.paths.awsEmulatorCoreManifest,
  ]);
  system.checked = [];
  await system.verifyAdditionalManifestState({ assertActive() {} }, system.paths.awsEmulatorS3Manifest);
  assert.deepEqual(system.checked, [
    system.paths.graphManifest, system.paths.observabilityCoreManifest, system.paths.awsEmulatorS3Manifest,
  ]);
  await assert.rejects(
    () => system.verifyAdditionalManifestState({ assertActive() {} }, "/safe/runtime/foreign.yaml"),
    { category: "ownership" },
  );
});

test("validates the exact LocalStack index and selected platform manifest", () => {
  const selected = buildLocalStackImagePlan("linux/arm64");
  const index = {
    manifests: [
      { digest: "sha256:67739ef77133396bc952cee9140fe40ce8301a3d8036078a7709ea000e791a25", mediaType: "application/vnd.docker.distribution.manifest.v2+json", platform: { architecture: "amd64", os: "linux" }, size: 5342 },
      { digest: armManifestDigest, mediaType: "application/vnd.docker.distribution.manifest.v2+json", platform: { architecture: "arm64", os: "linux" }, size: 5342 },
    ],
    mediaType: "application/vnd.docker.distribution.manifest.list.v2+json",
    schemaVersion: 2,
  };
  const retainedIndex = validateLocalStackImageIndex(index, selected);
  assert.equal(retainedIndex.selected.digest, armManifestDigest);
  assert.equal(retainedIndex.manifests.length, 2);
  for (const mutate of [
    (value) => { value.schemaVersion = 1; },
    (value) => { value.manifests[1].digest = value.manifests[0].digest; },
    (value) => { value.manifests[1].platform.architecture = "amd64"; },
    (value) => { value.manifests.push(value.manifests[1]); },
  ]) {
    const value = structuredClone(index);
    mutate(value);
    assert.throws(() => validateLocalStackImageIndex(value, selected), AwsEmulatorFailure);
  }

  const manifest = armManifest();
  const retainedManifest = validateLocalStackImageManifest(manifest, selected);
  assert.equal(retainedManifest.config.digest, armConfigDigest);
  assert.equal(retainedManifest.layers.length, 24);
  for (const mutate of [
    (value) => { value.config.digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; },
    (value) => { value.layers[0].size += 1; },
    (value) => { value.layers.reverse(); },
    (value) => { value.layers.push(value.layers[0]); },
  ]) {
    const value = structuredClone(manifest);
    mutate(value);
    assert.throws(() => validateLocalStackImageManifest(value, selected), AwsEmulatorFailure);
  }
});

test("binds the complete LocalStack runtime metadata and rejects every drift", () => {
  const selected = buildLocalStackImagePlan("linux/arm64");
  const resolution = {
    index: validateLocalStackImageIndex(localStackIndex(), selected),
    manifest: validateLocalStackImageManifest(armManifest(), selected),
  };
  const inspection = armInspection();
  const retained = validateLocalStackImageInspection(inspection, selected, resolution, undefined, {
    repoDigests: [selected.repoDigest], repoTags: [selected.tag],
  });
  assert.equal(retained.id, armConfigDigest);
  assert.equal(retained.environment.length, 10);
  assert.equal(Object.keys(retained.exposedPorts).length, 52);
  assert.deepEqual(retained.intrinsicVolumes, { "/var/lib/localstack": {} });
  assert.equal(retained.rootfs.Layers.length, 24);
  assert.deepEqual(validateLocalStackImageInspection(inspection, selected, resolution, retained, {
    repoDigests: [selected.repoDigest], repoTags: [selected.tag],
  }), retained);
  for (const mutate of [
    (value) => { value.environment[0] += ":/forged"; },
    (value) => { value.entrypoint = null; },
    (value) => { value.exposedPorts["9999/tcp"] = {}; },
    (value) => { value.intrinsicVolumes = null; },
    (value) => { value.labels.description = "forged"; },
    (value) => { value.rootfs.Layers.reverse(); },
    (value) => { value.workingDirectory = "/tmp"; },
  ]) {
    const value = structuredClone(inspection);
    mutate(value);
    assert.throws(() => validateLocalStackImageInspection(value, selected, resolution), AwsEmulatorFailure);
  }
});

test("uses the exact immutable manifest and complete Docker inspection boundaries", async () => {
  const selected = buildLocalStackImagePlan("linux/arm64");
  const inspection = armInspection();
  const values = [
    inspection.architecture, inspection.operatingSystem, inspection.id, inspection.repoDigests,
    inspection.repoTags, inspection.rootfs, inspection.environment, inspection.entrypoint,
    inspection.command, inspection.exposedPorts, inspection.intrinsicVolumes, inspection.labels,
    inspection.user, inspection.workingDirectory,
  ];
  const calls = [];
  class ImageBoundarySystem extends LocalAwsEmulatorSystem {
    async runRead(command, arguments_) {
      calls.push([command, arguments_]);
      if (arguments_[0] === "manifest" && arguments_[2] === selected.reference) {
        return { stdout: JSON.stringify(localStackIndex()) };
      }
      if (arguments_[0] === "manifest" && arguments_[2] === selected.selectedReference) {
        return { stdout: JSON.stringify(armManifest()) };
      }
      if (arguments_[0] === "image") return { stdout: JSON.stringify(values) };
      throw new Error("unexpected read boundary");
    }
  }
  const system = new ImageBoundarySystem(input());
  const phase = { assertActive() {} };
  const resolution = await system.resolveGraphImage(selected, phase);
  const retained = await system.inspectGraphImage(
    selected, resolution, phase, undefined, selected.reference, "ownership",
    { repoDigests: [selected.repoDigest], repoTags: [selected.tag] },
  );
  assert.equal(retained.id, armConfigDigest);
  assert.deepEqual(calls.map(([command, arguments_]) => [command, arguments_.slice(0, 3)]), [
    ["docker", ["manifest", "inspect", selected.reference]],
    ["docker", ["manifest", "inspect", selected.selectedReference]],
    ["docker", ["image", "inspect", "--format"]],
  ]);
});

test("admits and preserves every exact shared image baseline without mutation", async () => {
  const calls = [];
  class SharedBaselineSystem extends LocalAwsEmulatorSystem {
    constructor() {
      super(input());
      this.paths = { graphManifest: "/safe/runtime/graph.yaml" };
    }
    async admitGraphGoTool() {}
    async requireTemporaryOwnership() {}
    async requireOwnedPath() {}
    async resolveGraphImage(selected) {
      calls.push(["resolve", selected.name]);
      return { index: { indexDigest: selected.indexDigest }, manifest: { config: { digest: selected.configDigest } } };
    }
    async readGraphImageBaseline(selected, _resolution, _phase, _category, retained) {
      calls.push(["baseline", selected.name]);
      const value = {
        aliases: { repoDigests: [selected.repoDigest], repoTags: [selected.tag] },
        consumers: [],
        identity: { id: selected.configDigest },
        listedIds: [selected.configDigest],
      };
      if (retained !== undefined) assert.deepEqual(retained, value);
      return value;
    }
    async runMutation() { throw new Error("shared image must not mutate"); }
  }
  const system = new SharedBaselineSystem();
  const phase = { assertActive() {} };
  await system.runAdditionalPreflightChecks(phase);
  assert.deepEqual(calls.filter(([kind]) => kind === "resolve").map(([, name]) => name), [
    "neo4j", "busybox", "collector", "localstack",
  ]);
  await system.buildAdditionalImages(phase);
  assert.deepEqual([...system.graphImageIdentities.keys()], ["neo4j", "busybox", "collector", "localstack"]);
  const cleanupOrder = [];
  await system.cleanupAdditionalImages(async (operation) => {
    await operation();
    cleanupOrder.push("step");
  }, phase);
  assert.equal(cleanupOrder.length, 4);
  assert.equal(system.graphImageIdentities.size, 0);
  assert.equal(system.graphImageAliases.size, 0);
  await system.requireAdditionalGlobalAbsence(phase, "cleanup");
  assert.equal(system.graphSharedImageBaselines.size, 0);
  assert.equal(system.graphImageResolutions.size, 0);
});

test("constructs only an exact AWS runtime profile and emits fixed success or failure", async () => {
  const system = new LocalAwsEmulatorSystem(input());
  assert.equal(system.profile.proof, "m1-30d");
  assert.deepEqual([...system.graphImagePlans.keys()], ["neo4j", "busybox", "collector", "localstack"]);
  assert.doesNotThrow(() => new DockerKindAwsEmulatorRuntime(input(), system));
  const forged = Object.create(system);
  Object.defineProperty(forged, "profile", { enumerable: true, value: buildObservabilityProfile() });
  assert.throws(() => new DockerKindAwsEmulatorRuntime(input(), forged), TypeError);

  let stdout = "";
  let stderr = "";
  let exitCode;
  assert.equal(await runAwsEmulatorMain(successfulRuntime(), {
    stdout: { write(value) { stdout += value; } },
    stderr: { write(value) { stderr += value; } },
    setExitCode(value) { exitCode = value; },
  }), 0);
  assert.equal(stdout, `${AWS_EMULATOR_SUCCESS_LINE}\n`);
  assert.equal(stderr, "");
  assert.equal(exitCode, 0);

  stdout = "";
  stderr = "";
  assert.equal(await runAwsEmulatorMain(successfulRuntime({ async buildImages() { throw new AwsEmulatorFailure("provider"); } }), {
    stdout: { write(value) { stdout += value; } },
    stderr: { write(value) { stderr += value; } },
    setExitCode() {},
  }), 1);
  assert.equal(stdout, "");
  assert.equal(stderr, "Local AWS emulator manifest failed: provider rejected.\n");
  assert.equal(new AwsEmulatorFailure("forged").category, "panic");
  assert.deepEqual(AWS_EMULATOR_FAILURE_CATEGORIES, ["build", "cleanup", "configuration", "deadline", "normalization", "ownership", "panic", "provider", "readiness"]);
});

function localStackIndex() {
  return {
    schemaVersion: 2,
    mediaType: "application/vnd.docker.distribution.manifest.list.v2+json",
    manifests: [
      { digest: "sha256:67739ef77133396bc952cee9140fe40ce8301a3d8036078a7709ea000e791a25", mediaType: "application/vnd.docker.distribution.manifest.v2+json", platform: { architecture: "amd64", os: "linux" }, size: 5342 },
      { digest: armManifestDigest, mediaType: "application/vnd.docker.distribution.manifest.v2+json", platform: { architecture: "arm64", os: "linux" }, size: 5342 },
    ],
  };
}

function armManifest() {
  const layers = [
    ["c046a38e34226ab0cae005551802ddc0e5c18a02fb42820f76003b3c527362eb",29180468],["27b1542b92578c5ae2fdd86937dbb3ff246ba74c2666b93d03369b030c2f6128",3337701],["23635a31452efc16982ee0c8dd50d46aa2445221f14cb157dfed8a387cce2ee6",16136798],["65bfefa96d6c8b1d434afa24988e3c8cf866f389a0920e43deb11aa26ff139d5",250],["71bfe837c38a481964c5dfa5ea2c40aa70dae438b362a903ee3fd451ea3c8e5e",77574345],["52f21b0b71be5b707bb588deebee02695b17fd32020d6ad60c72abdc90639ef5",54484795],["9ce6374220cb2f546376bc3d6973ee70fdf74629167240a1ec419f4bfc7c4fea",135],["af5f2f6fee615513619b2f97371aefd786972cfb6c63ee64f70d4d7e48e791d2",158],["4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1",32],["7799317606dc6f5a8991b53b1d332555cd29a327a12c18d0740069bf37abe2d4",3514],["c264381852da2268dfbaa310a781e979f2fb39561f3c2d996fc80f92476af175",902],["86d7ae0b49ce9778ca91b8bd1743adff2d835a14c0d078bdea6e2db99df03b42",249],["f071571c5fe3c7a1dce8059531a9b06287f077687e0f515b7f3910f863dd676c",26707461],["6f70d65ce515f4845232a96545c40d7e436c735fe56d0b7145fb9f3838ae4ae2",131716332],["af620d5826f23f3189975ee0c53d1b63a4b7021fb071cbce5f0a6046344cd9b6",7134],["0ddaef28eba3ec86511cdc288902be6ea876ca8af0c2de4aead3cf8ec1c270c0",2758],["c1343b1e1a2354024464644a0c45869d20ff0d1edd388a05d83e2c2fb1ab61b1",3408776],["be8b0eb944715c83d0e054b9446376b006cf5109835d5c10161bb322efc733ee",99359],["fa32476481367ea212c3091cd4f8a47e4f544d23cf52bb10e74e5cefef4bb335",5142757],["fae1e764c0d2673b998745776345b4a800325e632fe90fc2f5cbee7af420c8a5",127783],["ec73a34e5c88a08e65b10cdb25cb929608d6c2cd5e4d312676a2e0d16003f405",149062606],["bbcacd23a6b7d065d0fd56e1c3e5acd6c5172ec59c0d78d69c18233ea458f194",300],["4685c2a135576c299da17c6e9a22ab0cd4ac2e4279152c483612491744059c2b",299],["3272e171b270afc523e08b68161a8708e331aadab0c3daedb3e6f72ffdd93ca2",196],
  ].map(([digest, size]) => ({ digest: `sha256:${digest}`, mediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", size }));
  return { config: { digest: armConfigDigest, mediaType: "application/vnd.docker.container.image.v1+json", size: 27144 }, layers, mediaType: "application/vnd.docker.distribution.manifest.v2+json", schemaVersion: 2 };
}

function armInspection() {
  const exposedPorts = Object.fromEntries([...Array(50)].map((_, index) => [`${4510 + index}/tcp`, {}]));
  exposedPorts["4566/tcp"] = {};
  exposedPorts["5678/tcp"] = {};
  return {
    architecture: "arm64",
    command: null,
    entrypoint: ["docker-entrypoint.sh"],
    environment: ["PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","LANG=C.UTF-8","GPG_KEY=" + "A035C8C19219BA821ECEA86B64E628F8D684696D","PYTHON_VERSION=3.11.13","PYTHON_SHA256=8fb5f9fbc7609fa822cb31549884575db7fd9657cbffb89510b5d7975963a83a","USER=localstack","PYTHONUNBUFFERED=1","LOCALSTACK_BUILD_DATE=2025-07-31","LOCALSTACK_BUILD_GIT_HASH=82de91e30","LOCALSTACK_BUILD_VERSION=4.7.0"],
    exposedPorts,
    id: armConfigDigest,
    intrinsicVolumes: { "/var/lib/localstack": {} },
    labels: { authors: "LocalStack Contributors", description: "LocalStack Docker image", maintainer: "LocalStack Team (info@localstack.cloud)" },
    operatingSystem: "linux",
    repoDigests: ["localstack/localstack@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c"],
    repoTags: ["localstack/localstack:4.7.0"],
    rootfs: { Layers: ["sha256:dd97e58b4e812b247f3cd261fa7eac247b7c5896b8e34d9474762678cae7774d","sha256:e26286284f6ea22d800d847e7f0ccee9e39591de19270b17eec80289a6270c32","sha256:e9890cd72d1ba8ed4f2561f0a5bf8dcefdda006995f19d3c8440d76f35926cbf","sha256:c98a5e0a8fe7c817f5d1c8a66a8dab61f9d3078f6fb41139c24ce740dd16f62e","sha256:2c76fbccc2935724c3e84fc052b1148647bc36a42eb2369f19b2c5f39bf6dc1f","sha256:7e369ff650827f0c72650bcc5b389d3de1a5ed8c7d060103c37ae85b1960122c","sha256:74a3636105f24bf45639008f5a89c54891af9f9f6f54c009832635a8c6876b37","sha256:e542b6dea3e3aa65b52a788c7f37de76897565cfb524e9a6f0d14c8346834c2a","sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef","sha256:b0e2843524ab5d895251195da51e546d01d9c1773de9e8cccbcb89a7138eab85","sha256:88ee7e0947a470db0265f3bf6662b67c5fc355e6c6a8bf8b5f4059b3695840f8","sha256:439dfba5c7364008079ba52d5219e684caef5568f3a1bf01ece2bbea8d290110","sha256:0e2f66df6cc4ef1eba496407f6cf1b11205e29180d8f962d97d1b77f559dc30d","sha256:1c88bb3882c0289b43df9c7c494ffa3421371990c76a6c72c3384182a61f187d","sha256:296c1ff4085bb574b3fd1ebfa8b241b39e09aa42951f45a439182d4ba59c1b19","sha256:c7a5647fe1ea9d79d1b37c831530c6ed74ba10c60b28fbb3737508fc2e31239a","sha256:845b205b19f1db0d6aa84e66b39ca749a3bf5b02dea3f29a757665578b2606fe","sha256:860087e788694bbd0ecc2867ebc966180ad2386dea8e8a8227c724b9e7dce81b","sha256:0d7927c65099db2e28535a92810316146f02ecd0af0ab5b19851ed5594c66f08","sha256:09a2092ac95780b82c83349ae1a2137ed07f3d5c3d84718be02611eb6c32288f","sha256:23cb31207131721c9e5aacfe417150a9bfc772ebbf949bbd08ed598ac8de50db","sha256:22e218564ab1271874027666aeb047b2a7f6865517c21b45c349c035a74b29fa","sha256:3380a402b706b97495aff0e64a49a60b3d8394528073e426b224d7e724cdf235","sha256:1cb669a6e999056fa3dbaa70318b2193cd2130523097e4a5bedda740288b5e3a"], Type: "layers" },
    user: "",
    workingDirectory: "/opt/code/localstack/",
  };
}
