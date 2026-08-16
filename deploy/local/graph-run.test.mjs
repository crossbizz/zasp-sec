import assert from "node:assert/strict";
import test from "node:test";

import { PRODUCTS } from "./manifests.mjs";
import { BUSYBOX_IMAGE, GRAPH_CONSTANTS, NEO4J_IMAGE } from "./graph-manifest.mjs";
import { KIND_PINS, buildKindCreateArguments } from "./run.mjs";
import {
  GRAPH_FAILURE_CATEGORIES,
  GRAPH_IMAGE_PLANS,
  GRAPH_SUCCESS_LINE,
  DockerKindGraphRuntime,
  GraphFailure,
  LocalGraphSystem,
  buildGraphImagePlan,
  parseGraphContainerdImageTargets,
  projectGraphImageInspection,
  runGraphMain,
  validateGraphImageIndex,
  validateGraphImageInspection,
  validateGraphImageManifest,
  validateGraphNodeLabel,
  validateGraphNodePath,
} from "./graph-run.mjs";

const marker = "0123456789abcdef";
const phase = Object.freeze({ assertActive() {}, signal: new AbortController().signal });
const success = (stdout = "", stderr = "") => Object.freeze({
  signal: null, status: 0, stderr, stdout, thrown: false, timedOut: false,
});

function plan(name = "neo4j", platform = "linux/arm64") {
  return buildGraphImagePlan(name, platform);
}

function indexDocument(selected = plan()) {
  const pins = GRAPH_IMAGE_PLANS[selected.name].platforms;
  return {
    manifests: [
      {
        digest: pins["linux/amd64"].manifestDigest,
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        platform: { architecture: "amd64", os: "linux" },
        size: 2_048,
      },
      {
        digest: pins["linux/arm64"].manifestDigest,
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        platform: { architecture: "arm64", os: "linux" },
        size: 2_049,
      },
      {
        annotations: { "vnd.docker.reference.type": "attestation-manifest" },
        digest: `sha256:${"1".repeat(64)}`,
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        platform: { architecture: "unknown", os: "unknown" },
        size: 512,
      },
    ],
    mediaType: "application/vnd.oci.image.index.v1+json",
    schemaVersion: 2,
  };
}

function manifestDocument(selected = plan()) {
  return {
    config: {
      digest: selected.configDigest,
      mediaType: "application/vnd.oci.image.config.v1+json",
      size: 7_474,
    },
    layers: [
      {
        digest: `sha256:${"2".repeat(64)}`,
        mediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
        size: 12_345,
      },
      {
        digest: `sha256:${"3".repeat(64)}`,
        mediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
        size: 67_890,
      },
    ],
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    schemaVersion: 2,
  };
}

function projectedInspection(selected = plan(), overrides = {}) {
  return [
    selected.architecture,
    "linux",
    selected.configDigest,
    [selected.repoDigest],
    [selected.tag],
    { Layers: [`sha256:${"4".repeat(64)}`, `sha256:${"5".repeat(64)}`], Type: "layers" },
    [
      "PATH=/var/lib/neo4j/bin:/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "NEO4J_EDITION=community",
    ],
    ["tini", "-g", "--", "/startup/docker-entrypoint.sh"],
    ["neo4j"],
    { "7473/tcp": {}, "7474/tcp": {}, "7687/tcp": {} },
    { "/data": {}, "/logs": {} },
    { "org.opencontainers.image.title": "Neo4j" },
    "7474:7474",
    "/var/lib/neo4j",
    ...overrides.extra ?? [],
  ];
}

function resolvedImage(selected = plan()) {
  const index = validateGraphImageIndex(indexDocument(selected), selected);
  const manifest = validateGraphImageManifest(manifestDocument(selected), selected);
  return { index, manifest };
}

function graphDependencies(command = async () => success()) {
  const missing = async () => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); };
  return {
    canonicalPath: async (value) => value,
    changeMode: async () => {},
    command,
    fetchBytes: async () => Buffer.from("kind"),
    hashBytes: () => "0".repeat(64),
    makeDirectory: async () => {},
    makeTemp: async () => "/safe/tmp/zasp-m1-30b-0123456789abcdef-runtime-owned",
    movePath: async () => {},
    openPath: missing,
    readDirectory: async () => [],
    readPath: missing,
    removePath: async () => {},
    statPath: missing,
    tempParent: "/safe/tmp",
    writePath: async () => {},
  };
}

function graphSystem(command) {
  return new LocalGraphSystem({
    home: "/Users/test",
    hostPlatform: "darwin/arm64",
    marker,
    nodePlatform: "linux/arm64",
    path: "/usr/local/bin:/usr/bin:/bin",
    repositoryRoot: "/repository",
  }, graphDependencies(command));
}

function lifecycle(overrides = {}) {
  const events = [];
  const runtime = {};
  for (const name of [
    "initialize", "preflight", "buildImages", "createNetwork", "createCluster", "loadImages",
    "applyManifests", "joinMutations", "cleanup", "auditAbsence",
  ]) runtime[name] = async () => { events.push(name); };
  runtime.verifyReadiness = async () => {
    events.push("verifyReadiness");
    return {
      graph: { internal: true, persistent: true, ready: true },
      internal: true,
      pods: 4,
      ready: 4,
      services: 4,
    };
  };
  Object.assign(runtime, overrides);
  return { events, runtime };
}

test("pins both graph indexes and resolves only the exact selected node platform", () => {
  assert.deepEqual(GRAPH_IMAGE_PLANS, {
    busybox: {
      indexDigest: "sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9",
      name: "busybox",
      platforms: {
        "linux/amd64": {
          configDigest: "sha256:3e0d9138669908f438c06993e9a6815bbd8c05411b8e9acfc297b3c8b017c28c",
          manifestDigest: "sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb",
        },
        "linux/arm64": {
          configDigest: "sha256:6d0099de92b2a095017ed32499154f16eec2df38f0d2e9192bcf6ae7d241ac75",
          manifestDigest: "sha256:55c89c6d9404d6668eb237dda92f28a99eb14e640f1c177a55cc9d738c53c303",
        },
      },
      reference: BUSYBOX_IMAGE,
      repository: "registry.k8s.io/e2e-test-images/busybox",
    },
    neo4j: {
      indexDigest: "sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357",
      name: "neo4j",
      platforms: {
        "linux/amd64": {
          configDigest: "sha256:534fe13ef23432459f04f65e1fa4c25876bb981f147d96b1b3896278d23e7552",
          manifestDigest: "sha256:77a7a788aa3348c66a4c12a07930bc12232f22535b0e1a2a043df80bbfa823bd",
        },
        "linux/arm64": {
          configDigest: "sha256:db03e618d0cd04bbabeb4bf5296c91108f4be5185456565bb4046a33b226fcd2",
          manifestDigest: "sha256:5bed6b3adb938c45722e3639b853ecbc948b2e51cd5599d45fcd23f6d49b2d89",
        },
      },
      reference: NEO4J_IMAGE,
      repository: "neo4j",
    },
  });
  assert.deepEqual(plan(), {
    architecture: "arm64",
    configDigest: GRAPH_IMAGE_PLANS.neo4j.platforms["linux/arm64"].configDigest,
    indexDigest: GRAPH_IMAGE_PLANS.neo4j.indexDigest,
    manifestDigest: GRAPH_IMAGE_PLANS.neo4j.platforms["linux/arm64"].manifestDigest,
    name: "neo4j",
    platform: "linux/arm64",
    providerReference: `docker.io/library/${NEO4J_IMAGE}`,
    reference: NEO4J_IMAGE,
    repoDigest: `neo4j@${GRAPH_IMAGE_PLANS.neo4j.indexDigest}`,
    repository: "neo4j",
    selectedReference: `neo4j@${GRAPH_IMAGE_PLANS.neo4j.platforms["linux/arm64"].manifestDigest}`,
    tag: NEO4J_IMAGE.split("@")[0],
  });
  for (const [name, platform] of [["other", "linux/arm64"], ["neo4j", "darwin/arm64"], ["neo4j", "linux/s390x"]]) {
    assert.throws(() => buildGraphImagePlan(name, platform), { name: "TypeError" });
  }
});

test("constructs only the fixed M1-30b process profile without ambient authority", () => {
  const runtime = DockerKindGraphRuntime.fromProcess({
    HOME: "/Users/test",
    LANG: "C.UTF-8",
    PATH: "/usr/local/bin:/usr/bin:/bin",
  });
  assert.ok(runtime instanceof DockerKindGraphRuntime);
  assert.equal(runtime.system.profile.proof, "m1-30b");
  assert.deepEqual(runtime.system.profile.manifests.map(({ name, pathKey }) => ({ name, pathKey })), [
    { name: "graph.yaml", pathKey: "graphManifest" },
  ]);
  assert.equal(runtime.system.cluster, `zasp-m1-30b-${runtime.input.marker}`);
  assert.deepEqual(buildKindCreateArguments({
    cluster: `zasp-m1-30b-${marker}`,
    config: "/owned/kind.json",
    kubeconfig: "/owned/kubeconfig",
  }, "m1-30b"), [
    "create", "cluster", "--name", `zasp-m1-30b-${marker}`,
    "--config", "/owned/kind.json", "--kubeconfig", "/owned/kubeconfig",
    "--image", KIND_PINS.node.reference, "--wait", "180s",
  ]);
  assert.throws(() => buildKindCreateArguments({
    cluster: `zasp-m1-30b-${marker}`,
    config: "/owned/kind.json",
    kubeconfig: "/owned/kubeconfig",
  }), { name: "TypeError" });
  assert.throws(() => buildKindCreateArguments({
    cluster: `zasp-m1-30a-${marker}`,
    config: "/owned/kind.json",
    kubeconfig: "/owned/kubeconfig",
  }, "m1-30b"), { name: "TypeError" });
  assert.throws(() => DockerKindGraphRuntime.fromProcess({
    DOCKER_HOST: "tcp://shared.invalid:2375",
    HOME: "/Users/test",
    PATH: "/usr/bin:/bin",
  }), { name: "Failure" });
  assert.throws(() => new DockerKindGraphRuntime({
    home: "/Users/test",
    hostPlatform: "windows/amd64",
    marker,
    nodePlatform: "linux/amd64",
    path: "/usr/bin:/bin",
    repositoryRoot: "/repository",
  }), { name: "TypeError" });
  assert.throws(() => new DockerKindGraphRuntime({
    home: "/Users/test",
    hostPlatform: "darwin/amd64",
    marker,
    nodePlatform: "linux/arm64",
    path: "/usr/bin:/bin",
    repositoryRoot: "/repository",
  }), { name: "TypeError" });
});

test("retains the complete index and exact selected manifest descriptor", () => {
  const value = validateGraphImageIndex(indexDocument(), plan());
  assert.equal(value.indexDigest, GRAPH_IMAGE_PLANS.neo4j.indexDigest);
  assert.equal(value.selected.digest, plan().manifestDigest);
  assert.equal(value.manifests.length, 3);
  assert.ok(Object.isFrozen(value) && Object.isFrozen(value.manifests));

  const mutations = [
    (document) => { document.schemaVersion = 1; },
    (document) => { document.manifests[1].digest = `sha256:${"9".repeat(64)}`; },
    (document) => { document.manifests[1].platform.architecture = "amd64"; },
    (document) => { delete document.manifests[1].size; },
    (document) => { document.manifests.push(structuredClone(document.manifests[1])); },
  ];
  for (const mutate of mutations) {
    const document = structuredClone(indexDocument());
    mutate(document);
    assert.throws(() => validateGraphImageIndex(document, plan()), { name: "Failure" });
  }
});

test("binds selected config and every immutable rootfs layer descriptor", () => {
  const value = validateGraphImageManifest(manifestDocument(), plan());
  assert.equal(value.config.digest, plan().configDigest);
  assert.deepEqual(value.layers.map(({ digest }) => digest), [
    `sha256:${"2".repeat(64)}`, `sha256:${"3".repeat(64)}`,
  ]);
  for (const mutate of [
    (document) => { document.config.digest = `sha256:${"8".repeat(64)}`; },
    (document) => { document.layers = []; },
    (document) => { document.layers[0].size = 0; },
    (document) => { document.layers[0].mediaType = "text/plain"; },
    (document) => { document.extra = true; },
  ]) {
    const document = structuredClone(manifestDocument());
    mutate(document);
    assert.throws(() => validateGraphImageManifest(document, plan()), { name: "Failure" });
  }
});

test("retains complete intrinsic image configuration and rejects all identity drift", () => {
  const selected = plan();
  const resolution = resolvedImage(selected);
  const projected = projectGraphImageInspection(projectedInspection());
  const value = validateGraphImageInspection(projected, selected, resolution);
  assert.equal(value.configDigest, selected.configDigest);
  assert.deepEqual(value.entrypoint, ["tini", "-g", "--", "/startup/docker-entrypoint.sh"]);
  assert.deepEqual(value.command, ["neo4j"]);
  assert.deepEqual(value.exposedPorts, ["7473/tcp", "7474/tcp", "7687/tcp"]);
  assert.deepEqual(value.intrinsicVolumes, ["/data", "/logs"]);
  assert.equal(value.user, "7474:7474");

  const mutations = [
    (document) => { document[0] = "amd64"; },
    (document) => { document[2] = `sha256:${"8".repeat(64)}`; },
    (document) => { document[3] = []; },
    (document) => { document[4] = ["neo4j:latest"]; },
    (document) => { document[5].Layers[0] = `sha256:${"8".repeat(64)}`; },
    (document) => { document[6].push("AWS_SECRET_ACCESS_KEY=secret"); },
    (document) => { document[7] = ["other"]; },
    (document) => { document[8] = ["other"]; },
    (document) => { document[9]["80/tcp"] = {}; },
    (document) => { document[10]["/customer"] = {}; },
    (document) => { document.push("extra"); },
  ];
  for (const mutate of mutations) {
    const document = structuredClone(projectedInspection());
    mutate(document);
    assert.throws(() => validateGraphImageInspection(
      projectGraphImageInspection(document), selected, resolution, value,
    ), { name: "Failure" });
  }
});

test("rejects absent, malformed, duplicate-key, and selected-platform metadata", () => {
  assert.throws(() => projectGraphImageInspection(undefined), { name: "Failure" });
  assert.throws(() => projectGraphImageInspection(projectedInspection(plan(), { extra: [true] })), { name: "Failure" });
  assert.throws(() => validateGraphImageIndex({}, plan()), { name: "Failure" });
  assert.throws(() => validateGraphImageManifest({}, plan()), { name: "Failure" });
  assert.throws(() => validateGraphImageIndex(
    JSON.parse('{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],"manifests":[]}'),
    plan(),
  ), { name: "Failure" });
});

test("rejects duplicate registry JSON before any image can be retained", async () => {
  const system = graphSystem();
  const selected = plan();
  let reads = 0;
  system.runRead = async () => success(++reads === 1
    ? '{"schemaVersion":2,"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}\n'
    : `${JSON.stringify(manifestDocument(selected))}\n`);
  await assert.rejects(() => system.resolveGraphImage(selected, phase), {
    category: "normalization",
    name: "Failure",
  });
  assert.equal(system.graphImageIdentities.size, 0);
});

test("parses only the two immutable graph imports from the exact containerd inventory", () => {
  const neo4j = plan("neo4j");
  const busybox = plan("busybox");
  const source = [
    "REF TYPE DIGEST SIZE PLATFORMS LABELS",
    `docker.io/library/zasp-audit-api:m1-30a application/vnd.oci.image.manifest.v1+json sha256:${"7".repeat(64)} 12.3 MiB linux/arm64 managed=true`,
    `${neo4j.providerReference} application/vnd.oci.image.manifest.v1+json ${neo4j.manifestDigest} 456.7 MiB linux/arm64 managed=true`,
    `${busybox.providerReference} application/vnd.oci.image.manifest.v1+json ${busybox.manifestDigest} 1.2 MiB linux/arm64 managed=true`,
    "",
  ].join("\n");
  assert.deepEqual(Object.fromEntries(parseGraphContainerdImageTargets(source, "linux/arm64")), {
    busybox: busybox.manifestDigest,
    neo4j: neo4j.manifestDigest,
  });
  for (const drift of [
    source.replace(neo4j.manifestDigest, `sha256:${"8".repeat(64)}`),
    source.replace(`${neo4j.manifestDigest} 456.7 MiB linux/arm64`,
      `${neo4j.manifestDigest} 456.7 MiB linux/amd64`),
    source.replace(`${busybox.providerReference} `, `${neo4j.providerReference} `),
    source.replace(/\n$/, ""),
  ]) assert.throws(() => parseGraphContainerdImageTargets(drift, "linux/arm64"), { name: "Failure" });
});

test("validates only the retained Kubernetes node label and node-local data path", () => {
  const node = validateGraphNodeLabel({
    apiVersion: "v1",
    kind: "Node",
    metadata: {
      labels: {
        "kubernetes.io/hostname": "zasp-m1-30b-0123456789abcdef-control-plane",
        [GRAPH_CONSTANTS.nodeLabelKey]: GRAPH_CONSTANTS.nodeLabelValue,
      },
      name: "zasp-m1-30b-0123456789abcdef-control-plane",
      resourceVersion: "7",
      uid: "11111111-1111-4111-8111-111111111111",
    },
  }, {
    name: "zasp-m1-30b-0123456789abcdef-control-plane",
    token: "a".repeat(64),
  });
  assert.equal(node.uid, "11111111-1111-4111-8111-111111111111");
  assert.deepEqual(validateGraphNodeLabel({
    apiVersion: "v1", kind: "Node", metadata: {
      labels: { "kubernetes.io/hostname": node.name }, name: node.name,
      resourceVersion: "8", uid: node.uid,
    },
  }, { name: node.name, token: node.token }, node, false), { ...node, labeled: false });
  assert.throws(() => validateGraphNodeLabel({
    apiVersion: "v1", kind: "Node", metadata: {
      labels: { [GRAPH_CONSTANTS.nodeLabelKey]: "other" }, name: node.name,
      resourceVersion: "9", uid: node.uid,
    },
  }, { name: node.name, token: node.token }, node), { name: "Failure" });

  const path = validateGraphNodePath(
    `43|99|directory|7474|7474|700|${GRAPH_CONSTANTS.nodeDataPath}\n`, node,
  );
  assert.deepEqual(path, {
    dev: 43, gid: 7474, ino: 99, mode: 700, nodeToken: node.token,
    path: GRAPH_CONSTANTS.nodeDataPath, uid: 7474,
  });
  for (const value of [
    `43|100|directory|7474|7474|700|${GRAPH_CONSTANTS.nodeDataPath}\n`,
    `43|99|directory|0|7474|700|${GRAPH_CONSTANTS.nodeDataPath}\n`,
    `43|99|directory|7474|7474|755|${GRAPH_CONSTANTS.nodeDataPath}\n`,
    "43|99|directory|7474|7474|700|/other\n",
  ]) assert.throws(() => validateGraphNodePath(value, node, path), { name: "Failure" });
});

test("pulls both indexes once and accepts ambiguity only through complete reinspection", async () => {
  const system = graphSystem();
  const events = [];
  system.requireTemporaryOwnership = async () => {};
  system.resolveGraphImage = async (selected) => {
    events.push(`resolve:${selected.name}`);
    return resolvedImage(selected);
  };
  system.runMutation = async (command, arguments_) => {
    events.push([command, ...arguments_]);
    return { outcome: "ambiguous", result: success("pull progress\n") };
  };
  system.inspectGraphImage = async (selected, resolution) => {
    events.push(`inspect:${selected.name}`);
    const document = selected.name === "neo4j" ? projectedInspection(selected) : [
      selected.architecture, "linux", selected.configDigest, [selected.repoDigest], [selected.tag],
      { Layers: [`sha256:${"6".repeat(64)}`], Type: "layers" }, ["PATH=/usr/bin:/bin"],
      null, null, null, null, {}, "65534", "/",
    ];
    return validateGraphImageInspection(projectGraphImageInspection(document), selected, resolution);
  };
  await system.buildAdditionalImages(phase);
  assert.deepEqual(events.filter(Array.isArray), [
    ["docker", "pull", "--platform", "linux/arm64", NEO4J_IMAGE],
    ["docker", "pull", "--platform", "linux/arm64", BUSYBOX_IMAGE],
  ]);
  assert.deepEqual([...system.graphImageIdentities.keys()], ["neo4j", "busybox"]);
  assert.ok(events.every((event) => !Array.isArray(event) || event[0] !== "env"));

  const rejected = graphSystem();
  rejected.requireTemporaryOwnership = async () => {};
  rejected.resolveGraphImage = async (selected) => resolvedImage(selected);
  rejected.runMutation = async () => ({ outcome: "definitive", result: { ...success(), status: 1 } });
  await assert.rejects(() => rejected.buildAdditionalImages(phase), { name: "Failure" });
  assert.equal(rejected.graphImageMayHaveApplied.size, 0);
});

test("rejects a graph/product image collision before retaining the graph alias", async () => {
  const system = graphSystem();
  const collision = plan().configDigest;
  system.requireTemporaryOwnership = async () => {};
  system.imageIdentities.set(PRODUCTS[0].name, { id: collision });
  system.resolveGraphImage = async (selected) => resolvedImage(selected);
  system.runMutation = async () => ({ outcome: "applied", result: success() });
  system.inspectGraphImage = async (selected, resolution) => validateGraphImageInspection(
    projectGraphImageInspection(projectedInspection(selected)), selected, resolution,
  );
  await assert.rejects(() => system.buildAdditionalImages(phase), { name: "Failure" });
  assert.equal(system.graphImageIdentities.size, 0);
  assert.equal(system.graphImageMayHaveApplied.has("neo4j"), true, "cleanup retains the possibly applied alias");
});

test("labels and prepares only the retained kind node with exact fixed argv", async () => {
  const system = graphSystem();
  system.paths = { graphManifest: "/owned/graph.yaml" };
  system.nodeIdentity = { token: "a".repeat(64) };
  const calls = [];
  let labelReads = 0;
  let pathReads = 0;
  system.requireTemporaryOwnership = async () => {};
  system.requireOwnedPath = async () => {};
  system.verifyCluster = async () => system.nodeIdentity;
  system.runKubectlMutation = async (arguments_) => {
    calls.push(["kubectl", ...arguments_]);
    return { outcome: "ambiguous", result: success("node labeled\n") };
  };
  system.readGraphNodeLabel = async () => {
    labelReads += 1;
    if (labelReads === 1) return undefined;
    return { labeled: true, name: `${system.cluster}-control-plane`, token: system.nodeIdentity.token,
      uid: "11111111-1111-4111-8111-111111111111" };
  };
  system.runNodeMutation = async (arguments_) => {
    calls.push(["node", ...arguments_]);
    return { outcome: "ambiguous", result: success() };
  };
  system.readGraphNodePath = async () => {
    pathReads += 1;
    if (pathReads === 1) return undefined;
    return { dev: 43, gid: 7474, ino: 99, mode: 700, nodeToken: system.nodeIdentity.token,
      path: GRAPH_CONSTANTS.nodeDataPath, uid: 7474 };
  };
  await system.prepareAdditionalNode(phase);
  assert.deepEqual(calls, [
    ["kubectl", "label", "node", `${system.cluster}-control-plane`,
      `${GRAPH_CONSTANTS.nodeLabelKey}=${GRAPH_CONSTANTS.nodeLabelValue}`, "--overwrite=false"],
    ["node", "install", "-d", "-m", "0700", "-o", "7474", "-g", "7474", "--", GRAPH_CONSTANTS.nodeDataPath],
  ]);
  assert.equal(labelReads, 2, "an ambiguous label reconciles through the exact delayed node state");
  assert.equal(pathReads, 2, "an ambiguous exec reconciles through the exact delayed path state");

  const definitive = graphSystem();
  definitive.paths = { graphManifest: "/owned/graph.yaml" };
  definitive.nodeIdentity = { token: "b".repeat(64) };
  definitive.requireTemporaryOwnership = async () => {};
  definitive.requireOwnedPath = async () => {};
  definitive.verifyCluster = async () => definitive.nodeIdentity;
  definitive.runKubectlMutation = async () => ({ outcome: "applied", result: success() });
  definitive.readGraphNodeLabel = async () => ({
    labeled: true,
    name: `${definitive.cluster}-control-plane`,
    token: definitive.nodeIdentity.token,
    uid: "22222222-2222-4222-8222-222222222222",
  });
  definitive.runNodeMutation = async () => ({
    outcome: "definitive",
    result: { ...success(), status: 1 },
  });
  await assert.rejects(() => definitive.prepareAdditionalNode(phase), { name: "Failure" });
  assert.equal(definitive.graphNodeMayHaveApplied, true);
  assert.equal(definitive.graphPathMayHaveApplied, false,
    "a definitive exec rejection is never adopted or reconciled");
});

test("loads graph images by immutable reference and verifies exact containerd targets", async () => {
  const system = graphSystem();
  const calls = [];
  system.nodeIdentity = { token: "a".repeat(64) };
  system.paths = { kind: "/owned/kind" };
  system.requireTemporaryOwnership = async () => {};
  system.verifyCluster = async () => system.nodeIdentity;
  for (const name of ["neo4j", "busybox"]) {
    const selected = plan(name);
    system.graphImageIdentities.set(name, { ...selected, id: selected.configDigest });
  }
  system.verifyGraphImage = async () => {};
  system.runMutation = async (command, arguments_) => {
    calls.push([command, ...arguments_]);
    return { outcome: "ambiguous", result: success("loaded\n") };
  };
  system.runNodeRead = async (arguments_) => {
    calls.push(["node", ...arguments_]);
    const neo4j = plan("neo4j");
    const busybox = plan("busybox");
    return success([
      "REF TYPE DIGEST SIZE PLATFORMS LABELS",
      `${neo4j.providerReference} application/vnd.oci.image.manifest.v1+json ${neo4j.manifestDigest} 456 MiB linux/arm64 managed=true`,
      `${busybox.providerReference} application/vnd.oci.image.manifest.v1+json ${busybox.manifestDigest} 1 MiB linux/arm64 managed=true`,
      "",
    ].join("\n"));
  };
  await system.loadAdditionalImages(phase);
  assert.deepEqual(calls.slice(0, 2), [
    ["/owned/kind", "load", "docker-image", NEO4J_IMAGE, "--name", system.cluster],
    ["/owned/kind", "load", "docker-image", BUSYBOX_IMAGE, "--name", system.cluster],
  ]);
  assert.deepEqual(Object.fromEntries(system.graphLoadedImageTargets), {
    busybox: plan("busybox").manifestDigest,
    neo4j: plan("neo4j").manifestDigest,
  });

  const definitive = graphSystem();
  definitive.nodeIdentity = { token: "b".repeat(64) };
  definitive.paths = { kind: "/owned/kind" };
  definitive.requireTemporaryOwnership = async () => {};
  definitive.verifyCluster = async () => definitive.nodeIdentity;
  for (const name of ["neo4j", "busybox"]) {
    const selected = plan(name);
    definitive.graphImageIdentities.set(name, { ...selected, id: selected.configDigest });
  }
  definitive.verifyGraphImage = async () => {};
  definitive.runMutation = async () => ({ outcome: "definitive", result: { ...success(), status: 1 } });
  await assert.rejects(() => definitive.loadAdditionalImages(phase), { name: "Failure" });
  assert.equal(definitive.graphLoadedImageTargets.size, 0);
});

test("applies product and graph manifests through separate retained descriptors", async () => {
  const system = graphSystem();
  const productBytes = Buffer.from("product manifest\n");
  const graphBytes = Buffer.from("graph manifest\n");
  const calls = [];
  system.paths = {
    graphManifest: "/owned/graph.yaml",
    kubeconfig: "/owned/kubeconfig",
    manifest: "/owned/manifests.yaml",
  };
  system.additionalManifestPaths = new Map([["graphManifest", system.paths.graphManifest]]);
  system.environment = Object.freeze({
    DOCKER_CONFIG: "/owned/docker",
    HOME: "/owned/home",
    KIND_EXPERIMENTAL_DOCKER_NETWORK: system.cluster,
    KUBECONFIG: system.paths.kubeconfig,
    LANG: "C.UTF-8",
    PATH: "/usr/local/bin:/usr/bin:/bin",
  });
  system.requireTemporaryOwnership = async () => {};
  system.verifyCluster = async () => ({ token: "a".repeat(64) });
  system.verifyAdditionalManifestState = async (_phase, path) => { calls.push(["graph-state", path]); };
  system.requireOwnedPath = async (path) => { calls.push(["reprove", path]); };
  let descriptor = 30;
  system.withOwnedFiles = async (paths, _phase, _category, operation) => operation(paths.map((path) => ({
    handle: { fd: descriptor++ },
    identity: { bytes: path === system.paths.manifest ? productBytes : graphBytes },
  })));
  system.runMutation = async (command, arguments_, _phase, _category, options) => {
    calls.push({ arguments: arguments_, command, options });
    return { outcome: "ambiguous", result: success("provider acknowledgement\n") };
  };
  system.runRead = async (command, arguments_, _phase, _category, _timeout, _limit, options) => {
    calls.push({ arguments: arguments_, command, options });
    return success();
  };
  await system.applyManifests(phase);
  const applies = calls.filter((value) => value.command === "kubectl" && value.arguments.includes("apply"));
  assert.equal(applies.length, 2);
  assert.deepEqual(calls.filter((value) => Array.isArray(value) && value[0] === "graph-state"), [
    ["graph-state", system.paths.graphManifest],
  ]);
  assert.deepEqual(applies.map(({ arguments: arguments_ }) => arguments_), [
    ["--kubeconfig", "/dev/fd/3", "apply", "--filename", "-"],
    ["--kubeconfig", "/dev/fd/3", "apply", "--filename", "-"],
  ]);
  assert.deepEqual(applies.map(({ options }) => options.input), [productBytes, graphBytes]);
  assert.equal(new Set(applies.map(({ options }) => options.fileDescriptors[0])).size, 2);
  assert.ok(applies.every(({ options }) => options.environment === system.environment));
  assert.deepEqual(Object.keys(system.environment).sort(), [
    "DOCKER_CONFIG", "HOME", "KIND_EXPERIMENTAL_DOCKER_NETWORK", "KUBECONFIG", "LANG", "PATH",
  ]);

  const definitive = graphSystem();
  definitive.paths = system.paths;
  definitive.additionalManifestPaths = new Map([["graphManifest", definitive.paths.graphManifest]]);
  definitive.environment = system.environment;
  definitive.requireTemporaryOwnership = async () => {};
  definitive.verifyCluster = async () => ({ token: "a".repeat(64) });
  definitive.verifyAdditionalManifestState = async () => {};
  definitive.requireOwnedPath = async () => {};
  definitive.withOwnedFiles = system.withOwnedFiles;
  let mutations = 0;
  definitive.runMutation = async () => ({
    outcome: ++mutations === 2 ? "definitive" : "applied",
    result: mutations === 2 ? { ...success(), status: 1 } : success(),
  });
  definitive.runRead = async () => success();
  await assert.rejects(() => definitive.applyManifests(phase), { name: "Failure" });
  assert.equal(definitive.resourcesMayHaveApplied, true,
    "product resources remain cleanup-owned when graph apply is definitively rejected");
});

test("reverse cleanup re-proves node storage and images and retains recovery on replacement", async () => {
  const system = graphSystem();
  const events = [];
  system.paths = { graphManifest: "/owned/graph.yaml" };
  system.nodeIdentity = { token: "a".repeat(64) };
  system.graphNodeIdentity = { labeled: true, name: `${system.cluster}-control-plane`,
    token: system.nodeIdentity.token, uid: "11111111-1111-4111-8111-111111111111" };
  system.graphPathIdentity = { dev: 43, gid: 7474, ino: 99, mode: 700,
    nodeToken: system.nodeIdentity.token, path: GRAPH_CONSTANTS.nodeDataPath, uid: 7474 };
  system.graphNodeMayHaveApplied = true;
  system.graphPathMayHaveApplied = true;
  system.requireTemporaryOwnership = async () => { events.push("root"); };
  system.requireOwnedPath = async () => { events.push("manifest"); };
  system.verifyCluster = async () => { events.push("cluster"); return system.nodeIdentity; };
  system.readGraphNodeLabel = async () => { events.push("label"); return system.graphNodeIdentity; };
  system.readGraphNodePath = async () => { events.push("path"); return system.graphPathIdentity; };
  await system.verifyAdditionalNodeForCleanup(phase);
  assert.deepEqual(events, ["root", "manifest", "cluster", "label", "path"]);

  system.readGraphNodePath = async () => ({ ...system.graphPathIdentity, ino: 100 });
  await assert.rejects(() => system.verifyAdditionalNodeForCleanup(phase), { name: "Failure" });
  assert.equal(system.graphPathMayHaveApplied, true, "replacement retains recovery material and blocks deletion");
});

test("cleanup reconciles ambiguous node mutations only through exact present or absent state", async () => {
  const present = graphSystem();
  present.paths = { graphManifest: "/owned/graph.yaml" };
  present.nodeIdentity = { token: "a".repeat(64) };
  present.graphNodeMayHaveApplied = true;
  present.graphPathMayHaveApplied = true;
  present.requireTemporaryOwnership = async () => {};
  present.requireOwnedPath = async () => {};
  present.verifyCluster = async () => present.nodeIdentity;
  present.readGraphNodeLabel = async () => ({
    labeled: true,
    name: `${present.cluster}-control-plane`,
    token: present.nodeIdentity.token,
    uid: "11111111-1111-4111-8111-111111111111",
  });
  present.readGraphNodePath = async () => ({
    dev: 43, gid: 7474, ino: 99, mode: 700, nodeToken: present.nodeIdentity.token,
    path: GRAPH_CONSTANTS.nodeDataPath, uid: 7474,
  });
  await present.verifyAdditionalNodeForCleanup(phase);
  assert.equal(present.graphNodeIdentity?.labeled, true);
  assert.equal(present.graphPathIdentity?.ino, 99);

  const absent = graphSystem();
  absent.paths = { graphManifest: "/owned/graph.yaml" };
  absent.nodeIdentity = { token: "b".repeat(64) };
  absent.graphNodeMayHaveApplied = true;
  absent.graphPathMayHaveApplied = true;
  absent.requireTemporaryOwnership = async () => {};
  absent.requireOwnedPath = async () => {};
  absent.verifyCluster = async () => absent.nodeIdentity;
  absent.readGraphNodeLabel = async (_phase, _category, _retained, labeled) => labeled ?
    Promise.reject(new GraphFailure("ownership")) : {
      labeled: false,
      name: `${absent.cluster}-control-plane`,
      token: absent.nodeIdentity.token,
      uid: "22222222-2222-4222-8222-222222222222",
    };
  absent.readGraphNodePath = async () => undefined;
  await absent.verifyAdditionalNodeForCleanup(phase);
  assert.equal(absent.graphNodeMayHaveApplied, false);
  assert.equal(absent.graphPathMayHaveApplied, false);
});

test("removes retained graph aliases in reverse order only after exact reinspection", async () => {
  const system = graphSystem();
  const events = [];
  system.paths = { graphManifest: "/owned/graph.yaml" };
  system.requireTemporaryOwnership = async () => {};
  system.requireOwnedPath = async () => {};
  for (const [index, name] of ["neo4j", "busybox"].entries()) {
    const selected = plan(name);
    system.graphImageIdentities.set(name, { id: `sha256:${String(index + 7).repeat(64)}`, name });
    system.graphImageResolutions.set(name, resolvedImage(selected));
    system.graphImageMayHaveApplied.add(name);
  }
  system.verifyGraphImage = async (selected, retained) => { events.push(`verify:${selected.name}:${retained.id}`); };
  system.runMutation = async (_command, arguments_) => {
    events.push(`remove:${arguments_.at(-1)}`);
    return { outcome: "ambiguous", result: success("removed\n") };
  };
  system.requireGraphImageAbsent = async (selected) => { events.push(`absent:${selected.name}`); };
  const failures = [];
  const step = async (operation) => {
    try { await operation(); } catch (error) { failures.push(error); }
  };
  await system.cleanupAdditionalImages(step, phase);
  assert.deepEqual(events, [
    `verify:busybox:sha256:${"8".repeat(64)}`,
    `remove:sha256:${"8".repeat(64)}`,
    "absent:busybox",
    `verify:neo4j:sha256:${"7".repeat(64)}`,
    `remove:sha256:${"7".repeat(64)}`,
    "absent:neo4j",
  ]);
  assert.deepEqual(failures, []);
  assert.equal(system.graphImageIdentities.size, 0);
  assert.equal(system.graphImageMayHaveApplied.size, 0);
});

test("uses the original lifecycle ordering with graph fixed output, cancellation, and panic fencing", async () => {
  assert.deepEqual(GRAPH_FAILURE_CATEGORIES, [
    "build", "cleanup", "configuration", "deadline", "normalization", "ownership", "panic", "provider", "readiness",
  ]);
  assert.equal(GRAPH_SUCCESS_LINE,
    "Local graph manifest passed: ready=true internal=true persistent=true cleanup=true.");
  const output = [];
  const errors = [];
  const exits = [];
  const { events, runtime } = lifecycle();
  assert.equal(await runGraphMain(runtime, {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 100,
    stderr: { write: (value) => errors.push(value) },
    stdout: { write: (value) => output.push(value) },
    setExitCode: (value) => exits.push(value),
  }), 0);
  assert.deepEqual(events, [
    "initialize", "preflight", "buildImages", "createNetwork", "createCluster", "loadImages",
    "applyManifests", "verifyReadiness", "joinMutations", "cleanup", "auditAbsence",
  ]);
  assert.deepEqual(output, [`${GRAPH_SUCCESS_LINE}\n`]);
  assert.deepEqual(errors, []);
  assert.deepEqual(exits, [0]);

  for (const [failure, category] of [
    [new Error("secret provider panic"), "panic"],
    [new GraphFailure("normalization"), "normalization"],
  ]) {
    const failed = lifecycle({ initialize: async () => { throw failure; } });
    const failedOutput = [];
    assert.equal(await runGraphMain(failed.runtime, {
      cleanupTimeoutMilliseconds: 100,
      mainTimeoutMilliseconds: 100,
      settlementTimeoutMilliseconds: 100,
      stderr: { write: (value) => failedOutput.push(value) },
      stdout: { write: () => assert.fail("unexpected success") },
      setExitCode() {},
    }), 1);
    assert.deepEqual(failedOutput, [`Local graph manifest failed: ${category} rejected.\n`]);
    assert.ok(!failedOutput[0].includes("secret") && !failedOutput[0].includes("raw"));
  }

  const cancelled = lifecycle({ initialize: async () => await new Promise(() => {}) });
  const cancellationOutput = [];
  assert.equal(await runGraphMain(cancelled.runtime, {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 5,
    settlementTimeoutMilliseconds: 5,
    stderr: { write: (value) => cancellationOutput.push(value) },
    stdout: { write: () => assert.fail("unexpected success") },
    setExitCode() {},
  }), 1);
  assert.deepEqual(cancellationOutput, ["Local graph manifest failed: deadline rejected.\n"]);
  assert.deepEqual(cancelled.events, ["joinMutations", "cleanup", "auditAbsence"]);
});
