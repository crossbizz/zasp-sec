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
const missingUnformattedGraphImage = (reference) => Object.freeze({
  ...success("[]\n", `Error response from daemon: No such image: ${reference}\n`),
  status: 1,
});
const missingFormattedGraphImage = (reference) => Object.freeze({
  ...success("\n", `Error response from daemon: No such image: ${reference}\n`),
  status: 1,
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
  return [...pinnedGraphImageInspection(selected), ...overrides.extra ?? []];
}

function pinnedGraphImageInspection(selected = plan()) {
  const layers = {
    busybox: {
      "linux/amd64": ["sha256:3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f"],
      "linux/arm64": ["sha256:3694737149b11ec4d2c9f15ad24788e81955cd1c7f2c6f555baf1e4a3615bd26"],
    },
    neo4j: {
      "linux/amd64": [
        "sha256:6f94328331290cbd81edab450664d42da7b64c191416c9346cd5d28c84f76035",
        "sha256:8b21e26c8d3c159e0cbe66c916817f3c6248d896e17696a688cd1fc628084fc6",
        "sha256:25b91126e4557fee9cbf75da6100a71079d92e71c476b2736c69a4118c374856",
        "sha256:7b06c003260874d1194c2a789ad0bb53fa08aef8fb621ad85a60ba093464cd5c",
        "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
      ],
      "linux/arm64": [
        "sha256:c01c35a040a25a51cd473910e3212a46d85fb700a6467c687f231d7edd47cbc1",
        "sha256:9740541a641149918376635dca8d31a457abbe8201ffa5b1c4bcf62b3c235342",
        "sha256:24be1ee0a923e6aa95b88769e7567db289e37a0a6c11bd2a23a433b392fdc341",
        "sha256:4f2bc04bffc88e927b6c7b6eba1d35b13e2567fee53d48970ddc89d1e690ef1c",
        "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
      ],
    },
  }[selected.name]?.[selected.platform];
  if (selected.name === "busybox") return [
    selected.architecture,
    "linux",
    selected.configDigest,
    [selected.repoDigest],
    [],
    { Layers: layers, Type: "layers" },
    ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    null,
    ["sh"],
    null,
    null,
    {
      commit_id: "22d90ebde235edec3541f728b37a01285bdd8b1b",
      git_url: "https://github.com/kubernetes/kubernetes/tree/22d90ebde235edec3541f728b37a01285bdd8b1b/test/images/busybox",
      image_version: "1.36.1-1",
    },
    "",
    "",
  ];
  return [
    selected.architecture,
    "linux",
    selected.configDigest,
    [selected.repoDigest],
    [],
    { Layers: layers, Type: "layers" },
    [
      "PATH=/var/lib/neo4j/bin:/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "JAVA_HOME=/opt/java/openjdk",
      "NEO4J_SHA256=9d4064cdd87627cae376a741c893848c4faa3c4fb980362b6dae541c203e8072",
      "NEO4J_TARBALL=neo4j-community-5.26.28-unix.tar.gz",
      "NEO4J_EDITION=community",
      "NEO4J_HOME=/var/lib/neo4j",
      "LANG=C.UTF-8",
    ],
    ["tini", "-g", "--", "/startup/docker-entrypoint.sh"],
    ["neo4j"],
    { "7473/tcp": {}, "7474/tcp": {}, "7687/tcp": {} },
    { "/data": {}, "/logs": {} },
    null,
    "",
    "/var/lib/neo4j",
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
  assert.equal(value.user, "");

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

test("binds digest-only first adoption to every pinned runtime and rootfs fact", () => {
  for (const name of ["neo4j", "busybox"]) {
    for (const platform of ["linux/amd64", "linux/arm64"]) {
      const platformPlan = plan(name, platform);
      const exactPlatform = pinnedGraphImageInspection(platformPlan);
      const identity = validateGraphImageInspection(
        projectGraphImageInspection(exactPlatform), platformPlan, resolvedImage(platformPlan),
      );
      assert.deepEqual(identity.rootfs.Layers, exactPlatform[5].Layers);
      assert.deepEqual(identity.repoDigests, [platformPlan.repoDigest]);
      assert.deepEqual(identity.repoTags, []);

      const unexpectedTag = structuredClone(exactPlatform);
      unexpectedTag[4] = [platformPlan.tag];
      assert.throws(() => validateGraphImageInspection(
        projectGraphImageInspection(unexpectedTag), platformPlan, resolvedImage(platformPlan),
      ), { name: "Failure" }, `${name} ${platform} must not invent a tag alias`);
    }
  }
  const selected = plan();
  const resolution = resolvedImage(selected);
  const exact = pinnedGraphImageInspection();
  assert.deepEqual(validateGraphImageInspection(
    projectGraphImageInspection(exact), selected, resolution,
  ).rootfs.Layers, exact[5].Layers);

  const hostile = [
    ["rootfs", (value) => { value[5].Layers[0] = `sha256:${"9".repeat(64)}`; }],
    ["environment", (value) => { value[6][1] = "JAVA_HOME=/foreign"; }],
    ["entrypoint", (value) => { value[7] = ["/foreign"]; }],
    ["command", (value) => { value[8] = ["sh"]; }],
    ["ports", (value) => { value[9] = { "7474/tcp": {} }; }],
    ["volumes", (value) => { value[10] = { "/data": {} }; }],
    ["labels", (value) => { value[11] = { ambient: "true" }; }],
    ["user", (value) => { value[12] = "7474:7474"; }],
    ["working directory", (value) => { value[13] = "/foreign"; }],
  ];
  for (const [label, mutate] of hostile) {
    const value = structuredClone(exact);
    mutate(value);
    assert.throws(() => validateGraphImageInspection(
      projectGraphImageInspection(value), selected, resolution,
    ), { name: "Failure" }, label);
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
  system.requireGraphImageBaselineAbsent = async () => {};
  system.requireGraphImageConsumersAbsent = async () => {};
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
    const document = projectedInspection(selected);
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
  rejected.requireGraphImageBaselineAbsent = async () => {};
  rejected.resolveGraphImage = async (selected) => resolvedImage(selected);
  rejected.runMutation = async () => ({ outcome: "definitive", result: { ...success(), status: 1 } });
  await assert.rejects(() => rejected.buildAdditionalImages(phase), { name: "Failure" });
  assert.equal(rejected.graphImageMayHaveApplied.size, 0);
});

test("reconciles thrown, signaled, and malformed pulls through exact digest-only inspection", async () => {
  const selected = plan();
  const cases = [
    ["thrown", async () => { throw new Error("transport ended"); }],
    ["signaled", async () => Object.freeze({
      signal: "SIGTERM", status: null, stderr: "", stdout: "", thrown: false, timedOut: false,
    })],
    ["malformed output", async () => success("provider output without a stable grammar\n")],
  ];
  const results = [];
  for (const [label, command] of cases) {
    const system = graphSystem(command);
    system.graphImagePlans = new Map([[selected.name, selected]]);
    system.requireTemporaryOwnership = async () => {};
    system.requireGraphImageBaselineAbsent = async () => {};
    system.requireGraphImageConsumersAbsent = async () => {};
    system.resolveGraphImage = async () => resolvedImage(selected);
    system.runRead = async (_command, arguments_) => {
      assert.equal(arguments_[0], "image");
      assert.equal(arguments_[1], "inspect");
      assert.equal(arguments_.at(-1), selected.reference);
      return success(`${JSON.stringify(pinnedGraphImageInspection(selected))}\n`);
    };
    try {
      await system.buildAdditionalImages(phase);
      results.push({
        aliases: system.graphImageAliases.get(selected.name),
        identityTags: system.graphImageIdentities.get(selected.name)?.repoTags,
        label,
      });
    } catch (error) {
      results.push({ error: error?.name, label });
    }
  }
  const aliases = { repoDigests: [selected.repoDigest], repoTags: [] };
  assert.deepEqual(results, [
    { aliases, identityTags: [], label: "thrown" },
    { aliases, identityTags: [], label: "signaled" },
    { aliases, identityTags: [], label: "malformed output" },
  ]);
});

test("rejects a graph/product image collision before retaining the graph alias", async () => {
  const system = graphSystem();
  const collision = plan().configDigest;
  system.requireTemporaryOwnership = async () => {};
  system.requireGraphImageBaselineAbsent = async () => {};
  system.requireGraphImageConsumersAbsent = async () => {};
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

test("polls a real unlabeled node until the exact retained label appears", async () => {
  const system = graphSystem();
  const name = `${system.cluster}-control-plane`;
  const token = "a".repeat(64);
  const uid = "11111111-1111-4111-8111-111111111111";
  let reads = 0;
  system.paths = { graphManifest: "/owned/graph.yaml" };
  system.nodeIdentity = { token };
  system.requireTemporaryOwnership = async () => {};
  system.requireOwnedPath = async () => {};
  system.verifyCluster = async () => system.nodeIdentity;
  system.runKubectlMutation = async () => ({ outcome: "ambiguous", result: success() });
  system.runKubectlRead = async () => {
    reads += 1;
    return success(`${JSON.stringify({
      apiVersion: "v1",
      kind: "Node",
      metadata: {
        labels: {
          "kubernetes.io/hostname": name,
          ...(reads === 1 ? {} : { [GRAPH_CONSTANTS.nodeLabelKey]: GRAPH_CONSTANTS.nodeLabelValue }),
        },
        name,
        resourceVersion: String(reads + 7),
        uid,
      },
    })}\n`);
  };
  system.runNodeMutation = async () => ({ outcome: "applied", result: success() });
  system.readGraphNodePath = async () => ({
    dev: 43, gid: 7474, ino: 99, mode: 700, nodeToken: token,
    path: GRAPH_CONSTANTS.nodeDataPath, uid: 7474,
  });

  await system.prepareAdditionalNode(phase);
  assert.equal(reads, 2);
  assert.deepEqual(system.graphNodeIdentity, { labeled: true, name, token, uid });

  reads = 0;
  system.runKubectlRead = async () => {
    reads += 1;
    return success(`${JSON.stringify({
      apiVersion: "v1", kind: "Node", metadata: {
        labels: { "kubernetes.io/hostname": name }, name, resourceVersion: String(reads + 20), uid,
      },
    })}\n`);
  };
  await assert.rejects(() => system.reconcileGraphState(
    () => system.readGraphNodeLabel(phase, "ownership", system.graphNodeIdentity, null),
    (value) => value.labeled === true,
    phase,
    "ownership",
  ), { name: "Failure" });
  assert.equal(reads, 3, "an unapplied label is polled only through the fixed bound");

  const replaced = graphSystem();
  let replacementReads = 0;
  replaced.paths = { graphManifest: "/owned/graph.yaml" };
  replaced.nodeIdentity = { token };
  replaced.requireTemporaryOwnership = async () => {};
  replaced.requireOwnedPath = async () => {};
  replaced.verifyCluster = async () => replaced.nodeIdentity;
  replaced.runKubectlMutation = async () => ({ outcome: "ambiguous", result: success() });
  replaced.runKubectlRead = async () => {
    replacementReads += 1;
    return success(`${JSON.stringify({
      apiVersion: "v1", kind: "Node", metadata: {
        labels: {
          "kubernetes.io/hostname": name,
          ...(replacementReads === 1 ? {} : {
            [GRAPH_CONSTANTS.nodeLabelKey]: GRAPH_CONSTANTS.nodeLabelValue,
          }),
        },
        name,
        resourceVersion: String(replacementReads + 30),
        uid: replacementReads === 1 ? uid : "22222222-2222-4222-8222-222222222222",
      },
    })}\n`);
  };
  replaced.runNodeMutation = async () => ({ outcome: "applied", result: success() });
  replaced.readGraphNodePath = async () => ({
    dev: 43, gid: 7474, ino: 99, mode: 700, nodeToken: token,
    path: GRAPH_CONSTANTS.nodeDataPath, uid: 7474,
  });
  await assert.rejects(() => replaced.prepareAdditionalNode(phase), { name: "Failure" });
  assert.equal(replacementReads, 2, "the first valid unlabeled node UID is retained across polling");
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

test("blocks a preexisting config baseline before the digest-qualified pull", async () => {
  const selected = plan();
  const collision = graphSystem();
  let collisionPulls = 0;
  collision.requireTemporaryOwnership = async () => {};
  collision.resolveGraphImage = async () => resolvedImage(selected);
  collision.runRaw = async (_command, arguments_) => {
    assert.deepEqual(arguments_, ["image", "inspect", selected.configDigest]);
    return success("[{\"Id\":\"ambient\"}]\n");
  };
  collision.runMutation = async () => {
    collisionPulls += 1;
    return { outcome: "applied", result: success() };
  };
  collision.inspectGraphImage = async () => validateGraphImageInspection(
    projectGraphImageInspection(pinnedGraphImageInspection()), selected, resolvedImage(selected),
  );
  await assert.rejects(() => collision.buildAdditionalImages(phase), { name: "Failure" });
  assert.equal(collisionPulls, 0, "a pre-existing config ID is rejected before pull authority exists");
});

test("blocks an opposite-platform repository digest baseline before pull", async () => {
  const selected = plan("neo4j", "linux/arm64");
  const opposite = plan("neo4j", "linux/amd64");
  const system = graphSystem();
  system.graphImagePlans = new Map([[selected.name, selected]]);
  system.requireTemporaryOwnership = async () => {};
  system.resolveGraphImage = async () => resolvedImage(selected);
  system.runRaw = async (_command, arguments_) => {
    const reference = arguments_.at(-1);
    if (reference === selected.configDigest) return missingUnformattedGraphImage(reference);
    if (reference === selected.repoDigest) return success(`${JSON.stringify([
      opposite.configDigest,
      "amd64",
      "linux",
      [selected.repoDigest],
      [],
    ])}\n`);
    throw new Error("unexpected raw inspection");
  };
  system.runRead = async () => success();
  let pulls = 0;
  system.runMutation = async () => {
    pulls += 1;
    return { outcome: "applied", result: success() };
  };
  system.inspectGraphImage = async () => validateGraphImageInspection(
    projectGraphImageInspection(pinnedGraphImageInspection(selected)), selected, resolvedImage(selected),
  );

  await assert.rejects(() => system.buildAdditionalImages(phase), { name: "Failure" });
  assert.equal(pulls, 0, "an ambient opposite-platform alias is rejected before pull authority exists");
});

test("accepts only exact unformatted config and formatted repository-digest absence", async () => {
  const selected = plan();
  const system = graphSystem();
  const rawCalls = [];
  const readCalls = [];
  system.runRaw = async (command, arguments_) => {
    rawCalls.push([command, ...arguments_]);
    return arguments_.includes("--format") ?
      missingFormattedGraphImage(arguments_.at(-1)) : missingUnformattedGraphImage(arguments_.at(-1));
  };
  system.runRead = async (command, arguments_) => {
    readCalls.push([command, ...arguments_]);
    return success();
  };

  await system.requireGraphImageBaselineAbsent(selected, phase);
  assert.deepEqual(rawCalls, [
    ["docker", "image", "inspect", selected.configDigest],
    [
      "docker", "image", "inspect", "--format",
      "[{{json .Id}},{{json .Architecture}},{{json .Os}},{{json .RepoDigests}},{{json .RepoTags}}]",
      selected.repoDigest,
    ],
  ]);
  assert.deepEqual(readCalls, [
    ["docker", "image", "ls", "--quiet", "--no-trunc", "--filter", `reference=${selected.reference}`],
    ["docker", "ps", "--all", "--quiet", "--no-trunc", "--filter", `ancestor=${selected.configDigest}`],
  ]);
});

test("rejects swapped and malformed formatted or unformatted missing-image envelopes", async () => {
  const selected = plan();
  const cases = [
    {
      config: missingFormattedGraphImage(selected.configDigest),
      reference: missingFormattedGraphImage(selected.repoDigest),
    },
    {
      config: missingUnformattedGraphImage(selected.configDigest),
      reference: missingUnformattedGraphImage(selected.repoDigest),
    },
    {
      config: Object.freeze({
        ...missingUnformattedGraphImage(selected.configDigest),
        stdout: "[ ]\n",
      }),
      reference: missingFormattedGraphImage(selected.repoDigest),
    },
    {
      config: missingUnformattedGraphImage(selected.configDigest),
      reference: Object.freeze({
        ...missingFormattedGraphImage(selected.repoDigest),
        stdout: "\n\n",
      }),
    },
  ];
  const outcomes = [];
  for (const evidence of cases) {
    const system = graphSystem();
    system.runRaw = async (_command, arguments_) => arguments_.includes("--format") ?
      evidence.reference : evidence.config;
    system.runRead = async () => success();
    try {
      await system.requireGraphImageBaselineAbsent(selected, phase);
      outcomes.push("accepted");
    } catch (error) {
      outcomes.push(error?.name);
    }
  }
  assert.deepEqual(outcomes, ["Failure", "Failure", "Failure", "Failure"]);
});

test("final audit accepts exact provider-shaped graph image absence", async () => {
  const selected = plan("busybox", "linux/arm64");
  const system = graphSystem();
  system.graphImagePlans = new Map([[selected.name, selected]]);
  system.runRaw = async (_command, arguments_) => arguments_.includes("--format") ?
    missingFormattedGraphImage(arguments_.at(-1)) : missingUnformattedGraphImage(arguments_.at(-1));
  system.runRead = async () => success();

  await system.requireAdditionalGlobalAbsence(phase, "cleanup");
});

test("rejects malformed or signaled repository-digest baseline evidence", async () => {
  const selected = plan();
  const evidence = [
    success('[{"Id":"first","Id":"second"}]\n'),
    Object.freeze({ signal: "SIGTERM", status: null, stderr: "", stdout: "", thrown: false, timedOut: false }),
  ];
  const results = [];
  for (const repoDigestResult of evidence) {
    const system = graphSystem();
    system.runRaw = async (_command, arguments_) => {
      if (arguments_.at(-1) === selected.configDigest) {
        return missingUnformattedGraphImage(selected.configDigest);
      }
      assert.equal(arguments_.at(-1), selected.repoDigest);
      return repoDigestResult;
    };
    system.runRead = async () => success();
    try {
      await system.requireGraphImageBaselineAbsent(selected, phase);
      results.push("accepted");
    } catch (error) {
      results.push(error?.name);
    }
  }
  assert.deepEqual(results, ["Failure", "Failure"]);
});

test("final audit rejects an ambient repository digest when the selected config is absent", async () => {
  const selected = plan("busybox", "linux/arm64");
  const opposite = plan("busybox", "linux/amd64");
  const system = graphSystem();
  system.graphImagePlans = new Map([[selected.name, selected]]);
  system.runRaw = async (_command, arguments_) => {
    const reference = arguments_.at(-1);
    if (reference === selected.configDigest) return missingUnformattedGraphImage(reference);
    if (reference === selected.repoDigest) return success(`${JSON.stringify([
      opposite.configDigest,
      "amd64",
      "linux",
      [selected.repoDigest],
      [],
    ])}\n`);
    throw new Error("unexpected raw inspection");
  };
  system.runRead = async () => success();

  await assert.rejects(() => system.requireAdditionalGlobalAbsence(phase, "cleanup"), { name: "Failure" });
});

test("owns graph image aliases from exact baseline through ambiguity-safe cleanup", async () => {
  const selected = plan();
  const baselineInUse = graphSystem();
  let baselineInUsePulls = 0;
  baselineInUse.requireTemporaryOwnership = async () => {};
  baselineInUse.resolveGraphImage = async () => resolvedImage(selected);
  baselineInUse.runRaw = async (_command, arguments_) => arguments_.includes("--format") ?
    missingFormattedGraphImage(arguments_.at(-1)) : missingUnformattedGraphImage(arguments_.at(-1));
  baselineInUse.runRead = async (_command, arguments_) => arguments_[0] === "image" ? success() :
    success(`${"c".repeat(64)}\n`);
  baselineInUse.runMutation = async () => {
    baselineInUsePulls += 1;
    return { outcome: "applied", result: success() };
  };
  await assert.rejects(() => baselineInUse.buildAdditionalImages(phase), { name: "Failure" });
  assert.equal(baselineInUsePulls, 0, "consumer absence is also required before pull authority exists");

  const inUse = graphSystem();
  inUse.paths = { graphManifest: "/owned/graph.yaml" };
  inUse.requireTemporaryOwnership = async () => {};
  inUse.requireOwnedPath = async () => {};
  inUse.graphImageIdentities.set("neo4j", { id: selected.configDigest, name: "neo4j" });
  inUse.graphImageResolutions.set("neo4j", resolvedImage(selected));
  inUse.graphImageMayHaveApplied.add("neo4j");
  inUse.verifyGraphImage = async () => {};
  inUse.runRead = async (command, arguments_) => {
    assert.equal(command, "docker");
    assert.deepEqual(arguments_, [
      "ps", "--all", "--quiet", "--no-trunc", "--filter", `ancestor=${selected.configDigest}`,
    ]);
    return success(`${"b".repeat(64)}\n`);
  };
  let inUseMutations = 0;
  inUse.runMutation = async () => {
    inUseMutations += 1;
    return { outcome: "applied", result: success() };
  };
  const inUseFailures = [];
  await inUse.cleanupAdditionalImages(async (operation) => {
    try { await operation(); } catch (error) { inUseFailures.push(error); }
  }, phase);
  assert.equal(inUseMutations, 0, "an in-use retained config is never targeted");
  assert.equal(inUseFailures.length, 1);
  assert.equal(inUse.graphImageIdentities.has("neo4j"), true);

  const appeared = graphSystem();
  appeared.paths = { graphManifest: "/owned/graph.yaml" };
  appeared.requireTemporaryOwnership = async () => {};
  appeared.requireOwnedPath = async () => {};
  appeared.graphImageIdentities.set("neo4j", { id: selected.configDigest, name: "neo4j" });
  appeared.graphImageResolutions.set("neo4j", resolvedImage(selected));
  appeared.graphImageMayHaveApplied.add("neo4j");
  appeared.graphImageAliases.set("neo4j", { repoDigests: [selected.repoDigest], repoTags: [] });
  appeared.verifyGraphImage = async () => {};
  let appearedConsumerReads = 0;
  appeared.runRead = async (_command, arguments_) => {
    if (arguments_[0] === "ps") {
      appearedConsumerReads += 1;
      return appearedConsumerReads === 1 ? success() : success(`${"d".repeat(64)}\n`);
    }
    throw new Error("unexpected read");
  };
  await appeared.requireGraphImageConsumersAbsent(selected, phase, "ownership");
  const appearedRemovals = [];
  appeared.runMutation = async (_command, arguments_) => {
    appearedRemovals.push(arguments_);
    return { outcome: "ambiguous", result: success() };
  };
  const appearedFailures = [];
  await appeared.cleanupAdditionalImages(async (operation) => {
    try { await operation(); } catch (error) { appearedFailures.push(error); }
  }, phase);
  assert.deepEqual(appearedRemovals, []);
  assert.equal(appearedConsumerReads, 2, "consumer absence is re-proved immediately before digest deletion");
  assert.equal(appearedFailures.length, 1);
  assert.deepEqual(appeared.graphImageAliases.get("neo4j"), {
    repoDigests: [selected.repoDigest], repoTags: [],
  });

  const ambiguous = graphSystem();
  ambiguous.paths = { graphManifest: "/owned/graph.yaml" };
  ambiguous.requireTemporaryOwnership = async () => {};
  ambiguous.requireOwnedPath = async () => {};
  ambiguous.graphImageIdentities.set("neo4j", { id: selected.configDigest, name: "neo4j" });
  ambiguous.graphImageResolutions.set("neo4j", resolvedImage(selected));
  ambiguous.graphImageMayHaveApplied.add("neo4j");
  ambiguous.graphImageAliases.set("neo4j", { repoDigests: [selected.repoDigest], repoTags: [] });
  ambiguous.verifyGraphImage = async () => {};
  ambiguous.runRead = async (_command, arguments_) => {
    if (arguments_[0] === "ps") return success();
    if (arguments_[0] === "image" && arguments_[1] === "inspect") {
      return success(`${JSON.stringify([selected.configDigest, [selected.repoDigest], []])}\n`);
    }
    if (arguments_[0] === "image" && arguments_[1] === "ls") return success();
    throw new Error("unexpected read");
  };
  const removals = [];
  ambiguous.runMutation = async (_command, arguments_) => {
    removals.push(arguments_);
    return { outcome: "ambiguous", result: success("untagged\n") };
  };
  let imageReads = 0;
  ambiguous.runRaw = async (_command, arguments_) => {
    assert.deepEqual(arguments_, ["image", "inspect", selected.configDigest]);
    imageReads += 1;
    return imageReads === 1 ? success("[{\"Id\":\"delayed\"}]\n") : {
      ...success("[]\n", `Error response from daemon: No such image: ${selected.configDigest}\n`),
      status: 1,
    };
  };
  const ambiguousFailures = [];
  await ambiguous.cleanupAdditionalImages(async (operation) => {
    try { await operation(); } catch (error) { ambiguousFailures.push(error); }
  }, phase);
  assert.deepEqual(removals, [
    ["image", "rm", selected.repoDigest],
  ], "cleanup deletes only the digest alias created by this run without force-ID removal");
  assert.equal(imageReads, 2, "ambiguous alias removal reconciles bounded delayed config absence");
  assert.deepEqual(ambiguousFailures, []);
  assert.equal(ambiguous.graphImageIdentities.has("neo4j"), false);

  const definitive = graphSystem();
  definitive.paths = { graphManifest: "/owned/graph.yaml" };
  definitive.requireTemporaryOwnership = async () => {};
  definitive.requireOwnedPath = async () => {};
  definitive.graphImageIdentities.set("neo4j", { id: selected.configDigest, name: "neo4j" });
  definitive.graphImageResolutions.set("neo4j", resolvedImage(selected));
  definitive.graphImageMayHaveApplied.add("neo4j");
  definitive.graphImageAliases.set("neo4j", { repoDigests: [selected.repoDigest], repoTags: [] });
  definitive.verifyGraphImage = async () => {};
  definitive.runRead = async () => success();
  definitive.runMutation = async () => ({ outcome: "definitive", result: { ...success(), status: 1 } });
  let definitiveAbsenceReads = 0;
  definitive.runRaw = async () => {
    definitiveAbsenceReads += 1;
    return { ...success("[]\n", `Error: No such image: ${selected.configDigest}\n`), status: 1 };
  };
  const definitiveFailures = [];
  await definitive.cleanupAdditionalImages(async (operation) => {
    try { await operation(); } catch (error) { definitiveFailures.push(error); }
  }, phase);
  assert.equal(definitiveFailures.length, 1, "definitive failure wins over apparent later absence");
  assert.equal(definitiveAbsenceReads, 0);
  assert.equal(definitive.graphImageIdentities.has("neo4j"), true);
});

test("recovers an exact digest-only pull for cleanup without adopting a tag alias", async () => {
  const selected = plan();
  const system = graphSystem();
  system.graphImagePlans = new Map([[selected.name, selected]]);
  system.paths = { graphManifest: "/owned/graph.yaml" };
  system.graphImageResolutions.set(selected.name, resolvedImage(selected));
  system.graphImageMayHaveApplied.add(selected.name);
  system.requireTemporaryOwnership = async () => {};
  system.requireOwnedPath = async () => {};
  system.runRaw = async (_command, arguments_) => {
    assert.deepEqual(arguments_, ["image", "inspect", selected.repoDigest]);
    return success(`[${JSON.stringify({ Id: selected.configDigest })}]\n`);
  };
  const exactInspections = [];
  system.runRead = async (_command, arguments_) => {
    if (arguments_[0] === "image" && arguments_[1] === "inspect") {
      exactInspections.push(arguments_.at(-1));
      return success(`${JSON.stringify(pinnedGraphImageInspection(selected))}\n`);
    }
    if (arguments_[0] === "ps") return success();
    throw new Error("unexpected read");
  };
  const removals = [];
  system.runMutation = async (_command, arguments_) => {
    removals.push(arguments_);
    return { outcome: "ambiguous", result: success("untagged\n") };
  };
  system.requireGraphImageAbsent = async () => {};
  const failures = [];
  await system.cleanupAdditionalImages(async (operation) => {
    try { await operation(); } catch (error) { failures.push(error); }
  }, phase);

  assert.deepEqual(failures, []);
  assert.deepEqual(exactInspections, [selected.repoDigest, selected.configDigest],
    "recovery and immediate pre-delete proof both bind the digest alias");
  assert.deepEqual(removals, [["image", "rm", selected.repoDigest]]);
  assert.equal(system.graphImageIdentities.size, 0);
  assert.equal(system.graphImageMayHaveApplied.size, 0);
});

test("removes retained digest-only graph aliases in reverse order after exact reinspection", async () => {
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
    system.graphImageAliases.set(name, { repoDigests: [selected.repoDigest], repoTags: [] });
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
    `remove:registry.k8s.io/e2e-test-images/busybox@${GRAPH_IMAGE_PLANS.busybox.indexDigest}`,
    "absent:busybox",
    `verify:neo4j:sha256:${"7".repeat(64)}`,
    `remove:neo4j@${GRAPH_IMAGE_PLANS.neo4j.indexDigest}`,
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
