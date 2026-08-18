import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { PRODUCTS } from "./manifests.mjs";
import {
  BUSYBOX_IMAGE,
  GRAPH_CONSTANTS,
  NEO4J_IMAGE,
  buildGraphResources,
} from "./graph-manifest.mjs";
import { KIND_PINS, buildKindCreateArguments } from "./run.mjs";
import { buildObservabilityProfile } from "./observability-run.mjs";
import * as graphRunModule from "./graph-run.mjs";
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

function graphRawImportReference(name, platform = "linux/arm64", date = "2026-08-16") {
  return graphRawImportReferenceForDigest(plan(name, platform).manifestDigest, date);
}

function graphRawImportReferenceForDigest(digest, date = "2026-08-16") {
  return `import-${date}@${digest}`;
}

function graphImportRows(name, platform = "linux/arm64", wrapperDigest = `sha256:${"f".repeat(64)}`) {
  const selected = plan(name, platform);
  return [
    `${graphRawImportReferenceForDigest(wrapperDigest)} application/vnd.oci.image.index.v1+json ` +
      `${wrapperDigest} 457 MiB ${platform} managed=true`,
    `${graphRawImportReference(name, platform)} application/vnd.oci.image.manifest.v1+json ` +
      `${selected.manifestDigest} 456 MiB ${platform} managed=true`,
  ];
}

function graphImportTarget(name, platform = "linux/arm64", wrapperDigest = `sha256:${"f".repeat(64)}`) {
  const selected = plan(name, platform);
  const references = [
    {
      digest: wrapperDigest,
      labels: "managed=true",
      mediaType: "application/vnd.oci.image.index.v1+json",
      platform,
      reference: graphRawImportReferenceForDigest(wrapperDigest),
      size: "457 MiB",
    },
    {
      digest: selected.manifestDigest,
      labels: "managed=true",
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      platform,
      reference: graphRawImportReference(name, platform),
      size: "456 MiB",
    },
  ].sort((left, right) => left.reference.localeCompare(right.reference));
  return {
    imageID: `docker.io/library/${references[0].reference}`,
    manifestDigest: selected.manifestDigest,
    references,
  };
}

function graphArchiveImport(name, platform = "linux/arm64", mutate = () => {}) {
  const selected = plan(name, platform);
  const resolution = resolvedImage(selected);
  const retained = validateGraphImageInspection(
    projectedInspection(selected), selected, resolution,
  );
  const manifest = {
    config: {
      digest: selected.configDigest,
      mediaType: "application/vnd.oci.image.config.v1+json",
      size: resolution.manifest.config.size,
    },
    layers: retained.rootfs.Layers.map((digest, index) => ({
      digest,
      mediaType: "application/vnd.oci.image.layer.v1.tar",
      size: 1_024 + index,
    })),
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    schemaVersion: 2,
  };
  mutate({ manifest, phase: "manifest", retained, selected });
  const manifestSource = JSON.stringify(manifest);
  const manifestDigest = `sha256:${createHash("sha256").update(manifestSource).digest("hex")}`;
  const wrapper = {
    manifests: [{
      digest: manifestDigest,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      size: Buffer.byteLength(manifestSource),
    }],
    mediaType: "application/vnd.oci.image.index.v1+json",
    schemaVersion: 2,
  };
  mutate({ manifest, manifestDigest, phase: "wrapper", retained, selected, wrapper });
  const wrapperSource = JSON.stringify(wrapper);
  const wrapperDigest = `sha256:${createHash("sha256").update(wrapperSource).digest("hex")}`;
  const labels = "io.cri-containerd.image=managed,containerd.io/gc.ref.content=retained";
  const rows = [
    `${graphRawImportReferenceForDigest(manifestDigest)} application/vnd.oci.image.manifest.v1+json ` +
      `${manifestDigest} 456 MiB ${platform} io.cri-containerd.image=managed, ` +
      "containerd.io/gc.ref.content=retained",
    `${graphRawImportReferenceForDigest(wrapperDigest)} application/vnd.oci.image.index.v1+json ` +
      `${wrapperDigest} 457 MiB ${platform} io.cri-containerd.image=managed, ` +
      "containerd.io/gc.ref.content=retained",
    `${selected.configDigest} application/vnd.oci.image.manifest.v1+json ` +
      `${manifestDigest} 456 MiB ${platform} io.cri-containerd.image=managed, ` +
      "containerd.io/gc.ref.content=retained",
  ];
  const rawReferences = [
    {
      digest: manifestDigest,
      labels,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      platform,
      reference: graphRawImportReferenceForDigest(manifestDigest),
      size: "456 MiB",
    },
    {
      digest: wrapperDigest,
      labels,
      mediaType: "application/vnd.oci.image.index.v1+json",
      platform,
      reference: graphRawImportReferenceForDigest(wrapperDigest),
      size: "457 MiB",
    },
  ].sort((left, right) => left.reference.localeCompare(right.reference));
  const target = {
    imageID: `docker.io/library/${rawReferences[0].reference}`,
    manifestDigest: selected.manifestDigest,
    references: [
      ...rawReferences,
      {
        digest: manifestDigest,
        labels,
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        platform,
        reference: selected.configDigest,
        size: "456 MiB",
      },
    ],
  };
  return {
    manifestSource, retained, rows, selected, target, wrapperSource,
  };
}

function graphWorkloadReference(name, platform = "linux/arm64") {
  const selected = plan(name, platform);
  const tagged = selected.providerReference.slice(0, selected.providerReference.indexOf("@"));
  return `${tagged.slice(0, tagged.lastIndexOf(":"))}@${selected.indexDigest}`;
}

function graphBoundArchiveImport(name, platform = "linux/arm64", mutate = () => {}) {
  const fixture = graphArchiveImport(name, platform, mutate);
  const wrapper = fixture.target.references.find(({ mediaType }) => mediaType.endsWith("index.v1+json"));
  const alias = { ...wrapper, reference: graphWorkloadReference(name, platform) };
  const runtime = fixture.target.references[0];
  const runtimeAlias = { ...runtime, reference: `docker.io/library/${runtime.reference}` };
  const boundTarget = {
    ...fixture.target,
    imageID: alias.reference,
    references: [...fixture.target.references, alias],
  };
  return {
    ...fixture,
    alias,
    boundTarget,
    runtimeAlias,
    runtimeTarget: {
      ...boundTarget,
      imageID: `docker.io/library/${fixture.target.references[0].reference}`,
      references: [...boundTarget.references, runtimeAlias],
    },
  };
}

function containerdInventory(rows) {
  return ["REF TYPE DIGEST SIZE PLATFORMS LABELS", ...rows, ""].join("\n");
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

function graphSystem(command, dependencyOverrides = {}, profile = undefined) {
  return new LocalGraphSystem({
    home: "/Users/test",
    hostPlatform: "darwin/arm64",
    marker,
    nodePlatform: "linux/arm64",
    path: "/usr/local/bin:/usr/bin:/bin",
    repositoryRoot: "/repository",
  }, { ...graphDependencies(command), ...dependencyOverrides }, profile);
}

function providerLines(values) {
  return values.length === 0 ? "" : `${values.join("\n")}\n`;
}

function sharedGraphImageHarness(selected = plan(), overrides = {}) {
  const system = graphSystem();
  const state = {
    configPresent: overrides.configPresent ?? true,
    consumers: [...overrides.consumers ?? []],
    inspectionMutation: overrides.inspectionMutation,
    listedIds: [...overrides.listedIds ?? []],
    referenceId: overrides.referenceId ?? selected.configDigest,
    referencePresent: overrides.referencePresent ?? true,
    repoTags: [...overrides.repoTags ?? []],
  };
  const mutations = [];
  system.graphImagePlans = new Map([[selected.name, selected]]);
  system.paths = { graphManifest: "/owned/graph.yaml" };
  system.requireTemporaryOwnership = async () => {};
  system.requireOwnedPath = async () => {};
  system.resolveGraphImage = async () => resolvedImage(selected);
  system.runRaw = async (_command, arguments_) => {
    const reference = arguments_.at(-1);
    if (reference === selected.configDigest && !arguments_.includes("--format")) {
      return state.configPresent ? success(`[${JSON.stringify({ Id: selected.configDigest })}]\n`) :
        missingUnformattedGraphImage(reference);
    }
    if (reference === selected.repoDigest && arguments_.includes("--format")) {
      return state.referencePresent ? success(`${JSON.stringify([
        state.referenceId,
        selected.architecture,
        "linux",
        [selected.repoDigest],
        state.repoTags,
      ])}\n`) : missingFormattedGraphImage(reference);
    }
    throw new Error("unexpected raw graph image probe");
  };
  system.runRead = async (_command, arguments_) => {
    if (arguments_[0] === "image" && arguments_[1] === "inspect") {
      const inspection = structuredClone(pinnedGraphImageInspection(selected));
      inspection[4] = [...state.repoTags];
      state.inspectionMutation?.(inspection);
      return success(`${JSON.stringify(inspection)}\n`);
    }
    if (arguments_[0] === "image" && arguments_[1] === "ls") return success(providerLines(state.listedIds));
    if (arguments_[0] === "ps") return success(providerLines(state.consumers));
    throw new Error("unexpected shared graph image read");
  };
  system.runMutation = async (command, arguments_) => {
    mutations.push([command, ...arguments_]);
    return { outcome: "applied", result: success() };
  };
  return { mutations, state, system };
}

function graphResource(kind, name) {
  return buildGraphResources().find((value) => value.kind === kind && value.metadata.name === name);
}

function providerUid(index) {
  return `${index.toString(16).padStart(8, "0")}-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
}

function providerContainer(value) {
  const projected = {
    ...structuredClone(value),
    terminationMessagePath: "/dev/termination-log",
    terminationMessagePolicy: "File",
  };
  if (Array.isArray(projected.volumeMounts)) {
    projected.volumeMounts = projected.volumeMounts.map((mount) => {
      const item = { ...mount };
      if (item.readOnly === false) delete item.readOnly;
      return item;
    });
  }
  return projected;
}

function providerGraphTemplate(template, labels = template.metadata.labels) {
  return {
    metadata: { creationTimestamp: null, labels: structuredClone(labels) },
    spec: {
      ...structuredClone(template.spec),
      containers: template.spec.containers.map(providerContainer),
      schedulerName: "default-scheduler",
    },
  };
}

function providerGraphPodSpec(template, nodeName) {
  return {
    automountServiceAccountToken: template.spec.automountServiceAccountToken,
    containers: template.spec.containers.map(providerContainer),
    dnsPolicy: template.spec.dnsPolicy,
    enableServiceLinks: template.spec.enableServiceLinks,
    nodeName,
    preemptionPolicy: "PreemptLowerPriority",
    priority: 0,
    restartPolicy: template.spec.restartPolicy,
    schedulerName: "default-scheduler",
    securityContext: structuredClone(template.spec.securityContext),
    serviceAccount: "default",
    serviceAccountName: "default",
    terminationGracePeriodSeconds: template.spec.terminationGracePeriodSeconds,
    tolerations: [
      { effect: "NoExecute", key: "node.kubernetes.io/not-ready", operator: "Exists", tolerationSeconds: 300 },
      { effect: "NoExecute", key: "node.kubernetes.io/unreachable", operator: "Exists", tolerationSeconds: 300 },
    ],
    ...(template.spec.volumes === undefined ? {} : { volumes: structuredClone(template.spec.volumes).map((volume) => {
      if (volume.persistentVolumeClaim?.readOnly !== false) return volume;
      const item = structuredClone(volume);
      delete item.persistentVolumeClaim.readOnly;
      return item;
    }) }),
  };
}

function graphProviderState(overrides = {}) {
  const platform = overrides.platform ?? "linux/arm64";
  const busyboxImageTarget = graphBoundArchiveImport("busybox", platform).runtimeTarget;
  const neo4jImageTarget = graphBoundArchiveImport("neo4j", platform).runtimeTarget;
  const nodeName = overrides.nodeName ?? `zasp-m1-30b-${marker}-control-plane`;
  const deploymentResource = graphResource("Deployment", "neo4j");
  const serviceResource = graphResource("Service", "neo4j");
  const persistentVolumeResource = graphResource("PersistentVolume", GRAPH_CONSTANTS.persistentVolumeName);
  const persistentVolumeClaimResource = graphResource(
    "PersistentVolumeClaim", GRAPH_CONSTANTS.persistentVolumeClaimName,
  );
  const jobResource = graphResource("Job", "neo4j-health");
  const deploymentUid = providerUid(1);
  const replicaSetUid = providerUid(2);
  const podUid = overrides.podUid ?? providerUid(3);
  const serviceUid = providerUid(4);
  const endpointSliceUid = providerUid(5);
  const persistentVolumeUid = providerUid(6);
  const persistentVolumeClaimUid = providerUid(7);
  const jobUid = overrides.jobUid ?? providerUid(8);
  const healthPodUid = overrides.healthPodUid ?? providerUid(9);
  const hash = "abc123def4";
  const podName = overrides.podName ?? `neo4j-${hash}-pqrst`;
  const podIP = overrides.podIP ?? "10.244.0.20";
  const podStartedAt = overrides.podStartedAt ?? "2026-08-16T10:00:00Z";
  const podContainerID = overrides.podContainerID ?? `containerd://${"a".repeat(64)}`;
  const healthLabels = {
    ...jobResource.spec.template.metadata.labels,
    "batch.kubernetes.io/controller-uid": jobUid,
    "batch.kubernetes.io/job-name": "neo4j-health",
    "controller-uid": jobUid,
    "job-name": "neo4j-health",
  };
  const replicaSetLabels = {
    ...deploymentResource.metadata.labels,
    "pod-template-hash": hash,
  };
  const deployment = {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: {
      generation: 1,
      labels: structuredClone(deploymentResource.metadata.labels),
      name: "neo4j",
      namespace: "zasp-local",
      resourceVersion: "101",
      uid: deploymentUid,
    },
    spec: {
      ...structuredClone(deploymentResource.spec),
      template: providerGraphTemplate(deploymentResource.spec.template),
    },
    status: {
      availableReplicas: 1,
      conditions: [{ status: "True", type: "Available" }],
      observedGeneration: 1,
      readyReplicas: 1,
      replicas: 1,
      unavailableReplicas: 0,
      updatedReplicas: 1,
    },
  };
  const replicaSet = {
    apiVersion: "apps/v1",
    kind: "ReplicaSet",
    metadata: {
      labels: replicaSetLabels,
      name: `neo4j-${hash}`,
      namespace: "zasp-local",
      ownerReferences: [{
        apiVersion: "apps/v1",
        blockOwnerDeletion: true,
        controller: true,
        kind: "Deployment",
        name: "neo4j",
        uid: deploymentUid,
      }],
      resourceVersion: "102",
      uid: replicaSetUid,
    },
    spec: {
      replicas: 1,
      selector: { matchLabels: { "app.kubernetes.io/name": "neo4j", "pod-template-hash": hash } },
      template: providerGraphTemplate(deploymentResource.spec.template, replicaSetLabels),
    },
    status: {
      availableReplicas: 1,
      fullyLabeledReplicas: 1,
      observedGeneration: 1,
      readyReplicas: 1,
      replicas: 1,
    },
  };
  const pod = {
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
      labels: replicaSetLabels,
      name: podName,
      namespace: "zasp-local",
      ownerReferences: [{
        apiVersion: "apps/v1",
        blockOwnerDeletion: true,
        controller: true,
        kind: "ReplicaSet",
        name: replicaSet.metadata.name,
        uid: replicaSetUid,
      }],
      resourceVersion: "103",
      uid: podUid,
    },
    spec: providerGraphPodSpec(deploymentResource.spec.template, nodeName),
    status: {
      conditions: [{ status: "True", type: "Ready" }],
      containerStatuses: [{
        containerID: podContainerID,
        image: GRAPH_IMAGE_PLANS.neo4j.platforms[platform].configDigest,
        imageID: neo4jImageTarget.imageID,
        lastState: {},
        name: "neo4j",
        ready: true,
        restartCount: 0,
        started: true,
        state: { running: { startedAt: podStartedAt } },
      }],
      phase: "Running",
      podIP,
    },
  };
  const service = {
    apiVersion: "v1",
    kind: "Service",
    metadata: {
      labels: structuredClone(serviceResource.metadata.labels),
      name: "neo4j",
      namespace: "zasp-local",
      resourceVersion: "104",
      uid: serviceUid,
    },
    spec: {
      clusterIP: "10.96.0.20",
      clusterIPs: ["10.96.0.20"],
      internalTrafficPolicy: "Cluster",
      ...structuredClone(serviceResource.spec),
    },
    status: { loadBalancer: {} },
  };
  const endpointSlice = {
    addressType: "IPv4",
    apiVersion: "discovery.k8s.io/v1",
    endpoints: [{
      addresses: [podIP],
      conditions: { ready: true, serving: true, terminating: false },
      nodeName,
      targetRef: { kind: "Pod", name: podName, namespace: "zasp-local", uid: podUid },
    }],
    kind: "EndpointSlice",
    metadata: {
      labels: {
        "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
        "kubernetes.io/service-name": "neo4j",
      },
      name: "neo4j-abcde",
      namespace: "zasp-local",
      ownerReferences: [{
        apiVersion: "v1",
        blockOwnerDeletion: true,
        controller: true,
        kind: "Service",
        name: "neo4j",
        uid: serviceUid,
      }],
      resourceVersion: "105",
      uid: endpointSliceUid,
    },
    ports: [
      { name: "bolt", port: 7687, protocol: "TCP" },
      { name: "http", port: 7474, protocol: "TCP" },
    ],
  };
  const persistentVolumeClaim = {
    apiVersion: "v1",
    kind: "PersistentVolumeClaim",
    metadata: {
      labels: structuredClone(persistentVolumeClaimResource.metadata.labels),
      name: GRAPH_CONSTANTS.persistentVolumeClaimName,
      namespace: "zasp-local",
      resourceVersion: "107",
      uid: persistentVolumeClaimUid,
    },
    spec: structuredClone(persistentVolumeClaimResource.spec),
    status: { accessModes: ["ReadWriteOnce"], capacity: { storage: "1Gi" }, phase: "Bound" },
  };
  const persistentVolume = {
    apiVersion: "v1",
    kind: "PersistentVolume",
    metadata: {
      labels: structuredClone(persistentVolumeResource.metadata.labels),
      name: GRAPH_CONSTANTS.persistentVolumeName,
      resourceVersion: "106",
      uid: persistentVolumeUid,
    },
    spec: {
      ...structuredClone(persistentVolumeResource.spec),
      claimRef: {
        ...structuredClone(persistentVolumeResource.spec.claimRef),
        resourceVersion: "105",
        uid: persistentVolumeClaimUid,
      },
    },
    status: { lastPhaseTransitionTime: "2026-08-16T09:59:59Z", phase: "Bound" },
  };
  const jobTemplate = providerGraphTemplate(jobResource.spec.template, healthLabels);
  const job = {
    apiVersion: "batch/v1",
    kind: "Job",
    metadata: {
      labels: structuredClone(jobResource.metadata.labels),
      name: "neo4j-health",
      namespace: "zasp-local",
      resourceVersion: "108",
      uid: jobUid,
    },
    spec: {
      activeDeadlineSeconds: jobResource.spec.activeDeadlineSeconds,
      backoffLimit: 0,
      completionMode: "NonIndexed",
      completions: 1,
      manualSelector: false,
      parallelism: 1,
      selector: { matchLabels: { "batch.kubernetes.io/controller-uid": jobUid } },
      suspend: false,
      template: jobTemplate,
    },
    status: {
      completionTime: overrides.healthCompletionTime ?? "2026-08-16T10:00:06Z",
      conditions: [{
        lastProbeTime: "2026-08-16T10:00:06Z",
        lastTransitionTime: "2026-08-16T10:00:06Z",
        status: "True",
        type: "Complete",
      }],
      failed: 0,
      ready: 0,
      startTime: overrides.healthJobStartedAt ?? "2026-08-16T10:00:02Z",
      succeeded: 1,
    },
  };
  const healthPodName = overrides.healthPodName ?? "neo4j-health-fghij";
  const healthPod = {
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
      labels: healthLabels,
      name: healthPodName,
      namespace: "zasp-local",
      ownerReferences: [{
        apiVersion: "batch/v1",
        blockOwnerDeletion: true,
        controller: true,
        kind: "Job",
        name: "neo4j-health",
        uid: jobUid,
      }],
      resourceVersion: "109",
      uid: healthPodUid,
    },
    spec: providerGraphPodSpec(jobResource.spec.template, nodeName),
    status: {
      conditions: [{ status: "False", type: "Ready" }],
      containerStatuses: [{
        containerID: overrides.healthContainerID ?? `containerd://${"b".repeat(64)}`,
        image: GRAPH_IMAGE_PLANS.busybox.platforms[platform].configDigest,
        imageID: busyboxImageTarget.imageID,
        lastState: {},
        name: "health",
        ready: false,
        restartCount: 0,
        started: false,
        state: { terminated: {
          containerID: overrides.healthContainerID ?? `containerd://${"b".repeat(64)}`,
          exitCode: 0,
          finishedAt: overrides.healthFinishedAt ?? "2026-08-16T10:00:05Z",
          reason: "Completed",
          startedAt: overrides.healthPodStartedAt ?? "2026-08-16T10:00:03Z",
        } },
      }],
      phase: "Succeeded",
      podIP: "10.244.0.21",
    },
  };
  const productItems = (kind) => PRODUCTS.map((product, index) => ({
    apiVersion: kind === "Deployment" || kind === "ReplicaSet" ? "apps/v1" : "v1",
    kind,
    metadata: {
      labels: kind === "EndpointSlice"
        ? { "kubernetes.io/service-name": product.name }
        : { "app.kubernetes.io/name": product.name },
      name: kind === "EndpointSlice" ? `${product.name}-abcde` : product.name,
      uid: providerUid(20 + index),
    },
  }));
  return {
    deployments: [...productItems("Deployment"), deployment],
    endpointSlices: [...productItems("EndpointSlice"), endpointSlice],
    healthLog: "neo4j-health-ready\n",
    ingresses: [],
    jobs: [job],
    persistentVolumeClaims: [persistentVolumeClaim],
    persistentVolumes: [persistentVolume],
    pods: [...productItems("Pod"), pod, healthPod],
    replicaSets: [...productItems("ReplicaSet"), replicaSet],
    services: [...productItems("Service"), service],
  };
}

function graphProviderExpectation(platform = "linux/arm64") {
  return {
    imageTargets: {
      busybox: graphBoundArchiveImport("busybox", platform).runtimeTarget,
      neo4j: graphBoundArchiveImport("neo4j", platform).runtimeTarget,
    },
    nodeName: `zasp-m1-30b-${marker}-control-plane`,
  };
}

function graphProviderAbsence(absent, retained) {
  return { absent, retained };
}

function graphProviderStateWithout(kind, overrides = {}) {
  const value = graphProviderState(overrides);
  if (kind === "neo4j") {
    value.pods = value.pods.filter((item) =>
      item?.metadata?.labels?.["app.kubernetes.io/name"] !== "neo4j");
    value.endpointSlices.at(-1).endpoints = [];
  } else if (kind === "health") {
    value.jobs = [];
    value.pods = value.pods.filter((item) =>
      item?.metadata?.labels?.["app.kubernetes.io/name"] !== "neo4j-health");
    value.healthLog = null;
  } else {
    throw new TypeError("unknown graph provider absence");
  }
  return value;
}

function productProviderSnapshot(value) {
  const names = new Set(PRODUCTS.map(({ name }) => name));
  return {
    deployments: value.deployments.filter((item) => names.has(item?.metadata?.name)),
    endpointSlices: value.endpointSlices.filter((item) =>
      names.has(item?.metadata?.labels?.["kubernetes.io/service-name"])),
    pods: value.pods.filter((item) => names.has(item?.metadata?.labels?.["app.kubernetes.io/name"])),
    replicaSets: value.replicaSets.filter((item) =>
      names.has(item?.metadata?.labels?.["app.kubernetes.io/name"])),
    services: value.services.filter((item) => names.has(item?.metadata?.name)),
  };
}

test("normalizes one exact Bound graph lineage with internal health evidence", () => {
  const snapshot = graphRunModule.validateGraphKubernetesState(
    graphProviderState(), graphProviderExpectation(),
  );
  assert.deepEqual(snapshot, {
    health: {
      completionTime: "2026-08-16T10:00:06Z",
      jobStartedAt: "2026-08-16T10:00:02Z",
      jobUid: providerUid(8),
      podFinishedAt: "2026-08-16T10:00:05Z",
      podName: "neo4j-health-fghij",
      podStartedAt: "2026-08-16T10:00:03Z",
      podUid: providerUid(9),
    },
    internal: true,
    neo4j: {
      containerID: `containerd://${"a".repeat(64)}`,
      deploymentUid: providerUid(1),
      endpointSliceUid: providerUid(5),
      persistentVolumeClaimUid: providerUid(7),
      persistentVolumeUid: providerUid(6),
      podIP: "10.244.0.20",
      podName: "neo4j-abc123def4-pqrst",
      podUid: providerUid(3),
      replicaSetUid: providerUid(2),
      serviceUid: providerUid(4),
      startedAt: "2026-08-16T10:00:00Z",
    },
    ready: true,
  });
  assert.ok(Object.isFrozen(snapshot));
  assert.ok(Object.isFrozen(snapshot.neo4j));
});

test("accepts the exact M1-30d node throughout graph provider validation", () => {
  const nodeName = `zasp-m1-30d-${marker}-control-plane`;
  const expected = graphProviderExpectation();
  expected.nodeName = nodeName;
  assert.equal(graphRunModule.validateGraphKubernetesState(
    graphProviderState({ nodeName }), expected,
  ).ready, true);
});

test("cross-binds config status images and final imported image IDs on both node platforms", () => {
  for (const platform of ["linux/amd64", "linux/arm64"]) {
    const value = graphProviderState({ platform });
    const expected = graphProviderExpectation(platform);
    assert.equal(value.pods.at(-2).spec.containers[0].image, NEO4J_IMAGE);
    assert.equal(value.pods.at(-1).spec.containers[0].image, BUSYBOX_IMAGE);
    assert.equal(value.pods.at(-2).status.containerStatuses[0].image,
      GRAPH_IMAGE_PLANS.neo4j.platforms[platform].configDigest);
    assert.equal(value.pods.at(-1).status.containerStatuses[0].image,
      GRAPH_IMAGE_PLANS.busybox.platforms[platform].configDigest);
    assert.equal(graphRunModule.validateGraphKubernetesState(value, expected).ready, true, platform);

    for (const [podIndex, image] of [[-2, "neo4j"], [-1, "busybox"]]) {
      const selected = GRAPH_IMAGE_PLANS[image];
      for (const imageID of [
        selected.platforms[platform].configDigest,
        selected.indexDigest,
        selected.platforms[platform].manifestDigest,
        `${selected.repository}@${selected.indexDigest}`,
        `${selected.repository}@${selected.platforms[platform].manifestDigest}`,
        `${selected.repository}@${selected.platforms[platform].configDigest}`,
        expected.imageTargets[image].references[1].reference,
      ]) {
        if (imageID === expected.imageTargets[image].imageID) continue;
        const drifted = structuredClone(value);
        drifted.pods.at(podIndex).status.containerStatuses[0].imageID = imageID;
        assert.throws(() => graphRunModule.validateGraphKubernetesState(drifted, expected),
          { name: "Failure" }, `${image} ${platform} ${imageID}`);
        if (imageID !== selected.platforms[platform].configDigest) {
          const imageDrifted = structuredClone(value);
          imageDrifted.pods.at(podIndex).status.containerStatuses[0].image = imageID;
          assert.throws(() => graphRunModule.validateGraphKubernetesState(imageDrifted, expected),
            { name: "Failure" }, `${image} ${platform} status image ${imageID}`);
        }
      }
    }
  }
});

test("rejects every intermediate graph image target at the Kubernetes boundary", () => {
  for (const platform of ["linux/amd64", "linux/arm64"]) {
    for (const [podIndex, image] of [[-2, "neo4j"], [-1, "busybox"]]) {
      const fixture = graphBoundArchiveImport(image, platform);
      for (const target of [graphImportTarget(image, platform), fixture.target, fixture.boundTarget]) {
        const value = graphProviderState({ platform });
        const expected = graphProviderExpectation(platform);
        expected.imageTargets[image] = target;
        value.pods.at(podIndex).status.containerStatuses[0].imageID = target.imageID;
        assert.throws(() => graphRunModule.validateGraphKubernetesState(value, expected),
          { name: "Failure" }, `${image} ${platform} ${target.references.length} rows`);
      }
    }
  }
});

test("cross-binds the exact normalized CRI manifest identities for Docker archive imports", () => {
  for (const platform of ["linux/amd64", "linux/arm64"]) {
    const value = graphProviderState({ platform });
    const expected = graphProviderExpectation(platform);
    for (const [podIndex, image] of [[-2, "neo4j"], [-1, "busybox"]]) {
      const fixture = graphBoundArchiveImport(image, platform);
      expected.imageTargets[image] = fixture.runtimeTarget;
      value.pods.at(podIndex).status.containerStatuses[0].imageID = fixture.runtimeTarget.imageID;
    }
    assert.equal(graphRunModule.validateGraphKubernetesState(value, expected).ready, true, platform);

    for (const [podIndex, image] of [[-2, "neo4j"], [-1, "busybox"]]) {
      const fixture = graphBoundArchiveImport(image, platform);
      for (const alternate of [
        fixture.alias.reference,
        fixture.runtimeAlias.reference,
        fixture.runtimeAlias.reference.slice("docker.io/library/".length),
        fixture.selected.configDigest,
        fixture.selected.manifestDigest,
        fixture.selected.repoDigest,
      ].filter((reference) => reference !== fixture.runtimeTarget.imageID)) {
        const drifted = structuredClone(value);
        drifted.pods.at(podIndex).status.containerStatuses[0].imageID = alternate;
        assert.throws(() => graphRunModule.validateGraphKubernetesState(drifted, expected),
          { name: "Failure" }, `${image} ${platform} ${alternate}`);
      }
    }
  }
});

test("accepts both exact graph EndpointSlice port orderings", () => {
  const http = { name: "http", port: 7474, protocol: "TCP" };
  const bolt = { name: "bolt", port: 7687, protocol: "TCP" };
  for (const ports of [[http, bolt], [bolt, http]]) {
    const value = graphProviderState();
    value.endpointSlices.at(-1).ports = structuredClone(ports);
    assert.equal(
      graphRunModule.validateGraphKubernetesState(value, graphProviderExpectation()).ready,
      true,
      ports.map(({ name }) => name).join(","),
    );
  }
});

test("rejects every graph provider identity, lineage, storage, health, and exposure drift", () => {
  const cases = [
    ["unknown snapshot key", (value) => { value.unexpected = true; }],
    ["missing deployment", (value) => { value.deployments.pop(); }],
    ["extra service", (value) => { value.services.push(structuredClone(value.services.at(-1))); }],
    ["duplicate pod", (value) => { value.pods.push(structuredClone(value.pods.at(-2))); }],
    ["PV phase", (value) => { value.persistentVolumes[0].status.phase = "Available"; }],
    ["missing PV transition", (value) => {
      delete value.persistentVolumes[0].status.lastPhaseTransitionTime;
    }],
    ["malformed PV transition", (value) => {
      value.persistentVolumes[0].status.lastPhaseTransitionTime = "2026-02-30T00:00:00Z";
    }],
    ["unknown PV status", (value) => { value.persistentVolumes[0].status.foreign = true; }],
    ["PVC phase", (value) => { value.persistentVolumeClaims[0].status.phase = "Pending"; }],
    ["missing claim reference version", (value) => {
      delete value.persistentVolumes[0].spec.claimRef.resourceVersion;
    }],
    ["malformed claim reference version", (value) => {
      value.persistentVolumes[0].spec.claimRef.resourceVersion = "0";
    }],
    ["current claim reference version", (value) => {
      value.persistentVolumes[0].spec.claimRef.resourceVersion =
        value.persistentVolumeClaims[0].metadata.resourceVersion;
    }],
    ["claim UID", (value) => { value.persistentVolumes[0].spec.claimRef.uid = providerUid(99); }],
    ["claim reference name", (value) => { value.persistentVolumes[0].spec.claimRef.name = "foreign"; }],
    ["claim name", (value) => { value.persistentVolumeClaims[0].spec.volumeName = "foreign"; }],
    ["resource version", (value) => { value.deployments.at(-1).metadata.resourceVersion = "0"; }],
    ["deployment UID", (value) => { value.deployments.at(-1).metadata.uid = providerUid(99); }],
    ["non-null template timestamp", (value) => {
      value.deployments.at(-1).spec.template.metadata.creationTimestamp = "2026-08-16T10:00:00Z";
    }],
    ["unknown template metadata", (value) => {
      value.deployments.at(-1).spec.template.metadata.foreign = true;
    }],
    ["replica set owner", (value) => { value.replicaSets.at(-1).metadata.ownerReferences[0].uid = providerUid(99); }],
    ["replica set selector", (value) => {
      value.replicaSets.at(-1).spec.selector.matchLabels["pod-template-hash"] = "ffffffffff";
    }],
    ["pod owner", (value) => { value.pods.at(-2).metadata.ownerReferences[0].uid = providerUid(99); }],
    ["pod node", (value) => { value.pods.at(-2).spec.nodeName = "foreign"; }],
    ["pod image", (value) => { value.pods.at(-2).spec.containers[0].image = "neo4j:latest"; }],
    ["pod image ID", (value) => { value.pods.at(-2).status.containerStatuses[0].imageID = "foreign"; }],
    ["pod volume", (value) => {
      value.pods.at(-2).spec.volumes[0].persistentVolumeClaim.claimName = "foreign";
    }],
    ["pod host network", (value) => { value.pods.at(-2).spec.hostNetwork = true; }],
    ["pod host port", (value) => { value.pods.at(-2).spec.containers[0].ports[0].hostPort = 7474; }],
    ["pod restart", (value) => { value.pods.at(-2).status.containerStatuses[0].restartCount = 1; }],
    ["pod last state", (value) => {
      value.pods.at(-2).status.containerStatuses[0].lastState = {
        terminated: { exitCode: 1, reason: "Error" },
      };
    }],
    ["pod condition", (value) => { value.pods.at(-2).status.conditions[0].status = "False"; }],
    ["pod timestamp", (value) => {
      value.pods.at(-2).status.containerStatuses[0].state.running.startedAt = "2026-02-30T00:00:00Z";
    }],
    ["service exposure", (value) => { value.services.at(-1).spec.type = "NodePort"; }],
    ["external IP", (value) => { value.services.at(-1).spec.externalIPs = ["127.0.0.1"]; }],
    ["endpoint owner", (value) => {
      value.endpointSlices.at(-1).metadata.ownerReferences[0].uid = providerUid(99);
    }],
    ["alternate peer", (value) => { value.endpointSlices.at(-1).endpoints[0].addresses = ["10.244.0.99"]; }],
    ["endpoint target", (value) => { value.endpointSlices.at(-1).endpoints[0].targetRef.uid = providerUid(99); }],
    ["endpoint condition", (value) => { value.endpointSlices.at(-1).endpoints[0].conditions.ready = false; }],
    ["endpoint port duplicate", (value) => {
      value.endpointSlices.at(-1).ports[1] = structuredClone(value.endpointSlices.at(-1).ports[0]);
    }],
    ["endpoint port extra", (value) => {
      value.endpointSlices.at(-1).ports.push({ name: "foreign", port: 9999, protocol: "TCP" });
    }],
    ["endpoint port value", (value) => { value.endpointSlices.at(-1).ports[0].port = 9999; }],
    ["endpoint port key", (value) => { value.endpointSlices.at(-1).ports[0].appProtocol = "foreign"; }],
    ["job owner", (value) => { value.pods.at(-1).metadata.ownerReferences[0].uid = providerUid(99); }],
    ["job status", (value) => { value.jobs[0].status.succeeded = 0; }],
    ["job timestamp", (value) => { value.jobs[0].status.completionTime = "2026-13-01T00:00:00Z"; }],
    ["health image", (value) => { value.pods.at(-1).spec.containers[0].image = "busybox:latest"; }],
    ["health restart", (value) => { value.pods.at(-1).status.containerStatuses[0].restartCount = 1; }],
    ["health log", (value) => { value.healthLog = "neo4j-health-ready\nforeign\n"; }],
    ["ingress", (value) => { value.ingresses.push({ kind: "Ingress" }); }],
  ];
  const results = [];
  for (const [name, mutate] of cases) {
    const value = structuredClone(graphProviderState());
    mutate(value);
    try {
      graphRunModule.validateGraphKubernetesState(value, graphProviderExpectation());
      results.push(`${name}:accepted`);
    } catch (error) {
      results.push(`${name}:${error?.name}`);
    }
  }
  assert.deepEqual(results, cases.map(([name]) => `${name}:Failure`));
});

test("accepts only an exact replacement pod UID on the retained graph lineage", () => {
  const initial = graphRunModule.validateGraphKubernetesState(
    graphProviderState(), graphProviderExpectation(),
  );
  const replacementState = graphProviderState({
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  });
  const replacement = graphRunModule.validateGraphKubernetesState(
    replacementState, graphProviderExpectation(), initial, true,
  );
  assert.equal(replacement.neo4j.podUid, providerUid(10));
  assert.equal(replacement.neo4j.persistentVolumeUid, initial.neo4j.persistentVolumeUid);
  assert.equal(replacement.neo4j.persistentVolumeClaimUid, initial.neo4j.persistentVolumeClaimUid);
  for (const [name, mutate] of [
    ["reused pod UID", (value) => { value.pods.at(-2).metadata.uid = initial.neo4j.podUid; }],
    ["reused pod name", (value) => {
      value.pods.at(-2).metadata.name = initial.neo4j.podName;
      value.endpointSlices.at(-1).endpoints[0].targetRef.name = initial.neo4j.podName;
    }],
    ["reused container ID", (value) => {
      value.pods.at(-2).status.containerStatuses[0].containerID = initial.neo4j.containerID;
    }],
    ["equal start", (value) => {
      value.pods.at(-2).status.containerStatuses[0].state.running.startedAt = initial.neo4j.startedAt;
    }],
    ["earlier start", (value) => {
      value.pods.at(-2).status.containerStatuses[0].state.running.startedAt = "2026-08-16T09:59:59Z";
    }],
    ["PV UID", (value) => { value.persistentVolumes[0].metadata.uid = providerUid(11); }],
    ["PVC UID", (value) => { value.persistentVolumeClaims[0].metadata.uid = providerUid(12); }],
    ["deployment UID", (value) => { value.deployments.at(-1).metadata.uid = providerUid(13); }],
    ["replica set UID", (value) => { value.replicaSets.at(-1).metadata.uid = providerUid(14); }],
    ["service UID", (value) => { value.services.at(-1).metadata.uid = providerUid(15); }],
    ["endpoint slice UID", (value) => { value.endpointSlices.at(-1).metadata.uid = providerUid(16); }],
  ]) {
    const drifted = structuredClone(replacementState);
    mutate(drifted);
    assert.throws(() => graphRunModule.validateGraphKubernetesState(
      drifted, graphProviderExpectation(), initial, true,
    ), { name: "Failure" }, name);
  }
});

test("accepts only a fresh completed health Job after the replacement pod starts", () => {
  const initial = graphRunModule.validateGraphKubernetesState(
    graphProviderState(), graphProviderExpectation(),
  );
  const replacementState = graphProviderState({
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  });
  const replacement = graphRunModule.validateGraphKubernetesState(
    replacementState, graphProviderExpectation(), initial, true,
  );
  const freshState = graphProviderState({
    healthCompletionTime: "2026-08-16T10:00:16Z",
    healthContainerID: `containerd://${"d".repeat(64)}`,
    healthFinishedAt: "2026-08-16T10:00:15Z",
    healthJobStartedAt: "2026-08-16T10:00:12Z",
    healthPodName: "neo4j-health-klmno",
    healthPodStartedAt: "2026-08-16T10:00:13Z",
    healthPodUid: providerUid(12),
    jobUid: providerUid(11),
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  });
  const fresh = graphRunModule.validateGraphKubernetesState(
    freshState, graphProviderExpectation(), replacement, false, true,
  );
  assert.equal(fresh.health.jobUid, providerUid(11));
  assert.equal(fresh.health.podUid, providerUid(12));
  for (const [name, mutate] of [
    ["reused Job UID", (value) => { value.jobs[0].metadata.uid = replacement.health.jobUid; }],
    ["reused health Pod UID", (value) => { value.pods.at(-1).metadata.uid = replacement.health.podUid; }],
    ["early Job start", (value) => { value.jobs[0].status.startTime = replacement.neo4j.startedAt; }],
    ["early health start", (value) => {
      value.pods.at(-1).status.containerStatuses[0].state.terminated.startedAt = replacement.neo4j.startedAt;
    }],
    ["early completion", (value) => { value.jobs[0].status.completionTime = replacement.neo4j.startedAt; }],
  ]) {
    const drifted = structuredClone(freshState);
    mutate(drifted);
    assert.throws(() => graphRunModule.validateGraphKubernetesState(
      drifted, graphProviderExpectation(), replacement, false, true,
    ), { name: "Failure" }, name);
  }
});

test("parses only one bounded unique-key Kubernetes List envelope", () => {
  const exact = '{"apiVersion":"v1","items":[],"kind":"List","metadata":{"resourceVersion":""}}\n';
  assert.deepEqual(graphRunModule.parseGraphProviderList(exact, "pods"), []);
  for (const source of [
    '',
    '{"apiVersion":"v1","items":[],"items":[],"kind":"List","metadata":{"resourceVersion":""}}\n',
    '{"apiVersion":"v1","items":[],"kind":"List","metadata":{"resourceVersion":"1"}}\n',
    '{"apiVersion":"v1","items":[],"kind":"List","metadata":{"resourceVersion":""},"extra":true}\n',
    `${" ".repeat(4_194_305)}\n`,
  ]) assert.throws(() => graphRunModule.parseGraphProviderList(source, "pods"), { name: "Failure" });
});

test("projects only an omitted or null pod-template timestamp before inherited product validation", async () => {
  const raw = {
    apiVersion: "v1",
    items: [{
      spec: { template: { metadata: {
        creationTimestamp: null,
        labels: { "app.kubernetes.io/name": "audit-api" },
      }, spec: {} } },
    }],
    kind: "List",
    metadata: { resourceVersion: "" },
  };
  const read = async (document) => {
    let invocation;
    const system = graphSystem(async (command, arguments_) => {
      invocation = [command, ...arguments_];
      return success(`${JSON.stringify(document)}\n`);
    });
    system.paths = { kubeconfig: "/owned/kubeconfig" };
    system.productProviderProjection = true;
    system.productProviderCapture = new Map();
    system.withOwnedFiles = async (_paths, _phase, _category, operation) =>
      await operation([{ handle: { fd: 31 } }]);
    system.requireOwnedPath = async () => {};
    const result = await system.runKubectlRead([
      "get", "deployment", "--namespace", "zasp-local", "--output=json",
    ], phase, "readiness", 30_000, 4_194_304);
    return { invocation, result, system };
  };
  const { invocation, result, system } = await read(raw);
  assert.deepEqual(invocation, [
    "kubectl", "--kubeconfig", "/dev/fd/3", "get", "deployment", "--namespace", "zasp-local",
    "--selector=app.kubernetes.io/component!=graph", "--output=json",
  ]);
  assert.deepEqual(JSON.parse(result.stdout).items[0].spec.template.metadata,
    { labels: { "app.kubernetes.io/name": "audit-api" } });
  assert.deepEqual(system.productProviderCapture.get("deployments"), raw.items);

  const omitted = structuredClone(raw);
  delete omitted.items[0].spec.template.metadata.creationTimestamp;
  const omittedRead = await read(omitted);
  assert.deepEqual(JSON.parse(omittedRead.result.stdout).items[0].spec.template.metadata,
    { labels: { "app.kubernetes.io/name": "audit-api" } });
  assert.deepEqual(omittedRead.system.productProviderCapture.get("deployments"), omitted.items);

  for (const mutate of [
    (value) => { value.items[0].spec.template.metadata.creationTimestamp = "2026-08-16T10:00:00Z"; },
    (value) => { value.items[0].spec.template.metadata.foreign = true; },
  ]) {
    const drifted = structuredClone(raw);
    mutate(drifted);
    await assert.rejects(() => read(drifted), { category: "readiness", name: "Failure" });
  }
});

test("the observability profile excludes graph and observability resources from product projection", async () => {
  const document = {
    apiVersion: "v1",
    items: [{
      spec: { template: { metadata: { labels: { "app.kubernetes.io/name": "audit-api" } }, spec: {} } },
    }],
    kind: "List",
    metadata: { resourceVersion: "" },
  };
  let invocation;
  const system = graphSystem(async (command, arguments_) => {
    invocation = [command, ...arguments_];
    return success(`${JSON.stringify(document)}\n`);
  }, {}, buildObservabilityProfile());
  system.paths = { kubeconfig: "/owned/kubeconfig" };
  system.productProviderProjection = true;
  system.productProviderCapture = new Map();
  system.withOwnedFiles = async (_paths, _phase, _category, operation) =>
    await operation([{ handle: { fd: 31 } }]);
  system.requireOwnedPath = async () => {};
  await system.runKubectlRead([
    "get", "deployment", "--namespace", "zasp-local", "--output=json",
  ], phase, "readiness", 30_000, 4_194_304);
  assert.deepEqual(invocation, [
    "kubectl", "--kubeconfig", "/dev/fd/3", "get", "deployment", "--namespace", "zasp-local",
    "--selector=app.kubernetes.io/component notin (graph,observability)", "--output=json",
  ]);
  assert.deepEqual(system.productProviderCapture.get("deployments"), document.items);
});

test("the observability profile preserves exact Collector reads during product projection", async () => {
  const cases = [
    ["deployment", "app.kubernetes.io/component=observability"],
    ["replicaset", "app.kubernetes.io/component=observability"],
    ["pod", "app.kubernetes.io/component=observability"],
    ["service", "app.kubernetes.io/component=observability"],
    ["endpointslice", "kubernetes.io/service-name=otel-collector"],
  ];
  for (const [resource, selector] of cases) {
    let invocation;
    const system = graphSystem(async (command, arguments_) => {
      invocation = [command, ...arguments_];
      return success('{"apiVersion":"v1","items":[],"kind":"List","metadata":{"resourceVersion":""}}\n');
    }, {}, buildObservabilityProfile());
    system.paths = { kubeconfig: "/owned/kubeconfig" };
    system.productProviderProjection = true;
    system.productProviderCapture = new Map();
    system.withOwnedFiles = async (_paths, _phase, _category, operation) =>
      await operation([{ handle: { fd: 31 } }]);
    system.requireOwnedPath = async () => {};
    const arguments_ = [
      "get", resource, "--namespace", "zasp-local", `--selector=${selector}`, "--output=json",
    ];
    await system.runKubectlRead(arguments_, phase, "readiness", 30_000, 4_194_304);
    assert.deepEqual(invocation, ["kubectl", "--kubeconfig", "/dev/fd/3", ...arguments_], resource);
    assert.equal(system.productProviderCapture.size, 0, resource);
  }
});

test("accepts only omitted or null graph workload template timestamps", () => {
  const omitted = graphProviderState();
  delete omitted.deployments.at(-1).spec.template.metadata.creationTimestamp;
  delete omitted.replicaSets.at(-1).spec.template.metadata.creationTimestamp;
  delete omitted.jobs[0].spec.template.metadata.creationTimestamp;
  assert.equal(graphRunModule.validateGraphKubernetesState(
    omitted, graphProviderExpectation(),
  ).ready, true);
});

test("uses fixed marker argv, UID-preconditioned deletes, and exact fresh health Job bytes", async () => {
  const system = graphSystem();
  const pod = { name: "neo4j-abc123def4-pqrst", uid: providerUid(3) };
  const health = { jobUid: providerUid(8), podName: "neo4j-health-fghij", podUid: providerUid(9) };
  const calls = [];
  system.paths = { kubeconfig: "/owned/kubeconfig" };
  system.environment = Object.freeze({ PATH: "/usr/bin:/bin" });
  system.requireOwnedPath = async () => {};
  system.withOwnedFiles = async (paths, _phase, _category, operation) => {
    assert.deepEqual(paths, [system.paths.kubeconfig]);
    return await operation([{ handle: { fd: 31 }, identity: { bytes: Buffer.from("kubeconfig") } }]);
  };
  system.runMutation = async (command, arguments_, _phase, category, options) => {
    calls.push({ arguments: arguments_, category, command, options });
    return { outcome: "ambiguous", result: success("provider acknowledgement\n") };
  };
  system.runKubectlRead = async (arguments_, _phase, category, timeoutMilliseconds, outputLimit) => {
    calls.push({ arguments: arguments_, category, command: "kubectl-read", outputLimit, timeoutMilliseconds });
    return success("marker_count\n1\n");
  };

  await system.writeGraphMarker(pod, phase);
  assert.equal(await system.readGraphMarker(pod, phase, "readiness"), true);
  await system.deleteGraphPod(pod, phase);
  await system.deleteGraphHealthJob(health, phase);
  await system.applyGraphHealthJob(phase);

  assert.deepEqual(calls[0].arguments, [
    "--kubeconfig", "/dev/fd/3",
    "--namespace", "zasp-local", "exec", pod.name, "--container", "neo4j", "--",
    "cypher-shell", "--address", "neo4j://neo4j.zasp-local.svc.cluster.local:7687",
    "--database", "neo4j", "--format", "plain", "--non-interactive",
    "--param", `proof_id => '${marker}'`,
    "MERGE (marker:ZaspLocalGraphProof {id: $proof_id}) RETURN count(marker) AS marker_count",
  ]);
  assert.deepEqual(calls[1].arguments, [
    "--namespace", "zasp-local", "exec", pod.name, "--container", "neo4j", "--",
    "cypher-shell", "--address", "neo4j://neo4j.zasp-local.svc.cluster.local:7687",
    "--database", "neo4j", "--format", "plain", "--non-interactive",
    "--param", `proof_id => '${marker}'`,
    "MATCH (marker:ZaspLocalGraphProof {id: $proof_id}) RETURN count(marker) AS marker_count",
  ]);
  assert.deepEqual(calls[2].arguments, [
    "--kubeconfig", "/dev/fd/3", "delete",
    `--raw=/api/v1/namespaces/zasp-local/pods/${pod.name}`, "--filename=-",
  ]);
  assert.equal(calls[2].options.input, `${JSON.stringify({
    apiVersion: "v1",
    kind: "DeleteOptions",
    preconditions: { uid: pod.uid },
  })}\n`);
  assert.deepEqual(calls[3].arguments, [
    "--kubeconfig", "/dev/fd/3", "delete",
    "--raw=/apis/batch/v1/namespaces/zasp-local/jobs/neo4j-health", "--filename=-",
  ]);
  assert.equal(calls[3].options.input, `${JSON.stringify({
    apiVersion: "v1",
    kind: "DeleteOptions",
    preconditions: { uid: health.jobUid },
    propagationPolicy: "Foreground",
  })}\n`);
  assert.deepEqual(calls[4].arguments, [
    "--kubeconfig", "/dev/fd/3", "apply", "--filename", "-",
  ]);
  assert.equal(calls[4].options.input,
    `${JSON.stringify(buildGraphResources().find((item) => item.kind === "Job"))}\n`);
  assert.deepEqual(calls.map(({ category }) => category), [
    "provider", "readiness", "provider", "provider", "provider",
  ]);
});

test("polls delayed provider state and performs the persistence sequence once", async () => {
  let initial;
  for (const mutate of [
    (value) => { value.persistentVolumeClaims[0].status.phase = "Pending"; },
    (value) => { value.pods.at(-2).status.phase = "Pending"; },
    (value) => { value.jobs[0].status.succeeded = 0; },
  ]) {
    const delayed = graphSystem();
    delayed.graphLoadedImageTargets = new Map(Object.entries(graphProviderExpectation().imageTargets));
    let reads = 0;
    let pauses = 0;
    let productReads = 0;
    let next;
    delayed.verifyProductReadiness = async () => {
      productReads += 1;
      next = graphProviderState();
      if (reads + 1 < 3) mutate(next);
      delayed.productProviderSnapshot = productProviderSnapshot(next);
    };
    delayed.readGraphProviderState = async () => {
      reads += 1;
      return next;
    };
    delayed.pauseGraphPoll = async () => { pauses += 1; };
    initial = await delayed.pollGraphProviderState(phase);
    assert.equal(reads, 3);
    assert.equal(pauses, 2);
    assert.equal(productReads, 3);
  }

  const regressed = graphSystem();
  regressed.graphLoadedImageTargets = new Map(Object.entries(graphProviderExpectation().imageTargets));
  let regressionReads = 0;
  let regressionPauses = 0;
  regressed.verifyProductReadiness = async () => {
    regressed.productProviderSnapshot = productProviderSnapshot(graphProviderState());
  };
  regressed.readGraphProviderState = async () => {
    regressionReads += 1;
    const value = graphProviderState();
    if (regressionReads === 1) value.pods[0].metadata.uid = providerUid(99);
    return value;
  };
  regressed.pauseGraphPoll = async () => { regressionPauses += 1; };
  await regressed.pollGraphProviderState(phase);
  assert.equal(regressionReads, 2, "a product regression in the graph poll cannot reuse an earlier proof");
  assert.equal(regressionPauses, 1);

  const events = [];
  const replacement = graphRunModule.validateGraphKubernetesState(graphProviderState({
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  }), graphProviderExpectation(), initial, true);
  const fresh = graphRunModule.validateGraphKubernetesState(graphProviderState({
    healthCompletionTime: "2026-08-16T10:00:16Z",
    healthContainerID: `containerd://${"d".repeat(64)}`,
    healthFinishedAt: "2026-08-16T10:00:15Z",
    healthJobStartedAt: "2026-08-16T10:00:12Z",
    healthPodName: "neo4j-health-klmno",
    healthPodStartedAt: "2026-08-16T10:00:13Z",
    healthPodUid: providerUid(12),
    jobUid: providerUid(11),
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  }), graphProviderExpectation(), replacement, false, true);
  const system = graphSystem();
  system.pollGraphProviderState = async (
    _phase, retained, requireReplacement, _category, requireHealthReplacement,
  ) => {
    events.push([
      "snapshot", retained?.neo4j?.podUid, requireReplacement, requireHealthReplacement,
    ]);
    if (retained === undefined) return initial;
    return requireHealthReplacement === true ? fresh :
      retained.health.jobUid === fresh.health.jobUid ? fresh : replacement;
  };
  system.writeGraphMarker = async (pod) => {
    events.push(["write", pod.uid]);
    return { outcome: "ambiguous", result: success("marker_count\n1\n") };
  };
  system.readGraphMarker = async (pod) => { events.push(["read", pod.uid]); return true; };
  system.deleteGraphPod = async (pod) => {
    events.push(["delete", pod.uid]);
    return { outcome: "ambiguous", result: success(`pod/${pod.name}\n`) };
  };
  system.deleteGraphHealthJob = async (health) => {
    events.push(["delete-health", health.jobUid, health.podUid]);
    return { outcome: "ambiguous", result: success("job.batch/neo4j-health\n") };
  };
  system.pollGraphHealthJobAbsent = async (_phase, health) => {
    events.push(["health-absent", health.health.jobUid, health.health.podUid]);
    return true;
  };
  system.applyGraphHealthJob = async () => {
    events.push(["apply-health"]);
    return { outcome: "ambiguous", result: success("job.batch/neo4j-health created\n") };
  };
  const product = { internal: true, pods: 4, ready: 4, services: 4 };
  assert.deepEqual(await system.verifyAdditionalReadiness(product, phase), {
    ...product,
    graph: { internal: true, persistent: true, ready: true },
  });
  assert.deepEqual(events, [
    ["snapshot", undefined, undefined, undefined],
    ["write", providerUid(3)],
    ["read", providerUid(3)],
    ["delete", providerUid(3)],
    ["snapshot", providerUid(3), true, undefined],
    ["delete-health", providerUid(8), providerUid(9)],
    ["health-absent", providerUid(8), providerUid(9)],
    ["apply-health"],
    ["snapshot", providerUid(10), false, true],
    ["read", providerUid(10)],
    ["snapshot", providerUid(10), false, undefined],
  ]);
});

test("reconciles the exact original health Job and Pod absence before recreation", async () => {
  const initial = graphRunModule.validateGraphKubernetesState(
    graphProviderState(), graphProviderExpectation(),
  );
  const system = graphSystem();
  system.graphLoadedImageTargets = new Map(Object.entries(graphProviderExpectation().imageTargets));
  const states = [graphProviderState(), graphProviderStateWithout("health")];
  let reads = 0;
  let pauses = 0;
  system.readGraphProviderState = async (_phase, category, allowMissingHealth) => {
    assert.equal(category, "readiness");
    assert.equal(allowMissingHealth, true);
    return states[Math.min(reads++, states.length - 1)];
  };
  system.pauseGraphPoll = async () => { pauses += 1; };
  assert.equal(await system.pollGraphHealthJobAbsent(phase, initial), true);
  assert.equal(reads, 2);
  assert.equal(pauses, 1);

  for (const mutate of [
    (value) => { value.jobs[0] = structuredClone(graphProviderState().jobs[0]); },
    (value) => { value.healthLog = "foreign\n"; },
    (value) => { value.deployments.at(-1).metadata.uid = providerUid(99); },
  ]) {
    const hostile = graphProviderStateWithout("health");
    mutate(hostile);
    const rejected = graphSystem();
    rejected.graphLoadedImageTargets = new Map(Object.entries(graphProviderExpectation().imageTargets));
    let hostileReads = 0;
    rejected.readGraphProviderState = async () => { hostileReads += 1; return hostile; };
    rejected.pauseGraphPoll = async () => {};
    await assert.rejects(() => rejected.pollGraphHealthJobAbsent(phase, initial), { name: "Failure" });
    assert.equal(hostileReads, 3, "health absence reconciliation is bounded");
  }
});

test("reconciles only ambiguous marker and pod mutations through exact observed state", async () => {
  const initial = graphRunModule.validateGraphKubernetesState(graphProviderState(), graphProviderExpectation());
  const replacement = graphRunModule.validateGraphKubernetesState(graphProviderState({
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  }), graphProviderExpectation(), initial, true);
  const fresh = graphRunModule.validateGraphKubernetesState(graphProviderState({
    healthCompletionTime: "2026-08-16T10:00:16Z",
    healthContainerID: `containerd://${"d".repeat(64)}`,
    healthFinishedAt: "2026-08-16T10:00:15Z",
    healthJobStartedAt: "2026-08-16T10:00:12Z",
    healthPodName: "neo4j-health-klmno",
    healthPodStartedAt: "2026-08-16T10:00:13Z",
    healthPodUid: providerUid(12),
    jobUid: providerUid(11),
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  }), graphProviderExpectation(), replacement, false, true);
  for (const result of [
    { outcome: "ambiguous", result: { ...success(), thrown: true } },
    { outcome: "ambiguous", result: { ...success(), signal: "SIGTERM", status: null } },
    { outcome: "ambiguous", result: success("malformed provider output\n") },
  ]) {
    const system = graphSystem();
    let snapshots = 0;
    let reads = 0;
    system.pollGraphProviderState = async (_phase, retained, _replacePod, _category, replaceHealth) => {
      snapshots += 1;
      if (retained === undefined) return initial;
      return replaceHealth === true || retained.health.jobUid === fresh.health.jobUid ? fresh : replacement;
    };
    system.writeGraphMarker = async () => result;
    system.readGraphMarker = async () => { reads += 1; return true; };
    system.deleteGraphPod = async () => result;
    system.deleteGraphHealthJob = async () => result;
    system.pollGraphHealthJobAbsent = async () => true;
    system.applyGraphHealthJob = async () => result;
    await system.verifyAdditionalReadiness({ internal: true, pods: 4, ready: 4, services: 4 }, phase);
    assert.equal(snapshots, 4);
    assert.equal(reads, 2);
  }

  for (const operation of ["write", "delete"]) {
    const system = graphSystem();
    let reads = 0;
    system.pollGraphProviderState = async () => initial;
    system.writeGraphMarker = async () => operation === "write"
      ? { outcome: "definitive", result: { ...success(), status: 1 } }
      : { outcome: "applied", result: success() };
    system.readGraphMarker = async () => { reads += 1; return true; };
    system.deleteGraphHealthJob = async () => ({ outcome: "applied", result: success() });
    system.pollGraphHealthJobAbsent = async () => true;
    system.applyGraphHealthJob = async () => ({ outcome: "applied", result: success() });
    system.deleteGraphPod = async () => operation === "delete"
      ? { outcome: "definitive", result: { ...success(), status: 1 } }
      : { outcome: "applied", result: success() };
    await assert.rejects(() => system.verifyAdditionalReadiness(
      { internal: true, pods: 4, ready: 4, services: 4 }, phase,
    ), { name: "Failure" });
    assert.equal(reads, operation === "write" ? 0 : 1);
  }
});

test("rejects definitive health Job deletion or recreation mutations", async () => {
  const initial = graphRunModule.validateGraphKubernetesState(
    graphProviderState(), graphProviderExpectation(),
  );
  const replacement = graphRunModule.validateGraphKubernetesState(graphProviderState({
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  }), graphProviderExpectation(), initial, true);
  for (const operation of ["health-delete", "health-apply"]) {
    const system = graphSystem();
    system.pollGraphProviderState = async (_phase, retained) => retained === undefined ? initial : replacement;
    system.writeGraphMarker = async () => ({ outcome: "applied", result: success() });
    system.readGraphMarker = async () => true;
    system.deleteGraphPod = async () => ({ outcome: "applied", result: success() });
    system.deleteGraphHealthJob = async () => operation === "health-delete"
      ? { outcome: "definitive", result: { ...success(), status: 1 } }
      : { outcome: "applied", result: success() };
    system.pollGraphHealthJobAbsent = async () => true;
    system.applyGraphHealthJob = async () => operation === "health-apply"
      ? { outcome: "definitive", result: { ...success(), status: 1 } }
      : { outcome: "applied", result: success() };
    await assert.rejects(() => system.verifyAdditionalReadiness(
      { internal: true, pods: 4, ready: 4, services: 4 }, phase,
    ), { name: "Failure" });
  }
});

test("retains proved health absence after definitive recreation rejection for bounded cleanup", async () => {
  const replacementOverrides = {
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  };
  const initial = graphRunModule.validateGraphKubernetesState(
    graphProviderState(), graphProviderExpectation(),
  );
  const replacement = graphRunModule.validateGraphKubernetesState(
    graphProviderState(replacementOverrides), graphProviderExpectation(), initial, true,
  );
  const system = graphSystem();
  system.graphLoadedImageTargets = new Map(Object.entries(graphProviderExpectation().imageTargets));
  let polls = 0;
  system.pollGraphProviderState = async () => polls++ === 0 ? initial : replacement;
  system.writeGraphMarker = async () => ({ outcome: "applied", result: success() });
  system.readGraphMarker = async () => true;
  system.deleteGraphPod = async () => ({ outcome: "applied", result: success() });
  system.deleteGraphHealthJob = async () => ({ outcome: "applied", result: success() });
  system.pollGraphHealthJobAbsent = async () => true;
  system.applyGraphHealthJob = async () => ({
    outcome: "definitive", result: { ...success(), status: 1 },
  });
  await assert.rejects(() => system.verifyAdditionalReadiness(
    { internal: true, pods: 4, ready: 4, services: 4 }, phase,
  ), { category: "provider", name: "Failure" });
  assert.deepEqual(system.graphProviderAbsenceIdentity, graphProviderAbsence("health", replacement),
    "the settled old health absence remains recovery authority without adopting a rejected apply");
  assert.ok(Object.isFrozen(system.graphProviderAbsenceIdentity));
  assert.ok(Object.isFrozen(system.graphProviderAbsenceIdentity.retained));
  assert.equal(system.graphHealthApplyMayHaveApplied, false);

  system.paths = { graphManifest: "/owned/graph.yaml" };
  system.nodeIdentity = { token: "a".repeat(64) };
  system.requireTemporaryOwnership = async () => {};
  system.requireOwnedPath = async () => {};
  system.verifyCluster = async () => system.nodeIdentity;
  let reads = 0;
  system.readGraphProviderState = async (_phase, category, allowMissingHealth) => {
    assert.equal(category, "cleanup");
    assert.equal(allowMissingHealth, true);
    reads += 1;
    return graphProviderStateWithout("health", replacementOverrides);
  };
  system.pauseGraphPoll = async () => {};
  await system.verifyAdditionalNodeForCleanup(phase);
  assert.equal(reads, 1, "exact absence proof permits the base cleanup to continue");
  assert.deepEqual(system.graphProviderAbsenceIdentity, graphProviderAbsence("health", replacement),
    "recovery authority is retained until cluster deletion settles");
  await system.afterClusterAbsent();
  assert.equal(system.graphProviderAbsenceIdentity, undefined);
});

test("continues reverse cluster cleanup after proved health absence without masking provider failure", async () => {
  const replacementOverrides = {
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  };
  const initial = graphRunModule.validateGraphKubernetesState(
    graphProviderState(), graphProviderExpectation(),
  );
  const replacement = graphRunModule.validateGraphKubernetesState(
    graphProviderState(replacementOverrides), graphProviderExpectation(), initial, true,
  );
  const system = graphSystem();
  const events = [];
  system.paths = { graphManifest: "/owned/graph.yaml" };
  system.clusterMayHaveApplied = true;
  system.nodeIdentity = { token: "a".repeat(64), volumeToken: "b".repeat(64) };
  system.graphProviderAbsenceIdentity = Object.freeze(graphProviderAbsence("health", replacement));
  system.graphLoadedImageTargets = new Map(Object.entries(graphProviderExpectation().imageTargets));
  system.requireTemporaryOwnership = async () => {};
  system.requireOwnedPath = async () => {};
  system.verifyCluster = async () => system.nodeIdentity;
  system.readGraphProviderState = async () => {
    events.push("health absent");
    return graphProviderStateWithout("health", replacementOverrides);
  };
  system.runMutation = async (command, arguments_) => {
    assert.equal(command, "docker");
    assert.deepEqual(arguments_, ["rm", "--force", "--volumes", "a".repeat(64)]);
    events.push("node remove");
    return { outcome: "applied", result: success() };
  };
  system.requireClusterAbsent = async () => {
    events.push("cluster absent");
    system.nodeIdentity = undefined;
  };
  system.cleanupAdditionalImages = async () => { events.push("images"); };
  const runtime = lifecycle({
    auditAbsence: async () => { events.push("audit"); },
    cleanup: async (cleanupPhase) => await system.cleanup(cleanupPhase),
    verifyReadiness: async () => { throw new GraphFailure("provider"); },
  }).runtime;
  const errors = [];
  assert.equal(await runGraphMain(runtime, {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 100,
    stderr: { write: (value) => errors.push(value) },
    stdout: { write: () => assert.fail("unexpected success") },
    setExitCode() {},
  }), 1);
  assert.deepEqual(events, ["health absent", "node remove", "cluster absent", "images", "audit"]);
  assert.deepEqual(errors, ["Local graph manifest failed: provider rejected.\n"]);
});

test("rejects late or foreign health state after a definitive recreation rejection", async () => {
  const replacementOverrides = {
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  };
  const initial = graphRunModule.validateGraphKubernetesState(
    graphProviderState(), graphProviderExpectation(),
  );
  const replacement = graphRunModule.validateGraphKubernetesState(
    graphProviderState(replacementOverrides), graphProviderExpectation(), initial, true,
  );
  const freshOverrides = {
    ...replacementOverrides,
    healthCompletionTime: "2026-08-16T10:00:16Z",
    healthContainerID: `containerd://${"d".repeat(64)}`,
    healthFinishedAt: "2026-08-16T10:00:15Z",
    healthJobStartedAt: "2026-08-16T10:00:12Z",
    healthPodName: "neo4j-health-klmno",
    healthPodStartedAt: "2026-08-16T10:00:13Z",
    healthPodUid: providerUid(12),
    jobUid: providerUid(11),
  };
  const foreign = graphProviderStateWithout("health", replacementOverrides);
  foreign.services.at(-1).metadata.uid = providerUid(99);
  for (const [name, state] of [
    ["old health returned late", graphProviderState(replacementOverrides)],
    ["new health appeared despite rejection", graphProviderState(freshOverrides)],
    ["foreign graph lineage", foreign],
  ]) {
    const system = graphSystem();
    system.paths = { graphManifest: "/owned/graph.yaml" };
    system.nodeIdentity = { token: "a".repeat(64) };
    system.graphProviderIdentity = replacement;
    system.graphProviderAbsenceIdentity = Object.freeze(graphProviderAbsence("health", replacement));
    system.graphLoadedImageTargets = new Map(Object.entries(graphProviderExpectation().imageTargets));
    system.requireTemporaryOwnership = async () => {};
    system.requireOwnedPath = async () => {};
    system.verifyCluster = async () => system.nodeIdentity;
    let reads = 0;
    system.readGraphProviderState = async (_phase, category, allowMissingHealth) => {
      assert.equal(category, "cleanup");
      assert.equal(allowMissingHealth, true);
      reads += 1;
      return structuredClone(state);
    };
    system.pauseGraphPoll = async () => {};
    await assert.rejects(() => system.verifyAdditionalNodeForCleanup(phase),
      { category: "cleanup", name: "Failure" }, name);
    assert.equal(reads, 3, `${name} is rejected within the fixed reconciliation bound`);
    assert.deepEqual(system.graphProviderAbsenceIdentity, graphProviderAbsence("health", replacement), name);
  }
});

test("journals cancelled marker/delete children and forbids cleanup audit before settlement", async () => {
  for (const operation of ["marker", "delete", "health-delete", "health-apply"]) {
    let release;
    let settled = false;
    const controller = new AbortController();
    const system = graphSystem(async () => await new Promise((resolve) => {
      release = () => { settled = true; resolve(success()); };
    }));
    system.paths = { kubeconfig: "/owned/kubeconfig" };
    system.environment = Object.freeze({ PATH: "/usr/bin:/bin" });
    system.requireOwnedPath = async () => {};
    system.withOwnedFiles = async (_paths, _phase, _category, callback) => await callback([{
      handle: { fd: 31 }, identity: { bytes: Buffer.from("kubeconfig") },
    }]);
    const cancellingPhase = Object.freeze({
      assertActive(category) {
        if (controller.signal.aborted) throw new GraphFailure(category);
      },
      signal: controller.signal,
    });
    const pod = { name: "neo4j-abc123def4-pqrst", uid: providerUid(3) };
    const health = { jobUid: providerUid(8), podName: "neo4j-health-fghij", podUid: providerUid(9) };
    const pending = operation === "marker" ? system.writeGraphMarker(pod, cancellingPhase)
      : operation === "delete" ? system.deleteGraphPod(pod, cancellingPhase)
        : operation === "health-delete" ? system.deleteGraphHealthJob(health, cancellingPhase)
          : system.applyGraphHealthJob(cancellingPhase);
    await new Promise((resolve) => setImmediate(resolve));
    controller.abort();
    release();
    await assert.rejects(() => pending, { name: "Failure" });
    assert.equal(system.mutationSettlements.length, 1);
    await system.joinMutations(phase);
    assert.equal(settled, true);
  }

  for (const operation of ["marker", "delete", "health-delete", "health-apply"]) {
    const order = [];
    const late = graphSystem(async () => await new Promise((resolve) => {
      setTimeout(() => {
        order.push("late mutation");
        resolve(success());
      }, 20);
    }));
    late.paths = { kubeconfig: "/owned/kubeconfig" };
    late.environment = Object.freeze({ PATH: "/usr/bin:/bin" });
    late.requireOwnedPath = async () => {};
    late.withOwnedFiles = async (_paths, _phase, _category, callback) => await callback([{
      handle: { fd: 31 }, identity: { bytes: Buffer.from("kubeconfig") },
    }]);
    const pod = { name: "neo4j-abc123def4-pqrst", uid: providerUid(3) };
    const health = { jobUid: providerUid(8), podName: "neo4j-health-fghij", podUid: providerUid(9) };
    const runtime = {};
    for (const name of [
      "initialize", "preflight", "buildImages", "createNetwork", "createCluster", "loadImages", "applyManifests",
    ]) runtime[name] = async () => {};
    runtime.verifyReadiness = async (mainPhase) => {
      order.push("mutation start");
      if (operation === "marker") await late.writeGraphMarker(pod, mainPhase);
      else if (operation === "delete") await late.deleteGraphPod(pod, mainPhase);
      else if (operation === "health-delete") await late.deleteGraphHealthJob(health, mainPhase);
      else await late.applyGraphHealthJob(mainPhase);
      assert.fail("cancelled mutation returned");
    };
    runtime.joinMutations = async (cleanupPhase) => {
      order.push("join start");
      await late.joinMutations(cleanupPhase);
      order.push("join complete");
    };
    runtime.cleanup = async () => { order.push("cleanup"); };
    runtime.auditAbsence = async () => { order.push("audit"); };
    const output = [];
    assert.equal(await runGraphMain(runtime, {
      cleanupTimeoutMilliseconds: 100,
      mainTimeoutMilliseconds: 5,
      settlementTimeoutMilliseconds: 5,
      stderr: { write: (value) => output.push(value) },
      stdout: { write: () => assert.fail("unexpected success") },
      setExitCode() {},
    }), 1);
    assert.deepEqual(output, ["Local graph manifest failed: deadline rejected.\n"]);
    assert.deepEqual(order, [
      "mutation start", "join start", "late mutation", "join complete", "cleanup", "audit",
    ]);
  }
});

test("cleanup failure wins over provider panic and uncooperative mutation settlement", async () => {
  const output = [];
  const providerPanic = lifecycle({
    verifyReadiness: async () => { throw new Error("raw provider panic"); },
    cleanup: async () => { throw new Error("raw cleanup panic"); },
  });
  assert.equal(await runGraphMain(providerPanic.runtime, {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 20,
    stderr: { write: (value) => output.push(value) },
    stdout: { write: () => assert.fail("unexpected success") },
    setExitCode() {},
  }), 1);
  assert.deepEqual(output, ["Local graph manifest failed: cleanup rejected.\n"]);
  assert.ok(providerPanic.events.includes("auditAbsence"), "audit continues after cleanup panic");

  const absent = lifecycle({
    auditAbsence: async () => { throw new Error("raw absence panic"); },
  });
  const absentOutput = [];
  assert.equal(await runGraphMain(absent.runtime, {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 20,
    stderr: { write: (value) => absentOutput.push(value) },
    stdout: { write: () => assert.fail("unexpected success") },
    setExitCode() {},
  }), 1);
  assert.deepEqual(absentOutput, ["Local graph manifest failed: cleanup rejected.\n"]);

  const blocked = lifecycle({
    joinMutations: async () => await new Promise(() => {}),
    verifyReadiness: async () => { throw new GraphFailure("provider"); },
  });
  const blockedOutput = [];
  assert.equal(await runGraphMain(blocked.runtime, {
    cleanupTimeoutMilliseconds: 5,
    mainTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 5,
    stderr: { write: (value) => blockedOutput.push(value) },
    stdout: { write: () => assert.fail("unexpected success") },
    setExitCode() {},
  }), 1);
  assert.deepEqual(blockedOutput, ["Local graph manifest failed: cleanup rejected.\n"]);
  assert.equal(blocked.events.includes("cleanup"), false);
  assert.equal(blocked.events.includes("auditAbsence"), false);
});

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

test("uses the pinned absolute Go tool without widening the isolated live PATH", async () => {
  const goCandidate = "/opt/homebrew/bin/go";
  const goCommand = "/opt/homebrew/Cellar/go/1.25.6/libexec/bin/go";
  const livePath = "/Users/test/.nvm/versions/node/v22.23.1/bin:/usr/local/bin:/usr/bin:/bin";
  const metadata = {
    dev: 43,
    gid: 80,
    ino: 99,
    isFile: () => true,
    isSymbolicLink: () => false,
    mode: 0o100755,
    mtimeMs: 1_770_000_000_000,
    size: 14_098_546,
    uid: 501,
  };
  const canonicalReads = [];
  const calls = [];
  const system = graphSystem(async (command, arguments_, options) => {
    calls.push({ arguments_, command, path: options.environment.PATH });
    return arguments_[0] === "version" ? success("go version go1.25.6 darwin/arm64\n") : success();
  }, {
    canonicalPath: async (value) => {
      canonicalReads.push(value);
      return value === goCandidate ? goCommand : value;
    },
    statPath: async () => metadata,
  });
  system.environment = Object.freeze({ HOME: "/owned/home", LANG: "C.UTF-8", PATH: livePath });
  system.resolveGraphImage = async (selected) => resolvedImage(selected);
  system.readGraphImageBaseline = async () => undefined;
  await system.runAdditionalPreflightChecks(phase);
  await system.runMutation("go", ["build"], phase, "build", {
    environment: system.environment,
    outputLimit: 16_384,
    timeoutMilliseconds: 30_000,
  });
  assert.deepEqual(calls, [
    { arguments_: ["version"], command: goCommand, path: livePath },
    { arguments_: ["version"], command: goCommand, path: livePath },
    { arguments_: ["build"], command: goCommand, path: livePath },
  ]);
  assert.ok(canonicalReads.includes(goCandidate));
  assert.equal(system.graphGoToolIdentity.command, goCommand);
  assert.ok(Object.isFrozen(system.graphGoToolIdentity));

  const wrongVersion = graphSystem(async () => success("go version go1.25.5 darwin/arm64\n"), {
    canonicalPath: async (value) => value === goCandidate ? goCommand : value,
    statPath: async () => metadata,
  });
  wrongVersion.environment = system.environment;
  wrongVersion.resolveGraphImage = system.resolveGraphImage;
  wrongVersion.readGraphImageBaseline = system.readGraphImageBaseline;
  await assert.rejects(() => wrongVersion.runAdditionalPreflightChecks(phase), {
    category: "configuration", name: "Failure",
  });

  const missing = graphSystem(async () => success(), {
    canonicalPath: async () => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); },
    statPath: async () => metadata,
  });
  missing.environment = system.environment;
  missing.resolveGraphImage = system.resolveGraphImage;
  missing.readGraphImageBaseline = system.readGraphImageBaseline;
  await assert.rejects(() => missing.runAdditionalPreflightChecks(phase), {
    category: "configuration", name: "Failure",
  });

  const symlinked = graphSystem(async () => success("go version go1.25.6 darwin/arm64\n"), {
    canonicalPath: async (value) => value === goCandidate ? goCommand : value,
    statPath: async () => ({ ...metadata, isSymbolicLink: () => true }),
  });
  symlinked.environment = system.environment;
  symlinked.resolveGraphImage = system.resolveGraphImage;
  symlinked.readGraphImageBaseline = system.readGraphImageBaseline;
  await assert.rejects(() => symlinked.runAdditionalPreflightChecks(phase), {
    category: "configuration", name: "Failure",
  });

  let replaced = false;
  const replacementCalls = [];
  const replacement = graphSystem(async (command, arguments_) => {
    replacementCalls.push([command, ...arguments_]);
    return success("go version go1.25.6 darwin/arm64\n");
  }, {
    canonicalPath: async (value) => value === goCandidate ? goCommand : value,
    statPath: async () => ({ ...metadata, ino: replaced ? 100 : 99 }),
  });
  replacement.environment = system.environment;
  replacement.resolveGraphImage = system.resolveGraphImage;
  replacement.readGraphImageBaseline = system.readGraphImageBaseline;
  await replacement.runAdditionalPreflightChecks(phase);
  replaced = true;
  await assert.rejects(() => replacement.runMutation("go", ["build"], phase, "build", {
    environment: replacement.environment,
    outputLimit: 16_384,
    timeoutMilliseconds: 30_000,
  }), { category: "build", name: "Failure" });
  assert.deepEqual(replacementCalls, [[goCommand, "version"]], "replacement is rejected before build execution");

  assert.throws(() => DockerKindGraphRuntime.fromProcess({
    GOROOT: "/alternate/go",
    HOME: "/Users/test",
    PATH: livePath,
  }), { category: "configuration", name: "Failure" });
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

test("projects optional Docker config keys without assuming provider map membership", async () => {
  const selected = plan();
  const system = graphSystem();
  system.runRead = async (command, arguments_) => {
    assert.equal(command, "docker");
    assert.deepEqual(arguments_.slice(0, 3), ["image", "inspect", "--format"]);
    for (const key of ["Env", "Entrypoint", "Cmd", "ExposedPorts", "Volumes", "Labels"]) {
      assert.match(arguments_[3], new RegExp(`\\{\\{json \\(index \\.Config "${key}"\\)\\}\\}`));
    }
    for (const key of ["User", "WorkingDir"]) {
      assert.match(arguments_[3], new RegExp(
        `\\{\\{json \\(or \\(index \\.Config "${key}"\\) ""\\)\\}\\}`,
      ));
    }
    assert.equal(arguments_.at(-1), selected.repoDigest);
    return success(`${JSON.stringify(pinnedGraphImageInspection(selected))}\n`);
  };
  const identity = await system.inspectGraphImage(
    selected, resolvedImage(selected), phase, undefined, selected.repoDigest,
  );
  assert.equal(identity.id, selected.configDigest);
  assert.equal(identity.user, "");
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

test("rejects unproved two-row imports before retaining any synthetic image identity", () => {
  for (const name of ["neo4j", "busybox"]) {
    for (const platform of ["linux/amd64", "linux/arm64"]) {
      const productDigest = `sha256:${"7".repeat(64)}`;
      const kubernetesDigest = `sha256:${"8".repeat(64)}`;
      const priorImportDigest = `sha256:${"9".repeat(64)}`;
      const baselineRows = [
        `docker.io/library/zasp-audit-api:m1-30a application/vnd.oci.image.manifest.v1+json ` +
          `${productDigest} 12.3 MiB ${platform} managed=true`,
        `registry.k8s.io/pause:3.10 application/vnd.oci.image.manifest.v1+json ` +
          `${kubernetesDigest} 320 KiB ${platform} io.cri-containerd.image=managed`,
        `${graphRawImportReferenceForDigest(priorImportDigest, "2026-08-15")} ` +
          `application/vnd.oci.image.index.v1+json ${priorImportDigest} 13 MiB ${platform} managed=true`,
      ];
      for (const [order, wrapperDigest] of [
        ["wrapper-first", `sha256:${"0".repeat(64)}`],
        ["child-first", `sha256:${"f".repeat(64)}`],
      ]) {
        const before = containerdInventory(baselineRows);
        const after = containerdInventory([...baselineRows, ...graphImportRows(name, platform, wrapperDigest)]);
        assert.throws(() => parseGraphContainerdImageTargets(before, after, plan(name, platform)),
          { name: "Failure" }, `${name} ${platform} ${order}`);
      }
    }
  }
});

test("binds Docker archive imports through the selected config and retained RootFS", () => {
  assert.equal(typeof graphRunModule.validateGraphContainerdImageContents, "function");
  for (const name of ["neo4j", "busybox"]) {
    for (const platform of ["linux/amd64", "linux/arm64"]) {
      const fixture = graphArchiveImport(name, platform);
      const before = containerdInventory([
        `registry.k8s.io/pause:3.10 application/vnd.oci.image.manifest.v1+json ` +
          `sha256:${"8".repeat(64)} 320 KiB ${platform} io.cri-containerd.image=managed`,
      ]);
      const after = containerdInventory([
        before.split("\n")[1], ...fixture.rows,
      ]);
      const target = parseGraphContainerdImageTargets(before, after, fixture.selected);
      assert.deepEqual(target, fixture.target, `${name} ${platform} retains the complete archive projection`);
      assert.deepEqual(graphRunModule.validateGraphContainerdImageContents(
        target,
        fixture.manifestSource,
        fixture.wrapperSource,
        fixture.selected,
        fixture.retained,
        resolvedImage(fixture.selected),
      ), fixture.target, `${name} ${platform} binds every imported content edge`);
      assert.ok(Object.isFrozen(target));
      assert.ok(Object.isFrozen(target.references));
    }
  }
});

test("binds each verified anonymous archive to one exact CRI-reachable node-local alias", () => {
  assert.equal(typeof graphRunModule.bindGraphContainerdWorkloadAlias, "function");
  for (const name of ["neo4j", "busybox"]) {
    for (const platform of ["linux/amd64", "linux/arm64"]) {
      const fixture = graphBoundArchiveImport(name, platform);
      const beforeRows = [...fixture.rows];
      const afterRows = [...beforeRows, [
        fixture.alias.reference, fixture.alias.mediaType, fixture.alias.digest, fixture.alias.size,
        fixture.alias.platform, fixture.alias.labels,
      ].join(" ")];
      const target = graphRunModule.bindGraphContainerdWorkloadAlias(
        containerdInventory(beforeRows), containerdInventory(afterRows), fixture.target, fixture.selected,
      );
      assert.deepEqual(target, fixture.boundTarget, `${name} ${platform}`);
      assert.ok(Object.isFrozen(target));
      assert.ok(Object.isFrozen(target.references));
    }
  }
});

test("rejects missing, colliding, replaced, ambiguous, or substituted node-local workload aliases", () => {
  const fixture = graphBoundArchiveImport("neo4j");
  const row = [
    fixture.alias.reference, fixture.alias.mediaType, fixture.alias.digest, fixture.alias.size,
    fixture.alias.platform, fixture.alias.labels,
  ].join(" ");
  const before = containerdInventory(fixture.rows);
  const cases = [
    ["missing", fixture.rows],
    ["collision already in baseline", [...fixture.rows, row]],
    ["raw replacement", [fixture.rows[0].replace("456 MiB", "455 MiB"), ...fixture.rows.slice(1), row]],
    ["target digest", [...fixture.rows, row.replace(fixture.alias.digest, fixture.selected.manifestDigest)]],
    ["target media type", [...fixture.rows, row.replace("image.index", "image.manifest")]],
    ["target size", [...fixture.rows, row.replace(fixture.alias.size, "458 MiB")]],
    ["target platform", [...fixture.rows, row.replace(fixture.alias.platform, "linux/amd64")]],
    ["target labels", [...fixture.rows, row.replace(fixture.alias.labels, "managed=false")]],
    ["tag retained", [...fixture.rows, row.replace(fixture.alias.reference, fixture.selected.providerReference)]],
    ["manifest digest alias", [...fixture.rows, row.replace(fixture.selected.indexDigest, fixture.selected.manifestDigest)]],
    ["alternate repository", [...fixture.rows, row.replace("docker.io/library/neo4j", "registry.example/neo4j")]],
    ["extra", [...fixture.rows, row,
      row.replace("docker.io/library/neo4j", "docker.io/library/neo4j-copy")]],
  ];
  for (const [label, afterRows] of cases) {
    const baseline = label === "collision already in baseline" ? containerdInventory(afterRows) : before;
    assert.throws(() => graphRunModule.bindGraphContainerdWorkloadAlias(
      baseline, containerdInventory(afterRows), fixture.target, fixture.selected,
    ), { name: "Failure" }, label);
  }
});

test("binds only the normalized provider-manifest identity selected by containerd CRI", () => {
  assert.equal(typeof graphRunModule.bindGraphContainerdRuntimeAlias, "function");
  const firstTypes = new Set();
  for (const name of ["neo4j", "busybox"]) {
    for (const platform of ["linux/amd64", "linux/arm64"]) {
      const fixture = graphBoundArchiveImport(name, platform);
      firstTypes.add(fixture.target.references[0].mediaType);
      const workloadRow = [
        fixture.alias.reference, fixture.alias.mediaType, fixture.alias.digest, fixture.alias.size,
        fixture.alias.platform, fixture.alias.labels,
      ].join(" ");
      const runtimeRow = [
        fixture.runtimeAlias.reference, fixture.runtimeAlias.mediaType, fixture.runtimeAlias.digest,
        fixture.runtimeAlias.size, fixture.runtimeAlias.platform, fixture.runtimeAlias.labels,
      ].join(" ");
      const before = containerdInventory([...fixture.rows, workloadRow]);
      const target = graphRunModule.bindGraphContainerdRuntimeAlias(
        before, containerdInventory([...fixture.rows, workloadRow, runtimeRow]),
        fixture.boundTarget, fixture.selected,
      );
      assert.deepEqual(target, fixture.runtimeTarget, `${name} ${platform}`);
      assert.ok(Object.isFrozen(target));
      assert.ok(Object.isFrozen(target.references));
    }
  }
  assert.deepEqual(firstTypes, new Set([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
  ]), "the regression covers both wrapper-first and child-first CRI public ordering");
});

test("rejects every absent, colliding, replaced, or substituted normalized provider alias", () => {
  const fixture = graphBoundArchiveImport("neo4j");
  const workloadRow = [
    fixture.alias.reference, fixture.alias.mediaType, fixture.alias.digest, fixture.alias.size,
    fixture.alias.platform, fixture.alias.labels,
  ].join(" ");
  const runtimeRow = [
    fixture.runtimeAlias.reference, fixture.runtimeAlias.mediaType, fixture.runtimeAlias.digest,
    fixture.runtimeAlias.size, fixture.runtimeAlias.platform, fixture.runtimeAlias.labels,
  ].join(" ");
  const rows = [...fixture.rows, workloadRow];
  const before = containerdInventory(rows);
  const wrapper = fixture.boundTarget.references.find(({ mediaType }) => mediaType.endsWith("index.v1+json"));
  const cases = [
    ["missing", rows],
    ["collision", [...rows, runtimeRow]],
    ["baseline replacement", [rows[0].replace("456 MiB", "455 MiB"), ...rows.slice(1), runtimeRow]],
    ["wrapper identity", [...rows, runtimeRow.replace(fixture.runtimeAlias.digest, wrapper.digest)]],
    ["wrong media type", [...rows, runtimeRow.replace("image.manifest", "image.index")]],
    ["wrong size", [...rows, runtimeRow.replace(fixture.runtimeAlias.size, "455 MiB")]],
    ["wrong platform", [...rows, runtimeRow.replace(fixture.runtimeAlias.platform, "linux/amd64")]],
    ["wrong labels", [...rows, runtimeRow.replace(fixture.runtimeAlias.labels, "managed=false")]],
    ["raw identity", [...rows, runtimeRow.replace("docker.io/library/", "")]],
    ["alternate repository", [...rows, runtimeRow.replace("docker.io/library/", "registry.example/")]],
    ["extra", [...rows, runtimeRow,
      runtimeRow.replace("docker.io/library/", "registry.example/")]],
  ];
  for (const [label, afterRows] of cases) {
    const baseline = label === "collision" ? containerdInventory(afterRows) : before;
    assert.throws(() => graphRunModule.bindGraphContainerdRuntimeAlias(
      baseline, containerdInventory(afterRows), fixture.boundTarget, fixture.selected,
    ), { name: "Failure" }, label);
  }
});

test("accepts only the pinned ctr tabwriter's bounded trailing row pad", () => {
  const fixture = graphArchiveImport("neo4j");
  const baselineRows = [
    `registry.k8s.io/pause:3.10 application/vnd.oci.image.manifest.v1+json ` +
      `sha256:${"8".repeat(64)} 320 KiB linux/arm64 io.cri-containerd.image=managed`,
  ];
  for (const length of [1, 33]) {
    const padding = " ".repeat(length);
    const before = containerdInventory(baselineRows.map((row) => `${row}${padding}`));
    const after = containerdInventory([...baselineRows, ...fixture.rows].map((row) => `${row}${padding}`));
    assert.deepEqual(parseGraphContainerdImageTargets(before, after, fixture.selected), fixture.target);
  }
  const before = containerdInventory(baselineRows.map((row) => `${row} `));
  for (const suffix of [" ".repeat(34), "\t", " \t"]) {
    assert.throws(() => parseGraphContainerdImageTargets(
      before,
      containerdInventory([...baselineRows, ...fixture.rows].map((row) => `${row}${suffix}`)),
      fixture.selected,
    ), { name: "Failure" }, JSON.stringify(suffix));
  }
});

test("rejects every unproved Docker archive alias and imported-content substitution", () => {
  const exact = graphArchiveImport("neo4j");
  const baselineRows = [
    `registry.k8s.io/pause:3.10 application/vnd.oci.image.manifest.v1+json ` +
      `sha256:${"8".repeat(64)} 320 KiB linux/arm64 io.cri-containerd.image=managed`,
  ];
  const before = containerdInventory(baselineRows);
  const rowCases = [
    ["missing config alias", exact.rows.slice(0, 2)],
    ["missing wrapper", [exact.rows[0], exact.rows[2]]],
    ["missing child", exact.rows.slice(1)],
    ["wrong config alias", [
      ...exact.rows.slice(0, 2), exact.rows[2].replace(exact.selected.configDigest, `sha256:${"a".repeat(64)}`),
    ]],
    ["wrong alias target", [
      ...exact.rows.slice(0, 2), exact.rows[2].replace(
        exact.rows[2].split(/\s+/)[2], exact.rows[1].split(/\s+/)[2],
      ),
    ]],
    ["extra alias", [...exact.rows,
      `sha256:${"b".repeat(64)} application/vnd.oci.image.manifest.v1+json ` +
        `${exact.rows[0].split(/\s+/)[2]} 456 MiB linux/arm64 managed=true`,
    ]],
    ["unbounded label whitespace", exact.rows.map((row) => row.replace(
      "io.cri-containerd.image=managed, containerd.io", "io.cri-containerd.image=managed foreign containerd.io",
    ))],
  ];
  for (const [label, rows] of rowCases) {
    assert.throws(() => parseGraphContainerdImageTargets(
      before, containerdInventory([...baselineRows, ...rows]), exact.selected,
    ), { name: "Failure" }, label);
  }

  const semanticCases = [
    ["wrong config", ({ manifest, phase }) => {
      if (phase === "manifest") manifest.config.digest = `sha256:${"a".repeat(64)}`;
    }],
    ["wrong RootFS", ({ manifest, phase }) => {
      if (phase === "manifest") manifest.layers[0].digest = `sha256:${"b".repeat(64)}`;
    }],
    ["wrong wrapper edge", ({ phase, wrapper }) => {
      if (phase === "wrapper") wrapper.manifests[0].digest = `sha256:${"c".repeat(64)}`;
    }],
    ["extra wrapper descriptor", ({ phase, wrapper }) => {
      if (phase === "wrapper") wrapper.manifests.push({ ...wrapper.manifests[0] });
    }],
  ];
  for (const [label, mutate] of semanticCases) {
    const fixture = graphArchiveImport("neo4j", "linux/arm64", mutate);
    const target = parseGraphContainerdImageTargets(
      before, containerdInventory([...baselineRows, ...fixture.rows]), fixture.selected,
    );
    assert.throws(() => graphRunModule.validateGraphContainerdImageContents(
      target,
      fixture.manifestSource,
      fixture.wrapperSource,
      fixture.selected,
      fixture.retained,
      resolvedImage(fixture.selected),
    ), { name: "Failure" }, label);
  }
  const target = parseGraphContainerdImageTargets(
    before, containerdInventory([...baselineRows, ...exact.rows]), exact.selected,
  );
  assert.throws(() => graphRunModule.validateGraphContainerdImageContents(
    target,
    `${exact.manifestSource} `,
    exact.wrapperSource,
    exact.selected,
    exact.retained,
    resolvedImage(exact.selected),
  ), { name: "Failure" }, "manifest bytes changed");
  assert.throws(() => graphRunModule.validateGraphContainerdImageContents(
    target,
    exact.manifestSource,
    `${exact.wrapperSource} `,
    exact.selected,
    exact.retained,
    resolvedImage(exact.selected),
  ), { name: "Failure" }, "wrapper bytes changed");
});

test("rejects changed baselines and every missing, alternate, duplicate, or extra graph-load delta row", () => {
  const selected = plan("neo4j");
  const wrapperDigest = `sha256:${"f".repeat(64)}`;
  const baselineRows = [
    `docker.io/library/zasp-audit-api:m1-30a application/vnd.oci.image.manifest.v1+json ` +
      `sha256:${"7".repeat(64)} 12.3 MiB linux/arm64 managed=true`,
    `registry.k8s.io/pause:3.10 application/vnd.oci.image.manifest.v1+json ` +
      `sha256:${"8".repeat(64)} 320 KiB linux/arm64 io.cri-containerd.image=managed`,
  ];
  const deltaRows = graphImportRows("neo4j", "linux/arm64", wrapperDigest);
  const before = containerdInventory(baselineRows);
  const extraDigest = `sha256:${"e".repeat(64)}`;
  const cases = [
    ["changed baseline", containerdInventory([
      baselineRows[0].replace("12.3 MiB", "12.4 MiB"), baselineRows[1], ...deltaRows,
    ])],
    ["dropped baseline", containerdInventory([baselineRows[0], ...deltaRows])],
    ["missing child", containerdInventory([...baselineRows, deltaRows[0]])],
    ["missing wrapper", containerdInventory([...baselineRows, deltaRows[1]])],
    ["already-normalized delta", containerdInventory([
      ...baselineRows, ...deltaRows.map((row) => row.replace("import-", "docker.io/library/import-")),
    ])],
    ["mixed normalized wrapper", containerdInventory([
      ...baselineRows, deltaRows[0].replace("import-", "docker.io/library/import-"), deltaRows[1],
    ])],
    ["mixed normalized child", containerdInventory([
      ...baselineRows, deltaRows[0], deltaRows[1].replace("import-", "docker.io/library/import-"),
    ])],
    ["alternate repository", containerdInventory([
      ...baselineRows, deltaRows[0].replace("import-", "registry.example/import-"), deltaRows[1],
    ])],
    ["alternate prefix", containerdInventory([
      ...baselineRows, deltaRows[0], deltaRows[1].replace("import-", "library/import-"),
    ])],
    ["mixed duplicate spelling", containerdInventory([
      ...baselineRows, ...deltaRows, deltaRows[1].replace("import-", "docker.io/library/import-"),
    ])],
    ["mismatched dates", containerdInventory([
      ...baselineRows, deltaRows[0].replace("2026-08-16", "2026-08-15"), deltaRows[1],
    ])],
    ["invalid shared date", containerdInventory([
      ...baselineRows, ...deltaRows.map((row) => row.replace("2026-08-16", "2026-02-30")),
    ])],
    ["malformed reference digest", containerdInventory([
      ...baselineRows, deltaRows[0],
      deltaRows[1].replace(`@${selected.manifestDigest}`, `@sha256:${"A".repeat(64)}`),
    ])],
    ["malformed column digest", containerdInventory([
      ...baselineRows, deltaRows[0],
      deltaRows[1].replace(` ${selected.manifestDigest} `, ` sha256:${"A".repeat(64)} `),
    ])],
    ["mismatched child reference digest", containerdInventory([
      ...baselineRows, deltaRows[0], deltaRows[1].replace(`@${selected.manifestDigest}`, `@${extraDigest}`),
    ])],
    ["malformed reference and column digest", containerdInventory([
      ...baselineRows, deltaRows[0], deltaRows[1].replaceAll(selected.manifestDigest, `sha256:${"A".repeat(64)}`),
    ])],
    ["wrong child digest", containerdInventory([
      ...baselineRows, deltaRows[0], deltaRows[1].replaceAll(selected.manifestDigest, extraDigest),
    ])],
    ["wrong wrapper type", containerdInventory([
      ...baselineRows, deltaRows[0].replace("image.index", "image.manifest"), deltaRows[1],
    ])],
    ["wrong platform", containerdInventory([
      ...baselineRows, deltaRows[0], deltaRows[1].replace("linux/arm64", "linux/amd64"),
    ])],
    ["duplicate row", containerdInventory([...baselineRows, ...deltaRows, deltaRows[1]])],
    ["extra new target", containerdInventory([
      ...baselineRows, ...deltaRows,
      `${graphRawImportReferenceForDigest(extraDigest)} application/vnd.oci.image.manifest.v1+json ` +
        `${extraDigest} 2 MiB linux/arm64 managed=true`,
    ])],
    ["malformed new target", containerdInventory([...baselineRows, ...deltaRows, "malformed"] )],
  ];
  for (const [label, after] of cases) {
    assert.throws(() => parseGraphContainerdImageTargets(before, after, selected),
      { name: "Failure" }, label);
  }
  assert.throws(() => parseGraphContainerdImageTargets(before.slice(0, -1),
    containerdInventory([...baselineRows, ...deltaRows]), selected), { name: "Failure" });
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
  system.readGraphImageBaseline = async () => undefined;
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
  rejected.readGraphImageBaseline = async () => undefined;
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
    system.readGraphImageBaseline = async () => undefined;
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
  system.readGraphImageBaseline = async () => undefined;
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

test("rejects an unproved two-row load immediately after its strict inventory delta", async () => {
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
  const baselineRows = [
    `docker.io/library/zasp-audit-api:m1-30a application/vnd.oci.image.manifest.v1+json ` +
      `sha256:${"7".repeat(64)} 12.3 MiB linux/arm64 managed=true`,
    `registry.k8s.io/pause:3.10 application/vnd.oci.image.manifest.v1+json ` +
      `sha256:${"8".repeat(64)} 320 KiB linux/arm64 io.cri-containerd.image=managed`,
  ];
  const neo4jRows = graphImportRows("neo4j");
  const inventories = [
    containerdInventory(baselineRows),
    containerdInventory([...baselineRows, ...neo4jRows]),
  ];
  let inventory = 0;
  system.runNodeRead = async (arguments_) => {
    calls.push(["node", ...arguments_]);
    return success(inventories[inventory++]);
  };
  await assert.rejects(() => system.loadAdditionalImages(phase), { category: "provider", name: "Failure" });
  const list = ["node", "ctr", "--namespace", "k8s.io", "images", "list"];
  assert.deepEqual(calls, [
    list,
    ["/owned/kind", "load", "docker-image", NEO4J_IMAGE, "--name", system.cluster],
    list,
  ]);
  assert.equal(inventory, 2);
  assert.equal(system.graphLoadedImageTargets.size, 0);

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
  definitive.runNodeRead = async () => success(containerdInventory(baselineRows));
  definitive.runMutation = async () => ({ outcome: "definitive", result: { ...success(), status: 1 } });
  await assert.rejects(() => definitive.loadAdditionalImages(phase), { name: "Failure" });
  assert.equal(definitive.graphLoadedImageTargets.size, 0);
});

test("reads and proves Docker archive content before retaining graph image targets", async () => {
  const system = graphSystem();
  const calls = [];
  system.nodeIdentity = { token: "a".repeat(64) };
  system.paths = { kind: "/owned/kind" };
  system.requireTemporaryOwnership = async () => {};
  system.verifyCluster = async () => system.nodeIdentity;
  system.verifyGraphImage = async () => {};
  const fixtures = [graphBoundArchiveImport("neo4j"), graphBoundArchiveImport("busybox")];
  for (const fixture of fixtures) {
    system.graphImageIdentities.set(fixture.selected.name, fixture.retained);
    system.graphImageResolutions.set(fixture.selected.name, resolvedImage(fixture.selected));
  }
  system.runMutation = async (command, arguments_) => {
    calls.push([command, ...arguments_]);
    return { outcome: "ambiguous", result: success("loaded\n") };
  };
  system.runNodeMutation = async (arguments_) => {
    calls.push(["node-mutation", ...arguments_]);
    return { outcome: "ambiguous", result: success("alias\n") };
  };
  const productRows = [
    `docker.io/library/zasp-audit-api:m1-30a application/vnd.oci.image.manifest.v1+json ` +
      `sha256:${"7".repeat(64)} 12.3 MiB linux/arm64 managed=true`,
  ];
  const neo4jRows = [...productRows, ...fixtures[0].rows];
  const boundNeo4jRows = [...neo4jRows, [
    fixtures[0].alias.reference, fixtures[0].alias.mediaType, fixtures[0].alias.digest,
    fixtures[0].alias.size, fixtures[0].alias.platform, fixtures[0].alias.labels,
  ].join(" ")];
  const runtimeNeo4jRows = [...boundNeo4jRows, [
    fixtures[0].runtimeAlias.reference, fixtures[0].runtimeAlias.mediaType, fixtures[0].runtimeAlias.digest,
    fixtures[0].runtimeAlias.size, fixtures[0].runtimeAlias.platform, fixtures[0].runtimeAlias.labels,
  ].join(" ")];
  const allRows = [...runtimeNeo4jRows, ...fixtures[1].rows];
  const boundRows = [...allRows, [
    fixtures[1].alias.reference, fixtures[1].alias.mediaType, fixtures[1].alias.digest,
    fixtures[1].alias.size, fixtures[1].alias.platform, fixtures[1].alias.labels,
  ].join(" ")];
  const runtimeRows = [...boundRows, [
    fixtures[1].runtimeAlias.reference, fixtures[1].runtimeAlias.mediaType, fixtures[1].runtimeAlias.digest,
    fixtures[1].runtimeAlias.size, fixtures[1].runtimeAlias.platform, fixtures[1].runtimeAlias.labels,
  ].join(" ")];
  const outputs = [
    containerdInventory(productRows),
    containerdInventory(neo4jRows),
    fixtures[0].manifestSource,
    fixtures[0].wrapperSource,
    containerdInventory(boundNeo4jRows),
    containerdInventory(runtimeNeo4jRows),
    containerdInventory(runtimeNeo4jRows),
    containerdInventory(allRows),
    fixtures[1].manifestSource,
    fixtures[1].wrapperSource,
    containerdInventory(boundRows),
    containerdInventory(runtimeRows),
  ];
  system.runNodeRead = async (arguments_) => {
    calls.push(["node", ...arguments_]);
    return success(outputs.shift());
  };
  await system.loadAdditionalImages(phase);
  assert.equal(outputs.length, 0);
  assert.deepEqual(Object.fromEntries(system.graphLoadedImageTargets), {
    busybox: fixtures[1].runtimeTarget,
    neo4j: fixtures[0].runtimeTarget,
  });
  const inventory = ["node", "ctr", "--namespace", "k8s.io", "images", "list"];
  const content = (digest) => ["node", "ctr", "--namespace", "k8s.io", "content", "get", digest];
  assert.deepEqual(calls, [
    inventory,
    ["/owned/kind", "load", "docker-image", NEO4J_IMAGE, "--name", system.cluster],
    inventory,
    content(fixtures[0].target.references.find(({ mediaType, reference }) =>
      mediaType.endsWith("manifest.v1+json") && reference.startsWith("import-"))?.digest),
    content(fixtures[0].target.references.find(({ mediaType }) => mediaType.endsWith("index.v1+json"))?.digest),
    ["node-mutation", "ctr", "--namespace", "k8s.io", "images", "tag", "--local",
      fixtures[0].target.references.find(({ mediaType }) => mediaType.endsWith("index.v1+json"))?.reference,
      fixtures[0].alias.reference],
    inventory,
    ["node-mutation", "ctr", "--namespace", "k8s.io", "images", "tag", "--local",
      fixtures[0].target.references.find(({ mediaType, reference }) =>
        mediaType.endsWith("manifest.v1+json") && reference.startsWith("import-"))?.reference,
      fixtures[0].runtimeAlias.reference],
    inventory,
    inventory,
    ["/owned/kind", "load", "docker-image", BUSYBOX_IMAGE, "--name", system.cluster],
    inventory,
    content(fixtures[1].target.references.find(({ mediaType, reference }) =>
      mediaType.endsWith("manifest.v1+json") && reference.startsWith("import-"))?.digest),
    content(fixtures[1].target.references.find(({ mediaType }) => mediaType.endsWith("index.v1+json"))?.digest),
    ["node-mutation", "ctr", "--namespace", "k8s.io", "images", "tag", "--local",
      fixtures[1].target.references.find(({ mediaType }) => mediaType.endsWith("index.v1+json"))?.reference,
      fixtures[1].alias.reference],
    inventory,
    ["node-mutation", "ctr", "--namespace", "k8s.io", "images", "tag", "--local",
      fixtures[1].target.references.find(({ mediaType, reference }) =>
        mediaType.endsWith("manifest.v1+json") && reference.startsWith("import-"))?.reference,
      fixtures[1].runtimeAlias.reference],
    inventory,
  ]);
});

test("rejects node image inventory drift between the two proved graph loads", async () => {
  const system = graphSystem();
  system.nodeIdentity = { token: "a".repeat(64) };
  system.paths = { kind: "/owned/kind" };
  system.requireTemporaryOwnership = async () => {};
  system.verifyCluster = async () => system.nodeIdentity;
  system.verifyGraphImage = async () => {};
  const fixtures = [graphBoundArchiveImport("neo4j"), graphBoundArchiveImport("busybox")];
  for (const fixture of fixtures) {
    system.graphImageIdentities.set(fixture.selected.name, fixture.retained);
    system.graphImageResolutions.set(fixture.selected.name, resolvedImage(fixture.selected));
  }
  system.runMutation = async () => ({ outcome: "ambiguous", result: success("loaded\n") });
  system.runNodeMutation = async () => ({ outcome: "ambiguous", result: success("alias\n") });
  const productRows = [
    `docker.io/library/zasp-audit-api:m1-30a application/vnd.oci.image.manifest.v1+json ` +
      `sha256:${"7".repeat(64)} 12.3 MiB linux/arm64 managed=true`,
  ];
  const importedRows = [...productRows, ...fixtures[0].rows];
  const workloadRows = [...importedRows, [
    fixtures[0].alias.reference, fixtures[0].alias.mediaType, fixtures[0].alias.digest,
    fixtures[0].alias.size, fixtures[0].alias.platform, fixtures[0].alias.labels,
  ].join(" ")];
  const runtimeRows = [...workloadRows, [
    fixtures[0].runtimeAlias.reference, fixtures[0].runtimeAlias.mediaType, fixtures[0].runtimeAlias.digest,
    fixtures[0].runtimeAlias.size, fixtures[0].runtimeAlias.platform, fixtures[0].runtimeAlias.labels,
  ].join(" ")];
  const outputs = [
    containerdInventory(productRows), containerdInventory(importedRows), fixtures[0].manifestSource,
    fixtures[0].wrapperSource, containerdInventory(workloadRows), containerdInventory(runtimeRows),
    containerdInventory(runtimeRows).replace("12.3 MiB", "12.4 MiB"),
  ];
  system.runNodeRead = async () => success(outputs.shift());
  await assert.rejects(() => system.loadAdditionalImages(phase), { category: "ownership", name: "Failure" });
  assert.equal(outputs.length, 0);
  assert.deepEqual([...system.graphLoadedImageTargets.keys()], ["neo4j"]);
});

test("retains the last proved inventory across every first-image mutation failure", async () => {
  const fixture = graphBoundArchiveImport("neo4j");
  const invalidContentFixture = graphBoundArchiveImport("neo4j", "linux/arm64", ({ manifest, phase }) => {
    if (phase === "manifest") manifest.config.digest = `sha256:${"e".repeat(64)}`;
  });
  const row = (value) => [
    value.reference, value.mediaType, value.digest, value.size, value.platform, value.labels,
  ].join(" ");
  const baselineRows = [
    `docker.io/library/zasp-audit-api:m1-30a application/vnd.oci.image.manifest.v1+json ` +
      `sha256:${"7".repeat(64)} 12.3 MiB linux/arm64 managed=true`,
  ];
  const importedRows = [...baselineRows, ...fixture.rows];
  const invalidContentRows = [...baselineRows, ...invalidContentFixture.rows];
  const workloadRows = [...importedRows, row(fixture.alias)];
  const baseline = containerdInventory(baselineRows);
  const imported = containerdInventory(importedRows);
  const invalidContent = containerdInventory(invalidContentRows);
  const workload = containerdInventory(workloadRows);
  const malformedImport = containerdInventory([...baselineRows, "malformed"]);
  const badWorkload = containerdInventory([...importedRows,
    row(fixture.alias).replace("docker.io/library/neo4j", "registry.example/neo4j")]);
  const badRuntime = containerdInventory([...workloadRows,
    row(fixture.runtimeAlias).replace("docker.io/library/", "registry.example/")]);
  const cases = [
    { label: "definitive load", load: "definitive", reads: [baseline], retained: baseline, observed: baseline },
    { label: "partial load", load: "ambiguous", reads: [baseline, malformedImport], retained: baseline,
      observed: malformedImport, cleanupRejects: true },
    { label: "invalid imported content", load: "ambiguous",
      reads: [baseline, invalidContent, invalidContentFixture.manifestSource,
        invalidContentFixture.wrapperSource],
      retained: baseline, observed: invalidContent, cleanupRejects: true },
    { label: "definitive workload alias", load: "ambiguous", node: ["definitive"],
      reads: [baseline, imported, fixture.manifestSource, fixture.wrapperSource],
      retained: imported, observed: imported },
    { label: "partial workload alias", load: "ambiguous", node: ["ambiguous"],
      reads: [baseline, imported, fixture.manifestSource, fixture.wrapperSource, badWorkload],
      retained: imported, observed: badWorkload, cleanupRejects: true },
    { label: "definitive runtime alias", load: "ambiguous", node: ["ambiguous", "definitive"],
      reads: [baseline, imported, fixture.manifestSource, fixture.wrapperSource, workload],
      retained: workload, observed: workload },
    { label: "partial runtime alias", load: "ambiguous", node: ["ambiguous", "ambiguous"],
      reads: [baseline, imported, fixture.manifestSource, fixture.wrapperSource, workload, badRuntime],
      retained: workload, observed: badRuntime, cleanupRejects: true },
  ];
  for (const scenario of cases) {
    const system = graphSystem();
    system.graphImagePlans = new Map([[fixture.selected.name, fixture.selected]]);
    system.nodeIdentity = { token: "a".repeat(64) };
    system.paths = { graphManifest: "/owned/graph.yaml", kind: "/owned/kind" };
    system.graphImageIdentities.set(fixture.selected.name, fixture.retained);
    system.graphImageResolutions.set(fixture.selected.name, resolvedImage(fixture.selected));
    system.requireTemporaryOwnership = async () => {};
    system.requireOwnedPath = async () => {};
    system.verifyCluster = async () => system.nodeIdentity;
    system.verifyGraphImage = async () => {};
    system.runMutation = async () => ({ outcome: scenario.load, result: success("load\n") });
    const nodeOutcomes = [...(scenario.node ?? [])];
    system.runNodeMutation = async () => ({ outcome: nodeOutcomes.shift(), result: success("alias\n") });
    const reads = [...scenario.reads];
    system.runNodeRead = async () => success(reads.shift());
    await assert.rejects(() => system.loadAdditionalImages(phase), { name: "Failure" }, scenario.label);
    assert.equal(reads.length, 0, `${scenario.label} consumes only its bounded evidence`);
    assert.equal(system.graphNodeImageInventory, scenario.retained, `${scenario.label} retained inventory`);

    system.graphNodeMayHaveApplied = true;
    system.graphPathMayHaveApplied = true;
    system.graphNodeIdentity = { labeled: true, name: `${system.cluster}-control-plane`,
      token: system.nodeIdentity.token, uid: "11111111-1111-4111-8111-111111111111" };
    system.graphPathIdentity = { dev: 43, gid: 7474, ino: 99, mode: 700,
      nodeToken: system.nodeIdentity.token, path: GRAPH_CONSTANTS.nodeDataPath, uid: 7474 };
    system.readGraphNodeLabel = async () => system.graphNodeIdentity;
    system.readGraphNodePath = async () => system.graphPathIdentity;
    system.runNodeRead = async () => success(scenario.observed);
    if (scenario.cleanupRejects) {
      await assert.rejects(() => system.verifyAdditionalNodeForCleanup(phase),
        { category: "cleanup", name: "Failure" }, scenario.label);
    } else {
      await system.verifyAdditionalNodeForCleanup(phase);
    }
  }
});

test("re-proves the complete node image inventory before graph manifest application", async () => {
  const system = graphSystem();
  const inventory = containerdInventory(graphArchiveImport("neo4j").rows);
  system.paths = { graphManifest: "/owned/graph.yaml" };
  system.graphNodeIdentity = { labeled: true, name: `${system.cluster}-control-plane`, token: "a".repeat(64) };
  system.graphPathIdentity = { nodeToken: "a".repeat(64), path: GRAPH_CONSTANTS.nodeDataPath };
  system.graphNodeImageInventory = inventory;
  system.requireTemporaryOwnership = async () => {};
  system.verifyCluster = async () => ({ token: "a".repeat(64) });
  system.readGraphNodeLabel = async () => system.graphNodeIdentity;
  system.readGraphNodePath = async () => system.graphPathIdentity;
  system.requireOwnedPath = async () => {};
  system.runNodeRead = async () => success(inventory);
  await system.verifyAdditionalManifestState(phase, system.paths.graphManifest);

  system.runNodeRead = async () => success(inventory.replace("456 MiB", "455 MiB"));
  await assert.rejects(
    () => system.verifyAdditionalManifestState(phase, system.paths.graphManifest),
    { category: "ownership", name: "Failure" },
  );
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
  system.graphNodeImageInventory = containerdInventory(graphArchiveImport("neo4j").rows);
  system.graphNodeMayHaveApplied = true;
  system.graphPathMayHaveApplied = true;
  system.requireTemporaryOwnership = async () => { events.push("root"); };
  system.requireOwnedPath = async () => { events.push("manifest"); };
  system.verifyCluster = async () => { events.push("cluster"); return system.nodeIdentity; };
  system.readGraphNodeLabel = async () => { events.push("label"); return system.graphNodeIdentity; };
  system.readGraphNodePath = async () => { events.push("path"); return system.graphPathIdentity; };
  system.runNodeRead = async (arguments_) => {
    assert.deepEqual(arguments_, ["ctr", "--namespace", "k8s.io", "images", "list"]);
    events.push("images");
    return success(system.graphNodeImageInventory);
  };
  await system.verifyAdditionalNodeForCleanup(phase);
  assert.deepEqual(events, ["root", "manifest", "cluster", "images", "label", "path"]);

  system.readGraphNodePath = async () => ({ ...system.graphPathIdentity, ino: 100 });
  await assert.rejects(() => system.verifyAdditionalNodeForCleanup(phase), { name: "Failure" });
  assert.equal(system.graphPathMayHaveApplied, true, "replacement retains recovery material and blocks deletion");

  system.readGraphNodePath = async () => system.graphPathIdentity;
  system.runNodeRead = async () => success(
    system.graphNodeImageInventory.replace("456 MiB", "455 MiB"),
  );
  await assert.rejects(
    () => system.verifyAdditionalNodeForCleanup(phase),
    { category: "cleanup", name: "Failure" },
  );
});

test("boundedly reconciles uncertain exact pod deletion before base node removal", async () => {
  const initial = graphRunModule.validateGraphKubernetesState(
    graphProviderState(), graphProviderExpectation(),
  );
  const replacementState = graphProviderState({
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  });
  const setup = (providerState) => {
    const system = graphSystem();
    system.paths = { graphManifest: "/owned/graph.yaml" };
    system.nodeIdentity = { token: "a".repeat(64) };
    system.graphNodeIdentity = { labeled: true, name: `${system.cluster}-control-plane`,
      token: system.nodeIdentity.token, uid: "11111111-1111-4111-8111-111111111111" };
    system.graphNodeMayHaveApplied = true;
    system.graphProviderIdentity = initial;
    system.graphPodDeleteMayHaveApplied = true;
    system.graphLoadedImageTargets = new Map(Object.entries(graphProviderExpectation().imageTargets));
    system.requireTemporaryOwnership = async () => {};
    system.requireOwnedPath = async () => {};
    system.verifyCluster = async () => system.nodeIdentity;
    system.readGraphNodeLabel = async () => system.graphNodeIdentity;
    let reads = 0;
    system.readGraphProviderState = async () => {
      reads += 1;
      if (providerState instanceof Error) throw providerState;
      return structuredClone(providerState);
    };
    system.pauseGraphPoll = async () => {};
    return { reads: () => reads, system };
  };

  for (const [name, state, replacement] of [
    ["original", graphProviderState(), false],
    ["replacement", replacementState, true],
    ["absent", graphProviderStateWithout("neo4j"), false],
  ]) {
    const subject = setup(state);
    await subject.system.verifyAdditionalNodeForCleanup(phase);
    assert.equal(subject.reads(), 1, name);
    assert.equal(subject.system.graphPodDeleteMayHaveApplied, false, name);
    if (replacement) assert.equal(subject.system.graphProviderIdentity.neo4j.podUid, providerUid(10));
    if (name === "absent") {
      assert.equal(subject.system.graphProviderIdentity, undefined);
      assert.deepEqual(subject.system.graphProviderAbsenceIdentity,
        graphProviderAbsence("neo4j", initial));
      assert.ok(Object.isFrozen(subject.system.graphProviderAbsenceIdentity));
    }
  }

  for (const [name, state] of [
    ["foreign", (() => {
      const value = structuredClone(replacementState);
      value.deployments.at(-1).metadata.uid = providerUid(99);
      return value;
    })()],
    ["unproved", new GraphFailure("cleanup")],
  ]) {
    const subject = setup(state);
    await assert.rejects(() => subject.system.verifyAdditionalNodeForCleanup(phase),
      { name: "Failure" }, name);
    assert.equal(subject.reads(), 3, `${name} reconciliation is bounded`);
    assert.equal(subject.system.graphPodDeleteMayHaveApplied, true, name);
  }
});

test("retains exact provider absence across a failed base node removal and re-proves it on cleanup retry", async () => {
  const initial = graphRunModule.validateGraphKubernetesState(
    graphProviderState(), graphProviderExpectation(),
  );
  const setup = (laterState, absent = "neo4j") => {
    const system = graphSystem();
    system.paths = { graphManifest: "/owned/graph.yaml" };
    system.clusterMayHaveApplied = true;
    system.nodeIdentity = { token: "a".repeat(64), volumeToken: "b".repeat(64) };
    system.graphProviderIdentity = initial;
    system.graphPodDeleteMayHaveApplied = absent === "neo4j";
    system.graphHealthDeleteMayHaveApplied = absent === "health";
    system.graphLoadedImageTargets = new Map(Object.entries(graphProviderExpectation().imageTargets));
    system.requireTemporaryOwnership = async () => {};
    system.requireOwnedPath = async () => {};
    system.verifyCluster = async () => system.nodeIdentity;
    let reads = 0;
    system.readGraphProviderState = async () => {
      reads += 1;
      return structuredClone(reads === 1 ? graphProviderStateWithout(absent) : laterState);
    };
    system.pauseGraphPoll = async () => {};
    let removals = 0;
    system.runMutation = async (command, arguments_) => {
      assert.equal(command, "docker");
      assert.deepEqual(arguments_, ["rm", "--force", "--volumes", "a".repeat(64)]);
      removals += 1;
      return removals === 1
        ? { outcome: "definitive", result: { ...success(), status: 1 } }
        : { outcome: "applied", result: success() };
    };
    system.requireClusterAbsent = async () => {
      if (removals === 1) throw new GraphFailure("cleanup");
      system.nodeIdentity = undefined;
    };
    system.verifyStoppedClusterForCleanup = async () => { throw new GraphFailure("cleanup"); };
    system.cleanupAdditionalImages = async () => {};
    return { reads: () => reads, removals: () => removals, system };
  };

  for (const absent of ["neo4j", "health"]) {
    const exact = setup(graphProviderStateWithout(absent), absent);
    await assert.rejects(() => exact.system.cleanup(phase), { category: "cleanup", name: "Failure" });
    assert.equal(exact.reads(), 1, absent);
    assert.equal(exact.removals(), 1, absent);
    assert.deepEqual(exact.system.graphProviderAbsenceIdentity,
      graphProviderAbsence(absent, initial), absent);
    await exact.system.cleanup(phase);
    assert.equal(exact.reads(), 2, `${absent} retry independently re-proves the retained absence`);
    assert.equal(exact.removals(), 2, absent);
    assert.equal(exact.system.graphProviderAbsenceIdentity, undefined,
      `${absent} absence authority clears only after exact cluster absence`);
  }

  const replacementState = graphProviderState({
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  });
  const foreign = graphProviderStateWithout("neo4j");
  foreign.services.at(-1).metadata.uid = providerUid(99);
  for (const [name, laterState] of [
    ["late replacement", replacementState],
    ["foreign lineage", foreign],
  ]) {
    const subject = setup(laterState);
    await assert.rejects(() => subject.system.cleanup(phase), { category: "cleanup", name: "Failure" });
    await assert.rejects(() => subject.system.cleanup(phase),
      { category: "cleanup", name: "Failure" }, name);
    assert.equal(subject.reads(), 4, `${name} exhausts only the fixed second-proof bound`);
    assert.equal(subject.removals(), 1, `${name} blocks a second destructive node mutation`);
    assert.deepEqual(subject.system.graphProviderAbsenceIdentity,
      graphProviderAbsence("neo4j", initial), name);
  }
});

test("reconciles uncertain health deletion and recreation before base node removal", async () => {
  const replacementOverrides = {
    podContainerID: `containerd://${"c".repeat(64)}`,
    podIP: "10.244.0.22",
    podName: "neo4j-abc123def4-uvwxy",
    podStartedAt: "2026-08-16T10:00:10Z",
    podUid: providerUid(10),
  };
  const initial = graphRunModule.validateGraphKubernetesState(
    graphProviderState(), graphProviderExpectation(),
  );
  const replacement = graphRunModule.validateGraphKubernetesState(
    graphProviderState(replacementOverrides), graphProviderExpectation(), initial, true,
  );
  const freshOverrides = {
    ...replacementOverrides,
    healthCompletionTime: "2026-08-16T10:00:16Z",
    healthContainerID: `containerd://${"d".repeat(64)}`,
    healthFinishedAt: "2026-08-16T10:00:15Z",
    healthJobStartedAt: "2026-08-16T10:00:12Z",
    healthPodName: "neo4j-health-klmno",
    healthPodStartedAt: "2026-08-16T10:00:13Z",
    healthPodUid: providerUid(12),
    jobUid: providerUid(11),
  };
  const setup = (providerState, operation) => {
    const system = graphSystem();
    system.paths = { graphManifest: "/owned/graph.yaml" };
    system.nodeIdentity = { token: "a".repeat(64) };
    system.graphNodeIdentity = { labeled: true, name: `${system.cluster}-control-plane`,
      token: system.nodeIdentity.token, uid: "11111111-1111-4111-8111-111111111111" };
    system.graphNodeMayHaveApplied = true;
    system.graphProviderIdentity = replacement;
    system.graphHealthDeleteMayHaveApplied = operation === "delete";
    system.graphHealthApplyMayHaveApplied = operation === "apply";
    if (operation === "apply") {
      system.graphProviderAbsenceIdentity = Object.freeze(graphProviderAbsence("health", replacement));
    }
    system.graphLoadedImageTargets = new Map(Object.entries(graphProviderExpectation().imageTargets));
    system.requireTemporaryOwnership = async () => {};
    system.requireOwnedPath = async () => {};
    system.verifyCluster = async () => system.nodeIdentity;
    system.readGraphNodeLabel = async () => system.graphNodeIdentity;
    let reads = 0;
    system.readGraphProviderState = async (_phase, category, allowMissingHealth) => {
      assert.equal(category, "cleanup");
      assert.equal(allowMissingHealth, true);
      reads += 1;
      return structuredClone(providerState);
    };
    system.pauseGraphPoll = async () => {};
    return { reads: () => reads, system };
  };
  const healthAbsent = graphProviderStateWithout("health", replacementOverrides);
  for (const [name, state, operation, freshUid] of [
    ["delete-not-applied", graphProviderState(replacementOverrides), "delete", undefined],
    ["delete-applied", healthAbsent, "delete", undefined],
    ["apply-not-applied", healthAbsent, "apply", undefined],
    ["apply-applied", graphProviderState(freshOverrides), "apply", providerUid(11)],
  ]) {
    const subject = setup(state, operation);
    await subject.system.verifyAdditionalNodeForCleanup(phase);
    assert.equal(subject.reads(), 1, name);
    assert.equal(subject.system.graphHealthDeleteMayHaveApplied, false, name);
    assert.equal(subject.system.graphHealthApplyMayHaveApplied, false, name);
    if (freshUid !== undefined) {
      assert.equal(subject.system.graphProviderIdentity.health.jobUid, freshUid);
      assert.equal(subject.system.graphProviderAbsenceIdentity, undefined, name);
    }
    if (name === "delete-applied" || name === "apply-not-applied") {
      assert.equal(subject.system.graphProviderIdentity, undefined, name);
      assert.deepEqual(subject.system.graphProviderAbsenceIdentity,
        graphProviderAbsence("health", replacement), name);
      assert.ok(Object.isFrozen(subject.system.graphProviderAbsenceIdentity), name);
    }
  }

  for (const [name, state, operation] of [
    ["old health after apply", graphProviderState(replacementOverrides), "apply"],
    ["foreign health absence", (() => {
      const value = structuredClone(healthAbsent);
      value.services.at(-1).metadata.uid = providerUid(99);
      return value;
    })(), "delete"],
  ]) {
    const subject = setup(state, operation);
    await assert.rejects(() => subject.system.verifyAdditionalNodeForCleanup(phase),
      { name: "Failure" }, name);
    assert.equal(subject.reads(), 3, name);
  }
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

test("reuses exact shared graph images with zero or stable consumers without mutation", async () => {
  const selected = plan();
  const cases = [
    { consumers: [], listedIds: [], repoTags: [] },
    {
      consumers: [`${"c".repeat(64)}`, `${"d".repeat(64)}`],
      listedIds: [selected.configDigest],
      repoTags: [selected.tag],
    },
  ];
  for (const evidence of cases) {
    const { mutations, system } = sharedGraphImageHarness(selected, evidence);
    await system.buildAdditionalImages(phase);
    assert.equal(system.graphImageMayHaveApplied.size, 0);
    assert.deepEqual(system.graphImageIdentities.get(selected.name)?.repoTags, evidence.repoTags);
    assert.deepEqual(system.graphSharedImageBaselines.get(selected.name)?.consumers, evidence.consumers);

    await system.cleanupAdditionalImages(async (operation) => await operation(), phase);
    assert.equal(system.graphImageIdentities.size, 0);
    assert.deepEqual(mutations, [], "shared image admission and cleanup are read-only");

    await system.requireAdditionalGlobalAbsence(phase, "cleanup");
    assert.equal(system.graphSharedImageBaselines.size, 0);
    assert.deepEqual(mutations, [], "the final shared-state audit is read-only");
  }
});

test("rejects partial, mismatched, colliding, and ambiguous shared graph image baselines", async () => {
  const selected = plan();
  const cases = [
    sharedGraphImageHarness(selected, { referencePresent: false }),
    sharedGraphImageHarness(selected, { configPresent: false }),
    sharedGraphImageHarness(selected, { referenceId: `sha256:${"8".repeat(64)}` }),
    sharedGraphImageHarness(selected, {
      inspectionMutation: (inspection) => { inspection[5].Layers[0] = `sha256:${"9".repeat(64)}`; },
    }),
    sharedGraphImageHarness(selected, { listedIds: [`sha256:${"a".repeat(64)}`] }),
  ];
  cases.push(sharedGraphImageHarness(selected));
  cases.at(-1).system.imageIdentities.set(PRODUCTS[0].name, { id: selected.configDigest });

  for (const { mutations, system } of cases) {
    await assert.rejects(() => system.buildAdditionalImages(phase), { name: "Failure" });
    assert.deepEqual(mutations, [], "unproved shared state never grants pull or removal authority");
  }
});

test("rejects shared graph image consumer, alias, and immutable-identity drift without deletion", async () => {
  const selected = plan();
  const mutations = [
    (state) => { state.consumers = [`${"b".repeat(64)}`]; },
    (state) => {
      state.repoTags = [selected.tag];
      state.listedIds = [selected.configDigest];
    },
    (state) => {
      state.inspectionMutation = (inspection) => {
        inspection[5].Layers[0] = `sha256:${"7".repeat(64)}`;
      };
    },
    (state) => { state.referenceId = `sha256:${"6".repeat(64)}`; },
  ];
  for (const mutate of mutations) {
    const harness = sharedGraphImageHarness(selected);
    await harness.system.buildAdditionalImages(phase);
    mutate(harness.state);
    await assert.rejects(
      () => harness.system.cleanupAdditionalImages(async (operation) => await operation(), phase),
      { name: "Failure" },
    );
    assert.deepEqual(harness.mutations, [], "drifted shared state is never deleted");
    assert.equal(harness.system.graphImageIdentities.has(selected.name), true);
    assert.equal(harness.system.graphSharedImageBaselines.has(selected.name), true);
  }
});

test("final shared-image audit is exact and transactional across the whole graph range", async () => {
  const selected = plan();
  const drifted = sharedGraphImageHarness(selected);
  await drifted.system.buildAdditionalImages(phase);
  await drifted.system.cleanupAdditionalImages(async (operation) => await operation(), phase);
  drifted.state.consumers = [`${"a".repeat(64)}`];
  await assert.rejects(
    () => drifted.system.requireAdditionalGlobalAbsence(phase, "cleanup"),
    { name: "Failure" },
  );
  assert.equal(drifted.system.graphSharedImageBaselines.has(selected.name), true);
  assert.deepEqual(drifted.mutations, []);

  const range = graphSystem();
  const retained = { aliases: {}, consumers: [], identity: { id: selected.configDigest }, listedIds: [] };
  for (const [name] of range.graphImagePlans) {
    range.graphSharedImageBaselines.set(name, retained);
    range.graphImageResolutions.set(name, {});
  }
  range.readGraphImageBaseline = async (image, _resolution, _phase, _category, baseline) => {
    if (image.name === "busybox") throw new GraphFailure("cleanup");
    return baseline;
  };
  await assert.rejects(() => range.requireAdditionalGlobalAbsence(phase, "cleanup"), { name: "Failure" });
  assert.deepEqual([...range.graphSharedImageBaselines.keys()], ["neo4j", "busybox"],
    "a later audit rejection retains every baseline for an exact retry");
});

test("shared graph image cleanup rejection wins over an earlier provider rejection", async () => {
  const selected = plan();
  const harness = sharedGraphImageHarness(selected);
  await harness.system.buildAdditionalImages(phase);
  harness.state.consumers = [`${"e".repeat(64)}`];
  const output = [];
  const runtime = lifecycle({
    cleanup: async () => await harness.system.cleanupAdditionalImages(
      async (operation) => await operation(), phase,
    ),
    verifyReadiness: async () => { throw new GraphFailure("provider"); },
  }).runtime;
  assert.equal(await runGraphMain(runtime, {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 100,
    stderr: { write: (value) => output.push(value) },
    stdout: { write: () => assert.fail("unexpected success") },
    setExitCode() {},
  }), 1);
  assert.deepEqual(output, ["Local graph manifest failed: cleanup rejected.\n"]);
  assert.deepEqual(harness.mutations, [], "cleanup precedence never weakens shared-image preservation");
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
