import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { buildKindConfig, buildKindCreateArguments } from "./run.mjs";
import {
  LocalGraphSystem,
  bindGraphContainerdRuntimeAlias,
  bindGraphContainerdWorkloadAlias,
  buildGraphImagePlan,
  parseGraphContainerdImageTargets,
  validateGraphContainerdImageContents,
} from "./graph-run.mjs";
import {
  OBSERVABILITY_CONSTANTS,
  buildObservabilityResources,
  buildSyntheticObservabilitySpan,
  renderObservabilitySpanManifest,
} from "./observability-manifest.mjs";
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
  validateObservabilityKubernetesState,
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

function collectorManifestLayers(selected) {
  return {
    "linux/amd64": [
      ["sha256:8c8a67a16bae14d484a4480fd94097228acb83f2746c2293f1eeeea1c12f442e", 104777],
      ["sha256:5d91b1b2ea92893a66dbe36f05fa085279852d73183468ed3416f785b8435ca7", 107881884],
      ["sha256:8233e4e5eb575ff94048bfd4ecf0fbb0b3a1abed5e6231b2fd608386f5ca4c11", 830],
    ],
    "linux/arm64": [
      ["sha256:34b792c60cdbd7e37aacef47fb59842810f6a2a7ac0bf34e1616700f6cc7e37f", 104777],
      ["sha256:a259f54463eaa1c0fcef7a5cb382eef6c368cbfca16848ae360a7ca82710fe20", 97957362],
      ["sha256:da800e1629f8181d26e0a5b6fc8f39986b681a42a57280824d91237fe0ef5327", 829],
    ],
  }[selected.platform].map(([digest, size]) => ({
    digest,
    mediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
    size,
  }));
}

function resolution(selected) {
  return {
    index: { indexDigest: selected.indexDigest, selected: { digest: selected.manifestDigest } },
    manifest: collectorManifestDocument(selected),
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
      mediaType: "application/vnd.docker.container.image.v1+json",
      size: selected.platform === "linux/amd64" ? 2409 : 2417,
    },
    layers: collectorManifestLayers(selected),
    mediaType: "application/vnd.docker.distribution.manifest.v2+json",
    schemaVersion: 2,
  };
}

function containerdInventory(rows) {
  return ["REF TYPE DIGEST SIZE PLATFORMS LABELS", ...rows].join("\n") + "\n";
}

function collectorArchiveImport(platform = "linux/arm64") {
  const selected = buildCollectorImagePlan(platform);
  const retained = validateCollectorImageInspection(
    collectorInspection(selected), selected, resolution(selected),
  );
  const manifestSource = JSON.stringify({
    config: {
      digest: selected.configDigest,
      mediaType: "application/vnd.oci.image.config.v1+json",
      size: resolution(selected).manifest.config.size,
    },
    layers: retained.rootfs.Layers.map((digest, index) => ({
      digest,
      mediaType: "application/vnd.oci.image.layer.v1.tar",
      size: [182_784, 358_221_824, 4_608][index],
    })),
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    schemaVersion: 2,
  });
  const childDigest = `sha256:${createHash("sha256").update(manifestSource).digest("hex")}`;
  const wrapperSource = JSON.stringify({
    manifests: [{
      digest: childDigest,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      size: Buffer.byteLength(manifestSource),
    }],
    mediaType: "application/vnd.oci.image.index.v1+json",
    schemaVersion: 2,
  });
  const wrapperDigest = `sha256:${createHash("sha256").update(wrapperSource).digest("hex")}`;
  const date = "2026-08-17";
  const labels = "io.cri-containerd.image=managed";
  const child = `import-${date}@${childDigest} application/vnd.oci.image.manifest.v1+json ${childDigest} 341.8 MiB ${platform} ${labels}`;
  const wrapper = `import-${date}@${wrapperDigest} application/vnd.oci.image.index.v1+json ${wrapperDigest} 4.9 MiB ${platform} ${labels}`;
  const alias = `${selected.configDigest} application/vnd.oci.image.manifest.v1+json ${childDigest} 341.8 MiB ${platform} ${labels}`;
  return { alias, child, childDigest, manifestSource, retained, selected, wrapper, wrapperDigest, wrapperSource };
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

function providerUid(index) {
  return `${index.toString(16).padStart(8, "0")}-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
}

function providerContainer(value) {
  const projected = {
    ...clone(value),
    terminationMessagePath: "/dev/termination-log",
    terminationMessagePolicy: "File",
  };
  projected.volumeMounts = projected.volumeMounts?.map((mount) => {
    const item = { ...mount };
    if (item.readOnly === false) delete item.readOnly;
    return item;
  });
  return projected;
}

function providerTemplate(template, labels = template.metadata.labels) {
  return {
    metadata: { creationTimestamp: null, labels: clone(labels) },
    spec: {
      ...clone(template.spec),
      containers: template.spec.containers.map(providerContainer),
      schedulerName: "default-scheduler",
    },
  };
}

function providerPodSpec(template, nodeName) {
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
    securityContext: clone(template.spec.securityContext),
    serviceAccount: "default",
    serviceAccountName: "default",
    terminationGracePeriodSeconds: template.spec.terminationGracePeriodSeconds,
    tolerations: [
      { effect: "NoExecute", key: "node.kubernetes.io/not-ready", operator: "Exists", tolerationSeconds: 300 },
      { effect: "NoExecute", key: "node.kubernetes.io/unreachable", operator: "Exists", tolerationSeconds: 300 },
    ],
    volumes: clone(template.spec.volumes),
  };
}

function observabilityExpectation(platform = "linux/amd64") {
  const collector = buildCollectorImagePlan(platform);
  const busybox = buildGraphImagePlan("busybox", platform);
  return {
    imageTargets: {
      busybox: {
        configDigest: busybox.configDigest,
        imageID: `docker.io/library/import-2026-08-16@${busybox.manifestDigest}`,
      },
      collector: {
        configDigest: collector.configDigest,
        imageID: `docker.io/library/import-2026-08-16@${collector.manifestDigest}`,
      },
    },
    nodeName: `zasp-m1-30c-${input.marker}-control-plane`,
  };
}

function observabilityProviderState({ includeJob = true, platform = "linux/amd64" } = {}) {
  const expectation = observabilityExpectation(platform);
  const [configResource, deploymentResource, serviceResource, jobResource] = buildObservabilityResources();
  const deploymentUid = providerUid(40);
  const replicaSetUid = providerUid(41);
  const podUid = providerUid(42);
  const serviceUid = providerUid(43);
  const hash = "abc123def4";
  const podName = `otel-collector-${hash}-pqrst`;
  const podIP = "10.244.0.30";
  const replicaLabels = { ...deploymentResource.metadata.labels, "pod-template-hash": hash };
  const deployment = {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: { generation: 1, labels: clone(deploymentResource.metadata.labels), name: "otel-collector", namespace: "zasp-local", resourceVersion: "201", uid: deploymentUid },
    spec: { ...clone(deploymentResource.spec), template: providerTemplate(deploymentResource.spec.template) },
    status: { availableReplicas: 1, conditions: [{ status: "True", type: "Available" }], observedGeneration: 1, readyReplicas: 1, replicas: 1, unavailableReplicas: 0, updatedReplicas: 1 },
  };
  const replicaSet = {
    apiVersion: "apps/v1",
    kind: "ReplicaSet",
    metadata: {
      labels: replicaLabels, name: `otel-collector-${hash}`, namespace: "zasp-local",
      ownerReferences: [{ apiVersion: "apps/v1", blockOwnerDeletion: true, controller: true, kind: "Deployment", name: "otel-collector", uid: deploymentUid }],
      resourceVersion: "202", uid: replicaSetUid,
    },
    spec: { replicas: 1, selector: { matchLabels: { "app.kubernetes.io/name": "otel-collector", "pod-template-hash": hash } }, template: providerTemplate(deploymentResource.spec.template, replicaLabels) },
    status: { availableReplicas: 1, fullyLabeledReplicas: 1, observedGeneration: 1, readyReplicas: 1, replicas: 1 },
  };
  const pod = {
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
      labels: replicaLabels, name: podName, namespace: "zasp-local",
      ownerReferences: [{ apiVersion: "apps/v1", blockOwnerDeletion: true, controller: true, kind: "ReplicaSet", name: replicaSet.metadata.name, uid: replicaSetUid }],
      resourceVersion: "203", uid: podUid,
    },
    spec: providerPodSpec(deploymentResource.spec.template, expectation.nodeName),
    status: {
      conditions: [{ status: "True", type: "Ready" }],
      containerStatuses: [
        { containerID: `containerd://${"c".repeat(64)}`, image: expectation.imageTargets.collector.configDigest, imageID: expectation.imageTargets.collector.imageID, lastState: {}, name: "otel-collector", ready: true, restartCount: 0, started: true, state: { running: { startedAt: "2026-08-16T10:00:00Z" } } },
        { containerID: `containerd://${"d".repeat(64)}`, image: expectation.imageTargets.busybox.configDigest, imageID: expectation.imageTargets.busybox.imageID, lastState: {}, name: "sink-reader", ready: true, restartCount: 0, started: true, state: { running: { startedAt: "2026-08-16T10:00:01Z" } } },
      ],
      phase: "Running",
      podIP,
    },
  };
  const service = {
    apiVersion: "v1", kind: "Service",
    metadata: { labels: clone(serviceResource.metadata.labels), name: "otel-collector", namespace: "zasp-local", resourceVersion: "204", uid: serviceUid },
    spec: { clusterIP: "10.96.0.30", clusterIPs: ["10.96.0.30"], internalTrafficPolicy: "Cluster", ...clone(serviceResource.spec) },
    status: { loadBalancer: {} },
  };
  const endpointSlice = {
    addressType: "IPv4", apiVersion: "discovery.k8s.io/v1",
    endpoints: [{ addresses: [podIP], conditions: { ready: true, serving: true, terminating: false }, nodeName: expectation.nodeName, targetRef: { kind: "Pod", name: podName, namespace: "zasp-local", uid: podUid } }],
    kind: "EndpointSlice",
    metadata: {
      labels: {
        ...clone(serviceResource.metadata.labels),
        "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
        "kubernetes.io/service-name": "otel-collector",
      },
      name: "otel-collector-abcde", namespace: "zasp-local",
      ownerReferences: [{ apiVersion: "v1", blockOwnerDeletion: true, controller: true, kind: "Service", name: "otel-collector", uid: serviceUid }],
      resourceVersion: "205", uid: providerUid(44),
    },
    ports: [{ name: "otlp-http", port: 4318, protocol: "TCP" }],
  };
  const value = {
    configMaps: [{ apiVersion: "v1", data: clone(configResource.data), kind: "ConfigMap", metadata: { labels: clone(configResource.metadata.labels), name: "otel-collector-config", namespace: "zasp-local", resourceVersion: "200", uid: providerUid(39) } }],
    deployments: [deployment], endpointSlices: [endpointSlice], ingresses: [], jobs: [], pods: [pod], replicaSets: [replicaSet], services: [service],
    jobLog: null,
  };
  if (!includeJob) return value;
  const jobUid = providerUid(45);
  const jobPodUid = providerUid(46);
  const jobLabels = { ...jobResource.spec.template.metadata.labels, "batch.kubernetes.io/controller-uid": jobUid, "batch.kubernetes.io/job-name": "otel-test-span", "controller-uid": jobUid, "job-name": "otel-test-span" };
  value.jobs.push({
    apiVersion: "batch/v1", kind: "Job",
    metadata: { labels: clone(jobResource.metadata.labels), name: "otel-test-span", namespace: "zasp-local", resourceVersion: "206", uid: jobUid },
    spec: {
      activeDeadlineSeconds: 30, backoffLimit: 0, completionMode: "NonIndexed", completions: 1,
      manualSelector: false, parallelism: 1, podReplacementPolicy: "Failed",
      selector: { matchLabels: { "batch.kubernetes.io/controller-uid": jobUid } }, suspend: false,
      template: providerTemplate(jobResource.spec.template, jobLabels),
    },
    status: {
      completionTime: "2026-08-16T10:00:06Z",
      conditions: [{ lastProbeTime: "2026-08-16T10:00:06Z", lastTransitionTime: "2026-08-16T10:00:06Z", status: "True", type: "Complete" }],
      failed: 0, ready: 0, startTime: "2026-08-16T10:00:02Z", succeeded: 1,
    },
  });
  value.pods.push({
    apiVersion: "v1", kind: "Pod",
    metadata: {
      labels: jobLabels, name: "otel-test-span-fghij", namespace: "zasp-local",
      ownerReferences: [{ apiVersion: "batch/v1", blockOwnerDeletion: true, controller: true, kind: "Job", name: "otel-test-span", uid: jobUid }],
      resourceVersion: "207", uid: jobPodUid,
    },
    spec: providerPodSpec(jobResource.spec.template, expectation.nodeName),
    status: {
      conditions: [{ status: "False", type: "Ready" }],
      containerStatuses: [{
        containerID: `containerd://${"e".repeat(64)}`, image: expectation.imageTargets.busybox.configDigest,
        imageID: expectation.imageTargets.busybox.imageID, lastState: {}, name: "span-generator", ready: false,
        restartCount: 0, started: false, state: { terminated: { containerID: `containerd://${"e".repeat(64)}`, exitCode: 0, finishedAt: "2026-08-16T10:00:05Z", reason: "Completed", startedAt: "2026-08-16T10:00:03Z" } },
      }],
      phase: "Succeeded", podIP: "10.244.0.31",
    },
  });
  value.jobLog = "otel-test-span-sent\n";
  return value;
}

function realisticObservabilityProviderState(options = {}) {
  const value = observabilityProviderState(options);
  const timestamp = "2026-08-16T09:59:00Z";
  for (const items of [
    value.configMaps, value.deployments, value.endpointSlices, value.jobs, value.pods, value.replicaSets,
    value.services,
  ]) {
    for (const item of items) {
      item.metadata.annotations = { "kubectl.kubernetes.io/last-applied-configuration": "{}" };
      item.metadata.creationTimestamp = timestamp;
      item.metadata.managedFields = [{ apiVersion: item.apiVersion, manager: "kubectl-client-side-apply" }];
    }
  }
  value.deployments[0].status.conditions.unshift({
    lastTransitionTime: timestamp,
    lastUpdateTime: timestamp,
    message: "ReplicaSet progressed.",
    reason: "NewReplicaSetAvailable",
    status: "True",
    type: "Progressing",
  });
  for (const pod of value.pods) {
    pod.status.hostIP = "172.18.0.2";
    pod.status.podIPs = [{ ip: pod.status.podIP }];
    pod.status.qosClass = "Burstable";
    pod.status.startTime = timestamp;
    pod.status.conditions.unshift({ status: "True", type: "PodScheduled" });
  }
  value.services[0].metadata.finalizers = ["service.kubernetes.io/load-balancer-cleanup"];
  if (value.jobs.length === 1) value.jobs[0].status.uncountedTerminatedPods = {};
  for (const item of [...value.deployments, ...value.replicaSets, ...value.jobs]) {
    delete item.spec.template.spec.hostIPC;
    delete item.spec.template.spec.hostNetwork;
    delete item.spec.template.spec.hostPID;
  }
  return value;
}

function emptyObservabilityProviderState() {
  return {
    configMaps: [], deployments: [], endpointSlices: [], ingresses: [], jobLog: null,
    jobs: [], pods: [], replicaSets: [], services: [],
  };
}

function failedObservabilityProviderState() {
  const value = observabilityProviderState();
  value.jobs[0].status.completionTime = undefined;
  value.jobs[0].status.conditions = [{
    lastProbeTime: "2026-08-16T10:00:06Z",
    lastTransitionTime: "2026-08-16T10:00:06Z",
    status: "True",
    type: "Failed",
  }];
  value.jobs[0].status.failed = 1;
  value.jobs[0].status.ready = 0;
  value.jobs[0].status.succeeded = 0;
  value.jobLog = "";
  const status = value.pods.at(-1).status;
  status.phase = "Failed";
  status.containerStatuses[0].state.terminated.exitCode = 1;
  status.containerStatuses[0].state.terminated.reason = "Error";
  return value;
}

function capturedProductProviderState() {
  return new Map([
    "deployments", "endpointSlices", "pods", "replicaSets", "services",
  ].map((key) => [key, Array.from({ length: 4 }, (_value, index) => ({ key, index }))]));
}

function providerList(items) {
  return `${JSON.stringify({ apiVersion: "v1", items, kind: "List", metadata: { resourceVersion: "" } })}\n`;
}

function sinkFrame(value = buildSyntheticObservabilitySpan(), metadata = "9|10|SIZE|regular file|10001|10001|600") {
  const bytes = `${JSON.stringify(value)}\n`;
  const identity = metadata.replace("SIZE", String(Buffer.byteLength(bytes)));
  return `ZASP-SINK:${identity}\n${bytes}ZASP-SINK:${identity}\n`;
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
    (value) => { value.manifests[0].bytes += " "; },
    (value) => { value.manifests[1].bytes = value.manifests[2].bytes; },
    (value) => { value.manifests[2].bytes = `${value.manifests[2].bytes.slice(0, -1)} \n`; },
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

  for (const field of ["bytes", "name", "pathKey"]) {
    let entryReads = 0;
    const entryAccessor = clone(profile);
    Object.defineProperty(entryAccessor.manifests[0], field, {
      configurable: true,
      enumerable: true,
      get() { entryReads += 1; return profile.manifests[0][field]; },
    });
    assert.throws(() => new LocalGraphSystem(input, undefined, entryAccessor), TypeError);
    assert.equal(entryReads, 0);
  }

  const fake = fakeLifecycle({});
  fake.runtime.profile = clone(profile);
  fake.runtime.profile.manifests[1].bytes = "forged collector manifest\n";
  assert.throws(() => new DockerKindObservabilityRuntime(input, fake.runtime), TypeError);
});

test("re-proves only the exact Collector core descriptor through inherited graph authority", async () => {
  class GuardedSystem extends LocalObservabilitySystem {
    constructor() {
      super(input);
      this.paths = Object.freeze({
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
  const phase = { assertActive() {} };
  await system.verifyAdditionalManifestState(phase, system.paths.observabilityCoreManifest);
  assert.deepEqual(system.checked, [system.paths.graphManifest, system.paths.observabilityCoreManifest]);
  await assert.rejects(
    () => system.verifyAdditionalManifestState(phase, "/safe/runtime/foreign.yaml"),
    { category: "ownership" },
  );
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
  assert.equal(system.observabilityCoreMayHaveApplied, true);
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

test("binds the exact pinned Collector through the inherited containerd archive pipeline", () => {
  const fixture = collectorArchiveImport();
  const baselineRows = [
    `docker.io/library/zasp-audit-api:m1-30a application/vnd.oci.image.manifest.v1+json ` +
      `sha256:${"7".repeat(64)} 12.3 MiB linux/arm64 managed=true`,
  ];
  const before = containerdInventory(baselineRows);
  const importedRows = [...baselineRows, fixture.child, fixture.wrapper, fixture.alias];
  const imported = containerdInventory(importedRows);
  const target = parseGraphContainerdImageTargets(before, imported, fixture.selected);
  assert.equal(validateGraphContainerdImageContents(
    target,
    fixture.manifestSource,
    fixture.wrapperSource,
    fixture.selected,
    fixture.retained,
    resolution(fixture.selected),
  ), target);

  const workloadReference = `docker.io/${fixture.selected.repoDigest}`;
  const workloadRow = fixture.wrapper.replace(/^\S+/, workloadReference);
  const workload = bindGraphContainerdWorkloadAlias(
    imported,
    containerdInventory([...importedRows, workloadRow]),
    target,
    fixture.selected,
  );
  const runtimeReference = `docker.io/library/${fixture.child.slice(0, fixture.child.indexOf(" "))}`;
  const runtimeRow = fixture.child.replace(/^\S+/, runtimeReference);
  const runtime = bindGraphContainerdRuntimeAlias(
    containerdInventory([...importedRows, workloadRow]),
    containerdInventory([...importedRows, workloadRow, runtimeRow]),
    workload,
    fixture.selected,
  );
  assert.equal(runtime.references.length, 5);
  assert.equal(runtime.imageID, runtimeReference);

  const drift = { ...fixture.selected, configDigest: `sha256:${"f".repeat(64)}` };
  assert.throws(() => parseGraphContainerdImageTargets(before, imported, drift), { name: "Failure" });
});

test("resolves the Collector through profile-local OCI validation without widening the graph image map", async () => {
  const selected = buildCollectorImagePlan("linux/amd64");
  const index = collectorIndexDocument();
  const manifest = collectorManifestDocument(selected);
  const validatedIndex = validateCollectorImageIndex(index, selected);
  const validatedManifest = validateCollectorImageManifest(manifest, selected);
  assert.equal(validatedIndex.selected.digest, selected.manifestDigest);
  assert.deepEqual(validatedManifest.layers, collectorManifestLayers(selected));
  assert.notDeepEqual(
    validatedManifest.layers.map(({ digest }) => digest),
    collectorInspection(selected)[5].Layers,
  );

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

test("normalizes one exact Collector core and one exact completed span Job", () => {
  const expected = observabilityExpectation();
  const core = validateObservabilityKubernetesState(
    observabilityProviderState({ includeJob: false }), expected, undefined, false,
  );
  assert.equal(core.ready, true);
  assert.equal(core.job, null);
  assert.equal(core.collector.podName, "otel-collector-abc123def4-pqrst");
  assert.equal(core.collector.podUid, providerUid(42));
  assert.equal(core.collector.resourceVersion, "200");

  const complete = validateObservabilityKubernetesState(
    observabilityProviderState(), expected, core, true,
  );
  assert.equal(complete.ready, true);
  assert.equal(complete.job.jobUid, providerUid(45));
  assert.equal(complete.job.podUid, providerUid(46));
  assert.equal(complete.job.log, "otel-test-span-sent\n");
  assert.deepEqual(complete.collector, core.collector);
});

test("rejects every observability provider ownership, exposure, lineage, status, and retry drift", () => {
  const expected = observabilityExpectation();
  const core = validateObservabilityKubernetesState(
    observabilityProviderState({ includeJob: false }), expected, undefined, false,
  );
  const mutations = [
    ["extra resource", (value) => { value.services.push(clone(value.services[0])); }],
    ["config resource version", (value) => { value.configMaps[0].metadata.resourceVersion = "foreign"; }],
    ["deployment owner", (value) => { value.replicaSets[0].metadata.ownerReferences[0].uid = providerUid(99); }],
    ["pod owner", (value) => { value.pods[0].metadata.ownerReferences[0].uid = providerUid(99); }],
    ["node", (value) => { value.pods[0].spec.nodeName = "foreign"; }],
    ["image", (value) => { value.pods[0].status.containerStatuses[0].imageID = "foreign"; }],
    ["mount", (value) => { value.pods[0].spec.containers[1].volumeMounts[0].readOnly = false; }],
    ["restart", (value) => { value.pods[0].status.containerStatuses[0].restartCount = 1; }],
    ["selector", (value) => { value.services[0].spec.selector["app.kubernetes.io/name"] = "foreign"; }],
    ["endpoint target", (value) => { value.endpointSlices[0].endpoints[0].targetRef.uid = providerUid(99); }],
    ["endpoint condition", (value) => { value.endpointSlices[0].endpoints[0].conditions.ready = false; }],
    ["endpoint copied label", (value) => { value.endpointSlices[0].metadata.labels["zasp.dev/environment"] = "foreign"; }],
    ["endpoint extra label", (value) => { value.endpointSlices[0].metadata.labels.foreign = "true"; }],
    ["external service", (value) => { value.services[0].spec.type = "LoadBalancer"; }],
    ["ingress", (value) => { value.ingresses.push({ kind: "Ingress" }); }],
    ["premature Job", (value) => { value.jobs = []; value.pods.pop(); value.jobLog = null; }],
    ["failed Job", (value) => { value.jobs[0].status.failed = 1; }],
    ["replaced Job pod", (value) => { value.pods.push(clone(value.pods.at(-1))); }],
    ["retry", (value) => { value.pods.at(-1).status.containerStatuses[0].restartCount = 1; }],
    ["timestamp", (value) => { value.jobs[0].status.completionTime = "2026-02-30T00:00:00Z"; }],
    ["log", (value) => { value.jobLog = "provider output\n"; }],
  ];
  for (const [name, mutate] of mutations) {
    const value = observabilityProviderState();
    mutate(value);
    assert.throws(() => validateObservabilityKubernetesState(value, expected, core, true),
      { category: "readiness" }, name);
  }
});

test("stages one span Job only after exact core readiness and reads one stable sink artifact", async () => {
  const expected = observabilityExpectation();
  const core = validateObservabilityKubernetesState(
    observabilityProviderState({ includeJob: false }), expected, undefined, false,
  );
  const complete = validateObservabilityKubernetesState(observabilityProviderState(), expected, core, true);
  const graphResult = Object.freeze({
    graph: Object.freeze({ internal: true, persistent: true, ready: true }),
    internal: true,
    pods: 4,
    ready: 4,
    services: 4,
  });

  class StagedSystem extends LocalObservabilitySystem {
    constructor(outcome = "applied") {
      super(input);
      this.events = [];
      this.outcome = outcome;
      this.productProviderCapture = capturedProductProviderState();
    }

    async verifyGraphReadiness(value) {
      this.events.push("graph");
      return value;
    }

    async pollObservabilityProviderState(_phase, retained, requireJob) {
      this.events.push(requireJob ? retained === complete ? "stable" : "complete" : "core");
      return requireJob ? complete : core;
    }

    async applyObservabilityJob() {
      this.events.push("apply-job");
      return { outcome: this.outcome };
    }

    async requireObservabilitySinkAbsent(retained) {
      assert.deepEqual(retained, core);
      this.events.push("sink-absent");
    }

    async readObservabilitySink(retained) {
      assert.deepEqual(retained, complete);
      this.events.push("read-sink");
      return buildSyntheticObservabilitySpan();
    }
  }

  const phase = { assertActive() {} };
  const system = new StagedSystem();
  assert.deepEqual(await system.verifyAdditionalReadiness(graphResult, phase), {
    ...graphResult,
    observability: { internal: true, noEgress: true, ready: true, sink: true, spans: 1 },
  });
  assert.deepEqual(system.events, [
    "graph", "core", "sink-absent", "apply-job", "complete", "read-sink", "stable",
  ]);
  assert.equal(system.observabilityCoreMayHaveApplied, false);
  assert.equal(system.observabilityJobMayHaveApplied, false);
  assert.deepEqual(system.observabilityProviderIdentity, complete);

  for (const outcome of ["definitive", "rejected"]) {
    const rejected = new StagedSystem(outcome);
    await assert.rejects(() => rejected.verifyAdditionalReadiness(graphResult, phase), { category: "provider" });
    assert.deepEqual(rejected.events, ["graph", "core", "sink-absent", "apply-job"]);
    assert.equal(rejected.observabilityJobMayHaveApplied, false);
  }
});

test("retains the original product snapshot across graph and observability reproof", async () => {
  const baseline = Object.freeze({ token: "original-product-provider-state" });
  const graphResult = Object.freeze({
    graph: Object.freeze({ internal: true, persistent: true, ready: true }),
    internal: true,
    pods: 4,
    ready: 4,
    services: 4,
  });
  class DriftSystem extends LocalObservabilitySystem {
    constructor() {
      super(input);
      this.productProviderSnapshot = baseline;
    }
    async verifyGraphReadiness() {
      this.productProviderSnapshot = Object.freeze({ token: "drifted-product-provider-state" });
      return graphResult;
    }
  }
  const system = new DriftSystem();
  await assert.rejects(
    () => system.verifyAdditionalReadiness(graphResult, { assertActive() {} }),
    { category: "ownership" },
  );
  assert.equal(system.productProviderSnapshot, baseline);
});

test("uses fixed bounded provider, Job-apply, log, and sink command boundaries", async () => {
  const state = observabilityProviderState();
  const rawState = realisticObservabilityProviderState();
  delete rawState.deployments[0].spec.template.metadata.creationTimestamp;
  delete rawState.replicaSets[0].spec.template.metadata.creationTimestamp;
  const expected = observabilityExpectation();
  const complete = validateObservabilityKubernetesState(state, expected, undefined, true);
  const resourceMap = new Map([
    ["configmap", rawState.configMaps], ["deployment", rawState.deployments],
    ["replicaset", rawState.replicaSets], ["pod", rawState.pods], ["service", rawState.services],
    ["endpointslice", rawState.endpointSlices], ["job", rawState.jobs], ["ingress", rawState.ingresses],
  ]);

  class ProviderSystem extends LocalObservabilitySystem {
    constructor() {
      super(input);
      this.paths = Object.freeze({
        graphManifest: "/safe/runtime/graph.yaml",
        kubeconfig: "/safe/runtime/kubeconfig",
        observabilityCoreManifest: "/safe/runtime/observability.yaml",
        observabilitySpanManifest: "/safe/runtime/observability-span.yaml",
      });
      this.environment = Object.freeze({ PATH: input.path });
      this.calls = [];
      this.sink = sinkFrame();
      this.mutationOutcome = "ambiguous";
      this.rawOverride = undefined;
    }

    async requireTemporaryOwnership() {}
    async verifyCluster() { return { token: "a".repeat(64) }; }
    async requireOwnedPath() {}
    async verifyAdditionalManifestState() {}
    async withOwnedFiles(paths, _phase, _category, callback) {
      return await callback(paths.map((path, index) => ({
        handle: { fd: index + 3 },
        identity: {
          bytes: Buffer.from(path === this.paths.observabilitySpanManifest
            ? renderObservabilitySpanManifest(buildObservabilityResources().slice(3)) : "owned", "utf8"),
        },
      })));
    }
    async runRead(command, arguments_) {
      this.calls.push(["read", command, arguments_]);
      const operation = arguments_.indexOf("get");
      if (operation >= 0) return {
        stderr: "",
        stdout: this.rawOverride ?? providerList(resourceMap.get(arguments_[operation + 1])),
      };
      if (arguments_.includes("logs")) return { stderr: "", stdout: "otel-test-span-sent\n" };
      if (arguments_.includes("exec")) return { stderr: "", stdout: this.sink };
      throw new Error("unexpected read");
    }
    async runMutation(command, arguments_, _phase, _category, options) {
      this.calls.push(["mutation", command, arguments_, options]);
      return { outcome: this.mutationOutcome };
    }
  }

  const phase = { assertActive() {} };
  const system = new ProviderSystem();
  assert.deepEqual(await system.readObservabilityProviderState(phase), state);
  for (const collection of [
    "configMaps", "deployments", "replicaSets", "pods", "services", "endpointSlices", "jobs",
  ]) {
    rawState[collection][0].metadata.deletionTimestamp = "2026-08-16T10:00:06Z";
    const terminating = new ProviderSystem();
    const projected = await terminating.readObservabilityProviderState(phase);
    assert.throws(
      () => validateObservabilityKubernetesState(projected, expected, undefined, true),
      { category: "readiness" },
      `${collection} deletion state must survive provider projection`,
    );
    delete rawState[collection][0].metadata.deletionTimestamp;
  }
  const failedProvider = failedObservabilityProviderState();
  resourceMap.set("job", failedProvider.jobs);
  resourceMap.set("pod", failedProvider.pods);
  const projectedFailure = await new ProviderSystem().readObservabilityProviderState(phase);
  assert.equal(projectedFailure.jobs[0].status.conditions[0].type, "Failed");
  assert.equal(projectedFailure.jobs[0].status.failed, 1);
  assert.equal(projectedFailure.pods.at(-1).status.containerStatuses[0].state.terminated.exitCode, 1);
  resourceMap.set("job", rawState.jobs);
  resourceMap.set("pod", rawState.pods);
  assert.deepEqual(system.calls.filter(([, , arguments_]) => arguments_.includes("get")).map(([, , arguments_]) =>
    arguments_.slice(2)), [
    ["get", "configmap", "--namespace", "zasp-local", "--selector=app.kubernetes.io/component=observability", "--output=json"],
    ["get", "deployment", "--namespace", "zasp-local", "--selector=app.kubernetes.io/component=observability", "--output=json"],
    ["get", "replicaset", "--namespace", "zasp-local", "--selector=app.kubernetes.io/component=observability", "--output=json"],
    ["get", "pod", "--namespace", "zasp-local", "--selector=app.kubernetes.io/component=observability", "--output=json"],
    ["get", "service", "--namespace", "zasp-local", "--selector=app.kubernetes.io/component=observability", "--output=json"],
    ["get", "endpointslice", "--namespace", "zasp-local", "--selector=kubernetes.io/service-name=otel-collector", "--output=json"],
    ["get", "job", "--namespace", "zasp-local", "--selector=app.kubernetes.io/component=observability", "--output=json"],
    ["get", "ingress", "--namespace", "zasp-local", "--selector=app.kubernetes.io/component=observability", "--output=json"],
  ]);
  assert.deepEqual(await system.applyObservabilityJob(phase), { outcome: "ambiguous" });
  const mutation = system.calls.find(([kind]) => kind === "mutation");
  assert.deepEqual(mutation.slice(1, 3), [
    "kubectl", ["--kubeconfig", "/dev/fd/3", "apply", "--filename", "-"],
  ]);
  assert.equal(
    mutation[3].input.toString("utf8"), renderObservabilitySpanManifest(buildObservabilityResources().slice(3)),
  );
  assert.deepEqual(await system.readObservabilitySink(complete, phase), buildSyntheticObservabilitySpan());
  const sinkCall = system.calls.find(([, , arguments_]) => arguments_.includes("exec"));
  assert.deepEqual(sinkCall[2].slice(2, 10), [
    "exec", "--namespace", OBSERVABILITY_CONSTANTS.namespace, complete.collector.podName,
    "--container", "sink-reader", "--", "sh",
  ]);
  assert.match(sinkCall[2].at(-1), /test ! -L.*stat -Lc.*dd if=.*bs=65537.*stat -Lc/u);

  system.sink = "ZASP-SINK-PRISTINE\n";
  await system.requireObservabilitySinkAbsent(complete, phase);
  const pristineCall = system.calls.filter(([, , arguments_]) => arguments_.includes("exec")).at(-1);
  assert.match(pristineCall[2].at(-1), /test ! -L.*if test -e.*test -f.*test ! -s/u);
  system.sink = sinkFrame();
  await assert.rejects(
    () => system.requireObservabilitySinkAbsent(complete, phase), { category: "readiness" },
  );

  for (const source of [
    "", "provider output\n", sinkFrame(undefined, "9|10|0|regular file|10001|10001|600"),
    sinkFrame().replace("ZASP-SINK:9|10|", "ZASP-SINK:9|11|"),
    sinkFrame({ ...buildSyntheticObservabilitySpan(), extra: true }),
  ]) {
    system.sink = source;
    await assert.rejects(() => system.readObservabilitySink(complete, phase), { category: "normalization" });
  }
  for (const source of [
    '{"apiVersion":"v1","apiVersion":"v1","items":[],"kind":"List","metadata":{"resourceVersion":""}}\n',
    '{"apiVersion":"v1","items":[],"kind":"List","metadata":{"resourceVersion":""},"unknown":true}\n',
    '{"apiVersion":"v1","items":[],"kind":"List","metadata":{"resourceVersion":"1"}}\n',
  ]) {
    const rejected = new ProviderSystem();
    rejected.rawOverride = source;
    await assert.rejects(() => rejected.readObservabilityProviderState(phase), { category: "normalization" });
  }
});

test("classifies thrown and signaled Job apply and sink exec boundaries without raw output", async () => {
  const expected = observabilityExpectation();
  const complete = validateObservabilityKubernetesState(
    observabilityProviderState(), expected, undefined, true,
  );
  class BoundarySystem extends LocalObservabilitySystem {
    constructor(result) {
      super(input);
      this.paths = Object.freeze({
        graphManifest: "/safe/runtime/graph.yaml",
        kubeconfig: "/safe/runtime/kubeconfig",
        observabilityCoreManifest: "/safe/runtime/observability.yaml",
        observabilitySpanManifest: "/safe/runtime/observability-span.yaml",
      });
      this.environment = Object.freeze({ PATH: input.path });
      this.result = result;
      this.dependencies = {
        ...this.dependencies,
        command: async () => {
          if (this.result instanceof Error) throw this.result;
          return this.result;
        },
      };
    }
    async requireOwnedPath() {}
    async verifyAdditionalManifestState() {}
    async withOwnedFiles(paths, _phase, _category, callback) {
      return await callback(paths.map((path, index) => ({
        handle: { fd: index + 3 },
        identity: {
          bytes: Buffer.from(path === this.paths.observabilitySpanManifest
            ? renderObservabilitySpanManifest(buildObservabilityResources().slice(3)) : "owned", "utf8"),
        },
      })));
    }
  }
  const phase = { assertActive() {}, signal: new AbortController().signal };
  const childResults = [
    new Error("raw provider error"),
    { signal: "SIGKILL", status: null, stderr: "", stdout: "", thrown: false, timedOut: false },
    { signal: null, status: 0, stderr: "", stdout: "", thrown: true, timedOut: false },
  ];
  for (const childResult of childResults) {
    const system = new BoundarySystem(childResult);
    assert.equal((await system.applyObservabilityJob(phase)).outcome, "ambiguous");
    await assert.rejects(() => system.readObservabilitySink(complete, phase), { category: "readiness" });
    await system.joinMutations({ assertActive() {} });
  }
  const definitive = new BoundarySystem({
    signal: null, status: 1, stderr: "", stdout: "", thrown: false, timedOut: false,
  });
  assert.equal((await definitive.applyObservabilityJob(phase)).outcome, "definitive");
});

test("reconciles uncertain Collector core application before inherited destructive cleanup", async () => {
  const expected = observabilityExpectation();
  const coreState = observabilityProviderState({ includeJob: false });
  const phase = { assertActive() {} };
  class CoreCleanupSystem extends LocalObservabilitySystem {
    constructor(values) {
      super(input);
      this.paths = Object.freeze({
        graphManifest: "/safe/runtime/graph.yaml",
        observabilityCoreManifest: "/safe/runtime/observability.yaml",
        observabilitySpanManifest: "/safe/runtime/observability-span.yaml",
      });
      this.observabilityCoreMayHaveApplied = true;
      this.values = [...values];
      this.events = [];
    }
    observabilityProviderExpectation() { return expected; }
    async requireTemporaryOwnership() { this.events.push("temporary"); }
    async requireOwnedPath(path) { this.events.push(`descriptor:${path}`); }
    async verifyGraphNodeForCleanup() { this.events.push("graph-cleanup-proof"); }
    async readObservabilityProviderState() {
      this.events.push("observability-cleanup-proof");
      return this.values.length > 1 ? this.values.shift() : this.values[0];
    }
  }

  const absent = new CoreCleanupSystem([emptyObservabilityProviderState()]);
  await absent.verifyAdditionalNodeForCleanup(phase);
  assert.equal(absent.observabilityCoreMayHaveApplied, false);
  assert.equal(absent.observabilityProviderIdentity, undefined);
  assert.deepEqual(absent.events.slice(0, 5), [
    "temporary",
    "descriptor:/safe/runtime/graph.yaml",
    "descriptor:/safe/runtime/observability.yaml",
    "descriptor:/safe/runtime/observability-span.yaml",
    "graph-cleanup-proof",
  ]);
  assert.ok(absent.events.includes("observability-cleanup-proof"));

  const present = new CoreCleanupSystem([coreState]);
  await present.verifyAdditionalNodeForCleanup(phase);
  assert.equal(present.observabilityCoreMayHaveApplied, false);
  assert.equal(present.observabilityProviderIdentity.collector.podUid, providerUid(42));

  const partialState = emptyObservabilityProviderState();
  partialState.configMaps = clone(coreState.configMaps);
  const partial = new CoreCleanupSystem([partialState, partialState, partialState]);
  await assert.rejects(() => partial.verifyAdditionalNodeForCleanup(phase), { category: "cleanup" });
  assert.equal(partial.observabilityCoreMayHaveApplied, true);
});

test("reconciles an uncertain Job before destructive graph cleanup and rejects replacement", async () => {
  const expected = observabilityExpectation();
  const core = validateObservabilityKubernetesState(
    observabilityProviderState({ includeJob: false }), expected, undefined, false,
  );
  const completeState = observabilityProviderState();
  const phase = { assertActive() {} };
  class CleanupSystem extends LocalObservabilitySystem {
    constructor() {
      super(input);
      this.paths = Object.freeze({
        graphManifest: "/safe/runtime/graph.yaml",
        observabilityCoreManifest: "/safe/runtime/observability.yaml",
        observabilitySpanManifest: "/safe/runtime/observability-span.yaml",
      });
      this.graphLoadedImageTargets.set("busybox", expected.imageTargets.busybox);
      this.graphLoadedImageTargets.set("collector", expected.imageTargets.collector);
      this.observabilityProviderIdentity = core;
      this.observabilityJobMayHaveApplied = true;
      this.values = [completeState];
      this.events = [];
    }
    async requireTemporaryOwnership() {}
    async requireOwnedPath() {}
    async verifyGraphNodeForCleanup() { this.events.push("graph-cleanup-proof"); }
    async readObservabilityProviderState() {
      this.events.push("observability-cleanup-proof");
      return this.values.shift();
    }
    async pauseObservabilityPoll() { this.events.push("pause"); }
  }
  const system = new CleanupSystem();
  await system.verifyAdditionalNodeForCleanup(phase);
  assert.deepEqual(system.events, ["graph-cleanup-proof", "observability-cleanup-proof"]);
  assert.equal(system.observabilityJobMayHaveApplied, false);
  assert.equal(system.observabilityProviderIdentity.job.jobUid, providerUid(45));

  for (const mutate of [
    (value) => { value.jobs[0].metadata.resourceVersion = "999"; },
    (value) => { value.pods.at(-1).metadata.resourceVersion = "999"; },
    (value) => { value.jobs[0].status.startTime = "2026-08-16T10:00:01Z"; },
    (value) => {
      value.jobs[0].status.completionTime = "2026-08-16T10:00:07Z";
      value.jobs[0].status.conditions[0].lastProbeTime = "2026-08-16T10:00:07Z";
      value.jobs[0].status.conditions[0].lastTransitionTime = "2026-08-16T10:00:07Z";
    },
    (value) => { value.pods.at(-1).status.containerStatuses[0].state.terminated.startedAt = "2026-08-16T10:00:02Z"; },
    (value) => { value.pods.at(-1).status.containerStatuses[0].state.terminated.finishedAt = "2026-08-16T10:00:04Z"; },
    (value) => { value.pods.at(-1).status.podIP = "10.244.0.99"; },
  ]) {
    const changedRetryState = observabilityProviderState();
    mutate(changedRetryState);
    system.values = [changedRetryState];
    await assert.rejects(() => system.verifyAdditionalNodeForCleanup(phase), { category: "cleanup" });
    assert.equal(system.observabilityProviderIdentity.job.jobUid, providerUid(45));
  }

  const replaced = new CleanupSystem();
  const foreign = observabilityProviderState();
  foreign.jobs[0].metadata.uid = providerUid(99);
  replaced.values = [foreign, foreign, foreign];
  await assert.rejects(() => replaced.verifyAdditionalNodeForCleanup(phase), { category: "cleanup" });
  assert.equal(replaced.observabilityJobMayHaveApplied, true);

  const activeState = observabilityProviderState();
  delete activeState.jobs[0].status.completionTime;
  activeState.jobs[0].status.conditions = [];
  activeState.jobs[0].status.ready = 1;
  activeState.jobs[0].status.succeeded = 0;
  activeState.pods.pop();
  activeState.jobLog = null;
  const active = new CleanupSystem();
  active.values = [activeState, activeState, activeState, completeState];
  await active.verifyAdditionalNodeForCleanup(phase);
  assert.equal(active.observabilityJobMayHaveApplied, false);
  assert.equal(active.observabilityProviderIdentity.job.jobUid, providerUid(45));
  assert.equal(active.events.filter((event) => event === "observability-cleanup-proof").length, 4);
  assert.equal(active.events.filter((event) => event === "pause").length, 3);

  const failed = new CleanupSystem();
  failed.values = [failedObservabilityProviderState()];
  await failed.verifyAdditionalNodeForCleanup(phase);
  assert.equal(failed.observabilityJobMayHaveApplied, false);
  assert.equal(failed.observabilityProviderIdentity.job.failed, true);
  assert.equal(failed.observabilityProviderIdentity.job.jobUid, providerUid(45));
  failed.values = [failedObservabilityProviderState()];
  await failed.verifyAdditionalNodeForCleanup(phase);
  assert.equal(failed.observabilityProviderIdentity.job.failed, true);

  for (const mutate of [
    (value) => { value.pods.at(-1).metadata.uid = providerUid(98); },
    (value) => { value.pods.at(-1).status.containerStatuses[0].state.terminated.exitCode = 2; },
    (value) => {
      const container = value.pods.at(-1).status.containerStatuses[0];
      container.containerID = `containerd://${"9".repeat(64)}`;
      container.state.terminated.containerID = container.containerID;
    },
    (value) => { value.jobs[0].metadata.resourceVersion = "999"; },
    (value) => { value.pods.at(-1).metadata.resourceVersion = "999"; },
    (value) => { value.jobs[0].status.startTime = "2026-08-16T10:00:01Z"; },
    (value) => {
      value.jobs[0].status.conditions[0].lastProbeTime = "2026-08-16T10:00:07Z";
      value.jobs[0].status.conditions[0].lastTransitionTime = "2026-08-16T10:00:07Z";
    },
    (value) => { value.pods.at(-1).status.podIP = "10.244.0.99"; },
  ]) {
    const changedRetryState = failedObservabilityProviderState();
    mutate(changedRetryState);
    failed.values = [changedRetryState];
    await assert.rejects(() => failed.verifyAdditionalNodeForCleanup(phase), { category: "cleanup" });
    assert.equal(failed.observabilityProviderIdentity.job.podUid, providerUid(46));
  }

  for (const mutate of [
    (value) => { value.jobs[0].metadata.uid = providerUid(99); },
    (value) => { value.jobs[0].status.failed = 2; },
    (value) => { value.pods.at(-1).status.containerStatuses[0].state.terminated.exitCode = 0; },
    (value) => { value.pods.at(-1).status.containerStatuses[0].state.terminated.reason = "Completed"; },
    (value) => { value.jobLog = "provider output\n"; },
  ]) {
    const invalid = failedObservabilityProviderState();
    mutate(invalid);
    const rejectedFailed = new CleanupSystem();
    rejectedFailed.values = [invalid];
    await assert.rejects(
      () => rejectedFailed.verifyAdditionalNodeForCleanup(phase), { category: "cleanup" },
    );
    assert.equal(rejectedFailed.observabilityJobMayHaveApplied, true);
  }
});

test("drives production cancellation state through settled active-Job cleanup", async () => {
  const expected = observabilityExpectation();
  const coreState = observabilityProviderState({ includeJob: false });
  const core = validateObservabilityKubernetesState(coreState, expected, undefined, false);
  const activeState = observabilityProviderState();
  delete activeState.jobs[0].status.completionTime;
  activeState.jobs[0].status.conditions = [];
  activeState.jobs[0].status.ready = 1;
  activeState.jobs[0].status.succeeded = 0;
  activeState.pods.pop();
  activeState.jobLog = null;
  const graphResult = Object.freeze({
    graph: Object.freeze({ internal: true, persistent: true, ready: true }),
    internal: true,
    pods: 4,
    ready: 4,
    services: 4,
  });

  class LifecycleSystem extends LocalObservabilitySystem {
    constructor() {
      super(input);
      this.paths = Object.freeze({
        graphManifest: "/safe/runtime/graph.yaml",
        kubeconfig: "/safe/runtime/kubeconfig",
        observabilityCoreManifest: "/safe/runtime/observability.yaml",
        observabilitySpanManifest: "/safe/runtime/observability-span.yaml",
      });
      this.environment = Object.freeze({ PATH: input.path });
      this.productProviderCapture = capturedProductProviderState();
      this.events = [];
      this.cleanupValues = [];
    }
    observabilityProviderExpectation() { return expected; }
    async verifyGraphReadiness(value) { this.events.push("graph"); return value; }
    async pollObservabilityProviderState(_phase, _retained, requireJob) {
      if (!requireJob) { this.events.push("core"); return core; }
      this.events.push("completion-poll");
      throw new ObservabilityFailure("deadline");
    }
    async requireObservabilitySinkAbsent() { this.events.push("sink-absent"); }
    async requireTemporaryOwnership() {}
    async requireOwnedPath() {}
    async verifyAdditionalManifestState() {}
    async withOwnedFiles(paths, _phase, _category, callback) {
      return await callback(paths.map((path, index) => ({
        handle: { fd: index + 3 },
        identity: {
          bytes: Buffer.from(path === this.paths.observabilitySpanManifest
            ? renderObservabilitySpanManifest(buildObservabilityResources().slice(3)) : "owned", "utf8"),
        },
      })));
    }
    async verifyGraphNodeForCleanup() { this.events.push("graph-cleanup-proof"); }
    async readObservabilityProviderState() {
      this.events.push("observability-cleanup-proof");
      return this.cleanupValues.shift();
    }
    async pauseObservabilityPoll() { this.events.push("pause"); }
  }

  const beforeApply = new LifecycleSystem();
  beforeApply.requireObservabilitySinkAbsent = async () => {
    beforeApply.events.push("sink-cancelled");
    throw new ObservabilityFailure("deadline");
  };
  await assert.rejects(
    () => beforeApply.verifyAdditionalReadiness(graphResult, { assertActive() {} }),
    { category: "deadline" },
  );
  assert.equal(beforeApply.observabilityJobMayHaveApplied, false);
  assert.deepEqual(beforeApply.observabilityProviderIdentity, core);
  beforeApply.cleanupValues = [coreState];
  await beforeApply.verifyAdditionalNodeForCleanup({ assertActive() {} });
  assert.equal(beforeApply.observabilityJobMayHaveApplied, false);

  let commandStarted;
  let settleCommand;
  const started = new Promise((resolve) => { commandStarted = resolve; });
  const command = new Promise((resolve) => { settleCommand = resolve; });
  const afterApply = new LifecycleSystem();
  afterApply.dependencies = {
    ...afterApply.dependencies,
    command: async () => {
      afterApply.events.push("mutation-start");
      commandStarted();
      const result = await command;
      afterApply.events.push("mutation-settled");
      return result;
    },
  };
  let mainActive = true;
  const controller = new AbortController();
  const mainPhase = {
    signal: controller.signal,
    assertActive(category) {
      if (!mainActive) throw new ObservabilityFailure(category);
    },
  };
  const readiness = afterApply.verifyAdditionalReadiness(graphResult, mainPhase);
  await started;
  mainActive = false;
  controller.abort();
  settleCommand({ signal: null, status: 0, stderr: "", stdout: "", thrown: false, timedOut: false });
  await assert.rejects(() => readiness, { category: "provider" });
  assert.equal(afterApply.observabilityJobMayHaveApplied, true);
  const cleanupPhase = { assertActive() {}, signal: new AbortController().signal };
  await afterApply.joinMutations(cleanupPhase);
  afterApply.cleanupValues = [activeState, activeState, failedObservabilityProviderState()];
  await afterApply.verifyAdditionalNodeForCleanup(cleanupPhase);
  assert.equal(afterApply.observabilityJobMayHaveApplied, false);
  assert.equal(afterApply.observabilityProviderIdentity.job.jobUid, providerUid(45));
  assert.equal(afterApply.observabilityProviderIdentity.job.failed, true);
  assert.ok(afterApply.events.indexOf("mutation-settled") < afterApply.events.indexOf("graph-cleanup-proof"));
  assert.equal(afterApply.events.filter((event) => event === "pause").length, 2);
});

test("polls bounded delayed state but rejects failed or duplicate Job state without retry", async () => {
  const expected = observabilityExpectation();
  const coreState = observabilityProviderState({ includeJob: false });
  const delayed = clone(coreState);
  delayed.endpointSlices[0].endpoints[0].conditions.ready = false;
  class PollSystem extends LocalObservabilitySystem {
    constructor(values) {
      super(input);
      this.paths = Object.freeze({
        observabilityCoreManifest: "/safe/runtime/observability.yaml",
        observabilitySpanManifest: "/safe/runtime/observability-span.yaml",
      });
      this.values = [...values];
      this.reads = 0;
      this.baseProofs = 0;
    }
    observabilityProviderExpectation() { return expected; }
    async readObservabilityProviderState() { this.reads += 1; return this.values.shift(); }
    async verifyObservabilityBaseState() { this.baseProofs += 1; }
    async verifyAdditionalManifestState() {}
    async pauseObservabilityPoll() {}
  }
  const phase = { assertActive() {} };
  const delayedSystem = new PollSystem([delayed, coreState, coreState]);
  const core = await delayedSystem.pollObservabilityProviderState(phase);
  assert.equal(core.ready, true);
  assert.equal(delayedSystem.reads, 3);
  assert.equal(delayedSystem.baseProofs, 1);

  for (const mutate of [
    (value) => { value.jobs[0].status.failed = 1; },
    (value) => { value.jobs.push(clone(value.jobs[0])); },
    (value) => { value.pods.at(-1).metadata.deletionTimestamp = "2026-08-16T10:00:06Z"; },
  ]) {
    const value = observabilityProviderState();
    mutate(value);
    const rejected = new PollSystem([value, observabilityProviderState(), observabilityProviderState()]);
    await assert.rejects(
      () => rejected.pollObservabilityProviderState(phase, core, true), { category: "provider" },
    );
    assert.equal(rejected.reads, 1);
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

test("bounds cancellation, joins late mutations, and preserves cleanup precedence", async () => {
  const result = {
    graph: { internal: true, persistent: true, ready: true },
    internal: true,
    observability: { internal: true, noEgress: true, ready: true, sink: true, spans: 1 },
    pods: 4,
    ready: 4,
    services: 4,
  };
  let stderr = "";
  const timedOut = fakeLifecycle(result, {
    async verifyReadiness() { return await new Promise(() => {}); },
  });
  assert.equal(await runObservabilityMain(timedOut.runtime, {
    stdout: { write() {} },
    stderr: { write(value) { stderr += value; } },
    setExitCode() {},
    mainTimeoutMilliseconds: 5,
    cleanupTimeoutMilliseconds: 50,
    settlementTimeoutMilliseconds: 5,
  }), 1);
  assert.equal(stderr, "Local observability manifest failed: deadline rejected.\n");
  assert.deepEqual(timedOut.calls.slice(-3), ["joinMutations", "cleanup", "auditAbsence"]);

  const events = [];
  let settle;
  const late = new Promise((resolve) => { settle = resolve; });
  const joined = fakeLifecycle(result, {
    async verifyReadiness() {
      events.push("mutation-start");
      setTimeout(() => { events.push("late-mutation"); settle(); }, 5);
      throw new ObservabilityFailure("provider");
    },
    async joinMutations() { events.push("join-start"); await late; events.push("join-complete"); },
    async cleanup() { events.push("cleanup"); },
    async auditAbsence() { events.push("audit"); },
  });
  stderr = "";
  assert.equal(await runObservabilityMain(joined.runtime, {
    stdout: { write() {} },
    stderr: { write(value) { stderr += value; } },
    setExitCode() {},
    mainTimeoutMilliseconds: 50,
    cleanupTimeoutMilliseconds: 50,
    settlementTimeoutMilliseconds: 10,
  }), 1);
  assert.equal(stderr, "Local observability manifest failed: provider rejected.\n");
  assert.deepEqual(events, ["mutation-start", "join-start", "late-mutation", "join-complete", "cleanup", "audit"]);

  const precedence = fakeLifecycle(result, {
    async verifyReadiness() { throw new ObservabilityFailure("provider"); },
    async cleanup() { precedence.calls.push("cleanup"); throw new Error("raw cleanup panic"); },
    async auditAbsence() { precedence.calls.push("auditAbsence"); },
  });
  stderr = "";
  assert.equal(await runObservabilityMain(precedence.runtime, {
    stdout: { write() {} },
    stderr: { write(value) { stderr += value; } },
    setExitCode() {},
    mainTimeoutMilliseconds: 50,
    cleanupTimeoutMilliseconds: 50,
    settlementTimeoutMilliseconds: 10,
  }), 1);
  assert.equal(stderr, "Local observability manifest failed: cleanup rejected.\n");
  assert.deepEqual(precedence.calls.slice(-3), ["joinMutations", "cleanup", "auditAbsence"]);

  const absence = fakeLifecycle(result, {
    async auditAbsence() { absence.calls.push("auditAbsence"); throw new Error("raw absence panic"); },
  });
  stderr = "";
  assert.equal(await runObservabilityMain(absence.runtime, {
    stdout: { write() {} },
    stderr: { write(value) { stderr += value; } },
    setExitCode() {},
    mainTimeoutMilliseconds: 50,
    cleanupTimeoutMilliseconds: 50,
    settlementTimeoutMilliseconds: 10,
  }), 1);
  assert.equal(stderr, "Local observability manifest failed: cleanup rejected.\n");
  assert.deepEqual(absence.calls.slice(-3), ["joinMutations", "cleanup", "auditAbsence"]);

  const blocked = fakeLifecycle(result, {
    async joinMutations() { blocked.calls.push("joinMutations"); return await new Promise(() => {}); },
  });
  stderr = "";
  assert.equal(await runObservabilityMain(blocked.runtime, {
    stdout: { write() {} },
    stderr: { write(value) { stderr += value; } },
    setExitCode() {},
    mainTimeoutMilliseconds: 50,
    cleanupTimeoutMilliseconds: 5,
    settlementTimeoutMilliseconds: 5,
  }), 1);
  assert.equal(stderr, "Local observability manifest failed: cleanup rejected.\n");
  assert.deepEqual(blocked.calls.slice(-1), ["joinMutations"]);
  assert.equal(blocked.calls.includes("cleanup"), false);
  assert.equal(blocked.calls.includes("auditAbsence"), false);
});

test("retains the validated observability system through the Docker runtime", () => {
  const system = new LocalObservabilitySystem(input);
  const runtime = new DockerKindObservabilityRuntime(input, system);
  assert.equal(runtime.system, system);
  assert.equal(runtime.system.profile.proof, "m1-30c");
  assert.throws(() => new DockerKindObservabilityRuntime({ ...input, nodePlatform: "linux/arm64" }, system), TypeError);
});
