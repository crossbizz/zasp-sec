import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import {
  buildObservabilityCoreResources,
  buildObservabilityResources,
  buildObservabilitySpanResources,
  buildSyntheticObservabilitySpan,
  COLLECTOR_IMAGE,
  OBSERVABILITY_CONSTANTS,
  parseObservabilitySink,
  renderObservabilityCoreManifest,
  renderObservabilitySpanManifest,
} from "./observability-manifest.mjs";
import {
  DockerKindGraphRuntime,
  LocalGraphSystem,
  projectGraphImageInspection,
} from "./graph-run.mjs";
import { buildGraphResources, renderGraphManifest } from "./graph-manifest.mjs";
import { Failure, orchestrate, parseBoundedJson } from "./run.mjs";

const observabilityMainTimeoutMilliseconds = 900_000;
const observabilityCleanupTimeoutMilliseconds = 300_000;
const observabilitySettlementTimeoutMilliseconds = 60_000;
const observabilityProviderByteLimit = 4_194_304;
const observabilityProviderPollLimit = 180;
const observabilityProviderPollMilliseconds = 500;
const observabilityJobLog = "otel-test-span-sent\n";
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const collectorImagePlan = deepFreeze({
  indexDigest: "sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5",
  name: "collector",
  platforms: {
    "linux/amd64": {
      configDigest: "sha256:837606a793453fd0c2eef9a6d4ee47ecc970d228ede7bc0c15d32ea9324c9e80",
      manifestDigest: "sha256:e290476fa9a75f7a84a28798832bde7068d27825745de67bc38957e22949a64c",
    },
    "linux/arm64": {
      configDigest: "sha256:e4ed3985c0db662ed2f0be81ac3b10110aefd379b0be24c780e2803571997c93",
      manifestDigest: "sha256:51e1afc9d762a359387723170be5cecccad2c09e73a5a2061361c62c60855ccf",
    },
  },
  reference: COLLECTOR_IMAGE,
  repository: "otel/opentelemetry-collector-contrib",
});
const collectorRuntimeFacts = deepFreeze({
  "linux/amd64": collectorFacts(
    "2026-08-04T19:23:24Z",
    [
      "sha256:b5440ec587ede814b7c8ebccb96bc5487401de66da7dfe450a202aa79c111166",
      "sha256:08b8e470b260dd54255ed6bf28dd03f47054a8b3a2709a1bc739087fdc4b958f",
      "sha256:8a565f28d3634fbc7e4589e52415632f74cf4f024dfc14d8a1a54dc3fa28327d",
    ],
  ),
  "linux/arm64": collectorFacts(
    "2026-08-04T19:24:29Z",
    [
      "sha256:0a16b43820c80185ecd6718a21d88ee191fa0b2a782ccd7a49ccab7c3be08962",
      "sha256:f3d42a646dc2f6c9a4b776f3de3efadcd278ba3de08b60331eb37776d54aef81",
      "sha256:dd866c2bf687864ac0789f16b4e9a2aac6c845ae260a4f09dc857962dfe7bec4",
    ],
  ),
});

export const OBSERVABILITY_SUCCESS_LINE = "Local observability manifest passed: ready=true internal=true no_egress=true spans=1 sink=true cleanup=true.";
export const OBSERVABILITY_FAILURE_CATEGORIES = Object.freeze([
  "build",
  "cleanup",
  "configuration",
  "deadline",
  "normalization",
  "ownership",
  "panic",
  "provider",
  "readiness",
]);

export class ObservabilityFailure extends Failure {
  constructor(category = "panic") {
    super("operation");
    this.name = "ObservabilityFailure";
    this.category = OBSERVABILITY_FAILURE_CATEGORIES.includes(category) ? category : "panic";
  }
}

export function buildObservabilityProfile(...input) {
  if (input.length !== 0) throw new TypeError("observability profile accepts no caller input");
  return deepFreeze({
    manifests: [
      {
        bytes: renderGraphManifest(buildGraphResources()),
        name: "graph.yaml",
        pathKey: "graphManifest",
      },
      {
        bytes: renderObservabilityCoreManifest(buildObservabilityCoreResources()),
        name: "observability.yaml",
        pathKey: "observabilityCoreManifest",
      },
      {
        bytes: renderObservabilitySpanManifest(buildObservabilitySpanResources()),
        name: "observability-span.yaml",
        pathKey: "observabilitySpanManifest",
      },
    ],
    proof: "m1-30c",
  });
}

export function observabilityApplyPlan(...input) {
  if (input.length !== 0) throw new TypeError("observability apply plan accepts no caller input");
  return deepFreeze({
    base: ["graphManifest", "observabilityCoreManifest"],
    staged: ["observabilitySpanManifest"],
  });
}

export function buildCollectorImagePlan(platform) {
  if (arguments.length !== 1) throw new TypeError("Collector image plan is invalid");
  const selected = collectorImagePlan.platforms[platform];
  if (selected === undefined || (platform !== "linux/amd64" && platform !== "linux/arm64")) {
    throw new TypeError("Collector image plan is invalid");
  }
  const architecture = platform.slice("linux/".length);
  const tag = collectorImagePlan.reference.split("@")[0];
  return deepFreeze({
    architecture,
    configDigest: selected.configDigest,
    indexDigest: collectorImagePlan.indexDigest,
    manifestDigest: selected.manifestDigest,
    name: "collector",
    platform,
    providerReference: `docker.io/${collectorImagePlan.repository}:0.158.0@${collectorImagePlan.indexDigest}`,
    reference: collectorImagePlan.reference,
    repoDigest: `${collectorImagePlan.repository}@${collectorImagePlan.indexDigest}`,
    repository: collectorImagePlan.repository,
    selectedReference: `${collectorImagePlan.repository}@${selected.manifestDigest}`,
    tag,
  });
}

export function validateCollectorImageIndex(document, selected) {
  try {
    requireCollectorPlan(selected);
    requireKeySet(document, ["manifests", "mediaType", "schemaVersion"]);
    if (document.schemaVersion !== 2 || !new Set([
      "application/vnd.docker.distribution.manifest.list.v2+json",
      "application/vnd.oci.image.index.v1+json",
    ]).has(document.mediaType) || !plainArray(document.manifests) || document.manifests.length < 2 ||
        document.manifests.length > 64) throw new TypeError("Collector index is invalid");
    const descriptors = document.manifests.map((descriptor) => {
      requireKeySet(descriptor, descriptor.annotations === undefined
        ? ["digest", "mediaType", "platform", "size"]
        : ["annotations", "digest", "mediaType", "platform", "size"]);
      validateContentDescriptor(descriptor, new Set([
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
      ]), 16_777_216, ["digest", "mediaType", "platform", "size"], true);
      requireKeySet(descriptor.platform, Object.keys(descriptor.platform));
      const platformKeys = Object.keys(descriptor.platform);
      if (platformKeys.length < 2 || platformKeys.length > 4 ||
          platformKeys.some((key) => !new Set(["architecture", "os", "os.version", "variant"]).has(key)) ||
          typeof descriptor.platform.architecture !== "string" || descriptor.platform.architecture.length < 1 ||
          descriptor.platform.architecture.length > 64 || typeof descriptor.platform.os !== "string" ||
          descriptor.platform.os.length < 1 || descriptor.platform.os.length > 64 ||
          descriptor.platform.variant !== undefined && (typeof descriptor.platform.variant !== "string" ||
            descriptor.platform.variant.length > 64) ||
          descriptor.platform["os.version"] !== undefined &&
            (typeof descriptor.platform["os.version"] !== "string" || descriptor.platform["os.version"].length > 256)) {
        throw new TypeError("Collector platform is invalid");
      }
      if (descriptor.annotations !== undefined) validateStringMap(descriptor.annotations);
      return structuredClone(descriptor);
    });
    if (new Set(descriptors.map(({ digest }) => digest)).size !== descriptors.length) {
      throw new TypeError("Collector index has duplicate digests");
    }
    for (const [platform, pinned] of Object.entries(collectorImagePlan.platforms)) {
      const architecture = platform.slice("linux/".length);
      if (descriptors.filter((descriptor) => descriptor.digest === pinned.manifestDigest &&
        descriptor.platform.architecture === architecture && descriptor.platform.os === "linux").length !== 1) {
        throw new TypeError("Collector platform descriptor is invalid");
      }
    }
    const selectedDescriptors = descriptors.filter((descriptor) => descriptor.digest === selected.manifestDigest &&
      descriptor.platform.architecture === selected.architecture && descriptor.platform.os === "linux");
    if (selectedDescriptors.length !== 1) throw new TypeError("selected Collector descriptor is invalid");
    return deepFreeze({
      indexDigest: selected.indexDigest,
      manifests: descriptors,
      mediaType: document.mediaType,
      schemaVersion: 2,
      selected: structuredClone(selectedDescriptors[0]),
    });
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new ObservabilityFailure("normalization");
  }
}

export function validateCollectorImageManifest(document, selected) {
  try {
    requireCollectorPlan(selected);
    requireKeySet(document, document?.annotations === undefined
      ? ["config", "layers", "mediaType", "schemaVersion"]
      : ["annotations", "config", "layers", "mediaType", "schemaVersion"]);
    if (document.schemaVersion !== 2 || !new Set([
      "application/vnd.docker.distribution.manifest.v2+json",
      "application/vnd.oci.image.manifest.v1+json",
    ]).has(document.mediaType) || !plainArray(document.layers) || document.layers.length < 1 ||
        document.layers.length > 256) throw new TypeError("Collector manifest is invalid");
    if (document.annotations !== undefined) validateStringMap(document.annotations);
    validateContentDescriptor(document.config, new Set([
      "application/vnd.docker.container.image.v1+json",
      "application/vnd.oci.image.config.v1+json",
    ]), 16_777_216);
    if (document.config.digest !== selected.configDigest) throw new TypeError("Collector config is invalid");
    const layers = document.layers.map((layer) => {
      validateContentDescriptor(layer, new Set([
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
      ]), 8_589_934_592);
      return structuredClone(layer);
    });
    if (new Set(layers.map(({ digest }) => digest)).size !== layers.length ||
        !isDeepStrictEqual(layers.map(({ digest }) => digest), collectorRuntimeFacts[selected.platform].rootfs.Layers)) {
      throw new TypeError("Collector layers are invalid");
    }
    return deepFreeze({
      config: structuredClone(document.config),
      layers,
      mediaType: document.mediaType,
      schemaVersion: 2,
    });
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new ObservabilityFailure("normalization");
  }
}

export function validateCollectorImageInspection(document, selected, resolution, retained = undefined,
  aliases = undefined) {
  try {
    const expectedPlan = buildCollectorImagePlan(selected?.platform);
    const facts = collectorRuntimeFacts[selected?.platform];
    const expectedAliases = aliases ?? { repoDigests: [expectedPlan.repoDigest], repoTags: [] };
    if (!isDeepStrictEqual(selected, expectedPlan) || !Array.isArray(document) || document.length !== 14 ||
        facts === undefined || !isPlainObject(resolution) ||
        resolution.index?.indexDigest !== selected.indexDigest ||
        resolution.index?.selected?.digest !== selected.manifestDigest ||
        resolution.manifest?.config?.digest !== selected.configDigest ||
        !Array.isArray(resolution.manifest?.layers) || resolution.manifest.layers.length < 1 ||
        !isDeepStrictEqual(resolution.manifest.layers.map((layer) => layer?.digest), facts?.rootfs?.Layers) ||
        !isPlainObject(expectedAliases) || !Array.isArray(expectedAliases.repoDigests) ||
        !Array.isArray(expectedAliases.repoTags) ||
        !isDeepStrictEqual(expectedAliases.repoDigests, [selected.repoDigest]) ||
        !(isDeepStrictEqual(expectedAliases.repoTags, []) || isDeepStrictEqual(expectedAliases.repoTags, [selected.tag]))) {
      throw new TypeError("Collector image evidence is invalid");
    }
    const [architecture, operatingSystem, configDigest, repoDigests, repoTags, rootfs, environment,
      entrypoint, command, exposedPorts, intrinsicVolumes, labels, user, workingDirectory] = document;
    if (architecture !== selected.architecture || operatingSystem !== "linux" || configDigest !== selected.configDigest ||
        !isDeepStrictEqual(repoDigests, expectedAliases.repoDigests) ||
        !isDeepStrictEqual(repoTags, expectedAliases.repoTags) || !isDeepStrictEqual({
          command, entrypoint, environment, exposedPorts, intrinsicVolumes, labels, rootfs, user, workingDirectory,
        }, facts)) throw new TypeError("Collector image evidence is invalid");
    const identity = deepFreeze({
      architecture,
      command: [...command],
      configDigest,
      entrypoint: [...entrypoint],
      environment: [...environment],
      exposedPorts: Object.keys(exposedPorts).sort(),
      id: configDigest,
      index: structuredClone(resolution.index),
      indexDigest: selected.indexDigest,
      intrinsicVolumes: [],
      labels: structuredClone(labels),
      manifest: structuredClone(resolution.manifest),
      manifestDigest: selected.manifestDigest,
      name: selected.name,
      platform: selected.platform,
      reference: selected.reference,
      repoDigests: [...repoDigests],
      repoTags: [...repoTags],
      rootfs: structuredClone(rootfs),
      user,
      workingDirectory,
    });
    if (retained !== undefined && !isDeepStrictEqual({
      ...identity,
      repoDigests: retained.repoDigests,
      repoTags: retained.repoTags,
    }, retained)) throw new TypeError("Collector image identity changed");
    return identity;
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new ObservabilityFailure("ownership");
  }
}

export function validateObservabilityKubernetesState(value, expected, retained = undefined, requireJob = false,
  category = "readiness") {
  try {
    requireKeySet(value, [
      "configMaps", "deployments", "endpointSlices", "ingresses", "jobLog", "jobs", "pods", "replicaSets",
      "services",
    ]);
    requireKeySet(expected, ["imageTargets", "nodeName"]);
    requireKeySet(expected.imageTargets, ["busybox", "collector"]);
    for (const name of ["busybox", "collector"]) {
      requireKeySet(expected.imageTargets[name], ["configDigest", "imageID"]);
      if (!digestPattern.test(expected.imageTargets[name].configDigest) ||
          !/^docker\.io\/library\/import-\d{4}-\d{2}-\d{2}@sha256:[0-9a-f]{64}$/.test(
            expected.imageTargets[name].imageID,
          )) throw new TypeError("observability image target is invalid");
    }
    if (!/^zasp-m1-30c-[0-9a-f]{16}-control-plane$/.test(expected.nodeName) ||
        typeof requireJob !== "boolean" || !OBSERVABILITY_FAILURE_CATEGORIES.includes(category) ||
        !plainArray(value.configMaps) || value.configMaps.length !== 1 ||
        !plainArray(value.deployments) || value.deployments.length !== 1 ||
        !plainArray(value.replicaSets) || value.replicaSets.length !== 1 ||
        !plainArray(value.services) || value.services.length !== 1 ||
        !plainArray(value.endpointSlices) || value.endpointSlices.length !== 1 ||
        !plainArray(value.ingresses) || value.ingresses.length !== 0 || !plainArray(value.jobs) ||
        value.jobs.length !== (requireJob ? 1 : 0) || !plainArray(value.pods) ||
        value.pods.length !== (requireJob ? 2 : 1) || value.jobLog !== (requireJob ? observabilityJobLog : null)) {
      throw new TypeError("observability provider collection is invalid");
    }

    const [configResource, deploymentResource, serviceResource, jobResource] = buildObservabilityResources();
    const configMap = value.configMaps[0];
    const deployment = value.deployments[0];
    const replicaSet = value.replicaSets[0];
    const collectorPod = value.pods.find((pod) => pod?.metadata?.labels?.["app.kubernetes.io/name"] === "otel-collector");
    const service = value.services[0];
    const endpointSlice = value.endpointSlices[0];
    const deploymentUid = providerUid(deployment?.metadata?.uid);
    const replicaSetUid = providerUid(replicaSet?.metadata?.uid);
    const podUid = providerUid(collectorPod?.metadata?.uid);
    const serviceUid = providerUid(service?.metadata?.uid);
    const configUid = providerUid(configMap?.metadata?.uid);
    const endpointUid = providerUid(endpointSlice?.metadata?.uid);
    const deploymentVersion = providerVersion(deployment?.metadata?.resourceVersion);
    const replicaSetVersion = providerVersion(replicaSet?.metadata?.resourceVersion);
    const podVersion = providerVersion(collectorPod?.metadata?.resourceVersion);
    const serviceVersion = providerVersion(service?.metadata?.resourceVersion);
    const configVersion = providerVersion(configMap?.metadata?.resourceVersion);
    const endpointVersion = providerVersion(endpointSlice?.metadata?.resourceVersion);
    const hash = /^otel-collector-([a-z0-9]{10})$/.exec(replicaSet?.metadata?.name ?? "")?.[1];
    const podName = hash === undefined ? undefined : /^otel-collector-[a-z0-9]{10}-[a-z0-9]{5}$/.test(
      collectorPod?.metadata?.name ?? "",
    ) ? collectorPod.metadata.name : undefined;
    const podIP = validPodAddress(collectorPod?.status?.podIP) ? collectorPod.status.podIP : undefined;
    const clusterIP = validServiceAddress(service?.spec?.clusterIP) ? service.spec.clusterIP : undefined;
    const endpointName = /^otel-collector-[a-z0-9]{5}$/.test(endpointSlice?.metadata?.name ?? "")
      ? endpointSlice.metadata.name : undefined;
    const collectorStatus = collectorPod?.status?.containerStatuses?.find(({ name }) => name === "otel-collector");
    const readerStatus = collectorPod?.status?.containerStatuses?.find(({ name }) => name === "sink-reader");
    const collectorContainerId = providerContainerId(collectorStatus?.containerID);
    const readerContainerId = providerContainerId(readerStatus?.containerID);
    const collectorStartedAt = providerTimestamp(collectorStatus?.state?.running?.startedAt);
    const readerStartedAt = providerTimestamp(readerStatus?.state?.running?.startedAt);
    if ([deploymentUid, replicaSetUid, podUid, serviceUid, configUid, endpointUid, deploymentVersion,
      replicaSetVersion, podVersion, serviceVersion, configVersion, endpointVersion, hash, podName, podIP,
      clusterIP, endpointName, collectorContainerId, readerContainerId, collectorStartedAt, readerStartedAt]
      .some((item) => item === undefined)) throw new TypeError("observability provider identity is invalid");

    const replicaLabels = { ...deploymentResource.metadata.labels, "pod-template-hash": hash };
    const expectedConfig = {
      apiVersion: "v1", data: structuredClone(configResource.data), kind: "ConfigMap",
      metadata: { labels: structuredClone(configResource.metadata.labels), name: "otel-collector", namespace: "zasp-local" },
    };
    expectedConfig.metadata.name = "otel-collector-config";
    Object.assign(expectedConfig.metadata, { resourceVersion: configVersion, uid: configUid });
    const expectedDeployment = {
      apiVersion: "apps/v1", kind: "Deployment",
      metadata: { generation: 1, labels: structuredClone(deploymentResource.metadata.labels), name: "otel-collector", namespace: "zasp-local", resourceVersion: deploymentVersion, uid: deploymentUid },
      spec: { ...structuredClone(deploymentResource.spec), template: providerObservabilityTemplate(deploymentResource.spec.template) },
      status: { availableReplicas: 1, conditions: [{ status: "True", type: "Available" }], observedGeneration: 1, readyReplicas: 1, replicas: 1, unavailableReplicas: 0, updatedReplicas: 1 },
    };
    const expectedReplicaSet = {
      apiVersion: "apps/v1", kind: "ReplicaSet",
      metadata: {
        labels: replicaLabels, name: `otel-collector-${hash}`, namespace: "zasp-local",
        ownerReferences: [{ apiVersion: "apps/v1", blockOwnerDeletion: true, controller: true, kind: "Deployment", name: "otel-collector", uid: deploymentUid }],
        resourceVersion: replicaSetVersion, uid: replicaSetUid,
      },
      spec: { replicas: 1, selector: { matchLabels: { "app.kubernetes.io/name": "otel-collector", "pod-template-hash": hash } }, template: providerObservabilityTemplate(deploymentResource.spec.template, replicaLabels) },
      status: { availableReplicas: 1, fullyLabeledReplicas: 1, observedGeneration: 1, readyReplicas: 1, replicas: 1 },
    };
    const expectedPod = {
      apiVersion: "v1", kind: "Pod",
      metadata: {
        labels: replicaLabels, name: podName, namespace: "zasp-local",
        ownerReferences: [{ apiVersion: "apps/v1", blockOwnerDeletion: true, controller: true, kind: "ReplicaSet", name: `otel-collector-${hash}`, uid: replicaSetUid }],
        resourceVersion: podVersion, uid: podUid,
      },
      spec: providerObservabilityPodSpec(deploymentResource.spec.template, expected.nodeName),
      status: {
        conditions: [{ status: "True", type: "Ready" }],
        containerStatuses: [
          { containerID: collectorContainerId, image: expected.imageTargets.collector.configDigest, imageID: expected.imageTargets.collector.imageID, lastState: {}, name: "otel-collector", ready: true, restartCount: 0, started: true, state: { running: { startedAt: collectorStartedAt } } },
          { containerID: readerContainerId, image: expected.imageTargets.busybox.configDigest, imageID: expected.imageTargets.busybox.imageID, lastState: {}, name: "sink-reader", ready: true, restartCount: 0, started: true, state: { running: { startedAt: readerStartedAt } } },
        ],
        phase: "Running", podIP,
      },
    };
    const expectedService = {
      apiVersion: "v1", kind: "Service",
      metadata: { labels: structuredClone(serviceResource.metadata.labels), name: "otel-collector", namespace: "zasp-local", resourceVersion: serviceVersion, uid: serviceUid },
      spec: { clusterIP, clusterIPs: [clusterIP], internalTrafficPolicy: "Cluster", ...structuredClone(serviceResource.spec) },
      status: { loadBalancer: {} },
    };
    const expectedEndpoint = {
      addressType: "IPv4", apiVersion: "discovery.k8s.io/v1",
      endpoints: [{ addresses: [podIP], conditions: { ready: true, serving: true, terminating: false }, nodeName: expected.nodeName, targetRef: { kind: "Pod", name: podName, namespace: "zasp-local", uid: podUid } }],
      kind: "EndpointSlice",
      metadata: {
        labels: { "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io", "kubernetes.io/service-name": "otel-collector" },
        name: endpointName, namespace: "zasp-local",
        ownerReferences: [{ apiVersion: "v1", blockOwnerDeletion: true, controller: true, kind: "Service", name: "otel-collector", uid: serviceUid }],
        resourceVersion: endpointVersion, uid: endpointUid,
      },
      ports: [{ name: "otlp-http", port: 4318, protocol: "TCP" }],
    };
    if (![isDeepStrictEqual(configMap, expectedConfig), isDeepStrictEqual(deployment, expectedDeployment),
      isDeepStrictEqual(replicaSet, expectedReplicaSet), isDeepStrictEqual(collectorPod, expectedPod),
      isDeepStrictEqual(service, expectedService), isDeepStrictEqual(endpointSlice, expectedEndpoint)]
      .every(Boolean)) throw new TypeError("observability core provider state is invalid");

    const snapshot = deepFreeze({
      configMaps: structuredClone(value.configMaps), deployments: structuredClone(value.deployments),
      endpointSlices: structuredClone(value.endpointSlices), ingresses: [], pods: [structuredClone(collectorPod)],
      replicaSets: structuredClone(value.replicaSets), services: structuredClone(value.services),
    });
    const collector = deepFreeze({
      collectorContainerId, podIP, podName, podUid, readerContainerId, resourceVersion: configVersion,
    });
    if (retained !== undefined && (!isPlainObject(retained) || !isDeepStrictEqual(retained.collector, collector) ||
      !isDeepStrictEqual(retained.snapshot, snapshot))) throw new TypeError("observability core state changed");
    let job = null;
    if (requireJob) job = validateObservabilityJob(value, expected, jobResource);
    if (requireJob && retained?.job !== null && retained?.job !== undefined &&
        !isDeepStrictEqual(retained.job, job)) throw new TypeError("observability Job state changed");
    return deepFreeze({ collector, job, ready: true, snapshot });
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new ObservabilityFailure(category);
  }
}

export class LocalObservabilitySystem extends LocalGraphSystem {
  constructor(input, dependencies = undefined) {
    super(input, dependencies, buildObservabilityProfile());
    this.graphImagePlans.set("collector", buildCollectorImagePlan(input.nodePlatform));
    this.observabilityCoreMayHaveApplied = false;
    this.observabilityJobMayHaveApplied = false;
    this.observabilityProviderIdentity = undefined;
  }

  async applyManifests(phase) {
    const stagedKey = observabilityApplyPlan().staged[0];
    const spanPath = this.additionalManifestPaths.get(stagedKey);
    if (spanPath === undefined || !this.additionalManifestPaths.delete(stagedKey)) {
      throw new ObservabilityFailure("ownership");
    }
    this.observabilityCoreMayHaveApplied = true;
    try {
      await super.applyManifests(phase);
    } finally {
      this.additionalManifestPaths.set(stagedKey, spanPath);
    }
  }

  async verifyAdditionalManifestState(phase, path) {
    if (path === this.paths?.graphManifest) return await super.verifyAdditionalManifestState(phase, path);
    if (path !== this.paths?.observabilityCoreManifest && path !== this.paths?.observabilitySpanManifest) {
      throw new ObservabilityFailure("ownership");
    }
    await super.verifyAdditionalManifestState(phase, this.paths.graphManifest);
    await this.requireOwnedPath(path, phase, "ownership");
  }

  observabilityProviderExpectation() {
    const targets = {};
    for (const name of ["busybox", "collector"]) {
      const selected = this.graphImagePlans.get(name);
      const loaded = this.graphLoadedImageTargets.get(name);
      if (selected === undefined || loaded === undefined || !digestPattern.test(selected.configDigest) ||
          typeof loaded.imageID !== "string") throw new ObservabilityFailure("ownership");
      targets[name] = { configDigest: selected.configDigest, imageID: loaded.imageID };
    }
    return deepFreeze({ imageTargets: targets, nodeName: `${this.cluster}-control-plane` });
  }

  async readObservabilityProviderState(phase, category = "readiness") {
    await this.requireTemporaryOwnership(phase, "ownership");
    await this.verifyCluster(phase, "ownership");
    const requests = [
      ["configMaps", "configmap", "app.kubernetes.io/component=observability"],
      ["deployments", "deployment", "app.kubernetes.io/component=observability"],
      ["replicaSets", "replicaset", "app.kubernetes.io/component=observability"],
      ["pods", "pod", "app.kubernetes.io/component=observability"],
      ["services", "service", "app.kubernetes.io/component=observability"],
      ["endpointSlices", "endpointslice", "kubernetes.io/service-name=otel-collector"],
      ["jobs", "job", "app.kubernetes.io/component=observability"],
      ["ingresses", "ingress", "app.kubernetes.io/component=observability"],
    ];
    const documents = {};
    for (const [name, resource, selector] of requests) {
      const result = await super.runKubectlRead([
        "get", resource, "--namespace", OBSERVABILITY_CONSTANTS.namespace,
        `--selector=${selector}`, "--output=json",
      ], phase, category, 30_000, observabilityProviderByteLimit);
      documents[name] = projectObservabilityProviderResources(
        parseObservabilityProviderList(result.stdout), name,
      );
    }
    const spanPods = documents.pods.filter((pod) =>
      pod?.metadata?.labels?.["app.kubernetes.io/name"] === OBSERVABILITY_CONSTANTS.spanJobName);
    let jobLog = null;
    if (spanPods.length === 1 && /^otel-test-span-[a-z0-9]{5}$/.test(spanPods[0]?.metadata?.name ?? "")) {
      const result = await super.runKubectlRead([
        "logs", "--namespace", OBSERVABILITY_CONSTANTS.namespace, spanPods[0].metadata.name,
        "--container", "span-generator",
      ], phase, category, 30_000, 16_384);
      jobLog = result.stdout;
    }
    return { ...documents, jobLog };
  }

  async verifyObservabilityBaseState(phase, category) {
    if (this.graphProviderIdentity === undefined) throw new ObservabilityFailure("ownership");
    this.graphProviderIdentity = await this.withRetainedProductSnapshot(async () => {
      await this.verifyProductReadiness(phase);
      return await this.pollGraphProviderState(
        phase, this.graphProviderIdentity, false, category,
      );
    }, category);
  }

  async withRetainedProductSnapshot(operation, category) {
    const retained = this.productProviderSnapshot;
    if (retained === undefined || typeof operation !== "function") {
      throw new ObservabilityFailure(category === "cleanup" ? "cleanup" : "ownership");
    }
    try {
      const result = await operation();
      if (!isDeepStrictEqual(this.productProviderSnapshot, retained)) {
        throw new ObservabilityFailure(category === "cleanup" ? "cleanup" : "ownership");
      }
      return result;
    } finally {
      this.productProviderSnapshot = retained;
    }
  }

  retainInitialProductSnapshot() {
    if (this.productProviderSnapshot !== undefined) return;
    const capture = this.productProviderCapture;
    const keys = ["deployments", "endpointSlices", "pods", "replicaSets", "services"];
    if (!(capture instanceof Map) || capture.size !== keys.length || keys.some((key) =>
      !plainArray(capture.get(key)) || capture.get(key).length !== 4)) {
      throw new ObservabilityFailure("ownership");
    }
    this.productProviderSnapshot = deepFreeze(Object.fromEntries(
      keys.map((key) => [key, structuredClone(capture.get(key))]),
    ));
  }

  async pauseObservabilityPoll(phase, category) {
    await new Promise((resolve) => setTimeout(resolve, observabilityProviderPollMilliseconds));
    phase.assertActive(category);
  }

  async pollObservabilityProviderState(phase, retained = undefined, requireJob = false,
    category = "readiness") {
    let failure;
    for (let attempt = 0; attempt < observabilityProviderPollLimit; attempt += 1) {
      phase.assertActive(category);
      try {
        const providerState = await this.readObservabilityProviderState(phase, category);
        if (terminalObservabilityProviderState(providerState, requireJob)) {
          throw new ObservabilityFailure(category === "readiness" ? "provider" : category);
        }
        const candidate = validateObservabilityKubernetesState(
          providerState, this.observabilityProviderExpectation(), retained, requireJob, category,
        );
        await this.verifyObservabilityBaseState(phase, category);
        await this.verifyAdditionalManifestState(phase, this.paths.observabilityCoreManifest);
        if (requireJob) {
          await this.verifyAdditionalManifestState(phase, this.paths.observabilitySpanManifest);
        }
        const stable = validateObservabilityKubernetesState(
          await this.readObservabilityProviderState(phase, category),
          this.observabilityProviderExpectation(), candidate, requireJob, category,
        );
        return stable;
      } catch (error) {
        if (!(error instanceof Failure) || error.category !== category) throw error;
        failure = error;
      }
      if (attempt + 1 < observabilityProviderPollLimit) await this.pauseObservabilityPoll(phase, category);
    }
    throw failure ?? new ObservabilityFailure(category);
  }

  async applyObservabilityJob(phase) {
    const path = this.paths?.observabilitySpanManifest;
    if (path === undefined) throw new ObservabilityFailure("ownership");
    await this.verifyAdditionalManifestState(phase, path);
    const result = await this.withOwnedFiles(
      [this.paths.kubeconfig, path], phase, "ownership", async ([kubeconfig, manifest]) =>
        await this.runMutation("kubectl", [
          "--kubeconfig", "/dev/fd/3", "apply", "--filename", "-",
        ], phase, "provider", {
          environment: this.environment,
          fileDescriptors: [kubeconfig.handle.fd],
          input: manifest.identity.bytes,
          outputLimit: 4_194_304,
          timeoutMilliseconds: 90_000,
        }),
    );
    await this.requireOwnedPath(this.paths.kubeconfig, phase, "ownership");
    await this.requireOwnedPath(path, phase, "ownership");
    return result;
  }

  async readObservabilitySink(retained, phase) {
    const podName = retained?.collector?.podName;
    if (!/^otel-collector-[a-z0-9]{10}-[a-z0-9]{5}$/.test(podName ?? "")) {
      throw new ObservabilityFailure("ownership");
    }
    const path = OBSERVABILITY_CONSTANTS.sinkPath;
    const source = [
      "set -eu",
      `path=${path}`,
      "test ! -L \"$path\"",
      "before=$(stat -Lc '%d|%i|%s|%F|%u|%g|%a' -- \"$path\")",
      "printf 'ZASP-SINK:%s\\n' \"$before\"",
      `dd if="$path" bs=${OBSERVABILITY_CONSTANTS.sinkByteLimit + 1} count=1 status=none`,
      "after=$(stat -Lc '%d|%i|%s|%F|%u|%g|%a' -- \"$path\")",
      "printf 'ZASP-SINK:%s\\n' \"$after\"",
    ].join("; ");
    const result = await super.runKubectlRead([
      "exec", "--namespace", OBSERVABILITY_CONSTANTS.namespace, podName,
      "--container", "sink-reader", "--", "sh", "-ec", source,
    ], phase, "readiness", 30_000, OBSERVABILITY_CONSTANTS.sinkByteLimit + 1_024);
    return parseObservabilitySinkFrame(result.stdout);
  }

  async requireObservabilitySinkAbsent(retained, phase, category = "readiness") {
    const podName = retained?.collector?.podName;
    if (!/^otel-collector-[a-z0-9]{10}-[a-z0-9]{5}$/.test(podName ?? "") ||
        !OBSERVABILITY_FAILURE_CATEGORIES.includes(category)) {
      throw new ObservabilityFailure(category === "cleanup" ? "cleanup" : "ownership");
    }
    const path = OBSERVABILITY_CONSTANTS.sinkPath;
    const source = [
      "set -eu",
      `path=${path}`,
      "test ! -e \"$path\"",
      "test ! -L \"$path\"",
      "printf 'ZASP-SINK-ABSENT\\n'",
    ].join("; ");
    const result = await super.runKubectlRead([
      "exec", "--namespace", OBSERVABILITY_CONSTANTS.namespace, podName,
      "--container", "sink-reader", "--", "sh", "-ec", source,
    ], phase, category, 30_000, 128);
    if (result.stdout !== "ZASP-SINK-ABSENT\n") throw new ObservabilityFailure(category);
  }

  async verifyGraphReadiness(productResult, phase) {
    return await super.verifyAdditionalReadiness(productResult, phase);
  }

  async verifyAdditionalReadiness(productResult, phase) {
    if (this.productReadinessOnly) return productResult;
    this.retainInitialProductSnapshot();
    const graphResult = await this.withRetainedProductSnapshot(
      async () => await this.verifyGraphReadiness(productResult, phase), "ownership",
    );
    const core = await this.pollObservabilityProviderState(phase);
    this.observabilityProviderIdentity = core;
    this.observabilityCoreMayHaveApplied = false;
    await this.requireObservabilitySinkAbsent(core, phase);
    this.observabilityJobMayHaveApplied = true;
    const applied = await this.applyObservabilityJob(phase);
    if (!new Set(["ambiguous", "applied"]).has(applied?.outcome)) {
      this.observabilityJobMayHaveApplied = false;
      throw new ObservabilityFailure("provider");
    }
    const complete = await this.pollObservabilityProviderState(phase, core, true);
    this.observabilityProviderIdentity = complete;
    this.observabilityJobMayHaveApplied = false;
    const span = await this.readObservabilitySink(complete, phase);
    this.observabilityProviderIdentity = await this.pollObservabilityProviderState(phase, complete, true);
    if (!isDeepStrictEqual(span, buildSyntheticObservabilitySpan())) {
      throw new ObservabilityFailure("normalization");
    }
    return deepFreeze({
      ...graphResult,
      observability: { internal: true, noEgress: true, ready: true, sink: true, spans: 1 },
    });
  }

  async verifyGraphNodeForCleanup(phase) {
    return await super.verifyAdditionalNodeForCleanup(phase);
  }

  async verifyObservabilityDescriptorsForCleanup(phase) {
    await this.requireTemporaryOwnership(phase, "cleanup");
    for (const path of [
      this.paths?.graphManifest,
      this.paths?.observabilityCoreManifest,
      this.paths?.observabilitySpanManifest,
    ]) {
      if (typeof path !== "string") throw new ObservabilityFailure("cleanup");
      await this.requireOwnedPath(path, phase, "cleanup");
    }
  }

  async reconcileObservabilityCoreForCleanup(phase) {
    let failure;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      phase.assertActive("cleanup");
      try {
        const providerState = await this.readObservabilityProviderState(phase, "cleanup");
        try {
          requireObservabilityProviderAbsent(providerState);
          this.observabilityCoreMayHaveApplied = false;
          this.observabilityProviderIdentity = undefined;
          return;
        } catch {
          const current = validateObservabilityKubernetesState(
            providerState, this.observabilityProviderExpectation(), undefined, false, "cleanup",
          );
          this.observabilityProviderIdentity = current;
          this.observabilityCoreMayHaveApplied = false;
          return;
        }
      } catch (error) {
        if (!(error instanceof Failure) || error.category !== "cleanup") throw error;
        failure = error;
      }
    }
    throw failure ?? new ObservabilityFailure("cleanup");
  }

  async verifyAdditionalNodeForCleanup(phase) {
    await this.verifyObservabilityDescriptorsForCleanup(phase);
    await this.verifyGraphNodeForCleanup(phase);
    if (this.observabilityCoreMayHaveApplied && this.observabilityProviderIdentity === undefined) {
      await this.reconcileObservabilityCoreForCleanup(phase);
    }
    const retained = this.observabilityProviderIdentity;
    if (retained === undefined && !this.observabilityJobMayHaveApplied) return;
    if (retained === undefined) throw new ObservabilityFailure("cleanup");
    let failure;
    for (let attempt = 0; attempt < observabilityProviderPollLimit; attempt += 1) {
      phase.assertActive("cleanup");
      try {
        const providerState = await this.readObservabilityProviderState(phase, "cleanup");
        let current;
        if (this.observabilityJobMayHaveApplied) {
          try {
            current = validateObservabilityKubernetesState(
              providerState, this.observabilityProviderExpectation(), retained, true,
              "cleanup",
            );
          } catch {
            try {
              current = validateObservabilityKubernetesState(
                providerState, this.observabilityProviderExpectation(), retained, false,
                "cleanup",
              );
            } catch {
              current = validateFailedObservabilityKubernetesState(
                providerState, this.observabilityProviderExpectation(), retained, "cleanup",
              );
            }
          }
        } else {
          current = retained.job?.failed === true
            ? validateFailedObservabilityKubernetesState(
              providerState, this.observabilityProviderExpectation(), retained, "cleanup",
            )
            : validateObservabilityKubernetesState(
              providerState, this.observabilityProviderExpectation(), retained, retained.job !== null,
              "cleanup",
            );
        }
        this.observabilityProviderIdentity = current;
        this.observabilityJobMayHaveApplied = false;
        return;
      } catch (error) {
        if (!(error instanceof Failure) || error.category !== "cleanup") throw error;
        failure = error;
      }
      if (attempt + 1 < observabilityProviderPollLimit) {
        await this.pauseObservabilityPoll(phase, "cleanup");
      }
    }
    throw failure ?? new ObservabilityFailure("cleanup");
  }

  async afterClusterAbsent() {
    await super.afterClusterAbsent();
    this.observabilityCoreMayHaveApplied = false;
    this.observabilityJobMayHaveApplied = false;
    this.observabilityProviderIdentity = undefined;
  }

  hasAdditionalRecoveryState() {
    return super.hasAdditionalRecoveryState() || this.observabilityCoreMayHaveApplied ||
      this.observabilityJobMayHaveApplied || this.observabilityProviderIdentity !== undefined;
  }

  async resolveGraphImage(selected, phase) {
    if (selected.name !== "collector") return await super.resolveGraphImage(selected, phase);
    const indexResult = await this.runRead(
      "docker", ["manifest", "inspect", selected.reference], phase, "provider", 30_000, 4_194_304,
    );
    const manifestResult = await this.runRead(
      "docker", ["manifest", "inspect", selected.selectedReference], phase, "provider", 30_000, 4_194_304,
    );
    try {
      return deepFreeze({
        index: validateCollectorImageIndex(parseBoundedJson(indexResult.stdout, 4_194_304), selected),
        manifest: validateCollectorImageManifest(parseBoundedJson(manifestResult.stdout, 4_194_304), selected),
      });
    } catch (error) {
      if (error instanceof Failure) throw error;
      throw new ObservabilityFailure("normalization");
    }
  }

  async inspectGraphImage(selected, resolution, phase, retained = undefined, reference = selected.reference,
    category = "ownership", aliases = undefined) {
    if (selected.name !== "collector") {
      return await super.inspectGraphImage(selected, resolution, phase, retained, reference, category, aliases);
    }
    const format = "[{{json .Architecture}},{{json .Os}},{{json .Id}},{{json .RepoDigests}},{{json .RepoTags}}," +
      "{{json .RootFS}},{{json (index .Config \"Env\")}},{{json (index .Config \"Entrypoint\")}}," +
      "{{json (index .Config \"Cmd\")}},{{json (index .Config \"ExposedPorts\")}}," +
      "{{json (index .Config \"Volumes\")}},{{json (index .Config \"Labels\")}}," +
      "{{json (or (index .Config \"User\") \"\")}},{{json (or (index .Config \"WorkingDir\") \"\")}}]";
    const result = await this.runRead(
      "docker", ["image", "inspect", "--format", format, reference], phase, category, 15_000, 4_194_304,
    );
    let document;
    try { document = projectGraphImageInspection(parseBoundedJson(result.stdout, 4_194_304)); }
    catch { throw new ObservabilityFailure("normalization"); }
    return validateCollectorImageInspection(document, selected, resolution, retained, aliases);
  }
}

export class DockerKindObservabilityRuntime extends DockerKindGraphRuntime {
  constructor(input, system = undefined) {
    super(input, system ?? new LocalObservabilitySystem(input));
    if (!isDeepStrictEqual(this.system?.profile, buildObservabilityProfile())) {
      throw new TypeError("observability runtime profile is invalid");
    }
  }

  static fromProcess(environment = process.env, systemFactory = (input) => new LocalObservabilitySystem(input)) {
    const selected = DockerKindGraphRuntime.fromProcess(environment, systemFactory);
    return new DockerKindObservabilityRuntime(selected.input, selected.system);
  }
}

export async function runObservabilityMain(runtime = undefined, options = {}) {
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const setExitCode = options.setExitCode ?? ((value) => { process.exitCode = value; });
  try {
    const selected = runtime ?? DockerKindObservabilityRuntime.fromProcess();
    const result = await orchestrate(guardObservabilityLifecycle(selected), {
      cleanupTimeoutMilliseconds: options.cleanupTimeoutMilliseconds ?? observabilityCleanupTimeoutMilliseconds,
      mainTimeoutMilliseconds: options.mainTimeoutMilliseconds ?? observabilityMainTimeoutMilliseconds,
      settlementTimeoutMilliseconds: options.settlementTimeoutMilliseconds ?? observabilitySettlementTimeoutMilliseconds,
    });
    validateObservabilityResult(result);
    stdout.write(`${OBSERVABILITY_SUCCESS_LINE}\n`);
    setExitCode(0);
    return 0;
  } catch (error) {
    const category = OBSERVABILITY_FAILURE_CATEGORIES.includes(error?.category) ? error.category : "panic";
    stderr.write(`Local observability manifest failed: ${category} rejected.\n`);
    setExitCode(1);
    return 1;
  }
}

function guardObservabilityLifecycle(runtime) {
  if (runtime === null || typeof runtime !== "object") throw new TypeError("observability runtime is invalid");
  const guarded = {};
  for (const name of [
    "initialize", "preflight", "buildImages", "createNetwork", "createCluster", "loadImages",
    "applyManifests", "verifyReadiness",
  ]) {
    if (typeof runtime[name] !== "function") throw new TypeError(`observability runtime ${name} is invalid`);
    guarded[name] = (phase) => runtime[name](phase);
  }
  for (const name of ["joinMutations", "cleanup", "auditAbsence"]) {
    if (typeof runtime[name] !== "function") throw new TypeError(`observability runtime ${name} is invalid`);
    guarded[name] = async (phase) => {
      try {
        return await runtime[name](phase);
      } catch (error) {
        if (error instanceof Failure) throw error;
        throw new ObservabilityFailure("cleanup");
      }
    };
  }
  return Object.freeze(guarded);
}

function validateObservabilityResult(value) {
  if (!isPlainObject(value) || value.cleanup !== true || value.internal !== true || value.pods !== 4 ||
      value.ready !== 4 || value.services !== 4 || !isPlainObject(value.graph) ||
      !exactKeys(value.graph, ["internal", "persistent", "ready"]) || value.graph.internal !== true ||
      value.graph.persistent !== true || value.graph.ready !== true || !isPlainObject(value.observability) ||
      !exactKeys(value.observability, ["internal", "noEgress", "ready", "sink", "spans"]) ||
      value.observability.internal !== true || value.observability.noEgress !== true ||
      value.observability.ready !== true || value.observability.sink !== true || value.observability.spans !== 1) {
    throw new ObservabilityFailure("readiness");
  }
}

function exactKeys(value, keys) {
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function plainArray(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return false;
  const keys = Reflect.ownKeys(value);
  const length = Object.getOwnPropertyDescriptor(value, "length");
  if (length === undefined || !("value" in length) || !Number.isSafeInteger(length.value) || length.value < 0 ||
      length.enumerable || keys.length !== length.value + 1 || keys[length.value] !== "length") return false;
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (keys[index] !== String(index) || descriptor === undefined || !("value" in descriptor) ||
        !descriptor.enumerable) return false;
  }
  return true;
}

function requireKeySet(value, keys) {
  if (!isPlainObject(value)) throw new TypeError("Collector evidence is invalid");
  const actual = Object.keys(value);
  if (actual.length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) {
    throw new TypeError("Collector evidence is invalid");
  }
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("Collector evidence is invalid");
    }
  }
}

function requireCollectorPlan(value) {
  if (!isPlainObject(value) || !isDeepStrictEqual(value, buildCollectorImagePlan(value.platform))) {
    throw new TypeError("Collector plan is invalid");
  }
}

function validateContentDescriptor(value, mediaTypes, maximumSize, keys = ["digest", "mediaType", "size"],
  allowPlatform = false) {
  const permitted = allowPlatform && value?.annotations !== undefined ? ["annotations", ...keys] : keys;
  requireKeySet(value, permitted);
  if (!digestPattern.test(value.digest) || !mediaTypes.has(value.mediaType) || !Number.isSafeInteger(value.size) ||
      value.size < 1 || value.size > maximumSize) throw new TypeError("Collector descriptor is invalid");
}

function validateStringMap(value) {
  if (!isPlainObject(value) || Object.keys(value).length > 32 || Object.entries(value).some(([key, item]) =>
    key.length < 1 || key.length > 4_096 || typeof item !== "string" || item.length > 4_096)) {
    throw new TypeError("Collector annotations are invalid");
  }
}

function parseObservabilityProviderList(source) {
  try {
    const document = parseBoundedJson(source, observabilityProviderByteLimit);
    requireKeySet(document, ["apiVersion", "items", "kind", "metadata"]);
    requireKeySet(document.metadata, ["resourceVersion"]);
    if (document.apiVersion !== "v1" || document.kind !== "List" ||
        document.metadata.resourceVersion !== "" || !plainArray(document.items) ||
        document.items.length > 128) throw new TypeError("observability provider list is invalid");
    return structuredClone(document.items);
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new ObservabilityFailure("normalization");
  }
}

function projectObservabilityProviderResources(items, label) {
  try {
    if (!plainArray(items)) throw new TypeError("observability provider items are invalid");
    const projector = {
      configMaps: projectObservabilityConfigMap,
      deployments: projectObservabilityDeployment,
      endpointSlices: projectObservabilityEndpointSlice,
      ingresses: (item) => structuredClone(item),
      jobs: projectObservabilityJob,
      pods: projectObservabilityPod,
      replicaSets: projectObservabilityReplicaSet,
      services: projectObservabilityService,
    }[label];
    if (projector === undefined) throw new TypeError("observability provider label is invalid");
    return items.map(projector);
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new ObservabilityFailure("normalization");
  }
}

function projectObservabilityConfigMap(item) {
  return {
    apiVersion: item?.apiVersion,
    data: structuredClone(item?.data),
    kind: item?.kind,
    metadata: retainObservabilityDeletionState(item, {
      labels: structuredClone(item?.metadata?.labels),
      name: item?.metadata?.name,
      namespace: item?.metadata?.namespace,
      resourceVersion: item?.metadata?.resourceVersion,
      uid: item?.metadata?.uid,
    }),
  };
}

function projectObservabilityDeployment(item) {
  return {
    apiVersion: item?.apiVersion,
    kind: item?.kind,
    metadata: retainObservabilityDeletionState(item, {
      generation: item?.metadata?.generation,
      labels: structuredClone(item?.metadata?.labels),
      name: item?.metadata?.name,
      namespace: item?.metadata?.namespace,
      resourceVersion: item?.metadata?.resourceVersion,
      uid: item?.metadata?.uid,
    }),
    spec: projectObservabilityWorkloadSpec(item?.spec),
    status: {
      availableReplicas: item?.status?.availableReplicas ?? 0,
      conditions: Array.isArray(item?.status?.conditions) ? item.status.conditions
        .filter(({ type }) => type === "Available").map(({ status, type }) => ({ status, type })) : undefined,
      observedGeneration: item?.status?.observedGeneration,
      readyReplicas: item?.status?.readyReplicas ?? 0,
      replicas: item?.status?.replicas ?? 0,
      unavailableReplicas: item?.status?.unavailableReplicas ?? 0,
      updatedReplicas: item?.status?.updatedReplicas ?? 0,
    },
  };
}

function projectObservabilityReplicaSet(item) {
  return {
    apiVersion: item?.apiVersion,
    kind: item?.kind,
    metadata: retainObservabilityDeletionState(item, {
      labels: structuredClone(item?.metadata?.labels),
      name: item?.metadata?.name,
      namespace: item?.metadata?.namespace,
      ownerReferences: projectObservabilityOwnerReferences(item?.metadata?.ownerReferences),
      resourceVersion: item?.metadata?.resourceVersion,
      uid: item?.metadata?.uid,
    }),
    spec: projectObservabilityWorkloadSpec(item?.spec),
    status: {
      availableReplicas: item?.status?.availableReplicas ?? 0,
      fullyLabeledReplicas: item?.status?.fullyLabeledReplicas ?? 0,
      observedGeneration: item?.status?.observedGeneration,
      readyReplicas: item?.status?.readyReplicas ?? 0,
      replicas: item?.status?.replicas ?? 0,
    },
  };
}

function projectObservabilityPod(item) {
  return {
    apiVersion: item?.apiVersion,
    kind: item?.kind,
    metadata: retainObservabilityDeletionState(item, {
      labels: structuredClone(item?.metadata?.labels),
      name: item?.metadata?.name,
      namespace: item?.metadata?.namespace,
      ownerReferences: projectObservabilityOwnerReferences(item?.metadata?.ownerReferences),
      resourceVersion: item?.metadata?.resourceVersion,
      uid: item?.metadata?.uid,
    }),
    spec: structuredClone(item?.spec),
    status: {
      conditions: Array.isArray(item?.status?.conditions) ? item.status.conditions
        .filter(({ type }) => type === "Ready").map(({ status, type }) => ({ status, type })) : undefined,
      containerStatuses: Array.isArray(item?.status?.containerStatuses)
        ? item.status.containerStatuses.map(projectObservabilityContainerStatus) : undefined,
      phase: item?.status?.phase,
      podIP: item?.status?.podIP,
    },
  };
}

function projectObservabilityContainerStatus(value) {
  let state;
  if (value?.state?.running !== undefined) {
    state = { running: { startedAt: value.state.running.startedAt } };
  } else if (value?.state?.terminated !== undefined) {
    state = { terminated: {
      containerID: value.state.terminated.containerID,
      exitCode: value.state.terminated.exitCode,
      finishedAt: value.state.terminated.finishedAt,
      reason: value.state.terminated.reason,
      startedAt: value.state.terminated.startedAt,
    } };
  } else {
    state = structuredClone(value?.state);
  }
  return {
    containerID: value?.containerID,
    image: value?.image,
    imageID: value?.imageID,
    lastState: structuredClone(value?.lastState),
    name: value?.name,
    ready: value?.ready,
    restartCount: value?.restartCount,
    started: value?.started,
    state,
  };
}

function projectObservabilityService(item) {
  return {
    apiVersion: item?.apiVersion,
    kind: item?.kind,
    metadata: retainObservabilityDeletionState(item, {
      labels: structuredClone(item?.metadata?.labels),
      name: item?.metadata?.name,
      namespace: item?.metadata?.namespace,
      resourceVersion: item?.metadata?.resourceVersion,
      uid: item?.metadata?.uid,
    }),
    spec: structuredClone(item?.spec),
    status: { loadBalancer: structuredClone(item?.status?.loadBalancer ?? {}) },
  };
}

function projectObservabilityEndpointSlice(item) {
  return {
    addressType: item?.addressType,
    apiVersion: item?.apiVersion,
    endpoints: Array.isArray(item?.endpoints) ? item.endpoints.map((endpoint) => ({
      addresses: structuredClone(endpoint?.addresses),
      conditions: {
        ready: endpoint?.conditions?.ready,
        serving: endpoint?.conditions?.serving,
        terminating: endpoint?.conditions?.terminating ?? false,
      },
      nodeName: endpoint?.nodeName,
      targetRef: {
        kind: endpoint?.targetRef?.kind,
        name: endpoint?.targetRef?.name,
        namespace: endpoint?.targetRef?.namespace,
        uid: endpoint?.targetRef?.uid,
      },
    })) : [],
    kind: item?.kind,
    metadata: retainObservabilityDeletionState(item, {
      labels: structuredClone(item?.metadata?.labels),
      name: item?.metadata?.name,
      namespace: item?.metadata?.namespace,
      ownerReferences: projectObservabilityOwnerReferences(item?.metadata?.ownerReferences),
      resourceVersion: item?.metadata?.resourceVersion,
      uid: item?.metadata?.uid,
    }),
    ports: Array.isArray(item?.ports)
      ? item.ports.map(({ name, port, protocol }) => ({ name, port, protocol })) : [],
  };
}

function projectObservabilityJob(item) {
  return {
    apiVersion: item?.apiVersion,
    kind: item?.kind,
    metadata: retainObservabilityDeletionState(item, {
      labels: structuredClone(item?.metadata?.labels),
      name: item?.metadata?.name,
      namespace: item?.metadata?.namespace,
      resourceVersion: item?.metadata?.resourceVersion,
      uid: item?.metadata?.uid,
    }),
    spec: projectObservabilityWorkloadSpec(item?.spec),
    status: {
      completionTime: item?.status?.completionTime,
      conditions: Array.isArray(item?.status?.conditions) ? item.status.conditions
        .filter(({ type }) => type === "Complete" || type === "Failed").map((condition) => ({
          lastProbeTime: condition.lastProbeTime,
          lastTransitionTime: condition.lastTransitionTime,
          status: condition.status,
          type: condition.type,
        })) : undefined,
      failed: item?.status?.failed ?? 0,
      ready: item?.status?.ready ?? 0,
      startTime: item?.status?.startTime,
      succeeded: item?.status?.succeeded ?? 0,
    },
  };
}

function projectObservabilityOwnerReferences(value) {
  return Array.isArray(value) ? value.map((entry) => ({
    apiVersion: entry?.apiVersion,
    blockOwnerDeletion: entry?.blockOwnerDeletion,
    controller: entry?.controller,
    kind: entry?.kind,
    name: entry?.name,
    uid: entry?.uid,
  })) : [];
}

function retainObservabilityDeletionState(item, metadata) {
  if (item?.metadata?.deletionTimestamp !== undefined) {
    metadata.deletionTimestamp = item.metadata.deletionTimestamp;
  }
  if (item?.metadata?.deletionGracePeriodSeconds !== undefined) {
    metadata.deletionGracePeriodSeconds = item.metadata.deletionGracePeriodSeconds;
  }
  return metadata;
}

function projectObservabilityWorkloadSpec(value) {
  const spec = structuredClone(value);
  const podSpec = spec?.template?.spec;
  if (!isPlainObject(podSpec)) return spec;
  for (const key of ["hostIPC", "hostNetwork", "hostPID"]) {
    if (podSpec[key] === undefined) podSpec[key] = false;
  }
  return spec;
}

function requireObservabilityProviderAbsent(value) {
  try {
    requireKeySet(value, [
      "configMaps", "deployments", "endpointSlices", "ingresses", "jobLog", "jobs", "pods", "replicaSets",
      "services",
    ]);
    if (value.jobLog !== null || [
      value.configMaps, value.deployments, value.endpointSlices, value.ingresses, value.jobs, value.pods,
      value.replicaSets, value.services,
    ].some((items) => !plainArray(items) || items.length !== 0)) {
      throw new TypeError("observability provider resources remain");
    }
    return true;
  } catch {
    throw new ObservabilityFailure("cleanup");
  }
}

function terminalObservabilityProviderState(value, requireJob) {
  if (!isPlainObject(value) || !plainArray(value.jobs) || !plainArray(value.pods)) return true;
  const spanPods = value.pods.filter((pod) =>
    pod?.metadata?.labels?.["app.kubernetes.io/name"] === OBSERVABILITY_CONSTANTS.spanJobName);
  const collectorPods = value.pods.filter((pod) =>
    pod?.metadata?.labels?.["app.kubernetes.io/name"] === OBSERVABILITY_CONSTANTS.collectorName);
  if (collectorPods.length > 1 || value.jobs.length > 1 || spanPods.length > 1 ||
      value.pods.some((pod) => pod?.metadata?.deletionTimestamp !== undefined) ||
      value.pods.flatMap((pod) => pod?.status?.containerStatuses ?? []).some((status) =>
        status?.restartCount > 0 || status?.state?.terminated?.exitCode !== undefined &&
          status.state.terminated.exitCode !== 0)) return true;
  if (!requireJob) return value.jobs.length !== 0 || spanPods.length !== 0;
  return value.jobs.some((job) => job?.status?.failed > 0 || job?.status?.conditions?.some((condition) =>
    condition?.type === "Failed" && condition?.status === "True"));
}

function parseObservabilitySinkFrame(source) {
  try {
    if (typeof source !== "string" || !source.endsWith("\n") ||
        Buffer.byteLength(source, "utf8") > OBSERVABILITY_CONSTANTS.sinkByteLimit + 1_024) {
      throw new TypeError("observability sink frame is invalid");
    }
    const lines = source.split("\n");
    if (lines.length !== 4 || lines[3] !== "") throw new TypeError("observability sink frame is invalid");
    const pattern = /^ZASP-SINK:(\d+)\|(\d+)\|(\d+)\|regular file\|(\d+)\|(\d+)\|([0-7]{3,4})$/;
    const before = pattern.exec(lines[0]);
    const after = pattern.exec(lines[2]);
    if (before === null || after === null || lines[0] !== lines[2]) {
      throw new TypeError("observability sink changed");
    }
    const numbers = before.slice(1, 6).map(Number);
    const size = numbers[2];
    if (numbers.some((value) => !Number.isSafeInteger(value) || value < 0) || numbers[0] < 1 || numbers[1] < 1 ||
        size < 1 || size > OBSERVABILITY_CONSTANTS.sinkByteLimit ||
        size !== Buffer.byteLength(`${lines[1]}\n`, "utf8")) throw new TypeError("observability sink identity is invalid");
    return parseObservabilitySink(Buffer.from(`${lines[1]}\n`, "utf8"));
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new ObservabilityFailure("normalization");
  }
}

function validateObservabilityJob(value, expected, jobResource) {
  const job = value.jobs[0];
  const pod = value.pods.find((item) => item?.metadata?.labels?.["app.kubernetes.io/name"] === "otel-test-span");
  const jobUid = providerUid(job?.metadata?.uid);
  const podUid = providerUid(pod?.metadata?.uid);
  const jobVersion = providerVersion(job?.metadata?.resourceVersion);
  const podVersion = providerVersion(pod?.metadata?.resourceVersion);
  const podName = /^otel-test-span-[a-z0-9]{5}$/.test(pod?.metadata?.name ?? "") ? pod.metadata.name : undefined;
  const container = pod?.status?.containerStatuses?.[0];
  const containerId = providerContainerId(container?.containerID);
  const startTime = providerTimestamp(job?.status?.startTime);
  const completionTime = providerTimestamp(job?.status?.completionTime);
  const podStartedAt = providerTimestamp(container?.state?.terminated?.startedAt);
  const finishedAt = providerTimestamp(container?.state?.terminated?.finishedAt);
  const transitionTime = providerTimestamp(job?.status?.conditions?.[0]?.lastTransitionTime);
  const probeTime = providerTimestamp(job?.status?.conditions?.[0]?.lastProbeTime);
  const podIP = validPodAddress(pod?.status?.podIP) ? pod.status.podIP : undefined;
  if ([jobUid, podUid, jobVersion, podVersion, podName, containerId, startTime, completionTime, podStartedAt,
    finishedAt, transitionTime, probeTime, podIP].some((item) => item === undefined) ||
      !(Date.parse(startTime) <= Date.parse(podStartedAt) && Date.parse(podStartedAt) < Date.parse(finishedAt) &&
        Date.parse(finishedAt) <= Date.parse(completionTime)) || transitionTime !== completionTime ||
      probeTime !== completionTime) throw new TypeError("observability Job identity is invalid");
  const labels = {
    ...jobResource.spec.template.metadata.labels,
    "batch.kubernetes.io/controller-uid": jobUid,
    "batch.kubernetes.io/job-name": "otel-test-span",
    "controller-uid": jobUid,
    "job-name": "otel-test-span",
  };
  const expectedJob = {
    apiVersion: "batch/v1", kind: "Job",
    metadata: { labels: structuredClone(jobResource.metadata.labels), name: "otel-test-span", namespace: "zasp-local", resourceVersion: jobVersion, uid: jobUid },
    spec: {
      activeDeadlineSeconds: 30, backoffLimit: 0, completionMode: "NonIndexed", completions: 1,
      manualSelector: false, parallelism: 1, podReplacementPolicy: "Failed",
      selector: { matchLabels: { "batch.kubernetes.io/controller-uid": jobUid } }, suspend: false,
      template: providerObservabilityTemplate(jobResource.spec.template, labels),
    },
    status: {
      completionTime,
      conditions: [{ lastProbeTime: probeTime, lastTransitionTime: transitionTime, status: "True", type: "Complete" }],
      failed: 0, ready: 0, startTime, succeeded: 1,
    },
  };
  const expectedPod = {
    apiVersion: "v1", kind: "Pod",
    metadata: {
      labels, name: podName, namespace: "zasp-local",
      ownerReferences: [{ apiVersion: "batch/v1", blockOwnerDeletion: true, controller: true, kind: "Job", name: "otel-test-span", uid: jobUid }],
      resourceVersion: podVersion, uid: podUid,
    },
    spec: providerObservabilityPodSpec(jobResource.spec.template, expected.nodeName),
    status: {
      conditions: [{ status: "False", type: "Ready" }],
      containerStatuses: [{
        containerID: containerId, image: expected.imageTargets.busybox.configDigest,
        imageID: expected.imageTargets.busybox.imageID, lastState: {}, name: "span-generator", ready: false,
        restartCount: 0, started: false, state: { terminated: {
          containerID: containerId, exitCode: 0, finishedAt, reason: "Completed", startedAt: podStartedAt,
        } },
      }],
      phase: "Succeeded", podIP,
    },
  };
  if (!isDeepStrictEqual(job, expectedJob) || !isDeepStrictEqual(pod, expectedPod)) {
    throw new TypeError("observability Job provider state is invalid");
  }
  return deepFreeze({
    completionTime,
    containerId,
    finishedAt,
    jobUid,
    log: observabilityJobLog,
    podName,
    podUid,
    providerJob: structuredClone(job),
    providerPod: structuredClone(pod),
  });
}

function validateFailedObservabilityKubernetesState(value, expected, retained, category) {
  try {
    requireKeySet(value, [
      "configMaps", "deployments", "endpointSlices", "ingresses", "jobLog", "jobs", "pods", "replicaSets",
      "services",
    ]);
    if (!plainArray(value.jobs) || value.jobs.length !== 1 || !plainArray(value.pods) ||
        value.pods.length !== 2 || value.jobLog !== "") {
      throw new TypeError("failed observability collection is invalid");
    }
    const collectorPods = value.pods.filter((pod) =>
      pod?.metadata?.labels?.["app.kubernetes.io/name"] === OBSERVABILITY_CONSTANTS.collectorName);
    const failedPods = value.pods.filter((pod) =>
      pod?.metadata?.labels?.["app.kubernetes.io/name"] === OBSERVABILITY_CONSTANTS.spanJobName);
    if (collectorPods.length !== 1 || failedPods.length !== 1) {
      throw new TypeError("failed observability pods are invalid");
    }
    const core = validateObservabilityKubernetesState({
      configMaps: value.configMaps,
      deployments: value.deployments,
      endpointSlices: value.endpointSlices,
      ingresses: value.ingresses,
      jobLog: null,
      jobs: [],
      pods: collectorPods,
      replicaSets: value.replicaSets,
      services: value.services,
    }, expected, retained, false, category);
    const job = validateFailedObservabilityJob(value.jobs[0], failedPods[0], expected);
    if (retained?.job !== null && retained?.job !== undefined &&
        !isDeepStrictEqual(retained.job, job)) {
      throw new TypeError("failed observability Job changed");
    }
    return deepFreeze({ ...core, job });
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new ObservabilityFailure(category);
  }
}

function validateFailedObservabilityJob(job, pod, expected) {
  const jobResource = buildObservabilityResources()[3];
  const jobUid = providerUid(job?.metadata?.uid);
  const podUid = providerUid(pod?.metadata?.uid);
  const jobVersion = providerVersion(job?.metadata?.resourceVersion);
  const podVersion = providerVersion(pod?.metadata?.resourceVersion);
  const podName = /^otel-test-span-[a-z0-9]{5}$/.test(pod?.metadata?.name ?? "")
    ? pod.metadata.name : undefined;
  const container = pod?.status?.containerStatuses?.[0];
  const containerId = providerContainerId(container?.containerID);
  const startTime = providerTimestamp(job?.status?.startTime);
  const podStartedAt = providerTimestamp(container?.state?.terminated?.startedAt);
  const finishedAt = providerTimestamp(container?.state?.terminated?.finishedAt);
  const transitionTime = providerTimestamp(job?.status?.conditions?.[0]?.lastTransitionTime);
  const probeTime = providerTimestamp(job?.status?.conditions?.[0]?.lastProbeTime);
  const podIP = validPodAddress(pod?.status?.podIP) ? pod.status.podIP : undefined;
  const exitCode = container?.state?.terminated?.exitCode;
  if ([jobUid, podUid, jobVersion, podVersion, podName, containerId, startTime, podStartedAt, finishedAt,
    transitionTime, probeTime, podIP].some((item) => item === undefined) ||
      !Number.isSafeInteger(exitCode) || exitCode < 1 || exitCode > 255 ||
      !(Date.parse(startTime) <= Date.parse(podStartedAt) && Date.parse(podStartedAt) < Date.parse(finishedAt) &&
        Date.parse(finishedAt) <= Date.parse(transitionTime)) || probeTime !== transitionTime) {
    throw new TypeError("failed observability Job identity is invalid");
  }
  const labels = {
    ...jobResource.spec.template.metadata.labels,
    "batch.kubernetes.io/controller-uid": jobUid,
    "batch.kubernetes.io/job-name": OBSERVABILITY_CONSTANTS.spanJobName,
    "controller-uid": jobUid,
    "job-name": OBSERVABILITY_CONSTANTS.spanJobName,
  };
  const expectedJob = {
    apiVersion: "batch/v1",
    kind: "Job",
    metadata: {
      labels: structuredClone(jobResource.metadata.labels),
      name: OBSERVABILITY_CONSTANTS.spanJobName,
      namespace: OBSERVABILITY_CONSTANTS.namespace,
      resourceVersion: jobVersion,
      uid: jobUid,
    },
    spec: {
      activeDeadlineSeconds: 30,
      backoffLimit: 0,
      completionMode: "NonIndexed",
      completions: 1,
      manualSelector: false,
      parallelism: 1,
      podReplacementPolicy: "Failed",
      selector: { matchLabels: { "batch.kubernetes.io/controller-uid": jobUid } },
      suspend: false,
      template: providerObservabilityTemplate(jobResource.spec.template, labels),
    },
    status: {
      completionTime: undefined,
      conditions: [{
        lastProbeTime: probeTime,
        lastTransitionTime: transitionTime,
        status: "True",
        type: "Failed",
      }],
      failed: 1,
      ready: 0,
      startTime,
      succeeded: 0,
    },
  };
  const expectedPod = {
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
      labels,
      name: podName,
      namespace: OBSERVABILITY_CONSTANTS.namespace,
      ownerReferences: [{
        apiVersion: "batch/v1",
        blockOwnerDeletion: true,
        controller: true,
        kind: "Job",
        name: OBSERVABILITY_CONSTANTS.spanJobName,
        uid: jobUid,
      }],
      resourceVersion: podVersion,
      uid: podUid,
    },
    spec: providerObservabilityPodSpec(jobResource.spec.template, expected.nodeName),
    status: {
      conditions: [{ status: "False", type: "Ready" }],
      containerStatuses: [{
        containerID: containerId,
        image: expected.imageTargets.busybox.configDigest,
        imageID: expected.imageTargets.busybox.imageID,
        lastState: {},
        name: "span-generator",
        ready: false,
        restartCount: 0,
        started: false,
        state: { terminated: {
          containerID: containerId,
          exitCode,
          finishedAt,
          reason: "Error",
          startedAt: podStartedAt,
        } },
      }],
      phase: "Failed",
      podIP,
    },
  };
  if (!isDeepStrictEqual(job, expectedJob) || !isDeepStrictEqual(pod, expectedPod)) {
    throw new TypeError("failed observability Job provider state is invalid");
  }
  return deepFreeze({
    failed: true,
    finishedAt,
    jobUid,
    log: "",
    podName,
    podUid,
    providerJob: structuredClone(job),
    providerPod: structuredClone(pod),
  });
}

function providerObservabilityContainer(value) {
  const projected = {
    ...structuredClone(value),
    terminationMessagePath: "/dev/termination-log",
    terminationMessagePolicy: "File",
  };
  if (Array.isArray(projected.volumeMounts)) projected.volumeMounts = projected.volumeMounts.map((mount) => {
    const item = { ...mount };
    if (item.readOnly === false) delete item.readOnly;
    return item;
  });
  return projected;
}

function providerObservabilityTemplate(template, labels = template.metadata.labels) {
  return {
    metadata: { creationTimestamp: null, labels: structuredClone(labels) },
    spec: {
      ...structuredClone(template.spec),
      containers: template.spec.containers.map(providerObservabilityContainer),
      schedulerName: "default-scheduler",
    },
  };
}

function providerObservabilityPodSpec(template, nodeName) {
  return {
    automountServiceAccountToken: template.spec.automountServiceAccountToken,
    containers: template.spec.containers.map(providerObservabilityContainer),
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
    volumes: structuredClone(template.spec.volumes),
  };
}

function providerUid(value) {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
    ? value : undefined;
}

function providerVersion(value) {
  return typeof value === "string" && /^[1-9]\d{0,19}$/.test(value) ? value : undefined;
}

function providerContainerId(value) {
  return typeof value === "string" && /^containerd:\/\/[0-9a-f]{64}$/.test(value) ? value : undefined;
}

function providerTimestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value))) return undefined;
  return new Date(value).toISOString().replace(".000Z", "Z") === value ? value : undefined;
}

function validPodAddress(value) {
  if (typeof value !== "string") return false;
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (match === null || match.slice(1).some((item) => Number(item) > 255)) return false;
  return value.startsWith("10.");
}

function validServiceAddress(value) {
  return validPodAddress(value) && value.startsWith("10.96.");
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function collectorFacts(created, layers) {
  return {
    command: ["--config", "/etc/otelcol-contrib/config.yaml"],
    entrypoint: ["/otelcol-contrib"],
    environment: ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    exposedPorts: { "4317/tcp": {}, "4318/tcp": {}, "55679/tcp": {} },
    intrinsicVolumes: null,
    labels: {
      "org.opencontainers.image.created": created,
      "org.opencontainers.image.licenses": "Apache-2.0",
      "org.opencontainers.image.name": "opentelemetry-collector-releases",
      "org.opencontainers.image.revision": "1400269f8ace841f8d0492f4f9c6c7f305f95268",
      "org.opencontainers.image.source": "https://github.com/open-telemetry/opentelemetry-collector-releases",
      "org.opencontainers.image.version": "0.158.0",
    },
    rootfs: { Layers: layers, Type: "layers" },
    user: "10001:10001",
    workingDirectory: "/",
  };
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runObservabilityMain();
}
