import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import {
  buildObservabilityCoreResources,
  buildObservabilitySpanResources,
  COLLECTOR_IMAGE,
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

export class LocalObservabilitySystem extends LocalGraphSystem {
  constructor(input, dependencies = undefined) {
    super(input, dependencies, buildObservabilityProfile());
    this.graphImagePlans.set("collector", buildCollectorImagePlan(input.nodePlatform));
  }

  async applyManifests(phase) {
    const stagedKey = observabilityApplyPlan().staged[0];
    const spanPath = this.additionalManifestPaths.get(stagedKey);
    if (spanPath === undefined || !this.additionalManifestPaths.delete(stagedKey)) {
      throw new ObservabilityFailure("ownership");
    }
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
