import { createHash } from "node:crypto";
import { normalize } from "node:path";
import { fileURLToPath } from "node:url";

import { GRAPH_CONSTANTS, GRAPH_IMAGES, buildGraphResources, renderGraphManifest } from "./graph-manifest.mjs";
import { PRODUCTS } from "./manifests.mjs";
import { buildLocalStackImagePlan } from "./aws-emulator-image.mjs";
import { buildCollectorImagePlan } from "./observability-image.mjs";
import {
  DockerKindRuntime,
  Failure,
  LocalProductSystem,
  orchestrate,
  parseBoundedJson,
} from "./run.mjs";

const digestPattern = /^sha256:[0-9a-f]{64}$/;
const objectIdPattern = /^[0-9a-f]{64}$/;
const kubernetesUidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const resourceVersionPattern = /^[1-9]\d*$/;
const forbiddenImageEnvironment = /^(?:AWS_|AZURE_|GOOGLE_|CLOUDSDK_|KUBE|DOCKER_|HTTP_PROXY$|HTTPS_PROXY$|ALL_PROXY$|NO_PROXY$)/i;
const graphMainTimeoutMilliseconds = 720_000;
const graphCleanupTimeoutMilliseconds = 240_000;
const graphSettlementTimeoutMilliseconds = 60_000;
const graphProviderByteLimit = 4_194_304;
const graphProviderPollLimit = 240;
const graphProviderPollMilliseconds = 500;
const graphHealthLog = "neo4j-health-ready\n";
const graphMarkerOutput = "marker_count\n1\n";
const graphMarkerAddress = "neo4j://neo4j.zasp-local.svc.cluster.local:7687";
const graphMarkerLabel = "ZaspLocalGraphProof";
const graphForbiddenGoEnvironment = /^(?:CGO_|GO)[A-Z0-9_]*$/;
const graphGoToolCandidates = deepFreeze({
  "darwin/amd64": "/usr/local/bin/go",
  "darwin/arm64": "/opt/homebrew/bin/go",
  "linux/amd64": "/usr/local/go/bin/go",
  "linux/arm64": "/usr/local/go/bin/go",
});
const graphGoToolCanonicalPatterns = deepFreeze({
  "darwin/amd64": /^(?:\/usr\/local\/bin\/go|\/usr\/local\/Cellar\/go\/1\.25\.6(?:_\d+)?\/libexec\/bin\/go)$/,
  "darwin/arm64": /^(?:\/opt\/homebrew\/bin\/go|\/opt\/homebrew\/Cellar\/go\/1\.25\.6(?:_\d+)?\/libexec\/bin\/go)$/,
  "linux/amd64": /^\/usr\/local\/go\/bin\/go$/,
  "linux/arm64": /^\/usr\/local\/go\/bin\/go$/,
});

export const GRAPH_SUCCESS_LINE = "Local graph manifest passed: ready=true internal=true persistent=true cleanup=true.";
export const GRAPH_FAILURE_CATEGORIES = Object.freeze([
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

export const GRAPH_IMAGE_PLANS = deepFreeze({
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
    reference: GRAPH_IMAGES.health,
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
    reference: GRAPH_IMAGES.neo4j,
    repository: "neo4j",
  },
});

const graphImageRuntimeFacts = deepFreeze({
  busybox: {
    "linux/amd64": {
      command: ["sh"],
      entrypoint: null,
      environment: ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
      exposedPorts: null,
      intrinsicVolumes: null,
      labels: {
        commit_id: "22d90ebde235edec3541f728b37a01285bdd8b1b",
        git_url: "https://github.com/kubernetes/kubernetes/tree/22d90ebde235edec3541f728b37a01285bdd8b1b/test/images/busybox",
        image_version: "1.36.1-1",
      },
      rootfs: {
        Layers: ["sha256:3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f"],
        Type: "layers",
      },
      user: "",
      workingDirectory: "",
    },
    "linux/arm64": {
      command: ["sh"],
      entrypoint: null,
      environment: ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
      exposedPorts: null,
      intrinsicVolumes: null,
      labels: {
        commit_id: "22d90ebde235edec3541f728b37a01285bdd8b1b",
        git_url: "https://github.com/kubernetes/kubernetes/tree/22d90ebde235edec3541f728b37a01285bdd8b1b/test/images/busybox",
        image_version: "1.36.1-1",
      },
      rootfs: {
        Layers: ["sha256:3694737149b11ec4d2c9f15ad24788e81955cd1c7f2c6f555baf1e4a3615bd26"],
        Type: "layers",
      },
      user: "",
      workingDirectory: "",
    },
  },
  neo4j: {
    "linux/amd64": {
      command: ["neo4j"],
      entrypoint: ["tini", "-g", "--", "/startup/docker-entrypoint.sh"],
      environment: [
        "PATH=/var/lib/neo4j/bin:/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "JAVA_HOME=/opt/java/openjdk",
        "NEO4J_SHA256=9d4064cdd87627cae376a741c893848c4faa3c4fb980362b6dae541c203e8072",
        "NEO4J_TARBALL=neo4j-community-5.26.28-unix.tar.gz",
        "NEO4J_EDITION=community",
        "NEO4J_HOME=/var/lib/neo4j",
        "LANG=C.UTF-8",
      ],
      exposedPorts: { "7473/tcp": {}, "7474/tcp": {}, "7687/tcp": {} },
      intrinsicVolumes: { "/data": {}, "/logs": {} },
      labels: null,
      rootfs: {
        Layers: [
          "sha256:6f94328331290cbd81edab450664d42da7b64c191416c9346cd5d28c84f76035",
          "sha256:8b21e26c8d3c159e0cbe66c916817f3c6248d896e17696a688cd1fc628084fc6",
          "sha256:25b91126e4557fee9cbf75da6100a71079d92e71c476b2736c69a4118c374856",
          "sha256:7b06c003260874d1194c2a789ad0bb53fa08aef8fb621ad85a60ba093464cd5c",
          "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
        ],
        Type: "layers",
      },
      user: "",
      workingDirectory: "/var/lib/neo4j",
    },
    "linux/arm64": {
      command: ["neo4j"],
      entrypoint: ["tini", "-g", "--", "/startup/docker-entrypoint.sh"],
      environment: [
        "PATH=/var/lib/neo4j/bin:/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "JAVA_HOME=/opt/java/openjdk",
        "NEO4J_SHA256=9d4064cdd87627cae376a741c893848c4faa3c4fb980362b6dae541c203e8072",
        "NEO4J_TARBALL=neo4j-community-5.26.28-unix.tar.gz",
        "NEO4J_EDITION=community",
        "NEO4J_HOME=/var/lib/neo4j",
        "LANG=C.UTF-8",
      ],
      exposedPorts: { "7473/tcp": {}, "7474/tcp": {}, "7687/tcp": {} },
      intrinsicVolumes: { "/data": {}, "/logs": {} },
      labels: null,
      rootfs: {
        Layers: [
          "sha256:c01c35a040a25a51cd473910e3212a46d85fb700a6467c687f231d7edd47cbc1",
          "sha256:9740541a641149918376635dca8d31a457abbe8201ffa5b1c4bcf62b3c235342",
          "sha256:24be1ee0a923e6aa95b88769e7567db289e37a0a6c11bd2a23a433b392fdc341",
          "sha256:4f2bc04bffc88e927b6c7b6eba1d35b13e2567fee53d48970ddc89d1e690ef1c",
          "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
        ],
        Type: "layers",
      },
      user: "",
      workingDirectory: "/var/lib/neo4j",
    },
  },
});

export class GraphFailure extends Failure {
  constructor(category = "panic") {
    super("operation");
    this.category = GRAPH_FAILURE_CATEGORIES.includes(category) ? category : "panic";
  }
}

export function buildGraphImagePlan(name, platform) {
  const image = GRAPH_IMAGE_PLANS[name];
  const selected = image?.platforms?.[platform];
  if (image === undefined || selected === undefined || !new Set(["linux/amd64", "linux/arm64"]).has(platform)) {
    throw new TypeError("graph image plan is invalid");
  }
  const architecture = platform.slice("linux/".length);
  const tag = image.reference.split("@")[0];
  const providerRepository = image.repository.includes("/") ? image.repository : `docker.io/library/${image.repository}`;
  return deepFreeze({
    architecture,
    configDigest: selected.configDigest,
    indexDigest: image.indexDigest,
    manifestDigest: selected.manifestDigest,
    name: image.name,
    platform,
    providerReference: `${providerRepository}:${tag.slice(tag.lastIndexOf(":") + 1)}@${image.indexDigest}`,
    reference: image.reference,
    repoDigest: `${image.repository}@${image.indexDigest}`,
    repository: image.repository,
    selectedReference: `${image.repository}@${selected.manifestDigest}`,
    tag,
  });
}

export function validateGraphImageIndex(document, selected) {
  try {
    validateSelectedPlan(selected);
    requireExactKeySet(document, ["manifests", "mediaType", "schemaVersion"], "graph index");
    if (document.schemaVersion !== 2 || !new Set([
      "application/vnd.docker.distribution.manifest.list.v2+json",
      "application/vnd.oci.image.index.v1+json",
    ]).has(document.mediaType) || !Array.isArray(document.manifests) || document.manifests.length < 2 ||
        document.manifests.length > 64) throw new TypeError("graph index is invalid");

    const descriptors = [];
    const digests = new Set();
    for (const descriptor of document.manifests) {
      const allowed = descriptor.annotations === undefined
        ? ["digest", "mediaType", "platform", "size"]
        : ["annotations", "digest", "mediaType", "platform", "size"];
      requireExactKeySet(descriptor, allowed, "graph index descriptor");
      if (!digestPattern.test(descriptor.digest) || digests.has(descriptor.digest) ||
          !new Set([
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
          ]).has(descriptor.mediaType) || !Number.isSafeInteger(descriptor.size) || descriptor.size < 1 ||
          descriptor.size > 16_777_216) throw new TypeError("graph index descriptor is invalid");
      validatePlatformDescriptor(descriptor.platform);
      if (descriptor.annotations !== undefined) validateStringMap(descriptor.annotations, 32, 4_096);
      digests.add(descriptor.digest);
      descriptors.push(structuredClone(descriptor));
    }

    for (const [platform, pinned] of Object.entries(GRAPH_IMAGE_PLANS[selected.name].platforms)) {
      const architecture = platform.slice("linux/".length);
      const matches = descriptors.filter((descriptor) => descriptor.platform.os === "linux" &&
        descriptor.platform.architecture === architecture && descriptor.digest === pinned.manifestDigest);
      if (matches.length !== 1) throw new TypeError("graph platform descriptor is invalid");
    }
    const matches = descriptors.filter((descriptor) => descriptor.platform.os === "linux" &&
      descriptor.platform.architecture === selected.architecture && descriptor.digest === selected.manifestDigest);
    if (matches.length !== 1) throw new TypeError("selected graph descriptor is invalid");
    return deepFreeze({
      indexDigest: selected.indexDigest,
      manifests: descriptors,
      mediaType: document.mediaType,
      schemaVersion: 2,
      selected: structuredClone(matches[0]),
    });
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("normalization");
  }
}

export function validateGraphImageManifest(document, selected) {
  try {
    validateSelectedPlan(selected);
    const keys = document?.annotations === undefined
      ? ["config", "layers", "mediaType", "schemaVersion"]
      : ["annotations", "config", "layers", "mediaType", "schemaVersion"];
    requireExactKeySet(document, keys, "graph platform manifest");
    if (document.schemaVersion !== 2 || !new Set([
      "application/vnd.docker.distribution.manifest.v2+json",
      "application/vnd.oci.image.manifest.v1+json",
    ]).has(document.mediaType) || !Array.isArray(document.layers) || document.layers.length < 1 ||
        document.layers.length > 256) throw new TypeError("graph platform manifest is invalid");
    if (document.annotations !== undefined) validateStringMap(document.annotations, 32, 4_096);
    validateContentDescriptor(document.config, new Set([
      "application/vnd.docker.container.image.v1+json",
      "application/vnd.oci.image.config.v1+json",
    ]), 16_777_216);
    if (document.config.digest !== selected.configDigest) throw new TypeError("graph config digest is invalid");
    const layers = [];
    const digests = new Set();
    for (const layer of document.layers) {
      validateContentDescriptor(layer, new Set([
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
      ]), 8_589_934_592);
      if (digests.has(layer.digest)) throw new TypeError("duplicate graph layer");
      digests.add(layer.digest);
      layers.push(structuredClone(layer));
    }
    return deepFreeze({
      config: structuredClone(document.config),
      layers,
      mediaType: document.mediaType,
      schemaVersion: 2,
    });
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("normalization");
  }
}

export function projectGraphImageInspection(document) {
  try {
    if (!Array.isArray(document) || document.length !== 14) throw new TypeError("graph image inspection is invalid");
    return deepFreeze(structuredClone(document));
  } catch {
    throw new GraphFailure("normalization");
  }
}

export function validateGraphImageInspection(document, selected, resolution, retained = undefined,
  aliases = undefined) {
  try {
    validateSelectedPlan(selected);
    if (!Array.isArray(document) || document.length !== 14 || !isPlainObject(resolution) ||
        resolution.index?.indexDigest !== selected.indexDigest ||
        resolution.index?.selected?.digest !== selected.manifestDigest ||
        resolution.manifest?.config?.digest !== selected.configDigest ||
        !Array.isArray(resolution.manifest?.layers) || resolution.manifest.layers.length < 1) {
      throw new TypeError("graph image evidence is invalid");
    }
    const [architecture, operatingSystem, configDigest, repoDigests, repoTags, rootfs, environment,
      entrypoint, command, exposedPorts, intrinsicVolumes, labels, user, workingDirectory] = document;
    const runtime = graphImageRuntimeFacts[selected.name]?.[selected.platform];
    const expectedAliases = aliases ?? { repoDigests: [selected.repoDigest], repoTags: [] };
    requireExactKeySet(expectedAliases, ["repoDigests", "repoTags"], "graph image aliases");
    if (!exactStringArray(expectedAliases.repoDigests, [selected.repoDigest]) ||
        !(exactStringArray(expectedAliases.repoTags, []) ||
          exactStringArray(expectedAliases.repoTags, [selected.tag]))) {
      throw new TypeError("graph image aliases are invalid");
    }
    if (architecture !== selected.architecture || operatingSystem !== "linux" || configDigest !== selected.configDigest ||
        !exactStringArray(repoDigests, expectedAliases.repoDigests) ||
        !exactStringArray(repoTags, expectedAliases.repoTags) ||
        !isPlainObject(rootfs) || !exactKeySet(rootfs, ["Layers", "Type"]) || rootfs.Type !== "layers" ||
        !Array.isArray(rootfs.Layers) || rootfs.Layers.length < 1 || rootfs.Layers.length > 256 ||
        new Set(rootfs.Layers).size !== rootfs.Layers.length || rootfs.Layers.some((value) => !digestPattern.test(value)) ||
        !validStringArray(environment, 256, 16_384) || !uniqueEnvironment(environment) ||
        environment.some((value) => forbiddenImageEnvironment.test(value.slice(0, value.indexOf("=")))) ||
        !nullableStringArray(entrypoint, 64, 4_096) || !nullableStringArray(command, 64, 4_096) ||
        !validEmptyObjectMap(exposedPorts, /^\d{1,5}\/tcp$/, 64) ||
        !validEmptyObjectMap(intrinsicVolumes, /^\/[\x20-\x7e]+$/, 64) ||
        !validNullableStringMap(labels, 256, 16_384) || typeof user !== "string" || user.length > 1_024 ||
        typeof workingDirectory !== "string" || workingDirectory.length > 4_096 || runtime === undefined ||
        !exactData(rootfs, runtime.rootfs) || !exactData(environment, runtime.environment) ||
        !exactData(entrypoint, runtime.entrypoint) || !exactData(command, runtime.command) ||
        !exactData(exposedPorts, runtime.exposedPorts) || !exactData(intrinsicVolumes, runtime.intrinsicVolumes) ||
        !exactData(labels, runtime.labels) || user !== runtime.user || workingDirectory !== runtime.workingDirectory) {
      throw new TypeError("graph image inspection is invalid");
    }
    const identity = deepFreeze({
      architecture,
      command: command === null ? null : [...command],
      configDigest,
      entrypoint: entrypoint === null ? null : [...entrypoint],
      environment: [...environment],
      exposedPorts: exposedPorts === null ? [] : Object.keys(exposedPorts).sort(),
      id: configDigest,
      index: structuredClone(resolution.index),
      indexDigest: selected.indexDigest,
      intrinsicVolumes: intrinsicVolumes === null ? [] : Object.keys(intrinsicVolumes).sort(),
      labels: labels === null ? null : structuredClone(labels),
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
    if (retained !== undefined && !exactData({
      ...identity,
      repoDigests: retained.repoDigests,
      repoTags: retained.repoTags,
    }, retained)) throw new TypeError("graph image identity changed");
    return identity;
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("ownership");
  }
}

export function parseGraphContainerdImageTargets(beforeSource, afterSource, selected) {
  try {
    validateSelectedPlan(selected);
    const before = parseGraphContainerdInventory(beforeSource);
    const after = parseGraphContainerdInventory(afterSource);
    for (const [reference, row] of before) {
      if (!exactData(after.get(reference), row)) throw new TypeError("graph containerd baseline changed");
    }
    const delta = [...after].filter(([reference]) => !before.has(reference)).map(([, row]) => row);
    if (delta.length !== 3) throw new TypeError("graph containerd delta is invalid");
    const target = graphArchiveContainerdTarget(delta, selected);
    validateGraphContainerdTarget(target, selected);
    return target;
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("provider");
  }
}

export function bindGraphContainerdWorkloadAlias(beforeSource, afterSource, target, selected) {
  try {
    validateSelectedPlan(selected);
    validateGraphContainerdTarget(target, selected);
    if (target.references.length !== 3) throw new TypeError("graph workload alias target is invalid");
    const before = parseGraphContainerdInventory(beforeSource);
    const after = parseGraphContainerdInventory(afterSource);
    for (const [reference, row] of before) {
      if (!exactData(after.get(reference), row)) throw new TypeError("graph workload alias baseline changed");
    }
    for (const row of target.references) {
      if (!exactData(before.get(row.reference), row)) throw new TypeError("graph workload alias authority changed");
    }
    const delta = [...after].filter(([reference]) => !before.has(reference)).map(([, row]) => row);
    const wrapper = target.references.find(({ mediaType }) =>
      mediaType === "application/vnd.oci.image.index.v1+json");
    const reference = graphWorkloadImageReference(selected);
    if (delta.length !== 1 || wrapper === undefined || delta[0].reference !== reference ||
        !exactData({ ...delta[0], reference: wrapper.reference }, wrapper)) {
      throw new TypeError("graph workload alias is invalid");
    }
    const bound = deepFreeze({
      ...target,
      imageID: reference,
      references: [...target.references, delta[0]],
    });
    validateGraphContainerdTarget(bound, selected);
    return bound;
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("provider");
  }
}

export function bindGraphContainerdRuntimeAlias(beforeSource, afterSource, target, selected) {
  try {
    validateSelectedPlan(selected);
    validateGraphContainerdTarget(target, selected);
    if (target.references.length !== 4) throw new TypeError("graph runtime alias target is invalid");
    const before = parseGraphContainerdInventory(beforeSource);
    const after = parseGraphContainerdInventory(afterSource);
    for (const [reference, row] of before) {
      if (!exactData(after.get(reference), row)) throw new TypeError("graph runtime alias baseline changed");
    }
    for (const row of target.references) {
      if (!exactData(before.get(row.reference), row)) throw new TypeError("graph runtime alias authority changed");
    }
    const delta = [...after].filter(([reference]) => !before.has(reference)).map(([, row]) => row);
    const runtime = target.references[0];
    const reference = runtime === undefined ? undefined : graphPublicImageReference(runtime.reference);
    if (delta.length !== 1 || runtime === undefined || delta[0].reference !== reference ||
        !exactData({ ...delta[0], reference: runtime.reference }, runtime)) {
      throw new TypeError("graph runtime alias is invalid");
    }
    const bound = deepFreeze({
      ...target,
      imageID: graphPublicImageReference(target.references[0].reference),
      references: [...target.references, delta[0]],
    });
    validateGraphContainerdTarget(bound, selected);
    return bound;
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("provider");
  }
}

function parseGraphContainerdInventory(source) {
  if (typeof source !== "string" || Buffer.byteLength(source) < 1 || Buffer.byteLength(source) > 4_194_304 ||
      !source.endsWith("\n")) throw new TypeError("graph containerd inventory is invalid");
  const lines = source.slice(0, -1).split("\n");
  if (lines.length > 4_097 ||
      !exactStringArray(lines[0]?.trim().split(/\s+/), ["REF", "TYPE", "DIGEST", "SIZE", "PLATFORMS", "LABELS"])) {
    throw new TypeError("graph containerd inventory is invalid");
  }
  const mediaTypes = new Set([
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
  ]);
  const inventory = new Map();
  for (const line of lines.slice(1)) {
    const padding = / +$/.exec(line)?.[0] ?? "";
    const row = padding.length > 0 && padding.length <= 33 ? line.slice(0, -padding.length) : line;
    if (line.length < 1 || line.length > 32_768 || row !== row.trim()) {
      throw new TypeError("graph containerd inventory is invalid");
    }
    const fields = row.split(/\s+/);
    const reference = fields[0];
    const mediaType = fields[1];
    const digest = fields[2];
    const size = `${fields[3]} ${fields[4]}`;
    const platform = fields[5];
    const labelFields = fields.slice(6);
    const labels = labelFields.join("");
    if (fields.length < 7 || labelFields.slice(0, -1).some((value) => !value.endsWith(",")) ||
        typeof reference !== "string" || reference.length > 1_024 ||
        !/^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/.test(reference) || inventory.has(reference) ||
        !mediaTypes.has(mediaType) || !digestPattern.test(digest ?? "") ||
        !/^\d+(?:\.\d+)? (?:B|KiB|MiB|GiB)$/.test(size) ||
        typeof platform !== "string" || platform.length > 8_192 ||
        !/^(?:-|[a-z0-9][a-z0-9._/-]*(?:,[a-z0-9][a-z0-9._/-]*)*)$/.test(platform) ||
        typeof labels !== "string" || labels.length > 16_384 || !/^[^\s]+$/.test(labels)) {
      throw new TypeError("graph containerd inventory is invalid");
    }
    inventory.set(reference, deepFreeze({ digest, labels, mediaType, platform, reference, size }));
  }
  return inventory;
}

function graphArchiveContainerdTarget(delta, selected) {
  const rawPattern = /^import-\d{4}-\d{2}-\d{2}@sha256:[0-9a-f]{64}$/;
  const raw = delta.filter(({ reference }) => rawPattern.test(reference));
  const aliases = delta.filter(({ reference }) => reference === selected.configDigest);
  const children = raw.filter(({ mediaType }) => mediaType === "application/vnd.oci.image.manifest.v1+json");
  const wrappers = raw.filter(({ mediaType }) => mediaType === "application/vnd.oci.image.index.v1+json");
  if (raw.length !== 2 || aliases.length !== 1 || children.length !== 1 || wrappers.length !== 1) {
    throw new TypeError("graph containerd archive structure is invalid");
  }
  const references = [...raw].sort((left, right) => lexicalCompare(
    graphPublicImageReference(left.reference), graphPublicImageReference(right.reference),
  ));
  return deepFreeze({
    imageID: graphPublicImageReference(references[0].reference),
    manifestDigest: selected.manifestDigest,
    references: [...references, aliases[0]],
  });
}

function validateGraphContainerdTarget(target, selected) {
  requireExactKeySet(target, ["imageID", "manifestDigest", "references"], "graph containerd target");
  if (target.manifestDigest !== selected.manifestDigest || !Array.isArray(target.references) ||
      !new Set([2, 3, 4, 5]).has(target.references.length)) throw new TypeError("graph containerd target is invalid");
  if (new Set([3, 4, 5]).has(target.references.length)) {
    validateGraphArchiveContainerdTarget(target, selected);
    return;
  }
  const dates = new Set();
  let child = 0;
  let wrapper = 0;
  for (const row of target.references) {
    requireExactKeySet(row, ["digest", "labels", "mediaType", "platform", "reference", "size"],
      "graph containerd reference");
    const match = /^import-(\d{4}-\d{2}-\d{2})@(sha256:[0-9a-f]{64})$/.exec(row.reference ?? "");
    if (match === null || !canonicalGraphDate(match[1]) || match[2] !== row.digest ||
        row.platform !== selected.platform || typeof row.labels !== "string" || row.labels.length < 1 ||
        row.labels.length > 16_384 || !/^\d+(?:\.\d+)? ?(?:B|KiB|MiB|GiB)$/.test(row.size ?? "")) {
      throw new TypeError("graph containerd reference is invalid");
    }
    dates.add(match[1]);
    if (row.digest === selected.manifestDigest && new Set([
      "application/vnd.docker.distribution.manifest.v2+json",
      "application/vnd.oci.image.manifest.v1+json",
    ]).has(row.mediaType)) child += 1;
    else if (row.mediaType === "application/vnd.oci.image.index.v1+json" &&
        !new Set([selected.configDigest, selected.indexDigest, selected.manifestDigest]).has(row.digest)) wrapper += 1;
    else throw new TypeError("graph containerd reference is invalid");
  }
  const ordered = [...target.references].sort((left, right) => lexicalCompare(
    graphPublicImageReference(left.reference), graphPublicImageReference(right.reference),
  ));
  if (dates.size !== 1 || child !== 1 || wrapper !== 1 || !exactData(target.references, ordered) ||
      target.imageID !== graphPublicImageReference(ordered[0].reference)) {
    throw new TypeError("graph containerd target is invalid");
  }
}

function validateGraphArchiveContainerdTarget(target, selected) {
  const references = target.references.slice(0, 2);
  const alias = target.references[2];
  const dates = new Set();
  for (const row of references) {
    requireExactKeySet(row, ["digest", "labels", "mediaType", "platform", "reference", "size"],
      "graph containerd reference");
    const match = /^import-(\d{4}-\d{2}-\d{2})@(sha256:[0-9a-f]{64})$/.exec(row.reference ?? "");
    if (match === null || !canonicalGraphDate(match[1]) || match[2] !== row.digest ||
        row.platform !== selected.platform || typeof row.labels !== "string" || row.labels.length < 1 ||
        row.labels.length > 16_384 || !/^\d+(?:\.\d+)? (?:B|KiB|MiB|GiB)$/.test(row.size ?? "")) {
      throw new TypeError("graph containerd archive reference is invalid");
    }
    dates.add(match[1]);
  }
  const children = references.filter(({ mediaType }) =>
    mediaType === "application/vnd.oci.image.manifest.v1+json");
  const wrappers = references.filter(({ mediaType }) =>
    mediaType === "application/vnd.oci.image.index.v1+json");
  const ordered = [...references].sort((left, right) => lexicalCompare(
    graphPublicImageReference(left.reference), graphPublicImageReference(right.reference),
  ));
  if (dates.size !== 1 || children.length !== 1 || wrappers.length !== 1 ||
      new Set([selected.configDigest, selected.indexDigest, selected.manifestDigest]).has(children[0].digest) ||
      new Set([selected.configDigest, selected.indexDigest, selected.manifestDigest, children[0].digest])
        .has(wrappers[0].digest) ||
      !exactData(references, ordered)) {
    throw new TypeError("graph containerd archive target is invalid");
  }
  requireExactKeySet(alias, ["digest", "labels", "mediaType", "platform", "reference", "size"],
    "graph containerd archive alias");
  if (alias.reference !== selected.configDigest || alias.digest !== children[0].digest ||
      alias.mediaType !== children[0].mediaType || alias.platform !== children[0].platform ||
      alias.labels !== children[0].labels || alias.size !== children[0].size) {
    throw new TypeError("graph containerd archive alias is invalid");
  }
  const workloadAlias = target.references[3];
  if (workloadAlias === undefined) {
    if (target.imageID !== graphPublicImageReference(ordered[0].reference)) {
      throw new TypeError("graph containerd archive target is invalid");
    }
    return;
  }
  requireExactKeySet(workloadAlias, ["digest", "labels", "mediaType", "platform", "reference", "size"],
    "graph containerd workload alias");
  if (workloadAlias.reference !== graphWorkloadImageReference(selected) ||
      !exactData({ ...workloadAlias, reference: wrappers[0].reference }, wrappers[0])) {
    throw new TypeError("graph containerd workload alias is invalid");
  }
  const runtimeAlias = target.references[4];
  if (runtimeAlias === undefined) {
    if (target.imageID !== workloadAlias.reference) throw new TypeError("graph containerd workload alias is invalid");
    return;
  }
  requireExactKeySet(runtimeAlias, ["digest", "labels", "mediaType", "platform", "reference", "size"],
    "graph containerd runtime alias");
  if (runtimeAlias.reference !== graphPublicImageReference(ordered[0].reference) ||
      !exactData({ ...runtimeAlias, reference: ordered[0].reference }, ordered[0]) ||
      target.imageID !== graphPublicImageReference(ordered[0].reference)) {
    throw new TypeError("graph containerd runtime alias is invalid");
  }
}

export function validateGraphContainerdImageContents(
  target, manifestSource, wrapperSource, selected, retained, resolution,
) {
  try {
    validateSelectedPlan(selected);
    validateGraphContainerdTarget(target, selected);
    if (target.references.length !== 3 || !isPlainObject(retained) || !isPlainObject(resolution) ||
        retained.id !== selected.configDigest || retained.configDigest !== selected.configDigest ||
        retained.indexDigest !== selected.indexDigest || retained.manifestDigest !== selected.manifestDigest ||
        retained.name !== selected.name || retained.platform !== selected.platform ||
        retained.reference !== selected.reference || !isPlainObject(retained.rootfs) ||
        retained.rootfs.Type !== "layers" || !Array.isArray(retained.rootfs.Layers) ||
        !exactData(retained.index, resolution.index) || !exactData(retained.manifest, resolution.manifest) ||
        resolution.index?.indexDigest !== selected.indexDigest ||
        resolution.index?.selected?.digest !== selected.manifestDigest ||
        resolution.manifest?.config?.digest !== selected.configDigest) {
      throw new TypeError("graph containerd content authority is invalid");
    }
    const child = target.references.find(({ mediaType, reference }) =>
      mediaType === "application/vnd.oci.image.manifest.v1+json" && reference.startsWith("import-"));
    const wrapper = target.references.find(({ mediaType }) =>
      mediaType === "application/vnd.oci.image.index.v1+json");
    if (child === undefined || wrapper === undefined ||
        `sha256:${createHash("sha256").update(manifestSource).digest("hex")}` !== child.digest ||
        `sha256:${createHash("sha256").update(wrapperSource).digest("hex")}` !== wrapper.digest) {
      throw new TypeError("graph containerd content digest is invalid");
    }
    const manifest = parseBoundedJson(manifestSource, graphProviderByteLimit);
    requireExactKeySet(manifest, ["config", "layers", "mediaType", "schemaVersion"],
      "graph containerd manifest");
    if (manifest.schemaVersion !== 2 || manifest.mediaType !== "application/vnd.oci.image.manifest.v1+json" ||
        !Array.isArray(manifest.layers) || manifest.layers.length !== retained.rootfs.Layers.length) {
      throw new TypeError("graph containerd manifest is invalid");
    }
    validateContentDescriptor(manifest.config,
      new Set(["application/vnd.oci.image.config.v1+json"]), 16_777_216);
    if (manifest.config.digest !== selected.configDigest ||
        manifest.config.size !== resolution.manifest.config.size) {
      throw new TypeError("graph containerd config is invalid");
    }
    let totalSize = 0;
    for (const [index, layer] of manifest.layers.entries()) {
      validateContentDescriptor(layer, new Set(["application/vnd.oci.image.layer.v1.tar"]), 8_589_934_592);
      if (layer.digest !== retained.rootfs.Layers[index]) {
        throw new TypeError("graph containerd layer is invalid");
      }
      totalSize += layer.size;
      if (!Number.isSafeInteger(totalSize) || totalSize > 1_099_511_627_776) {
        throw new TypeError("graph containerd layer size is invalid");
      }
    }
    const index = parseBoundedJson(wrapperSource, graphProviderByteLimit);
    requireExactKeySet(index, ["manifests", "mediaType", "schemaVersion"], "graph containerd index");
    if (index.schemaVersion !== 2 || index.mediaType !== "application/vnd.oci.image.index.v1+json" ||
        !Array.isArray(index.manifests) || index.manifests.length !== 1) {
      throw new TypeError("graph containerd index is invalid");
    }
    validateContentDescriptor(index.manifests[0],
      new Set(["application/vnd.oci.image.manifest.v1+json"]), graphProviderByteLimit);
    if (index.manifests[0].digest !== child.digest ||
        index.manifests[0].size !== Buffer.byteLength(manifestSource)) {
      throw new TypeError("graph containerd index edge is invalid");
    }
    return target;
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("provider");
  }
}

function graphPublicImageReference(reference) {
  if (!/^import-\d{4}-\d{2}-\d{2}@sha256:[0-9a-f]{64}$/.test(reference ?? "")) {
    throw new TypeError("graph containerd reference is invalid");
  }
  return `docker.io/library/${reference}`;
}

function graphWorkloadImageReference(selected) {
  const separator = selected.providerReference.indexOf("@");
  const tagged = selected.providerReference.slice(0, separator);
  const tagSeparator = tagged.lastIndexOf(":");
  const slash = tagged.lastIndexOf("/");
  if (separator < 1 || tagSeparator <= slash ||
      selected.providerReference.slice(separator + 1) !== selected.indexDigest) {
    throw new TypeError("graph workload reference is invalid");
  }
  return `${tagged.slice(0, tagSeparator)}@${selected.indexDigest}`;
}

function lexicalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function validateGraphNodeLabel(document, expected, retained = undefined, labeled = true) {
  try {
    requireExactKeySet(expected, ["name", "token"], "graph node expectation");
    if (typeof expected.name !== "string" || !/^zasp-m1-30[bcd]-[0-9a-f]{16}-control-plane$/.test(expected.name) ||
        !objectIdPattern.test(expected.token) || labeled !== null && typeof labeled !== "boolean" ||
        !isPlainObject(document) ||
        document.apiVersion !== "v1" || document.kind !== "Node" || !isPlainObject(document.metadata) ||
        document.metadata.name !== expected.name || !resourceVersionPattern.test(document.metadata.resourceVersion ?? "") ||
        !kubernetesUidPattern.test(document.metadata.uid ?? "") || !isPlainObject(document.metadata.labels) ||
        document.metadata.labels["kubernetes.io/hostname"] !== expected.name) {
      throw new TypeError("graph node label is invalid");
    }
    validateStringMap(document.metadata.labels, 128, 4_096);
    const actual = document.metadata.labels[GRAPH_CONSTANTS.nodeLabelKey];
    if (actual !== undefined && actual !== GRAPH_CONSTANTS.nodeLabelValue ||
        labeled === true && actual !== GRAPH_CONSTANTS.nodeLabelValue || labeled === false && actual !== undefined) {
      throw new TypeError("graph node label is invalid");
    }
    const identity = Object.freeze({
      labeled: actual === GRAPH_CONSTANTS.nodeLabelValue,
      name: expected.name,
      token: expected.token,
      uid: document.metadata.uid,
    });
    if (retained !== undefined && (retained.name !== identity.name || retained.token !== identity.token ||
        retained.uid !== identity.uid)) throw new TypeError("graph node changed");
    return identity;
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("ownership");
  }
}

export function validateGraphNodePath(source, node, retained = undefined) {
  try {
    if (!isPlainObject(node) || !objectIdPattern.test(node.token) || typeof source !== "string" ||
        Buffer.byteLength(source) > 16_384 || !source.endsWith("\n") || source.indexOf("\n") !== source.length - 1) {
      throw new TypeError("graph node path is invalid");
    }
    const fields = source.slice(0, -1).split("|");
    if (fields.length !== 7 || !/^\d+$/.test(fields[0]) || !/^\d+$/.test(fields[1]) ||
        fields[2] !== "directory" || fields[3] !== "7474" || fields[4] !== "7474" ||
        fields[5] !== "700" || fields[6] !== GRAPH_CONSTANTS.nodeDataPath) {
      throw new TypeError("graph node path is invalid");
    }
    const dev = Number(fields[0]);
    const ino = Number(fields[1]);
    if (!Number.isSafeInteger(dev) || dev < 1 || !Number.isSafeInteger(ino) || ino < 1) {
      throw new TypeError("graph node path is invalid");
    }
    const identity = Object.freeze({
      dev, gid: 7474, ino, mode: 700, nodeToken: node.token,
      path: GRAPH_CONSTANTS.nodeDataPath, uid: 7474,
    });
    if (retained !== undefined && !exactData(identity, retained)) throw new TypeError("graph node path changed");
    return identity;
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("ownership");
  }
}

export function parseGraphProviderList(source, label) {
  try {
    if (!new Set([
      "deployments", "endpointSlices", "ingresses", "jobs", "persistentVolumeClaims",
      "persistentVolumes", "pods", "replicaSets", "services",
    ]).has(label)) throw new TypeError("graph provider list label is invalid");
    const document = parseBoundedJson(source, graphProviderByteLimit);
    requireExactKeySet(document, ["apiVersion", "items", "kind", "metadata"], "graph provider list");
    requireExactKeySet(document.metadata, ["resourceVersion"], "graph provider list metadata");
    if (document.apiVersion !== "v1" || document.kind !== "List" ||
        document.metadata.resourceVersion !== "" || !Array.isArray(document.items) ||
        document.items.length > 128) throw new TypeError("graph provider list is invalid");
    return deepFreeze(structuredClone(document.items));
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("normalization");
  }
}

export function projectGraphProviderResources(items, label, proof) {
  if (proof === "m1-30b") return items;
  if (!new Set(["m1-30c", "m1-30d"]).has(proof) || !Array.isArray(items)) {
    throw new GraphFailure("readiness");
  }
  if (["deployments", "jobs", "pods", "replicaSets", "services"].includes(label)) {
    const excluded = proof === "m1-30d" ? new Set(["aws-emulator", "observability"]) : new Set(["observability"]);
    return items.filter((item) => !excluded.has(item?.metadata?.labels?.["app.kubernetes.io/component"]));
  }
  if (label === "endpointSlices") {
    const excluded = proof === "m1-30d" ? new Set(["localstack", "otel-collector"]) : new Set(["otel-collector"]);
    return items.filter((item) => !excluded.has(item?.metadata?.labels?.["kubernetes.io/service-name"]));
  }
  return items;
}

export function isObservabilityProviderRead(arguments_, proof) {
  if (!new Set(["m1-30c", "m1-30d"]).has(proof) || !Array.isArray(arguments_)) return false;
  const selector = new Map([
    ["deployment", "app.kubernetes.io/component=observability"],
    ["replicaset", "app.kubernetes.io/component=observability"],
    ["pod", "app.kubernetes.io/component=observability"],
    ["service", "app.kubernetes.io/component=observability"],
    ["endpointslice", "kubernetes.io/service-name=otel-collector"],
  ]).get(arguments_[1]);
  return selector !== undefined && exactStringArray(arguments_, [
    "get", arguments_[1], "--namespace", GRAPH_CONSTANTS.namespace,
    `--selector=${selector}`, "--output=json",
  ]);
}

export function validateGraphKubernetesState(value, expected, retained = undefined, requireReplacement = false,
  requireHealthReplacement = false) {
  try {
    requireExactKeySet(value, [
      "deployments", "endpointSlices", "healthLog", "ingresses", "jobs", "persistentVolumeClaims",
      "persistentVolumes", "pods", "replicaSets", "services",
    ], "graph Kubernetes state");
    requireExactKeySet(expected, ["imageTargets", "nodeName"], "graph Kubernetes expectation");
    requireExactKeySet(expected.imageTargets, ["busybox", "neo4j"], "graph image targets");
    const platform = platformForNode(expected);
    if (!/^zasp-m1-30[bcd]-[0-9a-f]{16}-control-plane$/.test(expected.nodeName ?? "") ||
        expected.imageTargets.busybox.manifestDigest !== GRAPH_IMAGE_PLANS.busybox.platforms[platform].manifestDigest ||
        expected.imageTargets.neo4j.manifestDigest !== GRAPH_IMAGE_PLANS.neo4j.platforms[platform].manifestDigest ||
        value.healthLog !== graphHealthLog || requireReplacement !== false && requireReplacement !== true ||
        requireHealthReplacement !== false && requireHealthReplacement !== true) {
      throw new TypeError("graph Kubernetes expectation is invalid");
    }
    for (const name of [
      "deployments", "endpointSlices", "ingresses", "jobs", "persistentVolumeClaims",
      "persistentVolumes", "pods", "replicaSets", "services",
    ]) if (!Array.isArray(value[name])) throw new TypeError("graph Kubernetes resource list is invalid");
    if (value.deployments.length !== PRODUCTS.length + 1 ||
        value.endpointSlices.length !== PRODUCTS.length + 1 || value.ingresses.length !== 0 ||
        value.jobs.length !== 1 || value.persistentVolumeClaims.length !== 1 ||
        value.persistentVolumes.length !== 1 || value.pods.length !== PRODUCTS.length + 2 ||
        value.replicaSets.length !== PRODUCTS.length + 1 || value.services.length !== PRODUCTS.length + 1) {
      throw new TypeError("graph Kubernetes resource count is invalid");
    }
    requireExactIdentities(value.deployments, [...PRODUCTS.map(({ name }) => name), "neo4j"],
      (item) => item?.metadata?.name);
    requireExactIdentities(value.replicaSets, [...PRODUCTS.map(({ name }) => name), "neo4j"],
      (item) => item?.metadata?.labels?.["app.kubernetes.io/name"]);
    requireExactIdentities(value.pods, [...PRODUCTS.map(({ name }) => name), "neo4j", "neo4j-health"],
      (item) => item?.metadata?.labels?.["app.kubernetes.io/name"]);
    requireExactIdentities(value.services, [...PRODUCTS.map(({ name }) => name), "neo4j"],
      (item) => item?.metadata?.name);
    requireExactIdentities(value.endpointSlices, [...PRODUCTS.map(({ name }) => name), "neo4j"],
      (item) => item?.metadata?.labels?.["kubernetes.io/service-name"]);

    const deployment = onlyMatch(value.deployments, (item) => item?.metadata?.name === "neo4j");
    const replicaSet = onlyMatch(value.replicaSets,
      (item) => item?.metadata?.labels?.["app.kubernetes.io/name"] === "neo4j");
    const pod = onlyMatch(value.pods,
      (item) => item?.metadata?.labels?.["app.kubernetes.io/name"] === "neo4j");
    const service = onlyMatch(value.services, (item) => item?.metadata?.name === "neo4j");
    const endpointSlice = onlyMatch(value.endpointSlices,
      (item) => item?.metadata?.labels?.["kubernetes.io/service-name"] === "neo4j");
    const persistentVolume = onlyMatch(value.persistentVolumes,
      (item) => item?.metadata?.name === GRAPH_CONSTANTS.persistentVolumeName);
    const persistentVolumeClaim = onlyMatch(value.persistentVolumeClaims,
      (item) => item?.metadata?.name === GRAPH_CONSTANTS.persistentVolumeClaimName);
    const job = onlyMatch(value.jobs, (item) => item?.metadata?.name === "neo4j-health");
    const healthPod = onlyMatch(value.pods,
      (item) => item?.metadata?.labels?.["app.kubernetes.io/name"] === "neo4j-health");

    validateGraphPersistentStorage(persistentVolume, persistentVolumeClaim);
    validateGraphDeployment(deployment);
    validateGraphReplicaSet(replicaSet, deployment);
    const neo4jPod = validateGraphPod(pod, replicaSet, persistentVolumeClaim, expected, "neo4j");
    validateGraphService(service);
    validateGraphEndpointSlice(endpointSlice, service, neo4jPod, expected.nodeName);
    validateGraphJob(job);
    validateGraphHealthPod(healthPod, job, expected);

    const snapshot = deepFreeze({
      health: {
        completionTime: job.status.completionTime,
        jobStartedAt: job.status.startTime,
        jobUid: job.metadata.uid,
        podFinishedAt: healthPod.status.containerStatuses[0].state.terminated.finishedAt,
        podName: healthPod.metadata.name,
        podStartedAt: healthPod.status.containerStatuses[0].state.terminated.startedAt,
        podUid: healthPod.metadata.uid,
      },
      internal: true,
      neo4j: {
        containerID: pod.status.containerStatuses[0].containerID,
        deploymentUid: deployment.metadata.uid,
        endpointSliceUid: endpointSlice.metadata.uid,
        persistentVolumeClaimUid: persistentVolumeClaim.metadata.uid,
        persistentVolumeUid: persistentVolume.metadata.uid,
        podIP: pod.status.podIP,
        podName: pod.metadata.name,
        podUid: pod.metadata.uid,
        replicaSetUid: replicaSet.metadata.uid,
        serviceUid: service.metadata.uid,
        startedAt: pod.status.containerStatuses[0].state.running.startedAt,
      },
      ready: true,
    });
    if (retained !== undefined) {
      validateRetainedGraphSnapshot(snapshot, retained, requireReplacement, requireHealthReplacement);
    }
    return snapshot;
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("readiness");
  }
}

function platformForNode(expected) {
  const targets = expected?.imageTargets;
  if (targets?.neo4j?.references?.length !== 5 || targets?.busybox?.references?.length !== 5) {
    throw new TypeError("graph image targets are incomplete");
  }
  for (const platform of ["linux/amd64", "linux/arm64"]) {
    try {
      validateGraphContainerdTarget(targets?.neo4j, buildGraphImagePlan("neo4j", platform));
      validateGraphContainerdTarget(targets?.busybox, buildGraphImagePlan("busybox", platform));
      return platform;
    } catch {
      // A different platform may still be the exact retained target pair.
    }
  }
  throw new TypeError("graph image targets are invalid");
}

function canonicalGraphDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  try {
    return new Date(`${value}T00:00:00.000Z`).toISOString().slice(0, 10) === value;
  } catch {
    return false;
  }
}

function onlyMatch(items, predicate) {
  const matches = items.filter(predicate);
  if (matches.length !== 1) throw new TypeError("graph resource identity is invalid");
  return matches[0];
}

function requireExactIdentities(items, expected, project) {
  const actual = items.map(project).sort();
  const selected = [...expected].sort();
  if (!exactData(actual, selected)) throw new TypeError("graph resource identities are invalid");
}

function graphManifestResource(kind, name) {
  const matches = buildGraphResources().filter((item) => item.kind === kind && item.metadata.name === name);
  if (matches.length !== 1) throw new TypeError("graph manifest resource is invalid");
  return matches[0];
}

function validateProviderMetadata(metadata, name, namespace = undefined) {
  if (!isPlainObject(metadata) || metadata.name !== name ||
      namespace !== undefined && metadata.namespace !== namespace ||
      !resourceVersionPattern.test(metadata.resourceVersion ?? "") ||
      !kubernetesUidPattern.test(metadata.uid ?? "")) throw new TypeError("graph metadata is invalid");
}

function exactControllerOwner(value, expected) {
  return exactData(value, [{
    apiVersion: expected.apiVersion,
    blockOwnerDeletion: true,
    controller: true,
    kind: expected.kind,
    name: expected.name,
    uid: expected.uid,
  }]);
}

function providerGraphContainer(container) {
  return {
    ...structuredClone(container),
    terminationMessagePath: "/dev/termination-log",
    terminationMessagePolicy: "File",
  };
}

function providerGraphTemplate(template, labels = template.metadata.labels) {
  return {
    metadata: { labels: structuredClone(labels) },
    spec: {
      ...structuredClone(template.spec),
      containers: template.spec.containers.map(providerGraphContainer),
      schedulerName: "default-scheduler",
    },
  };
}

function providerGraphPodSpec(template, nodeName) {
  return {
    automountServiceAccountToken: template.spec.automountServiceAccountToken,
    containers: template.spec.containers.map(providerGraphContainer),
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
    ...(template.spec.volumes === undefined ? {} : { volumes: structuredClone(template.spec.volumes) }),
  };
}

function normalizeProviderContainer(container) {
  const normalized = structuredClone(container);
  if (!isPlainObject(normalized) || !Array.isArray(normalized.volumeMounts)) return normalized;
  normalized.volumeMounts = normalized.volumeMounts.map((mount) => {
    if (!isPlainObject(mount) || Object.hasOwn(mount, "readOnly")) return mount;
    return { ...mount, readOnly: false };
  });
  return normalized;
}

function normalizeProviderPodSpec(spec) {
  const normalized = structuredClone(spec);
  if (!isPlainObject(normalized)) return normalized;
  if (Array.isArray(normalized.containers)) {
    normalized.containers = normalized.containers.map(normalizeProviderContainer);
  }
  if (Array.isArray(normalized.volumes)) {
    normalized.volumes = normalized.volumes.map((volume) => {
      if (!isPlainObject(volume) || !isPlainObject(volume.persistentVolumeClaim) ||
          Object.hasOwn(volume.persistentVolumeClaim, "readOnly")) return volume;
      return {
        ...volume,
        persistentVolumeClaim: { ...volume.persistentVolumeClaim, readOnly: false },
      };
    });
  }
  return normalized;
}

function normalizeProviderTemplate(template) {
  const normalized = structuredClone(template);
  requireExactKeySet(normalized, ["metadata", "spec"], "graph provider template");
  const metadataKeys = Object.hasOwn(normalized.metadata ?? {}, "creationTimestamp")
    ? ["creationTimestamp", "labels"] : ["labels"];
  requireExactKeySet(normalized.metadata, metadataKeys, "graph provider template metadata");
  if (normalized.metadata.creationTimestamp !== undefined && normalized.metadata.creationTimestamp !== null) {
    throw new TypeError("graph provider template timestamp is invalid");
  }
  return {
    metadata: { labels: normalized.metadata.labels },
    spec: normalizeProviderPodSpec(normalized.spec),
  };
}

function normalizeProviderServiceSpec(spec) {
  const normalized = structuredClone(spec);
  if (isPlainObject(normalized) && !Object.hasOwn(normalized, "externalIPs")) normalized.externalIPs = [];
  return normalized;
}

function normalizeProductProviderResult(result, resource, category, capture) {
  try {
    const label = new Map([
      ["deployment", "deployments"],
      ["endpointslice", "endpointSlices"],
      ["pod", "pods"],
      ["replicaset", "replicaSets"],
      ["service", "services"],
    ]).get(resource);
    if (label === undefined || !(capture instanceof Map)) {
      throw new TypeError("product provider capture is invalid");
    }
    const document = parseBoundedJson(result.stdout, graphProviderByteLimit);
    requireExactKeySet(document, ["apiVersion", "items", "kind", "metadata"], "product provider list");
    requireExactKeySet(document.metadata, ["resourceVersion"], "product provider list metadata");
    if (document.apiVersion !== "v1" || document.kind !== "List" ||
        document.metadata.resourceVersion !== "" || !Array.isArray(document.items) ||
        document.items.length > 128) throw new TypeError("product provider list is invalid");
    const retained = deepFreeze(structuredClone(document.items));
    if (resource === "deployment" || resource === "replicaset") {
      for (const item of document.items) {
        requireExactKeySet(item?.spec?.template, ["metadata", "spec"], "product provider template");
        const metadataKeys = Object.hasOwn(item.spec.template.metadata ?? {}, "creationTimestamp")
          ? ["creationTimestamp", "labels"] : ["labels"];
        requireExactKeySet(item.spec.template.metadata, metadataKeys, "product provider template metadata");
        if (item.spec.template.metadata.creationTimestamp !== undefined &&
            item.spec.template.metadata.creationTimestamp !== null) {
          throw new TypeError("product provider template timestamp is invalid");
        }
        item.spec.template.metadata = { labels: item.spec.template.metadata.labels };
      }
    }
    capture.set(label, retained);
    return Object.freeze({ ...result, stdout: `${JSON.stringify(document)}\n` });
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure(category);
  }
}

function validateCorrelatedProductProviderState(value, retained) {
  try {
    const keys = ["deployments", "endpointSlices", "pods", "replicaSets", "services"];
    requireExactKeySet(retained, keys, "retained product provider state");
    const names = PRODUCTS.map(({ name }) => name).sort();
    const identity = (label, item) => new Set(["deployments", "services"]).has(label)
      ? item?.metadata?.name
      : label === "endpointSlices"
        ? item?.metadata?.labels?.["kubernetes.io/service-name"]
        : item?.metadata?.labels?.["app.kubernetes.io/name"];
    for (const key of keys) {
      if (!Array.isArray(value[key]) || !Array.isArray(retained[key])) {
        throw new TypeError("product provider state is invalid");
      }
      const current = value[key].filter((item) => names.includes(identity(key, item)));
      requireExactIdentities(current, names, (item) => identity(key, item));
      requireExactIdentities(retained[key], names, (item) => identity(key, item));
      const ordered = (items) => [...items].sort((left, right) =>
        identity(key, left).localeCompare(identity(key, right)));
      if (!exactData(ordered(current), ordered(retained[key]))) {
        throw new TypeError("product provider state changed during graph polling");
      }
    }
    return true;
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("readiness");
  }
}

function projectGraphContainerStatus(status) {
  if (!isPlainObject(status) || !exactData(status.lastState, {})) {
    throw new TypeError("graph container status is invalid");
  }
  return {
    containerID: status.containerID,
    image: status.image,
    imageID: status.imageID,
    name: status.name,
    ready: status.ready,
    restartCount: status.restartCount,
    started: status.started,
    state: status.state,
  };
}

function validateGraphPersistentStorage(persistentVolume, persistentVolumeClaim) {
  const expectedVolume = graphManifestResource("PersistentVolume", GRAPH_CONSTANTS.persistentVolumeName);
  const expectedClaim = graphManifestResource("PersistentVolumeClaim", GRAPH_CONSTANTS.persistentVolumeClaimName);
  requireExactKeySet(persistentVolume, ["apiVersion", "kind", "metadata", "spec", "status"], "graph PV");
  requireExactKeySet(persistentVolumeClaim, ["apiVersion", "kind", "metadata", "spec", "status"], "graph PVC");
  validateProviderMetadata(persistentVolume.metadata, GRAPH_CONSTANTS.persistentVolumeName);
  validateProviderMetadata(persistentVolumeClaim.metadata, GRAPH_CONSTANTS.persistentVolumeClaimName,
    GRAPH_CONSTANTS.namespace);
  requireExactKeySet(persistentVolume.spec?.claimRef,
    ["apiVersion", "kind", "name", "namespace", "resourceVersion", "uid"], "graph PV claim reference");
  requireExactKeySet(persistentVolume.status, ["lastPhaseTransitionTime", "phase"], "graph PV status");
  requireExactKeySet(persistentVolumeClaim.status, ["accessModes", "capacity", "phase"], "graph PVC status");
  if (persistentVolume.apiVersion !== "v1" || persistentVolume.kind !== "PersistentVolume" ||
      persistentVolumeClaim.apiVersion !== "v1" || persistentVolumeClaim.kind !== "PersistentVolumeClaim" ||
      !exactData(persistentVolume.metadata.labels, expectedVolume.metadata.labels) ||
      !exactData(persistentVolumeClaim.metadata.labels, expectedClaim.metadata.labels) ||
      !exactData(persistentVolumeClaim.spec, expectedClaim.spec) ||
      !resourceVersionPattern.test(persistentVolume.spec.claimRef.resourceVersion ?? "") ||
      persistentVolume.spec.claimRef.resourceVersion === persistentVolumeClaim.metadata.resourceVersion ||
      !exactData(persistentVolume.spec, {
        ...expectedVolume.spec,
        claimRef: {
          ...expectedVolume.spec.claimRef,
          resourceVersion: persistentVolume.spec.claimRef.resourceVersion,
          uid: persistentVolumeClaim.metadata.uid,
        },
      }) || persistentVolume.status.phase !== "Bound" ||
      !canonicalGraphSecond(persistentVolume.status.lastPhaseTransitionTime) ||
      persistentVolumeClaim.status.phase !== "Bound" ||
      !exactData(persistentVolumeClaim.status.accessModes, ["ReadWriteOnce"]) ||
      !exactData(persistentVolumeClaim.status.capacity, { storage: "1Gi" })) {
    throw new TypeError("graph persistent storage is invalid");
  }
}

function validateGraphDeployment(deployment) {
  const expected = graphManifestResource("Deployment", "neo4j");
  requireExactKeySet(deployment, ["apiVersion", "kind", "metadata", "spec", "status"], "graph deployment");
  validateProviderMetadata(deployment.metadata, "neo4j", GRAPH_CONSTANTS.namespace);
  if (deployment.apiVersion !== "apps/v1" || deployment.kind !== "Deployment" ||
      !Number.isSafeInteger(deployment.metadata.generation) || deployment.metadata.generation < 1 ||
      !exactData(deployment.metadata.labels, expected.metadata.labels) || !exactData({
        ...structuredClone(deployment.spec),
        template: normalizeProviderTemplate(deployment.spec?.template),
      }, {
        ...expected.spec,
        template: providerGraphTemplate(expected.spec.template),
      }) || deployment.status?.observedGeneration !== deployment.metadata.generation ||
      deployment.status?.replicas !== 1 || deployment.status?.updatedReplicas !== 1 ||
      deployment.status?.readyReplicas !== 1 || deployment.status?.availableReplicas !== 1 ||
      (deployment.status?.unavailableReplicas ?? 0) !== 0 ||
      !exactCondition(deployment.status?.conditions, "Available", "True")) {
    throw new TypeError("graph deployment is not ready");
  }
}

function validateGraphReplicaSet(replicaSet, deployment) {
  const expected = graphManifestResource("Deployment", "neo4j");
  requireExactKeySet(replicaSet, ["apiVersion", "kind", "metadata", "spec", "status"], "graph replica set");
  const hash = replicaSet?.metadata?.labels?.["pod-template-hash"];
  validateProviderMetadata(replicaSet.metadata, `neo4j-${hash}`, GRAPH_CONSTANTS.namespace);
  const labels = { ...expected.metadata.labels, "pod-template-hash": hash };
  if (replicaSet.apiVersion !== "apps/v1" || replicaSet.kind !== "ReplicaSet" ||
      !/^[a-z0-9]{10}$/.test(hash ?? "") || !exactData(replicaSet.metadata.labels, labels) ||
      !exactControllerOwner(replicaSet.metadata.ownerReferences, {
        apiVersion: "apps/v1", kind: "Deployment", name: "neo4j", uid: deployment.metadata.uid,
      }) || !exactData({
        ...structuredClone(replicaSet.spec),
        template: normalizeProviderTemplate(replicaSet.spec?.template),
      }, {
        replicas: 1,
        selector: { matchLabels: { "app.kubernetes.io/name": "neo4j", "pod-template-hash": hash } },
        template: providerGraphTemplate(expected.spec.template, labels),
      }) || replicaSet.status?.observedGeneration !== 1 || replicaSet.status?.replicas !== 1 ||
      replicaSet.status?.readyReplicas !== 1 || replicaSet.status?.availableReplicas !== 1 ||
      replicaSet.status?.fullyLabeledReplicas !== 1) throw new TypeError("graph replica set is not ready");
}

function validateGraphPod(pod, replicaSet, persistentVolumeClaim, expected, name) {
  const deployment = graphManifestResource("Deployment", "neo4j");
  requireExactKeySet(pod, ["apiVersion", "kind", "metadata", "spec", "status"], "graph pod");
  const hash = replicaSet.metadata.labels["pod-template-hash"];
  const podName = new RegExp(`^neo4j-${hash}-[a-z0-9]{5}$`).exec(pod?.metadata?.name ?? "");
  validateProviderMetadata(pod.metadata, pod.metadata?.name, GRAPH_CONSTANTS.namespace);
  const labels = { ...deployment.metadata.labels, "pod-template-hash": hash };
  if (name !== "neo4j" || podName === null || pod.apiVersion !== "v1" || pod.kind !== "Pod" ||
      !exactData(pod.metadata.labels, labels) || !exactControllerOwner(pod.metadata.ownerReferences, {
        apiVersion: "apps/v1", kind: "ReplicaSet", name: replicaSet.metadata.name, uid: replicaSet.metadata.uid,
      }) || !exactData(normalizeProviderPodSpec(pod.spec),
        providerGraphPodSpec(deployment.spec.template, expected.nodeName)) ||
      pod.spec.volumes?.[0]?.persistentVolumeClaim?.claimName !== persistentVolumeClaim.metadata.name ||
      pod.status?.phase !== "Running" || !exactCondition(pod.status?.conditions, "Ready", "True") ||
      !Array.isArray(pod.status?.containerStatuses) || pod.status.containerStatuses.length !== 1 ||
      !validClusterIP(pod.status.podIP)) throw new TypeError("graph pod is not ready");
  const status = projectGraphContainerStatus(pod.status.containerStatuses[0]);
  const selected = GRAPH_IMAGE_PLANS.neo4j.platforms[platformForNode(expected)];
  if (!exactData(Object.keys(status).sort(), [
    "containerID", "image", "imageID", "name", "ready", "restartCount", "started", "state",
  ].sort()) || status.name !== "neo4j" || status.image !== selected.configDigest ||
      status.imageID !== expected.imageTargets.neo4j.imageID || status.ready !== true ||
      status.started !== true || status.restartCount !== 0 || !/^containerd:\/\/[0-9a-f]{64}$/.test(status.containerID) ||
      !isPlainObject(status.state) || !exactKeySet(status.state, ["running"]) ||
      !isPlainObject(status.state.running) || !exactKeySet(status.state.running, ["startedAt"]) ||
      !canonicalGraphSecond(status.state.running.startedAt)) throw new TypeError("graph container is not ready");
  return pod;
}

function validateGraphService(service) {
  const expected = graphManifestResource("Service", "neo4j");
  requireExactKeySet(service, ["apiVersion", "kind", "metadata", "spec", "status"], "graph service");
  validateProviderMetadata(service.metadata, "neo4j", GRAPH_CONSTANTS.namespace);
  const spec = normalizeProviderServiceSpec(service.spec);
  requireExactKeySet(spec, [
    "clusterIP", "clusterIPs", "externalIPs", "internalTrafficPolicy", "ipFamilies", "ipFamilyPolicy",
    "ports", "selector", "sessionAffinity", "type",
  ], "graph service spec");
  const ip = spec.clusterIP;
  if (service.apiVersion !== "v1" || service.kind !== "Service" ||
      !exactData(service.metadata.labels, expected.metadata.labels) || !validClusterIP(ip) ||
      !exactData(spec.clusterIPs, [ip]) || !exactData(spec.externalIPs, []) ||
      spec.internalTrafficPolicy !== "Cluster" || !exactData(spec.ipFamilies, ["IPv4"]) ||
      spec.ipFamilyPolicy !== "SingleStack" || !exactData(spec.ports, expected.spec.ports) ||
      !exactData(spec.selector, expected.spec.selector) || spec.sessionAffinity !== "None" ||
      spec.type !== "ClusterIP" || !exactData(service.status, { loadBalancer: {} })) {
    throw new TypeError("graph service is not internal");
  }
}

function exactGraphEndpointPorts(value) {
  const http = { name: "http", port: 7474, protocol: "TCP" };
  const bolt = { name: "bolt", port: 7687, protocol: "TCP" };
  return exactData(value, [http, bolt]) || exactData(value, [bolt, http]);
}

function validateGraphEndpointSlice(endpointSlice, service, pod, nodeName) {
  requireExactKeySet(endpointSlice, ["addressType", "apiVersion", "endpoints", "kind", "metadata", "ports"],
    "graph endpoint slice");
  validateProviderMetadata(endpointSlice.metadata, endpointSlice.metadata?.name, GRAPH_CONSTANTS.namespace);
  if (endpointSlice.addressType !== "IPv4" || endpointSlice.apiVersion !== "discovery.k8s.io/v1" ||
      endpointSlice.kind !== "EndpointSlice" || !/^neo4j-[a-z0-9]{5}$/.test(endpointSlice.metadata.name ?? "") ||
      endpointSlice.metadata.labels?.["endpointslice.kubernetes.io/managed-by"] !==
        "endpointslice-controller.k8s.io" ||
      endpointSlice.metadata.labels?.["kubernetes.io/service-name"] !== "neo4j" ||
      !exactControllerOwner(endpointSlice.metadata.ownerReferences, {
        apiVersion: "v1", kind: "Service", name: "neo4j", uid: service.metadata.uid,
      }) || !exactGraphEndpointPorts(endpointSlice.ports) || !exactData(endpointSlice.endpoints, [{
        addresses: [pod.status.podIP],
        conditions: { ready: true, serving: true, terminating: false },
        nodeName,
        targetRef: {
          kind: "Pod", name: pod.metadata.name, namespace: GRAPH_CONSTANTS.namespace, uid: pod.metadata.uid,
        },
      }])) throw new TypeError("graph endpoint slice is invalid");
}

function validateGraphEndpointSliceWithoutPod(endpointSlice, service) {
  requireExactKeySet(endpointSlice, ["addressType", "apiVersion", "endpoints", "kind", "metadata", "ports"],
    "graph endpoint slice");
  validateProviderMetadata(endpointSlice.metadata, endpointSlice.metadata?.name, GRAPH_CONSTANTS.namespace);
  if (endpointSlice.addressType !== "IPv4" || endpointSlice.apiVersion !== "discovery.k8s.io/v1" ||
      endpointSlice.kind !== "EndpointSlice" || !/^neo4j-[a-z0-9]{5}$/.test(endpointSlice.metadata.name ?? "") ||
      !exactData(endpointSlice.metadata.labels, {
        "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
        "kubernetes.io/service-name": "neo4j",
      }) || !exactControllerOwner(endpointSlice.metadata.ownerReferences, {
        apiVersion: "v1", kind: "Service", name: "neo4j", uid: service.metadata.uid,
      }) || !exactGraphEndpointPorts(endpointSlice.ports) ||
      !exactData(endpointSlice.endpoints, [])) throw new TypeError("graph endpoint slice is invalid");
}

function validateGraphJob(job) {
  const expected = graphManifestResource("Job", "neo4j-health");
  requireExactKeySet(job, ["apiVersion", "kind", "metadata", "spec", "status"], "graph health job");
  validateProviderMetadata(job.metadata, "neo4j-health", GRAPH_CONSTANTS.namespace);
  const labels = {
    ...expected.spec.template.metadata.labels,
    "batch.kubernetes.io/controller-uid": job.metadata.uid,
    "batch.kubernetes.io/job-name": "neo4j-health",
    "controller-uid": job.metadata.uid,
    "job-name": "neo4j-health",
  };
  if (job.apiVersion !== "batch/v1" || job.kind !== "Job" ||
      !exactData(job.metadata.labels, expected.metadata.labels) ||
      job.spec?.activeDeadlineSeconds !== expected.spec.activeDeadlineSeconds ||
      job.spec?.backoffLimit !== expected.spec.backoffLimit || job.spec?.completionMode !== "NonIndexed" ||
      job.spec?.completions !== 1 ||
      job.spec?.manualSelector !== false || job.spec?.parallelism !== 1 || job.spec?.suspend !== false ||
      !exactData(job.spec?.selector, {
        matchLabels: { "batch.kubernetes.io/controller-uid": job.metadata.uid },
      }) || !exactData(normalizeProviderTemplate(job.spec?.template),
        providerGraphTemplate(expected.spec.template, labels)) ||
      job.status?.succeeded !== 1 || (job.status?.failed ?? 0) !== 0 || (job.status?.ready ?? 0) !== 0 ||
      !canonicalGraphSecond(job.status?.startTime) || !canonicalGraphSecond(job.status?.completionTime) ||
      job.status.completionTime < job.status.startTime || !exactTimedCondition(job.status?.conditions, "Complete")) {
    throw new TypeError("graph health job is not complete");
  }
}

function validateGraphHealthPod(pod, job, expected) {
  const resource = graphManifestResource("Job", "neo4j-health");
  requireExactKeySet(pod, ["apiVersion", "kind", "metadata", "spec", "status"], "graph health pod");
  validateProviderMetadata(pod.metadata, pod.metadata?.name, GRAPH_CONSTANTS.namespace);
  const labels = {
    ...resource.spec.template.metadata.labels,
    "batch.kubernetes.io/controller-uid": job.metadata.uid,
    "batch.kubernetes.io/job-name": "neo4j-health",
    "controller-uid": job.metadata.uid,
    "job-name": "neo4j-health",
  };
  if (!/^neo4j-health-[a-z0-9]{5}$/.test(pod.metadata.name ?? "") || pod.apiVersion !== "v1" ||
      pod.kind !== "Pod" || !exactData(pod.metadata.labels, labels) ||
      !exactControllerOwner(pod.metadata.ownerReferences, {
        apiVersion: "batch/v1", kind: "Job", name: "neo4j-health", uid: job.metadata.uid,
      }) || !exactData(normalizeProviderPodSpec(pod.spec),
        providerGraphPodSpec(resource.spec.template, expected.nodeName)) ||
      pod.status?.phase !== "Succeeded" || !exactCondition(pod.status?.conditions, "Ready", "False") ||
      !validClusterIP(pod.status?.podIP) || !Array.isArray(pod.status?.containerStatuses) ||
      pod.status.containerStatuses.length !== 1) throw new TypeError("graph health pod is invalid");
  const status = projectGraphContainerStatus(pod.status.containerStatuses[0]);
  const terminated = status?.state?.terminated;
  if (!exactData(Object.keys(status ?? {}).sort(), [
    "containerID", "image", "imageID", "name", "ready", "restartCount", "started", "state",
  ].sort()) || status.name !== "health" ||
      status.image !== GRAPH_IMAGE_PLANS.busybox.platforms[platformForNode(expected)].configDigest ||
      status.imageID !== expected.imageTargets.busybox.imageID ||
      status.ready !== false || status.started !== false || status.restartCount !== 0 ||
      !/^containerd:\/\/[0-9a-f]{64}$/.test(status.containerID ?? "") || !isPlainObject(terminated) ||
      !exactKeySet(terminated, ["containerID", "exitCode", "finishedAt", "reason", "startedAt"]) ||
      terminated.containerID !== status.containerID || terminated.exitCode !== 0 || terminated.reason !== "Completed" ||
      !canonicalGraphSecond(terminated.startedAt) || !canonicalGraphSecond(terminated.finishedAt) ||
      terminated.finishedAt < terminated.startedAt) throw new TypeError("graph health container is invalid");
}

function exactCondition(value, type, status) {
  const selected = Array.isArray(value) ? value.filter((item) => item?.type === type) : [];
  return selected.length === 1 && selected[0]?.status === status;
}

function exactTimedCondition(value, type) {
  const selected = Array.isArray(value) ? value.filter((item) => item?.type === type) : [];
  return selected.length === 1 && selected[0]?.status === "True" &&
    canonicalGraphSecond(selected[0]?.lastProbeTime) && canonicalGraphSecond(selected[0]?.lastTransitionTime);
}

function canonicalGraphSecond(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) &&
    new Date(value).toISOString() === value.replace("Z", ".000Z");
}

function graphProviderAbsenceIdentity(absent, retained) {
  if (!new Set(["health", "neo4j"]).has(absent) || !isPlainObject(retained)) {
    throw new GraphFailure("ownership");
  }
  return deepFreeze({ absent, retained });
}

function validateGraphProviderAbsence(value, expected, retained, absent) {
  try {
    if (!new Set(["health", "neo4j"]).has(absent)) throw new TypeError("graph absence is invalid");
    requireExactKeySet(value, [
      "deployments", "endpointSlices", "healthLog", "ingresses", "jobs", "persistentVolumeClaims",
      "persistentVolumes", "pods", "replicaSets", "services",
    ], "graph Kubernetes state");
    requireExactKeySet(expected, ["imageTargets", "nodeName"], "graph Kubernetes expectation");
    requireExactKeySet(expected.imageTargets, ["busybox", "neo4j"], "graph image targets");
    platformForNode(expected);
    requireExactKeySet(retained, ["health", "internal", "neo4j", "ready"], "retained graph snapshot");
    requireExactKeySet(retained.health, [
      "completionTime", "jobStartedAt", "jobUid", "podFinishedAt", "podName", "podStartedAt", "podUid",
    ], "retained graph health");
    requireExactKeySet(retained.neo4j, [
      "containerID", "deploymentUid", "endpointSliceUid", "persistentVolumeClaimUid", "persistentVolumeUid",
      "podIP", "podName", "podUid", "replicaSetUid", "serviceUid", "startedAt",
    ], "retained graph pod");
    for (const name of [
      "deployments", "endpointSlices", "ingresses", "jobs", "persistentVolumeClaims",
      "persistentVolumes", "pods", "replicaSets", "services",
    ]) if (!Array.isArray(value[name])) throw new TypeError("graph Kubernetes resource list is invalid");
    const missingHealth = absent === "health";
    if (value.deployments.length !== PRODUCTS.length + 1 ||
        value.endpointSlices.length !== PRODUCTS.length + 1 || value.ingresses.length !== 0 ||
        value.jobs.length !== (missingHealth ? 0 : 1) || value.persistentVolumeClaims.length !== 1 ||
        value.persistentVolumes.length !== 1 || value.pods.length !== PRODUCTS.length + 1 ||
        value.replicaSets.length !== PRODUCTS.length + 1 || value.services.length !== PRODUCTS.length + 1 ||
        value.healthLog !== (missingHealth ? null : graphHealthLog)) {
      throw new TypeError("graph Kubernetes resource count is invalid");
    }
    requireExactIdentities(value.deployments, [...PRODUCTS.map(({ name }) => name), "neo4j"],
      (item) => item?.metadata?.name);
    requireExactIdentities(value.replicaSets, [...PRODUCTS.map(({ name }) => name), "neo4j"],
      (item) => item?.metadata?.labels?.["app.kubernetes.io/name"]);
    requireExactIdentities(value.pods, [
      ...PRODUCTS.map(({ name }) => name), missingHealth ? "neo4j" : "neo4j-health",
    ], (item) => item?.metadata?.labels?.["app.kubernetes.io/name"]);
    requireExactIdentities(value.services, [...PRODUCTS.map(({ name }) => name), "neo4j"],
      (item) => item?.metadata?.name);
    requireExactIdentities(value.endpointSlices, [...PRODUCTS.map(({ name }) => name), "neo4j"],
      (item) => item?.metadata?.labels?.["kubernetes.io/service-name"]);

    const deployment = onlyMatch(value.deployments, (item) => item?.metadata?.name === "neo4j");
    const replicaSet = onlyMatch(value.replicaSets,
      (item) => item?.metadata?.labels?.["app.kubernetes.io/name"] === "neo4j");
    const service = onlyMatch(value.services, (item) => item?.metadata?.name === "neo4j");
    const endpointSlice = onlyMatch(value.endpointSlices,
      (item) => item?.metadata?.labels?.["kubernetes.io/service-name"] === "neo4j");
    const persistentVolume = onlyMatch(value.persistentVolumes,
      (item) => item?.metadata?.name === GRAPH_CONSTANTS.persistentVolumeName);
    const persistentVolumeClaim = onlyMatch(value.persistentVolumeClaims,
      (item) => item?.metadata?.name === GRAPH_CONSTANTS.persistentVolumeClaimName);
    validateGraphPersistentStorage(persistentVolume, persistentVolumeClaim);
    validateGraphDeployment(deployment);
    validateGraphReplicaSet(replicaSet, deployment);
    validateGraphService(service);
    const stable = {
      deploymentUid: deployment.metadata.uid,
      endpointSliceUid: endpointSlice.metadata.uid,
      persistentVolumeClaimUid: persistentVolumeClaim.metadata.uid,
      persistentVolumeUid: persistentVolume.metadata.uid,
      replicaSetUid: replicaSet.metadata.uid,
      serviceUid: service.metadata.uid,
    };
    if (Object.entries(stable).some(([key, identity]) => identity !== retained.neo4j[key])) {
      throw new TypeError("graph stable identity changed");
    }
    if (missingHealth) {
      const pod = onlyMatch(value.pods,
        (item) => item?.metadata?.labels?.["app.kubernetes.io/name"] === "neo4j");
      const neo4jPod = validateGraphPod(pod, replicaSet, persistentVolumeClaim, expected, "neo4j");
      validateGraphEndpointSlice(endpointSlice, service, neo4jPod, expected.nodeName);
      const current = {
        containerID: pod.status.containerStatuses[0].containerID,
        ...stable,
        podIP: pod.status.podIP,
        podName: pod.metadata.name,
        podUid: pod.metadata.uid,
        startedAt: pod.status.containerStatuses[0].state.running.startedAt,
      };
      if (!exactData(current, retained.neo4j)) throw new TypeError("graph pod identity changed");
    } else {
      validateGraphEndpointSliceWithoutPod(endpointSlice, service);
      const job = onlyMatch(value.jobs, (item) => item?.metadata?.name === "neo4j-health");
      const healthPod = onlyMatch(value.pods,
        (item) => item?.metadata?.labels?.["app.kubernetes.io/name"] === "neo4j-health");
      validateGraphJob(job);
      validateGraphHealthPod(healthPod, job, expected);
      const health = {
        completionTime: job.status.completionTime,
        jobStartedAt: job.status.startTime,
        jobUid: job.metadata.uid,
        podFinishedAt: healthPod.status.containerStatuses[0].state.terminated.finishedAt,
        podName: healthPod.metadata.name,
        podStartedAt: healthPod.status.containerStatuses[0].state.terminated.startedAt,
        podUid: healthPod.metadata.uid,
      };
      if (!exactData(health, retained.health)) throw new TypeError("graph health identity changed");
    }
    return true;
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("readiness");
  }
}

function validClusterIP(value) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value ?? "");
  return match !== null && match.slice(1).every((part) => Number(part) <= 255) && value.startsWith("10.");
}

function validateRetainedGraphSnapshot(snapshot, retained, requireReplacement, requireHealthReplacement) {
  requireExactKeySet(retained, ["health", "internal", "neo4j", "ready"], "retained graph snapshot");
  requireExactKeySet(retained.health, [
    "completionTime", "jobStartedAt", "jobUid", "podFinishedAt", "podName", "podStartedAt", "podUid",
  ], "retained graph health");
  requireExactKeySet(retained.neo4j, [
    "containerID", "deploymentUid", "endpointSliceUid", "persistentVolumeClaimUid", "persistentVolumeUid",
    "podIP", "podName", "podUid", "replicaSetUid", "serviceUid", "startedAt",
  ], "retained graph pod");
  const stable = [
    "deploymentUid", "endpointSliceUid", "persistentVolumeClaimUid", "persistentVolumeUid",
    "replicaSetUid", "serviceUid",
  ];
  if (snapshot.internal !== true || retained.internal !== true ||
      snapshot.ready !== true || retained.ready !== true ||
      stable.some((key) => snapshot.neo4j[key] !== retained.neo4j[key])) throw new GraphFailure("ownership");
  if (requireReplacement) {
    if (snapshot.neo4j.podUid === retained.neo4j.podUid || snapshot.neo4j.podName === retained.neo4j.podName ||
        snapshot.neo4j.containerID === retained.neo4j.containerID ||
        snapshot.neo4j.startedAt <= retained.neo4j.startedAt) throw new GraphFailure("readiness");
  } else if (!exactData(snapshot.neo4j, retained.neo4j)) {
    throw new GraphFailure("ownership");
  }
  if (requireHealthReplacement) {
    if (requireReplacement || snapshot.health.jobUid === retained.health.jobUid ||
        snapshot.health.podUid === retained.health.podUid ||
        snapshot.health.podName === retained.health.podName ||
        snapshot.health.jobStartedAt <= snapshot.neo4j.startedAt ||
        snapshot.health.podStartedAt <= snapshot.neo4j.startedAt ||
        snapshot.health.podFinishedAt <= snapshot.neo4j.startedAt ||
        snapshot.health.completionTime <= snapshot.neo4j.startedAt) throw new GraphFailure("readiness");
  } else if (!exactData(snapshot.health, retained.health)) {
    throw new GraphFailure("ownership");
  }
}

export class LocalGraphSystem extends LocalProductSystem {
  constructor(input, dependencies = undefined, profile = undefined) {
    super(input, dependencies, profile ?? {
      manifests: [{
        bytes: renderGraphManifest(buildGraphResources()),
        name: "graph.yaml",
        pathKey: "graphManifest",
      }],
      proof: "m1-30b",
    });
    this.graphImagePlans = new Map(["neo4j", "busybox"].map((name) => [
      name, buildGraphImagePlan(name, input.nodePlatform),
    ]));
    this.graphImageResolutions = new Map();
    this.graphImageIdentities = new Map();
    this.graphImageAliases = new Map();
    this.graphSharedImageBaselines = new Map();
    this.graphImageBaselineAbsences = new Set();
    this.graphLoadedImageTargets = new Map();
    this.graphNodeImageInventory = undefined;
    this.graphImageMayHaveApplied = new Set();
    this.graphGoToolIdentity = undefined;
    this.graphNodeIdentity = undefined;
    this.graphPathIdentity = undefined;
    this.graphNodeMayHaveApplied = false;
    this.graphPathMayHaveApplied = false;
    this.graphProviderIdentity = undefined;
    this.graphMarkerMayHaveApplied = false;
    this.graphPodDeleteMayHaveApplied = false;
    this.graphHealthDeleteMayHaveApplied = false;
    this.graphHealthApplyMayHaveApplied = false;
    this.graphProviderAbsenceIdentity = undefined;
    this.productProviderCapture = undefined;
    this.productProviderProjection = false;
    this.productProviderSnapshot = undefined;
    this.productReadinessOnly = false;
  }

  async verifyReadiness(phase) {
    const previous = this.productProviderProjection;
    const previousCapture = this.productProviderCapture;
    const capture = new Map();
    this.productProviderCapture = capture;
    this.productProviderProjection = true;
    try {
      const result = await super.verifyReadiness(phase);
      const keys = ["deployments", "endpointSlices", "pods", "replicaSets", "services"];
      if (capture.size !== keys.length || keys.some((key) =>
        !Array.isArray(capture.get(key)) || capture.get(key).length !== PRODUCTS.length)) {
        throw new GraphFailure("readiness");
      }
      this.productProviderSnapshot = deepFreeze(Object.fromEntries(
        keys.map((key) => [key, capture.get(key)]),
      ));
      return result;
    } finally {
      this.productProviderProjection = previous;
      this.productProviderCapture = previousCapture;
    }
  }

  async verifyProductReadiness(phase) {
    const previous = this.productReadinessOnly;
    this.productReadinessOnly = true;
    try {
      return await this.verifyReadiness(phase);
    } finally {
      this.productReadinessOnly = previous;
    }
  }

  async runKubectlRead(arguments_, phase, category, timeoutMilliseconds, outputLimit) {
    let selected = arguments_;
    let productResource;
    if (this.productProviderProjection && !isObservabilityProviderRead(arguments_, this.profile.proof) &&
        Array.isArray(arguments_) && arguments_[0] === "get" &&
        arguments_.at(-1) === "--output=json") {
      const observability = new Set(["m1-30c", "m1-30d"]).has(this.profile.proof);
      const awsEmulator = this.profile.proof === "m1-30d";
      const selector = new Map([
        ["deployment", awsEmulator ? "app.kubernetes.io/component notin (aws-emulator,graph,observability)" :
          observability ? "app.kubernetes.io/component notin (graph,observability)" : "app.kubernetes.io/component!=graph"],
        ["replicaset", awsEmulator ? "app.kubernetes.io/component notin (aws-emulator,graph,observability)" :
          observability ? "app.kubernetes.io/component notin (graph,observability)" : "app.kubernetes.io/component!=graph"],
        ["pod", awsEmulator ? "app.kubernetes.io/component notin (aws-emulator,graph,observability)" :
          observability ? "app.kubernetes.io/component notin (graph,observability)" : "app.kubernetes.io/component!=graph"],
        ["service", awsEmulator ? "app.kubernetes.io/component notin (aws-emulator,graph,observability)" :
          observability ? "app.kubernetes.io/component notin (graph,observability)" : "app.kubernetes.io/component!=graph"],
        ["endpointslice", awsEmulator ? "kubernetes.io/service-name notin (localstack,neo4j,otel-collector)" :
          observability ? "kubernetes.io/service-name notin (neo4j,otel-collector)" : "kubernetes.io/service-name!=neo4j"],
      ]).get(arguments_[1]);
      if (selector !== undefined) {
        productResource = arguments_[1];
        selected = [...arguments_.slice(0, -1), `--selector=${selector}`, "--output=json"];
      }
    }
    const result = await super.runKubectlRead(selected, phase, category, timeoutMilliseconds, outputLimit);
    return productResource === undefined ? result : normalizeProductProviderResult(
      result, productResource, category, this.productProviderCapture,
    );
  }

  async runAdditionalPreflightChecks(phase) {
    await this.admitGraphGoTool(phase);
    for (const selected of this.graphImagePlans.values()) {
      const resolution = await this.resolveGraphImage(selected, phase);
      const baseline = await this.readGraphImageBaseline(selected, resolution, phase, "configuration");
      this.requireDistinctGraphImageIdentity(selected.name, baseline?.identity, "configuration");
      this.graphImageResolutions.set(selected.name, resolution);
      if (baseline === undefined) this.graphImageBaselineAbsences.add(selected.name);
      else this.graphSharedImageBaselines.set(selected.name, baseline);
    }
  }

  async inspectGraphGoTool(phase, category, retained = undefined) {
    phase.assertActive(category);
    const candidate = graphGoToolCandidates[this.input.hostPlatform];
    const pattern = graphGoToolCanonicalPatterns[this.input.hostPlatform];
    if (candidate === undefined || pattern === undefined) throw new Failure(category);
    let command;
    let status;
    try {
      command = await this.dependencies.canonicalPath(candidate);
      status = await this.dependencies.statPath(command);
    } catch {
      throw new Failure(category);
    }
    phase.assertActive(category);
    if (typeof command !== "string" || command !== normalize(command) || !pattern.test(command) ||
        !status?.isFile?.() || status?.isSymbolicLink?.() || !Number.isSafeInteger(status.dev) ||
        !Number.isSafeInteger(status.ino) || !Number.isSafeInteger(status.mode) ||
        !Number.isSafeInteger(status.uid) || !Number.isSafeInteger(status.gid) ||
        !Number.isSafeInteger(status.size) || status.size < 1 || status.size > 134_217_728 ||
        !Number.isFinite(status.mtimeMs) || (status.mode & 0o111) === 0) throw new Failure(category);
    const identity = deepFreeze({
      candidate,
      command,
      dev: status.dev,
      gid: status.gid,
      ino: status.ino,
      mode: status.mode,
      mtimeMs: status.mtimeMs,
      size: status.size,
      uid: status.uid,
    });
    if (retained !== undefined && !exactData(identity, retained)) throw new Failure(category);
    return identity;
  }

  async requireGraphGoVersion(identity, phase, category) {
    const result = await this.runRead(identity.command, ["version"], phase, category, 15_000, 16_384);
    if (result.stdout !== `go version go1.25.6 ${this.input.hostPlatform}\n`) throw new Failure(category);
  }

  async admitGraphGoTool(phase) {
    const identity = await this.inspectGraphGoTool(phase, "configuration");
    await this.requireGraphGoVersion(identity, phase, "configuration");
    this.graphGoToolIdentity = await this.inspectGraphGoTool(phase, "configuration", identity);
  }

  async requireGraphGoTool(phase, category) {
    const retained = this.graphGoToolIdentity;
    if (retained === undefined) throw new Failure(category);
    await this.inspectGraphGoTool(phase, category, retained);
    await this.requireGraphGoVersion(retained, phase, category);
    return await this.inspectGraphGoTool(phase, category, retained);
  }

  async runMutation(command, arguments_, phase, category, options) {
    const executable = command === "go" ? (await this.requireGraphGoTool(phase, category)).command : command;
    return await super.runMutation(executable, arguments_, phase, category, options);
  }

  async readGraphImageConsumers(selected, phase, category) {
    const result = await this.runRead("docker", [
      "ps", "--all", "--quiet", "--no-trunc", "--filter", `ancestor=${selected.configDigest}`,
    ], phase, category);
    if (result.stdout === "") return deepFreeze([]);
    if (!result.stdout.endsWith("\n")) throw new Failure(category);
    const consumers = result.stdout.slice(0, -1).split("\n");
    if (consumers.length > 4_096 || consumers.some((value) => !/^[0-9a-f]{64}$/.test(value)) ||
        new Set(consumers).size !== consumers.length) throw new Failure(category);
    return deepFreeze(consumers.sort());
  }

  async requireGraphImageConsumersAbsent(selected, phase, category) {
    if ((await this.readGraphImageConsumers(selected, phase, category)).length !== 0) throw new Failure(category);
  }

  async readGraphImageReference(selected, phase, category) {
    const format = "[{{json .Id}},{{json .Architecture}},{{json .Os}},{{json .RepoDigests}},{{json .RepoTags}}]";
    const result = await this.runRaw(
      "docker", ["image", "inspect", "--format", format, selected.repoDigest],
      phase, category, 15_000, 262_144,
    );
    if (exactMissingFormattedGraphImage(result, selected.repoDigest)) return undefined;
    if (!isPlainObject(result) || result.status !== 0 || result.signal !== null || result.stderr !== "" ||
        result.stdout === "" || result.thrown !== false || result.timedOut !== false) throw new Failure(category);
    let document;
    try { document = parseBoundedJson(result.stdout, 262_144); }
    catch { throw new Failure(category); }
    if (!Array.isArray(document) || document.length !== 5 || !digestPattern.test(document[0]) ||
        !new Set(["amd64", "arm64"]).has(document[1]) || document[2] !== "linux" ||
        !exactStringArray(document[3], [selected.repoDigest]) ||
        !(exactStringArray(document[4], []) || exactStringArray(document[4], [selected.tag]))) {
      throw new Failure(category);
    }
    return deepFreeze({
      architecture: document[1],
      id: document[0],
      operatingSystem: document[2],
      repoDigests: [...document[3]],
      repoTags: [...document[4]],
    });
  }

  async readGraphImageConfigPresence(selected, phase, category) {
    const result = await this.runRaw(
      "docker", ["image", "inspect", selected.configDigest], phase, category, 15_000, 262_144,
    );
    if (exactMissingGraphImage(result, selected.configDigest)) return false;
    if (!isPlainObject(result) || result.status !== 0 || result.signal !== null || result.stderr !== "" ||
        result.stdout === "" || result.thrown !== false || result.timedOut !== false) throw new Failure(category);
    let document;
    try { document = parseBoundedJson(result.stdout, 262_144); }
    catch { throw new Failure(category); }
    if (!Array.isArray(document) || document.length !== 1 || !isPlainObject(document[0]) ||
        document[0].Id !== selected.configDigest) throw new Failure(category);
    return true;
  }

  async readGraphImageListing(selected, phase, category) {
    const result = await this.runRead("docker", [
      "image", "ls", "--quiet", "--no-trunc", "--filter", `reference=${selected.reference}`,
    ], phase, category);
    if (result.stdout === "") return deepFreeze([]);
    if (!result.stdout.endsWith("\n")) throw new Failure(category);
    const ids = result.stdout.slice(0, -1).split("\n");
    if (ids.length > 16 || ids.some((value) => !digestPattern.test(value)) ||
        new Set(ids).size !== ids.length) throw new Failure(category);
    return deepFreeze(ids.sort());
  }

  async readGraphImageBaseline(selected, resolution, phase, category, retained = undefined) {
    const configPresent = await this.readGraphImageConfigPresence(selected, phase, category);
    const reference = await this.readGraphImageReference(selected, phase, category);
    const listedIds = await this.readGraphImageListing(selected, phase, category);
    const consumers = await this.readGraphImageConsumers(selected, phase, category);
    if (!configPresent && reference === undefined) {
      if (listedIds.length !== 0 || consumers.length !== 0 || retained !== undefined) throw new Failure(category);
      return undefined;
    }
    if (!configPresent || reference === undefined || reference.id !== selected.configDigest ||
        reference.architecture !== selected.architecture || reference.operatingSystem !== "linux" ||
        !(listedIds.length === 0 || exactStringArray(listedIds, [selected.configDigest]))) {
      throw new Failure(category);
    }
    const aliases = deepFreeze({
      repoDigests: [...reference.repoDigests],
      repoTags: [...reference.repoTags],
    });
    let identity;
    try {
      identity = await this.inspectGraphImage(
        selected, resolution, phase, undefined, selected.repoDigest, category, aliases,
      );
    } catch {
      throw new Failure(category);
    }
    const baseline = deepFreeze({
      aliases,
      consumers: [...consumers],
      identity,
      listedIds: [...listedIds],
    });
    if (retained !== undefined && !exactData(baseline, retained)) throw new Failure(category);
    return baseline;
  }

  requireDistinctGraphImageIdentity(name, identity, category) {
    if (identity === undefined) return;
    const identities = [
      ...this.imageIdentities.entries(),
      ...this.graphImageIdentities.entries(),
      ...[...this.graphSharedImageBaselines.entries()].map(([key, value]) => [key, value.identity]),
    ];
    if (identities.some(([key, value]) => key !== name && value.id === identity.id)) {
      throw new Failure(category);
    }
  }

  async requireGraphImageBaselineAbsent(selected, phase, category = "ownership") {
    const inspected = await this.runRaw(
      "docker", ["image", "inspect", selected.configDigest], phase, category, 15_000, 262_144,
    );
    if (!exactMissingGraphImage(inspected, selected.configDigest)) throw new Failure(category);
    if (await this.readGraphImageReference(selected, phase, category) !== undefined) throw new Failure(category);
    const listed = await this.runRead("docker", [
      "image", "ls", "--quiet", "--no-trunc", "--filter", `reference=${selected.reference}`,
    ], phase, category);
    if (listed.stdout !== "") throw new Failure(category);
    await this.requireGraphImageConsumersAbsent(selected, phase, category);
  }

  async resolveGraphImage(selected, phase) {
    const indexResult = await this.runRead(
      "docker", ["manifest", "inspect", selected.reference], phase, "provider", 30_000, 4_194_304,
    );
    const manifestResult = await this.runRead(
      "docker", ["manifest", "inspect", selected.selectedReference], phase, "provider", 30_000, 4_194_304,
    );
    try {
      return deepFreeze({
        index: validateGraphImageIndex(parseBoundedJson(indexResult.stdout, 4_194_304), selected),
        manifest: validateGraphImageManifest(parseBoundedJson(manifestResult.stdout, 4_194_304), selected),
      });
    } catch (error) {
      if (error instanceof Failure) throw error;
      throw new GraphFailure("normalization");
    }
  }

  async inspectGraphImage(selected, resolution, phase, retained = undefined, reference = selected.reference,
    category = "ownership", aliases = undefined) {
    const format = "[{{json .Architecture}},{{json .Os}},{{json .Id}},{{json .RepoDigests}},{{json .RepoTags}}," +
      "{{json .RootFS}},{{json (index .Config \"Env\")}},{{json (index .Config \"Entrypoint\")}}," +
      "{{json (index .Config \"Cmd\")}},{{json (index .Config \"ExposedPorts\")}}," +
      "{{json (index .Config \"Volumes\")}},{{json (index .Config \"Labels\")}}," +
      "{{json (or (index .Config \"User\") \"\")}},{{json (or (index .Config \"WorkingDir\") \"\")}}]";
    const result = await this.runRead(
      "docker", ["image", "inspect", "--format", format, reference], phase, category, 15_000, 4_194_304,
    );
    let document;
    try { document = parseBoundedJson(result.stdout, 4_194_304); }
    catch { throw new GraphFailure("normalization"); }
    return validateGraphImageInspection(
      projectGraphImageInspection(document), selected, resolution, retained, aliases,
    );
  }

  async buildAdditionalImages(phase) {
    await this.requireTemporaryOwnership(phase, "ownership");
    for (const selected of this.graphImagePlans.values()) {
      const resolution = this.graphImageResolutions.get(selected.name) ??
        await this.resolveGraphImage(selected, phase);
      this.graphImageResolutions.set(selected.name, resolution);
      const retainedBaseline = this.graphSharedImageBaselines.get(selected.name);
      const baseline = await this.readGraphImageBaseline(
        selected, resolution, phase, "ownership", retainedBaseline,
      );
      if (this.graphImageBaselineAbsences.has(selected.name) && baseline !== undefined) {
        throw new GraphFailure("ownership");
      }
      if (baseline !== undefined) {
        this.requireDistinctGraphImageIdentity(selected.name, baseline.identity, "ownership");
        this.graphSharedImageBaselines.set(selected.name, baseline);
        this.graphImageIdentities.set(selected.name, baseline.identity);
        this.graphImageAliases.set(selected.name, baseline.aliases);
        continue;
      }
      this.graphImageBaselineAbsences.add(selected.name);
      this.graphImageMayHaveApplied.add(selected.name);
      const pulled = await this.runMutation("docker", [
        "pull", "--platform", selected.platform, selected.reference,
      ], phase, "provider", {
        environment: this.environment,
        outputLimit: 4_194_304,
        timeoutMilliseconds: 240_000,
      });
      if (pulled.outcome === "definitive") {
        this.graphImageMayHaveApplied.delete(selected.name);
        throw new Failure("provider");
      }
      const identity = await this.inspectGraphImage(selected, resolution, phase);
      this.requireDistinctGraphImageIdentity(selected.name, identity, "ownership");
      await this.requireGraphImageConsumersAbsent(selected, phase, "ownership");
      this.graphImageIdentities.set(selected.name, identity);
      this.graphImageAliases.set(selected.name, {
        repoDigests: [selected.repoDigest],
        repoTags: [],
      });
    }
    await this.requireTemporaryOwnership(phase, "ownership");
  }

  async readGraphNodeLabel(phase, category, retained = undefined, labeled = true) {
    const node = await this.verifyCluster(phase, "ownership");
    const name = `${this.cluster}-control-plane`;
    const result = await this.runKubectlRead([
      "get", "node", name, "--output=json",
    ], phase, category, 30_000, 262_144);
    let document;
    try { document = parseBoundedJson(result.stdout, 262_144); }
    catch { throw new GraphFailure("normalization"); }
    return validateGraphNodeLabel(document, { name, token: node.token }, retained, labeled);
  }

  async readGraphNodePath(phase, category, retained = undefined) {
    const result = await this.runNodeRaw([
      "stat", "--format=%d|%i|%F|%u|%g|%a|%n", "--", GRAPH_CONSTANTS.nodeDataPath,
    ], phase, category, 30_000, 16_384);
    if (result.status === 0 && result.signal === null && result.stderr === "") {
      return validateGraphNodePath(result.stdout, this.graphNodeIdentity ?? {
        token: this.nodeIdentity?.token,
      }, retained);
    }
    const missing = result.status === 1 && result.signal === null && result.stdout === "" &&
      new Set([
        `stat: cannot stat '${GRAPH_CONSTANTS.nodeDataPath}': No such file or directory\n`,
        `stat: cannot statx '${GRAPH_CONSTANTS.nodeDataPath}': No such file or directory\n`,
      ]).has(result.stderr);
    if (missing) return undefined;
    throw new Failure(category);
  }

  async reconcileGraphState(reader, predicate, phase, category) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      phase.assertActive(category);
      const value = await reader();
      if (predicate(value)) return value;
    }
    throw new Failure(category);
  }

  async prepareAdditionalNode(phase) {
    await this.requireTemporaryOwnership(phase, "ownership");
    await this.requireOwnedPath(this.paths.graphManifest, phase, "ownership");
    const node = await this.verifyCluster(phase, "ownership");
    const name = `${this.cluster}-control-plane`;
    this.graphNodeMayHaveApplied = true;
    const labeled = await this.runKubectlMutation([
      "label", "node", name, `${GRAPH_CONSTANTS.nodeLabelKey}=${GRAPH_CONSTANTS.nodeLabelValue}`,
      "--overwrite=false",
    ], phase, "provider");
    if (labeled.outcome === "definitive") {
      this.graphNodeMayHaveApplied = false;
      throw new Failure("provider");
    }
    let pendingNodeIdentity = this.graphNodeIdentity;
    this.graphNodeIdentity = await this.reconcileGraphState(
      async () => {
        const current = await this.readGraphNodeLabel(phase, "ownership", pendingNodeIdentity, null);
        pendingNodeIdentity ??= current;
        return current;
      },
      (value) => value?.labeled === true && value.token === node.token,
      phase,
      "ownership",
    );

    this.graphPathMayHaveApplied = true;
    const prepared = await this.runNodeMutation([
      "install", "-d", "-m", "0700", "-o", "7474", "-g", "7474", "--", GRAPH_CONSTANTS.nodeDataPath,
    ], phase, "provider");
    if (prepared.outcome === "definitive") {
      this.graphPathMayHaveApplied = false;
      throw new Failure("provider");
    }
    this.graphPathIdentity = await this.reconcileGraphState(
      () => this.readGraphNodePath(phase, "ownership", this.graphPathIdentity),
      (value) => value?.nodeToken === node.token,
      phase,
      "ownership",
    );
    await this.requireOwnedPath(this.paths.graphManifest, phase, "ownership");
  }

  async verifyGraphImage(selected, retained, phase, category) {
    const resolution = this.graphImageResolutions.get(selected.name);
    if (resolution === undefined) throw new Failure(category);
    const aliases = this.graphImageAliases.get(selected.name) ?? {
      repoDigests: retained.repoDigests,
      repoTags: retained.repoTags,
    };
    return await this.inspectGraphImage(selected, resolution, phase, retained, retained.id, category, aliases);
  }

  async loadAdditionalImages(phase) {
    await this.requireTemporaryOwnership(phase, "ownership");
    await this.verifyCluster(phase, "ownership");
    for (const selected of this.graphImagePlans.values()) {
      const retained = this.graphImageIdentities.get(selected.name);
      if (retained === undefined) throw new GraphFailure("ownership");
      await this.verifyGraphImage(selected, retained, phase, "ownership");
      const before = await this.runNodeRead([
        "ctr", "--namespace", "k8s.io", "images", "list",
      ], phase, "provider", 30_000, 4_194_304);
      if (this.graphNodeImageInventory === undefined) {
        try { parseGraphContainerdInventory(before.stdout); }
        catch { throw new GraphFailure("provider"); }
        this.graphNodeImageInventory = before.stdout;
      } else if (before.stdout !== this.graphNodeImageInventory) {
        throw new GraphFailure("ownership");
      }
      const loaded = await this.runMutation(this.paths.kind, [
        "load", "docker-image", selected.reference, "--name", this.cluster,
      ], phase, "provider", {
        environment: this.environment,
        outputLimit: 4_194_304,
        timeoutMilliseconds: 180_000,
      });
      if (loaded.outcome === "definitive") throw new Failure("provider");
      const after = await this.runNodeRead([
        "ctr", "--namespace", "k8s.io", "images", "list",
      ], phase, "provider", 30_000, 4_194_304);
      let target = parseGraphContainerdImageTargets(before.stdout, after.stdout, selected);
      if (target.references.length !== 3) throw new GraphFailure("provider");
        const child = target.references.find(({ mediaType, reference }) =>
          mediaType === "application/vnd.oci.image.manifest.v1+json" && reference.startsWith("import-"));
        const wrapper = target.references.find(({ mediaType }) =>
          mediaType === "application/vnd.oci.image.index.v1+json");
        if (child === undefined || wrapper === undefined) throw new GraphFailure("provider");
        const manifest = await this.runNodeRead([
          "ctr", "--namespace", "k8s.io", "content", "get", child.digest,
        ], phase, "provider", 30_000, 4_194_304);
        const index = await this.runNodeRead([
          "ctr", "--namespace", "k8s.io", "content", "get", wrapper.digest,
        ], phase, "provider", 30_000, 4_194_304);
        target = validateGraphContainerdImageContents(
          target, manifest.stdout, index.stdout, selected, retained, this.graphImageResolutions.get(selected.name),
        );
        this.graphNodeImageInventory = after.stdout;
        const tagged = await this.runNodeMutation([
          "ctr", "--namespace", "k8s.io", "images", "tag", "--local",
          wrapper.reference, graphWorkloadImageReference(selected),
        ], phase, "provider", 30_000, 4_194_304);
        if (tagged.outcome === "definitive") throw new GraphFailure("provider");
        const aliased = await this.runNodeRead([
          "ctr", "--namespace", "k8s.io", "images", "list",
        ], phase, "provider", 30_000, 4_194_304);
        target = bindGraphContainerdWorkloadAlias(after.stdout, aliased.stdout, target, selected);
        this.graphNodeImageInventory = aliased.stdout;
        const runtimeTarget = target.references[0];
        if (runtimeTarget === undefined || !runtimeTarget.reference.startsWith("import-")) {
          throw new GraphFailure("provider");
        }
        const runtimeTagged = await this.runNodeMutation([
          "ctr", "--namespace", "k8s.io", "images", "tag", "--local",
          runtimeTarget.reference, graphPublicImageReference(runtimeTarget.reference),
        ], phase, "provider", 30_000, 4_194_304);
        if (runtimeTagged.outcome === "definitive") throw new GraphFailure("provider");
        const runtimeAliased = await this.runNodeRead([
          "ctr", "--namespace", "k8s.io", "images", "list",
        ], phase, "provider", 30_000, 4_194_304);
        target = bindGraphContainerdRuntimeAlias(aliased.stdout, runtimeAliased.stdout, target, selected);
        this.graphNodeImageInventory = runtimeAliased.stdout;
      if (this.graphLoadedImageTargets.has(selected.name)) throw new GraphFailure("ownership");
      this.graphLoadedImageTargets.set(selected.name, target);
    }
    await this.verifyCluster(phase, "ownership");
  }

  async verifyAdditionalManifestState(phase, path) {
    if (path !== this.paths.graphManifest || this.graphNodeIdentity === undefined ||
        this.graphPathIdentity === undefined) throw new GraphFailure("ownership");
    await this.requireTemporaryOwnership(phase, "ownership");
    await this.verifyCluster(phase, "ownership");
    const node = await this.readGraphNodeLabel(phase, "ownership", this.graphNodeIdentity, true);
    const storage = await this.readGraphNodePath(phase, "ownership", this.graphPathIdentity);
    if (!exactData(node, this.graphNodeIdentity) || !exactData(storage, this.graphPathIdentity)) {
      throw new GraphFailure("ownership");
    }
    if (typeof this.graphNodeImageInventory !== "string") throw new GraphFailure("ownership");
    const images = await this.runNodeRead([
      "ctr", "--namespace", "k8s.io", "images", "list",
    ], phase, "ownership", 30_000, 4_194_304);
    if (images.stdout !== this.graphNodeImageInventory) throw new GraphFailure("ownership");
    await this.requireOwnedPath(path, phase, "ownership");
  }

  graphProviderExpectation() {
    if (this.graphLoadedImageTargets.size !== this.graphImagePlans.size || !this.graphLoadedImageTargets.has("busybox") ||
        !this.graphLoadedImageTargets.has("neo4j")) throw new GraphFailure("ownership");
    const expected = {
      imageTargets: Object.fromEntries(["busybox", "neo4j"].map((name) => [name, this.graphLoadedImageTargets.get(name)])),
      nodeName: `${this.cluster}-control-plane`,
    };
    try {
      platformForNode(expected);
    } catch {
      throw new GraphFailure("ownership");
    }
    return expected;
  }

  async readGraphProviderState(phase, category = "readiness", allowMissingHealth = false) {
    await this.requireTemporaryOwnership(phase, "ownership");
    await this.requireOwnedPath(this.paths.graphManifest, phase, "ownership");
    await this.verifyCluster(phase, "ownership");
    const node = await this.readGraphNodeLabel(phase, "ownership", this.graphNodeIdentity, true);
    const storage = await this.readGraphNodePath(phase, "ownership", this.graphPathIdentity);
    if (!exactData(node, this.graphNodeIdentity) || !exactData(storage, this.graphPathIdentity)) {
      throw new GraphFailure("ownership");
    }
    for (const selected of this.graphImagePlans.values()) {
      const retained = this.graphImageIdentities.get(selected.name);
      if (retained === undefined) throw new GraphFailure("ownership");
      await this.verifyGraphImage(selected, retained, phase, "ownership");
    }
    this.graphProviderExpectation();
    const requests = [
      ["persistentVolumes", ["get", "persistentvolume", "--output=json"]],
      ["persistentVolumeClaims", [
        "get", "persistentvolumeclaim", "--namespace", GRAPH_CONSTANTS.namespace, "--output=json",
      ]],
      ["deployments", ["get", "deployment", "--namespace", GRAPH_CONSTANTS.namespace, "--output=json"]],
      ["replicaSets", ["get", "replicaset", "--namespace", GRAPH_CONSTANTS.namespace, "--output=json"]],
      ["pods", ["get", "pod", "--namespace", GRAPH_CONSTANTS.namespace, "--output=json"]],
      ["services", ["get", "service", "--namespace", GRAPH_CONSTANTS.namespace, "--output=json"]],
      ["endpointSlices", ["get", "endpointslice", "--namespace", GRAPH_CONSTANTS.namespace, "--output=json"]],
      ["jobs", ["get", "job", "--namespace", GRAPH_CONSTANTS.namespace, "--output=json"]],
      ["ingresses", ["get", "ingress", "--namespace", GRAPH_CONSTANTS.namespace, "--output=json"]],
    ];
    const documents = {};
    for (const [name, arguments_] of requests) {
      const result = await super.runKubectlRead(
        arguments_, phase, category, 30_000, graphProviderByteLimit,
      );
      documents[name] = projectGraphProviderResources(
        parseGraphProviderList(result.stdout, name), name, this.profile.proof,
      );
    }
    const matches = documents.pods.filter((item) =>
      item?.metadata?.labels?.["app.kubernetes.io/name"] === "neo4j-health");
    const healthPodName = matches[0]?.metadata?.name;
    if (matches.length === 0 && allowMissingHealth) return { ...documents, healthLog: null };
    if (matches.length !== 1 || !/^neo4j-health-[a-z0-9]{5}$/.test(healthPodName ?? "")) {
      throw new GraphFailure("readiness");
    }
    const health = await super.runKubectlRead([
      "logs", "--namespace", GRAPH_CONSTANTS.namespace, healthPodName, "--container", "health",
    ], phase, category, 30_000, 16_384);
    return { ...documents, healthLog: health.stdout };
  }

  async pauseGraphPoll(phase, category) {
    await new Promise((resolve) => setTimeout(resolve, graphProviderPollMilliseconds));
    phase.assertActive(category);
  }

  async pollGraphProviderState(phase, retained = undefined, requireReplacement = false,
    category = "readiness", requireHealthReplacement = false) {
    let failure;
    for (let attempt = 0; attempt < graphProviderPollLimit; attempt += 1) {
      phase.assertActive(category);
      try {
        await this.verifyProductReadiness(phase);
        const providerState = await this.readGraphProviderState(phase, category);
        validateCorrelatedProductProviderState(providerState, this.productProviderSnapshot);
        return validateGraphKubernetesState(
          providerState, this.graphProviderExpectation(),
          retained, requireReplacement, requireHealthReplacement,
        );
      } catch (error) {
        if (!(error instanceof Failure) || error.category !== "readiness") throw error;
        failure = error;
      }
      if (attempt + 1 < graphProviderPollLimit) await this.pauseGraphPoll(phase, category);
    }
    throw failure ?? new GraphFailure(category);
  }

  graphMarkerArguments(pod, mutation) {
    if (!isPlainObject(pod) || !/^neo4j-[a-z0-9]{10}-[a-z0-9]{5}$/.test(pod.name ?? "") ||
        !kubernetesUidPattern.test(pod.uid ?? "") || typeof mutation !== "boolean") {
      throw new GraphFailure("ownership");
    }
    const statement = mutation
      ? `MERGE (marker:${graphMarkerLabel} {id: $proof_id}) RETURN count(marker) AS marker_count`
      : `MATCH (marker:${graphMarkerLabel} {id: $proof_id}) RETURN count(marker) AS marker_count`;
    return [
      "--namespace", GRAPH_CONSTANTS.namespace, "exec", pod.name, "--container", "neo4j", "--",
      "cypher-shell", "--address", graphMarkerAddress, "--database", "neo4j", "--format", "plain",
      "--non-interactive", "--param", `proof_id => '${this.input.marker}'`, statement,
    ];
  }

  async writeGraphMarker(pod, phase) {
    return await this.runKubectlMutation(this.graphMarkerArguments(pod, true), phase, "provider", 30_000, 16_384);
  }

  async readGraphMarker(pod, phase, category = "readiness") {
    const result = await this.runKubectlRead(
      this.graphMarkerArguments(pod, false), phase, category, 30_000, 16_384,
    );
    if (result.stdout !== graphMarkerOutput) throw new GraphFailure(category);
    return true;
  }

  async deleteGraphPod(pod, phase) {
    if (!isPlainObject(pod) || !/^neo4j-[a-z0-9]{10}-[a-z0-9]{5}$/.test(pod.name ?? "") ||
        !kubernetesUidPattern.test(pod.uid ?? "")) throw new GraphFailure("ownership");
    const input = `${JSON.stringify({
      apiVersion: "v1",
      kind: "DeleteOptions",
      preconditions: { uid: pod.uid },
    })}\n`;
    const result = await this.withOwnedFiles(
      [this.paths.kubeconfig], phase, "ownership", async ([kubeconfig]) =>
        await this.runMutation("kubectl", [
          "--kubeconfig", "/dev/fd/3", "delete",
          `--raw=/api/v1/namespaces/${GRAPH_CONSTANTS.namespace}/pods/${pod.name}`, "--filename=-",
        ], phase, "provider", {
          environment: this.environment,
          fileDescriptors: [kubeconfig.handle.fd],
          input,
          outputLimit: 262_144,
          timeoutMilliseconds: 30_000,
        }),
    );
    await this.requireOwnedPath(this.paths.kubeconfig, phase, "ownership");
    return result;
  }

  async deleteGraphHealthJob(health, phase) {
    try {
      requireExactKeySet(health, ["jobUid", "podName", "podUid"], "graph health identity");
      if (!kubernetesUidPattern.test(health.jobUid ?? "") ||
          !/^neo4j-health-[a-z0-9]{5}$/.test(health.podName ?? "") ||
          !kubernetesUidPattern.test(health.podUid ?? "")) throw new TypeError("graph health identity is invalid");
    } catch {
      throw new GraphFailure("ownership");
    }
    const input = `${JSON.stringify({
      apiVersion: "v1",
      kind: "DeleteOptions",
      preconditions: { uid: health.jobUid },
      propagationPolicy: "Foreground",
    })}\n`;
    const result = await this.withOwnedFiles(
      [this.paths.kubeconfig], phase, "ownership", async ([kubeconfig]) =>
        await this.runMutation("kubectl", [
          "--kubeconfig", "/dev/fd/3", "delete",
          `--raw=/apis/batch/v1/namespaces/${GRAPH_CONSTANTS.namespace}/jobs/neo4j-health`, "--filename=-",
        ], phase, "provider", {
          environment: this.environment,
          fileDescriptors: [kubeconfig.handle.fd],
          input,
          outputLimit: 262_144,
          timeoutMilliseconds: 30_000,
        }),
    );
    await this.requireOwnedPath(this.paths.kubeconfig, phase, "ownership");
    return result;
  }

  async applyGraphHealthJob(phase) {
    const job = graphManifestResource("Job", "neo4j-health");
    const input = `${JSON.stringify(job)}\n`;
    const result = await this.withOwnedFiles(
      [this.paths.kubeconfig], phase, "ownership", async ([kubeconfig]) =>
        await this.runMutation("kubectl", [
          "--kubeconfig", "/dev/fd/3", "apply", "--filename", "-",
        ], phase, "provider", {
          environment: this.environment,
          fileDescriptors: [kubeconfig.handle.fd],
          input,
          outputLimit: 262_144,
          timeoutMilliseconds: 30_000,
        }),
    );
    await this.requireOwnedPath(this.paths.kubeconfig, phase, "ownership");
    return result;
  }

  async pollGraphHealthJobAbsent(phase, retained, category = "readiness") {
    let failure;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      phase.assertActive(category);
      try {
        const providerState = await this.readGraphProviderState(phase, category, true);
        if (validateGraphProviderAbsence(
          providerState, this.graphProviderExpectation(), retained, "health",
        )) return true;
      } catch (error) {
        if (!(error instanceof Failure) || !new Set([category, "readiness"]).has(error.category)) throw error;
        failure = error;
      }
      if (attempt + 1 < 3) await this.pauseGraphPoll(phase, category);
    }
    throw failure ?? new GraphFailure(category);
  }

  async verifyAdditionalReadiness(productResult, phase) {
    if (this.productReadinessOnly) return productResult;
    const initial = await this.pollGraphProviderState(phase);
    this.graphProviderIdentity = initial;
    const initialPod = { name: initial.neo4j.podName, uid: initial.neo4j.podUid };
    this.graphMarkerMayHaveApplied = true;
    const written = await this.writeGraphMarker(initialPod, phase);
    if (!new Set(["ambiguous", "applied"]).has(written?.outcome)) {
      this.graphMarkerMayHaveApplied = false;
      throw new GraphFailure("provider");
    }
    if (await this.readGraphMarker(initialPod, phase, "readiness") !== true) {
      throw new GraphFailure("readiness");
    }
    this.graphPodDeleteMayHaveApplied = true;
    const deleted = await this.deleteGraphPod(initialPod, phase);
    if (!new Set(["ambiguous", "applied"]).has(deleted?.outcome)) {
      this.graphPodDeleteMayHaveApplied = false;
      throw new GraphFailure("provider");
    }
    const replacement = await this.pollGraphProviderState(phase, initial, true);
    this.graphProviderIdentity = replacement;
    this.graphPodDeleteMayHaveApplied = false;
    const initialHealth = {
      jobUid: initial.health.jobUid,
      podName: initial.health.podName,
      podUid: initial.health.podUid,
    };
    this.graphHealthDeleteMayHaveApplied = true;
    const healthDeleted = await this.deleteGraphHealthJob(initialHealth, phase);
    if (!new Set(["ambiguous", "applied"]).has(healthDeleted?.outcome)) {
      this.graphHealthDeleteMayHaveApplied = false;
      throw new GraphFailure("provider");
    }
    await this.pollGraphHealthJobAbsent(phase, replacement);
    this.graphHealthDeleteMayHaveApplied = false;
    this.graphProviderAbsenceIdentity = graphProviderAbsenceIdentity("health", replacement);
    this.graphHealthApplyMayHaveApplied = true;
    const healthApplied = await this.applyGraphHealthJob(phase);
    if (!new Set(["ambiguous", "applied"]).has(healthApplied?.outcome)) {
      this.graphHealthApplyMayHaveApplied = false;
      this.graphProviderIdentity = undefined;
      throw new GraphFailure("provider");
    }
    const fresh = await this.pollGraphProviderState(phase, replacement, false, "readiness", true);
    this.graphProviderIdentity = fresh;
    this.graphHealthApplyMayHaveApplied = false;
    this.graphProviderAbsenceIdentity = undefined;
    const replacementPod = { name: replacement.neo4j.podName, uid: replacement.neo4j.podUid };
    if (await this.readGraphMarker(replacementPod, phase, "readiness") !== true) {
      throw new GraphFailure("readiness");
    }
    this.graphProviderIdentity = await this.pollGraphProviderState(phase, fresh, false);
    return Object.freeze({
      ...productResult,
      graph: Object.freeze({ internal: true, persistent: true, ready: true }),
    });
  }

  async verifyAdditionalNodeForCleanup(phase) {
    await this.requireTemporaryOwnership(phase, "cleanup");
    await this.requireOwnedPath(this.paths.graphManifest, phase, "cleanup");
    await this.verifyCluster(phase, "cleanup");
    if (this.graphNodeImageInventory !== undefined) {
      if (typeof this.graphNodeImageInventory !== "string") throw new Failure("cleanup");
      const images = await this.runNodeRead([
        "ctr", "--namespace", "k8s.io", "images", "list",
      ], phase, "cleanup", 30_000, 4_194_304);
      if (images.stdout !== this.graphNodeImageInventory) throw new Failure("cleanup");
    }
    if (!this.graphNodeMayHaveApplied && !this.graphPathMayHaveApplied &&
        this.graphProviderIdentity === undefined && !this.graphPodDeleteMayHaveApplied &&
        !this.graphHealthDeleteMayHaveApplied && !this.graphHealthApplyMayHaveApplied &&
        this.graphProviderAbsenceIdentity === undefined) return;
    if (this.graphNodeMayHaveApplied) {
      if (this.graphNodeIdentity === undefined) {
        try {
          this.graphNodeIdentity = await this.reconcileGraphState(
            () => this.readGraphNodeLabel(phase, "cleanup", undefined, true),
            (value) => value?.labeled === true,
            phase,
            "cleanup",
          );
        } catch {
          const absent = await this.reconcileGraphState(
            () => this.readGraphNodeLabel(phase, "cleanup", undefined, false),
            (value) => value?.labeled === false,
            phase,
            "cleanup",
          );
          if (absent.token !== this.nodeIdentity.token) throw new Failure("cleanup");
          this.graphNodeMayHaveApplied = false;
        }
      } else {
        const current = await this.readGraphNodeLabel(phase, "cleanup", this.graphNodeIdentity, true);
        if (!exactData(current, this.graphNodeIdentity)) throw new Failure("cleanup");
      }
    }
    if (this.graphPathMayHaveApplied) {
      if (this.graphPathIdentity === undefined) {
        let missing = 0;
        for (let attempt = 0; attempt < 3; attempt += 1) {
          phase.assertActive("cleanup");
          const current = await this.readGraphNodePath(phase, "cleanup");
          if (current !== undefined) {
            this.graphPathIdentity = current;
            break;
          }
          missing += 1;
        }
        if (this.graphPathIdentity === undefined) {
          if (missing !== 3) throw new Failure("cleanup");
          this.graphPathMayHaveApplied = false;
        }
      } else {
        const current = await this.readGraphNodePath(phase, "cleanup", this.graphPathIdentity);
        if (!exactData(current, this.graphPathIdentity)) throw new Failure("cleanup");
      }
    }
    let providerProved = false;
    if (this.graphProviderIdentity !== undefined && this.graphPodDeleteMayHaveApplied) {
      const retained = this.graphProviderIdentity;
      const reconciled = await this.reconcileGraphPodDeleteForCleanup(phase);
      if (reconciled === undefined) {
        this.graphProviderIdentity = undefined;
        this.graphProviderAbsenceIdentity = graphProviderAbsenceIdentity("neo4j", retained);
      } else {
        this.graphProviderIdentity = reconciled;
      }
      this.graphPodDeleteMayHaveApplied = false;
      providerProved = true;
    }
    if (this.graphProviderIdentity !== undefined && this.graphHealthDeleteMayHaveApplied) {
      const retained = this.graphProviderIdentity;
      const reconciled = await this.reconcileGraphHealthForCleanup(phase, false);
      if (reconciled === undefined) {
        this.graphProviderIdentity = undefined;
        this.graphProviderAbsenceIdentity = graphProviderAbsenceIdentity("health", retained);
      } else {
        this.graphProviderIdentity = reconciled;
      }
      this.graphHealthDeleteMayHaveApplied = false;
      providerProved = true;
    }
    if (this.graphProviderIdentity !== undefined && this.graphHealthApplyMayHaveApplied) {
      const retained = this.graphProviderIdentity;
      const reconciled = await this.reconcileGraphHealthForCleanup(phase, true);
      if (reconciled === undefined) {
        this.graphProviderIdentity = undefined;
        this.graphProviderAbsenceIdentity = graphProviderAbsenceIdentity("health", retained);
      } else {
        this.graphProviderIdentity = reconciled;
        this.graphProviderAbsenceIdentity = undefined;
      }
      this.graphHealthApplyMayHaveApplied = false;
      providerProved = true;
    }
    if (this.graphProviderAbsenceIdentity !== undefined && !providerProved &&
        !this.graphHealthApplyMayHaveApplied && !this.graphHealthDeleteMayHaveApplied &&
        !this.graphPodDeleteMayHaveApplied) {
      await this.reconcileGraphProviderAbsenceForCleanup(phase);
      providerProved = true;
    }
    if (this.graphProviderIdentity !== undefined && this.graphProviderAbsenceIdentity === undefined &&
        !providerProved) {
      try {
        validateGraphKubernetesState(
          await this.readGraphProviderState(phase, "cleanup"), this.graphProviderExpectation(),
          this.graphProviderIdentity, false,
        );
      } catch {
        throw new Failure("cleanup");
      }
    }
  }

  async reconcileGraphPodDeleteForCleanup(phase) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      phase.assertActive("cleanup");
      try {
        const providerState = await this.readGraphProviderState(phase, "cleanup");
        try {
          return validateGraphKubernetesState(
            providerState, this.graphProviderExpectation(), this.graphProviderIdentity, false,
          );
        } catch {
          try {
            return validateGraphKubernetesState(
              providerState, this.graphProviderExpectation(), this.graphProviderIdentity, true,
            );
          } catch {
            if (validateGraphProviderAbsence(
              providerState, this.graphProviderExpectation(), this.graphProviderIdentity, "neo4j",
            )) return undefined;
          }
        }
      } catch {
        // Retry only within this fixed cleanup reconciliation bound.
      }
      if (attempt + 1 < 3) await this.pauseGraphPoll(phase, "cleanup");
    }
    throw new Failure("cleanup");
  }

  async reconcileGraphHealthForCleanup(phase, applying) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      phase.assertActive("cleanup");
      try {
        const providerState = await this.readGraphProviderState(phase, "cleanup", true);
        if (!applying) {
          try {
            return validateGraphKubernetesState(
              providerState, this.graphProviderExpectation(), this.graphProviderIdentity, false,
            );
          } catch {
            // A settled delete may instead leave the exact Job and Pod absent.
          }
        } else {
          try {
            return validateGraphKubernetesState(
              providerState, this.graphProviderExpectation(), this.graphProviderIdentity, false, true,
            );
          } catch {
            // A settled apply may instead leave the exact pre-apply absence.
          }
        }
        if (validateGraphProviderAbsence(
          providerState, this.graphProviderExpectation(), this.graphProviderIdentity, "health",
        )) return undefined;
      } catch {
        // Retry only within this fixed cleanup reconciliation bound.
      }
      if (attempt + 1 < 3) await this.pauseGraphPoll(phase, "cleanup");
    }
    throw new Failure("cleanup");
  }

  async reconcileGraphProviderAbsenceForCleanup(phase) {
    const authority = this.graphProviderAbsenceIdentity;
    try {
      requireExactKeySet(authority, ["absent", "retained"], "graph provider absence identity");
      if (!new Set(["health", "neo4j"]).has(authority.absent)) throw new TypeError("invalid absence");
    } catch {
      throw new Failure("cleanup");
    }
    for (let attempt = 0; attempt < 3; attempt += 1) {
      phase.assertActive("cleanup");
      try {
        const providerState = await this.readGraphProviderState(phase, "cleanup", authority.absent === "health");
        if (validateGraphProviderAbsence(
          providerState, this.graphProviderExpectation(), authority.retained, authority.absent,
        )) return true;
      } catch {
        // Retry only within this fixed cleanup reconciliation bound.
      }
      if (attempt + 1 < 3) await this.pauseGraphPoll(phase, "cleanup");
    }
    throw new Failure("cleanup");
  }

  async afterClusterAbsent() {
    this.graphNodeMayHaveApplied = false;
    this.graphPathMayHaveApplied = false;
    this.graphNodeIdentity = undefined;
    this.graphPathIdentity = undefined;
    this.graphLoadedImageTargets.clear();
    this.graphNodeImageInventory = undefined;
    this.graphProviderIdentity = undefined;
    this.graphMarkerMayHaveApplied = false;
    this.graphPodDeleteMayHaveApplied = false;
    this.graphHealthDeleteMayHaveApplied = false;
    this.graphHealthApplyMayHaveApplied = false;
    this.graphProviderAbsenceIdentity = undefined;
  }

  async reconcileGraphImage(selected, phase) {
    const inspectAlias = async () => {
      const result = await this.runRaw(
        "docker", ["image", "inspect", selected.repoDigest], phase, "cleanup", 15_000, 262_144,
      );
      if (exactMissingGraphImage(result, selected.repoDigest)) return false;
      if (!isPlainObject(result) || result.status !== 0 || result.signal !== null || result.stderr !== "" ||
          result.stdout === "" || result.thrown !== false || result.timedOut !== false) throw new Failure("cleanup");
      return true;
    };
    let present = await inspectAlias();
    if (!present) present = await inspectAlias();
    if (!present) return undefined;
    const resolution = this.graphImageResolutions.get(selected.name);
    if (resolution === undefined) throw new Failure("cleanup");
    const retained = await this.inspectGraphImage(
      selected, resolution, phase, undefined, selected.repoDigest, "cleanup",
    );
    if ([...this.imageIdentities.values(), ...this.graphImageIdentities.values()]
      .some((value) => value.id === retained.id)) throw new Failure("cleanup");
    this.graphImageIdentities.set(selected.name, retained);
    this.graphImageAliases.set(selected.name, {
      repoDigests: [selected.repoDigest],
      repoTags: [],
    });
    return retained;
  }

  async requireGraphImageAbsent(selected, retained, phase) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const inspected = await this.runRaw("docker", ["image", "inspect", retained.id], phase, "cleanup");
      if (inspected.status === 0 && inspected.stderr === "" && inspected.stdout !== "") continue;
      if (!exactMissingGraphImage(inspected, retained.id)) throw new Failure("cleanup");
      const listed = await this.runRead("docker", [
        "image", "ls", "--quiet", "--no-trunc", "--filter", `reference=${selected.reference}`,
      ], phase, "cleanup");
      if (listed.stdout === "") return;
    }
    throw new Failure("cleanup");
  }

  async cleanupAdditionalImages(step, phase) {
    for (const selected of [...this.graphImagePlans.values()].reverse()) {
      let retained = this.graphImageIdentities.get(selected.name);
      if (retained === undefined && this.graphImageMayHaveApplied.has(selected.name)) {
        await step(async () => {
          retained = await this.reconcileGraphImage(selected, phase);
          if (retained === undefined) this.graphImageMayHaveApplied.delete(selected.name);
        });
      }
      if (retained === undefined) continue;
      const sharedBaseline = this.graphSharedImageBaselines.get(selected.name);
      if (sharedBaseline !== undefined) {
        await step(async () => {
          const resolution = this.graphImageResolutions.get(selected.name);
          if (resolution === undefined || this.graphImageMayHaveApplied.has(selected.name)) {
            throw new Failure("cleanup");
          }
          await this.requireTemporaryOwnership(phase, "cleanup");
          await this.requireOwnedPath(this.paths.graphManifest, phase, "cleanup");
          await this.readGraphImageBaseline(selected, resolution, phase, "cleanup", sharedBaseline);
          this.graphImageIdentities.delete(selected.name);
          this.graphImageAliases.delete(selected.name);
        });
        continue;
      }
      await step(async () => {
        await this.requireTemporaryOwnership(phase, "cleanup");
        await this.requireOwnedPath(this.paths.graphManifest, phase, "cleanup");
        await this.verifyGraphImage(selected, retained, phase, "cleanup");
        await this.requireGraphImageConsumersAbsent(selected, phase, "cleanup");
        const removedDigest = await this.runMutation("docker", [
          "image", "rm", selected.repoDigest,
        ], phase, "cleanup", {
          environment: this.environment,
          outputLimit: 262_144,
          timeoutMilliseconds: 60_000,
        });
        if (removedDigest.outcome === "definitive") throw new Failure("cleanup");
        await this.requireGraphImageAbsent(selected, retained, phase);
        this.graphImageIdentities.delete(selected.name);
        this.graphImageAliases.delete(selected.name);
        this.graphImageMayHaveApplied.delete(selected.name);
        this.graphImageResolutions.delete(selected.name);
      });
    }
  }

  async requireAdditionalGlobalAbsence(phase, category) {
    for (const selected of this.graphImagePlans.values()) {
      const sharedBaseline = this.graphSharedImageBaselines.get(selected.name);
      if (sharedBaseline === undefined) {
        await this.requireGraphImageBaselineAbsent(selected, phase, category);
      } else {
        const resolution = this.graphImageResolutions.get(selected.name);
        if (resolution === undefined || this.graphImageIdentities.has(selected.name) ||
            this.graphImageAliases.has(selected.name) || this.graphImageMayHaveApplied.has(selected.name)) {
          throw new Failure(category);
        }
        await this.readGraphImageBaseline(selected, resolution, phase, category, sharedBaseline);
      }
    }
    for (const selected of this.graphImagePlans.values()) {
      this.graphSharedImageBaselines.delete(selected.name);
      this.graphImageBaselineAbsences.delete(selected.name);
      this.graphImageResolutions.delete(selected.name);
    }
  }

  hasAdditionalRecoveryState() {
    return this.graphImageIdentities.size !== 0 || this.graphImageMayHaveApplied.size !== 0 ||
      this.graphImageAliases.size !== 0 || this.graphNodeMayHaveApplied || this.graphPathMayHaveApplied ||
      this.graphProviderIdentity !== undefined || this.graphMarkerMayHaveApplied || this.graphPodDeleteMayHaveApplied ||
      this.graphHealthDeleteMayHaveApplied || this.graphHealthApplyMayHaveApplied ||
      this.graphProviderAbsenceIdentity !== undefined;
  }
}

export class DockerKindGraphRuntime extends DockerKindRuntime {
  constructor(input, system = undefined) {
    super(input, system ?? new LocalGraphSystem(input));
    if (input.hostPlatform.slice(input.hostPlatform.indexOf("/") + 1) !==
        input.nodePlatform.slice("linux/".length)) throw new TypeError("graph runtime platform is invalid");
  }

  static fromProcess(environment = process.env, systemFactory = (input) => new LocalGraphSystem(input)) {
    if (environment === null || typeof environment !== "object" || Array.isArray(environment)) {
      throw new Failure("configuration");
    }
    for (const [name, value] of Object.entries(environment)) {
      if (graphForbiddenGoEnvironment.test(name) && value !== undefined && value !== "") {
        throw new Failure("configuration");
      }
    }
    const selected = DockerKindRuntime.fromProcess(environment, systemFactory);
    return new DockerKindGraphRuntime(selected.input, selected.system);
  }
}

export async function runGraphMain(runtime = undefined, options = {}) {
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const setExitCode = options.setExitCode ?? ((value) => { process.exitCode = value; });
  try {
    const selected = runtime ?? DockerKindGraphRuntime.fromProcess();
    const result = await orchestrate(guardGraphLifecycle(selected), {
      cleanupTimeoutMilliseconds: options.cleanupTimeoutMilliseconds ?? graphCleanupTimeoutMilliseconds,
      mainTimeoutMilliseconds: options.mainTimeoutMilliseconds ?? graphMainTimeoutMilliseconds,
      settlementTimeoutMilliseconds: options.settlementTimeoutMilliseconds ?? graphSettlementTimeoutMilliseconds,
    });
    validateGraphResult(result);
    stdout.write(`${GRAPH_SUCCESS_LINE}\n`);
    setExitCode(0);
    return 0;
  } catch (error) {
    const category = GRAPH_FAILURE_CATEGORIES.includes(error?.category) ? error.category : "panic";
    stderr.write(`Local graph manifest failed: ${category} rejected.\n`);
    setExitCode(1);
    return 1;
  }
}

function guardGraphLifecycle(runtime) {
  if (runtime === null || typeof runtime !== "object") throw new TypeError("graph runtime is invalid");
  const guarded = {};
  for (const name of [
    "initialize", "preflight", "buildImages", "createNetwork", "createCluster", "loadImages",
    "applyManifests", "verifyReadiness",
  ]) {
    if (typeof runtime[name] !== "function") throw new TypeError(`graph runtime ${name} is invalid`);
    guarded[name] = (phase) => runtime[name](phase);
  }
  for (const name of ["joinMutations", "cleanup", "auditAbsence"]) {
    if (typeof runtime[name] !== "function") throw new TypeError(`graph runtime ${name} is invalid`);
    guarded[name] = async (phase) => {
      try {
        return await runtime[name](phase);
      } catch (error) {
        if (error instanceof Failure) throw error;
        throw new GraphFailure("cleanup");
      }
    };
  }
  return Object.freeze(guarded);
}

function validateGraphResult(value) {
  if (!isPlainObject(value) || value.cleanup !== true || value.internal !== true || value.pods !== 4 ||
      value.ready !== 4 || value.services !== 4 || !isPlainObject(value.graph) ||
      !exactKeySet(value.graph, ["internal", "persistent", "ready"]) || value.graph.internal !== true ||
      value.graph.persistent !== true || value.graph.ready !== true) throw new Failure("readiness");
}

function validateSelectedPlan(value) {
  if (!isPlainObject(value) || !exactKeySet(value, [
    "architecture", "configDigest", "indexDigest", "manifestDigest", "name", "platform", "providerReference",
    "reference", "repoDigest", "repository", "selectedReference", "tag",
  ])) throw new TypeError("graph image plan is invalid");
  const expected = value.name === "collector"
    ? buildCollectorImagePlan(value.platform)
    : value.name === "localstack"
      ? buildLocalStackImagePlan(value.platform)
      : buildGraphImagePlan(value.name, value.platform);
  if (!exactData(value, expected)) throw new TypeError("graph image plan is invalid");
}

function validatePlatformDescriptor(value) {
  if (!isPlainObject(value) || !new Set([2, 3, 4]).has(Object.keys(value).length) ||
      typeof value.architecture !== "string" || value.architecture.length === 0 || value.architecture.length > 64 ||
      typeof value.os !== "string" || value.os.length === 0 || value.os.length > 64 ||
      value.variant !== undefined && (typeof value.variant !== "string" || value.variant.length > 64) ||
      value["os.version"] !== undefined && (typeof value["os.version"] !== "string" || value["os.version"].length > 256) ||
      Object.keys(value).some((key) => !new Set(["architecture", "os", "os.version", "variant"]).has(key))) {
    throw new TypeError("graph platform is invalid");
  }
}

function validateContentDescriptor(value, mediaTypes, maximumSize) {
  requireExactKeySet(value, ["digest", "mediaType", "size"], "content descriptor");
  if (!digestPattern.test(value.digest) || !mediaTypes.has(value.mediaType) ||
      !Number.isSafeInteger(value.size) || value.size < 1 || value.size > maximumSize) {
    throw new TypeError("content descriptor is invalid");
  }
}

function validateStringMap(value, maximumKeys, maximumLength) {
  if (!isPlainObject(value) || Object.keys(value).length > maximumKeys || Object.entries(value).some(([key, item]) =>
    key.length === 0 || key.length > maximumLength || typeof item !== "string" || item.length > maximumLength)) {
    throw new TypeError("string map is invalid");
  }
}

function validNullableStringMap(value, maximumKeys, maximumLength) {
  if (value === null) return true;
  try { validateStringMap(value, maximumKeys, maximumLength); return true; }
  catch { return false; }
}

function validStringArray(value, maximumItems, maximumLength) {
  return Array.isArray(value) && value.length <= maximumItems && new Set(value).size === value.length &&
    value.every((item) => typeof item === "string" && item.length > 0 && item.length <= maximumLength &&
      !hasControlCharacter(item));
}

function nullableStringArray(value, maximumItems, maximumLength) {
  return value === null || validStringArray(value, maximumItems, maximumLength);
}

function uniqueEnvironment(value) {
  const names = new Set();
  return value.every((entry) => {
    const separator = entry.indexOf("=");
    if (separator < 1) return false;
    const name = entry.slice(0, separator);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || names.has(name)) return false;
    names.add(name);
    return true;
  });
}

function validEmptyObjectMap(value, keyPattern, maximumKeys) {
  return value === null || isPlainObject(value) && Object.keys(value).length <= maximumKeys &&
    Object.entries(value).every(([key, item]) => keyPattern.test(key) && isPlainObject(item) &&
      Object.keys(item).length === 0);
}

function requireExactKeySet(value, keys, label) {
  if (!isPlainObject(value) || !exactKeySet(value, keys)) throw new TypeError(`${label} is invalid`);
}

function exactKeySet(value, keys) {
  return isPlainObject(value) && Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function exactStringArray(value, expected) {
  return Array.isArray(value) && value.length === expected.length &&
    value.every((item, index) => item === expected[index]);
}

function exactData(value, expected) {
  if (Array.isArray(expected)) {
    return Array.isArray(value) && value.length === expected.length &&
      expected.every((item, index) => exactData(value[index], item));
  }
  if (isPlainObject(expected)) {
    return isPlainObject(value) && Object.keys(value).length === Object.keys(expected).length &&
      Object.keys(expected).every((key) => Object.hasOwn(value, key) && exactData(value[key], expected[key]));
  }
  return value === expected && typeof value === typeof expected;
}

function exactMissingFormattedGraphImage(result, id) {
  return exactMissingGraphImageResult(result, id, "\n");
}

function exactMissingGraphImage(result, id) {
  return exactMissingGraphImageResult(result, id, "[]\n");
}

function exactMissingGraphImageResult(result, id, stdout) {
  return isPlainObject(result) && result.status === 1 && result.signal === null && result.stdout === stdout &&
    result.thrown === false && result.timedOut === false && new Set([
      `Error response from daemon: No such image: ${id}\n`,
      `Error: No such image: ${id}\n`,
    ]).has(result.stderr);
}

function hasControlCharacter(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runGraphMain();
}
