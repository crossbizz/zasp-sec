import { fileURLToPath } from "node:url";

import { GRAPH_CONSTANTS, GRAPH_IMAGES, buildGraphResources, renderGraphManifest } from "./graph-manifest.mjs";
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
    const expectedAliases = aliases ?? { repoDigests: [selected.repoDigest], repoTags: [selected.tag] };
    requireExactKeySet(expectedAliases, ["repoDigests", "repoTags"], "graph image aliases");
    if (!(exactStringArray(expectedAliases.repoDigests, []) ||
        exactStringArray(expectedAliases.repoDigests, [selected.repoDigest])) ||
        !(exactStringArray(expectedAliases.repoTags, []) || exactStringArray(expectedAliases.repoTags, [selected.tag]))) {
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

export function parseGraphContainerdImageTargets(source, platform) {
  try {
    if (typeof source !== "string" || Buffer.byteLength(source) < 1 || Buffer.byteLength(source) > 4_194_304 ||
        !source.endsWith("\n") || !new Set(["linux/amd64", "linux/arm64"]).has(platform)) {
      throw new TypeError("graph containerd inventory is invalid");
    }
    const lines = source.slice(0, -1).split("\n");
    if (!exactStringArray(lines[0]?.trim().split(/\s+/), ["REF", "TYPE", "DIGEST", "SIZE", "PLATFORMS", "LABELS"])) {
      throw new TypeError("graph containerd inventory is invalid");
    }
    const selected = new Map(Object.keys(GRAPH_IMAGE_PLANS).map((name) => [name, buildGraphImagePlan(name, platform)]));
    const targets = new Map();
    for (const line of lines.slice(1)) {
      if (line.length === 0) throw new TypeError("graph containerd inventory is invalid");
      const fields = line.trim().split(/\s+/);
      if (fields.length < 6) throw new TypeError("graph containerd inventory is invalid");
      const image = [...selected.values()].find(({ providerReference }) => providerReference === fields[0]);
      if (image === undefined) continue;
      const size = fields.slice(3, -2).join(" ");
      if (targets.has(image.name) || !new Set([
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
      ]).has(fields[1]) || fields[2] !== image.manifestDigest ||
          !/^\d+(?:\.\d+)? ?(?:B|KiB|MiB|GiB)$/.test(size) || fields.at(-2) !== platform ||
          typeof fields.at(-1) !== "string" || fields.at(-1).length === 0) {
        throw new TypeError("graph containerd target is invalid");
      }
      targets.set(image.name, fields[2]);
    }
    if (targets.size !== selected.size) throw new TypeError("graph containerd inventory is incomplete");
    return new Map([...targets].sort(([left], [right]) => left.localeCompare(right)));
  } catch (error) {
    if (error instanceof GraphFailure) throw error;
    throw new GraphFailure("provider");
  }
}

export function validateGraphNodeLabel(document, expected, retained = undefined, labeled = true) {
  try {
    requireExactKeySet(expected, ["name", "token"], "graph node expectation");
    if (typeof expected.name !== "string" || !/^zasp-m1-30b-[0-9a-f]{16}-control-plane$/.test(expected.name) ||
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

export class LocalGraphSystem extends LocalProductSystem {
  constructor(input, dependencies = undefined) {
    super(input, dependencies, {
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
    this.graphLoadedImageTargets = new Map();
    this.graphImageMayHaveApplied = new Set();
    this.graphNodeIdentity = undefined;
    this.graphPathIdentity = undefined;
    this.graphNodeMayHaveApplied = false;
    this.graphPathMayHaveApplied = false;
  }

  async runAdditionalPreflightChecks(phase) {
    for (const selected of this.graphImagePlans.values()) {
      await this.requireGraphImageBaselineAbsent(selected, phase, "configuration");
    }
  }

  async requireGraphImageConsumersAbsent(selected, phase, category) {
    const result = await this.runRead("docker", [
      "ps", "--all", "--quiet", "--no-trunc", "--filter", `ancestor=${selected.configDigest}`,
    ], phase, category);
    if (result.stdout !== "") throw new Failure(category);
  }

  async requireGraphImageBaselineAbsent(selected, phase, category = "ownership") {
    const inspected = await this.runRaw(
      "docker", ["image", "inspect", selected.configDigest], phase, category, 15_000, 262_144,
    );
    if (!exactMissingGraphImage(inspected, selected.configDigest)) throw new Failure(category);
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
    const format = "[{{json .Architecture}},{{json .Os}},{{json .Id}},{{json .RepoDigests}},{{json .RepoTags}},{{json .RootFS}},{{json .Config.Env}},{{json .Config.Entrypoint}},{{json .Config.Cmd}},{{json .Config.ExposedPorts}},{{json .Config.Volumes}},{{json .Config.Labels}},{{json .Config.User}},{{json .Config.WorkingDir}}]";
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
      const resolution = await this.resolveGraphImage(selected, phase);
      this.graphImageResolutions.set(selected.name, resolution);
      await this.requireGraphImageBaselineAbsent(selected, phase);
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
      if ([...this.imageIdentities.values(), ...this.graphImageIdentities.values()]
        .some((value) => value.id === identity.id)) throw new GraphFailure("ownership");
      await this.requireGraphImageConsumersAbsent(selected, phase, "ownership");
      this.graphImageIdentities.set(selected.name, identity);
      this.graphImageAliases.set(selected.name, {
        repoDigests: [selected.repoDigest],
        repoTags: [selected.tag],
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
      const loaded = await this.runMutation(this.paths.kind, [
        "load", "docker-image", selected.reference, "--name", this.cluster,
      ], phase, "provider", {
        environment: this.environment,
        outputLimit: 4_194_304,
        timeoutMilliseconds: 180_000,
      });
      if (loaded.outcome === "definitive") throw new Failure("provider");
    }
    const listed = await this.runNodeRead([
      "ctr", "--namespace", "k8s.io", "images", "list",
    ], phase, "provider", 30_000, 4_194_304);
    this.graphLoadedImageTargets = parseGraphContainerdImageTargets(listed.stdout, this.input.nodePlatform);
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
    await this.requireOwnedPath(path, phase, "ownership");
  }

  async verifyAdditionalReadiness() {
    // Task 4 owns graph provider normalization, health, pod replacement, and persistence.
    throw new Failure("readiness");
  }

  async verifyAdditionalNodeForCleanup(phase) {
    await this.requireTemporaryOwnership(phase, "cleanup");
    await this.requireOwnedPath(this.paths.graphManifest, phase, "cleanup");
    await this.verifyCluster(phase, "cleanup");
    if (!this.graphNodeMayHaveApplied && !this.graphPathMayHaveApplied) return;
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
  }

  async afterClusterAbsent() {
    this.graphNodeMayHaveApplied = false;
    this.graphPathMayHaveApplied = false;
    this.graphNodeIdentity = undefined;
    this.graphPathIdentity = undefined;
    this.graphLoadedImageTargets.clear();
  }

  async reconcileGraphImage(selected, phase) {
    const list = async () => {
      const result = await this.runRead("docker", [
        "image", "ls", "--quiet", "--no-trunc", "--filter", `reference=${selected.reference}`,
      ], phase, "cleanup");
      if (result.stdout === "") return [];
      if (!result.stdout.endsWith("\n")) throw new Failure("cleanup");
      const values = result.stdout.slice(0, -1).split("\n");
      if (new Set(values).size !== values.length || values.some((value) => !digestPattern.test(value))) {
        throw new Failure("cleanup");
      }
      return values;
    };
    let candidates = await list();
    if (candidates.length === 0) candidates = await list();
    if (candidates.length === 0) return undefined;
    if (candidates.length !== 1) throw new Failure("cleanup");
    const resolution = this.graphImageResolutions.get(selected.name);
    if (resolution === undefined) throw new Failure("cleanup");
    const retained = await this.inspectGraphImage(selected, resolution, phase, undefined, candidates[0], "cleanup");
    if (retained.id !== candidates[0] || [...this.imageIdentities.values(), ...this.graphImageIdentities.values()]
      .some((value) => value.id === retained.id)) throw new Failure("cleanup");
    this.graphImageIdentities.set(selected.name, retained);
    this.graphImageAliases.set(selected.name, {
      repoDigests: [selected.repoDigest],
      repoTags: [selected.tag],
    });
    return retained;
  }

  async readGraphImageAliases(selected, retained, phase) {
    const format = "[{{json .Id}},{{json .RepoDigests}},{{json .RepoTags}}]";
    const result = await this.runRead(
      "docker", ["image", "inspect", "--format", format, retained.id], phase, "cleanup", 15_000, 262_144,
    );
    let document;
    try { document = parseBoundedJson(result.stdout, 262_144); }
    catch { throw new Failure("cleanup"); }
    if (!Array.isArray(document) || document.length !== 3 || document[0] !== retained.id ||
        !(exactStringArray(document[1], []) || exactStringArray(document[1], [selected.repoDigest])) ||
        !(exactStringArray(document[2], []) || exactStringArray(document[2], [selected.tag])) ||
        document[1].length === 0 && document[2].length === 0) throw new Failure("cleanup");
    return Object.freeze({ repoDigests: Object.freeze([...document[1]]), repoTags: Object.freeze([...document[2]]) });
  }

  async reconcileGraphImageAliases(selected, retained, expected, phase) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const aliases = await this.readGraphImageAliases(selected, retained, phase);
      if (exactData(aliases, expected)) {
        this.graphImageAliases.set(selected.name, aliases);
        return;
      }
    }
    throw new Failure("cleanup");
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
      await step(async () => {
        let aliases = this.graphImageAliases.get(selected.name) ?? {
          repoDigests: [selected.repoDigest],
          repoTags: [selected.tag],
        };
        if (aliases.repoTags.length !== 0) {
          await this.requireTemporaryOwnership(phase, "cleanup");
          await this.requireOwnedPath(this.paths.graphManifest, phase, "cleanup");
          await this.verifyGraphImage(selected, retained, phase, "cleanup");
          await this.requireGraphImageConsumersAbsent(selected, phase, "cleanup");
          const removedTag = await this.runMutation("docker", [
            "image", "rm", selected.tag,
          ], phase, "cleanup", {
            environment: this.environment,
            outputLimit: 262_144,
            timeoutMilliseconds: 60_000,
          });
          if (removedTag.outcome === "definitive") throw new Failure("cleanup");
          aliases = { repoDigests: [selected.repoDigest], repoTags: [] };
          await this.reconcileGraphImageAliases(selected, retained, aliases, phase);
        }
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
      await this.requireGraphImageBaselineAbsent(selected, phase, category);
    }
  }

  hasAdditionalRecoveryState() {
    return this.graphImageIdentities.size !== 0 || this.graphImageMayHaveApplied.size !== 0 ||
      this.graphImageAliases.size !== 0 || this.graphNodeMayHaveApplied || this.graphPathMayHaveApplied;
  }
}

export class DockerKindGraphRuntime extends DockerKindRuntime {
  constructor(input, system = undefined) {
    super(input, system ?? new LocalGraphSystem(input));
    if (input.hostPlatform.slice(input.hostPlatform.indexOf("/") + 1) !==
        input.nodePlatform.slice("linux/".length)) throw new TypeError("graph runtime platform is invalid");
  }

  static fromProcess(environment = process.env, systemFactory = (input) => new LocalGraphSystem(input)) {
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
    const result = await orchestrate(selected, {
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
  const expected = buildGraphImagePlan(value.name, value.platform);
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

function exactMissingGraphImage(result, id) {
  return isPlainObject(result) && result.status === 1 && result.signal === null && result.stdout === "[]\n" &&
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
