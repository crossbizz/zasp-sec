import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { buildAwsEmulatorResources } from "./aws-emulator-manifest.mjs";
import {
  AWS_EMULATOR_FAILURE_CATEGORIES,
  AWS_EMULATOR_SUCCESS_LINE,
  awsEmulatorApplyPlan,
  buildAwsEmulatorProfile,
  runAwsEmulatorMain,
} from "./aws-emulator-run.mjs";
import { buildGraphResources } from "./graph-manifest.mjs";
import { buildProductResources } from "./manifests.mjs";
import { buildObservabilityResources } from "./observability-manifest.mjs";

const exactExposure = Object.freeze({
  clusterIPServices: 7,
  configMaps: 2,
  dashboardsPublished: 0,
  deployments: 7,
  externalServices: 0,
  hostNamespaces: 0,
  hostPathVolumes: 0,
  hostPorts: 0,
  ingresses: 0,
  jobs: 3,
  persistentVolumeClaims: 1,
  persistentVolumes: 1,
  resources: 22,
});

export const LOCAL_START_TARGET = deepFreeze({
  command: "npm run local:start",
  dependencies: ["m1-30a", "m1-30b", "m1-30c", "m1-30d"],
  entrypoint: "node deploy/local/start.mjs",
  failureCategories: [...AWS_EMULATOR_FAILURE_CATEGORIES],
  manifests: [
    "product-stubs.yaml",
    "graph.yaml",
    "observability.yaml",
    "observability-span.yaml",
    "aws-emulator.yaml",
    "aws-emulator-s3.yaml",
  ],
  profile: "m1-30d",
  successLine: AWS_EMULATOR_SUCCESS_LINE,
});

export function projectLocalStartExposure(value) {
  const resources = strictSnapshot(value);
  if (!Array.isArray(resources) || resources.length !== exactExposure.resources) {
    throw new TypeError("local start resources are invalid");
  }
  const resourceReferences = new Set();
  for (const resource of value) {
    if (resource === null || typeof resource !== "object" || resourceReferences.has(resource)) {
      throw new TypeError("local start resources are invalid");
    }
    resourceReferences.add(resource);
  }

  const counts = {
    ConfigMap: 0,
    Deployment: 0,
    Ingress: 0,
    Job: 0,
    Namespace: 0,
    PersistentVolume: 0,
    PersistentVolumeClaim: 0,
    Service: 0,
  };
  let externalServices = 0;
  let hostNamespaces = 0;
  let hostPathVolumes = 0;
  let hostPorts = 0;

  for (const resource of resources) {
    if (!isPlainObject(resource) || typeof resource.kind !== "string" || !Object.hasOwn(counts, resource.kind)) {
      throw new TypeError("local start resource is invalid");
    }
    counts[resource.kind] += 1;
    if (resource.kind === "Service") {
      if (!isPlainObject(resource.spec)) throw new TypeError("local start Service is invalid");
      const externalKeys = ["externalIPs", "externalName", "externalTrafficPolicy", "loadBalancerIP", "loadBalancerSourceRanges"];
      const ports = Array.isArray(resource.spec.ports) ? resource.spec.ports : [];
      if (resource.spec.type !== "ClusterIP" || externalKeys.some((key) => Object.hasOwn(resource.spec, key)) ||
          ports.some((port) => isPlainObject(port) && Object.hasOwn(port, "nodePort"))) externalServices += 1;
    }
    const podSpec = resource.kind === "Deployment" || resource.kind === "Job" ? resource.spec?.template?.spec : undefined;
    if (podSpec !== undefined) {
      if (!isPlainObject(podSpec)) throw new TypeError("local start pod template is invalid");
      if (podSpec.hostNetwork === true || podSpec.hostPID === true || podSpec.hostIPC === true) hostNamespaces += 1;
      for (const container of [...arrayOrEmpty(podSpec.initContainers), ...arrayOrEmpty(podSpec.containers)]) {
        if (!isPlainObject(container)) throw new TypeError("local start container is invalid");
        for (const port of arrayOrEmpty(container.ports)) {
          if (!isPlainObject(port)) throw new TypeError("local start port is invalid");
          if (Object.hasOwn(port, "hostPort")) hostPorts += 1;
        }
        for (const mount of arrayOrEmpty(container.volumeMounts)) {
          if (!isPlainObject(mount)) throw new TypeError("local start mount is invalid");
          if (mount.mountPath === "/var/run/docker.sock" || mount.mountPath === "/run/docker.sock") hostPathVolumes += 1;
        }
      }
      for (const volume of arrayOrEmpty(podSpec.volumes)) {
        if (!isPlainObject(volume)) throw new TypeError("local start volume is invalid");
        if (Object.hasOwn(volume, "hostPath")) hostPathVolumes += 1;
      }
    }
  }

  const projection = {
    clusterIPServices: counts.Service - externalServices,
    configMaps: counts.ConfigMap,
    dashboardsPublished: counts.Ingress + externalServices + hostNamespaces + hostPathVolumes + hostPorts,
    deployments: counts.Deployment,
    externalServices,
    hostNamespaces,
    hostPathVolumes,
    hostPorts,
    ingresses: counts.Ingress,
    jobs: counts.Job,
    persistentVolumeClaims: counts.PersistentVolumeClaim,
    persistentVolumes: counts.PersistentVolume,
    resources: resources.length,
  };
  if (counts.Namespace !== 1 || !isDeepStrictEqual(projection, exactExposure)) {
    throw new TypeError("local start exposure is invalid");
  }
  return deepFreeze(projection);
}

export function validateLocalStartAssembly(...input) {
  if (input.length !== 0) throw new TypeError("local start assembly accepts no caller input");
  const exposure = projectLocalStartExposure([
    ...buildProductResources(),
    ...buildGraphResources(),
    ...buildObservabilityResources(),
    ...buildAwsEmulatorResources(),
  ]);
  const profile = buildAwsEmulatorProfile();
  const applyPlan = awsEmulatorApplyPlan();
  if (profile.proof !== LOCAL_START_TARGET.profile ||
      !isDeepStrictEqual(profile.manifests.map(({ name }) => name), LOCAL_START_TARGET.manifests.slice(1)) ||
      !isDeepStrictEqual(applyPlan, {
        base: ["graphManifest", "observabilityCoreManifest", "awsEmulatorCoreManifest"],
        staged: ["observabilitySpanManifest", "awsEmulatorS3Manifest"],
      })) throw new TypeError("local start assembly is invalid");
  return exposure;
}

export async function runLocalStartMain(runtime = undefined, options = {}) {
  validateLocalStartAssembly();
  return await runAwsEmulatorMain(runtime, options);
}

function arrayOrEmpty(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new TypeError("local start array is invalid");
  return value;
}

function strictSnapshot(value, active = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean" ||
      (typeof value === "number" && Number.isFinite(value))) return value;
  if (typeof value !== "object" || active.has(value)) throw new TypeError("local start value is invalid");
  const array = Array.isArray(value);
  if (Object.getPrototypeOf(value) !== (array ? Array.prototype : Object.prototype)) {
    throw new TypeError("local start value is invalid");
  }
  active.add(value);
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) throw new TypeError("local start value is invalid");
    if (array) {
      const length = Object.getOwnPropertyDescriptor(value, "length");
      if (length === undefined || !("value" in length) || !Number.isSafeInteger(length.value) || length.value < 0 ||
          length.enumerable || keys.length !== length.value + 1 || keys[length.value] !== "length") {
        throw new TypeError("local start array is invalid");
      }
      return Array.from({ length: length.value }, (_unused, index) => {
        if (keys[index] !== String(index)) throw new TypeError("local start array is invalid");
        return strictSnapshot(dataValue(value, String(index)), active);
      });
    }
    const snapshot = {};
    for (const key of keys) snapshot[key] = strictSnapshot(dataValue(value, key), active);
    return snapshot;
  } finally {
    active.delete(value);
  }
}

function dataValue(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
    throw new TypeError("local start value is invalid");
  }
  return descriptor.value;
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

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runLocalStartMain();
}
