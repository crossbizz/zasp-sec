import { dump, loadAll, JSON_SCHEMA } from "js-yaml";

const manifestByteLimit = 262_144;
const commonLabels = Object.freeze({
  "app.kubernetes.io/part-of": "zasp",
  "app.kubernetes.io/component": "graph",
  "zasp.dev/environment": "local",
});

export const NEO4J_IMAGE = "neo4j:5.26.28-community@sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357";
export const BUSYBOX_IMAGE = "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9";
export const GRAPH_IMAGES = deepFreeze({ neo4j: NEO4J_IMAGE, health: BUSYBOX_IMAGE });
export const GRAPH_CONSTANTS = deepFreeze({
  namespace: "zasp-local",
  storageClassName: "zasp-local-neo4j",
  persistentVolumeName: "zasp-local-neo4j",
  persistentVolumeClaimName: "neo4j-data",
  nodeDataPath: "/var/lib/zasp/m1-30b/neo4j-data",
  nodeLabelKey: "zasp.dev/graph-node",
  nodeLabelValue: "m1-30b",
});

export function buildGraphResources(...input) {
  if (input.length !== 0) throw new TypeError("graph resources accept no caller input");
  const deploymentLabels = { "app.kubernetes.io/name": "neo4j", ...commonLabels };
  const healthLabels = { "app.kubernetes.io/name": "neo4j-health", ...commonLabels };
  return deepFreeze([
    {
      apiVersion: "v1",
      kind: "PersistentVolume",
      metadata: { labels: { ...commonLabels }, name: GRAPH_CONSTANTS.persistentVolumeName },
      spec: {
        accessModes: ["ReadWriteOnce"],
        capacity: { storage: "1Gi" },
        claimRef: {
          apiVersion: "v1",
          kind: "PersistentVolumeClaim",
          name: GRAPH_CONSTANTS.persistentVolumeClaimName,
          namespace: GRAPH_CONSTANTS.namespace,
        },
        hostPath: { path: GRAPH_CONSTANTS.nodeDataPath, type: "Directory" },
        nodeAffinity: {
          required: {
            nodeSelectorTerms: [{
              matchExpressions: [{
                key: GRAPH_CONSTANTS.nodeLabelKey,
                operator: "In",
                values: [GRAPH_CONSTANTS.nodeLabelValue],
              }],
            }],
          },
        },
        persistentVolumeReclaimPolicy: "Retain",
        storageClassName: GRAPH_CONSTANTS.storageClassName,
        volumeMode: "Filesystem",
      },
    },
    {
      apiVersion: "v1",
      kind: "PersistentVolumeClaim",
      metadata: {
        labels: { ...commonLabels },
        name: GRAPH_CONSTANTS.persistentVolumeClaimName,
        namespace: GRAPH_CONSTANTS.namespace,
      },
      spec: {
        accessModes: ["ReadWriteOnce"],
        resources: { requests: { storage: "1Gi" } },
        storageClassName: GRAPH_CONSTANTS.storageClassName,
        volumeMode: "Filesystem",
        volumeName: GRAPH_CONSTANTS.persistentVolumeName,
      },
    },
    {
      apiVersion: "apps/v1",
      kind: "Deployment",
      metadata: { labels: deploymentLabels, name: "neo4j", namespace: GRAPH_CONSTANTS.namespace },
      spec: {
        progressDeadlineSeconds: 180,
        replicas: 1,
        revisionHistoryLimit: 1,
        selector: { matchLabels: { "app.kubernetes.io/name": "neo4j" } },
        strategy: { type: "Recreate" },
        template: {
          metadata: { labels: deploymentLabels },
          spec: {
            automountServiceAccountToken: false,
            containers: [{
              env: [
                { name: "NEO4J_AUTH", value: "none" },
                { name: "NEO4J_db_tx__log_preallocate", value: "false" },
                { name: "NEO4J_db_tx__log_rotation_size", value: "128K" },
              ],
              image: NEO4J_IMAGE,
              imagePullPolicy: "IfNotPresent",
              livenessProbe: graphProbe(3, 10),
              name: "neo4j",
              ports: [
                { containerPort: 7474, name: "http", protocol: "TCP" },
                { containerPort: 7687, name: "bolt", protocol: "TCP" },
              ],
              readinessProbe: graphProbe(3, 2),
              resources: {
                limits: { cpu: "2", memory: "1Gi" },
                requests: { cpu: "100m", memory: "512Mi" },
              },
              securityContext: {
                allowPrivilegeEscalation: false,
                capabilities: { drop: ["ALL"] },
                privileged: false,
                readOnlyRootFilesystem: false,
                runAsGroup: 7474,
                runAsNonRoot: true,
                runAsUser: 7474,
              },
              startupProbe: graphProbe(60, 2),
              volumeMounts: [
                { mountPath: "/data", name: "data", readOnly: false },
                { mountPath: "/logs", name: "logs", readOnly: false },
              ],
            }],
            dnsPolicy: "ClusterFirst",
            enableServiceLinks: false,
            restartPolicy: "Always",
            securityContext: {
              fsGroup: 7474,
              runAsGroup: 7474,
              runAsNonRoot: true,
              runAsUser: 7474,
              seccompProfile: { type: "RuntimeDefault" },
            },
            terminationGracePeriodSeconds: 30,
            volumes: [
              { name: "data", persistentVolumeClaim: { claimName: GRAPH_CONSTANTS.persistentVolumeClaimName, readOnly: false } },
              { emptyDir: { sizeLimit: "256Mi" }, name: "logs" },
            ],
          },
        },
      },
    },
    {
      apiVersion: "v1",
      kind: "Service",
      metadata: { labels: deploymentLabels, name: "neo4j", namespace: GRAPH_CONSTANTS.namespace },
      spec: {
        ipFamilies: ["IPv4"],
        ipFamilyPolicy: "SingleStack",
        ports: [
          { name: "http", port: 7474, protocol: "TCP", targetPort: "http" },
          { name: "bolt", port: 7687, protocol: "TCP", targetPort: "bolt" },
        ],
        selector: { "app.kubernetes.io/name": "neo4j" },
        sessionAffinity: "None",
        type: "ClusterIP",
      },
    },
    {
      apiVersion: "batch/v1",
      kind: "Job",
      metadata: { labels: healthLabels, name: "neo4j-health", namespace: GRAPH_CONSTANTS.namespace },
      spec: {
        activeDeadlineSeconds: 120,
        backoffLimit: 0,
        template: {
          metadata: { labels: healthLabels },
          spec: {
            automountServiceAccountToken: false,
            containers: [{
              command: [
                "sh",
                "-ec",
                "wget -q -T 2 -O /dev/null http://neo4j.zasp-local.svc.cluster.local:7474/ && printf 'neo4j-health-ready\\n'",
              ],
              image: BUSYBOX_IMAGE,
              imagePullPolicy: "IfNotPresent",
              name: "health",
              resources: {
                limits: { cpu: "50m", memory: "32Mi" },
                requests: { cpu: "5m", memory: "8Mi" },
              },
              securityContext: {
                allowPrivilegeEscalation: false,
                capabilities: { drop: ["ALL"] },
                privileged: false,
                readOnlyRootFilesystem: true,
                runAsGroup: 65532,
                runAsNonRoot: true,
                runAsUser: 65532,
              },
            }],
            dnsPolicy: "ClusterFirst",
            enableServiceLinks: false,
            restartPolicy: "Never",
            securityContext: {
              runAsGroup: 65532,
              runAsNonRoot: true,
              runAsUser: 65532,
              seccompProfile: { type: "RuntimeDefault" },
            },
            terminationGracePeriodSeconds: 5,
          },
        },
      },
    },
  ]);
}

export function validateGraphResources(value) {
  requireExactValue(value, buildGraphResources(), "graph resources");
  return deepFreeze(structuredClone(value));
}

export function renderGraphManifest(value) {
  const items = validateGraphResources(value);
  return dump(
    { apiVersion: "v1", kind: "List", items },
    {
      condenseFlow: false,
      forceQuotes: false,
      indent: 2,
      lineWidth: -1,
      noCompatMode: true,
      noRefs: true,
      schema: JSON_SCHEMA,
      skipInvalid: false,
      sortKeys: false,
    },
  );
}

export function parseGraphManifest(text) {
  if (
    typeof text !== "string" || text.length === 0 ||
    Buffer.byteLength(text, "utf8") > manifestByteLimit ||
    Buffer.from(text, "utf8").toString("utf8") !== text
  ) throw new TypeError("graph manifest is invalid");

  let documents;
  try {
    documents = [];
    loadAll(text, (document) => documents.push(document), {
      filename: "graph.yaml",
      json: false,
      onWarning: () => { throw new TypeError("graph manifest is invalid"); },
      schema: JSON_SCHEMA,
    });
  } catch {
    throw new TypeError("graph manifest is invalid");
  }
  if (documents.length !== 1) throw new TypeError("graph manifest is invalid");
  const document = documents[0];
  requireExactKeys(document, ["apiVersion", "kind", "items"], "graph manifest");
  if (document.apiVersion !== "v1" || document.kind !== "List") throw new TypeError("graph manifest is invalid");
  const resources = validateGraphResources(document.items);
  if (renderGraphManifest(resources) !== text) throw new TypeError("graph manifest is invalid");
  return resources;
}

function graphProbe(failureThreshold, periodSeconds) {
  return {
    failureThreshold,
    periodSeconds,
    successThreshold: 1,
    tcpSocket: { port: "http" },
    timeoutSeconds: 1,
  };
}

function requireExactValue(value, expected, label) {
  if (Array.isArray(expected)) {
    if (!Array.isArray(value) || value.length !== expected.length || !exactArrayShape(value)) {
      throw new TypeError(`${label} are invalid`);
    }
    for (let index = 0; index < expected.length; index += 1) {
      requireExactValue(value[index], expected[index], `${label}[${index}]`);
    }
    return;
  }
  if (isPlainObject(expected)) {
    requireExactKeys(value, Object.keys(expected), label);
    for (const key of Object.keys(expected)) requireExactValue(value[key], expected[key], `${label}.${key}`);
    return;
  }
  if (value !== expected || typeof value !== typeof expected) throw new TypeError(`${label} is invalid`);
}

function requireExactKeys(value, keys, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} is invalid`);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw new TypeError(`${label} is invalid`);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError(`${label} is invalid`);
    }
  }
}

function exactArrayShape(value) {
  const keys = Reflect.ownKeys(value);
  return keys.length === value.length + 1 && keys.every((key, index) => (
    index < value.length ? key === String(index) : key === "length"
  ));
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
