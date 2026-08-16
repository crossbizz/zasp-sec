import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  BUSYBOX_IMAGE,
  GRAPH_CONSTANTS,
  GRAPH_IMAGES,
  NEO4J_IMAGE,
  buildGraphResources,
  parseGraphManifest,
  renderGraphManifest,
  validateGraphResources,
} from "./graph-manifest.mjs";

const manifestPath = join(import.meta.dirname, "graph.yaml");
const commonLabels = {
  "app.kubernetes.io/part-of": "zasp",
  "app.kubernetes.io/component": "graph",
  "zasp.dev/environment": "local",
};

function copy(value) {
  return structuredClone(value);
}

function resource(resources, kind, name) {
  return resources.find((value) => value.kind === kind && value.metadata.name === name);
}

test("pins immutable graph images and caller-input-free local storage constants", () => {
  assert.equal(NEO4J_IMAGE, "neo4j:5.26.28-community@sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357");
  assert.equal(BUSYBOX_IMAGE, "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9");
  assert.deepEqual(GRAPH_IMAGES, { neo4j: NEO4J_IMAGE, health: BUSYBOX_IMAGE });
  assert.deepEqual(GRAPH_CONSTANTS, {
    namespace: "zasp-local",
    storageClassName: "zasp-local-neo4j",
    persistentVolumeName: "zasp-local-neo4j",
    persistentVolumeClaimName: "neo4j-data",
    nodeDataPath: "/var/lib/zasp/m1-30b/neo4j-data",
    nodeLabelKey: "zasp.dev/graph-node",
    nodeLabelValue: "m1-30b",
  });
  for (const value of [GRAPH_IMAGES, GRAPH_CONSTANTS]) assert.ok(Object.isFrozen(value));
  assert.throws(() => buildGraphResources(null), TypeError);
});

test("builds exactly one bound local persistent volume and claim", () => {
  const resources = buildGraphResources();
  assert.equal(resources.length, 5);
  assert.deepEqual(resources.map(({ kind, metadata }) => [kind, metadata.name]), [
    ["PersistentVolume", "zasp-local-neo4j"],
    ["PersistentVolumeClaim", "neo4j-data"],
    ["Deployment", "neo4j"],
    ["Service", "neo4j"],
    ["Job", "neo4j-health"],
  ]);
  assert.deepEqual(resource(resources, "PersistentVolume", "zasp-local-neo4j"), {
    apiVersion: "v1",
    kind: "PersistentVolume",
    metadata: { labels: commonLabels, name: "zasp-local-neo4j" },
    spec: {
      accessModes: ["ReadWriteOnce"],
      capacity: { storage: "1Gi" },
      claimRef: { apiVersion: "v1", kind: "PersistentVolumeClaim", name: "neo4j-data", namespace: "zasp-local" },
      hostPath: { path: "/var/lib/zasp/m1-30b/neo4j-data", type: "Directory" },
      nodeAffinity: {
        required: {
          nodeSelectorTerms: [{
            matchExpressions: [{ key: "zasp.dev/graph-node", operator: "In", values: ["m1-30b"] }],
          }],
        },
      },
      persistentVolumeReclaimPolicy: "Retain",
      storageClassName: "zasp-local-neo4j",
      volumeMode: "Filesystem",
    },
  });
  assert.deepEqual(resource(resources, "PersistentVolumeClaim", "neo4j-data"), {
    apiVersion: "v1",
    kind: "PersistentVolumeClaim",
    metadata: { labels: commonLabels, name: "neo4j-data", namespace: "zasp-local" },
    spec: {
      accessModes: ["ReadWriteOnce"],
      resources: { requests: { storage: "1Gi" } },
      storageClassName: "zasp-local-neo4j",
      volumeMode: "Filesystem",
      volumeName: "zasp-local-neo4j",
    },
  });
});

test("builds one exact hardened Neo4j deployment on the retained claim", () => {
  const deployment = resource(buildGraphResources(), "Deployment", "neo4j");
  const labels = { "app.kubernetes.io/name": "neo4j", ...commonLabels };
  assert.deepEqual(deployment, {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: { labels, name: "neo4j", namespace: "zasp-local" },
    spec: {
      progressDeadlineSeconds: 180,
      replicas: 1,
      revisionHistoryLimit: 1,
      selector: { matchLabels: { "app.kubernetes.io/name": "neo4j" } },
      strategy: { type: "Recreate" },
      template: {
        metadata: { labels },
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
            livenessProbe: {
              failureThreshold: 3,
              periodSeconds: 10,
              successThreshold: 1,
              tcpSocket: { port: "http" },
              timeoutSeconds: 1,
            },
            name: "neo4j",
            ports: [
              { containerPort: 7474, name: "http", protocol: "TCP" },
              { containerPort: 7687, name: "bolt", protocol: "TCP" },
            ],
            readinessProbe: {
              failureThreshold: 3,
              periodSeconds: 2,
              successThreshold: 1,
              tcpSocket: { port: "http" },
              timeoutSeconds: 1,
            },
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
            startupProbe: {
              failureThreshold: 60,
              periodSeconds: 2,
              successThreshold: 1,
              tcpSocket: { port: "http" },
              timeoutSeconds: 1,
            },
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
            { name: "data", persistentVolumeClaim: { claimName: "neo4j-data", readOnly: false } },
            { emptyDir: { sizeLimit: "256Mi" }, name: "logs" },
          ],
        },
      },
    },
  });
});

test("builds only a ClusterIP graph service and one fixed internal health job", () => {
  const resources = buildGraphResources();
  assert.deepEqual(resource(resources, "Service", "neo4j"), {
    apiVersion: "v1",
    kind: "Service",
    metadata: { labels: { "app.kubernetes.io/name": "neo4j", ...commonLabels }, name: "neo4j", namespace: "zasp-local" },
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
  });
  assert.deepEqual(resource(resources, "Job", "neo4j-health"), {
    apiVersion: "batch/v1",
    kind: "Job",
    metadata: { labels: { "app.kubernetes.io/name": "neo4j-health", ...commonLabels }, name: "neo4j-health", namespace: "zasp-local" },
    spec: {
      activeDeadlineSeconds: 300,
      backoffLimit: 0,
      template: {
        metadata: { labels: { "app.kubernetes.io/name": "neo4j-health", ...commonLabels } },
        spec: {
          automountServiceAccountToken: false,
          containers: [{
            command: [
              "sh",
              "-ec",
              "attempt=0; until wget -q -T 1 -O /dev/null http://neo4j.zasp-local.svc.cluster.local:7474/; do attempt=$((attempt + 1)); [ \"$attempt\" -ge 90 ] && exit 1; sleep 2; done; printf 'neo4j-health-ready\\n'",
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
  });
  assert.equal(resources.some((value) => ["Ingress", "NodePort", "LoadBalancer"].includes(value.kind)), false);
});

test("round trips the one canonical tracked YAML document byte exactly", async () => {
  const text = await readFile(manifestPath, "utf8");
  const parsed = parseGraphManifest(text);
  assert.deepEqual(parsed, buildGraphResources());
  assert.equal(renderGraphManifest(parsed), text);
  assert.ok(Object.isFrozen(parsed));
  assert.ok(parsed.every((value) => Object.isFrozen(value)));
});

test("rejects duplicate, aliased, tagged, multiple, oversized, and noncanonical YAML", () => {
  const canonical = renderGraphManifest(buildGraphResources());
  const cases = [
    ["empty", ""],
    ["oversized", `${" ".repeat(262_145)}\n`],
    ["duplicate key", canonical.replace("apiVersion: v1", "apiVersion: v1\napiVersion: v1")],
    ["multiple document", `${canonical}---\n{}\n`],
    ["alias", "apiVersion: v1\nkind: List\nitems: &items []\nalias: *items\n"],
    ["tag", "!!js/function function () {}\n"],
    ["non-UTF8 surrogate", `${canonical}\ud800`],
    ["comment", `# alternate\n${canonical}`],
    ["whitespace", canonical.replace("\n", " \n")],
    ["missing newline", canonical.slice(0, -1)],
  ];
  for (const [name, value] of cases) assert.throws(() => parseGraphManifest(value), { name: "TypeError" }, name);
});

test("rejects every resource identity, storage, exposure, command, and security drift", () => {
  const cases = [
    ["missing", (values) => values.pop()],
    ["extra", (values) => values.push(copy(values[0]))],
    ["unknown key", (values) => { values[0].unexpected = true; }],
    ["duplicate resource", (values) => { values[1] = copy(values[0]); }],
    ["PV name", (values) => { values[0].metadata.name = "foreign"; }],
    ["node label", (values) => { values[0].spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values = ["foreign"]; }],
    ["host path", (values) => { values[0].spec.hostPath.path = "/tmp/neo4j"; }],
    ["claim owner", (values) => { values[0].spec.claimRef.name = "foreign"; }],
    ["storage", (values) => { values[1].spec.resources.requests.storage = "2Gi"; }],
    ["selector", (values) => { values[2].spec.selector.matchLabels["app.kubernetes.io/name"] = "foreign"; }],
    ["image", (values) => { values[2].spec.template.spec.containers[0].image = "neo4j:latest"; }],
    ["environment", (values) => { values[2].spec.template.spec.containers[0].env.push({ name: "HTTP_PROXY", value: "http://foreign" }); }],
    ["host namespace", (values) => { values[2].spec.template.spec.hostNetwork = true; }],
    ["host port", (values) => { values[2].spec.template.spec.containers[0].ports[0].hostPort = 7474; }],
    ["extra container", (values) => { values[2].spec.template.spec.containers.push(copy(values[2].spec.template.spec.containers[0])); }],
    ["service exposure", (values) => { values[3].spec.type = "LoadBalancer"; }],
    ["external IP", (values) => { values[3].spec.externalIPs = ["127.0.0.1"]; }],
    ["health command", (values) => { values[4].spec.template.spec.containers[0].command[2] = "true"; }],
    ["health volume", (values) => { values[4].spec.template.spec.volumes = [{ name: "foreign", hostPath: { path: "/" } }]; }],
    ["writable health root", (values) => { values[4].spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem = false; }],
    ["privilege", (values) => { values[2].spec.template.spec.containers[0].securityContext.privileged = true; }],
    ["capability", (values) => { values[2].spec.template.spec.containers[0].securityContext.capabilities.drop = []; }],
    ["seccomp", (values) => { values[4].spec.template.spec.securityContext.seccompProfile.type = "Unconfined"; }],
    ["deadline", (values) => { values[4].spec.activeDeadlineSeconds = 0; }],
  ];
  for (const [name, mutate] of cases) {
    const values = copy(buildGraphResources());
    mutate(values);
    assert.throws(() => validateGraphResources(values), { name: "TypeError" }, name);
  }
});

test("rejects arbitrary types, accessors, symbols, and non-plain prototypes", () => {
  for (const value of [undefined, null, true, false, 0, 1, "", {}, [null], new Proxy([], {})]) {
    assert.throws(() => validateGraphResources(value), { name: "TypeError" });
  }
  const accessor = copy(buildGraphResources());
  Object.defineProperty(accessor[0].metadata, "name", { enumerable: true, get: () => "zasp-local-neo4j" });
  assert.throws(() => validateGraphResources(accessor), TypeError);
  const symbolic = copy(buildGraphResources());
  symbolic[0][Symbol("extra")] = true;
  assert.throws(() => validateGraphResources(symbolic), TypeError);
  const foreign = copy(buildGraphResources());
  Object.setPrototypeOf(foreign[0], { inherited: true });
  assert.throws(() => validateGraphResources(foreign), TypeError);

  const first = buildGraphResources();
  const second = buildGraphResources();
  assert.notEqual(first, second);
  assert.deepEqual(first, second);
  assert.throws(() => { first[0].metadata.name = "changed"; }, TypeError);
});
