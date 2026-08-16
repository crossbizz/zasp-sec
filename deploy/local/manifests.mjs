import { dump, loadAll, JSON_SCHEMA } from "js-yaml";

const manifestByteLimit = 262_144;
const namespace = "zasp-local";
const commonLabels = Object.freeze({
  "app.kubernetes.io/part-of": "zasp",
  "zasp.dev/environment": "local",
});

export const PRODUCTS = deepFreeze([
  {
    image: "zasp-local/agentsec-api:m1-30a",
    module: "services/platform",
    name: "agentsec-api",
    package: "./agentsec-api",
  },
  {
    image: "zasp-local/agentsec-worker:m1-30a",
    module: "services/platform",
    name: "agentsec-worker",
    package: "./agentsec-worker",
  },
  {
    image: "zasp-local/event-ingest:m1-30a",
    module: "services/event-ingest",
    name: "event-ingest",
    package: ".",
  },
  {
    image: "zasp-local/runtime-gateway:m1-30a",
    module: "services/runtime-gateway",
    name: "runtime-gateway",
    package: ".",
  },
]);

export function buildProductResources() {
  return deepFreeze([
    {
      apiVersion: "v1",
      kind: "Namespace",
      metadata: {
        labels: { ...commonLabels },
        name: namespace,
      },
    },
    ...PRODUCTS.map(buildDeployment),
    ...PRODUCTS.map(buildService),
  ]);
}

export function validateProductResources(value) {
  const expected = buildProductResources();
  requireExactValue(value, expected, "product resources");
  return deepFreeze(structuredClone(value));
}

export function renderProductManifest(value) {
  const items = validateProductResources(value);
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

export function parseProductManifest(text) {
  if (
    typeof text !== "string" || text.length === 0 ||
    Buffer.byteLength(text, "utf8") > manifestByteLimit ||
    Buffer.from(text, "utf8").toString("utf8") !== text
  ) throw new TypeError("product manifest is invalid");

  let documents;
  try {
    documents = [];
    loadAll(text, (document) => documents.push(document), {
      filename: "product-stubs.yaml",
      json: false,
      onWarning: () => { throw new TypeError("product manifest is invalid"); },
      schema: JSON_SCHEMA,
    });
  } catch {
    throw new TypeError("product manifest is invalid");
  }
  if (documents.length !== 1) throw new TypeError("product manifest is invalid");
  const document = documents[0];
  requireExactKeys(document, ["apiVersion", "kind", "items"], "product manifest");
  if (document.apiVersion !== "v1" || document.kind !== "List") {
    throw new TypeError("product manifest is invalid");
  }
  const resources = validateProductResources(document.items);
  if (renderProductManifest(resources) !== text) throw new TypeError("product manifest is invalid");
  return resources;
}

function buildDeployment(product) {
  const labels = {
    "app.kubernetes.io/name": product.name,
    ...commonLabels,
  };
  return {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: {
      labels: { ...labels },
      name: product.name,
      namespace,
    },
    spec: {
      progressDeadlineSeconds: 120,
      replicas: 1,
      revisionHistoryLimit: 1,
      selector: { matchLabels: { "app.kubernetes.io/name": product.name } },
      strategy: { type: "Recreate" },
      template: {
        metadata: { labels: { ...labels } },
        spec: {
          automountServiceAccountToken: false,
          containers: [{
            image: product.image,
            imagePullPolicy: "Never",
            livenessProbe: probe("/healthz", 3, 10),
            name: product.name,
            ports: [{ containerPort: 8081, name: "health", protocol: "TCP" }],
            readinessProbe: probe("/readyz", 3, 2),
            resources: {
              limits: { cpu: "100m", memory: "64Mi" },
              requests: { cpu: "10m", memory: "16Mi" },
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
            startupProbe: probe("/healthz", 30, 1),
          }],
          dnsPolicy: "ClusterFirst",
          enableServiceLinks: false,
          restartPolicy: "Always",
          securityContext: {
            fsGroup: 65532,
            runAsGroup: 65532,
            runAsNonRoot: true,
            runAsUser: 65532,
            seccompProfile: { type: "RuntimeDefault" },
          },
          terminationGracePeriodSeconds: 10,
        },
      },
    },
  };
}

function buildService(product) {
  const labels = {
    "app.kubernetes.io/name": product.name,
    ...commonLabels,
  };
  return {
    apiVersion: "v1",
    kind: "Service",
    metadata: {
      labels,
      name: product.name,
      namespace,
    },
    spec: {
      ipFamilies: ["IPv4"],
      ipFamilyPolicy: "SingleStack",
      ports: [{ name: "health", port: 8081, protocol: "TCP", targetPort: "health" }],
      selector: { "app.kubernetes.io/name": product.name },
      sessionAffinity: "None",
      type: "ClusterIP",
    },
  };
}

function probe(path, failureThreshold, periodSeconds) {
  return {
    failureThreshold,
    httpGet: { path, port: "health", scheme: "HTTP" },
    periodSeconds,
    timeoutSeconds: 1,
  };
}

function requireExactValue(value, expected, label) {
  if (Array.isArray(expected)) {
    if (!Array.isArray(value) || value.length !== expected.length) throw new TypeError(`${label} are invalid`);
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
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw new TypeError(`${label} is invalid`);
  }
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
