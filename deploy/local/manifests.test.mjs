import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  PRODUCTS,
  buildProductResources,
  parseProductManifest,
  renderProductManifest,
  validateProductResources,
} from "./manifests.mjs";

const manifestPath = join(import.meta.dirname, "product-stubs.yaml");

function copy(value) {
  return structuredClone(value);
}

function deployment(resources, name) {
  return resources.find((resource) => resource.kind === "Deployment" && resource.metadata.name === name);
}

function service(resources, name) {
  return resources.find((resource) => resource.kind === "Service" && resource.metadata.name === name);
}

test("defines the exact four real product commands and local images", () => {
  assert.deepEqual(PRODUCTS, [
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
  assert.ok(Object.isFrozen(PRODUCTS));
  assert.ok(PRODUCTS.every((product) => Object.isFrozen(product)));
});

test("builds one namespace and exact hardened deployment for each product", () => {
  const resources = buildProductResources();
  assert.equal(resources.length, 9);
  assert.deepEqual(resources[0], {
    apiVersion: "v1",
    kind: "Namespace",
    metadata: {
      labels: {
        "app.kubernetes.io/part-of": "zasp",
        "zasp.dev/environment": "local",
      },
      name: "zasp-local",
    },
  });

  for (const product of PRODUCTS) {
    const item = deployment(resources, product.name);
    assert.deepEqual(item, {
      apiVersion: "apps/v1",
      kind: "Deployment",
      metadata: {
        labels: {
          "app.kubernetes.io/name": product.name,
          "app.kubernetes.io/part-of": "zasp",
          "zasp.dev/environment": "local",
        },
        name: product.name,
        namespace: "zasp-local",
      },
      spec: {
        progressDeadlineSeconds: 120,
        replicas: 1,
        revisionHistoryLimit: 1,
        selector: { matchLabels: { "app.kubernetes.io/name": product.name } },
        strategy: { type: "Recreate" },
        template: {
          metadata: {
            labels: {
              "app.kubernetes.io/name": product.name,
              "app.kubernetes.io/part-of": "zasp",
              "zasp.dev/environment": "local",
            },
          },
          spec: {
            automountServiceAccountToken: false,
            containers: [{
              image: product.image,
              imagePullPolicy: "Never",
              livenessProbe: {
                failureThreshold: 3,
                httpGet: { path: "/healthz", port: "health", scheme: "HTTP" },
                periodSeconds: 10,
                timeoutSeconds: 1,
              },
              name: product.name,
              ports: [{ containerPort: 8081, name: "health", protocol: "TCP" }],
              readinessProbe: {
                failureThreshold: 3,
                httpGet: { path: "/readyz", port: "health", scheme: "HTTP" },
                periodSeconds: 2,
                timeoutSeconds: 1,
              },
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
              startupProbe: {
                failureThreshold: 30,
                httpGet: { path: "/healthz", port: "health", scheme: "HTTP" },
                periodSeconds: 1,
                timeoutSeconds: 1,
              },
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
    });
  }
});

test("builds four internal-only services with exact selectors", () => {
  const resources = buildProductResources();
  for (const product of PRODUCTS) {
    assert.deepEqual(service(resources, product.name), {
      apiVersion: "v1",
      kind: "Service",
      metadata: {
        labels: {
          "app.kubernetes.io/name": product.name,
          "app.kubernetes.io/part-of": "zasp",
          "zasp.dev/environment": "local",
        },
        name: product.name,
        namespace: "zasp-local",
      },
      spec: {
        ipFamilies: ["IPv4"],
        ipFamilyPolicy: "SingleStack",
        ports: [{ name: "health", port: 8081, protocol: "TCP", targetPort: "health" }],
        selector: { "app.kubernetes.io/name": product.name },
        sessionAffinity: "None",
        type: "ClusterIP",
      },
    });
  }
  assert.equal(resources.some((resource) => ["Ingress", "PersistentVolume", "PersistentVolumeClaim"].includes(resource.kind)), false);
});

test("round trips the canonical tracked YAML byte exactly", async () => {
  const text = await readFile(manifestPath, "utf8");
  const parsed = parseProductManifest(text);
  assert.deepEqual(parsed, buildProductResources());
  assert.equal(renderProductManifest(parsed), text);
  assert.ok(Object.isFrozen(parsed));
  assert.ok(parsed.every((resource) => Object.isFrozen(resource)));
});

test("rejects noncanonical or dangerous YAML representations", () => {
  const canonical = renderProductManifest(buildProductResources());
  const cases = [
    ["empty", ""],
    ["oversized", `${" ".repeat(262_145)}\n`],
    ["duplicate key", canonical.replace("apiVersion: v1", "apiVersion: v1\napiVersion: v1")],
    ["multiple document", `${canonical}---\n{}\n`],
    ["alias", "items: &items []\nalias: *items\n"],
    ["tag", "!!js/function function () {}\n"],
    ["non-UTF8 surrogate", `${canonical}\ud800`],
    ["leading comment", `# alternate\n${canonical}`],
    ["trailing whitespace", canonical.replace("\n", " \n")],
    ["missing newline", canonical.slice(0, -1)],
  ];
  for (const [name, value] of cases) {
    assert.throws(() => parseProductManifest(value), { name: "TypeError" }, name);
  }
});

test("rejects every manifest identity, exposure, and security mutation", () => {
  const cases = [
    ["missing resource", (resources) => resources.pop()],
    ["extra resource", (resources) => resources.push(copy(resources[0]))],
    ["unknown key", (resources) => { resources[0].unexpected = true; }],
    ["namespace drift", (resources) => { resources[0].metadata.name = "default"; }],
    ["duplicate name", (resources) => { resources[2].metadata.name = "agentsec-api"; }],
    ["replica drift", (resources) => { deployment(resources, "agentsec-api").spec.replicas = 2; }],
    ["selector drift", (resources) => { deployment(resources, "agentsec-api").spec.selector.matchLabels["app.kubernetes.io/name"] = "event-ingest"; }],
    ["image drift", (resources) => { deployment(resources, "agentsec-api").spec.template.spec.containers[0].image = "busybox:latest"; }],
    ["pull drift", (resources) => { deployment(resources, "agentsec-api").spec.template.spec.containers[0].imagePullPolicy = "Always"; }],
    ["command injection", (resources) => { deployment(resources, "agentsec-api").spec.template.spec.containers[0].command = ["sh"]; }],
    ["environment injection", (resources) => { deployment(resources, "agentsec-api").spec.template.spec.containers[0].env = [{ name: "AWS_ACCESS_KEY_ID", value: "fixture" }]; }],
    ["host network", (resources) => { deployment(resources, "agentsec-api").spec.template.spec.hostNetwork = true; }],
    ["host port", (resources) => { deployment(resources, "agentsec-api").spec.template.spec.containers[0].ports[0].hostPort = 8081; }],
    ["service exposure", (resources) => { service(resources, "agentsec-api").spec.type = "NodePort"; }],
    ["external IP", (resources) => { service(resources, "agentsec-api").spec.externalIPs = ["127.0.0.1"]; }],
    ["service cross-selection", (resources) => { service(resources, "agentsec-api").spec.selector["app.kubernetes.io/name"] = "runtime-gateway"; }],
    ["token mount", (resources) => { deployment(resources, "agentsec-worker").spec.template.spec.automountServiceAccountToken = true; }],
    ["root user", (resources) => { deployment(resources, "event-ingest").spec.template.spec.securityContext.runAsUser = 0; }],
    ["writable root", (resources) => { deployment(resources, "runtime-gateway").spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem = false; }],
    ["added capability", (resources) => { deployment(resources, "agentsec-api").spec.template.spec.containers[0].securityContext.capabilities.add = ["NET_ADMIN"]; }],
    ["seccomp drift", (resources) => { deployment(resources, "agentsec-api").spec.template.spec.securityContext.seccompProfile.type = "Unconfined"; }],
    ["readiness drift", (resources) => { deployment(resources, "agentsec-api").spec.template.spec.containers[0].readinessProbe.httpGet.path = "/healthz"; }],
    ["resource drift", (resources) => { deployment(resources, "agentsec-api").spec.template.spec.containers[0].resources.limits.memory = "1Gi"; }],
    ["extra container", (resources) => { deployment(resources, "agentsec-api").spec.template.spec.containers.push(copy(deployment(resources, "agentsec-api").spec.template.spec.containers[0])); }],
    ["volume", (resources) => { deployment(resources, "agentsec-api").spec.template.spec.volumes = [{ name: "host", hostPath: { path: "/" } }]; }],
  ];
  for (const [name, mutate] of cases) {
    const resources = copy(buildProductResources());
    mutate(resources);
    assert.throws(() => validateProductResources(resources), { name: "TypeError" }, name);
  }
});

test("rejects primitives, aliases, and caller mutation while returning fresh values", () => {
  for (const value of [undefined, null, true, false, 0, 1, "", "resources", {}, [null]]) {
    assert.throws(() => validateProductResources(value), { name: "TypeError" });
  }
  const first = buildProductResources();
  const second = buildProductResources();
  assert.notEqual(first, second);
  assert.deepEqual(first, second);
  assert.throws(() => { first[0].metadata.name = "changed"; }, TypeError);
});
