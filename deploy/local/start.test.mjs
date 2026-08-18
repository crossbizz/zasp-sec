import assert from "node:assert/strict";
import { test } from "node:test";

import { buildAwsEmulatorResources } from "./aws-emulator-manifest.mjs";
import { AwsEmulatorFailure } from "./aws-emulator-run.mjs";
import { buildGraphResources } from "./graph-manifest.mjs";
import { buildProductResources } from "./manifests.mjs";
import { buildObservabilityResources } from "./observability-manifest.mjs";
import {
  LOCAL_START_TARGET,
  projectLocalStartExposure,
  runLocalStartMain,
  validateLocalStartAssembly,
} from "./start.mjs";

const expectedSuccess = "Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.";
const expectedCategories = [
  "build", "cleanup", "configuration", "deadline", "normalization",
  "ownership", "panic", "provider", "readiness",
];
const expectedExposure = {
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
};

function canonicalResources() {
  return JSON.parse(JSON.stringify([
    ...buildProductResources(),
    ...buildGraphResources(),
    ...buildObservabilityResources(),
    ...buildAwsEmulatorResources(),
  ]));
}

function productDeployment(resources) {
  return resources.find((resource) => resource.kind === "Deployment" && resource.metadata.name === "agentsec-api");
}

function productService(resources) {
  return resources.find((resource) => resource.kind === "Service" && resource.metadata.name === "agentsec-api");
}

function successfulRuntime(events, overrides = {}) {
  const result = {
    awsEmulator: { endpoint: true, internal: true, ready: true, s3: true },
    graph: { internal: true, persistent: true, ready: true },
    internal: true,
    observability: { internal: true, noEgress: true, ready: true, sink: true, spans: 1 },
    pods: 4,
    ready: 4,
    services: 4,
  };
  const method = (name, value) => async () => {
    events.push(name);
    return value;
  };
  return {
    initialize: method("initialize"),
    preflight: method("preflight"),
    buildImages: method("buildImages"),
    createNetwork: method("createNetwork"),
    createCluster: method("createCluster"),
    loadImages: method("loadImages"),
    applyManifests: method("applyManifests"),
    verifyReadiness: method("verifyReadiness", structuredClone(result)),
    joinMutations: method("joinMutations"),
    cleanup: method("cleanup"),
    auditAbsence: method("auditAbsence"),
    ...overrides,
  };
}

function assertDeepFrozen(value, seen = new Set()) {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  assert.equal(Object.isFrozen(value), true);
  for (const item of Object.values(value)) assertDeepFrozen(item, seen);
}

test("exposes one immutable assembled target over the exact reviewed lifecycle", () => {
  assert.deepEqual(LOCAL_START_TARGET, {
    command: "npm run local:start",
    dependencies: ["m1-30a", "m1-30b", "m1-30c", "m1-30d"],
    entrypoint: "node deploy/local/start.mjs",
    failureCategories: expectedCategories,
    manifests: [
      "product-stubs.yaml",
      "graph.yaml",
      "observability.yaml",
      "observability-span.yaml",
      "aws-emulator.yaml",
      "aws-emulator-s3.yaml",
    ],
    profile: "m1-30d",
    successLine: expectedSuccess,
  });
  assertDeepFrozen(LOCAL_START_TARGET);
});

test("proves the exact 22-resource assembly has no external vendor-dashboard exposure", () => {
  assert.deepEqual(projectLocalStartExposure(canonicalResources()), expectedExposure);
  assert.deepEqual(validateLocalStartAssembly(), expectedExposure);
  assert.throws(() => validateLocalStartAssembly("forged"), TypeError);
  assertDeepFrozen(validateLocalStartAssembly());
});

test("rejects every external service and host-namespace exposure", () => {
  const mutations = [
    ["Ingress", (resources) => resources.push({ apiVersion: "networking.k8s.io/v1", kind: "Ingress", metadata: { name: "vendor" } })],
    ["NodePort", (resources) => { productService(resources).spec.type = "NodePort"; }],
    ["LoadBalancer", (resources) => { productService(resources).spec.type = "LoadBalancer"; }],
    ["ExternalName", (resources) => { productService(resources).spec.type = "ExternalName"; }],
    ["externalIPs", (resources) => { productService(resources).spec.externalIPs = ["203.0.113.10"]; }],
    ["loadBalancerIP", (resources) => { productService(resources).spec.loadBalancerIP = "203.0.113.10"; }],
    ["externalTrafficPolicy", (resources) => { productService(resources).spec.externalTrafficPolicy = "Local"; }],
    ["hostNetwork", (resources) => { productDeployment(resources).spec.template.spec.hostNetwork = true; }],
    ["hostPID", (resources) => { productDeployment(resources).spec.template.spec.hostPID = true; }],
    ["hostIPC", (resources) => { productDeployment(resources).spec.template.spec.hostIPC = true; }],
    ["hostPort", (resources) => { productDeployment(resources).spec.template.spec.containers[0].ports[0].hostPort = 8081; }],
    ["hostPath", (resources) => { productDeployment(resources).spec.template.spec.volumes = [{ hostPath: { path: "/tmp" }, name: "host" }]; }],
    ["Docker socket", (resources) => { productDeployment(resources).spec.template.spec.containers[0].volumeMounts = [{ mountPath: "/var/run/docker.sock", name: "socket" }]; }],
  ];
  for (const [name, mutate] of mutations) {
    const resources = canonicalResources();
    mutate(resources);
    assert.throws(() => projectLocalStartExposure(resources), TypeError, name);
  }
});

test("rejects accessor, prototype, symbol, alias, cycle, and coercion traps", () => {
  let getterCalls = 0;
  let coercionCalls = 0;
  const cases = [
    () => {
      const resources = canonicalResources();
      Object.defineProperty(resources[0], "kind", { enumerable: true, get() { getterCalls += 1; return "Namespace"; } });
      return resources;
    },
    () => {
      const resources = canonicalResources();
      Object.setPrototypeOf(resources[0], { foreign: true });
      return resources;
    },
    () => {
      const resources = canonicalResources();
      resources[0][Symbol("foreign")] = true;
      return resources;
    },
    () => {
      const resources = canonicalResources();
      resources.push(resources[0]);
      return resources;
    },
    () => {
      const resources = canonicalResources();
      productService(resources).spec.selector = productDeployment(resources).spec.selector.matchLabels;
      return resources;
    },
    () => {
      const resources = canonicalResources();
      resources[0].cycle = resources;
      return resources;
    },
    () => {
      const resources = canonicalResources();
      resources[0].coercion = { toString() { coercionCalls += 1; return "foreign"; } };
      return resources;
    },
  ];
  for (const build of cases) assert.throws(() => projectLocalStartExposure(build()), TypeError);
  assert.equal(getterCalls, 0);
  assert.equal(coercionCalls, 0);
});

test("does not reread caller values after capturing the strict snapshot", () => {
  let iteratorReads = 0;
  const resources = new Proxy(canonicalResources(), {
    get(target, property, receiver) {
      if (property === Symbol.iterator) iteratorReads += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.deepEqual(projectLocalStartExposure(resources), expectedExposure);
  assert.equal(iteratorReads, 0);
});

test("delegates one complete lifecycle and preserves the exact fixed output", async () => {
  const events = [];
  let stdout = "";
  let stderr = "";
  let exitCode;
  assert.equal(await runLocalStartMain(successfulRuntime(events), {
    stdout: { write(value) { stdout += value; } },
    stderr: { write(value) { stderr += value; } },
    setExitCode(value) { exitCode = value; },
  }), 0);
  assert.deepEqual(events, [
    "initialize", "preflight", "buildImages", "createNetwork", "createCluster",
    "loadImages", "applyManifests", "verifyReadiness", "joinMutations", "cleanup", "auditAbsence",
  ]);
  assert.equal(stdout, `${expectedSuccess}\n`);
  assert.equal(stderr, "");
  assert.equal(exitCode, 0);
});

test("retains reviewed failure normalization and cleanup precedence", async () => {
  const events = [];
  let stdout = "";
  let stderr = "";
  const runtime = successfulRuntime(events, {
    async buildImages() { events.push("buildImages"); throw new AwsEmulatorFailure("provider"); },
    async cleanup() { events.push("cleanup"); throw new AwsEmulatorFailure("cleanup"); },
  });
  assert.equal(await runLocalStartMain(runtime, {
    stdout: { write(value) { stdout += value; } },
    stderr: { write(value) { stderr += value; } },
    setExitCode() {},
  }), 1);
  assert.equal(stdout, "");
  assert.equal(stderr, "Local AWS emulator manifest failed: cleanup rejected.\n");
  assert.deepEqual(events, ["initialize", "preflight", "buildImages", "joinMutations", "cleanup", "auditAbsence"]);
});

test("normalizes a pre-delegation assembly panic without invoking the runtime", async () => {
  const events = [];
  let stderr = "";
  let exitCode;
  const originalGetPrototypeOf = Object.getPrototypeOf;
  let injected = false;
  Object.getPrototypeOf = (value) => {
    if (!injected && Array.isArray(value)) {
      injected = true;
      throw new Error("private assembly detail");
    }
    return originalGetPrototypeOf(value);
  };
  try {
    assert.equal(await runLocalStartMain(successfulRuntime(events), {
      stdout: { write() {} },
      stderr: { write(value) { stderr += value; } },
      setExitCode(value) { exitCode = value; },
    }), 1);
  } finally {
    Object.getPrototypeOf = originalGetPrototypeOf;
  }
  assert.deepEqual(events, []);
  assert.equal(stderr, "Local AWS emulator manifest failed: panic rejected.\n");
  assert.equal(exitCode, 1);
});
