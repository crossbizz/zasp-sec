import assert from "node:assert/strict";
import test from "node:test";

import { executeDiscoverySchema60Transition } from "./discovery-schema60-transition.mjs";

const digest = "a".repeat(64);
const image = `registry.example/agentsec-worker@sha256:${digest}`;
const options = {
  kubeconfig: "/secure/kubeconfig",
  context: "production",
  namespace: "agentsec",
  namespaceUID: "namespace-uid",
  release: "zasp",
  chart: "/repo/deploy/staging/product",
  values: ["/repo/deploy/staging/product/values-saas.yaml", "/secure/release-values.yaml"],
  expectedSchedulerImage: image,
};

const namespace = { apiVersion: "v1", kind: "Namespace", metadata: { name: "agentsec", uid: "namespace-uid" } };
const deployment = (schema, replicas) => ({
  apiVersion: "apps/v1",
  kind: "Deployment",
  metadata: { name: "agentsec-discovery-scheduler", namespace: "agentsec", generation: 4 },
  spec: {
    replicas,
    template: {
      metadata: { annotations: { "zasp.io/schema-version": String(schema) } },
      spec: { containers: [{ name: "scheduler", image }] },
    },
  },
  status: { observedGeneration: 4, replicas, updatedReplicas: replicas, readyReplicas: replicas, availableReplicas: replicas },
});
const pod = number => ({
  apiVersion: "v1",
  kind: "Pod",
  metadata: { name: `scheduler-${number}`, namespace: "agentsec" },
  spec: { containers: [{ name: "scheduler", image }] },
  status: {
    phase: "Running",
    conditions: [{ type: "Ready", status: "True" }],
    containerStatuses: [{ name: "scheduler", ready: true, imageID: `docker-pullable://registry.example/agentsec-worker@sha256:${digest}` }],
  },
});
// kubectl get -o json normalizes collection envelopes to core v1/List.
const list = items => ({ apiVersion: "v1", kind: "List", items });
const hpa = { apiVersion: "autoscaling/v2", kind: "HorizontalPodAutoscaler", metadata: { name: "agentsec-discovery-scheduler", namespace: "agentsec" }, spec: { scaleTargetRef: { apiVersion: "apps/v1", kind: "Deployment", name: "agentsec-discovery-scheduler" } } };

function successfulRun(calls) {
  let reads = 0;
  return async (command, args) => {
    calls.push([command, args]);
    if (command === "helm") return { stdout: "release applied" };
    const resource = args[args.indexOf("get") + 1];
    if (resource === "namespace") return { stdout: JSON.stringify(namespace) };
    const active = reads++ >= 3;
    if (resource === "deployment") return { stdout: JSON.stringify(deployment(active ? 60 : 59, active ? 2 : 0)) };
    if (resource === "pods") return { stdout: JSON.stringify(list(active ? [pod(1), pod(2)] : [])) };
    if (resource === "horizontalpodautoscalers") return { stdout: JSON.stringify(list(active ? [hpa] : [])) };
    throw new Error(`unexpected command: ${command} ${args.join(" ")}`);
  };
}

test("schema60 transition applies maintenance, proves the scheduler is drained, then activates the reviewed image", async () => {
  const calls = [];
  const result = await executeDiscoverySchema60Transition(options, { run: successfulRun(calls) });

  assert.deepEqual(result, { namespaceUID: "namespace-uid", maintenanceSchema: 59, activeSchema: 60, schedulerImage: image, replicas: 2 });
  assert.equal(calls.filter(([command]) => command === "helm").length, 2);
  const [maintenance, active] = calls.filter(([command]) => command === "helm").map(([, args]) => args);
  assert.ok(maintenance.includes("schema.expectedVersion=59"));
  assert.ok(maintenance.includes("rollout.discoveryScheduleReplayPhase=maintenance"));
  assert.ok(active.includes("schema.expectedVersion=60"));
  assert.ok(active.includes("rollout.discoveryScheduleReplayPhase=active"));
  assert.equal(calls.findIndex(([command, args]) => command === "helm" && args.includes("schema.expectedVersion=60")) > calls.findIndex(([command, args]) => command === "kubectl" && args.includes("horizontalpodautoscalers")), true);
});

test("schema60 transition refuses activation while any old or terminating scheduler pod remains", async () => {
  const calls = [];
  const run = successfulRun(calls);
  await assert.rejects(executeDiscoverySchema60Transition(options, {
    run: async (command, args, settings) => {
      if (command === "kubectl" && args.includes("pods")) return { stdout: JSON.stringify(list([{ ...pod(1), metadata: { ...pod(1).metadata, deletionTimestamp: "2026-09-20T00:00:00Z" } }])) };
      return run(command, args, settings);
    },
  }), /schema60 transition rejected/);
  assert.equal(calls.some(([command, args]) => command === "helm" && args.includes("schema.expectedVersion=60")), false);
});

test("schema60 transition rejects mutable images and namespace replacement before invoking tools", async () => {
  let invoked = false;
  await assert.rejects(executeDiscoverySchema60Transition({ ...options, expectedSchedulerImage: "registry.example/agentsec-worker:latest" }, { run: async () => { invoked = true; } }), /schema60 transition rejected/);
  assert.equal(invoked, false);

  let helmInvocations = 0;
  await assert.rejects(executeDiscoverySchema60Transition(options, { run: async (command, args) => {
    if (command === "helm") { helmInvocations += 1; return { stdout: "ok" }; }
    if (args.includes("namespace")) return { stdout: JSON.stringify({ ...namespace, metadata: { ...namespace.metadata, uid: "replacement" } }) };
    throw new Error("must stop at namespace identity");
  } }), /schema60 transition rejected/);
  assert.equal(helmInvocations, 0);
});
