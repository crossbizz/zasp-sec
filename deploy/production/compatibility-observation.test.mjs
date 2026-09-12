import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { observeCompatibility, observeSandboxBackfill, observePrecisionConsumers, observePrecisionIntake, revalidateCompatibility, revalidateSandboxBackfill, revalidatePrecisionConsumers, revalidatePrecisionIntake } from "./compatibility-observation.mjs";
import { renderRelease } from "./release-contract.mjs";
import { productionReleaseFixture } from "./release-fixture.mjs";

// Expected digests come from a separately serialized, admitted template artifact.
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(k => [k, stable(value[k])])) : value;
const digest = value => createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");
const names = ["agentsec-api", "agentsec-runtime-outbox", "agentsec-runtime-coordinator", "agentsec-runtime-archive", "agentsec-runtime-index", "agentsec-runtime-correlation", "agentsec-runtime-projection", "agentsec-runtime-complete", "agentsec-event-ingest", "agentsec-gateway-control"];
const imageID = `docker-pullable://example.invalid/worker@sha256:${"a".repeat(64)}`;
function fixture(precision = false) {
  const docs = { namespace: { apiVersion: "v1", kind: "Namespace", metadata: { name: "agentsec", uid: "namespace-1" } }, deployment: [], replicaset: [], pod: [] };
  const expected = (precision ? [...names, "agentsec-runtime-session-index-v2"] : names).map(name => {
    const template = { metadata: { labels: { app: name }, annotations: { "zasp.io/schema-version": "49" } }, spec: { containers: [{ name: "main", image: `example.invalid/worker@sha256:${"a".repeat(64)}`, env: [{ name: "CONFIG", value: "intended" }] }] } };
    if (precision) {
      template.spec.serviceAccountName = `${name}-account`;
      template.metadata.annotations["zasp.io/schema-version"] = "51";
      const selections = {
        "agentsec-api": ["ZASP_RUNTIME_SESSION_INDEX", "zasp-runtime-sessions-v2"],
        "agentsec-event-ingest": ["ZASP_RUNTIME_INGEST_SCHEMA", "runtime-event-v1"],
        "agentsec-runtime-outbox": ["ZASP_RUNTIME_DELIVERY_SCHEMA", "runtime-event-v2"],
        "agentsec-runtime-coordinator": ["ZASP_RUNTIME_DELIVERY_SCHEMA", "runtime-event-v2"],
        "agentsec-runtime-archive": ["ZASP_RUNTIME_STAGE_VERSION", "runtime-archive-v2"],
        "agentsec-runtime-index": ["ZASP_RUNTIME_STAGE_VERSION", "runtime-index-v1"],
        "agentsec-runtime-session-index-v2": ["ZASP_RUNTIME_STAGE_VERSION", "runtime-index-v2"],
        "agentsec-runtime-correlation": ["ZASP_RUNTIME_STAGE_VERSION", "runtime-correlation-v4"],
        "agentsec-runtime-projection": ["ZASP_RUNTIME_STAGE_VERSION", "runtime-projection-v3"],
        "agentsec-runtime-complete": ["ZASP_RUNTIME_STAGE_VERSION", "runtime-complete-v3"],
      };
      const selected = selections[name];
      if (selected) template.spec.containers[0].env.push({ name: selected[0], value: selected[1] });
      if (name === "agentsec-runtime-session-index-v2" || name === "agentsec-runtime-index") template.spec.containers[0].env.push({ name: "ZASP_RUNTIME_SESSION_INDEX", value: name.endsWith("-v2") ? "zasp-runtime-sessions-v2" : "zasp-runtime-sessions-v1" });
    }
    docs.deployment.push({ apiVersion: "apps/v1", kind: "Deployment", metadata: { name, namespace: "agentsec", uid: `${name}-deployment`, generation: 2 }, spec: { replicas: 1, template }, status: { observedGeneration: 2, replicas: 1, updatedReplicas: 1, readyReplicas: 1, availableReplicas: 1 } });
    docs.replicaset.push({ apiVersion: "apps/v1", kind: "ReplicaSet", metadata: { name: `${name}-rs`, namespace: "agentsec", uid: `${name}-rs`, generation: 1, ownerReferences: [{ apiVersion: "apps/v1", kind: "Deployment", name, uid: `${name}-deployment`, controller: true }] }, spec: { replicas: 1, template }, status: { observedGeneration: 1, replicas: 1, readyReplicas: 1, availableReplicas: 1 } });
    docs.pod.push({ apiVersion: "v1", kind: "Pod", metadata: { name: `${name}-pod`, namespace: "agentsec", uid: `${name}-pod`, ownerReferences: [{ apiVersion: "apps/v1", kind: "ReplicaSet", name: `${name}-rs`, uid: `${name}-rs`, controller: true }] }, spec: structuredClone(template.spec), status: { phase: "Running", conditions: [{ type: "Ready", status: "True" }], containerStatuses: [{ name: "main", ready: true, imageID, state: { running: { startedAt: "2026-09-11T00:00:00Z" } } }] } });
    Object.assign(docs.pod.at(-1).metadata, structuredClone(template.metadata));
    return { name, templateDigest: digest(template), imageIDs: { main: imageID } };
  });
  let time = 1000;
  const options = { kubeconfig: "/explicit/config", context: "release", namespace: "agentsec", namespaceUID: "namespace-1", expected };
  const dependencies = { now: () => time, run: async (command, args, bounds) => {
    assert.equal(command, "kubectl");
    assert.deepEqual(args.slice(0, 4), ["--kubeconfig", "/explicit/config", "--context", "release"]);
    assert.equal(args[4], "get");
    assert.equal(bounds.timeout, 5000);
    assert.equal(bounds.maxBuffer, 4 * 1024 * 1024);
    const kind = args[5];
    assert.deepEqual(args.slice(6), kind === "namespace" ? ["agentsec", "--output=json", "--request-timeout=5s"] : ["--namespace", "agentsec", "--output=json", "--request-timeout=5s"]);
    return { stdout: JSON.stringify(kind === "namespace" ? docs.namespace : { apiVersion: "v1", kind: "List", items: docs[kind] }) };
  } };
  return { docs, options, dependencies, setTime: value => time = value };
}

function setPinnedSelection(f, name, key, value) {
  const d = f.docs.deployment.find(d => d.metadata.name === name);
  d.spec.template.spec.containers[0].env.find(e => e.name === key).value = value;
  f.docs.replicaset.find(r => r.metadata.name === `${name}-rs`).spec.template = structuredClone(d.spec.template);
  f.docs.pod.find(p => p.metadata.name === `${name}-pod`).spec = structuredClone(d.spec.template.spec);
  f.options.expected.find(e => e.name === name).templateDigest = digest(d.spec.template);
}

test("observer spends only the inherited deadline across sequential reads", async () => {
  for (const deadline of [2500, 4000]) {
    const f = fixture();
    let time = 1000;
    const timeouts = [];
    f.options.deadlineUnixMs = deadline;
    const dependencies = { now: () => time, run: async (_command, args, bounds) => {
      const remaining = Math.min(5000, deadline - time);
      assert.equal(bounds.timeout, remaining);
      assert.ok(args.includes(`--request-timeout=${remaining}ms`));
      timeouts.push(bounds.timeout);
      time += 400;
      const kind = args[5];
      return { stdout: JSON.stringify(kind === "namespace" ? f.docs.namespace : { apiVersion: "v1", kind: "List", items: f.docs[kind] }) };
    } };
    if (deadline === 2500) {
      await assert.rejects(observeCompatibility(f.options, dependencies));
      assert.deepEqual(timeouts, [1500, 1100, 700, 300]);
    } else {
      const observed = await observeCompatibility(f.options, dependencies);
      assert.equal(observed.observedAt, 3000);
      assert.deepEqual(timeouts, [3000, 2600, 2200, 1800, 1400]);
    }
  }
});

test("invalid or expired inherited deadlines never invoke kubectl", async () => {
  for (const deadlineUnixMs of [null, 1000, 999, 1000.5, 31001, Infinity, "2000"]) {
    const f = fixture();
    let calls = 0;
    await assert.rejects(observeCompatibility({ ...f.options, deadlineUnixMs }, {
      now: () => 1000,
      run: async () => { calls++; throw new Error("unexpected cluster read"); },
    }));
    assert.equal(calls, 0);
  }
});

test("a clock rewind cannot replenish an observation deadline", async () => {
  const f = fixture();
  let time = 1000, calls = 0;
  await assert.rejects(observeCompatibility({ ...f.options, deadlineUnixMs: 4000 }, {
    now: () => time,
    run: async (_command, args) => {
      calls++;
      time = calls === 1 ? 1200 : 1100;
      const kind = args[5];
      return { stdout: JSON.stringify(kind === "namespace" ? f.docs.namespace : { apiVersion: "v1", kind: "List", items: f.docs[kind] }) };
    },
  }));
  assert.equal(calls, 2);
});

test("precision intake observation requires completed v2 intake and unchanged consumers", async () => {
  const f = fixture(true);
  await assert.rejects(observePrecisionIntake(f.options, f.dependencies), /compatibility observation rejected/);
  setPinnedSelection(f, "agentsec-event-ingest", "ZASP_RUNTIME_INGEST_SCHEMA", "runtime-event-v2");
  const first = await observePrecisionIntake(f.options, f.dependencies);
  assert.equal(first.deployments.length, 11);
  await assert.rejects(observePrecisionConsumers(f.options, f.dependencies), /compatibility observation rejected/);
  f.setTime(2000);
  await revalidatePrecisionIntake(first, f.options, f.dependencies);
  setPinnedSelection(f, "agentsec-runtime-coordinator", "ZASP_RUNTIME_DELIVERY_SCHEMA", "runtime-event-v1");
  await assert.rejects(observePrecisionIntake(f.options, f.dependencies), /compatibility observation rejected/);
});

test("precision intake revalidation rejects expiry and pod replacement", async () => {
  for (const mutation of ["expiry", "replacement"]) {
    const f = fixture(true);
    setPinnedSelection(f, "agentsec-event-ingest", "ZASP_RUNTIME_INGEST_SCHEMA", "runtime-event-v2");
    const first = await observePrecisionIntake(f.options, f.dependencies);
    if (mutation === "expiry") f.setTime(31000);
    else f.docs.pod[0].metadata.uid = "replacement-pod";
    await assert.rejects(revalidatePrecisionIntake(first, f.options, f.dependencies), /compatibility observation rejected/);
  }
});

test("observes all precision consumers with intake still v1", async () => {
  const f = fixture(true);
  const observation = await observePrecisionConsumers(f.options, f.dependencies);
  assert.equal(observation.deployments.length, 11);
  f.setTime(2000);
  await revalidatePrecisionConsumers(observation, f.options, f.dependencies);
  f.setTime(31000);
  await assert.rejects(revalidatePrecisionConsumers(observation, f.options, f.dependencies), /compatibility observation rejected/);
});

test("precision observation refuses a consistently pinned old coordinator or early intake", async () => {
  for (const [name, key, value] of [["agentsec-runtime-coordinator", "ZASP_RUNTIME_DELIVERY_SCHEMA", "runtime-event-v1"], ["agentsec-event-ingest", "ZASP_RUNTIME_INGEST_SCHEMA", "runtime-event-v2"]]) {
    const f = fixture(true);
    const d = f.docs.deployment.find(d => d.metadata.name === name);
    d.spec.template.spec.containers[0].env.find(e => e.name === key).value = value;
    f.docs.replicaset.find(r => r.metadata.name === `${name}-rs`).spec.template = structuredClone(d.spec.template);
    f.docs.pod.find(p => p.metadata.name === `${name}-pod`).spec = structuredClone(d.spec.template.spec);
    f.options.expected.find(e => e.name === name).templateDigest = digest(d.spec.template);
    await assert.rejects(observePrecisionConsumers(f.options, f.dependencies), /compatibility observation rejected/);
  }
});

for (const signal of ["label", "serviceAccount", "mode"]) test(`precision observation refuses an orphan coordinator pod via ${signal}`, async () => {
  const f = fixture(true);
  const pod = structuredClone(f.docs.pod.find(p => p.metadata.name === "agentsec-runtime-coordinator-pod"));
  pod.metadata.name = "orphan-coordinator";
  pod.metadata.uid = "orphan-coordinator";
  delete pod.metadata.ownerReferences;
  if (signal !== "label") delete pod.metadata.labels;
  if (signal !== "serviceAccount") delete pod.spec.serviceAccountName;
  if (signal === "mode") pod.spec.containers[0].env = [{ name: "ZASP_WORKER_MODE", value: "runtime-coordinator" }];
  f.docs.pod.push(pod);
  await assert.rejects(observePrecisionConsumers(f.options, f.dependencies), /compatibility observation rejected/);
});

test("observes the complete compatible consumer set and revalidates unchanged identities", async () => {
  const f = fixture();
  const first = await observeCompatibility(f.options, f.dependencies);
  assert.equal(first.deployments.length, 10);
  assert.equal(first.namespaceUID, "namespace-1");
  assert.equal(first.deployments[0].generation, 2);
  assert.equal(first.deployments[0].pods[0].imageIDs.main, imageID);
  f.setTime(2000);
  await revalidateCompatibility(first, f.options, f.dependencies);
});

for (const [name, mutate] of Object.entries({
  staleGeneration: f => f.docs.deployment[0].status.observedGeneration = 1,
  oldReplicas: f => f.docs.deployment[0].status.replicas = 2,
  missingConsumer: f => f.options.expected.pop(),
  missingPod: f => f.docs.pod.pop(),
  terminatingPod: f => f.docs.pod[0].metadata.deletionTimestamp = "2026-09-11T00:00:00Z",
  nonReady: f => f.docs.pod[0].status.containerStatuses[0].ready = false,
  wrongOwner: f => f.docs.pod[0].metadata.ownerReferences[0].uid = "foreign",
  configDrift: f => f.docs.deployment[0].spec.template.spec.containers[0].env[0].value = "changed",
  podDrift: f => f.docs.pod[0].spec.containers[0].env[0].value = "changed",
  imageDrift: f => f.docs.pod[0].status.containerStatuses[0].imageID = imageID.replace(/a/g, "b"),
  wrongNamespace: f => f.docs.namespace.metadata.uid = "replacement",
  wrongSchema: f => f.docs.deployment[0].spec.template.metadata.annotations["zasp.io/schema-version"] = "50",
  staleReplicaSet: f => f.docs.replicaset[0].status.observedGeneration = 0,
  addedHostNetwork: f => f.docs.pod[0].spec.hostNetwork = true,
  addedHostPID: f => f.docs.pod[0].spec.hostPID = true,
  injectedInit: f => f.docs.pod[0].spec.initContainers = [{ name: "injected", image: "bad" }],
  injectedEphemeral: f => f.docs.pod[0].spec.ephemeralContainers = [{ name: "debug", image: "bad" }],
  changedPodLabel: f => f.docs.pod[0].metadata.labels.app = "foreign",
  changedPodAnnotation: f => f.docs.pod[0].metadata.annotations["zasp.io/schema-version"] = "50",
  addedPodLabel: f => f.docs.pod[0].metadata.labels.privileged = "true",
})) test(`rejects ${name}`, async () => {
  const f = fixture(); mutate(f);
  await assert.rejects(observeCompatibility(f.options, f.dependencies), /compatibility observation rejected/);
});

test("revalidation rejects expiry and replacement pods with unchanged images", async () => {
  const f = fixture();
  const first = await observeCompatibility(f.options, f.dependencies);
  f.setTime(31000);
  await assert.rejects(revalidateCompatibility(first, f.options, f.dependencies), /compatibility observation rejected/);
  f.setTime(2000);
  f.docs.pod[0].metadata.uid = "replacement-pod";
  await assert.rejects(revalidateCompatibility(first, f.options, f.dependencies), /compatibility observation rejected/);
});

for (const phase of ["compatibility", "backfill", "precision-consumers", "precision-intake"]) test(`observes rendered ${phase} with controlled provider metadata`, async () => {
  const precision = phase !== "compatibility";
  const f = fixture(precision);
  const rendered = precision ? await renderRelease(productionReleaseFixture, { schemaVersion: phase === "backfill" ? 50 : 51, sessionSearchPhase: phase }) : await renderRelease(productionReleaseFixture);
  for (const expected of f.options.expected) {
    const template = structuredClone(rendered.find(r => r.kind === "Deployment" && r.metadata.name === expected.name).spec.template);
    expected.templateDigest = digest(template);
    expected.imageIDs = Object.fromEntries([...template.spec.containers, ...(template.spec.initContainers ?? [])].map(c => [c.name, imageID]));
    f.docs.deployment.find(d => d.metadata.name === expected.name).spec.template = template;
    const rs = f.docs.replicaset.find(r => r.metadata.name === `${expected.name}-rs`);
    rs.spec.template = structuredClone(template);
    rs.spec.template.metadata.labels["pod-template-hash"] = "123456abcd";
    const pod = f.docs.pod.find(p => p.metadata.name === `${expected.name}-pod`);
    pod.spec = structuredClone(template.spec);
    Object.assign(pod.metadata, structuredClone(template.metadata));
    pod.metadata.labels["pod-template-hash"] = "123456abcd";
    pod.status.containerStatuses = template.spec.containers.map(c => ({ name: c.name, ready: true, imageID, state: { running: { startedAt: "2026-09-11T00:00:00Z" } } }));
    pod.status.initContainerStatuses = (template.spec.initContainers ?? []).map(c => ({ name: c.name, imageID, state: { terminated: { exitCode: 0 } } }));
  }
  const observe = phase === "backfill" ? observeSandboxBackfill : phase === "precision-intake" ? observePrecisionIntake : precision ? observePrecisionConsumers : observeCompatibility;
  const result = await observe(f.options, f.dependencies);
  assert.equal(result.deployments.length, precision ? 11 : 10);
  if (phase === "backfill") {
    await revalidateSandboxBackfill(result, f.options, f.dependencies);
    for (const [name, key, wrong, original] of [
      ["agentsec-api", "ZASP_RUNTIME_SESSION_INDEX", "zasp-runtime-sessions-v2", "zasp-runtime-sessions-v1"],
      ["agentsec-runtime-session-index-v2", "ZASP_RUNTIME_STAGE_VERSION", "runtime-index-v2", "runtime-index-v1"],
      ["agentsec-runtime-correlation", "ZASP_RUNTIME_STAGE_VERSION", "runtime-correlation-v4", "runtime-correlation-v2"],
    ]) {
      setPinnedSelection(f, name, key, wrong);
      await assert.rejects(observe(f.options, f.dependencies), /compatibility observation rejected/);
      setPinnedSelection(f, name, key, original);
    }
    f.setTime(31000);
    await assert.rejects(revalidateSandboxBackfill(result, f.options, f.dependencies), /compatibility observation rejected/);
    const ingest = f.docs.deployment.find(d => d.metadata.name === "agentsec-event-ingest");
    ingest.spec.template.spec.containers[0].env.push({ name: "ZASP_RUNTIME_INGEST_SCHEMA", value: "runtime-event-v2" });
    setPinnedSelection(f, "agentsec-event-ingest", "ZASP_RUNTIME_INGEST_SCHEMA", "runtime-event-v2");
    await assert.rejects(observeSandboxBackfill(f.options, f.dependencies), /compatibility observation rejected/);
  }
});

test("observes completed intended init containers and rejects failed or wrong-image initialization", async () => {
  const f = fixture();
  const d = f.docs.deployment[0];
  d.spec.template.spec.initContainers = [{ name: "setup", image: "example.invalid/setup@sha256:" + "a".repeat(64) }];
  f.docs.replicaset[0].spec.template = structuredClone(d.spec.template);
  f.docs.pod[0].spec = structuredClone(d.spec.template.spec);
  f.options.expected[0].templateDigest = digest(d.spec.template);
  f.options.expected[0].imageIDs.setup = imageID;
  f.docs.pod[0].status.initContainerStatuses = [{ name: "setup", imageID, state: { terminated: { exitCode: 0 } } }];
  await observeCompatibility(f.options, f.dependencies);
  f.docs.pod[0].status.initContainerStatuses[0].state.terminated.exitCode = 1;
  await assert.rejects(observeCompatibility(f.options, f.dependencies), /compatibility observation rejected/);
  f.docs.pod[0].status.initContainerStatuses[0].state.terminated.exitCode = 0;
  f.docs.pod[0].status.initContainerStatuses[0].imageID = "wrong";
  await assert.rejects(observeCompatibility(f.options, f.dependencies), /compatibility observation rejected/);
});
