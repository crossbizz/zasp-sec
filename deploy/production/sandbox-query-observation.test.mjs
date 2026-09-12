import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { renderRelease } from "./release-contract.mjs";
import { productionReleaseFixture } from "./release-fixture.mjs";
import * as bridge from "./sandbox-query-observation.mjs";
const names = ["agentsec-api", "agentsec-runtime-outbox", "agentsec-runtime-coordinator", "agentsec-runtime-archive", "agentsec-runtime-index", "agentsec-runtime-correlation", "agentsec-runtime-projection", "agentsec-runtime-complete", "agentsec-event-ingest", "agentsec-gateway-control", "agentsec-runtime-session-index-v2"];
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const digest = value => createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");

async function fixture(phase = "backfill") {
  const release = await renderRelease(productionReleaseFixture, { schemaVersion: 50, sessionSearchPhase: phase });
  const docs = { namespace: { apiVersion: "v1", kind: "Namespace", metadata: { name: "agentsec", uid: "namespace-fixture" } }, deployment: [], replicaset: [], pod: [] };
  const expected = names.map(name => {
    const template = structuredClone(release.find(row => row.kind === "Deployment" && row.metadata.name === name).spec.template);
    const imageIDs = Object.fromEntries([...template.spec.containers, ...(template.spec.initContainers ?? [])].map(container => [container.name, `docker-pullable://${container.image}`]));
    docs.deployment.push({ apiVersion: "apps/v1", kind: "Deployment", metadata: { name, namespace: "agentsec", uid: `${name}-deployment`, resourceVersion: `${name}:opaque/rv`, generation: 1 }, spec: { replicas: 1, template }, status: { observedGeneration: 1, replicas: 1, updatedReplicas: 1, readyReplicas: 1, availableReplicas: 1 } });
    docs.replicaset.push({ apiVersion: "apps/v1", kind: "ReplicaSet", metadata: { name: `${name}-rs`, namespace: "agentsec", uid: `${name}-rs`, generation: 1, ownerReferences: [{ apiVersion: "apps/v1", kind: "Deployment", name, uid: `${name}-deployment`, controller: true }] }, spec: { replicas: 1, template: structuredClone(template) }, status: { observedGeneration: 1, replicas: 1, readyReplicas: 1, availableReplicas: 1 } });
    docs.pod.push({ apiVersion: "v1", kind: "Pod", metadata: { ...structuredClone(template.metadata), name: `${name}-pod`, namespace: "agentsec", uid: `${name}-pod`, ownerReferences: [{ apiVersion: "apps/v1", kind: "ReplicaSet", name: `${name}-rs`, uid: `${name}-rs`, controller: true }] }, spec: structuredClone(template.spec), status: { phase: "Running", conditions: [{ type: "Ready", status: "True" }], containerStatuses: template.spec.containers.map(c => ({ name: c.name, imageID: imageIDs[c.name], ready: true, state: { running: { startedAt: "2026-09-12T00:00:00Z" } } })), initContainerStatuses: (template.spec.initContainers ?? []).map(c => ({ name: c.name, imageID: imageIDs[c.name], state: { terminated: { exitCode: 0 } } })) } });
    return { name, templateDigest: digest(template), imageIDs };
  });
  const calls = [];
  const request = { schema: "sandbox-query-observation-v1", operation: "observe", options: { kubeconfig: "/owned/pinned-kubeconfig", context: "fixture", namespace: "agentsec", namespaceUID: "namespace-fixture", expected, deadlineUnixMs: 4000 } };
  const dependencies = { now: () => 1000, run: async (command, args, bounds) => {
    assert.equal(command, "kubectl");
    assert.equal(args[4], "get");
    assert.equal(bounds.timeout, 3000);
    calls.push(args[5]);
    const kind = args[5];
    return { stdout: JSON.stringify(kind === "namespace" ? docs.namespace : { apiVersion: "v1", kind: "List", items: docs[kind] }) };
  } };
  return { request, dependencies, calls, docs };
}

test("bridge binds opaque API resourceVersion from the same validated backfill snapshot", async () => {
  assert.equal(typeof bridge.observeSandboxQueryRelease, "function", "read-only cutover observation bridge is missing");
  const f = await fixture();
  const result = await bridge.observeSandboxQueryRelease(f.request, f.dependencies);
  assert.equal(result.schema, "sandbox-query-observation-v1");
  assert.equal(result.apiResourceVersion, "agentsec-api:opaque/rv");
  assert.equal(result.observation.deployments.length, 11);
  assert.equal(result.observation.deployments.find(row => row.name === "agentsec-api").uid, "agentsec-api-deployment");
  assert.deepEqual(f.calls, ["namespace", "deployment", "replicaset", "pod", "namespace"]);
  assert.equal(JSON.stringify(result).includes("kubeconfig"), false);
  await bridge.observeSandboxQueryRelease({ ...f.request, operation: "revalidate", previous: result }, f.dependencies);
  f.docs.deployment.find(row => row.metadata.name === "agentsec-api").metadata.resourceVersion = "changed-rv";
  await assert.rejects(bridge.observeSandboxQueryRelease({ ...f.request, operation: "revalidate", previous: result }, f.dependencies));
});

test("bridge refuses malformed requests before any cluster read", async () => {
  assert.equal(typeof bridge.observeSandboxQueryRelease, "function");
  const f = await fixture();
  for (const request of [null, { ...f.request, apply: true }, { ...f.request, operation: "apply" }, { ...f.request, previous: {} }, { ...f.request, operation: "revalidate" }, { ...f.request, options: { ...f.request.options, deadlineUnixMs: undefined } }]) {
    await assert.rejects(bridge.observeSandboxQueryRelease(request, f.dependencies));
  }
  assert.deepEqual(f.calls, []);
});

test("bridge cannot substitute an API version from an invalid or missing deployment", async () => {
  assert.equal(typeof bridge.observeSandboxQueryRelease, "function");
  for (const fault of ["missing-rv", "wrong-uid", "stale-pod"]) {
    const f = await fixture();
    const api = f.docs.deployment.find(row => row.metadata.name === "agentsec-api");
    if (fault === "missing-rv") delete api.metadata.resourceVersion;
    if (fault === "wrong-uid") api.metadata.uid = "unrelated-api";
    if (fault === "stale-pod") f.docs.pod[0].status.phase = "Pending";
    await assert.rejects(bridge.observeSandboxQueryRelease(f.request, f.dependencies));
  }
});

test("bridge refuses deadline expiry or clock rewind after full observer validation", async () => {
  for (const finalTime of [4000, 999]) {
    const f = await fixture();
    let samples = 0;
    f.dependencies.now = () => ++samples <= 12 ? 1000 : finalTime;
    await assert.rejects(bridge.observeSandboxQueryRelease(f.request, f.dependencies));
    assert.equal(f.calls.length, 5, "failure must follow the complete read-only observation");
    assert.equal(samples, 13, "wrapper must check its completion time");
  }
});

test("read-only bridge process refuses malformed or oversized input without exposing it", () => {
  const entry = fileURLToPath(new URL("./sandbox-query-observation.mjs", import.meta.url));
  for (const [args, input] of [[[], "secret-invalid-json"], [[], "null"], [["--apply"], "{}"], [[], JSON.stringify({ secret: "x".repeat(4 * 1024 * 1024) })]]) {
    const result = spawnSync(process.execPath, [entry, ...args], { input, encoding: "utf8", timeout: 3000, maxBuffer: 4096 });
    assert.equal(result.status, 1, "invalid bridge input must fail the process");
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "sandbox query observation rejected\n");
  }
});

test("bridge process returns the validated snapshot through its real stdin/stdout protocol", async t => {
  const f = await fixture();
  const directory = await mkdtemp(path.join(tmpdir(), "zasp-observation-cli-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  // Only kubectl transport is controlled. The real Node entry, request parser,
  // actual-render observer and output serialization execute in a child process.
  const program = `#!${process.execPath}\nconst assert=require('node:assert/strict');
const args=process.argv.slice(2), docs=${JSON.stringify(f.docs)};
assert.equal(args[0],'--kubeconfig');assert.equal(args[1],'/owned/pinned-kubeconfig');
assert.equal(args[2],'--context');assert.equal(args[3],'fixture');assert.equal(args[4],'get');
assert.ok(['namespace','deployment','replicaset','pod'].includes(args[5]));
process.stdout.write(JSON.stringify(args[5]==='namespace'?docs.namespace:{apiVersion:'v1',kind:'List',items:docs[args[5]]}));\n`;
  await writeFile(path.join(directory, "kubectl"), program, { mode: 0o700 });
  f.request.options.deadlineUnixMs = Date.now() + 10000;
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("./sandbox-query-observation.mjs", import.meta.url))], {
    input: JSON.stringify(f.request), encoding: "utf8", timeout: 12000, maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, PATH: `${directory}${path.delimiter}${process.env.PATH}` },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.stdout);
  assert.equal(output.schema, "sandbox-query-observation-v1");
  assert.equal(output.apiResourceVersion, "agentsec-api:opaque/rv");
  assert.equal(output.observation.deployments.length, 11);
  assert.equal(output.observation.namespaceUID, "namespace-fixture");
  assert.ok(output.observation.observedAt < f.request.options.deadlineUnixMs);
  assert.equal(result.stdout.includes("kubeconfig"), false);
});

test("query observation requires all ready query consumers and refuses old API replicas", async () => {
  const query = await fixture("query");
  const result = await bridge.observeSandboxQueryRelease({ ...query.request, operation: "observe-query" }, query.dependencies);
  assert.equal(result.observation.deployments.length, 11);
  assert.equal(result.apiResourceVersion, "agentsec-api:opaque/rv");
  const old = await fixture();
  await assert.rejects(bridge.observeSandboxQueryRelease({ ...old.request, operation: "observe-query" }, old.dependencies));
  query.docs.deployment.find(row => row.metadata.name === "agentsec-api").status.updatedReplicas = 0;
  await assert.rejects(bridge.observeSandboxQueryRelease({ ...query.request, operation: "observe-query" }, query.dependencies));
});
