import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);
const consumers = Object.freeze(["agentsec-api", "agentsec-runtime-outbox", "agentsec-runtime-coordinator", "agentsec-runtime-archive", "agentsec-runtime-index", "agentsec-runtime-correlation", "agentsec-runtime-projection", "agentsec-runtime-complete", "agentsec-event-ingest", "agentsec-gateway-control"]);
const reject = () => { throw new Error("compatibility observation rejected"); };
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(k => [k, stable(value[k])])) : value;
export const templateDigest = value => createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");
const same = (a, b) => JSON.stringify(stable(a)) === JSON.stringify(stable(b));
const positive = value => Number.isSafeInteger(value) && value > 0;
const identity = value => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$/.test(value);
const controller = (child, parent) => {
  const owners = child.metadata?.ownerReferences?.filter(o => o.controller === true);
  return owners?.length === 1 && owners[0].apiVersion === parent.apiVersion && owners[0].kind === parent.kind && owners[0].name === parent.metadata.name && owners[0].uid === parent.metadata.uid;
};
const normalizedTemplate = template => {
  const value = structuredClone(template);
  if (value?.metadata?.labels) delete value.metadata.labels["pod-template-hash"];
  return value;
};

const precisionSelections = Object.freeze({
  "agentsec-api": { ZASP_RUNTIME_SESSION_INDEX: "zasp-runtime-sessions-v2" },
  "agentsec-event-ingest": { ZASP_RUNTIME_INGEST_SCHEMA: "runtime-event-v1" },
  "agentsec-runtime-outbox": { ZASP_RUNTIME_DELIVERY_SCHEMA: "runtime-event-v2" },
  "agentsec-runtime-coordinator": { ZASP_RUNTIME_DELIVERY_SCHEMA: "runtime-event-v2" },
  "agentsec-runtime-archive": { ZASP_RUNTIME_STAGE_VERSION: "runtime-archive-v2" },
  "agentsec-runtime-index": { ZASP_RUNTIME_STAGE_VERSION: "runtime-index-v1", ZASP_RUNTIME_SESSION_INDEX: "zasp-runtime-sessions-v1" },
  "agentsec-runtime-session-index-v2": { ZASP_RUNTIME_STAGE_VERSION: "runtime-index-v2", ZASP_RUNTIME_SESSION_INDEX: "zasp-runtime-sessions-v2" },
  "agentsec-runtime-correlation": { ZASP_RUNTIME_STAGE_VERSION: "runtime-correlation-v4" },
  "agentsec-runtime-projection": { ZASP_RUNTIME_STAGE_VERSION: "runtime-projection-v3" },
  "agentsec-runtime-complete": { ZASP_RUNTIME_STAGE_VERSION: "runtime-complete-v3" },
});

const backfillSelections = Object.freeze({
  "agentsec-api": { ZASP_RUNTIME_SESSION_INDEX: "zasp-runtime-sessions-v1" },
  "agentsec-event-ingest": { ZASP_RUNTIME_INGEST_SCHEMA: null },
  "agentsec-runtime-outbox": { ZASP_RUNTIME_DELIVERY_SCHEMA: null },
  "agentsec-runtime-coordinator": { ZASP_RUNTIME_DELIVERY_SCHEMA: null },
  "agentsec-runtime-archive": { ZASP_RUNTIME_STAGE_VERSION: "runtime-archive-v1" },
  "agentsec-runtime-index": { ZASP_RUNTIME_STAGE_VERSION: "runtime-index-v1", ZASP_RUNTIME_SESSION_INDEX: "zasp-runtime-sessions-v1" },
  "agentsec-runtime-session-index-v2": { ZASP_RUNTIME_STAGE_VERSION: "runtime-index-v1", ZASP_RUNTIME_SESSION_INDEX: "zasp-runtime-sessions-v2" },
  "agentsec-runtime-correlation": { ZASP_RUNTIME_STAGE_VERSION: "runtime-correlation-v2" },
  "agentsec-runtime-projection": { ZASP_RUNTIME_STAGE_VERSION: "runtime-projection-v1" },
  "agentsec-runtime-complete": { ZASP_RUNTIME_STAGE_VERSION: "runtime-complete-v1" },
});

// Read-only evidence. This neither authenticates a release artifact nor grants
// permission to mutate Kubernetes or the database.
export async function observeCompatibility(options, dependencies = {}) {
  return observeConsumers(options, dependencies, {});
}

export async function observeSandboxBackfill(options, dependencies = {}) {
  return observeConsumers(options, dependencies, { backfill: true });
}

// Completed query rollout evidence uses the same11-consumer checks. It changes
// only the API selector, not worker versions or any readiness requirement.
export async function observeSandboxQuery(options, dependencies = {}) {
  return observeConsumers(options, dependencies, { backfill: true, query: true });
}

export async function revalidateSandboxBackfill(previous, options, dependencies = {}) {
  return revalidateObservation(previous, options, dependencies, observeSandboxBackfill);
}

export async function observePrecisionConsumers(options, dependencies = {}) {
  return observeConsumers(options, dependencies, { precision: true });
}

export async function observePrecisionIntake(options, dependencies = {}) {
  return observeConsumers(options, dependencies, { precision: true, intakeSchema: "runtime-event-v2" });
}

export async function revalidatePrecisionIntake(previous, options, dependencies = {}) {
  return revalidateObservation(previous, options, dependencies, observePrecisionIntake);
}

async function observeConsumers(options, { run = exec, now = Date.now } = {}, { precision = false, backfill = false, query = false, intakeSchema = "runtime-event-v1" }) {
  try {
    const forward = precision || backfill;
    const requiredConsumers = forward ? [...consumers, "agentsec-runtime-session-index-v2"] : consumers;
    const schemaVersion = precision ? "51" : backfill ? "50" : "49";
    const { kubeconfig, context, namespace, namespaceUID, expected } = options;
    if (typeof kubeconfig !== "string" || !path.isAbsolute(kubeconfig) || !identity(context) || !identity(namespace) || !identity(namespaceUID) || !Array.isArray(expected) || !same(expected.map(e => e.name).sort(), [...requiredConsumers].sort())) reject();
    for (const e of expected) {
      if (!/^[a-f0-9]{64}$/.test(e.templateDigest) || !e.imageIDs || Object.keys(e.imageIDs).length === 0 || Object.values(e.imageIDs).some(id => typeof id !== "string" || !/^(?:docker-pullable:\/\/)?[^\s]+@sha256:[a-f0-9]{64}$/.test(id))) reject();
    }
    const startedAt = now();
    if (!Number.isSafeInteger(startedAt) || startedAt < 0) reject();
    const deadline = options.deadlineUnixMs === undefined ? startedAt + 30000 : options.deadlineUnixMs;
    if (!Number.isSafeInteger(deadline) || deadline <= startedAt || deadline > startedAt + 30000) reject();
    let lastTime = startedAt;
    const remaining = () => {
      const current = now();
      if (!Number.isSafeInteger(current) || current < lastTime || current >= deadline) reject();
      lastTime = current;
      return deadline - current;
    };
    const read = async kind => {
      const timeout = Math.min(5000, remaining());
      const requestTimeout = timeout === 5000 ? "5s" : `${timeout}ms`;
      const args = ["--kubeconfig", kubeconfig, "--context", context, "get", kind, ...(kind === "namespace" ? [namespace] : ["--namespace", namespace]), "--output=json", `--request-timeout=${requestTimeout}`];
      const { stdout } = await run("kubectl", args, { encoding: "utf8", timeout, maxBuffer: 4 * 1024 * 1024 });
      remaining();
      if (typeof stdout !== "string" || Buffer.byteLength(stdout) > 4 * 1024 * 1024) reject();
      return JSON.parse(stdout);
    };
    const ns = await read("namespace");
    const validNamespace = value => value.apiVersion === "v1" && value.kind === "Namespace" && value.metadata?.name === namespace && value.metadata.uid === namespaceUID && !value.metadata.deletionTimestamp;
    if (!validNamespace(ns)) reject();
    const lists = {};
    for (const kind of ["deployment", "replicaset", "pod"]) {
      const list = await read(kind);
      if (list.apiVersion !== "v1" || list.kind !== "List" || !Array.isArray(list.items)) reject();
      lists[kind] = list.items;
      const uids = new Set();
      const names = new Set();
      for (const row of list.items) {
        if (row.apiVersion !== (kind === "pod" ? "v1" : "apps/v1") || row.kind !== { deployment: "Deployment", replicaset: "ReplicaSet", pod: "Pod" }[kind] || row.metadata?.namespace !== namespace || !identity(row.metadata?.uid) || !identity(row.metadata?.name) || uids.has(row.metadata.uid) || names.has(row.metadata.name)) reject();
        uids.add(row.metadata.uid); names.add(row.metadata.name);
      }
    }
    if (forward) {
      const coordinator = lists.deployment.find(d => d.metadata.name === "agentsec-runtime-coordinator");
      const account = coordinator?.spec?.template?.spec?.serviceAccountName;
      const sets = lists.replicaset.filter(rs => coordinator && controller(rs, coordinator));
      for (const p of lists.pod) {
        const labels = p.metadata.labels ?? {};
        const matches = labels.app === "agentsec-runtime-coordinator" || labels["app.kubernetes.io/name"] === "agentsec-runtime-coordinator" || account && p.spec?.serviceAccountName === account || p.spec?.containers?.some(c => c.env?.some(e => e.name === "ZASP_WORKER_MODE" && e.value === "runtime-coordinator"));
        if (matches && !sets.some(rs => controller(p, rs))) reject();
      }
    }
    const deployments = expected.map(want => {
      const d = lists.deployment.find(row => row.metadata.name === want.name);
      if (!d || d.metadata.deletionTimestamp || !positive(d.metadata.generation) || !positive(d.spec?.replicas) || d.status?.observedGeneration !== d.metadata.generation || d.spec.template?.metadata?.annotations?.["zasp.io/schema-version"] !== schemaVersion || templateDigest(d.spec.template) !== want.templateDigest) reject();
      if (forward) {
        const containers = d.spec.template.spec?.containers;
        if (!Array.isArray(containers) || containers.length !== 1) reject();
        for (const [key, value] of Object.entries((backfill ? backfillSelections : precisionSelections)[want.name] ?? {})) {
          const entries = containers[0].env?.filter(e => e.name === key) ?? [];
          if (value === null) { if (entries.length !== 0) reject(); continue; }
          const expectedValue = query && want.name === "agentsec-api" && key === "ZASP_RUNTIME_SESSION_INDEX"
            ? "zasp-runtime-sessions-v2"
            : precision && key === "ZASP_RUNTIME_INGEST_SCHEMA" ? intakeSchema : value;
          if (entries?.length !== 1 || entries[0].value !== expectedValue || entries[0].valueFrom !== undefined) reject();
        }
      }
      for (const field of ["replicas", "updatedReplicas", "readyReplicas", "availableReplicas"]) if (d.status[field] !== d.spec.replicas) reject();
      if ((d.status.unavailableReplicas ?? 0) !== 0 || (d.status.terminatingReplicas ?? 0) !== 0) reject();
      const sets = lists.replicaset.filter(rs => controller(rs, d));
      const active = sets.filter(rs => rs.spec?.replicas !== 0 || (rs.status?.replicas ?? 0) !== 0);
      if (active.length !== 1) reject();
      const rs = active[0];
      if (rs.metadata.deletionTimestamp || !positive(rs.metadata.generation) || rs.status?.observedGeneration !== rs.metadata.generation || rs.spec.replicas !== d.spec.replicas || !same(normalizedTemplate(rs.spec.template), normalizedTemplate(d.spec.template))) reject();
      for (const field of ["replicas", "readyReplicas", "availableReplicas"]) if (rs.status[field] !== d.spec.replicas) reject();
      const ownedPods = lists.pod.filter(p => sets.some(s => controller(p, s)));
      if (ownedPods.length !== d.spec.replicas) reject();
      const pods = ownedPods.map(p => {
        if (!controller(p, rs) || p.metadata.deletionTimestamp || p.status?.phase !== "Running" || p.status.conditions?.filter(c => c.type === "Ready" && c.status === "True").length !== 1) reject();
        // The admitted template includes defaults. Pod-only scheduling fields
        // may be added, but every intended template spec field must agree.
        for (const [key, value] of Object.entries(d.spec.template.spec)) if (!same(p.spec?.[key], value)) reject();
        for (const key of Object.keys(p.spec ?? {})) if (!(key in d.spec.template.spec) && key !== "nodeName") reject();
        if (p.spec.ephemeralContainers?.length || p.status.ephemeralContainerStatuses?.length) reject();
        const labels = { ...p.metadata.labels };
        delete labels["pod-template-hash"];
        if (!same(labels, normalizedTemplate(d.spec.template).metadata.labels ?? {}) || !same(p.metadata.annotations ?? {}, d.spec.template.metadata.annotations ?? {})) reject();
        const containers = p.spec.containers;
        const statuses = p.status.containerStatuses;
        const initContainers = p.spec.initContainers ?? [];
        const initStatuses = p.status.initContainerStatuses ?? [];
        if (!Array.isArray(containers) || !Array.isArray(statuses) || !Array.isArray(initContainers) || !Array.isArray(initStatuses)) reject();
        const allNames = [...containers, ...initContainers].map(c => c.name).sort();
        if (new Set(allNames).size !== allNames.length || !same(allNames, Object.keys(want.imageIDs).sort()) || !same(statuses.map(c => c.name).sort(), containers.map(c => c.name).sort()) || !same(initStatuses.map(c => c.name).sort(), initContainers.map(c => c.name).sort())) reject();
        for (const c of statuses) if (!c.ready || !c.state?.running?.startedAt || c.imageID !== want.imageIDs[c.name]) reject();
        for (const c of initStatuses) if (c.state?.terminated?.exitCode !== 0 || c.imageID !== want.imageIDs[c.name]) reject();
        return { uid: p.metadata.uid, name: p.metadata.name, imageIDs: Object.fromEntries([...statuses, ...initStatuses].map(c => [c.name, c.imageID])) };
      }).sort((a, b) => a.uid.localeCompare(b.uid));
      return { name: want.name, uid: d.metadata.uid, generation: d.metadata.generation, observedGeneration: d.status.observedGeneration, templateDigest: want.templateDigest, replicaSetUID: rs.metadata.uid, pods };
    }).sort((a, b) => a.name.localeCompare(b.name));
    if (!validNamespace(await read("namespace"))) reject();
    const observedAt = now();
    if (!Number.isSafeInteger(observedAt) || observedAt < lastTime || observedAt >= deadline) reject();
    return { context, namespace, namespaceUID, observedAt, deployments };
  } catch { reject(); }
}

export async function revalidateCompatibility(previous, options, dependencies = {}) {
  return revalidateObservation(previous, options, dependencies, observeCompatibility);
}

export async function revalidatePrecisionConsumers(previous, options, dependencies = {}) {
  return revalidateObservation(previous, options, dependencies, observePrecisionConsumers);
}

async function revalidateObservation(previous, options, dependencies, observe) {
  const now = dependencies.now ?? Date.now;
  const currentTime = now();
  if (!Number.isSafeInteger(previous?.observedAt) || currentTime < previous.observedAt || currentTime - previous.observedAt >= 30000) reject();
  const current = await observe(options, dependencies);
  if (current.observedAt - previous.observedAt >= 30000 || !same({ ...previous, observedAt: 0 }, { ...current, observedAt: 0 })) reject();
  return current;
}
