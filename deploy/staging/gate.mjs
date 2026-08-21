const digestPattern = /^[a-z0-9./_-]+(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$/;
const identifierPattern = /^[a-z][a-z0-9-]{1,62}$/;
const expectedWorkloads = Object.freeze([
  Object.freeze({ name: "web", serviceAccount: "agentsec-web", role: null }),
  Object.freeze({ name: "agentsec-api", serviceAccount: "agentsec-api", role: "api" }),
  Object.freeze({ name: "agentsec-discovery-scheduler", serviceAccount: "zasp-discovery-scheduler", role: "discovery-scheduler" }),
  Object.freeze({ name: "agentsec-discovery-worker", serviceAccount: "zasp-discovery-worker", role: "discovery-worker" }),
  Object.freeze({ name: "agentsec-outbox-publisher", serviceAccount: "zasp-outbox-publisher", role: "outbox" }),
  Object.freeze({ name: "agentsec-projection-risk", serviceAccount: "zasp-projection-risk", role: "projection-risk" }),
  Object.freeze({ name: "agentsec-projection-graph", serviceAccount: "zasp-projection-graph", role: "projection-graph" }),
  Object.freeze({ name: "agentsec-projection-search", serviceAccount: "zasp-projection-search", role: "projection-search" }),
  Object.freeze({ name: "agentsec-event-ingest", serviceAccount: "zasp-runtime-ingest", role: "runtime-ingest" }),
  Object.freeze({ name: "agentsec-gateway-control", serviceAccount: "zasp-gateway-control", role: "gateway-control" }),
  Object.freeze({ name: "agentsec-runtime-outbox", serviceAccount: "zasp-runtime-outbox", role: "runtime-outbox" }),
  Object.freeze({ name: "agentsec-runtime-coordinator", serviceAccount: "zasp-runtime-coordinator", role: "runtime-coordinator" }),
  Object.freeze({ name: "agentsec-runtime-archive", serviceAccount: "zasp-runtime-archive", role: "runtime-archive" }),
  Object.freeze({ name: "agentsec-runtime-index", serviceAccount: "zasp-runtime-index", role: "runtime-index" }),
  Object.freeze({ name: "agentsec-runtime-correlation", serviceAccount: "zasp-runtime-correlation", role: "runtime-correlation" }),
  Object.freeze({ name: "agentsec-runtime-projection", serviceAccount: "zasp-runtime-projection", role: "runtime-projection" }),
  Object.freeze({ name: "agentsec-runtime-complete", serviceAccount: "zasp-runtime-complete", role: "runtime-complete" }),
  Object.freeze({ name: "nango", serviceAccount: "nango", role: null, image: "nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed" }),
  Object.freeze({ name: "otel-collector", serviceAccount: "otel-collector", role: null, image: "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5" }),
]);
const expectedJobIdentities = Object.freeze([
  Object.freeze({ name: "agentsec-schema-v16", serviceAccount: "agentsec-migration", role: "migration" }),
  Object.freeze({ name: "agentsec-projection-graph-init-v1", serviceAccount: "agentsec-projection-graph-init", role: "projection-graph-init" }),
  Object.freeze({ name: "agentsec-projection-search-init-v1", serviceAccount: "agentsec-projection-search-init", role: "projection-search-init" }),
  Object.freeze({ name: "nango-migrate", serviceAccount: "nango-migrate", role: null }),
  Object.freeze({ name: "production-readonly-canary", serviceAccount: "agentsec-canary", role: null }),
  Object.freeze({ name: "zasp-canary-secret-sync", serviceAccount: "agentsec-canary-secret-sync", role: "canary-secret-sync" }),
]);

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

function validIdentifier(value) {
  return typeof value === "string" && identifierPattern.test(value);
}

function freezeDeployment(value) {
  const workloads = value.workloads.map(({ name, image, serviceAccount, roleArn }) => Object.freeze({ name, image, serviceAccount, roleArn }));
  const jobIdentities = value.jobIdentities.map(({ name, serviceAccount, roleArn }) => Object.freeze({ name, serviceAccount, roleArn }));
  return Object.freeze({ cluster: value.cluster, namespace: value.namespace, platformAccountID: value.platformAccountID, privateEndpoints: true, workloads: Object.freeze(workloads), jobIdentities: Object.freeze(jobIdentities) });
}

export function buildStagingDeployment(value) {
  if (!exactKeys(value, ["cluster", "namespace", "platformAccountID", "privateEndpoints", "workloads", "jobIdentities"]) || !validIdentifier(value.cluster) || value.namespace !== "agentsec" || !/^[0-9]{12}$/.test(value.platformAccountID) || value.platformAccountID === "000000000000" || value.privateEndpoints !== true || !Array.isArray(value.workloads) || value.workloads.length !== expectedWorkloads.length || !Array.isArray(value.jobIdentities) || value.jobIdentities.length !== expectedJobIdentities.length) throw new Error("staging gate rejected");
  for (let index = 0; index < expectedWorkloads.length; index += 1) {
    const workload = value.workloads[index];
    const expected = expectedWorkloads[index];
    if (!exactKeys(workload, ["name", "image", "serviceAccount", "roleArn"]) || workload.name !== expected.name || workload.serviceAccount !== expected.serviceAccount || !digestPattern.test(workload.image) || (expected.image && workload.image !== expected.image)) throw new Error("staging gate rejected");
    const roleArn = expected.role === null ? null : `arn:aws:iam::${value.platformAccountID}:role/zasp-production-${expected.role}`;
    if (workload.roleArn !== roleArn) throw new Error("staging gate rejected");
  }
  for (let index = 0; index < expectedJobIdentities.length; index += 1) {
    const identity = value.jobIdentities[index];
    const expected = expectedJobIdentities[index];
    const roleArn = expected.role === null ? null : `arn:aws:iam::${value.platformAccountID}:role/zasp-production-${expected.role}`;
    if (!exactKeys(identity, ["name", "serviceAccount", "roleArn"]) || identity.name !== expected.name || identity.serviceAccount !== expected.serviceAccount || identity.roleArn !== roleArn) throw new Error("staging gate rejected");
  }
  return freezeDeployment(value);
}

export function startStagingDeployment(value, runtime) {
  const deployment = buildStagingDeployment(value);
  if (!runtime || typeof runtime.start !== "function") throw new Error("staging gate rejected");
  const runID = runtime.start(deployment);
  if (!validIdentifier(runID)) throw new Error("staging gate rejected");
  return runID;
}

export function inspectStagingDeployment(runID, runtime) {
  if (!validIdentifier(runID) || !runtime || typeof runtime.inspect !== "function") throw new Error("staging gate rejected");
  const result = runtime.inspect(runID);
  const expectedReady = expectedWorkloads.map(({ name }) => name);
  if (!exactKeys(result, ["runID", "ready", "vendorDashboardsExposed", "privateEndpoints"]) || result.runID !== runID || result.privateEndpoints !== true || result.vendorDashboardsExposed !== false || !Array.isArray(result.ready) || result.ready.join("\0") !== expectedReady.join("\0")) throw new Error("staging gate rejected");
  return Object.freeze({ ...result, ready: Object.freeze([...result.ready]) });
}

export function createStagingEvidence(value) {
  if (!exactKeys(value, ["terraformRevision", "clusterVersion", "cluster", "platformAccountID", "images", "identities", "deploymentRunID"]) || typeof value.terraformRevision !== "string" || !/^[0-9a-f]{40}$/.test(value.terraformRevision) || typeof value.clusterVersion !== "string" || !/^1\.[0-9]{2}\.[0-9]+$/.test(value.clusterVersion) || !validIdentifier(value.cluster) || !/^[0-9]{12}$/.test(value.platformAccountID) || value.platformAccountID === "000000000000" || !validIdentifier(value.deploymentRunID) || !Array.isArray(value.images) || value.images.length !== expectedWorkloads.length || !Array.isArray(value.identities) || value.identities.length !== expectedWorkloads.length + expectedJobIdentities.length) throw new Error("staging gate rejected");
  const names = new Set();
  const expectedNames = expectedWorkloads.map(({ name }) => name);
  const images = value.images.map((item) => {
    if (!exactKeys(item, ["name", "image"]) || !expectedNames.includes(item.name) || names.has(item.name) || !digestPattern.test(item.image)) throw new Error("staging gate rejected");
    names.add(item.name);
    return { name: item.name, image: item.image };
  }).sort((left, right) => left.name.localeCompare(right.name)).map(Object.freeze);
  const expectedIdentities = [...expectedWorkloads, ...expectedJobIdentities];
  const identities = value.identities.map((identity, index) => {
    const expected = expectedIdentities[index];
    const roleArn = expected.role === null ? null : `arn:aws:iam::${value.platformAccountID}:role/zasp-production-${expected.role}`;
    if (!exactKeys(identity, ["name", "serviceAccount", "roleArn"]) || identity.name !== expected.name || identity.serviceAccount !== expected.serviceAccount || identity.roleArn !== roleArn) throw new Error("staging gate rejected");
    return Object.freeze({ ...identity });
  });
  return Object.freeze({ terraformRevision: value.terraformRevision, clusterVersion: value.clusterVersion, cluster: value.cluster, platformAccountID: value.platformAccountID, images: Object.freeze(images), identities: Object.freeze(identities), deploymentRunID: value.deploymentRunID });
}

export function evaluateM1AGate(value) {
  if (!exactKeys(value, ["deploymentReady", "privateEndpoints", "perWorkloadIAM", "evidence"])) throw new Error("staging gate rejected");
  createStagingEvidence(value.evidence);
  const ready = value.deploymentReady === true && value.privateEndpoints === true && value.perWorkloadIAM === true;
  if (!ready) throw new Error("staging gate rejected");
  return Object.freeze({ ready: true, gate: "M1A", workloads: Object.freeze(expectedWorkloads.map(({ name }) => name)), privateEndpoints: true, perWorkloadIAM: true });
}
