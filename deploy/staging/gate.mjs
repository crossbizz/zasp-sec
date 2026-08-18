const digestPattern = /^[a-z0-9./_-]+(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$/;
const identifierPattern = /^[a-z][a-z0-9-]{1,62}$/;
const expectedWorkloads = Object.freeze(["web", "agentsec-api", "agentsec-worker", "event-ingest"]);
const expectedOperations = Object.freeze(["s3_put_get_delete", "sqs_send_receive_delete", "opensearch_index_search_delete"]);

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

function validIdentifier(value) {
  return typeof value === "string" && identifierPattern.test(value);
}

function freezeDeployment(value) {
  const workloads = value.workloads.map(({ name, image }) => Object.freeze({ name, image }));
  return Object.freeze({ cluster: value.cluster, namespace: value.namespace, serviceAccount: value.serviceAccount, privateEndpoints: true, workloads: Object.freeze(workloads) });
}

export function buildStagingDeployment(value) {
  if (!exactKeys(value, ["cluster", "namespace", "serviceAccount", "privateEndpoints", "workloads"]) || !validIdentifier(value.cluster) || value.namespace !== "agentsec" || value.serviceAccount !== "agentsec-product" || value.privateEndpoints !== true || !Array.isArray(value.workloads) || value.workloads.length !== expectedWorkloads.length) throw new Error("staging gate rejected");
  for (let index = 0; index < expectedWorkloads.length; index += 1) {
    const workload = value.workloads[index];
    if (!exactKeys(workload, ["name", "image"]) || workload.name !== expectedWorkloads[index] || !digestPattern.test(workload.image)) throw new Error("staging gate rejected");
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
  if (!exactKeys(result, ["runID", "ready", "vendorDashboardsExposed", "privateEndpoints"]) || result.runID !== runID || result.privateEndpoints !== true || result.vendorDashboardsExposed !== false || !Array.isArray(result.ready) || result.ready.join("\0") !== expectedWorkloads.join("\0")) throw new Error("staging gate rejected");
  return Object.freeze({ ...result, ready: Object.freeze([...result.ready]) });
}

export function runStagingDependencySmoke(runID, runtime) {
  if (!validIdentifier(runID) || !runtime || typeof runtime.smoke !== "function") throw new Error("staging gate rejected");
  const result = runtime.smoke(runID);
  if (!exactKeys(result, ["runID", "throughIRSA", "otlpHealthEmitted", "operations"]) || result.runID !== runID || result.throughIRSA !== true || result.otlpHealthEmitted !== true || !Array.isArray(result.operations) || result.operations.join("\0") !== expectedOperations.join("\0")) throw new Error("staging gate rejected");
  return Object.freeze({ ...result, operations: Object.freeze([...result.operations]) });
}

export function createStagingEvidence(value) {
  if (!exactKeys(value, ["terraformRevision", "clusterVersion", "cluster", "images", "deploymentRunID", "smokeRunID"]) || typeof value.terraformRevision !== "string" || !/^[0-9a-f]{40}$/.test(value.terraformRevision) || typeof value.clusterVersion !== "string" || !/^1\.[0-9]{2}\.[0-9]+$/.test(value.clusterVersion) || !validIdentifier(value.cluster) || !validIdentifier(value.deploymentRunID) || !validIdentifier(value.smokeRunID) || !Array.isArray(value.images) || value.images.length !== expectedWorkloads.length) throw new Error("staging gate rejected");
  const names = new Set();
  const images = value.images.map((item) => {
    if (!exactKeys(item, ["name", "image"]) || !expectedWorkloads.includes(item.name) || names.has(item.name) || !digestPattern.test(item.image)) throw new Error("staging gate rejected");
    names.add(item.name);
    return { name: item.name, image: item.image };
  }).sort((left, right) => left.name.localeCompare(right.name)).map(Object.freeze);
  return Object.freeze({ terraformRevision: value.terraformRevision, clusterVersion: value.clusterVersion, cluster: value.cluster, images: Object.freeze(images), deploymentRunID: value.deploymentRunID, smokeRunID: value.smokeRunID });
}

export function evaluateM1AGate(value) {
  if (!exactKeys(value, ["deploymentReady", "dependenciesReady", "privateEndpoints", "irsa", "otlpHealth", "evidence"])) throw new Error("staging gate rejected");
  createStagingEvidence(value.evidence);
  const ready = value.deploymentReady === true && value.dependenciesReady === true && value.privateEndpoints === true && value.irsa === true && value.otlpHealth === true;
  if (!ready) throw new Error("staging gate rejected");
  return Object.freeze({ ready: true, gate: "M1A", dependencies: Object.freeze(["s3", "sqs", "opensearch"]), privateEndpoints: true });
}
