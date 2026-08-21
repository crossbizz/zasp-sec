import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { loadAll, JSON_SCHEMA } from "js-yaml";

const exec = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const digestPattern = /^[a-z0-9][a-z0-9./_-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$/;
const hostPattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const namePattern = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const productIDPattern = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const imageNames = Object.freeze(["web", "agentsecApi", "agentsecWorker", "eventIngest", "gatewayControl", "runtimeGateway", "sensorAgent"]);
const tetragonChartDigest = "4935787067939cacfe779366e9959962458d0cb6accdb368ec2554c1b733b3b2";
const discoveryKeys = Object.freeze([
  "parserVersion", "toolVersion", "awsCollectorVersion", "kubernetesCollectorVersion", "githubCollectorVersion", "oktaCollectorVersion",
  "awsRegion", "queueURL", "roleArn", "webIdentityTokenFile", "secretPrefix", "evidenceBucket", "evidenceBucketOwner", "evidenceKMSKeyArn",
  "githubAppID", "githubPrivateKeyReference", "oktaClientID", "oktaClientSecretReference", "providerTimeout", "readinessTimeout",
]);
const projectionSearchKeys = Object.freeze(["awsRegion", "endpoint", "index", "roleArn", "webIdentityTokenFile", "initRoleArn"]);
const projectionRiskKeys = Object.freeze(["roleArn"]);
const projectionGraphKeys = Object.freeze(["awsRegion", "endpoint", "endpointCIDR", "credentialReference", "schemaCredentialReference", "secretPrefix", "roleArn", "webIdentityTokenFile", "initRoleArn", "expectedPrincipal", "expectedRole"]);
const outboxKeys = Object.freeze(["awsRegion", "queueURL", "roleArn", "webIdentityTokenFile", "egressCIDRs"]);
const runtimeKeys = Object.freeze([
  "awsRegion", "queueURL", "rawBucket", "rawBucketOwner", "rawKMSKeyArn", "openSearchEndpoint", "openSearchIndex", "webIdentityTokenFile",
  "eventIngestRoleArn", "gatewayControlRoleArn", "outboxRoleArn", "coordinatorRoleArn", "archiveRoleArn", "indexRoleArn", "correlationRoleArn", "projectionRoleArn", "completeRoleArn", "egressCIDRs",
]);
const connectorKeys = Object.freeze(["awsRegion", "roleArn", "awsCustomerRolePrefixes", "awsCustomerRoleARNs", "webIdentityTokenFile", "kmsKeyArn", "secretPrefix", "githubClientID", "githubClientSecretReference", "githubAppID", "githubPrivateKeyReference", "oktaClientID", "oktaClientSecretReference"]);
const connectorEgressKeys = Object.freeze(["aws", "github", "okta", "kubernetes"]);
const nangoKeys = Object.freeze(["storageSecretName", "databaseEgressCIDRs", "providerEgressCIDRs"]);
const telemetryKeys = Object.freeze(["backend", "endpoint", "authSecretName", "egressCIDRs"]);

export async function inspectContainerBuilds() {
  const definitions = [
    { name: "web", file: "web.Dockerfile", port: 3000 },
    { name: "agentsec-api", file: "api.Dockerfile", port: 8080 },
    { name: "agentsec-worker", file: "worker.Dockerfile", port: 8081 },
    { name: "event-ingest", file: "event-ingest.Dockerfile", port: 8081 },
    { name: "gateway-control", file: "gateway-control.Dockerfile", port: 8081 },
    { name: "runtime-gateway", file: "runtime-gateway.Dockerfile", port: 8081 },
    { name: "sensor-agent", file: "sensor-agent.Dockerfile", port: 8081 },
  ];
  return Promise.all(definitions.map(async ({ name, file, port }) => {
    const source = await readFile(path.join(here, file), "utf8");
    const runtime = source.slice(source.lastIndexOf("\nFROM "));
    const fromLines = [...source.matchAll(/^FROM\s+(\S+)/gm)].map((match) => match[1]);
    const user = runtime.match(/^USER ([^\n]+)$/m)?.[1] ?? "";
    const healthcheck = runtime.match(/^HEALTHCHECK ([^\n]+)$/m)?.[1] ?? "";
    const exposed = runtime.match(/^EXPOSE ([^\n]+)$/m)?.[1]?.split(/\s+/).map(Number) ?? [];
    return Object.freeze({
      name, user, port, healthcheck,
      readOnlyCompatible: user === "65532:65532" && exposed.includes(port) && !/\b(?:VOLUME|sudo|chmod 777)\b/i.test(runtime),
      digestPinned: fromLines.length >= 2 && fromLines.every((image) => /@sha256:[0-9a-f]{64}$/.test(image)),
      containsSecret: /(?:ARG|ENV)\s+[^\n]*(?:SECRET|TOKEN|PASSWORD|DSN)/i.test(source),
    });
  }));
}

export async function renderRelease(value) {
  if (!validRelease(value)) throw new Error("release rejected");
  const platformAccountID = value.discovery.roleArn.match(/^arn:aws:iam::([0-9]{12}):role\//)[1];
  const set = [
    ["global.publicOrigin", `https://${value.host}`],
    ["global.trustedProxyCIDRs[0]", "10.20.0.0/16"],
    ["serviceAccounts.api.roleArn", `arn:aws:iam::${platformAccountID}:role/zasp-production-api`],
    ["serviceAccounts.migration.roleArn", `arn:aws:iam::${platformAccountID}:role/zasp-production-migration`],
    ["serviceAccounts.worker.roleArn", value.discovery.roleArn],
    ["serviceAccounts.scheduler.roleArn", `arn:aws:iam::${platformAccountID}:role/zasp-production-discovery-scheduler`],
    ["serviceAccounts.securityAgent.roleArn", `arn:aws:iam::${platformAccountID}:role/zasp-production-security-agent-worker`],
    ["serviceAccounts.projectionRisk.roleArn", value.projectionRisk.roleArn],
    ["serviceAccounts.projectionGraph.roleArn", value.projectionGraph.roleArn],
    ["serviceAccounts.projectionGraphInit.roleArn", value.projectionGraph.initRoleArn],
    ["serviceAccounts.projectionSearch.roleArn", value.projectionSearch.roleArn],
    ["serviceAccounts.projectionSearchInit.roleArn", value.projectionSearch.initRoleArn],
    ["serviceAccounts.outbox.roleArn", value.outbox.roleArn],
    ["serviceAccounts.runtimeIngest.roleArn", value.runtime.eventIngestRoleArn],
    ["serviceAccounts.gatewayControl.roleArn", value.runtime.gatewayControlRoleArn],
    ["serviceAccounts.runtimeOutbox.roleArn", value.runtime.outboxRoleArn],
    ["serviceAccounts.runtimeCoordinator.roleArn", value.runtime.coordinatorRoleArn],
    ["serviceAccounts.runtimeArchive.roleArn", value.runtime.archiveRoleArn],
    ["serviceAccounts.runtimeIndex.roleArn", value.runtime.indexRoleArn],
    ["serviceAccounts.runtimeCorrelation.roleArn", value.runtime.correlationRoleArn],
    ["serviceAccounts.runtimeProjection.roleArn", value.runtime.projectionRoleArn],
    ["serviceAccounts.runtimeComplete.roleArn", value.runtime.completeRoleArn],
    ["serviceAccounts.canarySecretSync.roleArn", `arn:aws:iam::${platformAccountID}:role/zasp-production-canary-secret-sync`],
    ["ingress.host", value.host], ["ingress.tlsSecretName", value.tlsSecretName],
    ["secrets.providerClassName", value.secretProviderClass],
    ["secrets.apiPostgresDSNObjectName", "zasp/production/postgres-api-dsn"],
    ["secrets.securityAgentAPIPostgresDSNObjectName", "zasp/production/postgres-security-agent-api-dsn"],
    ["secrets.securityAgentWorkerPostgresDSNObjectName", "zasp/production/postgres-security-agent-worker-dsn"],
    ["secrets.workerPostgresDSNObjectName", "zasp/production/postgres-worker-dsn"],
    ["secrets.schedulerPostgresDSNObjectName", "zasp/production/postgres-scheduler-dsn"],
    ["secrets.projectionRiskPostgresDSNObjectName", "zasp/production/postgres-projection-risk-dsn"],
    ["secrets.projectionGraphPostgresDSNObjectName", "zasp/production/postgres-projection-graph-dsn"],
    ["secrets.projectionSearchPostgresDSNObjectName", "zasp/production/postgres-projection-search-dsn"],
    ["secrets.outboxPostgresDSNObjectName", "zasp/production/postgres-outbox-worker-dsn"],
    ["secrets.runtimeIngestPostgresDSNObjectName", "zasp/production/postgres-runtime-ingest-dsn"],
    ["secrets.runtimeCoordinatorPostgresDSNObjectName", "zasp/production/postgres-runtime-coordinator-dsn"],
    ["secrets.runtimeArchivePostgresDSNObjectName", "zasp/production/postgres-runtime-archive-dsn"],
    ["secrets.runtimeIndexPostgresDSNObjectName", "zasp/production/postgres-runtime-index-dsn"],
    ["secrets.runtimeCorrelationPostgresDSNObjectName", "zasp/production/postgres-runtime-correlation-dsn"],
    ["secrets.runtimeProjectionPostgresDSNObjectName", "zasp/production/postgres-runtime-projection-dsn"],
    ["secrets.gatewayControlPostgresDSNObjectName", "zasp/production/postgres-gateway-control-dsn"],
    ["secrets.migrationPostgresDSNObjectName", "zasp/production/postgres-migration-dsn"],
    ["secrets.stytchProjectIDObjectName", "zasp/production/stytch-project-id"],
    ["secrets.stytchSecretObjectName", "zasp/production/stytch-secret"],
    ["secrets.stytchPublicTokenObjectName", "zasp/production/stytch-public-token"],
    ["secrets.stytchOrganizationIDObjectName", "zasp/production/stytch-organization-id"],
    ["secrets.workflowSigningKeyObjectName", "zasp/production/workflow-signing-key"],
    ["secrets.tokenRevealKeyObjectName", "zasp/production/token-reveal-key"],
    ["secrets.canaryReadTokenObjectName", "zasp/production/canary-read-token"],
    ["databasePrincipals.migration", "zasp_migration"],
    ["databasePrincipals.api", "zasp_api_runtime"],
    ["databasePrincipals.securityAgentAPI", "zasp_security_agent_api_runtime"],
    ["databasePrincipals.securityAgentWorker", "zasp_security_agent_worker_runtime"],
    ["databasePrincipals.discoveryWorker", "zasp_discovery_runtime"],
    ["databasePrincipals.runtimeIngest", "zasp_ingest_runtime"],
    ["databasePrincipals.runtimeWorker", "zasp_runtime_worker_runtime"],
    ["databasePrincipals.outboxWorker", "zasp_outbox_runtime"],
    ["databasePrincipals.runtimeGateway", "zasp_gateway_runtime"],
    ["databasePrincipals.discoveryScheduler", "zasp_scheduler_runtime"],
    ["databasePrincipals.projectionRisk", "zasp_projection_risk_runtime"],
    ["databasePrincipals.projectionGraph", "zasp_projection_graph_runtime"],
    ["databasePrincipals.projectionSearch", "zasp_projection_search_runtime"],
    ["databasePrincipals.runtimeCoordinator", "zasp_runtime_coordinator_runtime"],
    ["databasePrincipals.runtimeArchive", "zasp_runtime_archive_runtime"],
    ["databasePrincipals.runtimeIndex", "zasp_runtime_index_runtime"],
    ["databasePrincipals.runtimeCorrelation", "zasp_runtime_correlation_runtime"],
    ["databasePrincipals.runtimeProjection", "zasp_runtime_projection_runtime"],
    ["databasePrincipals.gatewayControl", "zasp_gateway_control_runtime"],
    ["discovery.parserVersion", value.discovery.parserVersion],
    ["discovery.toolVersion", value.discovery.toolVersion],
    ["discovery.awsCollectorVersion", value.discovery.awsCollectorVersion],
    ["discovery.kubernetesCollectorVersion", value.discovery.kubernetesCollectorVersion],
    ["discovery.githubCollectorVersion", value.discovery.githubCollectorVersion],
    ["discovery.oktaCollectorVersion", value.discovery.oktaCollectorVersion],
    ["discovery.awsRegion", value.discovery.awsRegion],
    ["discovery.queueURL", value.discovery.queueURL],
    ["discovery.roleArn", value.discovery.roleArn],
    ["discovery.webIdentityTokenFile", value.discovery.webIdentityTokenFile],
    ["discovery.secretPrefix", value.discovery.secretPrefix],
    ["discovery.evidenceBucket", value.discovery.evidenceBucket],
    ["discovery.evidenceBucketOwner", value.discovery.evidenceBucketOwner],
    ["discovery.evidenceKMSKeyArn", value.discovery.evidenceKMSKeyArn],
    ["discovery.githubAppID", value.discovery.githubAppID],
    ["discovery.githubPrivateKeyReference", value.discovery.githubPrivateKeyReference],
    ["discovery.oktaClientID", value.discovery.oktaClientID],
    ["discovery.oktaClientSecretReference", value.discovery.oktaClientSecretReference],
    ["discovery.providerTimeout", value.discovery.providerTimeout],
    ["discovery.readinessTimeout", value.discovery.readinessTimeout],
    ["projectionRisk.roleArn", value.projectionRisk.roleArn],
    ["projectionGraph.awsRegion", value.projectionGraph.awsRegion],
    ["projectionGraph.endpoint", value.projectionGraph.endpoint],
    ["projectionGraph.credentialReference", value.projectionGraph.credentialReference],
    ["projectionGraph.schemaCredentialReference", value.projectionGraph.schemaCredentialReference],
    ["projectionGraph.secretPrefix", value.projectionGraph.secretPrefix],
    ["projectionGraph.roleArn", value.projectionGraph.roleArn],
    ["projectionGraph.webIdentityTokenFile", value.projectionGraph.webIdentityTokenFile],
    ["projectionGraph.initRoleArn", value.projectionGraph.initRoleArn],
    ["projectionGraph.expectedPrincipal", value.projectionGraph.expectedPrincipal],
    ["projectionGraph.expectedRole", value.projectionGraph.expectedRole],
    ["projectionSearch.awsRegion", value.projectionSearch.awsRegion],
    ["projectionSearch.endpoint", value.projectionSearch.endpoint],
    ["projectionSearch.index", value.projectionSearch.index],
    ["projectionSearch.roleArn", value.projectionSearch.roleArn],
    ["projectionSearch.webIdentityTokenFile", value.projectionSearch.webIdentityTokenFile],
    ["projectionSearch.initRoleArn", value.projectionSearch.initRoleArn],
    ["outbox.awsRegion", value.outbox.awsRegion],
    ["outbox.queueURL", value.outbox.queueURL],
    ["outbox.roleArn", value.outbox.roleArn],
    ["outbox.webIdentityTokenFile", value.outbox.webIdentityTokenFile],
    ...value.outbox.egressCIDRs.map((cidr, index) => [`network.outboxEgressCIDRs[${index}]`, cidr]),
    ["runtime.awsRegion", value.runtime.awsRegion],
    ["runtime.queueURL", value.runtime.queueURL],
    ["runtime.rawBucket", value.runtime.rawBucket],
    ["runtime.rawBucketOwner", value.runtime.rawBucketOwner],
    ["runtime.rawKMSKeyArn", value.runtime.rawKMSKeyArn],
    ["runtime.openSearchEndpoint", value.runtime.openSearchEndpoint],
    ["runtime.openSearchIndex", value.runtime.openSearchIndex],
    ["runtime.webIdentityTokenFile", value.runtime.webIdentityTokenFile],
    ["runtime.eventIngestRoleArn", value.runtime.eventIngestRoleArn],
    ["runtime.gatewayControlRoleArn", value.runtime.gatewayControlRoleArn],
    ["runtime.outboxRoleArn", value.runtime.outboxRoleArn],
    ["runtime.coordinatorRoleArn", value.runtime.coordinatorRoleArn],
    ["runtime.archiveRoleArn", value.runtime.archiveRoleArn],
    ["runtime.indexRoleArn", value.runtime.indexRoleArn],
    ["runtime.correlationRoleArn", value.runtime.correlationRoleArn],
    ["runtime.projectionRoleArn", value.runtime.projectionRoleArn],
    ["runtime.completeRoleArn", value.runtime.completeRoleArn],
    ...value.runtime.egressCIDRs.map((cidr, index) => [`network.runtimeEgressCIDRs[${index}]`, cidr]),
    ["network.postgresCIDR", "10.30.0.0/24"], ["network.stytchCIDR", "10.40.0.0/24"], ["network.opensearchCIDR", "10.50.0.0/24"],
    ["network.neo4jCIDR", value.projectionGraph.endpointCIDR],
    ["network.canaryCIDR", "10.60.0.0/24"],
    ["connectors.awsRegion", value.connectors.awsRegion],
    ["connectors.roleArn", value.connectors.roleArn],
    ["connectors.webIdentityTokenFile", value.connectors.webIdentityTokenFile],
    ["connectors.kmsKeyArn", value.connectors.kmsKeyArn],
    ["connectors.secretPrefix", value.connectors.secretPrefix],
    ["connectors.githubClientID", value.connectors.githubClientID],
    ["connectors.githubClientSecretReference", value.connectors.githubClientSecretReference],
    ["connectors.githubAppID", value.connectors.githubAppID],
    ["connectors.githubPrivateKeyReference", value.connectors.githubPrivateKeyReference],
    ["connectors.oktaClientID", value.connectors.oktaClientID],
    ["connectors.oktaClientSecretReference", value.connectors.oktaClientSecretReference],
    ...value.connectors.awsCustomerRolePrefixes.map((prefix, index) => [`connectors.awsCustomerRolePrefixes[${index}]`, prefix]),
    ...value.connectors.awsCustomerRoleARNs.map((roleARN, index) => [`connectors.awsCustomerRoleARNs[${index}]`, roleARN]),
    ...connectorEgressKeys.flatMap((provider) => value.connectorEgressCIDRs[provider].map((cidr, index) => [`network.connectorEgressCIDRs.${provider}[${index}]`, cidr])),
    ...value.findingTicketEgressCIDRs.map((cidr, index) => [`network.findingTicketEgressCIDRs[${index}]`, cidr]),
    ["nango.storageSecretName", value.nango.storageSecretName],
    ...value.nango.databaseEgressCIDRs.map((cidr, index) => [`nango.databaseEgressCIDRs[${index}]`, cidr]),
    ...value.nango.providerEgressCIDRs.map((cidr, index) => [`nango.providerEgressCIDRs[${index}]`, cidr]),
    ["telemetry.backend", value.telemetry.backend],
    ["telemetry.endpoint", value.telemetry.endpoint],
    ["telemetry.authSecretName", value.telemetry.authSecretName],
    ...value.telemetry.egressCIDRs.map((cidr, index) => [`telemetry.egressCIDRs[${index}]`, cidr]),
    ...imageNames.map((name) => [`global.productImages.${name}`, value.images[name]]),
  ];
  const chart = path.join(root, "deploy/staging/product");
  const valueArgs = [];
  for (const [key, entry] of set) valueArgs.push("--set-string", `${key}=${entry.replaceAll("\\", "\\\\").replaceAll(",", "\\,")}`);
  let stdout;
  try {
    await exec("helm", ["lint", chart, "--namespace", "agentsec", ...valueArgs], { cwd: root, encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
    ({ stdout } = await exec("helm", ["template", "zasp", chart, "--namespace", "agentsec", ...valueArgs], { cwd: root, encoding: "utf8", maxBuffer: 4 * 1024 * 1024 }));
  } catch {
    throw new Error("release rejected");
  }
  const resources = [];
  try {
    loadAll(stdout, (document) => { if (document) resources.push(document); }, { schema: JSON_SCHEMA });
  } catch {
    throw new Error("release rejected");
  }
  if (resources.length < 20 || resources.some((resource) => !resource?.apiVersion || !resource?.kind || !resource?.metadata?.name)) throw new Error("release rejected");
  validateRenderedRelease(resources, platformAccountID);
  return Object.freeze(resources);
}

export async function renderCustomerEdgeRelease(value) {
  if (!validCustomerEdgeRelease(value)) throw new Error("edge release rejected");
  const set = [
    ["global.productImages.runtimeGateway", value.image],
    ["global.productImages.sensorAgent", value.sensorImage],
    ["runtimeGateway.controlPlaneURL", value.controlPlaneURL],
    ["runtimeGateway.organizationID", value.organizationID],
    ["runtimeGateway.workspaceID", value.workspaceID],
    ["runtimeGateway.environmentID", value.environmentID],
    ["runtimeGateway.deviceID", value.deviceID],
    ["runtimeGateway.credentialID", value.credentialID],
    ["runtimeGateway.credentialSecretName", value.credentialSecretName],
    ["runtimeGateway.policyKeysSecretName", value.policyKeysSecretName],
    ["runtimeGateway.policyCache.storageClassName", value.storageClassName],
    ["sensorAgent.tokenSecretName", value.sensorTokenSecretName],
    ["sensorAgent.stateHostPath", value.stateHostPath],
    ...value.controlPlaneCIDRs.map((cidr, index) => [`network.controlPlaneCIDRs[${index}]`, cidr]),
    ...value.kubernetesAPICIDRs.map((cidr, index) => [`network.kubernetesAPICIDRs[${index}]`, cidr]),
    ...value.nodeCIDRs.map((cidr, index) => [`network.nodeCIDRs[${index}]`, cidr]),
  ];
  const chart = path.join(root, "deploy/staging/product");
  const edgeValues = path.join(chart, "values-customer-edge.yaml");
  const valueArgs = [];
  for (const [key, entry] of set) valueArgs.push("--set-string", `${key}=${entry.replaceAll("\\", "\\\\").replaceAll(",", "\\,")}`);
  let productOutput, tetragonOutput;
  try {
    const tetragonChart = path.join(root, "deploy/staging/tetragon");
    const dependency = await readFile(path.join(tetragonChart, "charts/tetragon-1.7.0.tgz"));
    if (createHash("sha256").update(dependency).digest("hex") !== tetragonChartDigest) throw new Error("tetragon dependency rejected");
    const results = await Promise.all([
      exec("helm", ["lint", chart, "--namespace", "agentsec", "--values", edgeValues, ...valueArgs], { cwd: root, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 }),
      exec("helm", ["template", "zasp", chart, "--namespace", "agentsec", "--values", edgeValues, ...valueArgs], { cwd: root, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 }),
      exec("helm", ["lint", tetragonChart, "--namespace", "agentsec"], { cwd: root, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 }),
      exec("helm", ["template", "zasp-tetragon", tetragonChart, "--namespace", "agentsec"], { cwd: root, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 }),
    ]);
    productOutput = results[1].stdout;
    tetragonOutput = results[3].stdout;
  } catch {
    throw new Error("edge release rejected");
  }
  const resources = [];
  try {
    loadAll(productOutput, (document) => { if (document) resources.push(document); }, { schema: JSON_SCHEMA });
    loadAll(tetragonOutput, (document) => { if (document) resources.push(document); }, { schema: JSON_SCHEMA });
  } catch {
    throw new Error("edge release rejected");
  }
  const deployments = resources.filter(({ kind }) => kind === "Deployment");
  const daemonSets = resources.filter(({ kind }) => kind === "DaemonSet");
  const accounts = resources.filter(({ kind }) => kind === "ServiceAccount");
  if (resources.length < 20 || resources.some((resource) => !resource?.apiVersion || !resource?.kind || !resource?.metadata?.name) || deployments.length !== 1 || deployments[0].metadata.name !== "runtime-gateway" || daemonSets.length !== 2 || !daemonSets.some(({ metadata }) => metadata.name === "sensor-agent") || !daemonSets.some(({ metadata }) => metadata.name === "zasp-tetragon") || accounts.length !== 3 || !["runtime-gateway", "sensor-agent", "zasp-tetragon"].every((name) => accounts.some(({ metadata }) => metadata.name === name)) || accounts.some(({ metadata }) => metadata.annotations?.["eks.amazonaws.com/role-arn"] !== undefined)) throw new Error("edge release rejected");
  return Object.freeze(resources);
}

function validCustomerEdgeRelease(value) {
  const keys = ["controlPlaneURL", "image", "sensorImage", "organizationID", "workspaceID", "environmentID", "deviceID", "credentialID", "credentialSecretName", "policyKeysSecretName", "sensorTokenSecretName", "storageClassName", "controlPlaneCIDRs", "kubernetesAPICIDRs", "nodeCIDRs", "stateHostPath"];
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== keys.sort().join("\0") || !digestPattern.test(value.image) || !digestPattern.test(value.sensorImage) || value.image === value.sensorImage) return false;
  if (!/^https:\/\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value.controlPlaneURL)) return false;
  if (![value.organizationID, value.workspaceID, value.environmentID, value.deviceID, value.credentialID].every((identifier) => productIDPattern.test(identifier)) || new Set([value.organizationID, value.workspaceID, value.environmentID, value.deviceID, value.credentialID]).size !== 5) return false;
  const secretNames = [value.credentialSecretName, value.policyKeysSecretName, value.sensorTokenSecretName];
  return secretNames.every((name) => namePattern.test(name)) && new Set(secretNames).size === secretNames.length && namePattern.test(value.storageClassName) && value.stateHostPath === "/var/lib/zasp-sensor" && validCIDRList(value.controlPlaneCIDRs) && validCIDRList(value.kubernetesAPICIDRs) && validCIDRList(value.nodeCIDRs);
}

function validRelease(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== ["connectorEgressCIDRs", "connectors", "discovery", "findingTicketEgressCIDRs", "projectionGraph", "projectionRisk", "projectionSearch", "outbox", "runtime", "nango", "telemetry", "host", "images", "secretProviderClass", "tlsSecretName"].sort().join("\0")) return false;
  if (!hostPattern.test(value.host) || !namePattern.test(value.tlsSecretName) || !namePattern.test(value.secretProviderClass)) return false;
  if (!value.images || typeof value.images !== "object" || Array.isArray(value.images) || Object.keys(value.images).sort().join("\0") !== [...imageNames].sort().join("\0")) return false;
  if (!imageNames.every((name) => digestPattern.test(value.images[name]))) return false;
  if (!value.discovery || typeof value.discovery !== "object" || Array.isArray(value.discovery) || Object.keys(value.discovery).sort().join("\0") !== [...discoveryKeys].sort().join("\0")) return false;
  for (const name of ["parserVersion", "toolVersion", "awsCollectorVersion", "kubernetesCollectorVersion", "githubCollectorVersion", "oktaCollectorVersion"]) {
    if (!/^[a-z][a-z0-9_.-]{1,63}$/.test(value.discovery[name]) || value.discovery[name] === "parser-v1" || value.discovery[name] === "tool-v1") return false;
  }
  const discoveryRole = /^arn:aws:iam::([0-9]{12}):role\/zasp-production-discovery-worker$/.exec(value.discovery.roleArn);
  const discoveryQueue = /^https:\/\/sqs\.([a-z]{2}(?:-gov)?-[a-z]+-[0-9])\.amazonaws\.com\/([0-9]{12})\/agentsec-discovery-jobs$/.exec(value.discovery.queueURL);
  const discoveryKMS = /^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.exec(value.discovery.evidenceKMSKeyArn);
  if (!discoveryRole || !discoveryQueue || !discoveryKMS || value.discovery.awsRegion !== discoveryQueue[1] || value.discovery.awsRegion !== discoveryKMS[1] || discoveryRole[1] !== discoveryQueue[2] || discoveryRole[1] !== discoveryKMS[2] || discoveryRole[1] !== value.discovery.evidenceBucketOwner) return false;
  if (!namePattern.test(value.discovery.evidenceBucket) || value.discovery.webIdentityTokenFile !== "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || value.discovery.secretPrefix !== "zasp-production/connectors" || value.discovery.providerTimeout !== "5s" || value.discovery.readinessTimeout !== "5s") return false;
  if (!value.projectionSearch || typeof value.projectionSearch !== "object" || Array.isArray(value.projectionSearch) || Object.keys(value.projectionSearch).sort().join("\0") !== [...projectionSearchKeys].sort().join("\0")) return false;
  const searchRole = /^arn:aws:iam::([0-9]{12}):role\/zasp-production-projection-search$/.exec(value.projectionSearch.roleArn);
  const searchInitRole = /^arn:aws:iam::([0-9]{12}):role\/zasp-production-projection-search-init$/.exec(value.projectionSearch.initRoleArn);
  const searchEndpoint = /^https:\/\/(?:search|vpc)-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.([a-z]{2}(?:-gov)?-[a-z]+-[0-9])\.es\.amazonaws\.com$/.exec(value.projectionSearch.endpoint);
  if (!searchRole || !searchInitRole || searchRole[1] !== searchInitRole[1] || searchRole[1] !== discoveryRole[1] || !searchEndpoint || value.projectionSearch.awsRegion !== searchEndpoint[1] || value.projectionSearch.index !== "zasp-inventory-v1" || value.projectionSearch.webIdentityTokenFile !== "/var/run/secrets/eks.amazonaws.com/serviceaccount/token") return false;
  if (!value.projectionRisk || typeof value.projectionRisk !== "object" || Array.isArray(value.projectionRisk) || Object.keys(value.projectionRisk).sort().join("\0") !== [...projectionRiskKeys].sort().join("\0")) return false;
  const riskRole = /^arn:aws:iam::([0-9]{12}):role\/zasp-production-projection-risk$/.exec(value.projectionRisk.roleArn);
  if (!riskRole || riskRole[1] !== searchRole[1]) return false;
  if (!value.projectionGraph || typeof value.projectionGraph !== "object" || Array.isArray(value.projectionGraph) || Object.keys(value.projectionGraph).sort().join("\0") !== [...projectionGraphKeys].sort().join("\0")) return false;
  const graphRole = /^arn:aws:iam::([0-9]{12}):role\/zasp-production-projection-graph$/.exec(value.projectionGraph.roleArn);
  const graphInitRole = /^arn:aws:iam::([0-9]{12}):role\/zasp-production-projection-graph-init$/.exec(value.projectionGraph.initRoleArn);
  const graphEndpoint = /^neo4j\+s:\/\/[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9]):7687$/.exec(value.projectionGraph.endpoint);
  if (!graphRole || !graphInitRole || !graphEndpoint || graphRole[1] !== graphInitRole[1] || graphRole[1] !== searchRole[1]) return false;
  if (value.projectionGraph.awsRegion !== value.projectionSearch.awsRegion || value.projectionGraph.webIdentityTokenFile !== "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || value.projectionGraph.secretPrefix !== "zasp-production/projection" || value.projectionGraph.credentialReference !== "ref:neo4j/auth/runtime" || value.projectionGraph.schemaCredentialReference !== "ref:neo4j/auth/schema" || value.projectionGraph.expectedPrincipal !== "zasp_projection_runtime" || value.projectionGraph.expectedRole !== "publisher" || !validCIDRList([value.projectionGraph.endpointCIDR])) return false;
  if (!value.outbox || typeof value.outbox !== "object" || Array.isArray(value.outbox) || Object.keys(value.outbox).sort().join("\0") !== [...outboxKeys].sort().join("\0")) return false;
  const outboxRole = /^arn:aws:iam::([0-9]{12}):role\/zasp-production-outbox$/.exec(value.outbox.roleArn);
  const outboxQueue = /^https:\/\/sqs\.([a-z]{2}(?:-gov)?-[a-z]+-[0-9])\.amazonaws\.com\/([0-9]{12})\/agentsec-discovery-jobs$/.exec(value.outbox.queueURL);
  if (!outboxRole || !outboxQueue || value.outbox.awsRegion !== outboxQueue[1] || outboxRole[1] !== outboxQueue[2] || outboxRole[1] !== discoveryRole[1] || value.outbox.webIdentityTokenFile !== "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || !validCIDRList(value.outbox.egressCIDRs)) return false;
  if (!value.runtime || typeof value.runtime !== "object" || Array.isArray(value.runtime) || Object.keys(value.runtime).sort().join("\0") !== [...runtimeKeys].sort().join("\0")) return false;
  const runtimeQueue = /^https:\/\/sqs\.([a-z]{2}(?:-gov)?-[a-z]+-[0-9])\.amazonaws\.com\/([0-9]{12})\/agentsec-runtime-events$/.exec(value.runtime.queueURL);
  const runtimeKMS = /^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.exec(value.runtime.rawKMSKeyArn);
  const runtimeEndpoint = /^https:\/\/(?:search|vpc)-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.([a-z]{2}(?:-gov)?-[a-z]+-[0-9])\.es\.amazonaws\.com$/.exec(value.runtime.openSearchEndpoint);
  const runtimeRoleNames = Object.freeze({ eventIngest: "runtime-ingest", gatewayControl: "gateway-control", outbox: "runtime-outbox", coordinator: "runtime-coordinator", archive: "runtime-archive", index: "runtime-index", correlation: "runtime-correlation", projection: "runtime-projection", complete: "runtime-complete" });
  const runtimeRoleARNs = Object.keys(runtimeRoleNames).map((key) => value.runtime[`${key}RoleArn`]);
  const runtimeRoles = Object.entries(runtimeRoleNames).map(([key, roleName]) => new RegExp(`^arn:aws:iam::([0-9]{12}):role/zasp-production-${roleName}$`).exec(value.runtime[`${key}RoleArn`]));
  if (!runtimeQueue || !runtimeKMS || !runtimeEndpoint || runtimeRoles.some((role) => !role) || new Set(runtimeRoleARNs).size !== runtimeRoles.length || runtimeRoles.some((role) => role[1] !== discoveryRole[1])) return false;
  if (value.runtime.awsRegion !== runtimeQueue[1] || value.runtime.awsRegion !== runtimeKMS[1] || value.runtime.awsRegion !== runtimeEndpoint[1] || runtimeQueue[2] !== discoveryRole[1] || runtimeKMS[2] !== discoveryRole[1] || value.runtime.rawBucketOwner !== discoveryRole[1]) return false;
  if (!namePattern.test(value.runtime.rawBucket) || value.runtime.openSearchIndex !== "zasp-runtime-events-v1" || value.runtime.webIdentityTokenFile !== "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || !validCIDRList(value.runtime.egressCIDRs)) return false;
  if (!value.connectors || typeof value.connectors !== "object" || Array.isArray(value.connectors) || Object.keys(value.connectors).sort().join("\0") !== [...connectorKeys].sort().join("\0")) return false;
  const role = /^arn:aws:iam::([0-9]{12}):role\/zasp-production-api-connectors$/.exec(value.connectors.roleArn);
  const kms = /^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.exec(value.connectors.kmsKeyArn);
  if (!/^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$/.test(value.connectors.awsRegion) || !role || !kms || kms[1] !== value.connectors.awsRegion || kms[2] !== role[1] || role[1] !== discoveryRole[1]) return false;
  if (!Array.isArray(value.connectors.awsCustomerRolePrefixes) || value.connectors.awsCustomerRolePrefixes.length < 1 || value.connectors.awsCustomerRolePrefixes.length > 64 || new Set(value.connectors.awsCustomerRolePrefixes).size !== value.connectors.awsCustomerRolePrefixes.length || !value.connectors.awsCustomerRolePrefixes.every((prefix) => /^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,120}\/$/.test(prefix))) return false;
  if (!Array.isArray(value.connectors.awsCustomerRoleARNs) || value.connectors.awsCustomerRoleARNs.length < 1 || value.connectors.awsCustomerRoleARNs.length > 64 || new Set(value.connectors.awsCustomerRoleARNs).size !== value.connectors.awsCustomerRoleARNs.length || !value.connectors.awsCustomerRoleARNs.every((roleARN) => /^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,128}$/.test(roleARN) && value.connectors.awsCustomerRolePrefixes.some((prefix) => roleARN.startsWith(prefix) && roleARN !== prefix))) return false;
  if (value.connectors.webIdentityTokenFile !== "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || value.connectors.secretPrefix !== "zasp-production/connectors/oauth") return false;
  if (!/^Iv1\.[A-Za-z0-9]{16}$/.test(value.connectors.githubClientID) || value.connectors.githubClientSecretReference !== "ref:github/client-secret" || !/^[1-9][0-9]{0,15}$/.test(value.connectors.githubAppID) || value.connectors.githubPrivateKeyReference !== "ref:github/app-private-key") return false;
  if (!/^0oa[A-Za-z0-9]{16}$/.test(value.connectors.oktaClientID) || value.connectors.oktaClientSecretReference !== "ref:okta/client-secret") return false;
  if (value.discovery.githubAppID !== value.connectors.githubAppID || value.discovery.githubPrivateKeyReference !== value.connectors.githubPrivateKeyReference || value.discovery.oktaClientID !== value.connectors.oktaClientID || value.discovery.oktaClientSecretReference !== value.connectors.oktaClientSecretReference) return false;
  if (!value.connectorEgressCIDRs || typeof value.connectorEgressCIDRs !== "object" || Array.isArray(value.connectorEgressCIDRs) || Object.keys(value.connectorEgressCIDRs).sort().join("\0") !== [...connectorEgressKeys].sort().join("\0")) return false;
  if (!connectorEgressKeys.every((provider) => validCIDRList(value.connectorEgressCIDRs[provider]))) return false;
  if (!validProviderCIDRList(value.findingTicketEgressCIDRs)) return false;
  if (!value.nango || typeof value.nango !== "object" || Array.isArray(value.nango) || Object.keys(value.nango).sort().join("\0") !== [...nangoKeys].sort().join("\0") || !namePattern.test(value.nango.storageSecretName) || !validPrivateCIDRList(value.nango.databaseEgressCIDRs) || !validProviderCIDRList(value.nango.providerEgressCIDRs)) return false;
  if (hasCIDROverlap([...value.nango.databaseEgressCIDRs, ...value.nango.providerEgressCIDRs])) return false;
  if (!value.telemetry || typeof value.telemetry !== "object" || Array.isArray(value.telemetry) || Object.keys(value.telemetry).sort().join("\0") !== [...telemetryKeys].sort().join("\0")) return false;
  if (value.telemetry.backend === "none") return value.telemetry.endpoint === "" && value.telemetry.authSecretName === "" && Array.isArray(value.telemetry.egressCIDRs) && value.telemetry.egressCIDRs.length === 0;
  if (!namePattern.test(value.telemetry.authSecretName) || value.telemetry.authSecretName === value.nango.storageSecretName || !validProviderCIDRList(value.telemetry.egressCIDRs)) return false;
  if (value.telemetry.backend === "grafana") return /^https:\/\/otlp-gateway-[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?\.grafana\.net\/otlp$/.test(value.telemetry.endpoint);
  return value.telemetry.backend === "newrelic" && value.telemetry.endpoint === "https://otlp.nr-data.net";
}

export function validateRenderedRelease(resources, platformAccountID) {
  const accountPattern = /^[0-9]{12}$/;
  if (!Array.isArray(resources) || !accountPattern.test(platformAccountID) || platformAccountID === "000000000000") throw new Error("release rejected");
  const deployments = new Map(resources.filter(({ kind }) => kind === "Deployment").map((resource) => [resource.metadata?.name, resource]));
  const deploymentIdentities = new Map([
    ["web", "agentsec-web"],
    ["agentsec-api", "agentsec-api"],
    ["agentsec-discovery-scheduler", "zasp-discovery-scheduler"],
    ["agentsec-discovery-worker", "zasp-discovery-worker"],
    ["agentsec-security-agent", "zasp-security-agent"],
    ["agentsec-outbox-publisher", "zasp-outbox-publisher"],
    ["agentsec-projection-risk", "zasp-projection-risk"],
    ["agentsec-projection-graph", "zasp-projection-graph"],
    ["agentsec-projection-search", "zasp-projection-search"],
    ["agentsec-event-ingest", "zasp-runtime-ingest"],
    ["agentsec-gateway-control", "zasp-gateway-control"],
    ["agentsec-runtime-outbox", "zasp-runtime-outbox"],
    ["agentsec-runtime-coordinator", "zasp-runtime-coordinator"],
    ["agentsec-runtime-archive", "zasp-runtime-archive"],
    ["agentsec-runtime-index", "zasp-runtime-index"],
    ["agentsec-runtime-correlation", "zasp-runtime-correlation"],
    ["agentsec-runtime-projection", "zasp-runtime-projection"],
    ["agentsec-runtime-complete", "zasp-runtime-complete"],
    ["nango", "nango"],
    ["otel-collector", "otel-collector"],
  ]);
  if (deployments.size !== deploymentIdentities.size || [...deploymentIdentities].some(([name, serviceAccount]) => deployments.get(name)?.spec?.template?.spec?.serviceAccountName !== serviceAccount)) throw new Error("release rejected");
  const identityContracts = new Map([
    ["agentsec-web", null],
    ["agentsec-api", "api"],
    ["zasp-discovery-scheduler", "discovery-scheduler"],
    ["zasp-discovery-worker", "discovery-worker"],
    ["zasp-security-agent", "security-agent-worker"],
    ["zasp-outbox-publisher", "outbox"],
    ["zasp-projection-risk", "projection-risk"],
    ["zasp-projection-graph", "projection-graph"],
    ["zasp-projection-search", "projection-search"],
    ["zasp-runtime-ingest", "runtime-ingest"],
    ["zasp-gateway-control", "gateway-control"],
    ["zasp-runtime-outbox", "runtime-outbox"],
    ["zasp-runtime-coordinator", "runtime-coordinator"],
    ["zasp-runtime-archive", "runtime-archive"],
    ["zasp-runtime-index", "runtime-index"],
    ["zasp-runtime-correlation", "runtime-correlation"],
    ["zasp-runtime-projection", "runtime-projection"],
    ["zasp-runtime-complete", "runtime-complete"],
    ["nango", null],
    ["nango-migrate", null],
    ["otel-collector", null],
    ["agentsec-migration", "migration"],
    ["agentsec-projection-graph-init", "projection-graph-init"],
    ["agentsec-projection-search-init", "projection-search-init"],
    ["agentsec-canary", null],
    ["agentsec-canary-secret-sync", "canary-secret-sync"],
  ]);
  const accounts = new Map(resources.filter(({ kind }) => kind === "ServiceAccount").map((resource) => [resource.metadata?.name, resource]));
  if (accounts.size !== identityContracts.size) throw new Error("release rejected");
  for (const [name, role] of identityContracts) {
    const rendered = accounts.get(name);
    const roleArn = rendered?.metadata?.annotations?.["eks.amazonaws.com/role-arn"];
    if (!rendered || (role === null ? roleArn !== undefined : roleArn !== `arn:aws:iam::${platformAccountID}:role/zasp-production-${role}`)) throw new Error("release rejected");
  }
  const jobIdentities = new Map([
    ["agentsec-schema-v19", "agentsec-migration"],
    ["agentsec-projection-graph-init-v1", "agentsec-projection-graph-init"],
    ["agentsec-projection-search-init-v1", "agentsec-projection-search-init"],
    ["nango-migrate", "nango-migrate"],
    ["zasp-canary-secret-sync", "agentsec-canary-secret-sync"],
  ]);
  const jobs = resources.filter(({ kind }) => kind === "Job");
  if (jobs.length !== jobIdentities.size || jobs.some((resource) => jobIdentities.get(resource.metadata?.name) !== resource.spec?.template?.spec?.serviceAccountName)) throw new Error("release rejected");
  const cronJobIdentities = new Map([["production-readonly-canary", "agentsec-canary"]]);
  const cronJobs = resources.filter(({ kind }) => kind === "CronJob");
  if (cronJobs.length !== cronJobIdentities.size || cronJobs.some((resource) => cronJobIdentities.get(resource.metadata?.name) !== resource.spec?.jobTemplate?.spec?.template?.spec?.serviceAccountName)) throw new Error("release rejected");
  return Object.freeze({ deployments: deployments.size, identities: accounts.size, platformAccountID });
}

function validCIDRList(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16 || new Set(value).size !== value.length) return false;
  return value.every((cidr) => cidrRange(cidr) !== undefined);
}

function validPrivateCIDRList(value) {
  if (!validCIDRList(value) || hasCIDROverlap(value)) return false;
  return value.every((cidr) => {
    const { first, second, prefix } = cidrRange(cidr);
    return prefix >= 24 && (first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168));
  });
}

function validProviderCIDRList(value) {
  if (!validCIDRList(value) || hasCIDROverlap(value)) return false;
  return value.every((cidr) => {
    const { first, second, prefix } = cidrRange(cidr);
    const nonPublic = first === 0 || first === 10 || first === 127 || first >= 224 ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      (first === 198 && (second === 18 || second === 19));
    return prefix >= 16 && !nonPublic;
  });
}

function hasCIDROverlap(value) {
  const ranges = value.map(cidrRange).sort((left, right) => left.start - right.start || left.end - right.end);
  return ranges.some((range, index) => index > 0 && range.start <= ranges[index - 1].end);
}

function cidrRange(cidr) {
  if (typeof cidr !== "string" || cidr.includes(" ")) return undefined;
  const match = /^([^/]+)\/([0-9]{1,2})$/.exec(cidr);
  if (!match || isIP(match[1]) !== 4 || match[1].split(".").some((part) => String(Number(part)) !== part)) return undefined;
  const prefix = Number(match[2]);
  if (prefix < 1 || prefix > 32) return undefined;
  const octets = match[1].split(".").map(Number);
  const address = octets.reduce((result, part) => ((result << 8) | part) >>> 0, 0);
  const mask = prefix === 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
  const start = (address & mask) >>> 0;
  if (start !== address) return undefined;
  return { start, end: start + (2 ** (32 - prefix)) - 1, prefix, first: octets[0], second: octets[1] };
}
