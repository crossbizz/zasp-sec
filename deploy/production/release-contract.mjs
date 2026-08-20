import { execFile } from "node:child_process";
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
const imageNames = Object.freeze(["web", "agentsecApi", "agentsecWorker"]);
const discoveryKeys = Object.freeze(["parserVersion", "toolVersion"]);
const projectionSearchKeys = Object.freeze(["awsRegion", "endpoint", "index", "roleArn", "webIdentityTokenFile"]);
const outboxKeys = Object.freeze(["awsRegion", "queueURL", "roleArn", "webIdentityTokenFile", "egressCIDRs"]);
const connectorKeys = Object.freeze(["awsRegion", "roleArn", "awsCustomerRolePrefixes", "awsCustomerRoleARNs", "webIdentityTokenFile", "kmsKeyArn", "secretPrefix", "githubClientID", "githubClientSecretReference", "githubAppID", "githubPrivateKeyReference", "oktaClientID", "oktaClientSecretReference"]);
const connectorEgressKeys = Object.freeze(["aws", "github", "okta", "kubernetes"]);

export async function inspectContainerBuilds() {
  const definitions = [
    { name: "web", file: "web.Dockerfile", port: 3000 },
    { name: "agentsec-api", file: "api.Dockerfile", port: 8080 },
    { name: "agentsec-worker", file: "worker.Dockerfile", port: 8081 },
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
  const set = [
    ["global.publicOrigin", `https://${value.host}`],
    ["global.trustedProxyCIDRs[0]", "10.20.0.0/16"],
    ["serviceAccounts.api.roleArn", "arn:aws:iam::123456789012:role/zasp-production-api"],
    ["serviceAccounts.migration.roleArn", "arn:aws:iam::123456789012:role/zasp-production-migration"],
    ["serviceAccounts.worker.roleArn", "arn:aws:iam::123456789012:role/zasp-production-worker"],
    ["serviceAccounts.scheduler.roleArn", "arn:aws:iam::123456789012:role/zasp-production-discovery-scheduler"],
    ["serviceAccounts.projectionSearch.roleArn", value.projectionSearch.roleArn],
    ["serviceAccounts.outbox.roleArn", value.outbox.roleArn],
    ["serviceAccounts.canarySecretSync.roleArn", "arn:aws:iam::123456789012:role/zasp-production-canary-sync"],
    ["ingress.host", value.host], ["ingress.tlsSecretName", value.tlsSecretName],
    ["secrets.providerClassName", value.secretProviderClass],
    ["secrets.apiPostgresDSNObjectName", "zasp/production/postgres-api-dsn"],
    ["secrets.workerPostgresDSNObjectName", "zasp/production/postgres-worker-dsn"],
    ["secrets.schedulerPostgresDSNObjectName", "zasp/production/postgres-scheduler-dsn"],
    ["secrets.projectionSearchPostgresDSNObjectName", "zasp/production/postgres-projection-search-dsn"],
    ["secrets.outboxPostgresDSNObjectName", "zasp/production/postgres-outbox-worker-dsn"],
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
    ["databasePrincipals.discoveryWorker", "zasp_discovery_runtime"],
    ["databasePrincipals.runtimeIngest", "zasp_ingest_runtime"],
    ["databasePrincipals.runtimeWorker", "zasp_runtime_worker_runtime"],
    ["databasePrincipals.outboxWorker", "zasp_outbox_runtime"],
    ["databasePrincipals.runtimeGateway", "zasp_gateway_runtime"],
    ["databasePrincipals.discoveryScheduler", "zasp_scheduler_runtime"],
    ["databasePrincipals.projectionRisk", "zasp_projection_risk_runtime"],
    ["databasePrincipals.projectionGraph", "zasp_projection_graph_runtime"],
    ["databasePrincipals.projectionSearch", "zasp_projection_search_runtime"],
    ["discovery.parserVersion", value.discovery.parserVersion],
    ["discovery.toolVersion", value.discovery.toolVersion],
    ["projectionSearch.awsRegion", value.projectionSearch.awsRegion],
    ["projectionSearch.endpoint", value.projectionSearch.endpoint],
    ["projectionSearch.index", value.projectionSearch.index],
    ["projectionSearch.roleArn", value.projectionSearch.roleArn],
    ["projectionSearch.webIdentityTokenFile", value.projectionSearch.webIdentityTokenFile],
    ["outbox.awsRegion", value.outbox.awsRegion],
    ["outbox.queueURL", value.outbox.queueURL],
    ["outbox.roleArn", value.outbox.roleArn],
    ["outbox.webIdentityTokenFile", value.outbox.webIdentityTokenFile],
    ...value.outbox.egressCIDRs.map((cidr, index) => [`network.outboxEgressCIDRs[${index}]`, cidr]),
    ["network.postgresCIDR", "10.30.0.0/24"], ["network.stytchCIDR", "10.40.0.0/24"], ["network.opensearchCIDR", "10.50.0.0/24"],
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
    ...imageNames.map((name) => [`global.productImages.${name}`, value.images[name]]),
  ];
  const args = ["template", "zasp", path.join(root, "deploy/staging/product"), "--namespace", "agentsec"];
  for (const [key, entry] of set) args.push("--set-string", `${key}=${entry.replaceAll("\\", "\\\\").replaceAll(",", "\\,")}`);
  let stdout;
  try {
    ({ stdout } = await exec("helm", args, { cwd: root, encoding: "utf8", maxBuffer: 4 * 1024 * 1024 }));
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
  return Object.freeze(resources);
}

function validRelease(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== ["connectorEgressCIDRs", "connectors", "discovery", "projectionSearch", "outbox", "host", "images", "secretProviderClass", "tlsSecretName"].sort().join("\0")) return false;
  if (!hostPattern.test(value.host) || !namePattern.test(value.tlsSecretName) || !namePattern.test(value.secretProviderClass)) return false;
  if (!value.images || typeof value.images !== "object" || Array.isArray(value.images) || Object.keys(value.images).sort().join("\0") !== [...imageNames].sort().join("\0")) return false;
  if (!imageNames.every((name) => digestPattern.test(value.images[name]))) return false;
  if (!value.discovery || typeof value.discovery !== "object" || Array.isArray(value.discovery) || Object.keys(value.discovery).sort().join("\0") !== [...discoveryKeys].sort().join("\0")) return false;
  if (!discoveryKeys.every((name) => /^[a-z][a-z0-9_.-]{1,63}$/.test(value.discovery[name])) || Object.values(value.discovery).some((version) => version === "parser-v1" || version === "tool-v1")) return false;
  if (!value.projectionSearch || typeof value.projectionSearch !== "object" || Array.isArray(value.projectionSearch) || Object.keys(value.projectionSearch).sort().join("\0") !== [...projectionSearchKeys].sort().join("\0")) return false;
  const searchRole = /^arn:aws:iam::([0-9]{12}):role\/zasp-production-projection-search$/.exec(value.projectionSearch.roleArn);
  const searchEndpoint = /^https:\/\/(?:search|vpc)-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.([a-z]{2}(?:-gov)?-[a-z]+-[0-9])\.es\.amazonaws\.com$/.exec(value.projectionSearch.endpoint);
  if (!searchRole || !searchEndpoint || value.projectionSearch.awsRegion !== searchEndpoint[1] || value.projectionSearch.index !== "zasp-inventory-v1" || value.projectionSearch.webIdentityTokenFile !== "/var/run/secrets/eks.amazonaws.com/serviceaccount/token") return false;
  if (!value.outbox || typeof value.outbox !== "object" || Array.isArray(value.outbox) || Object.keys(value.outbox).sort().join("\0") !== [...outboxKeys].sort().join("\0")) return false;
  const outboxRole = /^arn:aws:iam::([0-9]{12}):role\/zasp-production-outbox$/.exec(value.outbox.roleArn);
  const outboxQueue = /^https:\/\/sqs\.([a-z]{2}(?:-gov)?-[a-z]+-[0-9])\.amazonaws\.com\/([0-9]{12})\/agentsec-discovery-jobs$/.exec(value.outbox.queueURL);
  if (!outboxRole || !outboxQueue || value.outbox.awsRegion !== outboxQueue[1] || outboxRole[1] !== outboxQueue[2] || value.outbox.webIdentityTokenFile !== "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || !validCIDRList(value.outbox.egressCIDRs)) return false;
  if (!value.connectors || typeof value.connectors !== "object" || Array.isArray(value.connectors) || Object.keys(value.connectors).sort().join("\0") !== [...connectorKeys].sort().join("\0")) return false;
  const role = /^arn:aws:iam::([0-9]{12}):role\/zasp-production-api-connectors$/.exec(value.connectors.roleArn);
  const kms = /^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.exec(value.connectors.kmsKeyArn);
  if (!/^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$/.test(value.connectors.awsRegion) || !role || !kms || kms[1] !== value.connectors.awsRegion || kms[2] !== role[1]) return false;
  if (!Array.isArray(value.connectors.awsCustomerRolePrefixes) || value.connectors.awsCustomerRolePrefixes.length < 1 || value.connectors.awsCustomerRolePrefixes.length > 64 || new Set(value.connectors.awsCustomerRolePrefixes).size !== value.connectors.awsCustomerRolePrefixes.length || !value.connectors.awsCustomerRolePrefixes.every((prefix) => /^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,120}\/$/.test(prefix))) return false;
  if (!Array.isArray(value.connectors.awsCustomerRoleARNs) || value.connectors.awsCustomerRoleARNs.length < 1 || value.connectors.awsCustomerRoleARNs.length > 64 || new Set(value.connectors.awsCustomerRoleARNs).size !== value.connectors.awsCustomerRoleARNs.length || !value.connectors.awsCustomerRoleARNs.every((roleARN) => /^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,128}$/.test(roleARN) && value.connectors.awsCustomerRolePrefixes.some((prefix) => roleARN.startsWith(prefix) && roleARN !== prefix))) return false;
  if (value.connectors.webIdentityTokenFile !== "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || value.connectors.secretPrefix !== "zasp-production/connectors/oauth") return false;
  if (!/^Iv1\.[A-Za-z0-9]{16}$/.test(value.connectors.githubClientID) || value.connectors.githubClientSecretReference !== "ref:github/client-secret" || !/^[1-9][0-9]{0,15}$/.test(value.connectors.githubAppID) || value.connectors.githubPrivateKeyReference !== "ref:github/app-private-key") return false;
  if (!/^0oa[A-Za-z0-9]{16}$/.test(value.connectors.oktaClientID) || value.connectors.oktaClientSecretReference !== "ref:okta/client-secret") return false;
  if (!value.connectorEgressCIDRs || typeof value.connectorEgressCIDRs !== "object" || Array.isArray(value.connectorEgressCIDRs) || Object.keys(value.connectorEgressCIDRs).sort().join("\0") !== [...connectorEgressKeys].sort().join("\0")) return false;
  return connectorEgressKeys.every((provider) => validCIDRList(value.connectorEgressCIDRs[provider]));
}

function validCIDRList(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16 || new Set(value).size !== value.length) return false;
  return value.every((cidr) => {
    if (typeof cidr !== "string" || cidr.includes(" ")) return false;
    const match = /^([^/]+)\/([0-9]{1,2})$/.exec(cidr);
    if (!match || isIP(match[1]) !== 4 || match[1].split(".").some((part) => String(Number(part)) !== part)) return false;
    const prefix = Number(match[2]);
    if (prefix < 1 || prefix > 32) return false;
    const address = match[1].split(".").reduce((result, part) => ((result << 8) | Number(part)) >>> 0, 0);
    const mask = prefix === 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
    return (address & mask) >>> 0 === address;
  });
}
