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
const imageNames = Object.freeze(["web", "agentsecApi"]);
const connectorKeys = Object.freeze(["awsRegion", "roleArn", "webIdentityTokenFile", "kmsKeyArn", "secretPrefix", "githubClientID", "githubClientSecretReference", "oktaClientID", "oktaClientSecretReference"]);
const connectorEgressKeys = Object.freeze(["aws", "github", "okta"]);

export async function inspectContainerBuilds() {
  const definitions = [
    { name: "web", file: "web.Dockerfile", port: 3000 },
    { name: "agentsec-api", file: "api.Dockerfile", port: 8080 },
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
    ["serviceAccounts.canarySecretSync.roleArn", "arn:aws:iam::123456789012:role/zasp-production-canary-sync"],
    ["ingress.host", value.host], ["ingress.tlsSecretName", value.tlsSecretName],
    ["secrets.providerClassName", value.secretProviderClass],
    ["secrets.apiPostgresDSNObjectName", "zasp/production/postgres-api-dsn"],
    ["secrets.workerPostgresDSNObjectName", "zasp/production/postgres-worker-dsn"],
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
    ["network.postgresCIDR", "10.30.0.0/24"], ["network.stytchCIDR", "10.40.0.0/24"],
    ["network.canaryCIDR", "10.60.0.0/24"],
    ["connectors.awsRegion", value.connectors.awsRegion],
    ["connectors.roleArn", value.connectors.roleArn],
    ["connectors.webIdentityTokenFile", value.connectors.webIdentityTokenFile],
    ["connectors.kmsKeyArn", value.connectors.kmsKeyArn],
    ["connectors.secretPrefix", value.connectors.secretPrefix],
    ["connectors.githubClientID", value.connectors.githubClientID],
    ["connectors.githubClientSecretReference", value.connectors.githubClientSecretReference],
    ["connectors.oktaClientID", value.connectors.oktaClientID],
    ["connectors.oktaClientSecretReference", value.connectors.oktaClientSecretReference],
    ...connectorEgressKeys.flatMap((provider) => value.connectorEgressCIDRs[provider].map((cidr, index) => [`network.connectorEgressCIDRs.${provider}[${index}]`, cidr])),
    ...imageNames.map((name) => [`global.productImages.${name}`, value.images[name]]),
  ];
  const args = ["template", "zasp", path.join(root, "deploy/staging/product"), "--namespace", "agentsec"];
  for (const [key, entry] of set) args.push("--set-string", `${key}=${entry}`);
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
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== ["connectorEgressCIDRs", "connectors", "host", "images", "secretProviderClass", "tlsSecretName"].sort().join("\0")) return false;
  if (!hostPattern.test(value.host) || !namePattern.test(value.tlsSecretName) || !namePattern.test(value.secretProviderClass)) return false;
  if (!value.images || typeof value.images !== "object" || Array.isArray(value.images) || Object.keys(value.images).sort().join("\0") !== [...imageNames].sort().join("\0")) return false;
  if (!imageNames.every((name) => digestPattern.test(value.images[name]))) return false;
  if (!value.connectors || typeof value.connectors !== "object" || Array.isArray(value.connectors) || Object.keys(value.connectors).sort().join("\0") !== [...connectorKeys].sort().join("\0")) return false;
  const role = /^arn:aws:iam::([0-9]{12}):role\/zasp-production-api-connectors$/.exec(value.connectors.roleArn);
  const kms = /^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.exec(value.connectors.kmsKeyArn);
  if (!/^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$/.test(value.connectors.awsRegion) || !role || !kms || kms[1] !== value.connectors.awsRegion || kms[2] !== role[1]) return false;
  if (value.connectors.webIdentityTokenFile !== "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || value.connectors.secretPrefix !== "zasp-production/connectors/oauth") return false;
  if (!/^Iv1\.[A-Za-z0-9]{16}$/.test(value.connectors.githubClientID) || value.connectors.githubClientSecretReference !== "ref:github/client-secret") return false;
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
