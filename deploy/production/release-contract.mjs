import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
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
    ["serviceAccounts.canarySecretSync.roleArn", "arn:aws:iam::123456789012:role/zasp-production-canary-sync"],
    ["ingress.host", value.host], ["ingress.tlsSecretName", value.tlsSecretName],
    ["secrets.providerClassName", value.secretProviderClass],
    ["secrets.postgresDSNObjectName", "zasp/production/postgres-dsn"],
    ["secrets.stytchProjectIDObjectName", "zasp/production/stytch-project-id"],
    ["secrets.stytchSecretObjectName", "zasp/production/stytch-secret"],
    ["secrets.stytchPublicTokenObjectName", "zasp/production/stytch-public-token"],
    ["secrets.stytchOrganizationIDObjectName", "zasp/production/stytch-organization-id"],
    ["secrets.workflowSigningKeyObjectName", "zasp/production/workflow-signing-key"],
    ["secrets.tokenRevealKeyObjectName", "zasp/production/token-reveal-key"],
    ["secrets.canaryReadTokenObjectName", "zasp/production/canary-read-token"],
    ["network.postgresCIDR", "10.30.0.0/24"], ["network.stytchCIDR", "10.40.0.0/24"],
    ["network.otelCollectorCIDR", "10.50.0.0/24"],
    ["network.canaryCIDR", "10.60.0.0/24"],
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
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== ["host", "images", "secretProviderClass", "tlsSecretName"].sort().join("\0")) return false;
  if (!hostPattern.test(value.host) || !namePattern.test(value.tlsSecretName) || !namePattern.test(value.secretProviderClass)) return false;
  if (!value.images || typeof value.images !== "object" || Array.isArray(value.images) || Object.keys(value.images).sort().join("\0") !== [...imageNames].sort().join("\0")) return false;
  return imageNames.every((name) => digestPattern.test(value.images[name]));
}
