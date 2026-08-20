import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const toolChecks = Object.freeze([
  Object.freeze({ tool: "terraform", args: Object.freeze(["version", "-json"]) }),
  Object.freeze({ tool: "helm", args: Object.freeze(["version", "--short"]) }),
  Object.freeze({ tool: "kubectl", args: Object.freeze(["version", "--client=true", "--output=json"]) }),
  Object.freeze({ tool: "aws", args: Object.freeze(["--version"]) }),
]);
export const requiredTools = Object.freeze(toolChecks.map(({ tool }) => tool));
const digestPattern = /^[a-z0-9./_-]+(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$/;
const identityContract = Object.freeze({
  web: Object.freeze({ serviceAccount: "agentsec-web", role: null, deployment: true }),
  agentsecApi: Object.freeze({ serviceAccount: "agentsec-api", role: "api", deployment: true }),
  discoveryScheduler: Object.freeze({ serviceAccount: "zasp-discovery-scheduler", role: "discovery-scheduler", deployment: true }),
  discoveryWorker: Object.freeze({ serviceAccount: "zasp-discovery-worker", role: "discovery-worker", deployment: true }),
  outboxPublisher: Object.freeze({ serviceAccount: "zasp-outbox-publisher", role: "outbox", deployment: true }),
  projectionRisk: Object.freeze({ serviceAccount: "zasp-projection-risk", role: "projection-risk", deployment: true }),
  projectionGraph: Object.freeze({ serviceAccount: "zasp-projection-graph", role: "projection-graph", deployment: true }),
  projectionSearch: Object.freeze({ serviceAccount: "zasp-projection-search", role: "projection-search", deployment: true }),
  migration: Object.freeze({ serviceAccount: "agentsec-migration", role: "migration", deployment: false }),
  projectionGraphInit: Object.freeze({ serviceAccount: "agentsec-projection-graph-init", role: "projection-graph-init", deployment: false }),
  projectionSearchInit: Object.freeze({ serviceAccount: "agentsec-projection-search-init", role: "projection-search-init", deployment: false }),
  canary: Object.freeze({ serviceAccount: "agentsec-canary", role: null, deployment: false }),
  canarySecretSync: Object.freeze({ serviceAccount: "agentsec-canary-secret-sync", role: "canary-secret-sync", deployment: false }),
});

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

export function validateReleaseInput(input) {
  if (!exactKeys(input, ["environment", "platformAccountID", "privateEndpointOnly", "endpoint_public_access", "productImages", "workloadIdentities"]) || input.environment !== "production" || !/^[0-9]{12}$/.test(input.platformAccountID) || input.platformAccountID === "000000000000" || input.privateEndpointOnly !== true || input.endpoint_public_access !== false) throw new Error("release preflight rejected");
  if (!exactKeys(input.productImages, ["web", "agentsecApi", "agentsecWorker"]) || !Object.values(input.productImages).every((value) => digestPattern.test(value))) throw new Error("release preflight rejected");
  if (!exactKeys(input.workloadIdentities, Object.keys(identityContract))) throw new Error("release preflight rejected");
  for (const [name, expected] of Object.entries(identityContract)) {
    const identity = input.workloadIdentities[name];
    const expectedRole = expected.role === null ? null : `arn:aws:iam::${input.platformAccountID}:role/zasp-production-${expected.role}`;
    if (!exactKeys(identity, ["serviceAccount", "roleArn"]) || identity.serviceAccount !== expected.serviceAccount || identity.roleArn !== expectedRole) throw new Error("release preflight rejected");
  }
  return Object.freeze({ environment: "production", privateEndpointOnly: true, images: 3, deployments: Object.values(identityContract).filter(({ deployment }) => deployment).length, cloudIdentities: Object.values(identityContract).filter(({ role }) => role !== null).length });
}

export function runPreflight(argv = process.argv.slice(2), runtime = { spawn: spawnSync, read: readFileSync }) {
  if (argv.length !== 2 || argv[0] !== "--input") throw new Error("release preflight rejected");
  const input = JSON.parse(runtime.read(argv[1], "utf8"));
  const validated = validateReleaseInput(input);
  for (const { tool, args } of toolChecks) {
    const result = runtime.spawn(tool, args, { encoding: "utf8", timeout: 10_000, env: { PATH: process.env.PATH || "" }, maxBuffer: 16 * 1024 });
    if (!result || result.status !== 0 || result.signal || result.error) throw new Error("release preflight rejected");
  }
  return validated;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const value = runPreflight();
    process.stdout.write(`Release preflight passed: environment=${value.environment} privateEndpointOnly=${value.privateEndpointOnly} images=${value.images} cloudIdentities=${value.cloudIdentities}.\n`);
  } catch {
    process.stdout.write("Release preflight failed: configuration rejected.\n");
    process.exitCode = 1;
  }
}
