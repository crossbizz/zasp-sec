import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

export const requiredTools = Object.freeze(["terraform", "helm", "kubectl", "aws"]);
const digestPattern = /^[a-z0-9./_-]+(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$/;
const rolePrefix = "arn:aws:iam::[0-9]{12}:role/zasp-production-";
const identityContract = Object.freeze({
  web: Object.freeze({ serviceAccount: "agentsec-web", role: null }),
  agentsecApi: Object.freeze({ serviceAccount: "agentsec-api", role: new RegExp(`^${rolePrefix}api$`) }),
  migration: Object.freeze({ serviceAccount: "agentsec-migration", role: new RegExp(`^${rolePrefix}migration$`) }),
  canary: Object.freeze({ serviceAccount: "agentsec-canary", role: null }),
  canarySecretSync: Object.freeze({ serviceAccount: "agentsec-canary-secret-sync", role: new RegExp(`^${rolePrefix}canary-secret-sync$`) }),
});

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

export function validateReleaseInput(input) {
  if (!exactKeys(input, ["environment", "privateEndpointOnly", "endpoint_public_access", "productImages", "workloadIdentities"]) || input.environment !== "production" || input.privateEndpointOnly !== true || input.endpoint_public_access !== false) throw new Error("release preflight rejected");
  if (!exactKeys(input.productImages, ["web", "agentsecApi"]) || !Object.values(input.productImages).every((value) => digestPattern.test(value))) throw new Error("release preflight rejected");
  if (!exactKeys(input.workloadIdentities, Object.keys(identityContract))) throw new Error("release preflight rejected");
  for (const [name, expected] of Object.entries(identityContract)) {
    const identity = input.workloadIdentities[name];
    if (!exactKeys(identity, ["serviceAccount", "roleArn"]) || identity.serviceAccount !== expected.serviceAccount || (expected.role === null ? identity.roleArn !== null : !expected.role.test(identity.roleArn))) throw new Error("release preflight rejected");
  }
  return Object.freeze({ environment: "production", privateEndpointOnly: true, images: 2, cloudIdentities: 3 });
}

export function runPreflight(argv = process.argv.slice(2), runtime = { spawn: spawnSync, read: readFileSync }) {
  if (argv.length !== 2 || argv[0] !== "--input") throw new Error("release preflight rejected");
  const input = JSON.parse(runtime.read(argv[1], "utf8"));
  const validated = validateReleaseInput(input);
  for (const tool of requiredTools) {
    const result = runtime.spawn(tool, ["version"], { encoding: "utf8", timeout: 10_000, env: { PATH: process.env.PATH || "" }, maxBuffer: 16 * 1024 });
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
