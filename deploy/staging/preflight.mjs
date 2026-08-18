import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

export const requiredTools = Object.freeze(["terraform", "helm", "kubectl", "aws"]);
const digestPattern = /^[a-z0-9./_-]+(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$/;

export function validateReleaseInput(input) {
  if (!input || input.environment !== "production" || input.privateEndpointOnly !== true || input.endpoint_public_access !== false) throw new Error("release preflight rejected");
  if (!Array.isArray(input.productImages) || input.productImages.length !== 5 || input.productImages.some((value) => !digestPattern.test(value))) throw new Error("release preflight rejected");
  if (typeof input.attackLabSecurityGroupID !== "string" || !/^sg-[0-9a-f]{8,17}$/.test(input.attackLabSecurityGroupID)) throw new Error("release preflight rejected");
  return Object.freeze({ environment: "production", privateEndpointOnly: true, images: 5 });
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
    process.stdout.write(`Release preflight passed: environment=${value.environment} privateEndpointOnly=${value.privateEndpointOnly} images=${value.images}.\n`);
  } catch {
    process.stdout.write("Release preflight failed: configuration rejected.\n");
    process.exitCode = 1;
  }
}
