import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { verifyReleaseSources } from "../deploy/production/release-gates.mjs";

import { verifyPromotion } from './release-security/verify.mjs';

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

await verifyReleaseSources();
await run("npm", ["run", "production:release:test"]);
await run("node", ["--test", "deploy/production/nango-image-proof.test.mjs"]);
await run("node", ["--test", "deploy/production/otel-redaction-proof.test.mjs"]);
await run("node", ["--test", "deploy/staging/gate.test.mjs", "deploy/staging/preflight.test.mjs"]);
await run("go", ["test", "-C", "services/platform", "-race", "-count=1", "./externalclient", "./database", "./jobqueue", "./agentsec-api", "./healthserver"]);
await run("go", ["test", "-C", "cmd/agentsecctl", "-race", "-count=1", "./..."]);
for (const moduleRoot of ["services/health", "services/platform"]) {
  await run("go", ["list", "-mod=readonly", "-m", "all"], { cwd: path.join(root, moduleRoot) });
}
// Missing or unauthenticated advisory evidence fails before promotion.
const receipt = await verifyPromotion({dir:process.env.ZASP_RELEASE_EVIDENCE_DIR});
console.log(JSON.stringify(receipt));

async function run(command, args, options = {}) {
  try {
    return await exec(command, args, { cwd: root, encoding: "utf8", maxBuffer: 32 * 1024 * 1024, ...options });
  } catch (error) {
    if (error?.stdout) process.stdout.write(error.stdout);
    if (error?.stderr) process.stderr.write(error.stderr);
    throw error;
  }
}
