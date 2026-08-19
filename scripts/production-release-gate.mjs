import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { verifyReleaseSources } from "../deploy/production/release-gates.mjs";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

await verifyReleaseSources();
await run("node", ["--test", "deploy/production/release-contract.test.mjs", "deploy/production/release-gates.test.mjs"]);
await run("node", ["--test", "deploy/staging/gate.test.mjs", "deploy/staging/preflight.test.mjs"]);
await run("go", ["test", "-C", "services/platform", "-race", "-count=1", "./externalclient", "./database", "./jobqueue", "./agentsec-api", "./healthserver"]);
for (const moduleRoot of ["services/health", "services/platform"]) {
  await run("go", ["list", "-mod=readonly", "-m", "all"], { cwd: path.join(root, moduleRoot) });
}
const { stdout } = await run("npm", ["audit", "--omit=dev", "--offline", "--audit-level=high", "--json"]);
const audit = JSON.parse(stdout);
if (audit.metadata?.vulnerabilities?.high !== 0 || audit.metadata?.vulnerabilities?.critical !== 0) throw new Error("production dependency audit rejected");
console.log("production release gate: exact web/API source SBOM/license/container/secret + resilience/dependency checks passed");
console.log("production release gate: built-image scan/signature, remote CI, live providers, public DNS/TLS remain release-environment gates");

async function run(command, args, options = {}) {
  try {
    return await exec(command, args, { cwd: root, encoding: "utf8", maxBuffer: 32 * 1024 * 1024, ...options });
  } catch (error) {
    if (error?.stdout) process.stdout.write(error.stdout);
    if (error?.stderr) process.stderr.write(error.stderr);
    throw error;
  }
}
