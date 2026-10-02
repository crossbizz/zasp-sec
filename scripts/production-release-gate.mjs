import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { verifyReleaseSources } from "../deploy/production/release-gates.mjs";

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
// Offline npm audit skips advisory lookup but can still return zero counters.
// No approved advisory source is wired yet. Do not enable network disclosure or
// accept historical reports as a substitute. See the offline-audit gate-gap note.
throw new Error("production dependency audit evidence unavailable: release blocked until an approved advisory source supplies fresh, exact-lock scan evidence; offline zero counters are not clearance (docs/internal/2026-09-15-offline-audit-gate-gap.md)");

async function run(command, args, options = {}) {
  try {
    return await exec(command, args, { cwd: root, encoding: "utf8", maxBuffer: 32 * 1024 * 1024, ...options });
  } catch (error) {
    if (error?.stdout) process.stdout.write(error.stdout);
    if (error?.stderr) process.stderr.write(error.stderr);
    throw error;
  }
}
