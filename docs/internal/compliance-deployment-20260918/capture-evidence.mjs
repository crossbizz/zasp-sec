import { readFile, writeFile, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../../..");
const modified = [
  "deploy/production/release-contract.mjs", "deploy/production/session-search-rollout.mjs",
  "deploy/production/audit-export-rollout.mjs", "deploy/production/audit-export-network.mjs",
  "deploy/production/test-reconciler-rollout.mjs", "deploy/production/test-reconciler-rollout.test.mjs",
  "deploy/production/session-search-rollout.test.mjs", "deploy/production/security-agent-budget-rollout.test.mjs",
  "deploy/staging/product/values.yaml", "deploy/staging/product/templates/_session-search.tpl",
  "deploy/staging/product/templates/migration.yaml", "deploy/staging/product/templates/workloads.yaml",
  "deploy/staging/product/templates/test-reconciler.yaml", "deploy/staging/product/templates/resilience.yaml",
  "deploy/staging/product/templates/audit-exports.yaml", "deploy/staging/gate.test.mjs", "package.json",
  "services/platform/migrations/production_audit_exports.go", "services/platform/migrations/production_audit_exports_test.go",
];
const added = [
  "deploy/production/compliance-export-rollout.mjs", "deploy/production/compliance-export-network.mjs",
  "deploy/production/compliance-export-release-fixture.mjs", "deploy/production/compliance-export-rollout.test.mjs",
  "deploy/production/compliance-export-runtime.test.mjs", "deploy/production/compliance-export-helm.test.mjs",
  "deploy/staging/product/templates/_compliance-exports.tpl", "deploy/staging/product/templates/compliance-exports.yaml",
  "deploy/staging/product/templates/compliance-export-network.yaml", "deploy/staging/product/templates/compliance-export-operations.yaml",
  "services/platform/agentsec-api/compliance_deployment_config_test.go", "services/platform/agentsec-worker/compliance_deployment_config_test.go",
  "services/platform/agentsec-migrate/compliance_deployment_postgres_test.go",
];
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
let patch = "";
const hashes = [];
for (const file of [...modified, ...added]) {
  const beforePath = modified.includes(file) ? path.join(here, "before", file) : "/dev/null";
  const before = await readFile(beforePath), after = await readFile(path.join(root, file));
  if (before.equals(after)) throw new Error(`listed file unchanged: ${file}`);
  hashes.push({ file, before: modified.includes(file) ? hash(before) : null, after: hash(after) });
  try { patch += execFileSync("diff", ["-u", "--label", modified.includes(file) ? `a/${file}` : "/dev/null", "--label", `b/${file}`, beforePath, path.join(root, file)], { encoding: "utf8" }); }
  catch (e) { if (e.status !== 1) throw e; patch += e.stdout; }
}
await writeFile(path.join(here, "scoped.patch"), patch);
await writeFile(path.join(here, "source-hashes.json"), JSON.stringify(hashes, null, 2) + "\n");
const artifacts = [];
for (const file of (await readdir(here)).sort()) if (/\.(log|json|patch|md|mjs|sha256)$/.test(file) && file !== "artifact-hashes.json") artifacts.push({ file, sha256: hash(await readFile(path.join(here, file))) });
await writeFile(path.join(here, "artifact-hashes.json"), JSON.stringify(artifacts, null, 2) + "\n");
console.log(JSON.stringify({ modified: modified.length, added: added.length, patchSHA256: hash(patch), artifacts: artifacts.length }));
