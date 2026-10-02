import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import yaml from "../../../node_modules/js-yaml/index.js";

const base = ".superpowers/sdd/2026-09-18-compliance-production-plan";
const mode = process.argv[2];
assert.ok(["before-browser", "after"].includes(mode));
const files = ["scripts/production-combined-e2e.mjs", "scripts/production-combined-e2e.test.mjs", "scripts/browser-prerequisites.mjs", "scripts/browser-prerequisites.test.mjs", ".github/workflows/runnable-ui.yml"];
const blob = file => {
  const bytes = readFileSync(file);
  return { gitBlob: createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"), sha256: createHash("sha256").update(bytes).digest("hex"), bytes: bytes.length };
};
const trackedInputs = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "--", "app", "apps/web", "public", "services/platform", "package.json", "package-lock.json", "tsconfig.json", "vite.config.ts", "next.config.ts", "eslint.config.mjs"], { encoding: "utf8", maxBuffer: 4 * 1024 * 1024 }).trim().split("\n").filter(file => existsSync(file) && statSync(file).isFile());
function walk(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? walk(path.join(directory, entry.name)) : entry.isFile() ? [path.join(directory, entry.name)] : []);
}
const identities = Object.fromEntries([...new Set([...files, ...trackedInputs, ...walk("dist")])].sort().map(file => [file, blob(file)]));
writeFileSync(`${base}/compliance-ci-${mode}-identities.json`, JSON.stringify(identities, null, 2) + "\n");
const prior = new Map();
for (const name of ["task-5-blobs.json", "task-5-fix-1-blobs.json"]) {
  for (const file of JSON.parse(readFileSync(`docs/internal/compliance-ui-task5-20260918/${name}`)).files) {
    if (file.path.startsWith("app/") || file.path.startsWith("apps/web/") || file.path === "package.json") prior.set(file.path, file.after);
  }
}
for (const [file, expected] of prior) assert.equal(blob(file).gitBlob, expected, `reviewed UI source changed: ${file}`);
console.log(`Matched ${prior.size} reviewed Task5/fix1 UI/package source identities; captured ${Object.keys(identities).length} source/build files.`);

const workflow = yaml.load(readFileSync(".github/workflows/runnable-ui.yml", "utf8"));
const steps = workflow.jobs.verify.steps;
const beforeWorkflow = yaml.load(readFileSync(`${base}/compliance-ci-before/.github/workflows/runnable-ui.yml`, "utf8"));
for (const old of beforeWorkflow.jobs.verify.steps) assert.deepEqual(steps.find(step => step.name === old.name), old, `existing CI step changed: ${old.name}`);
const provision = steps.find(step => step.name === "Provision isolated compliance browser prerequisites");
const browser = steps.find(step => step.name === "Verify current compliance browser acceptance");
const pinnedImage = readFileSync("scripts/owned-browser-postgres.mjs", "utf8").match(/const IMAGE = "([^"]+)";/)?.[1];
assert.ok(pinnedImage && provision.run.includes(`compliance_postgres_image=${pinnedImage}\n`), "workflow image differs from owned PostgreSQL pin");
assert.ok(steps.indexOf(provision) > steps.findIndex(step => step.run === "npm run verify"));
assert.ok(steps.indexOf(browser) > steps.indexOf(provision));
assert.ok(steps.indexOf(browser) < steps.findIndex(step => step.run === "npm run production:release:gate"));
assert.equal(browser.env.ZASP_COMBINED_E2E_COMPLIANCE, "true");
assert.equal(browser["timeout-minutes"], 15);
assert.equal(provision["timeout-minutes"], 10);
for (const step of [provision, browser]) {
  const parsed = spawnSync("/bin/bash", ["-n"], { input: step.run, encoding: "utf8", timeout: 5000 });
  assert.equal(parsed.status, 0, parsed.stderr);
}
console.log("Workflow YAML parsed; shell blocks pass bash -n; every prior step is unchanged; provision/current mode precede unchanged advisory gate.");
const harnessBefore = readFileSync(`${base}/compliance-ci-before/scripts/production-combined-e2e.mjs`, "utf8");
const harnessAfter = readFileSync("scripts/production-combined-e2e.mjs", "utf8");
for (const name of ["exerciseComplianceBrowser", "startBrowser", "cleanupOwnedResources"]) {
  const body = source => {
    const start = source.indexOf(`async function ${name}(`);
    assert.ok(start >= 0);
    const next = source.indexOf("\nasync function ", start + 1);
    return source.slice(start, next < 0 ? undefined : next);
  };
  assert.equal(body(harnessAfter), body(harnessBefore), `${name} changed outside prerequisite scope`);
}
console.log("Owned PostgreSQL pin agrees; compliance assertions, browser launch flags, and bounded cleanup bodies are byte-identical to BEFORE.");

if (mode === "after") {
  const before = JSON.parse(readFileSync(`${base}/compliance-ci-before-browser-identities.json`));
  assert.deepEqual(identities, before, "source or built UI changed during browser acceptance");
  const manifest = files.map(file => ({ path: file, before: existsSync(`${base}/compliance-ci-before/${file}`) ? blob(`${base}/compliance-ci-before/${file}`) : null, after: blob(file) }));
  writeFileSync(`${base}/compliance-ci-blobs.json`, JSON.stringify({ head: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(), baseline: "captured working-tree BEFORE files, never HEAD", files: manifest }, null, 2) + "\n");
  let patch = "";
  for (const file of files) {
    const beforeFile = existsSync(`${base}/compliance-ci-before/${file}`) ? `${base}/compliance-ci-before/${file}` : "/dev/null";
    const diff = spawnSync("git", ["diff", "--no-index", "--", beforeFile, file], { encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
    assert.ok([0, 1].includes(diff.status), diff.stderr);
    patch += diff.stdout.replaceAll(`a/${base}/compliance-ci-before/`, "a/");
  }
  writeFileSync(`${base}/compliance-ci-scoped.patch`, patch);
  console.log("Source/build identity check unchanged; five-file incremental patch and before/after manifest written.");
}
