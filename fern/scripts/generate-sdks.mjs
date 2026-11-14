#!/usr/bin/env node
// Generates the SDKs under sdks/ from the API contract.
//
//   node fern/scripts/generate-sdks.mjs            Fern's cloud generators (needs FERN_TOKEN)
//   node fern/scripts/generate-sdks.mjs --local    generators run on this machine (needs Docker)
//   node fern/scripts/generate-sdks.mjs --group python-sdk --local
//
// Nothing is published: every generator writes to the local file system.
//
// Steps:
//   1. rebuild fern/openapi-overrides.yml, so the SDK names follow the contract;
//   2. run `fern generate` for the group (default: every SDK);
//   3. format the Go module with gofmt, because the generator's output is not
//      gofmt-clean.
//
// Files listed in each SDK's .fernignore (go.mod, pom.xml, the smoke tests,
// the README) are kept. Everything else in a generated directory is replaced.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { runFern } from "./fern.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");
const passed = process.argv.slice(2);

function run(command, args, cwd = root) {
  const result = spawnSync(command, args, { cwd, stdio: "inherit" });
  if (result.error) throw result.error;
  return result.status ?? 1;
}

if (run(process.execPath, [join(here, "build-openapi-overrides.mjs")]) !== 0) process.exit(1);

const group = passed.includes("--group") ? [] : ["--group", "sdks"];
const status = runFern(["generate", ...group, "--force", ...passed]);
if (status !== 0) process.exit(status);

const goModule = join(root, "sdks", "go");
if (existsSync(join(goModule, "go.mod"))) {
  const formatted = spawnSync("gofmt", ["-w", "."], { cwd: goModule, stdio: "inherit" });
  if (formatted.error) console.warn("gofmt was not found: format sdks/go with `gofmt -w sdks/go` before committing.");
}

console.log("SDKs written under sdks/. Check them with: npm run sdk:test");
