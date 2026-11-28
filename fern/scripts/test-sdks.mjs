#!/usr/bin/env node
// Compiles the generated SDKs and runs their smoke tests against a local fake
// of the API (sdks/fixtures/responses.json).
//
//   node fern/scripts/test-sdks.mjs                 TypeScript and Go
//   node fern/scripts/test-sdks.mjs --python        also Python (needs httpx, pydantic, pytest)
//   node fern/scripts/test-sdks.mjs --java          also Java (needs Maven and a JDK)
//
// TypeScript and Go use the toolchains this repository already needs. Python
// and Java are opt-in because their dependencies are not part of it.

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const flags = new Set(process.argv.slice(2));
const failures = [];

function step(name, command, args, cwd) {
  console.log(`\n== ${name}`);
  const result = spawnSync(command, args, { cwd, stdio: "inherit" });
  if (result.error) console.error(`Unable to start ${command}: ${result.error.code}`);
  if (result.error || result.status !== 0) failures.push(name);
}

const typescript = join(root, "sdks", "typescript");
step("typescript: compile", join(root, "node_modules", ".bin", "tsc"), ["-p", "tsconfig.json"], typescript);
step("typescript: smoke test", process.execPath, ["--test", "tests/smoke.test.mjs"], typescript);

const go = join(root, "sdks", "go");
step("go: build", "go", ["build", "./..."], go);
step("go: vet", "go", ["vet", "./..."], go);
step("go: test", "go", ["test", "-count=1", "./..."], go);

if (flags.has("--python")) {
  const python = join(root, "sdks", "python");
  step("python: compile", "python3", ["-m", "compileall", "-q", "src/zasp"], python);
  step("python: smoke test", "python3", ["-m", "pytest", "-q", "tests"], python);
}

if (flags.has("--java")) {
  // Maven Resolver retries individual repository requests. Compile and run JUnit once.
  step("java: compile and test", "mvn", [
    "-q", "-B", "-Dstyle.color=never",
    "-Daether.transport.http.retryHandler.serviceUnavailable=429,502,503,504",
    "-Daether.transport.http.retryHandler.count=5",
    "-Daether.transport.http.retryHandler.intervalMax=60000",
    "test",
  ], join(root, "sdks", "java"));
}

if (failures.length > 0) {
  console.error(`\nFailed: ${failures.join(", ")}`);
  process.exit(1);
}
console.log("\nSDK checks passed");
