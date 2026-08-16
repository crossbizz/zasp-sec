import assert from "node:assert/strict";
import { lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const repositoryRoot = resolve(import.meta.dirname, "..");
const schemaPath = resolve(repositoryRoot, "openapi/openapi.yaml");
const generatedPath = resolve(repositoryRoot, "apps/web/api/generated.ts");
const cliPath = resolve(repositoryRoot, "node_modules/openapi-typescript/bin/cli.js");
const generationFlags = [
  "--alphabetize",
  "--export-type",
  "--immutable",
  "--root-types",
  "--root-types-no-schema-prefix",
];
const generateScript = [
  "openapi-typescript openapi/openapi.yaml",
  "--output apps/web/api/generated.ts",
  ...generationFlags,
].join(" ");

function runGenerator(outputPath, extraFlags = []) {
  return spawnSync(
    process.execPath,
    [cliPath, schemaPath, "--output", outputPath, ...generationFlags, ...extraFlags],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: {
        HOME: process.env.HOME,
        LANG: "C.UTF-8",
        PATH: process.env.PATH,
      },
      maxBuffer: 64 * 1024,
      timeout: 30_000,
    },
  );
}

test("pins the official generator/runtime and wires exact local-only scripts into verify", async () => {
  const packageJson = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8"));
  const packageLock = JSON.parse(await readFile(resolve(repositoryRoot, "package-lock.json"), "utf8"));

  assert.equal(packageJson.dependencies?.["openapi-fetch"], "0.17.0");
  assert.equal(packageJson.devDependencies?.["openapi-typescript"], "7.13.0");
  assert.equal(packageLock.packages?.["node_modules/openapi-fetch"]?.version, "0.17.0");
  assert.equal(packageLock.packages?.["node_modules/openapi-typescript"]?.version, "7.13.0");
  assert.equal(packageJson.scripts?.["openapi:generate"], generateScript);
  assert.equal(packageJson.scripts?.["openapi:check"], `${generateScript} --check`);
  assert.equal(
    packageJson.scripts?.["openapi:test"],
    "node --test openapi/openapi.test.mjs openapi/generated-client.test.mjs",
  );
  assert.equal(
    packageJson.scripts?.verify,
    "npm run dependencies:check && npm run openapi:test && npm run openapi:lint && npm run openapi:check && npm run ui-api:test && npm run ui-api:check && npm test && npm run typecheck && npm run lint && npm run build",
  );
});

test("reproduces the committed bytes and rejects changed or missing output without rewriting it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zasp-m1-24-"));
  try {
    const outputPath = join(directory, "generated.ts");
    const missingPath = join(directory, "missing.ts");
    const committed = await readFile(generatedPath);
    const committedMetadata = await lstat(generatedPath);

    assert.equal(committedMetadata.isFile(), true);
    assert.equal(committedMetadata.isSymbolicLink(), false);

    const first = runGenerator(outputPath);
    assert.equal(first.status, 0, `${first.stdout}${first.stderr}`);
    assert.deepEqual(await readFile(outputPath), committed);

    const second = runGenerator(outputPath);
    assert.equal(second.status, 0, `${second.stdout}${second.stderr}`);
    assert.deepEqual(await readFile(outputPath), committed);

    const changed = Buffer.concat([committed, Buffer.from("// drift\n")]);
    await writeFile(outputPath, changed, { mode: 0o600 });
    const drift = runGenerator(outputPath, ["--check"]);
    assert.notEqual(drift.status, 0);
    assert.deepEqual(await readFile(outputPath), changed);

    const missing = runGenerator(missingPath, ["--check"]);
    assert.notEqual(missing.status, 0);
    await assert.rejects(readFile(missingPath));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
