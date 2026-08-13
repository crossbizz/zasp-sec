import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

type PackageManifest = {
  scripts?: Record<string, string>;
};

const repositoryRoot = process.cwd();
const proofDirectory = "proofs/neon-pooled";
const testCommand = `cd ${proofDirectory} && go test -race ./...`;
const runCommand = `cd ${proofDirectory} && go run .`;

describe("Neon pooled Go proof repository contract", () => {
  it("keeps the exact Go toolchain and pgx dependency pins", async () => {
    const goModule = await readFile(
      resolve(repositoryRoot, proofDirectory, "go.mod"),
      "utf8",
    );

    expect(goModule).toMatch(/^go 1\.25\.0$/m);
    expect(goModule).toMatch(/^toolchain go1\.26\.5$/m);
    expect(goModule).toMatch(/^require github\.com\/jackc\/pgx\/v5 v5\.10\.0$/m);
  });

  it("keeps stable package commands for the isolated test and live proof", async () => {
    const packageManifest = JSON.parse(
      await readFile(resolve(repositoryRoot, "package.json"), "utf8"),
    ) as PackageManifest;

    expect(packageManifest.scripts?.["proof:neon:test"]).toBe(testCommand);
    expect(packageManifest.scripts?.["proof:neon:run"]).toBe(runCommand);
  });

  it("documents both commands and the ignored environment input", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");

    expect(readme).toContain(testCommand);
    expect(readme).toContain(runCommand);
    expect(readme).toContain("Go `1.26.5`");
    expect(readme).toContain("DATABASE_URL");
    expect(readme).toContain(".env");
  });
});
