import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

type PackageManifest = {
  scripts?: Record<string, string>;
};

const repositoryRoot = process.cwd();
const proofDirectory = "proofs/neon-pooled";
const testCommand = `cd ${proofDirectory} && go test -race -count=1 ./...`;
const runCommand =
  "node --env-file=.env proofs/neon-pooled/run-migration.mjs";
const documentedRootSequence = [
  "npm run proof:neon:migration:test",
  "npm run proof:neon:migration:run",
];

describe("Neon direct migration proof repository contract", () => {
  it("keeps stable root commands for the race suite and live migration", async () => {
    const packageManifest = JSON.parse(
      await readFile(resolve(repositoryRoot, "package.json"), "utf8"),
    ) as PackageManifest;

    expect(packageManifest.scripts?.["proof:neon:migration:test"]).toBe(
      testCommand,
    );
    expect(packageManifest.scripts?.["proof:neon:migration:run"]).toBe(
      runCommand,
    );
  });

  it("documents one root sequence and the three environment inputs", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const migrationSection = readme.match(
      /## Neon migration proof[\s\S]*?```bash\n([\s\S]*?)\n```/,
    );

    expect(migrationSection?.[1]?.split("\n")).toEqual(
      documentedRootSequence,
    );
    expect(readme).toContain("NEON_API_KEY");
    expect(readme).toContain("NEON_PROJECT_ID");
    expect(readme).toContain("DATABASE_URL");
    expect(readme).toContain("disposable branch");
    expect(readme).toContain("validated direct or pooler parent URL");
    expect(readme).toContain("always connects through the child direct endpoint");
    expect(readme).toContain("Node's dotenv loader");
  });

  it("ships a matching versioned up/down migration pair", async () => {
    const migrationDirectory = resolve(
      repositoryRoot,
      proofDirectory,
      "migrations",
    );
    const [up, down] = await Promise.all([
      readFile(resolve(migrationDirectory, "0001_proof.up.sql"), "utf8"),
      readFile(resolve(migrationDirectory, "0001_proof.down.sql"), "utf8"),
    ]);

    expect(up).toContain("CREATE SCHEMA %s;");
    expect(up).toContain('CREATE TABLE %s."migration_probe"');
    expect(down.trim()).toBe("DROP SCHEMA %s CASCADE;");
  });
});
