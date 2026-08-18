import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const testCommand =
  "go test -C services/platform -race -count=1 ./tenantcontext ./tenantrls ./repository && go test -C proofs/neon-pooled -race -count=1 -run '^TestTenantRLS|^TestRenderTenantRLS' .";
const runCommand = "node --env-file=.env proofs/neon-pooled/run-tenant-rls.mjs";

describe("M1-45 Neon tenant isolation gate", () => {
  it("binds the four prerequisite task contracts", async () => {
    const source = await readFile(
      resolve(root, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const section = source.match(/\*\*M1-45a[\s\S]*?\*\*M1-36 -/)?.[0] ?? "";
    for (const task of ["M1-45a", "M1-45b", "M1-45c", "M1-45d", "M1-45 - Neon tenant isolation gate"]) {
      expect(section).toContain(task);
    }
    expect(section).toContain("current Organization context");
    expect(section).toContain("Row Level Security");
    expect(section).toContain("findings, tests, audit metadata and export-job tables");
    expect(section).toContain("bounded RLS cross-Organization fixture suite");
  });

  it("wires bounded hermetic and isolated live commands", async () => {
    const manifest = JSON.parse(await readFile(resolve(root, "package.json"), "utf8")) as {
      scripts: Record<string, string>;
    };
    expect(manifest.scripts["db:tenant-rls:test"]).toBe(testCommand);
    expect(manifest.scripts["db:tenant-rls:run"]).toBe(runCommand);
    expect(manifest.scripts.verify).toContain("npm run db:tenant-rls:test");
  });

  it("documents the exact isolation, cleanup, and provider boundary", async () => {
    const readme = await readFile(resolve(root, "README.md"), "utf8");
    const section = readme.match(/## Neon tenant isolation gate[\s\S]*?## Development/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");
    for (const value of [
      "npm run db:tenant-rls:test",
      "npm run db:tenant-rls:run",
      "eight tenant-protected tables",
      "temporary non-bypass role",
      "cross-Organization reads and writes",
      "schema and role absence",
      "DATABASE_URL",
    ]) expect(prose).toContain(value);
    expect(prose).toContain("does not require or mutate a Neon management branch");
  });
});
