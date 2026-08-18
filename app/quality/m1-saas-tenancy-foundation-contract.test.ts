import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const exactCommand =
  "go test -C services/platform -race -count=1 -timeout=90s ./config ./repository ./eventstore ./artifactstore ./jobqueue ./graphstore ./tenantquota";

describe("M1-44 SaaS tenancy foundation check", () => {
  it("binds the exact source dependencies and bounded cross-Organization suite", async () => {
    const source = await readFile(
      resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const section = source.match(/\*\*M1-44 - SaaS tenancy foundation check\*\*[\s\S]*?\*\*M1-45a -/)?.[0] ?? "";

    expect(section).toContain("Depends on: `M1-38, M1-39, M1-40, M1-41, M1-42, M1-43`");
    expect(section).toContain("Run the bounded cross-Organization store/queue/graph contract suite");
    expect(section).toContain("Every cross-Organization fixture is denied and single-tenant mode still passes the same scoped contracts");
  });

  it("wires the exact bounded product packages into root verification", async () => {
    const packageJson = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8")) as {
      scripts: Record<string, string>;
    };

    expect(packageJson.scripts["saas:tenancy:test"]).toBe(exactCommand);
    expect(packageJson.scripts.verify).toContain("npm run saas:tenancy:test");
  });

  it("documents the shared SaaS and single-tenant scope boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## SaaS tenancy foundation check[\s\S]*?## Development/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    expect(section).toContain("npm run saas:tenancy:test");
    for (const value of [
      "Neon query guards",
      "OpenSearch documents",
      "S3 artifacts",
      "SQS envelopes",
      "graph paths",
      "tenant quota counters",
      "single-tenant mode",
    ]) expect(prose).toContain(value);
    expect(prose).toContain("does not contact a provider or claim database RLS enforcement");
  });
});
