import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");

function markdownRows(markdown: string) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function taskRows(tracker: string, heading: "In progress" | "Complete" | "Blocked") {
  const end = heading === "In progress" ? "Complete" : heading === "Complete" ? "Blocked" : "Review findings";
  const section = tracker.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "";
  return markdownRows(section).slice(2);
}

describe("M1-23 OpenAPI root", () => {
  it("binds the source, public API rules, dependency, and closed design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-23-openapi-root-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-23-openapi-root-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-23 - OpenAPI root\*\*[\s\S]*?\*\*M1-24 - generated TS client/)?.[0] ?? "";

    expect(section).toContain("Depends on: `M1-22`");
    expect(section).toContain("Create OpenAPI 3.1 root, auth schemes, pagination/error schemas");
    expect(section).toContain("OpenAPI linter passes");
    expect(source).toContain("Use OpenAPI 3.1. Generate the TypeScript frontend client");
    expect(source).toContain("Normal UI code may not hand-write `/api/v1/` fetch URLs");
    expect(source).toContain("All list operations use cursor pagination and explicit filters");
    expect(source).toContain("All mutations return product IDs, audit correlation ID and stable product error codes");
    for (const text of [
      "openapi/openapi.yaml",
      "openapi: 3.1.0",
      "SessionJWT",
      "ProductAPIToken",
      "Cursor",
      "PageCursor",
      "PageLimit",
      "PageInfo",
      "ProductError",
      "@redocly/cli",
      "2.43.1",
    ]) {
      expect(design).toContain(text);
    }
    expect(design).toContain("empty `paths` object");
    expect(design).toMatch(/remote\s+references/);
    expect(plan).toContain("M1-24 remains Pending");
  });

  it("completes only M1-23 and preserves its prerequisite, successor, and blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toMatch(/M1-23\s+is\s+Complete/);
    expect(tracker).toContain("| Pending | 649 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 75 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`649/1/75/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "16", "1", "51", "0"]);
    expect(active.map(([task]) => task)).toEqual(["M1-36c"]);
    expect(complete.filter(([task]) => task === "M1-23")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-22")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-24")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-24")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("documents the exact public OpenAPI root and local verification boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## OpenAPI root[\s\S]*?## Neon pooled proof/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    expect(section).toMatch(/^npm run openapi:test$/m);
    expect(section).toMatch(/^npm run openapi:lint$/m);
    expect(section).toContain("`openapi/openapi.yaml`");
    expect(prose).toContain("OpenAPI 3.1.0");
    expect(prose).toContain("`SessionJWT` or `ProductAPIToken`");
    expect(prose).toContain("separate global security alternatives");
    for (const component of ["Cursor", "PageCursor", "PageLimit", "PageInfo", "ProductID", "ProductError", "ProductErrorResponse"]) {
      expect(section).toContain(`\`${component}\``);
    }
    expect(prose).toContain("`paths: {}`");
    expect(prose).toContain("no operations, servers, callbacks, webhooks, examples, or remote references");
    expect(prose).toContain("`no-empty-servers` and `no-unused-components`");
    expect(prose).toContain("No install, download, provider, network, credential, environment-file, database, Docker, or shared-resource I/O");
    expect(prose).toContain("M1-24 is Complete");
  });
});
