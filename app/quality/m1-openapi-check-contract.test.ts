import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");

function markdownRows(section: string): string[][] {
  return section
    .split("\n")
    .filter((line) => line.startsWith("|"))
    .map((line) => line.split("|").slice(1, -1).map((cell) => cell.trim()));
}

function taskRows(tracker: string, heading: "In progress" | "Complete" | "Blocked"): string[][] {
  const end = heading === "In progress" ? "Complete" : heading === "Complete" ? "Blocked" : "Review findings";
  const section = tracker.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "";
  return markdownRows(section).slice(2);
}

describe("M1-36c OpenAPI generation and client drift check", () => {
  it("binds the exact source, reviewed generator, commands, and successor boundary", async () => {
    const [source, design, plan, packageSource] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-36c-m1-openapi-check-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-36c-m1-openapi-check-implementation-plan.md"), "utf8"),
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-36c - M1 OpenAPI check\*\*[\s\S]*?\*\*M1-36d - M1 UI API coverage check/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");
    const packageJson = JSON.parse(packageSource);
    const generator = "openapi-typescript openapi/openapi.yaml --output apps/web/api/generated.ts --alphabetize --export-type --immutable --root-types --root-types-no-schema-prefix";

    expect(section).toContain("Depends on: `M1-36b`");
    expect(section).toContain("Deliverable: Run OpenAPI generation and generated-client drift check.");
    expect(section).toContain("Verify: Generated client has no uncommitted diff.");
    expect(packageJson.devDependencies?.["openapi-typescript"]).toBe("7.13.0");
    expect(packageJson.scripts?.["openapi:generate"]).toBe(generator);
    expect(packageJson.scripts?.["openapi:check"]).toBe(`${generator} --check`);
    for (const value of [
      "openapi/openapi.yaml",
      "apps/web/api/generated.ts",
      "npm run openapi:generate",
      "git diff --exit-code -- apps/web/api/generated.ts",
      "npm run openapi:check",
      "M1-36d remains Pending",
    ]) {
      expect(prose).toContain(value);
    }
    expect(plan.match(/^- \[[ x]\]/gm) ?? []).toHaveLength(15);
  });

  it("completes only M1-36c after completed M1-36b and preserves exact blockers", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(tracker).toContain("| Pending | 596 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 129 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`596/0/129/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete.filter(([task]) => task === "M1-36b")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-36c")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-36d")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-36d")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("documents only the OpenAPI generation and no-drift boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## M1 OpenAPI check[\s\S]*?(?=\n## )/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    expect(prose).toContain("M1-36c is Complete");
    expect(section).toContain("npm run openapi:generate");
    expect(section).toContain("npm run openapi:check");
    expect(prose).toContain("no uncommitted generated-client diff");
    expect(prose).toContain("M1-36d is Complete");
    expect(prose).not.toMatch(/UI\/API coverage passed|local infrastructure healthy|new API operation/i);
  });
});
