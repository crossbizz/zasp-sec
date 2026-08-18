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

    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-36b")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-36c")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-36d")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-36d")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M1A-10", "M1A-09", "M1A-08", "M1A-07", "M3-52", "M3-14", "M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
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
