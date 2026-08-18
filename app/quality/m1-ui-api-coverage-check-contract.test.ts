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

describe("M1-36d UI/API traceability validation", () => {
  it("binds the exact source, reviewed validator, lifecycle model, and successor", async () => {
    const [source, design, plan, packageSource] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-36d-m1-ui-api-coverage-check-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-36d-m1-ui-api-coverage-check-implementation-plan.md"), "utf8"),
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-36d - M1 UI API coverage check\*\*[\s\S]*?\*\*M1-36e - M1 local infrastructure smoke/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");
    const packageJson = JSON.parse(packageSource);

    expect(section).toContain("Depends on: `M1-36c`");
    expect(section).toContain("Deliverable: Run UI/API traceability validator.");
    expect(section).toContain("Verify: No interactive operation lacks a mapped UI action or implementation task.");
    expect(packageJson.scripts?.["ui-api:test"]).toBe("node --test scripts/check-ui-api-coverage.test.mjs");
    expect(packageJson.scripts?.["ui-api:check"]).toBe("node scripts/check-ui-api-coverage.mjs");
    for (const value of [
      "docs/product/ui-api-map.yaml",
      "openapi/openapi.yaml",
      "`planned`",
      "`available`",
      "`/api/v1`",
      "`/internal/v1`",
      "UI/API coverage passed: planned=5 available=0 public=0 internal=0.",
      "UI/API coverage rejected.",
      "M1-36e remains Pending",
    ]) {
      expect(prose).toContain(value);
    }
    expect(plan.match(/^- \[[ x]\]/gm) ?? []).toHaveLength(15);
  });

  it("completes only M1-36d after completed M1-36c and preserves exact blockers", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(tracker).toContain("| Pending | 645 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 80 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`645/0/80/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "12", "0", "56", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(active.filter(([task]) => task === "M1-36e")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-36c")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-36d")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-36e")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("documents only the UI/API coverage gate and honest current result", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## M1 UI API coverage check[\s\S]*?(?=\n## )/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    expect(prose).toContain("M1-36d is Complete");
    expect(section).toContain("npm run ui-api:test");
    expect(section).toContain("npm run ui-api:check");
    expect(prose).toContain("UI/API coverage passed: planned=5 available=0 public=0 internal=0.");
    expect(prose).toContain("M1-36e is Complete");
    expect(prose).not.toMatch(/local infrastructure healthy|new API operation|availability: available/i);
  });
});
