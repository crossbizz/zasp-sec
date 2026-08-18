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

describe("M1-36b hermetic schema check", () => {
  it("binds the exact source row, design, plan, and five schema authorities", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-36b-m1-schema-check-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-36b-m1-schema-check-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-36b - M1 schema check\*\*[\s\S]*?\*\*M1-36c - M1 OpenAPI check/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-36a`");
    expect(section).toContain("Deliverable: Run database/event/domain schema validation checks.");
    expect(section).toContain("Verify: All schema checks succeed with no drift.");
    for (const value of [
      "services/platform/migrations",
      "services/platform/domain",
      "services/platform/securityevent",
      "services/platform/eventindex",
      "services/platform/queuedefinition",
      "M1 schema check passed: targets=5",
      "M1 schema check rejected",
      "M1-36c remains Pending",
    ]) {
      expect(prose).toContain(value);
    }
    expect(plan).toContain("Use genuine tests-first RED/GREEN");
    expect(plan.match(/^- \[x\]/gm) ?? []).toHaveLength(15);
    expect(plan).not.toMatch(/^- \[ \]/m);
  });

  it("completes only M1-36b after completed M1-36a and preserves exact blockers", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(tracker).toContain("| Pending | 643 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 82 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`643/0/82/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "10", "0", "58", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(active.filter(([task]) => task === "M1-36b")).toHaveLength(0);
    expect(complete).toHaveLength(82);
    expect(complete.filter(([task]) => task === "M1-36a")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-36b")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-36c")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-36c")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("documents only the hermetic schema gate and its successor boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## M1 schema check[\s\S]*?(?=\n## )/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    expect(prose).toContain("M1-36b is Complete");
    expect(section).toContain("npm run schema:check");
    expect(prose).toContain("five schema authorities");
    expect(prose).toContain("M1-36c is Complete");
    expect(prose).not.toMatch(/OpenAPI generation passed|UI\/API coverage passed|local infrastructure healthy/i);
  });
});
