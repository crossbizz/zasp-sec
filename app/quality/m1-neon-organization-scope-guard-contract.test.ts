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

describe("M1-38 Neon Organization scope guard contract", () => {
  it("binds the source task to the stateless pre-SQL Organization guard", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-38-neon-organization-scope-guard-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-38-neon-organization-scope-guard-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-38 - Neon Organization scope guard\*\*[\s\S]*?\*\*M1-39 - OpenSearch Organization scope guard/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");

    expect(sourceSection).toContain("Depends on: `M1-04, M1-10`");
    expect(sourceSection).toContain("Add a scoped repository helper that requires Organization ID for customer-data queries");
    expect(sourceSection).toContain("A fixture query without Organization scope fails before SQL execution");
    for (const value of [
      "services/platform/repository",
      "QueryRow(context.Context, string, []any, ...any) error",
      "domain.ProductID",
      "Organization argument at `$1`",
      "never mutated or retained",
      "does not parse SQL",
      "M1-45a",
      "M1-39 remains Pending",
    ]) expect(prose).toContain(value);
    expect(plan).toContain("Every behavior and status change has a witnessed tests-only RED first");
    expect(plan.match(/^- \[[ x]\]/gm) ?? []).toHaveLength(16);
  });

  it("moves only M1-38 to Complete with exact arithmetic", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);
    const m1 = milestones.find(([milestone]) => milestone === "M1");

    expect(readme).toContain("M1-37 is Complete");
    expect(readme).toContain("M1-38 is Complete");
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(m1).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).not.toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-37")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-38")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-39")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });

  it("documents the pre-SQL guard without claiming SQL parsing or RLS", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## Neon Organization scope guard[\s\S]*?## OpenSearch Organization scope guard/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    for (const value of [
      "M1-38 is Complete",
      "canonical product Organization ID",
      "before SQL execution",
      "argument `$1`",
      "M1-45a",
      "M1-39 is Complete",
    ]) expect(prose).toContain(value);
    expect(section).not.toMatch(/parses SQL|row-level security is complete|reads credentials|provider call/i);
  });
});
