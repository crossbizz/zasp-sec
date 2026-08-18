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

describe("M1-39 OpenSearch Organization scope guard contract", () => {
  it("binds the source task to scope-mandatory EventStore builders", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-39-opensearch-organization-scope-guard-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-39-opensearch-organization-scope-guard-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-39 - OpenSearch Organization scope guard\*\*[\s\S]*?\*\*M1-40 - S3 Organization artifact prefix/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");

    expect(sourceSection).toContain("Depends on: `M1-04, M1-14`");
    expect(sourceSection).toContain("Add Organization scope to EventStore index and query builders");
    expect(sourceSection).toContain("Organization A query cannot return Organization B fixture document");
    for (const value of [
      "services/platform/eventstore",
      "buildDriverDocument(scope, event)",
      "buildDriverQuery(scope, filter, maximumResults)",
      "same-session",
      "M1-14 remains the provider-compatibility authority",
      "M1-40 remains Pending",
    ]) expect(prose).toContain(value);
    expect(plan).toContain("Every behavior and status change has a witnessed tests-only RED first");
    expect(plan.match(/^- \[[ x]\]/gm) ?? []).toHaveLength(16);
  });

  it("moves only M1-39 to In progress with exact arithmetic", async () => {
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

    expect(readme).toContain("M1-38 is Complete");
    expect(readme).toContain("M1-39 is In progress");
    expect(tracker).toContain("| Pending | 644 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 80 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`644/1/80/3`");
    expect(m1).toEqual(["M1", "68", "11", "1", "56", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.filter(([task]) => task === "M1-39")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-38")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-40")).toHaveLength(0);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });

  it("documents inherited provider authority and product-only scope hardening", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## OpenSearch Organization scope guard[\s\S]*?## Development/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    for (const value of [
      "M1-39 is In progress",
      "index-document and search-query builders",
      "Organization A",
      "Organization B",
      "M1-14",
      "M1-40 remains Pending",
    ]) expect(prose).toContain(value);
    expect(section).not.toMatch(/raw OpenSearch DSL|new provider lifecycle|AWS release parity is proven/i);
  });
});
