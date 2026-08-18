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

describe("M1-40 S3 Organization artifact prefix contract", () => {
  it("binds the source task to a scope-mandatory ArtifactStore locator", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-40-s3-organization-artifact-prefix-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-40-s3-organization-artifact-prefix-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-40 - S3 Organization artifact prefix\*\*[\s\S]*?\*\*M1-41 - SQS Organization envelope guard/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");

    expect(sourceSection).toContain("Depends on: `M1-04, M1-12`");
    expect(sourceSection).toContain("Prefix SaaS ArtifactStore keys with immutable Organization scope");
    expect(sourceSection).toContain("Organization A cannot read a fixture key created for Organization B through the product store");
    for (const value of [
      "services/platform/artifactstore",
      "buildDriverLocator(domain.Scope, domain.EvidenceRef)",
      "same-session",
      "M1-12 remains the ArtifactStore and provider-compatibility authority",
      "M1-34 remains the separate provider-neutral",
      "M1-41 remains Pending",
    ]) expect(prose).toContain(value);
    expect(plan).toContain("Every behavior and status change has a witnessed tests-only RED first");
    expect(plan.match(/^- \[[ x]\]/gm) ?? []).toHaveLength(17);
  });

  it("starts only M1-40 with exact arithmetic", async () => {
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

    expect(readme).toContain("M1-39 is Complete");
    expect(readme).toContain("M1-40 is In progress");
    expect(tracker).toContain("| Pending | 643 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 81 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`643/1/81/3`");
    expect(m1).toEqual(["M1", "68", "10", "1", "57", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.filter(([task]) => task === "M1-40")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-39")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-41")).toHaveLength(0);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });

  it("documents the inherited provider authority and product-only scope guard", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## S3 Organization artifact prefix[\s\S]*?## Development/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    for (const value of [
      "M1-40 is In progress",
      "scope-mandatory driver locator",
      "Organization A",
      "Organization B",
      "M1-12",
      "M1-34",
      "M1-41 remains Pending",
    ]) expect(prose).toContain(value);
    expect(section).not.toMatch(/raw object key|new provider lifecycle|AWS authorization is proven/i);
  });
});
