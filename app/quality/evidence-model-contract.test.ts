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

describe("M1-05 evidence model contract", () => {
  it("binds the canonical source vocabularies to the approved typed model", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-05-evidence-model-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-05-evidence-model-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-05 - evidence model\*\*[\s\S]*?\*\*M1-06 - product error envelope/)?.[0];
    const evidenceSection = source.match(/### Evidence confidence[\s\S]*?### Capability\/path state/)?.[0];
    const stateSection = source.match(/### Capability\/path state[\s\S]*?Do not conflate/)?.[0];
    const compactDesign = design.replace(/\s+/g, " ");

    expect(sourceSection).toContain("Depends on: `M1-04`");
    expect(sourceSection).toContain("Define EvidenceRef, confidence and capability/path state enums");
    expect(sourceSection).toContain("confidence is distinct from severity");
    for (const value of ["exact", "strong", "probable", "unattributed"]) {
      expect(evidenceSection).toContain(`- ${value}`);
    }
    for (const value of ["configured", "reachable", "observed", "verified", "blocked"]) {
      expect(stateSection).toContain(`- ${value}`);
    }
    expect(compactDesign).toContain("A reference alone grants no access");
    expect(compactDesign).toContain("finding-severity value are invalid");
    expect(plan).toContain("Every behavior and status change has a witnessed tests-only RED first");
    expect(plan).toContain("M1-06 remains Pending");
  });

  it("completes only M1-05 after the evidence boundary passes", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);
    const m0 = milestones.find(([milestone]) => milestone === "M0");
    const m1 = milestones.find(([milestone]) => milestone === "M1");

    expect(readme).toContain("M1-04 is Complete");
    expect(readme).toContain("M1-05 is Complete");
    expect(readme).toContain("evidence confidence");
    expect(tracker).toContain("| Pending | 656 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 68 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`656/1/68/3`");
    expect(m0).toEqual(["M0", "27", "0", "0", "24", "3"]);
    expect(m1).toEqual(["M1", "68", "23", "1", "44", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual(["M1-31"]);
    expect(complete.filter(([task]) => task === "M1-05")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-04")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-06")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });
});
