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

describe("M1-03 canonical ID contract", () => {
  it("binds the source task to the approved product and external identity boundary", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-03-canonical-id-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-03-canonical-id-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-03 - canonical IDs\*\*[\s\S]*?\*\*M1-04 - scope model/)?.[0];
    const compactDesign = design.replace(/\s+/g, " ");

    expect(sourceSection).toContain("Depends on: `M1-02`");
    expect(sourceSection).toContain("Define product UUID/ID wrappers and external-source reference type");
    expect(sourceSection).toContain("prevents external vendor ID from becoming product primary key");
    expect(design).toContain("`ProductID` is an opaque product-owned UUIDv4 wrapper");
    expect(design).toContain("`pid_<canonical-uuid>`");
    expect(design).toContain("`ProductID` and `ExternalID` have different concrete types and storage");
    expect(compactDesign).toContain("Product IDs are never derived, hashed, normalized, or copied from an `ExternalSourceRef`");
    expect(plan).toContain("Every behavior and status change has a witnessed tests-only RED first");
    expect(plan).toContain("M1-04 remains Pending");
  });

  it("completes only M1-03 after the identity boundary passes", async () => {
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

    expect(readme).toContain("M1-02 is Complete");
    expect(readme).toContain("M1-03 is Complete");
    expect(readme).toContain("pid_<canonical-uuid>");
    expect(tracker).toContain("| Pending | 682 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 43 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`682/0/43/3`");
    expect(m0).toEqual(["M0", "27", "0", "0", "24", "3"]);
    expect(m1).toEqual(["M1", "68", "49", "0", "19", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete.filter(([task]) => task === "M1-03")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-02")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-04")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });
});
