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

describe("M1-09 idempotency helper contract", () => {
  it("binds duplicate execution to the approved reliability boundary", async () => {
    const [source, prd, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-09-idempotency-helper-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-09-idempotency-helper-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-09 - idempotency helper\*\*[\s\S]*?\*\*M1-10 - Neon schema baseline/)?.[0];
    const compactDesign = design.replace(/\s+/g, " ");

    expect(sourceSection).toContain("Depends on: `M1-08`");
    expect(sourceSection).toContain("idempotency-key store interface and request helper");
    expect(sourceSection).toContain("Duplicate key returns prior result reference");
    expect(source).toContain("idempotency keys");
    expect(prd).toContain("idempotency keys for mutating/background workflows");
    expect(prd).toContain("no destructive action retry unless idempotent or prior outcome is verified");
    expect(compactDesign).toContain("Within one scope, the same key with a different operation or fingerprint is a conflict, never a duplicate");
    expect(compactDesign).toContain("the claim remains in progress for later explicit reconciliation");
    expect(plan).toContain("Completed duplicates return the prior canonical product result reference");
    expect(plan).toContain("M1-10 remains Pending");
  });

  it("completes only M1-09 after M1-08", async () => {
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

    expect(readme).toContain("M1-08 is Complete");
    expect(readme).toContain("M1-09 is Complete");
    expect(readme).toContain("completed duplicates return the prior");
    expect(readme).toContain("unknown outcomes remain in progress for explicit reconciliation");
    expect(tracker).toContain("| Pending | 643 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 81 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`643/1/81/3`");
    expect(m0).toEqual(["M0", "27", "0", "0", "24", "3"]);
    expect(m1).toEqual(["M1", "68", "10", "1", "57", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual(["M1-40"]);
    expect(complete.filter(([task]) => task === "M1-09")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-08")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-10")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });
});
