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

function taskRows(tracker: string, heading: "In progress" | "Complete") {
  const end = heading === "In progress" ? "Complete" : "Blocked";
  const body = tracker.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "";
  return markdownRows(body).slice(2);
}

describe("M0 technical proof gate repository contract", () => {
  it("binds the source gate to the evidence-only blocked-path design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-23-gate-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-23-gate-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M0-23 - M0 gate\*\*[\s\S]*?### M1 -/)?.[0];

    expect(sourceSection).toContain("Depends on: `M0-22`");
    expect(sourceSection).toContain("Record pass/fail and resulting architecture decision for every proof");
    expect(sourceSection).toContain("No unresolved proof is marked passed and blockers are explicit");
    expect(design).toContain("PROCEED WITH BLOCKED PATHS");
    expect(design).toContain("R-03 continues to block real-AWS IAM parity");
    expect(design).toContain("R-11 continues to block EKS Fargate strong-");
    expect(plan).toContain("Every behavior or status change follows a witnessed tests-only RED");
  });

  it("starts only M0-23 and leaves M1 pending", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const summary = markdownRows(
      tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "",
    ).slice(2);
    const m0 = markdownRows(
      tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "",
    ).find(([milestone]) => milestone === "M0");

    expect(readme).toContain("M0-23 is In progress");
    expect(readme).toContain("PROCEED WITH BLOCKED PATHS");
    expect(tracker).toContain("| Pending | 701 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 23 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`701/1/23/3`");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 1 \| 23 \| 3 \|/);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(m0?.slice(2).reduce((sum, count) => sum + Number(count), 0)).toBe(Number(m0?.[1]));
    expect(active.filter(([task]) => task === "M0-23")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-01d")).toHaveLength(0);
    expect(tracker).toContain("M0-09");
    expect(tracker).toContain("M0-18");
    expect(tracker).toContain("M0-19");
  });
});
