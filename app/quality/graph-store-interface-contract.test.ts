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

describe("M1-15 GraphStore interface contract", () => {
  it("binds the product interface to the authoritative task and approved design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-15-graph-store-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-15-graph-store-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-15 - GraphStore interface\*\*[\s\S]*?\*\*M1-16 - Neo4j GraphStore/)?.[0];

    expect(section).toContain("Depends on: `M1-14`");
    expect(section).toContain("product GraphStore interface independent of Neo4j types");
    expect(section).toContain("Fake implementation passes contract tests");
    expect(design).toContain("services/platform/graphstore");
    expect(design).toMatch(/M1-16 remains\s+Pending/);
    expect(plan).toContain("provider-neutral upsert/read contract");
  });

  it("starts only M1-15 and preserves prior completion and blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-15 is In progress");
    expect(readme).toContain("product GraphStore");
    expect(tracker).toContain("| Pending | 680 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 44 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`680/1/44/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "47", "1", "20", "0"]);
    expect(active.filter(([task]) => task === "M1-15")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-14")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-16")).toHaveLength(0);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });
});
