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

describe("M1-01b worker directories repository contract", () => {
  it("binds the source task to independent no-I/O worker packages", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-01b-worker-directories-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-01b-worker-directories-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-01b - worker directories\*\*[\s\S]*?\*\*M1-01c/)?.[0];

    expect(sourceSection).toContain("Depends on: `M1-01a`");
    expect(sourceSection).toContain("Create Python security-worker and Node redteam-worker package skeletons");
    expect(sourceSection).toContain("Each worker starts a no-op health command");
    expect(source).toContain("workers/security-python        Cartography/Prowler adapters");
    expect(source).toContain("workers/redteam-node           Promptfoo adapter");
    expect(design).toContain("workers/security-python/");
    expect(design).toContain("workers/redteam-node/");
    expect(design).toContain("security-worker health ok");
    expect(design).toContain("redteam-worker health ok");
    expect(design).toContain("separate deployables and ownership boundaries");
    expect(plan).toContain("Every behavior or status change has a witnessed tests-only RED");
    expect(plan).toContain("M1-01c remains Pending");
  });

  it("starts only M1-01b after the completed gateway command", async () => {
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

    expect(readme).toContain("M1-01b is In progress");
    expect(readme).toContain("security-worker health ok");
    expect(readme).toContain("redteam-worker health ok");
    expect(readme).toContain("do not start worker loops");
    expect(tracker).toContain("| Pending | 696 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 28 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`696/1/28/3`");
    expect(m0).toEqual(["M0", "27", "0", "0", "24", "3"]);
    expect(m1).toEqual(["M1", "68", "63", "1", "4", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.filter(([task]) => task === "M1-01b")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-01a")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-01c")).toHaveLength(0);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });
});
