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

describe("M1-43 tenant quota primitive contract", () => {
  it("binds the source task to exact Organization-scoped workload keys", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-43-tenant-quota-primitive-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-43-tenant-quota-primitive-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-43 - tenant quota primitive\*\*[\s\S]*?\*\*M1-44 - SaaS tenancy foundation check/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");

    expect(sourceSection).toContain("Depends on: `M1-04, M1-07`");
    expect(sourceSection).toContain("Organization-scoped concurrency/quota keys for connectors, graph queries, tests and AI requests");
    expect(sourceSection).toContain("separates counters for two Organizations and rejects an over-limit request predictably");
    for (const value of [
      "services/platform/tenantquota",
      'Connector Kind = "connector"',
      'GraphQuery Kind = "graph_query"',
      'Test Kind = "test"',
      'AIRequest Kind = "ai_request"',
      "same workload quota",
      "ErrQuotaExceeded",
      "does not read process environment",
      "M1-44 remains Pending",
    ]) expect(prose).toContain(value);
    expect(plan).toContain("Every behavior and status change has a witnessed tests-only RED first");
    expect(plan.match(/^- \[[ x]\]/gm) ?? []).toHaveLength(19);
  });

  it("records the completed M1 batch with exact arithmetic", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-43 is Complete");
    expect(tracker).toContain("| Pending | 495 |");
    expect(tracker).toContain("| In progress | 46 |");
    expect(tracker).toContain("| Complete | 184 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`495/46/184/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).toHaveLength(46);
    expect(complete.filter(([task]) => task === "M1-42")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-43")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-44")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("documents the in-process quota boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## Tenant quota primitive[\s\S]*?## Development/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    for (const value of [
      "M1-43 is Complete",
      "connectors, graph queries, tests, and AI requests",
      "same Organization",
      "different Organizations",
      "M1-44 is Complete",
    ]) expect(prose).toContain(value);
    expect(prose).toContain("not a distributed rate limiter, billing meter, or authorization decision");
  });
});
