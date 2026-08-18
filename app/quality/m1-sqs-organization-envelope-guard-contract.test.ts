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

describe("M1-41 SQS Organization envelope guard contract", () => {
  it("binds the source task to the Organization-bound product consumer", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-41-sqs-organization-envelope-guard-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-41-sqs-organization-envelope-guard-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-41 - SQS Organization envelope guard\*\*[\s\S]*?\*\*M1-42 - graph Organization scope guard/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");

    expect(sourceSection).toContain("Depends on: `M1-04, M1-13`");
    expect(sourceSection).toContain("Require Organization scope in background/test/runtime-event queue envelopes");
    expect(sourceSection).toContain("Consumer rejects a message with missing or mismatched Organization scope before side effects");
    for (const value of [
      "services/platform/jobqueue",
      "NewEnvelopeConsumer",
      "background",
      "runtime_events",
      "tests",
      "Organization-B envelope to an Organization-A consumer",
      "M1-13 remains the SQS adapter",
      "M1-33 remains the queue-definition",
      "M1-42 remains Pending",
    ]) expect(prose).toContain(value);
    expect(plan).toContain("Every behavior and status change has a witnessed tests-only RED first");
    expect(plan.match(/^- \[[ x]\]/gm) ?? []).toHaveLength(19);
  });

  it("completes only M1-41 with exact arithmetic", async () => {
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

    expect(readme).toContain("M1-40 is Complete");
    expect(readme).toContain("M1-41 is Complete");
    expect(tracker).toContain("| Pending | 596 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 129 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`596/0/129/3`");
    expect(m1).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete.filter(([task]) => task === "M1-40")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-41")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-41")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-42")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("documents the exact product-only consumer boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## SQS Organization envelope guard[\s\S]*?## Development/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    for (const value of [
      "M1-41 is Complete",
      "background, runtime-event, and test envelopes",
      "before the handler",
      "Organization A",
      "Organization B",
      "M1-13",
      "M1-33",
      "M1-42 is Complete",
    ]) expect(prose).toContain(value);
    expect(section).not.toMatch(/adds a new provider lifecycle|proves real-AWS authorization|acknowledges rejected/i);
  });
});
