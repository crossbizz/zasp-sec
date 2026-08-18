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

describe("M1-07 configuration loader contract", () => {
  it("binds required and optional dependencies to the approved typed boundary", async () => {
    const [source, prd, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-07-config-loader-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-07-config-loader-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-07 - config loader\*\*[\s\S]*?\*\*M1-08 - external client policy/)?.[0];
    const compactDesign = design.replace(/\s+/g, " ");

    expect(sourceSection).toContain("Depends on: `M1-06`");
    expect(sourceSection).toContain("typed config with required/optional dependency groups and secret references");
    expect(sourceSection).toContain("Missing required config fails start; optional config does not");
    expect(source).toContain("Stytch B2B is the required v1 human identity provider");
    expect(source).toContain("Neon is the required relational Postgres provider");
    expect(source).toContain("PostHog and remote OTLP are optional/non-critical");
    expect(prd).toContain("OpenRouter is unavailable, disabled or disallowed by Organization data policy");
    expect(compactDesign).toContain("stores secret references rather than secret material");
    expect(compactDesign).toContain("An entirely absent optional group produces an absent typed value and does not fail startup");
    expect(plan).toContain("Every behavior and status change has a witnessed tests-only RED first");
    expect(plan).toContain("M1-08 remains Pending");
  });

  it("completes only M1-07 after the loader boundary passes", async () => {
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

    expect(readme).toContain("M1-06 is Complete");
    expect(readme).toContain("M1-07 is Complete");
    expect(readme).toContain("required dependency configuration fails startup");
    expect(readme).toContain("PostHog, OpenRouter, and remote OTLP remain optional");
    expect(tracker).toContain("| Pending | 640 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 84 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`640/1/84/3`");
    expect(m0).toEqual(["M0", "27", "0", "0", "24", "3"]);
    expect(m1).toEqual(["M1", "68", "7", "1", "60", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual(["M1-43"]);
    expect(complete.filter(([task]) => task === "M1-07")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-06")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-08")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });
});
