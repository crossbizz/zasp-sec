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

describe("M1-29 system health aggregator", () => {
  it("binds the exact source task to the strict shared-module design and plan", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-29-system-health-aggregator-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-29-system-health-aggregator-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-29 - system health aggregator model\*\*[\s\S]*?\*\*M1-30a/)?.[0] ?? "";
    const designProse = design.replace(/\s+/g, " ");
    const planProse = plan.replace(/^>\s?/gm, "").replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-28`");
    expect(section).toContain("Define component status Healthy/Degraded/Unavailable with reason and last success");
    expect(section).toContain("Aggregation test handles required vs optional dependencies");
    for (const value of [
      "`services/health`",
      "`Component`",
      "func Aggregate(components []Component) (Status, error)",
      "required Unavailable component makes the system Unavailable",
      "optional Unavailable component makes the system Degraded",
      "M1-30a remains Pending",
      "`662/1/62/3`",
      "`68/29/1/38/0`",
    ]) {
      expect(designProse).toContain(value);
    }
    expect(planProse).toContain("Every behavior or status change requires a witnessed tests-only RED first");
    expect(planProse).toContain("Perform no file, environment, clock, provider, credential, subprocess, database, Docker, or network I/O");
  });

  it("completes M1-29 after M1-28 and preserves exact blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-29 is Complete");
    expect(readme).toContain("M1-30a is Complete");
    expect(readme).toContain("M1-30b is Complete");
    expect(tracker).toContain("| Pending | 541 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 184 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`541/0/184/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.filter(([task]) => task === "M1-29")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-29")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-28")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-30a")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-30a")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("documents the exact implemented value and aggregation boundary", async () => {
    const [source, packageJsonText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "services/health/aggregate.go"), "utf8"),
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageJsonText) as { scripts?: Record<string, string> };
    const section = readme.match(/## System health aggregation model[\s\S]*?## Platform health wiring/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");
    const sourceProse = source.replace(/\s+/g, " ");

    for (const value of [
      'StatusHealthy Status = "healthy"',
      'StatusDegraded Status = "degraded"',
      'StatusUnavailable Status = "unavailable"',
      'RequirementRequired Requirement = "required"',
      'RequirementOptional Requirement = "optional"',
      "func NewComponent(",
      "func (component Component) Validate() error",
      "func Aggregate(components []Component) (Status, error)",
    ]) {
      expect(sourceProse).toContain(value);
    }
    expect(packageJson.scripts?.["health:contract:test"]).toBe(
      "node --test openapi/internal-health.test.mjs && go test -C services/health -race -count=1 ./... && go test -C services/platform -race -count=1 ./healthserver ./agentsec-api ./agentsec-worker && go test -C services/event-ingest -race -count=1 ./... && go test -C services/runtime-gateway -race -count=1 ./...",
    );
    for (const value of [
      "M1-29 is Complete",
      "Healthy, Degraded, and Unavailable",
      "required Unavailable component makes the aggregate Unavailable",
      "optional Unavailable component makes it Degraded",
      "product-owned reason code",
      "canonical UTC millisecond last-success",
      "does not change process readiness",
      "npm run health:contract:test",
      "M1-30a is Complete",
      "M1-30b is Complete",
    ]) {
      expect(prose).toContain(value);
    }
    expect(prose).toContain("does not poll dependencies");
    expect(prose).not.toMatch(/provider response|raw error|credential|customer data/i);
  });
});
