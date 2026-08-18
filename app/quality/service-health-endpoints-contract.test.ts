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

describe("M1-28 common service health endpoints", () => {
  it("binds the exact source task to the separate internal OpenAPI design and plan", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-28-service-health-endpoints-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-28-service-health-endpoints-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-28 - service health endpoints\*\*[\s\S]*?\*\*M1-29/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");
    const planProse = plan.replace(/^>\s?/gm, "").replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-28d`");
    expect(section).toContain("Register common health endpoint contract in OpenAPI/internal service docs");
    expect(section).toContain("All Go commands expose the same endpoint semantics");
    for (const value of [
      "`openapi/internal-health.yaml`",
      "`docs/internal/service-health-endpoints.md`",
      "`health:contract:test`",
      "M1-29 remains Pending",
      "`663/1/61/3`",
      "`68/30/1/37/0`",
    ]) {
      expect(prose).toContain(value);
    }
    expect(planProse).toContain("Every contract, documentation, command, and status transition requires a witnessed tests-only RED");
    expect(planProse).toContain("Do not start M1-29");
  });

  it("completes only M1-28 after M1-28d and preserves exact blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const readmeProse = readme.replace(/\s+/g, " ");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-28 is Complete");
    expect(readme).toContain("M1-29 is Complete");
    expect(readmeProse).toContain("Health listeners for those worker packages remain outside M1-28 and are not yet implemented.");
    expect(readmeProse).not.toContain("Shared liveness and readiness endpoints remain deferred to M1-28.");
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).not.toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-28d")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-28")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-29")).toHaveLength(0);
    expect(blocked.map(([task]) => task)).toEqual(["M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
  });
});
