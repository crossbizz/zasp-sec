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

describe("M1-26 UI API coverage CI", () => {
  it("binds the source task to the closed coverage design and plan", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-26-ui-api-coverage-ci-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-26-ui-api-coverage-ci-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-26 - UI API coverage CI\*\*[\s\S]*?\*\*M1-27 - raw fetch lint/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-25`");
    expect(section).toContain("fails for missing mapped operation");
    expect(section).toContain("interactive public operation without a screen mapping");
    expect(section).toContain("Deliberately removing one op makes test fail");
    for (const requirement of [
      "`planned`",
      "`available`",
      "`/api/v1`",
      "`/internal/v1`",
      "UI/API coverage rejected.",
      "M1-27 remains Pending",
    ]) {
      expect(prose).toContain(requirement);
    }
    expect(plan).toContain("Every behavior or status change has a witnessed tests-only RED");
    expect(plan).toContain("M1-27 remains Pending");
  });

  it("completes only M1-26 after M1-25 and preserves the blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-26 is Complete");
    expect(tracker).toContain("| Pending | 651 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 74 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`651/0/74/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "18", "0", "50", "0"]);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete.filter(([task]) => task === "M1-25")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-26")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-27")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-27")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("preserves the exact M1-25 seed as five planned forward references", async () => {
    const map = await readFile(resolve(repositoryRoot, "docs/product/ui-api-map.yaml"), "utf8");
    expect(map.match(/availability: planned/g)).toHaveLength(5);
    expect(map).not.toContain("availability: available");
    expect(map).not.toMatch(/^\s*(?:route|path|method|server):/m);
  });

  it("documents the exact local coverage commands and honest current result", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## UI-to-API map seed[\s\S]*?## Neon pooled proof/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    expect(section).toContain("npm run ui-api:test");
    expect(section).toContain("npm run ui-api:check");
    expect(section).toContain("UI/API coverage passed: planned=5 available=0 public=0 internal=0.");
    expect(section).toContain("UI/API coverage rejected.");
    expect(prose).toContain("`planned` operation must remain absent");
    expect(prose).toContain("`available` operation must exist exactly once under `/api/v1`");
    expect(prose).toContain("`/internal/v1` operations must remain unmapped");
    expect(prose).toContain("M1-26 is Complete");
    expect(prose).toContain("M1-27 is Complete");
    expect(prose).toContain("M1-28a is Complete");
    expect(prose).toContain("M1-28b is Complete");
    expect(prose).toContain("M1-28c is Complete");
    expect(prose).toContain("M1-28d is Complete");
  });
});
