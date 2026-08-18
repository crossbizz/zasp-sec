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

describe("M1-17 AuditEmitter contract", () => {
  it("binds the product boundary to the authoritative task and approved design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-17-audit-emitter-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-17-audit-emitter-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-17 - audit emitter contract\*\*[\s\S]*?\*\*M1-18 - feature flag contract/)?.[0];

    expect(section).toContain("Depends on: `M1-16`");
    expect(section).toContain("Define AuditEmitter interface and required mutation fields");
    expect(section).toContain("rejects security mutation without actor/action/target/outcome");
    expect(design).toContain("services/platform/audit");
    expect(design).toContain("succeeded`, `failed`, and `denied");
    expect(plan).toContain("M1-18 remains Pending");
  });

  it("completes only M1-17 and preserves prerequisites and blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-17 is Complete");
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(active).not.toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-16")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-17")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-18")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
  });

  it("exposes only the hermetic root contract and documents deferred persistence", async () => {
    const [packageText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageText) as { scripts: Record<string, string> };
    const section = readme.match(/## AuditEmitter contract[\s\S]*?(?=\n## )/)?.[0] ?? "";

    expect(packageJson.scripts["audit:emitter:test"]).toBe("go test -C services/platform -race -count=1 ./audit");
    expect(section).toContain("npm run audit:emitter:test");
    expect(section).toContain("actor, action, target, and outcome");
    expect(section).toMatch(/Organization, Workspace, and\s+Environment/);
    expect(section).toContain("one-attempt append");
    expect(section).toContain("fixed product errors");
    expect(section).toContain("hermetic fake driver");
    expect(section).toMatch(/does\s+not prove persistence, retention, export, or a generic event envelope/);
    expect(section).toMatch(/M1-18\s+is\s+Complete/);
  });
});
