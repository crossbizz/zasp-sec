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

describe("M1-37 deployment mode configuration contract", () => {
  it("binds the source task to the strict deployment mode and Organization-pin design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-37-deployment-mode-config-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-37-deployment-mode-config-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-37 - deployment mode config\*\*[\s\S]*?\*\*M1-38 - Neon Organization scope guard/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");

    expect(sourceSection).toContain("Depends on: `M1-07`");
    expect(sourceSection).toContain("Add `saas` and `single_tenant` deployment-mode configuration plus optional pinned Organization ID");
    expect(sourceSection).toContain("SaaS starts without a pinned Organization; single-tenant mode rejects startup without one");
    for (const value of [
      "AGENTSEC_DEPLOYMENT_MODE",
      "AGENTSEC_SINGLE_TENANT_ORGANIZATION_ID",
      "There is no ambient/default mode",
      "`saas` | absent | valid",
      "`saas` | present, including empty | reject",
      "`single_tenant` | canonical product ID | valid",
      "domain.ProductID",
      "M2-49",
      "M1-38 remains Pending",
    ]) expect(prose).toContain(value);
    expect(plan).toContain("Every behavior and status change has a witnessed tests-only RED first");
    expect(plan.match(/^- \[[ x]\]/gm) ?? []).toHaveLength(16);
  });

  it("moves only M1-37 to Complete with exact arithmetic", async () => {
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

    expect(readme).toContain("M1-36e is Complete");
    expect(readme).toContain("M1-37 is Complete");
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(m1).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).not.toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-36e")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-37")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-38")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-39")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });

  it("documents only the typed startup boundary and deferred authorization guard", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## Deployment mode configuration[\s\S]*?## Development/)?.[0] ?? "";

    for (const value of [
      "M1-37 is Complete",
      "AGENTSEC_DEPLOYMENT_MODE",
      "AGENTSEC_SINGLE_TENANT_ORGANIZATION_ID",
      "saas",
      "single_tenant",
      "canonical product Organization ID",
      "M2-49",
      "M1-38 is Complete",
    ]) expect(section).toContain(value);
    expect(section).not.toMatch(/reads secret material|separate product fork|enforces authenticated Organization/i);
  });
});
