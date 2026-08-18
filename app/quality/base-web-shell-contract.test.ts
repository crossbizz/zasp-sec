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

describe("M1-35 base web shell", () => {
  it("binds the exact source task to the selected closed design", async () => {
    const [source, design, implementationPlan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-35-base-web-shell-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-35-base-web-shell-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-35 - base web shell\*\*[\s\S]*?\*\*M1-36a - M1 build check/)?.[0] ?? "";
    const designProse = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-34`");
    expect(section).toContain("Deliverable: Create product shell, unauthenticated-route guard scaffold and left-nav component from PRD IA.");
    expect(section).toContain("Verify: Route smoke test renders all MVP nav labels, no OSS labels.");
    expect(section).toContain("Timebox: <=15 minutes.");
    for (const value of [
      "app/components/LeftNav.tsx",
      "UnauthenticatedRouteGuard",
      "exact nine groups, 22 labels",
      "Overview",
      "Tools & MCP",
      "Attack Paths",
      "Security Agents",
      "External Data Flows",
      "API Access",
      "Cartography",
      "Prowler",
      "LocalStack",
      "public route catalog contains only exact `/sign-in`",
      "M2-01 and M2-02",
      "does not import Stytch",
      "M1-36a remains Pending",
    ]) {
      expect(designProse).toContain(value);
    }
    expect(implementationPlan).toContain("Use genuine tests-first RED/GREEN");
  });

  it("completes only M1-35 while preserving M1-34, M1-36a, and exact blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme.replace(/\s+/g, " ")).toContain("M1-35 is Complete");
    expect(tracker).toContain("| Pending | 648 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 77 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`648/0/77/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "15", "0", "53", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).toHaveLength(0);
    expect(complete).toHaveLength(77);
    expect(active.filter(([task]) => task === "M1-35")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-35")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-34")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-36a")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes one hermetic shell command and the bounded product documentation", async () => {
    const [packageText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageText) as { scripts: Record<string, string> };
    const command = "vitest run app/domain/routes.test.ts app/domain/route-guard.test.ts app/components/LeftNav.test.tsx app/components/UnauthenticatedRouteGuard.test.tsx app/components/ZaspApp.test.tsx";
    const section = readme.match(/## Base web shell[\s\S]*?## Development/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    expect(packageJson.scripts["web:shell:test"]).toBe(command);
    expect(Object.values(packageJson.scripts).filter((value) => value === command)).toHaveLength(1);
    expect(section).toContain("npm run web:shell:test");
    expect(prose).toContain("exactly 22 product labels in nine groups");
    for (const row of [
      "| Home | Overview |",
      "| Inventory | Agents; Tools & MCP; Identities; Runtimes |",
      "| Exposure | Findings; Attack Paths |",
      "| Test | Red Team; Attack Lab |",
      "| Protect | Policies; Security Agents; Approvals |",
      "| Investigate | Sessions |",
      "| Compliance | Evidence |",
      "| Integrations | Connections; Sensors |",
      "| Administration | Identity & Access; Audit Log; Data & Retention; External Data Flows; System Health; API Access |",
    ]) expect(section).toContain(row);
    expect(prose).toContain("No OSS or provider implementation label appears in the product navigation.");
    expect(prose).toContain("The unauthenticated-route guard is an inert scaffold");
    expect(prose).toContain("M2-01 and M2-02 own real authentication and session enforcement");
    expect(prose).toContain("browser-local demonstration data");
    expect(section).not.toMatch(/Cartography|Prowler|Nango|Promptfoo|Neo4j|Tetragon|OpenTelemetry|LocalStack|Stytch/i);
  });
});
