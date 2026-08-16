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

describe("M1-02 dependency lock contract", () => {
  it("binds the source task to the approved exact runtime inventory", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-02-dependency-lock-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-02-dependency-lock-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-02 - dependency lock\*\*[\s\S]*?\*\*M1-03 - canonical IDs/)?.[0];
    const compactDesign = design.replace(/\s+/g, " ");

    expect(sourceSection).toContain("Depends on: `M1-01`");
    expect(sourceSection).toContain("Create `build/dependencies.lock.yaml` with exact initial OSS versions/licenses and owners");
    expect(sourceSection).toContain("no unreviewed copyleft/runtime dependency is added");
    expect(compactDesign).toContain("direct dependencies of deployable product manifests");
    expect(compactDesign).toContain("proof harnesses, development/build tools, optional peer");
    for (const dependency of [
      "`drizzle-orm` | `0.45.2` | `Apache-2.0` | `platform-data`",
      "`lucide-react` | `1.31.0` | `ISC` | `web-platform`",
      "`react` | `19.2.6` | `MIT` | `web-platform`",
      "`react-dom` | `19.2.6` | `MIT` | `web-platform`",
      "`stytch` | `14.2.0` | `MIT` | `identity-platform`",
    ]) {
      expect(design).toContain(dependency);
    }
    expect(compactDesign).toContain("prohibited copyleft licenses");
    expect(compactDesign).toContain("runtime entry not explicitly approved");
    expect(plan).toContain("Every behavior or status change has a witnessed tests-only RED");
    expect(plan).toContain("M1-03 remains Pending");
  });

  it("completes only M1-02 after its reviewed lock passes", async () => {
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

    expect(readme).toContain("M1-01 is Complete");
    expect(readme).toContain("M1-02 is Complete");
    expect(readme).toContain("npm run dependencies:check");
    expect(tracker).toContain("| Pending | 687 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 37 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`687/1/37/3`");
    expect(m0).toEqual(["M0", "27", "0", "0", "24", "3"]);
    expect(m1).toEqual(["M1", "68", "54", "1", "13", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-02")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-01")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-03")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });

  it("wires the dependency validator into the existing CI verification path", async () => {
    const [packageText, workflow] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, ".github/workflows/runnable-ui.yml"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageText) as { scripts?: Record<string, string> };

    expect(packageJson.scripts?.["dependencies:check"]).toBe("node scripts/validate-dependencies.mjs");
    expect(packageJson.scripts?.verify).toBe(
      "npm run dependencies:check && npm test && npm run typecheck && npm run lint && npm run build",
    );
    expect(workflow).toContain("run: npm run verify");
    expect(workflow).not.toContain("validate-dependencies.mjs");
  });
});
