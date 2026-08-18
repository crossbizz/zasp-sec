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

describe("M1-36a clean-checkout build check", () => {
  it("binds the exact source task, selected design, and eight-target build", async () => {
    const [source, design, plan, buildSource] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-36a-m1-build-check-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-36a-m1-build-check-implementation-plan.md"), "utf8"),
      readFile(resolve(repositoryRoot, "scripts/build-repo.mjs"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-36a - M1 build check\*\*[\s\S]*?\*\*M1-36b - M1 schema check/)?.[0] ?? "";
    const designProse = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-35`");
    expect(section).toContain("Deliverable: Run clean-checkout service, worker, web and CLI build checks.");
    expect(section).toContain("Verify: All build targets succeed.");
    expect(section).toContain("Timebox: <=15 minutes.");
    for (const target of [
      "services/platform/agentsec-api",
      "services/platform/agentsec-worker",
      "services/event-ingest",
      "services/runtime-gateway",
      "workers/security-python",
      "workers/redteam-node",
      "apps/web",
      "cmd/agentsecctl",
    ]) {
      expect(design).toContain(target);
    }
    for (const boundary of [
      "detached local clone",
      "Node.js 22.23.1",
      "npm 10.9.8",
      "Go 1.25.6",
      "Python 3.13",
      "NPM_CONFIG_USERCONFIG",
      "Repository build passed: targets=8",
      "M1-36b remains Pending",
    ]) {
      expect(designProse).toContain(boundary);
    }
    expect(plan).toContain("Use genuine tests-first RED/GREEN");
    expect(buildSource).toContain('export const successLine = "Repository build passed: targets=8\\n"');
    expect(buildSource).toContain("return targets.length");
  });

  it("completes only M1-36a after M1-35 while preserving M1-36b and exact blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme.replace(/\s+/g, " ")).toContain("M1-36a is Complete");
    expect(tracker).toContain("| Pending | 646 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 79 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`646/0/79/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "13", "0", "55", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete).toHaveLength(79);
    expect(complete.filter(([task]) => task === "M1-35")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-36a")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-36a")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-36b")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("reuses one exact build command and documents only the build gate", async () => {
    const [packageText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageText) as { scripts: Record<string, string> };
    const section = readme.match(/## M1 build check[\s\S]*?(?=\n## )/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    expect(packageJson.scripts["build:repo"]).toBe("node scripts/build-repo.mjs");
    expect(Object.keys(packageJson.scripts).filter((name) => /m1.*build|build.*check/i.test(name))).toEqual([]);
    expect(section).toContain("npm run build:repo");
    expect(prose).toContain("clean checkout");
    expect(prose).toContain("all eight targets");
    expect(prose).toContain("M1-36b is Complete");
    expect(prose).not.toMatch(/schema validation passed|OpenAPI drift passed|UI\/API coverage passed|local infrastructure healthy/i);
  });
});
