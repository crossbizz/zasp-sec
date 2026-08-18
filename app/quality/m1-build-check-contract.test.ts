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
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).not.toHaveLength(0);
    expect(complete.length).toBeGreaterThan(0);
    expect(complete.filter(([task]) => task === "M1-35")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-36a")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-36a")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-36b")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
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
