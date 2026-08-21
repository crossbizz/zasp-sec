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

describe("M1-01 repository skeleton contract", () => {
  it("binds the source task to the exact completed target inventory", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-01-repo-skeleton-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-01-repo-skeleton-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-01 - repo skeleton\*\*[\s\S]*?\*\*M1-02 - dependency lock/)?.[0];

    expect(sourceSection).toContain("Depends on: `M1-01c`");
    expect(sourceSection).toContain("Add root build commands that invoke the already-created service, worker, web and CLI targets");
    expect(sourceSection).toContain("One root build command succeeds without downloading unpinned runtime dependencies");
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
    expect(design).toContain("GOTOOLCHAIN=local");
    expect(design).toContain("GOPROXY=off");
    expect(design).toContain("Repository build passed: targets=8");
    expect(plan).toContain("Every behavior or status change has a witnessed tests-only RED");
    expect(plan).toContain("M1-02 remains Pending");
  });

  it("completes only M1-01 after all six child tasks complete", async () => {
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
    expect(readme).toContain("npm run build:repo");
    expect(readme).toContain("does not install or download dependencies");
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(m0).toEqual(["M0", "27", "0", "0", "24", "3"]);
    expect(m1).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-01")).toHaveLength(1);
    for (const child of ["M1-01d", "M1-01e", "M1-01f", "M1-01a", "M1-01b", "M1-01c"]) {
      expect(complete.filter(([task]) => task === child)).toHaveLength(1);
    }
    expect([...active, ...complete].filter(([task]) => task === "M1-02")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M1A-10", "M1A-09", "M1A-08", "M1A-07", "M3-52", "M3-14", "M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });

  it("wires one dependency-free root command without changing Runnable UI verification", async () => {
    const [packageText, buildSource] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "scripts/build-repo.mjs"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageText) as { scripts?: Record<string, string> };

    expect(packageJson.scripts?.["build:repo"]).toBe("node scripts/build-repo.mjs");
    expect(packageJson.scripts?.verify).toBe(
      "npm run dependencies:check && npm run health:contract:test && npm run openapi:test && npm run openapi:lint && npm run openapi:check && npm run ui-api:test && npm run ui-api:check && npm run raw-fetch:test && npm run saas:tenancy:test && npm run db:tenant-rls:test && npm test && npm run typecheck && npm run lint && npm run production:imports:test && npm run production:imports:source && npm run production:release:test && npm run build && npm run production:imports:compiled && npm run implementation:status:check",
    );
    expect(buildSource).toContain('GOTOOLCHAIN: "local"');
    expect(buildSource).toContain('GOPROXY: "off"');
    expect(buildSource).toContain('GOWORK: "off"');
    expect(buildSource).toContain('["-B", "-u", "-m", "security_worker", "health"]');
    expect(buildSource).toContain('PYTHONPATH: resolve(repositoryRoot, "workers/security-python")');
    for (const forbidden of ["npm install", "npm ci", "go get", "go install", "pip install", "docker", "kubectl", "aws "]) {
      expect(buildSource).not.toContain(forbidden);
    }
  });
});
