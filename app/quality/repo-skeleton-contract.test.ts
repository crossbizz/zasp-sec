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
    expect(tracker).toContain("| Pending | 675 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 50 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`675/0/50/3`");
    expect(m0).toEqual(["M0", "27", "0", "0", "24", "3"]);
    expect(m1).toEqual(["M1", "68", "42", "0", "26", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete.filter(([task]) => task === "M1-01")).toHaveLength(1);
    for (const child of ["M1-01d", "M1-01e", "M1-01f", "M1-01a", "M1-01b", "M1-01c"]) {
      expect(complete.filter(([task]) => task === child)).toHaveLength(1);
    }
    expect([...active, ...complete].filter(([task]) => task === "M1-02")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
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
      "npm run dependencies:check && npm test && npm run typecheck && npm run lint && npm run build",
    );
    expect(buildSource).toContain('GOTOOLCHAIN: "local"');
    expect(buildSource).toContain('GOPROXY: "off"');
    expect(buildSource).toContain('GOWORK: "off"');
    expect(buildSource).toContain('["-I", "-B", "-u", "workers/security-python/security_worker/__main__.py", "health"]');
    for (const forbidden of ["npm install", "npm ci", "go get", "go install", "pip install", "docker", "kubectl", "aws "]) {
      expect(buildSource).not.toContain(forbidden);
    }
  });
});
