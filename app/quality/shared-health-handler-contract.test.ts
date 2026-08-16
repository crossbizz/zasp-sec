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

describe("M1-28a shared health handler", () => {
  it("binds the source task to the reviewed standalone handler design and plan", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-28a-shared-health-handler-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-28a-shared-health-handler-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-28a - shared health handler\*\*[\s\S]*?\*\*M1-28b - platform health wiring/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-27`");
    expect(section).toContain("shared Go health/readiness/version/metrics handler package");
    expect(section).toContain("distinguishes liveness, readiness and version responses");
    for (const requirement of [
      "`services/health`",
      "`/healthz`",
      "`/readyz`",
      "`/version`",
      "`/metrics`",
      "atomic boolean",
      "without opening a listener",
      "`667/0/58/3`",
      "M1-28b remains Pending",
    ]) {
      expect(prose).toContain(requirement);
    }
    expect(plan).toContain("Every behavior or status change requires a witnessed tests-only RED first");
    expect(plan).toContain("M1-28b remains Pending");
  });

  it("completes only M1-28a after reviewed handler evidence and preserves the blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-28a is Complete");
    expect(readme).toContain("M1-28b is Complete");
    expect(readme).toContain("M1-28c is Complete");
    expect(tracker).toContain("| Pending | 662 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 63 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`662/0/63/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "29", "0", "39", "0"]);
    expect(active.filter(([task]) => task === "M1-28a")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-28a")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-27")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-28b")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-28b")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes the exact standalone race-tested health command", async () => {
    const packageJson = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8")) as {
      scripts?: Record<string, string>;
    };

    expect(packageJson.scripts?.["health:test"]).toBe("go test -C services/health -race -count=1 ./...");
  });

  it("documents the exact shared handler boundary without claiming service wiring", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## Shared service health handler[\s\S]*?(?=\n## |$)/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    expect(section).toMatch(/^npm run health:test$/m);
    for (const value of [
      "`/healthz`",
      "`/readyz`",
      "`/version`",
      "`/metrics`",
      "starts not ready",
      "atomic `SetReady`",
      "does not open a listener",
      "does not perform dependency I/O",
      "internal endpoints",
      "M1-28a is Complete",
      "M1-28b is Complete",
      "M1-28c is Complete",
      "M1-28d is Complete",
    ]) {
      expect(prose).toContain(value);
    }
  });
});
