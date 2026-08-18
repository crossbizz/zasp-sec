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

describe("M1-28b platform health wiring", () => {
  it("binds the exact source task to the bounded two-command design and plan", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-28b-platform-health-wiring-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-28b-platform-health-wiring-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-28b - platform health wiring\*\*[\s\S]*?\*\*M1-28c - ingest health wiring/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");
    const planProse = plan.replace(/\n>\s*/g, " ").replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-28a`");
    expect(section).toContain("platform API and worker commands");
    expect(section).toContain("Both commands expose health/readiness/version/metrics endpoints");
    for (const requirement of [
      "`services/platform/healthserver`",
      "`agentsec-api`",
      "`agentsec-worker`",
      "`:8081`",
      "`/healthz`",
      "`/readyz`",
      "`/version`",
      "`/metrics`",
      "five-second graceful-shutdown budget",
      "M1-28c remains Pending",
    ]) {
      expect(prose).toContain(requirement);
    }
    expect(planProse).toContain("Every behavior, dependency-policy, documentation, and status transition requires a witnessed");
    expect(plan).toContain("M1-28c remains Pending");
  });

  it("completes only M1-28b after M1-28a and preserves exact blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-28b is Complete");
    expect(readme).toContain("M1-28c is Complete");
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).not.toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-28a")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-28b")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-28c")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-28c")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
  });

  it("wires both commands to the exact shared runtime without a third-party dependency", async () => {
    const [api, worker, platformModule, packageJson] = await Promise.all([
      readFile(resolve(repositoryRoot, "services/platform/agentsec-api/main.go"), "utf8"),
      readFile(resolve(repositoryRoot, "services/platform/agentsec-worker/main.go"), "utf8"),
      readFile(resolve(repositoryRoot, "services/platform/go.mod"), "utf8"),
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
    ]);

    for (const command of [api, worker]) {
      expect(command).toContain('"github.com/zasp-ai/zasp-sec/services/platform/healthserver"');
      expect(command).toContain('healthListenAddress = ":8081"');
      expect(command).toContain("signal.NotifyContext");
      expect(command).not.toContain('"net/http"');
    }
    expect(platformModule).toContain("github.com/zasp-ai/zasp-sec/services/health v0.0.0");
    expect(platformModule).toContain("replace github.com/zasp-ai/zasp-sec/services/health => ../health");
    expect(JSON.parse(packageJson).scripts?.["platform:health:test"]).toBe(
      "go test -C services/platform -race -count=1 ./healthserver ./agentsec-api ./agentsec-worker",
    );
  });

  it("documents the exact internal listener and deferred-service boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## Platform health wiring[\s\S]*?(?=\n## |$)/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    expect(section).toMatch(/^npm run platform:health:test$/m);
    for (const value of [
      "platform API and worker",
      "internal `:8081` listener",
      "`/healthz`",
      "`/readyz`",
      "`/version`",
      "`/metrics`",
      "five-second graceful shutdown",
      "default mux",
      "M1-28b is Complete",
      "M1-28c is Complete",
      "M1-28d is Complete",
    ]) {
      expect(prose).toContain(value);
    }
  });
});
