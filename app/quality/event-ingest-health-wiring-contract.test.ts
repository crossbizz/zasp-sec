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

describe("M1-28c event-ingest health wiring", () => {
  it("binds the exact source task to the standalone design and plan", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-28c-ingest-health-wiring-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-28c-ingest-health-wiring-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-28c - ingest health wiring\*\*[\s\S]*?\*\*M1-28d - gateway health wiring/)?.[0] ?? "";
    const prose = design.replace(/\s+/g, " ");
    const planProse = plan.replace(/^>\s?/gm, "").replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-28b`");
    expect(section).toContain("Wire shared health handlers into event-ingest");
    expect(section).toContain("smoke test distinguishes liveness and readiness");
    for (const value of [
      "`services/event-ingest`",
      "`services/health`",
      "`:8081`",
      "liveness is 200",
      "readiness is 503",
      "five-second graceful shutdown",
      "M1-28d remains Pending",
      "`665/1/59/3`",
    ]) {
      expect(prose).toContain(value);
    }
    expect(planProse).toContain("Every behavior, dependency-policy, documentation, and status transition requires a witnessed");
    expect(planProse).toContain("Do not start M1-28d");
  });

  it("completes only M1-28c after M1-28b and preserves exact blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-28c is Complete");
    expect(readme).toContain("M1-28d is Complete");
    expect(tracker).toContain("| Pending | 650 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 75 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`650/0/75/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "17", "0", "51", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete.filter(([task]) => task === "M1-28b")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-28c")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-28d")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("wires only the exact event-ingest health boundary after witnessed runtime RED", async () => {
    const [command, module, packageJson] = await Promise.all([
      readFile(resolve(repositoryRoot, "services/event-ingest/main.go"), "utf8"),
      readFile(resolve(repositoryRoot, "services/event-ingest/go.mod"), "utf8"),
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
    ]);

    expect(command).toContain("net.Listen");
    expect(command).toContain('healthListenAddress = ":8081"');
    expect(module).toContain("require github.com/zasp-ai/zasp-sec/services/health v0.0.0");
    expect(module).toContain("replace github.com/zasp-ai/zasp-sec/services/health => ../health");
    expect(JSON.parse(packageJson).scripts?.["event-ingest:health:test"]).toBe(
      "go test -C services/event-ingest -race -count=1 ./...",
    );
  });
});
