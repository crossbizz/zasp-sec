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

describe("M1-01f event ingest command repository contract", () => {
  it("binds the source task to the standalone no-I/O ingest design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-01f-event-ingest-command-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-01f-event-ingest-command-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-01f - event ingest command\*\*[\s\S]*?\*\*M1-01a/)?.[0];

    expect(sourceSection).toContain("Depends on: `M1-01e`");
    expect(sourceSection).toContain("Create the event-ingest directory and minimal Go command");
    expect(sourceSection).toContain("Command compiles and prints build version");
    expect(source).toContain("services/platform              Go codebase, two commands");
    expect(source).toContain("services/event-ingest          Go sensor/semantic normalization and SQS batching");
    expect(design).toContain("services/event-ingest/go.mod");
    expect(design).toContain("event-ingest build <version>");
    expect(design).toContain("separate deployable and ownership boundary");
    expect(design).toContain("performs no network, SQS, normalization, or batching");
    expect(plan).toContain("behavior or status change must have a witnessed tests-only RED");
    expect(plan).toContain("M1-01a remains Pending");
  });

  it("completes only M1-01f after the completed worker command", async () => {
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

    expect(readme).toContain("M1-01f is Complete");
    expect(readme).toContain("event-ingest build <version>");
    expect(readme).toContain("does not accept events or start a listener");
    expect(tracker).toContain("| Pending | 679 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 46 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`679/0/46/3`");
    expect(m0).toEqual(["M0", "27", "0", "0", "24", "3"]);
    expect(m1).toEqual(["M1", "68", "46", "0", "22", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete.filter(([task]) => task === "M1-01e")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-01f")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-01a")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });

  it("keeps ingest in its standalone module with only version output", async () => {
    const [goModule, command, commandTest] = await Promise.all([
      readFile(resolve(repositoryRoot, "services/event-ingest/go.mod"), "utf8"),
      readFile(resolve(repositoryRoot, "services/event-ingest/main.go"), "utf8"),
      readFile(resolve(repositoryRoot, "services/event-ingest/main_test.go"), "utf8"),
    ]);

    expect(goModule).toBe("module github.com/zasp-ai/zasp-sec/services/event-ingest\n\ngo 1.25.0\n");
    expect(command).toContain('buildVersion           = "dev"');
    expect(command).toContain('io.WriteString(output, "event-ingest build "+version+"\\n")');
    expect(command).toContain("len(version) > 64");
    expect(command).not.toContain("os.Getenv");
    expect(command).not.toContain('"net/http"');
    expect(command).not.toContain('"flag"');
    expect(command).not.toContain('"time"');
    expect(command).not.toMatch(/sqs|normalize|batch/i);
    expect(commandTest).toContain("TestRunPrintsExactBuildVersion");
    expect(commandTest).toContain("TestRunRejectsInvalidBuildVersionWithoutOutput");
    expect(commandTest).toContain("TestRunReturnsWriterFailure");
  });
});
