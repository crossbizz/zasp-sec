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

describe("M1-01d platform API command repository contract", () => {
  it("binds the source task to the minimal no-I/O command design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-01d-platform-api-command-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-01d-platform-api-command-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-01d - platform API command\*\*[\s\S]*?\*\*M1-01e/)?.[0];

    expect(sourceSection).toContain("Depends on: `M0-23`");
    expect(sourceSection).toContain("Create the platform API directory and minimal Go command");
    expect(sourceSection).toContain("Command compiles and prints build version");
    expect(design).toContain("services/platform/agentsec-api/main.go");
    expect(design).toContain("agentsec-api build <version>");
    expect(design).toContain("no environment variable");
    expect(design).toContain("opens no listener");
    expect(plan).toContain("behavior or status change must have a witnessed tests-only RED");
    expect(plan).toContain("M1-01e remains Pending");
  });

  it("completes only M1-01d after the completed M0 gate", async () => {
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

    expect(readme).toContain("M1-01d is Complete");
    expect(readme).toContain("agentsec-api build <version>");
    expect(readme).toContain("does not start an HTTP server");
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(m0).toEqual(["M0", "27", "0", "0", "24", "3"]);
    expect(m1).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).not.toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-01d")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M0-23")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-01e")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-01f")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });

  it("keeps the command in the service-local module with only version output", async () => {
    const [goModule, command, commandTest] = await Promise.all([
      readFile(resolve(repositoryRoot, "services/platform/go.mod"), "utf8"),
      readFile(resolve(repositoryRoot, "services/platform/agentsec-api/main.go"), "utf8"),
      readFile(resolve(repositoryRoot, "services/platform/agentsec-api/main_test.go"), "utf8"),
    ]);

    expect(goModule).toMatch(/^module github\.com\/zasp-ai\/zasp-sec\/services\/platform\n\ngo 1\.25\.0\n/);
    expect(command).toContain('buildVersion           = "dev"');
    expect(command).toContain('io.WriteString(output, "agentsec-api build "+version+"\\n")');
    expect(command).toContain("len(version) > 64");
    expect(command).not.toContain("os.Getenv");
    expect(command).not.toContain('"net/http"');
    expect(command).not.toContain('"flag"');
    expect(commandTest).toContain("TestRunPrintsExactBuildVersion");
    expect(commandTest).toContain("TestRunRejectsInvalidBuildVersionWithoutOutput");
    expect(commandTest).toContain("TestRunReturnsWriterFailure");
  });
});
