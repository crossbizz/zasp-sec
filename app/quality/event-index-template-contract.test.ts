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

describe("M1-32 OpenSearch index template", () => {
  it("binds the exact source task to the strict selected design", async () => {
    const [source, design, implementationPlan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-17-m1-32-opensearch-index-template-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-17-m1-32-opensearch-index-template-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-32 - OpenSearch index template\*\*[\s\S]*?\*\*M1-33 - SQS queue definitions/)?.[0] ?? "";
    const designProse = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-31`");
    expect(section).toContain("Deliverable: Create scoped session/runtime event index template with bounded keyword fields.");
    expect(section).toContain("Verify: Template rejects dynamic mapping explosion fixture.");
    expect(section).toContain("Timebox: <=15 minutes.");
    for (const value of [
      "services/platform/eventindex",
      "zasp-session-runtime-events-v1-*",
      "index.mapping.total_fields.limit",
      "dynamic: strict",
      "exactly the 12 properties",
      "1,024 unique attacker-controlled names",
      "M1-39 remains responsible",
      "M1-33 Pending",
    ]) {
      expect(designProse).toContain(value);
    }
    expect(implementationPlan).toContain("Use genuine tests-first RED/GREEN");
  });

  it("completes only M1-32 while preserving M1-31, M1-33, and exact blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-32 is Complete");
    expect(tracker).toContain("| Pending | 652 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 73 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`652/0/73/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "19", "0", "49", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete).toHaveLength(73);
    expect(active.filter(([task]) => task === "M1-32")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-32")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-31")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-33")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-33")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes one exact hermetic root test command without a provider run command", async () => {
    const packageDocument = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8")) as {
      scripts: Record<string, string>;
    };
    expect(packageDocument.scripts["event:index-template:test"]).toBe(
      "go test -C services/platform -race -count=1 ./eventindex",
    );
    expect(Object.keys(packageDocument.scripts).filter((name) => name.startsWith("event:index-template:"))).toEqual([
      "event:index-template:test",
    ]);
  });

  it("documents the exact product-owned template boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = (readme.match(/## OpenSearch session\/runtime event template[\s\S]*?(?=\n## )/)?.[0] ?? "").replace(
      /\s+/g,
      " ",
    );
    for (const value of [
      "npm run event:index-template:test",
      "zasp-session-runtime-events-v1-*",
      "exactly 12 fields",
      "index.mapping.total_fields.limit=12",
      "dynamic: strict",
      "ignore_above",
      "1,024-field mapping-explosion fixture",
      "does not apply the template",
      "does not claim OpenSearch or LocalStack parity",
      "M1-31 is Complete",
      "M1-39 owns cross-Organization query and indexing enforcement",
      "M1-33 is Complete",
    ]) {
      expect(section).toContain(value);
    }
  });
});
