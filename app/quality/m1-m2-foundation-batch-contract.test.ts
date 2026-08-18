import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");

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

const completedBatch = [
  "M1-36", "M1-43", "M1-44", "M1-45a", "M1-45b", "M1-45c", "M1-45d", "M1-45",
  "M2-01", "M2-02", "M2-02a", "M2-03", "M2-04", "M2-05a", "M2-05b", "M2-05",
  "M2-06", "M2-07", "M2-07a", "M2-07b", "M2-07c", "M2-07d",
];

describe("M1 tenancy and M2 identity foundation batch", () => {
  it("binds every completed M2 identity task to the source plan", async () => {
    const source = await readFile(
      resolve(root, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const section = source.match(/\*\*M2-01 - Stytch adapter\*\*[\s\S]*?\*\*M2-08 - API getOrganization/)?.[0] ?? "";
    for (const task of completedBatch.filter((task) => task.startsWith("M2-"))) {
      expect(section).toContain(`**${task} -`);
    }
    expect(section).toContain("without leaking Stytch SDK types");
    expect(section).toContain("Stytch outage fails the guarded mutation closed");
    expect(section).toContain("no customer-facing bypass login");
  });

  it("records all 22 tasks once with exact batch arithmetic", async () => {
    const tracker = await readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(milestones.find(([milestone]) => milestone === "M2")).toEqual(["M2", "72", "0", "0", "72", "0"]);
    expect(active).not.toHaveLength(0);
    for (const task of completedBatch) {
      expect(complete.filter(([candidate]) => candidate === task)).toHaveLength(1);
    }
    expect(complete.length).toBeGreaterThan(0);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("documents the batch boundary without advancing the next task", async () => {
    const readme = await readFile(resolve(root, "README.md"), "utf8");
    expect(readme).toContain("M1-36 is PASS");
    expect(readme).toContain("M1-45a through M1-45d and the M1-45 gate are Complete");
    expect(readme).toContain("M2-01 through M2-07d are Complete");
    expect(readme).toContain("M2-01 through M2-50 and the M2-47 gate are Complete");
    expect(readme).toContain("no local password or customer-facing bypass login");
  });
});
