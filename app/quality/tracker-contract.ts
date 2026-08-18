import { expect } from "vitest";

function rows(markdown: string) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function taskRows(tracker: string, heading: "In progress" | "Complete" | "Blocked") {
  const end = heading === "In progress" ? "Complete" : heading === "Complete" ? "Blocked" : "Review findings";
  return rows(tracker.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "").slice(2);
}

export function expectValidTrackerSnapshot(tracker: string) {
  const summary = new Map(rows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2).map(([status, count]) => [status, Number(count)]));
  const active = taskRows(tracker, "In progress");
  const complete = taskRows(tracker, "Complete");
  const blocked = taskRows(tracker, "Blocked");
  const taskIDs = [...active, ...complete, ...blocked].map(([task]) => task);
  const milestones = rows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

  expect([...summary.keys()]).toEqual(["Pending", "In progress", "Complete", "Blocked"]);
  expect(summary.get("In progress")).toBe(active.length);
  expect(summary.get("Complete")).toBe(complete.length);
  expect(summary.get("Blocked")).toBe(blocked.length);
  expect(summary.get("Pending")).toBe(728 - taskIDs.length);
  expect([...summary.values()].reduce((sum, count) => sum + count, 0)).toBe(728);
  expect(new Set(taskIDs).size).toBe(taskIDs.length);
  expect(milestones.reduce((sum, row) => sum + Number(row[1]), 0)).toBe(728);
  expect(milestones.reduce((sum, row) => sum + Number(row[2]), 0)).toBe(summary.get("Pending"));
  expect(milestones.reduce((sum, row) => sum + Number(row[3]), 0)).toBe(summary.get("In progress"));
  expect(milestones.reduce((sum, row) => sum + Number(row[4]), 0)).toBe(summary.get("Complete"));
  expect(milestones.reduce((sum, row) => sum + Number(row[5]), 0)).toBe(summary.get("Blocked"));
  expect(tracker).toContain(`\`${summary.get("Pending")}/${summary.get("In progress")}/${summary.get("Complete")}/${summary.get("Blocked")}\``);
}
