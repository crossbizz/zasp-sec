import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const read = (file: string) => fs.readFileSync(path.join(process.cwd(), file), "utf8");
const selected = ["M7A-38a", "M7A-38b", "M7A-38c", "M7A-38d", "M7A-39", "M7A-40", "M7A-41", "M7A-42", "M7A-43", "M7A-44", "M7A-45", "M7A-46", "M7A-47", "M7A-48", "M7A-49", "M7A-50", "M7A-51", "M7A-52", "M7A-53", "M7A-54", "M7A-55", "M7A-56", "M7A-57", "M7A-58", "M7A-59"];

describe("M7A trigger planner and run completion batch", () => {
  it("moves the exact twenty-five task runtime slice to Complete", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    for (const value of ["| Pending | 0 |", "| In progress | 168 |", "| Complete | 557 |", "| Blocked | 3 |", "`0/168/557/3`", "| M7A | 113 | 0 | 21 | 92 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    expect(selected).toHaveLength(25);
    for (const task of selected) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    }
  });
});
