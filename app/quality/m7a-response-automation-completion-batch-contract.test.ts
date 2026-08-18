import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const read = (file: string) => fs.readFileSync(path.join(process.cwd(), file), "utf8");
const selected = ["M7A-19", "M7A-20", "M7A-21", "M7A-22", "M7A-23", "M7A-24", "M7A-25", "M7A-26", "M7A-27", "M7A-28", "M7A-29", "M7A-30", "M7A-31", "M7A-32", "M7A-33", "M7A-34", "M7A-35", "M7A-36", "M7A-37", "M7A-38"];

describe("M7A response automation completion batch", () => {
  it("moves the exact twenty-task response slice to Complete", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    for (const value of ["| Pending | 0 |", "| In progress | 6 |", "| Complete | 667 |", "| Blocked | 55 |", "`0/6/667/55`", "| M7A | 113 | 0 | 0 | 113 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    expect(selected).toHaveLength(20);
    for (const task of selected) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    }
  });
});
