import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const read = (file: string) => fs.readFileSync(path.join(process.cwd(), file), "utf8");
const selected = ["M7A-01","M7A-02","M7A-03","M7A-04","M7A-05","M7A-06","M7A-07","M7A-08","M7A-09","M7A-10","M7A-11","M7A-12","M7A-13","M7A-14","M7A-15","M7A-16","M7A-17","M7A-18","M7A-18a","M7A-18b","M7A-18c","M7A-18d"];

describe("M7A Security Agent core completion batch", () => {
  it("moves the exact twenty-two task core to Complete", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    for (const value of ["| Pending | 0 |", "| In progress | 147 |", "| Complete | 578 |", "| Blocked | 3 |", "`0/147/578/3`", "| M7A | 113 | 0 | 0 | 113 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    expect(selected).toHaveLength(22);
    for (const task of selected) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    }
  });

});
