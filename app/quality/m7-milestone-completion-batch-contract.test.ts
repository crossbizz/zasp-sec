import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const read = (file: string) => fs.readFileSync(path.join(process.cwd(), file), "utf8");
const selected = ["M7-24","M7-25","M7-26a","M7-26b","M7-26c","M7-26","M7-27","M7-28","M7-29","M7-30","M7-31","M7-32","M7-33","M7-34","M7-35","M7-36","M7-37","M7-38","M7-39a","M7-39b","M7-39c","M7-39d","M7-39e","M7-39","M7-40a","M7-40b","M7-40c","M7-40d","M7-40e","M7-40f","M7-40"];

describe("M7 milestone completion batch", () => {
  it("retains the implemented governance, administration, degradation, and gate boundaries", () => {
    for (const [file, symbols] of [
      ["services/platform/producttelemetry/m7.go", ["NewFlagCache"]],
      ["services/platform/aigateway/m7.go", ["RedactApprovedFields", "NewGovernor"]],
      ["services/platform/admincontrol/admincontrol.go", ["NewSystemProbes"]],
      ["services/platform/m7gate/m7gate.go", ["Evaluate"]],
    ] as const) {
      const source = read(file);
      for (const symbol of symbols) expect(source).toContain(` ${symbol}`);
    }
  });

  it("moves the final thirty-one M7 tasks to Complete", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    for (const value of ["| Pending | 0 |", "| In progress | 218 |", "| Complete | 507 |", "| Blocked | 3 |", "`0/218/507/3`", "| M7 | 62 | 0 | 0 | 62 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    expect(selected).toHaveLength(31);
    for (const task of selected) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    }
    expect(read("README.md")).toContain("M7-01 through M7-40 are Complete");
  });
});
