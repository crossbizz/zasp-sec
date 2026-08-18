import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const read = (file: string) => fs.readFileSync(path.join(process.cwd(), file), "utf8");
const selected = ["M7-07a","M7-07b","M7-07c","M7-07","M7-08","M7-09","M7-10","M7-11","M7-12","M7-13","M7-14","M7-15a","M7-15b","M7-15c","M7-15d","M7-15","M7-16","M7-17","M7-18","M7-19","M7-20","M7-21","M7-22","M7-22a","M7-23"];

describe("M7 investigation and administration foundation completion batch", () => {
  it("binds the implemented service and artifact boundaries", () => {
    const session = read("services/platform/sessioncontrol/sessioncontrol.go");
    const admin = read("services/platform/admincontrol/admincontrol.go");
    for (const symbol of ["AssembleComplianceEvidence", "BuildComplianceExport", "WriteComplianceExportArtifact", "NewDataControlStore"]) expect(session).toContain(` ${symbol}`);
    for (const symbol of ["NewRetentionWorker", "NewExternalFlowStore"]) expect(admin).toContain(` ${symbol}`);
  });

  it("moves exactly twenty-five tasks to Complete", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    for (const value of ["| Pending | 0 |", "| In progress | 6 |", "| Complete | 667 |", "| Blocked | 55 |", "`0/6/667/55`", "| M7 | 62 | 0 | 0 | 62 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    for (const task of selected) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    }
    expect(read("README.md")).toContain("M7-01 through M7-40 are Complete");
  });
});
