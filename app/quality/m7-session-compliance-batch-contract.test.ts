import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const read = (file: string) => fs.readFileSync(path.join(process.cwd(), file), "utf8");

describe("M7 sessions, compliance, and data-controls batch", () => {
  it("publishes the exact nine product operations", () => {
    const source = read("openapi/openapi.yaml");
    for (const id of ["listSessions", "getSession", "listSessionEvents", "listComplianceControls", "listComplianceEvidence", "createComplianceExport", "getComplianceExport", "getDataControls", "updateDataControls"]) expect(source).toContain(`operationId: ${id}`);
  });
  it("implements local projection, evidence, export, and data-control boundaries", () => {
    const source = read("services/platform/sessioncontrol/sessioncontrol.go");
    for (const symbol of ["NewProjector", "BuildSessionFilter", "AssembleComplianceEvidence", "BuildComplianceExport", "NewDataControlStore"]) expect(source).toContain(` ${symbol}`);
  });
  it("records exactly the 25-task local M7 slice without provider completion claims", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    for (const value of ["| Pending | 0 |", "| In progress | 341 |", "| Complete | 384 |", "| Blocked | 3 |", "`0/341/384/3`", "| M7 | 62 | 0 | 62 | 0 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    for (const task of ["M7-01","M7-02","M7-03","M7-04","M7-05","M7-06","M7-07a","M7-07b","M7-07c","M7-07","M7-08","M7-09","M7-10","M7-11","M7-12","M7-13","M7-14","M7-15a","M7-15b","M7-15c","M7-15d","M7-15","M7-16","M7-17","M7-18"]) expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    expect(tracker).toContain("OpenSearch integration remains unresolved");
    expect(tracker).toContain("S3 writing remains unresolved");
  });
});
