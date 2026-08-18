import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const read = (file: string) => fs.readFileSync(path.join(process.cwd(), file), "utf8");

describe("M7 gate and Security Agent foundation batch", () => {
  it("implements the local M7 gate and Security Agent foundation", () => {
    const gate = read("services/platform/m7gate/m7gate.go");
    const root = "services/platform/securityagent/";
    const source = ["types.go", "migration.go", "repository.go", "action.go"].map((file) => read(root + file)).join("\n");
    for (const value of ["DegradedStates", "UIAPICoverage", 'Status: "PASS"', "DegradedChecks: 5"]) expect(gate).toContain(value);
    for (const symbol of ["ValidateAgent", "CanTransition", "ValidatePlan", "ValidateActionMetadata", "MigrationSQL", "NewMemoryRepository", "TransitionRun", "DecideApproval", "ClaimAction", "NewRegistry", "NewTemporaryPolicyAction"]) expect(source).toContain(` ${symbol}`);
  });

  it("records the M7 gate and Security Agent foundation complete", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    for (const value of ["| Pending | 0 |", "| In progress | 122 |", "| Complete | 603 |", "| Blocked | 3 |", "`0/122/603/3`", "| M7 | 62 | 0 | 0 | 62 | 0 |", "| M7A | 113 | 0 | 0 | 113 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    for (const task of ["M7-39", "M7-40a", "M7-40b", "M7-40c", "M7-40d", "M7-40e", "M7-40f", "M7-40"]) expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    for (const task of ["M7A-01", "M7A-02", "M7A-03", "M7A-04", "M7A-05", "M7A-06", "M7A-07", "M7A-08", "M7A-09", "M7A-10", "M7A-11", "M7A-12", "M7A-13", "M7A-14", "M7A-15", "M7A-16", "M7A-17"]) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    }
    expect(tracker).toContain("repeatably executable SQL boundary");
    expect(tracker).toContain("provider-backed staging is not claimed");
  });
});
