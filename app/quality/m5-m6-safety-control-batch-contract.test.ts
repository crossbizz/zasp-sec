import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const read = (file: string) => fs.readFileSync(path.join(process.cwd(), file), "utf8");

describe("M5 completion slice and M6 policy foundation", () => {
  it("publishes Attack Lab and policy product operations", () => {
    const source = read("openapi/openapi.yaml");
    for (const id of ["listAttackLabRuns", "createAttackLabRun", "getAttackLabRun", "cancelAttackLabRun", "rerunAttackLabRun", "listPolicies", "createPolicy", "getPolicy", "updatePolicy", "deletePolicy", "simulatePolicy", "rolloutPolicy", "disablePolicy", "listPolicyDecisions"]) expect(source).toContain(`operationId: ${id}`);
  });
  it("implements the policy and Attack Lab boundaries without provider completion claims", () => {
    const redteam = read("services/platform/redteam/redteam.go");
    const policy = read("services/platform/policy/policy.go") + read("services/platform/policy/runtime.go");
    for (const symbol of ["EvaluateAttackLabVerdict", "NewAttackLabWorker", "EvaluateM5Gate"]) expect(redteam).toContain(` ${symbol}`);
    for (const symbol of ["Validate", "Compile", "Evaluate", "SignBundle", "NewBundleCache", "GetPolicyBundle", "ParseMCPAction", "NewDecisionStore", "ApplyDecisionEvidence", "EvaluateM6Gate"]) expect(policy).toContain(` ${symbol}`);
  });
  it("records the completed local M5 and M6 slices without staging claims", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    for (const value of ["| Pending | 0 |", "| In progress | 291 |", "| Complete | 434 |", "| Blocked | 3 |", "`0/291/434/3`", "| M5 | 42 | 0 | 0 | 42 | 0 |", "| M6 | 36 | 0 | 0 | 36 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    for (const task of ["M6-18", "M6-19", "M6-20", "M6-21", "M6-22", "M6-23", "M6-24", "M6-25", "M6-26", "M6-27", "M6-28", "M6-29", "M6-30", "M6-31a", "M6-31b", "M6-31c", "M6-31d", "M6-31e", "M6-31"]) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(1);
    }
    expect(tracker).toContain("real AWS staging execution remains unresolved");
    expect(tracker).not.toContain("OPA SDK and runtime-gateway integration remain unresolved");
  });
});
