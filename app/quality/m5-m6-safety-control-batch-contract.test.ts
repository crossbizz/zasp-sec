import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const read = (file: string) => fs.readFileSync(path.join(process.cwd(), file), "utf8");

describe("M5 completion slice and M6 policy foundation", () => {
  it("publishes Attack Lab and policy product operations", () => {
    const source = read("openapi/openapi.yaml");
    for (const id of ["listAttackLabRuns", "createAttackLabRun", "getAttackLabRun", "cancelAttackLabRun", "rerunAttackLabRun", "listPolicies", "createPolicy", "getPolicy"]) expect(source).toContain(`operationId: ${id}`);
  });
  it("implements the policy and Attack Lab boundaries without provider completion claims", () => {
    const redteam = read("services/platform/redteam/redteam.go");
    const policy = read("services/platform/policy/policy.go");
    for (const symbol of ["EvaluateAttackLabVerdict", "NewAttackLabWorker", "EvaluateM5Gate"]) expect(redteam).toContain(` ${symbol}`);
    for (const symbol of ["Validate", "Compile", "Evaluate", "SignBundle", "NewBundleCache", "GetPolicyBundle"]) expect(policy).toContain(` ${symbol}`);
  });
  it("records the exact 23-task transition as local In-progress work", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    for (const value of ["| Pending | 346 |", "| In progress | 195 |", "| Complete | 184 |", "| Blocked | 3 |", "`346/195/184/3`", "| M5 | 42 | 0 | 42 | 0 | 0 |", "| M6 | 36 | 26 | 10 | 0 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    for (const task of ["M5-26", "M5-27", "M5-28", "M5-29", "M5-30", "M5-31", "M5-32", "M5-33a", "M5-33b", "M5-33c", "M5-33", "M5-34", "M5-35", "M6-01", "M6-02", "M6-03", "M6-04", "M6-05", "M6-06", "M6-07", "M6-08", "M6-09", "M6-10"]) expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    expect(tracker).toContain("staging Fargate evidence remains unresolved");
    expect(tracker).toContain("OPA SDK and runtime-gateway integration remain unresolved");
  });
});
