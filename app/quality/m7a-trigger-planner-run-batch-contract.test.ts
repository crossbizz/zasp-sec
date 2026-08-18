import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const read = (file: string) => fs.readFileSync(path.join(process.cwd(), file), "utf8");

describe("M7A trigger, planner, and run-engine batch", () => {
  it("implements the scoped dispatcher, structured planner, authorizer, budgets, and run lifecycle", () => {
    const root = "services/platform/securityagent/";
    const source = ["dispatcher.go", "planner.go", "engine.go"].map((file) => read(root + file)).join("\n");
    for (const symbol of ["ValidateTriggerEvent", "NewTriggerDispatcher", "NewTriggerSource", "BuildEvidenceSnapshot", "BuildPlannerInput", "ValidatePlannerOutput", "AuthorizeAction", "ValidateEnablePermissions", "NewBudgetManager", "NewRunJobHandler", "PlanQueuedRun", "ExecuteAutoStep", "CreateStepApproval", "NewApprovalCoordinator", "ClassifyExecution", "NewVerifierDispatcher", "EvaluateRunOutcome", "CancelRun"]) expect(source).toContain(` ${symbol}`);
    const ai = read("services/platform/aigateway/aigateway.go") + read("services/platform/aigateway/m7.go");
    expect(ai).toContain('PurposeSecurityResponsePlan Purpose = "security_response_plan"');
    expect(ai).toContain("IsStructuredPurpose");
    expect(ai).toContain("containsString(config.Purposes, string(PurposeSecurityResponsePlan))");
  });

  it("records exactly 25 related M7A tasks without queue/provider completion claims", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    for (const value of ["| Pending | 0 |", "| In progress | 416 |", "| Complete | 309 |", "| Blocked | 3 |", "`0/416/309/3`", "| M7A | 113 | 0 | 113 | 0 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const tasks = ["M7A-38a", "M7A-38b", "M7A-38c", "M7A-38d", "M7A-39", "M7A-40", "M7A-41", "M7A-42", "M7A-43", "M7A-44", "M7A-45", "M7A-46", "M7A-47", "M7A-48", "M7A-49", "M7A-50", "M7A-51", "M7A-52", "M7A-53", "M7A-54", "M7A-55", "M7A-56", "M7A-57", "M7A-58", "M7A-59"];
    expect(tasks).toHaveLength(25);
    for (const task of tasks) expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    expect(tracker).toContain("production queue wiring remains unresolved");
    expect(tracker).toContain("production SQS wiring remains unresolved");
  });
});
