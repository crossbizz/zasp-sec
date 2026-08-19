import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const operations = [
  "listSecurityAgentTemplates", "listSecurityActions", "listSecurityAgents", "createSecurityAgent", "getSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent", "simulateSecurityAgent", "runSecurityAgent", "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval", "decideSecurityAgentApproval",
] as const;
const retainedOperations = ["listSecurityAgentTemplates", "listSecurityAgents", "createSecurityAgent", "getSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent"] as const;
const hiddenExecutionOperations = operations.filter((operation) => !retainedOperations.includes(operation as typeof retainedOperations[number]));

describe("M7A audit, API, and builder batch", () => {
  it("publishes all fifteen generated Security Agent operations", async () => {
    const [openapi, generated] = await Promise.all([
      readFile(resolve(root, "openapi/openapi.yaml"), "utf8"),
      readFile(resolve(root, "apps/web/api/generated.ts"), "utf8"),
    ]);
    for (const operation of operations) {
      expect(openapi).toContain(`operationId: ${operation}`);
      expect(generated).toContain(operation);
    }
  });

  it("ships the generated-client definition surface and hides executor-dependent controls", async () => {
    const [app, view, routes] = await Promise.all([
      readFile(resolve(root, "app/components/ZaspApp.tsx"), "utf8"),
      readFile(resolve(root, "app/features/securityagents/SecurityAgentsView.tsx"), "utf8"),
      readFile(resolve(root, "app/domain/routes.ts"), "utf8"),
    ]);
    expect(routes).toContain('path: "/protect/security-agents"');
    expect(app).toContain("<SecurityAgentsView");
    expect(view).toContain('from "../../../apps/web/api/generated"');
    for (const operation of retainedOperations) expect(view).toContain(operation);
    for (const operation of hiddenExecutionOperations) expect(view).not.toContain(operation);
    for (const label of ["Definition template", "Definition name", "Authorized environment", "Step limit", "Runtime seconds", "Temporary-policy seconds", "AI token budget", "Concurrency", "Template controls", "Limits", "Definition enabled"]) expect(view).toContain(label);
    expect(view).toContain("Execution, simulation, approvals, and provider actions remain hidden");
    expect(view).not.toMatch(/textarea|tool URL|shell command|arbitrary query/i);
  });

  it("completes exactly M7A-60 through M7A-84", async () => {
    const tracker = await readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8");
    for (const value of ["| Pending | 0 |", "| In progress | 0 |", "| Complete | 667 |", "| Blocked | 61 |", "`0/0/667/61`", "| M7A | 113 | 0 | 0 | 113 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    const tasks = Array.from({ length: 25 }, (_, index) => `M7A-${60 + index}`);
    for (const task of tasks) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    }
  });
});
