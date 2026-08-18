import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const operations = [
  "listSecurityAgentTemplates", "listSecurityActions", "listSecurityAgents", "createSecurityAgent", "getSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent", "simulateSecurityAgent", "runSecurityAgent", "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval", "decideSecurityAgentApproval",
] as const;

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

  it("ships the generated-client Security Agents list and bounded seven-stage builder", async () => {
    const [app, view, routes] = await Promise.all([
      readFile(resolve(root, "app/components/ZaspApp.tsx"), "utf8"),
      readFile(resolve(root, "app/features/securityagents/SecurityAgentsView.tsx"), "utf8"),
      readFile(resolve(root, "app/domain/routes.ts"), "utf8"),
    ]);
    expect(routes).toContain('path: "/protect/security-agents"');
    expect(app).toContain("<SecurityAgentsView");
    expect(view).toContain('from "../../../apps/web/api/generated"');
    for (const operation of operations) expect(view).toContain(operation);
    for (const label of ["Status", "Trigger", "Scope", "Autonomy", "Last outcome", "Pending approvals", "Owner", "Start / Trigger", "Goal / Scope", "Actions", "Autonomy", "Limits", "Verification", "Simulate"]) expect(view).toContain(label);
    expect(view).toContain("Mandatory product approval floor");
    expect(view).toContain("authorization");
    expect(view).not.toMatch(/textarea|tool URL|shell command|arbitrary query/i);
  });

  it("moves exactly M7A-60 through M7A-84 into the active ledger", async () => {
    const tracker = await readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8");
    for (const value of ["| Pending | 0 |", "| In progress | 516 |", "| Complete | 209 |", "| Blocked | 3 |", "`0/516/209/3`", "| M7A | 113 | 0 | 113 | 0 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const tasks = Array.from({ length: 25 }, (_, index) => `M7A-${60 + index}`);
    for (const task of tasks) expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
  });
});
