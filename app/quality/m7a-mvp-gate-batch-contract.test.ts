import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("M7A-85 through M7A-101 Security Agent MVP gate", () => {
  it("renders bounded definition, run, approval, activity, and Home attention surfaces", () => {
    const securityAgents = read("app/features/securityagents/SecurityAgentsView.tsx");
    for (const value of ["Definition", "Allowed actions", "Recent runs", "AI rationale", "Deterministic authorization", "[REDACTED]", "Rollback / TTL", "Pending approvals", "Expected side effect", "Fresh authentication", "Scoped activity link"]) expect(securityAgents).toContain(value);
    const home = read("app/features/agents/AgentSecurityView.tsx");
    for (const value of ["Pending approvals", "Needs human", "Failed or inconclusive", "Recent containment", "Stale launch coverage"]) expect(home).toContain(value);
  });

  it("binds the home summary, signed notification, degraded suite, and fail-closed MVP gate", () => {
    const openapi = read("openapi/openapi.yaml");
    for (const field of ["pending_approvals", "oldest_approval_age_seconds", "needs_human_runs", "failed_runs", "inconclusive_runs", "recent_contained", "recent_remediated"]) expect(openapi).toContain(field);
    const mvp = read("services/platform/securityagent/mvp.go");
    for (const value of ["security_agent.approval_required", "EvaluateSecurityAgentMVPGate", "BuildSecurityAgentAttention", "DeliverOnce"]) expect(mvp).toContain(value);
    const tests = read("services/platform/securityagent/mvp_test.go") + read("services/platform/securityagent/pipeline_test.go");
    for (const value of ["planner", "Approval", "UnknownOutcome", "cross-scope", "Budget", "TenantIsolation", "SingleTenant"]) expect(tests).toContain(value);
  });

  it("moves exactly M7A-85 through M7A-101 into one truthful active batch", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] || "";
    for (const id of ["M7A-85", "M7A-86", "M7A-87", "M7A-88", "M7A-89", "M7A-90", "M7A-90a", "M7A-90b", "M7A-90c", "M7A-90d", "M7A-91", "M7A-92", "M7A-93", "M7A-94", "M7A-95", "M7A-96", "M7A-97", "M7A-98", "M7A-99", "M7A-100", "M7A-101"]) expect(active.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    expect(tracker).toContain("Pending | 0");
    expect(tracker).toContain("In progress | 416");
  });
});
