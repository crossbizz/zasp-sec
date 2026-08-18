import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { SecurityAction, SecurityAgentDefinition, SecurityAgentSimulation } from "../../../apps/web/api/generated";
import { SecurityAgentsView, type SecurityAgentsAPI } from "./SecurityAgentsView";

const action: SecurityAction = { key: "run_test", risk_class: "low", target_types: ["test_definition"], approval_floor: "none", reversible: true, verification_kind: "test_run" };
const created: SecurityAgentDefinition = {
  id: "agent-created", name: "Bounded response", trigger_kind: "finding", trigger_source: "credential", environment_ids: ["production"], autonomy: "supervised", max_steps: 10, max_duration_seconds: 900, temporary_policy_seconds: 3600, ai_token_budget: 4000, concurrency_limit: 2, allowed_actions: ["run_test"], verification_kind: "test_run", definition_version: 1, enabled: true,
};
const simulation: SecurityAgentSimulation = { matched_evidence_ids: ["evidence-selected"], summary: "one bounded step", steps: [{ index: 0, action: "run_test", authorization: "allow", approval_required: false }], side_effects: 0 };

function fixtureAPI(overrides: Partial<SecurityAgentsAPI> = {}): SecurityAgentsAPI {
  return {
    listSecurityAgentTemplates: async () => [], listSecurityActions: async () => [action], listSecurityAgents: async () => ({ items: [] }),
    createSecurityAgent: async () => created, getSecurityAgent: async () => created, updateSecurityAgent: async () => created, deleteSecurityAgent: async () => {},
    simulateSecurityAgent: async () => simulation, runSecurityAgent: async () => { throw new Error("unused"); }, listSecurityAgentRuns: async () => ({ items: [] }), getSecurityAgentRun: async () => { throw new Error("unused"); }, cancelSecurityAgentRun: async () => { throw new Error("unused"); },
    listSecurityAgentApprovals: async () => ({ items: [] }), getSecurityAgentApproval: async () => { throw new Error("unused"); }, decideSecurityAgentApproval: async () => { throw new Error("unused"); },
    ...overrides,
  };
}

describe("Security Agent builder", () => {
  it("creates a bounded verified definition and simulates the created agent", async () => {
    const user = userEvent.setup();
    const createSecurityAgent = vi.fn(async () => created);
    const simulateSecurityAgent = vi.fn(async () => simulation);
    render(<SecurityAgentsView api={fixtureAPI({ createSecurityAgent, simulateSecurityAgent })} />);
    await user.click(await screen.findByRole("button", { name: "Create Security Agent" }));
    await user.click(screen.getByRole("button", { name: /Actions/ }));
    await user.click(screen.getByRole("checkbox", { name: "Select run_test" }));
    await user.click(screen.getByRole("button", { name: /Simulate/ }));
    await user.click(screen.getByRole("button", { name: "Save Security Agent" }));
    await waitFor(() => expect(createSecurityAgent).toHaveBeenCalledWith(expect.objectContaining({ enabled: true, allowed_actions: ["run_test"], temporary_policy_seconds: 3600, ai_token_budget: 4000, concurrency_limit: 2 })));
    await user.click(screen.getByRole("button", { name: "Simulate with selected evidence" }));
    await waitFor(() => expect(simulateSecurityAgent).toHaveBeenCalledWith("agent-created", expect.objectContaining({ evidence_ids: ["evidence-selected"] })));
    expect(screen.getByText("authorization: allow")).toBeInTheDocument();
  });

  it("opens the dedicated approvals surface and renders all definition limits", async () => {
    const user = userEvent.setup();
    const approval = { id: "approval-1", run_id: "run-1", step_id: "run_test", state: "pending" as const, expires_at: "2026-08-18T22:00:00Z", version: 1, expected_effect: "Run the bounded test", reversible: true, ttl_seconds: 900, evidence_summary: ["evidence-1"] };
    const run = { id: "run-1", agent_id: created.id, state: "waiting_approval" as const, evidence_ids: ["evidence-1"], definition_version: 1, version: 1 };
    render(<SecurityAgentsView initialTab="approvals" api={fixtureAPI({ listSecurityAgents: async () => ({ items: [created] }), listSecurityAgentRuns: async () => ({ items: [run] }), listSecurityAgentApprovals: async () => ({ items: [approval] }), getSecurityAgentApproval: async () => approval })} />);
    expect(await screen.findByText("Pending approvals", { selector: ".card__title" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "run_test" }));
    expect(await screen.findByText("Run the bounded test")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close" }));
    await user.click(screen.getByRole("tab", { name: /Security Agents/ }));
    await user.click(screen.getByRole("button", { name: "Bounded response" }));
    expect(await screen.findByText(/3600s temporary policy · 4000 AI tokens · concurrency 2/)).toBeInTheDocument();
  });
});
