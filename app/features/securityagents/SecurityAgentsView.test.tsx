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
});
