import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { SecurityAction, SecurityAgentActivationState, SecurityAgentApproval, SecurityAgentDefinition, SecurityAgentExecutionControls, SecurityAgentRun, SecurityAgentRunDetail, SecurityAgentSimulation, SecurityAgentTemplate } from "../../../apps/web/api/generated";
import { decodeSecurityActionPage, decodeSecurityAgentActivationState, decodeSecurityAgentApprovalPage, decodeSecurityAgentExecutionControlResult, decodeSecurityAgentExecutionControls, decodeSecurityAgentRunDetail, decodeSecurityAgentRunPage, decodeSecurityAgentSimulation, decodeSecurityAgentPage } from "../../../apps/web/api/decoders";
import { SecurityAgentsView, type SecurityAgentsAPI } from "./SecurityAgentsView";

const environmentID = "pid_10000003-0000-4000-8000-000000000003";
const agentID = "pid_40000001-0000-4000-8000-000000000001";
const auditID = "pid_40000002-0000-4000-8000-000000000002";
const receiptID = "pid_40000003-0000-4000-8000-000000000003";
const runID = "pid_40000004-0000-4000-8000-000000000004";
const stepID = "pid_40000005-0000-4000-8000-000000000005";
const approvalID = "pid_40000006-0000-4000-8000-000000000006";
const evidenceID = "pid_40000007-0000-4000-8000-000000000007";
const expiresAt = "2026-08-21T20:00:00Z";
const template: SecurityAgentTemplate = { id: "pid_70000001-0000-4000-8000-000000000001", name: "Finding Response", version: 1, trigger_kind: "finding", default_actions: ["update_finding_response"], verification_condition: "finding_state" };
const action: SecurityAction = { key: "update_finding_response", risk_class: "low", target_types: ["finding"], approval_floor: "none", reversible: true, verification_kind: "finding_state" };
const created: SecurityAgentDefinition = { id: agentID, name: "Bounded response definition", trigger_kind: "finding", trigger_source: "credential", environment_ids: [environmentID], autonomy: "supervised", max_steps: 10, max_duration_seconds: 900, temporary_policy_seconds: 3600, ai_token_budget: 4000, concurrency_limit: 2, allowed_actions: ["update_finding_response"], verification_kind: "finding_state", definition_version: 1, enabled: false };
const draftActivation: SecurityAgentActivationState = { id: agentID, activation: "draft", enabled: false, version: 7 };
const simulation: SecurityAgentSimulation = { run_id: "pid_40000008-0000-4000-8000-000000000008", definition_id: agentID, definition_version: 3, plan_hash: `sha256:${"b".repeat(64)}`, catalog_version: "security-agent-actions-v1", expires_at: expiresAt, matched_evidence_ids: [evidenceID], summary: "Planned one finding response", steps: [{ index: 0, action: "update_finding_response", authorization: "approval_required", approval_required: true }], side_effects: 0, version: 1 };
const run: SecurityAgentRun = { id: runID, agent_id: agentID, state: "waiting_approval", evidence_ids: [evidenceID], definition_version: 1, version: 4 };
const approval: SecurityAgentApproval = { id: approvalID, run_id: runID, step_id: stepID, state: "pending", expires_at: expiresAt, version: 1, expected_effect: "Move finding to under review", reversible: true, ttl_seconds: 0, evidence_summary: [evidenceID] };
const runDetail: SecurityAgentRunDetail = { run, evidence_ids: [evidenceID], plan: { plan_hash: `sha256:${"a".repeat(64)}`, catalog_version: "security-agent-actions-v1", expires_at: expiresAt, steps: [{ id: stepID, index: 0, action: "update_finding_response", authorization: "approval_required", state: "waiting_approval", version: 1 }] }, authorization: "approval_required", approvals: [approval], execution: [{ step_id: stepID, action: "update_finding_response", state: "waiting_approval", version: 1 }], verification: "not_started" };
const controls: SecurityAgentExecutionControls = { global: { target: "global", action_key: "*", enabled: true, version: 1 }, environment: { target: "environment", action_key: "*", enabled: false, version: 0 }, actions: [{ target: "action", action_key: "update_finding_response", enabled: false, version: 0 }] };

function fixtureAPI(overrides: Partial<SecurityAgentsAPI> = {}): SecurityAgentsAPI {
  return {
    listSecurityAgentTemplates: async () => [template],
    listSecurityActions: async () => [action],
    getSecurityAgentExecutionControls: async () => controls,
    setSecurityAgentExecutionControl: async (target, version, enabled) => ({ value: { target, action_key: target === "environment" ? "*" : "update_finding_response", enabled, version: version + 1, audit_id: auditID, correlation_id: "pid_40000009-0000-4000-8000-000000000009", receipt_id: receiptID, replayed: false }, version: `"${version + 1}"`, auditID, receiptID }),
    listSecurityAgents: async () => ({ items: [], page_info: { next_cursor: null, has_more: false } }),
    createSecurityAgent: async () => ({ value: created, version: `"1"`, auditID, receiptID }),
    getSecurityAgent: async () => ({ value: created, version: `"7"` }),
    updateSecurityAgent: async (_id, _version, value) => ({ value, version: `"8"`, auditID, receiptID }),
    deleteSecurityAgent: async () => ({ value: undefined, version: `"9"`, auditID, receiptID }),
    getSecurityAgentActivation: async () => draftActivation,
    activateSecurityAgent: async (_id, version, activation) => ({ value: { id: agentID, activation, enabled: activation === "supervised" || activation === "autonomous", version: version + 1 }, version: `"${version + 1}"`, auditID, receiptID }),
    simulateSecurityAgent: async () => ({ value: simulation, version: `"1"`, auditID, receiptID }),
    runSecurityAgent: async () => ({ value: { ...run, state: "queued", version: 1, definition_version: 3 }, version: `"1"`, auditID, receiptID }),
    listSecurityAgentRuns: async () => ({ items: [] }),
    getSecurityAgentRun: async () => runDetail,
    cancelSecurityAgentRun: async () => ({ value: { ...run, state: "cancelled", version: 5 }, version: `"5"`, auditID, receiptID }),
    listSecurityAgentApprovals: async () => ({ items: [] }),
    getSecurityAgentApproval: async () => approval,
    decideSecurityAgentApproval: async (_id, _version, decision) => ({ value: { ...approval, state: decision }, version: `"2"`, auditID, receiptID }),
    ...overrides,
  };
}

describe("Security Agent definition surface", () => {
  it("strictly decodes hierarchical execution controls without tenant-global mutation authority", () => {
    expect(decodeSecurityAgentExecutionControls(controls)).toEqual(controls);
    expect(decodeSecurityAgentExecutionControlResult({ target: "environment", action_key: "*", enabled: true, version: 1, audit_id: auditID, correlation_id: "pid_40000009-0000-4000-8000-000000000009", receipt_id: receiptID, replayed: false }).target).toBe("environment");
    expect(() => decodeSecurityAgentExecutionControls({ ...controls, actions: [] })).toThrow();
    expect(() => decodeSecurityAgentExecutionControls({ ...controls, global: { ...controls.global, version: 0 } })).toThrow();
    expect(() => decodeSecurityAgentExecutionControlResult({ target: "global", action_key: "*", enabled: false, version: 2, audit_id: auditID, correlation_id: auditID, receipt_id: receiptID, replayed: false })).toThrow();
  });

  it("shows platform status and fresh-auth tenant execution controls only to identity administrators", async () => {
    const user = userEvent.setup();
    const reauthenticate = vi.fn();
    const setSecurityAgentExecutionControl = vi.fn(fixtureAPI().setSecurityAgentExecutionControl);
    const initialSnapshot = { agents: [], templates: [template], actions: [action], runs: [], approvals: [], controls };
    const { rerender } = render(<SecurityAgentsView api={fixtureAPI({ setSecurityAgentExecutionControl })} environmentID={environmentID} autoLoad={false} initialSnapshot={initialSnapshot} canManageControls fresh={false} onReauthenticate={reauthenticate} />);
    expect(screen.getByText("Platform execution enabled")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Reauthenticate to change execution controls" }));
    expect(reauthenticate).toHaveBeenCalledTimes(1);
    rerender(<SecurityAgentsView api={fixtureAPI({ setSecurityAgentExecutionControl })} environmentID={environmentID} autoLoad={false} initialSnapshot={initialSnapshot} canManageControls fresh onReauthenticate={reauthenticate} />);
    await user.click(screen.getByRole("button", { name: "Enable environment automation" }));
    await waitFor(() => expect(setSecurityAgentExecutionControl).toHaveBeenCalledWith("environment", 0, true, expect.objectContaining({ idempotencyKey: expect.stringMatching(/^wf_/) })));
    expect(await screen.findByText("Environment automation enabled")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Enable finding response action" }));
    await waitFor(() => expect(setSecurityAgentExecutionControl).toHaveBeenLastCalledWith("action", 0, true, expect.objectContaining({ idempotencyKey: expect.stringMatching(/^wf_/) })));
    expect(screen.queryByRole("button", { name: /platform execution/i })).not.toBeInTheDocument();
  });
  it("strictly binds run plans, approvals, effects, and cursor pages", () => {
    expect(decodeSecurityActionPage({ items: [action] })).toEqual({ items: [action] });
    expect(decodeSecurityAgentActivationState(draftActivation)).toEqual(draftActivation);
    expect(decodeSecurityAgentSimulation(simulation)).toEqual(simulation);
    expect(() => decodeSecurityActionPage({ items: [{ ...action, key: "z" }, action] })).toThrow();
    expect(() => decodeSecurityAgentActivationState({ ...draftActivation, enabled: true })).toThrow();
    expect(() => decodeSecurityAgentSimulation({ ...simulation, side_effects: 1 })).toThrow();
    expect(decodeSecurityAgentRunPage({ items: [run], next_cursor: "b2s" })).toEqual({ items: [run], next_cursor: "b2s" });
    expect(decodeSecurityAgentApprovalPage({ items: [approval] })).toEqual({ items: [approval] });
    expect(decodeSecurityAgentRunDetail(runDetail)).toEqual(runDetail);
    expect(() => decodeSecurityAgentRunPage({ items: [{ ...run, evidence_ids: [] }] })).toThrow();
    expect(() => decodeSecurityAgentApprovalPage({ items: [{ ...approval, evidence_summary: [] }] })).toThrow();
    expect(() => decodeSecurityAgentRunDetail({ ...runDetail, evidence_ids: [agentID] })).toThrow();
    expect(() => decodeSecurityAgentRunDetail({ ...runDetail, execution: [{ ...runDetail.execution[0], step_id: agentID }] })).toThrow();
    expect(() => decodeSecurityAgentRunDetail({ ...runDetail, plan: { ...runDetail.plan!, steps: [{ ...runDetail.plan!.steps[0], index: 1 }] } })).toThrow();
  });
  it("strictly rejects noncanonical or contradictory pagination metadata", () => {
    expect(() => decodeSecurityAgentPage({ items: [], page_info: { next_cursor: "bad=", has_more: true } })).toThrow();
    expect(() => decodeSecurityAgentPage({ items: [], page_info: { next_cursor: "b2s", has_more: false } })).toThrow();
    expect(() => decodeSecurityAgentPage({ items: [], page_info: { next_cursor: null, has_more: false }, unexpected: true })).toThrow();
  });
  it("creates only from locally supported templates and keeps manual execution evidence-bound", async () => {
    const user = userEvent.setup();
    const createSecurityAgent = vi.fn(fixtureAPI().createSecurityAgent);
    render(<SecurityAgentsView api={fixtureAPI({ createSecurityAgent })} environmentID={environmentID} />);
    await user.click(await screen.findByRole("button", { name: "Create Security Agent" }));
    await user.click(screen.getByRole("button", { name: "Save Security Agent definition" }));
    await waitFor(() => expect(createSecurityAgent).toHaveBeenCalledWith(expect.objectContaining({ environment_ids: [environmentID], autonomy: "supervised", allowed_actions: ["update_finding_response"], verification_kind: "finding_state" }), expect.objectContaining({ idempotencyKey: expect.stringMatching(/^wf_/) })));
    expect(screen.getByText("Pending approvals")).toBeInTheDocument();
  });

  it("validates, simulates, and queues a supervised finding run from exact durable activation authority", async () => {
    const user = userEvent.setup();
    const activationV1 = { ...draftActivation, version: 1 };
    const getSecurityAgentActivation = vi.fn(async () => activationV1);
    const activateSecurityAgent = vi.fn(fixtureAPI().activateSecurityAgent);
    const simulateSecurityAgent = vi.fn(fixtureAPI().simulateSecurityAgent);
    const runSecurityAgent = vi.fn(fixtureAPI().runSecurityAgent);
    const api = fixtureAPI({ getSecurityAgent: async () => ({ value: created, version: `"1"` }), getSecurityAgentActivation, activateSecurityAgent, simulateSecurityAgent, runSecurityAgent });
    const initialSnapshot = { agents: [created], templates: [template], actions: [action], runs: [], approvals: [] };
    const { rerender } = render(<SecurityAgentsView api={api} environmentID={environmentID} autoLoad={false} initialSnapshot={initialSnapshot} fresh={false} onReauthenticate={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: `Open ${created.name}` }));
    expect(await screen.findByText(/update_finding_response · low · approval none/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reauthenticate to activate" })).toBeInTheDocument();

    rerender(<SecurityAgentsView api={api} environmentID={environmentID} autoLoad={false} initialSnapshot={initialSnapshot} fresh />);
    await user.click(screen.getByRole("button", { name: "Validate definition" }));
    await waitFor(() => expect(activateSecurityAgent).toHaveBeenCalledWith(agentID, 1, "validated", expect.objectContaining({ idempotencyKey: expect.stringMatching(/^wf_/) })));
    expect(await screen.findByRole("button", { name: "Enable supervised execution" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Enable supervised execution" }));
    await waitFor(() => expect(activateSecurityAgent).toHaveBeenLastCalledWith(agentID, 2, "supervised", expect.objectContaining({ idempotencyKey: expect.stringMatching(/^wf_/) })));
    await user.type(screen.getByLabelText("Evidence ID"), evidenceID);
    await user.click(screen.getByRole("button", { name: "Simulate plan" }));
    await waitFor(() => expect(simulateSecurityAgent).toHaveBeenCalledWith(agentID, 3, expect.objectContaining({ evidence_ids: [evidenceID], environment_id: environmentID }), expect.objectContaining({ idempotencyKey: expect.stringMatching(/^wf_/) })));
    expect(await screen.findByText("Planned one finding response")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Start supervised run" }));
    await waitFor(() => expect(runSecurityAgent).toHaveBeenCalledWith(agentID, 3, { environment_id: environmentID, trigger_kind: "finding", trigger_id: evidenceID }, expect.objectContaining({ idempotencyKey: expect.stringMatching(/^wf_/) })));
  });

  it("shows redacted run and approval detail, gates decisions on fresh auth, and cancels with the listed version", async () => {
    const user = userEvent.setup();
    const reauthenticate = vi.fn();
    const cancelSecurityAgentRun = vi.fn(fixtureAPI().cancelSecurityAgentRun);
    const decideSecurityAgentApproval = vi.fn(fixtureAPI().decideSecurityAgentApproval);
    const initialSnapshot = { agents: [created], templates: [template], runs: [run], approvals: [approval] };
    const { rerender } = render(<SecurityAgentsView api={fixtureAPI({ cancelSecurityAgentRun, decideSecurityAgentApproval })} environmentID={environmentID} autoLoad={false} initialSnapshot={initialSnapshot} fresh={false} onReauthenticate={reauthenticate} />);

    await user.click(screen.getByRole("button", { name: `Open approval ${approvalID}` }));
    const staleDialog = await screen.findByRole("dialog", { name: `Approval ${approvalID}` });
    expect(within(staleDialog).getByText("Move finding to under review")).toBeInTheDocument();
    expect(within(staleDialog).getByText(evidenceID)).toBeInTheDocument();
    expect(within(staleDialog).queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    await user.click(within(staleDialog).getByRole("button", { name: "Reauthenticate to decide" }));
    expect(reauthenticate).toHaveBeenCalledTimes(1);

    rerender(<SecurityAgentsView api={fixtureAPI({ cancelSecurityAgentRun, decideSecurityAgentApproval })} environmentID={environmentID} autoLoad={false} initialSnapshot={initialSnapshot} fresh onReauthenticate={reauthenticate} />);
    const freshDialog = await screen.findByRole("dialog", { name: `Approval ${approvalID}` });
    await user.click(within(freshDialog).getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(decideSecurityAgentApproval).toHaveBeenCalledWith(approvalID, 1, "approved", expect.objectContaining({ idempotencyKey: expect.stringMatching(/^wf_/) })));

    await user.click(within(freshDialog).getByRole("button", { name: "Close" }));
    await user.click(screen.getByRole("button", { name: `Open run ${runID}` }));
    expect(await screen.findByText(/Plan sha256:/)).toBeInTheDocument();
    expect(screen.getAllByText(/update_finding_response/)).toHaveLength(2);
    await user.click(screen.getByRole("button", { name: "Cancel run" }));
    await waitFor(() => expect(cancelSecurityAgentRun).toHaveBeenCalledWith(runID, 4, expect.objectContaining({ idempotencyKey: expect.stringMatching(/^wf_/) })));
  });

  it("applies stale UI intent with the displayed ETag and never refetches before mutation", async () => {
    const user = userEvent.setup();
    const getSecurityAgent = vi.fn(fixtureAPI().getSecurityAgent);
    const updateSecurityAgent = vi.fn(fixtureAPI().updateSecurityAgent);
    const deleteSecurityAgent = vi.fn(fixtureAPI().deleteSecurityAgent);
    render(<SecurityAgentsView api={fixtureAPI({ getSecurityAgent, updateSecurityAgent, deleteSecurityAgent })} environmentID={environmentID} autoLoad={false} initialSnapshot={{ agents: [created], templates: [template] }} />);
    await user.click(screen.getByRole("button", { name: `Open ${created.name}` }));
    await screen.findByText("Resource version 7");
    await user.clear(screen.getByLabelText("Definition name"));
    await user.type(screen.getByLabelText("Definition name"), "Updated definition");
    await user.click(screen.getByRole("button", { name: "Save definition" }));
    await waitFor(() => expect(updateSecurityAgent).toHaveBeenCalledWith(agentID, `"7"`, expect.objectContaining({ name: "Updated definition" }), expect.objectContaining({ idempotencyKey: expect.stringMatching(/^wf_/) })));
    expect(getSecurityAgent).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "Delete definition" }));
    await waitFor(() => expect(deleteSecurityAgent).toHaveBeenCalledWith(agentID, `"8"`, expect.objectContaining({ idempotencyKey: expect.stringMatching(/^wf_/) })));
  });

  it("offers a manual retry that retains the exact create intent and attempt after an ambiguous response", async () => {
    const user = userEvent.setup();
    const calls: Array<{ value: Parameters<SecurityAgentsAPI["createSecurityAgent"]>[0]; key: string }> = [];
    const createSecurityAgent = vi.fn(async (value: Parameters<SecurityAgentsAPI["createSecurityAgent"]>[0], attempt?: Parameters<SecurityAgentsAPI["createSecurityAgent"]>[1]) => {
      calls.push({ value, key: attempt?.idempotencyKey ?? "" });
      if (calls.length === 1) throw new TypeError("two transport responses were lost");
      return { value: created, version: `"1"`, auditID, receiptID };
    });
    render(<SecurityAgentsView api={fixtureAPI({ createSecurityAgent })} environmentID={environmentID} />);
    await user.click(await screen.findByRole("button", { name: "Create Security Agent" }));
    await user.click(screen.getByRole("button", { name: "Save Security Agent definition" }));
    await screen.findByRole("button", { name: "Retry retained Security Agent definition" });
    expect(screen.getByLabelText("Definition name")).toBeDisabled();
    expect(screen.getByLabelText("Definition template")).toBeDisabled();
    expect(screen.getByLabelText("Step limit")).toBeDisabled();
    expect(screen.getByLabelText("Runtime seconds")).toBeDisabled();
    expect(screen.getByLabelText("Temporary-policy seconds")).toBeDisabled();
    expect(screen.getByLabelText("AI token budget")).toBeDisabled();
    expect(screen.getByLabelText("Concurrency")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Create Security Agent" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Retry retained Security Agent definition" }));
    await waitFor(() => expect(createSecurityAgent).toHaveBeenCalledTimes(2));
    expect(new Set(calls.map(({ key }) => key)).size).toBe(1);
    expect(calls[1]?.value).toEqual(calls[0]?.value);
  });

  it("locks the drawer and every competing definition action while an update is unresolved", async () => {
    const user = userEvent.setup();
    const updateSecurityAgent = vi.fn()
      .mockRejectedValueOnce(new TypeError("committed update response lost"))
      .mockResolvedValueOnce({ value: { ...created, name: "Updated definition" }, version: `"8"`, auditID, receiptID });
    render(<SecurityAgentsView api={fixtureAPI({ updateSecurityAgent })} environmentID={environmentID} autoLoad={false} initialSnapshot={{ agents: [created], templates: [template] }} />);
    await user.click(screen.getByRole("button", { name: `Open ${created.name}` }));
    await screen.findByText("Resource version 7");
    await user.clear(screen.getByLabelText("Definition name"));
    await user.type(screen.getByLabelText("Definition name"), "Updated definition");
    await user.click(screen.getByRole("button", { name: "Save definition" }));
    expect(await screen.findByRole("button", { name: "Retry retained definition operation" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Create Security Agent", hidden: true })).toBeDisabled();
    expect(screen.getByRole("button", { name: `Open ${created.name}`, hidden: true })).toBeDisabled();
    expect(screen.getByLabelText("Definition name")).toBeDisabled();
    expect(screen.getByLabelText("Definition enabled")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Close details" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Close" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Save definition" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete definition" })).not.toBeInTheDocument();
  });

  it("loads all deterministic cursor pages instead of truncating definitions at 100", async () => {
    const second = { ...created, id: "pid_40000003-0000-4000-8000-000000000003", name: "Second page definition" };
    const cursor = "b3JnLXBhZ2UtMg";
    const listSecurityAgents = vi.fn(async (options?: { cursor?: string; limit?: number }) => options?.cursor
      ? { items: [second], page_info: { next_cursor: null, has_more: false as const } }
      : { items: [created], page_info: { next_cursor: cursor, has_more: true as const } });
    render(<SecurityAgentsView api={fixtureAPI({ listSecurityAgents })} environmentID={environmentID} />);
    await screen.findByRole("button", { name: `Open ${second.name}` });
    expect(screen.getByRole("button", { name: `Open ${created.name}` })).toBeInTheDocument();
    expect(listSecurityAgents).toHaveBeenNthCalledWith(1, { cursor: undefined, limit: 100 }, expect.any(AbortSignal));
    expect(listSecurityAgents).toHaveBeenNthCalledWith(2, { cursor, limit: 100 }, expect.any(AbortSignal));
  });

  it("stops after page 100 without issuing a page 101 request", async () => {
    const listSecurityAgents = vi.fn(async () => ({ items: [], page_info: { next_cursor: "b3JnLXBhZ2U", has_more: true as const } }));
    render(<SecurityAgentsView api={fixtureAPI({ listSecurityAgents })} environmentID={environmentID} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Security Agent data is unavailable");
    expect(listSecurityAgents).toHaveBeenCalledTimes(100);
  });
});
