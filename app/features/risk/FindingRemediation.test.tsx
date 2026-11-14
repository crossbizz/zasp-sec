// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Finding } from "../../../apps/web/api/generated";
import { decodeSecurityAgentManualRunInput, validSecurityAgentRemediation } from "../../../apps/web/api/decoders";
import { FindingRemediation, findingRemediation, type FindingRemediationAPI, type RemediationAgent } from "./FindingRemediation";
import { createFindingRemediationAPI } from "./remediation-api";

const findingID = "pid_30000005-0000-4000-8000-000000000005";
const agent: RemediationAgent = { id: "pid_20000001-0000-4000-8000-000000000001", name: "Guardrail remediation", version: 4, environmentID: "pid_10000003-0000-4000-8000-000000000003" };

function finding(rule: string, status: Finding["status"] = "open"): Finding {
  return { id: findingID, source: "prowler", rule, title: `Discovered AWS control ${rule}`, severity: "high", status, version: 1, agent_id: "pid_40000001-0000-4000-8000-000000000001", evidence_ids: [], risk_factors: [], frameworks: [], updated_at: "2026-11-14T10:00:00Z" } as unknown as Finding;
}

function api(overrides: Partial<FindingRemediationAPI> = {}): FindingRemediationAPI & { startRemediation: ReturnType<typeof vi.fn> } {
  return { listRemediationAgents: vi.fn(async () => [agent]), startRemediation: vi.fn(async () => ({ runID: "pid_50000001-0000-4000-8000-000000000001", state: "waiting_approval" })), ...overrides } as FindingRemediationAPI & { startRemediation: ReturnType<typeof vi.fn> };
}

afterEach(cleanup);

describe("finding remediation", () => {
  it("offers the matching action only for an open finding of a rule an action answers", () => {
    expect(findingRemediation(finding("agent_guardrail_missing"))?.action).toBe("attach_bedrock_guardrail");
    expect(findingRemediation(finding("agent_role_administrator_access"))?.action).toBe("detach_role_administrator_policy");
    expect(findingRemediation(finding("agent_role_unused_90_days"))).toBeUndefined();
    expect(findingRemediation(finding("agent_guardrail_missing", "resolved"))).toBeUndefined();
  });

  it("requests a guardrail attachment with the finding as the trigger and reports the run waiting for approval", async () => {
    const remediation = api();
    render(<FindingRemediation finding={finding("agent_guardrail_missing")} api={remediation} disabled={false} onNavigate={() => undefined} />);
    const button = await screen.findByRole("button", { name: /Request approval: attach bedrock guardrail/ });
    // Nothing can be requested until the guardrail is named in a valid form.
    expect((button as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Guardrail identifier or ARN"), { target: { value: "gr1abc" } });
    fireEvent.change(screen.getByLabelText("Guardrail version"), { target: { value: "latest" } });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Guardrail version"), { target: { value: "3" } });
    expect((button as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(button);
    await waitFor(() => expect(remediation.startRemediation).toHaveBeenCalledTimes(1));
    expect(remediation.startRemediation).toHaveBeenCalledWith(agent, findingID, { action: "attach_bedrock_guardrail", parameters: { guardrail_identifier: "gr1abc", guardrail_version: "3" } });
    expect((await screen.findByRole("status")).textContent).toContain("waiting for approval");
  });

  it("requests a policy detachment and says who must approve it", async () => {
    const remediation = api();
    render(<FindingRemediation finding={finding("agent_role_administrator_access")} api={remediation} disabled={false} onNavigate={() => undefined} />);
    fireEvent.click(await screen.findByRole("button", { name: /Request approval: detach administrator policy from agent role/ }));
    await waitFor(() => expect(remediation.startRemediation).toHaveBeenCalledWith(agent, findingID, { action: "detach_role_administrator_policy", parameters: { policy_arn: "arn:aws:iam::aws:policy/AdministratorAccess" } }));
    expect(screen.getByLabelText("Fix with a Security Agent").textContent).toContain("An identity administrator other than you must approve");
  });

  it("says what to do when no Security Agent has the action", async () => {
    const navigate = vi.fn();
    render(<FindingRemediation finding={finding("agent_guardrail_missing")} api={api({ listRemediationAgents: vi.fn(async () => []) })} disabled={false} onNavigate={navigate} />);
    expect((await screen.findByText(/No enabled Security Agent has this action/)).textContent).toContain("Attach Bedrock Guardrail");
    fireEvent.click(screen.getByRole("button", { name: "Open Security Agents" }));
    expect(navigate).toHaveBeenCalledWith("/security-agents");
  });

  it("names the missing remediation role when the API refuses the request for it", async () => {
    const refused = Object.assign(new Error("refused"), { status: 409, product: { code: "remediation_role_not_configured" } });
    const remediation = api({ startRemediation: vi.fn(async () => { throw refused; }) });
    render(<FindingRemediation finding={finding("agent_role_administrator_access")} api={remediation} disabled={false} onNavigate={() => undefined} />);
    fireEvent.click(await screen.findByRole("button", { name: /Request approval/ }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("no remediation role");
    expect(alert.textContent).toContain("never used to make changes");
  });

  it.each([
    ["remediation_already_requested", "already has a remediation run"],
    ["remediation_target_unsupported", "not on an agent this action can change"],
    ["remediation_integration_unavailable", "not described by an active AWS integration"],
    ["remediation_rule_mismatch", "action does not answer this finding"],
    ["something_else", "The remediation was not requested"],
  ])("explains the refusal %s in product language", async (code, text) => {
    // A transport error carries the code at the top level, a product error under product.
    const refused = code === "remediation_rule_mismatch" ? Object.assign(new Error("refused"), { code }) : Object.assign(new Error("refused"), { status: 409, product: { code } });
    const remediation = api({ startRemediation: vi.fn(async () => { throw refused; }) });
    render(<FindingRemediation finding={finding("agent_role_administrator_access")} api={remediation} disabled={false} onNavigate={() => undefined} />);
    fireEvent.click(await screen.findByRole("button", { name: /Request approval/ }));
    expect((await screen.findByRole("alert")).textContent).toContain(text);
    // The form stays usable so the person can retry after fixing the cause.
    expect((screen.getByRole("button", { name: /Request approval/ }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("explains a refusal that is not an object", async () => {
    const remediation = api({ startRemediation: vi.fn(async () => { throw null; }) });
    render(<FindingRemediation finding={finding("agent_role_administrator_access")} api={remediation} disabled={false} onNavigate={() => undefined} />);
    fireEvent.click(await screen.findByRole("button", { name: /Request approval/ }));
    expect((await screen.findByRole("alert")).textContent).toContain("The remediation was not requested");
  });

  it("says Security Agents are unavailable when they cannot be listed", async () => {
    render(<FindingRemediation finding={finding("agent_guardrail_missing")} api={api({ listRemediationAgents: vi.fn(async () => { throw new Error("forbidden"); }) })} disabled={false} onNavigate={() => undefined} />);
    expect(await screen.findByText("Security Agents are not available to you in this scope.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Request approval/ })).toBeNull();
  });

  it("shows loading until the agents arrive and asks the API for the finding's action", async () => {
    let resolve: (value: readonly RemediationAgent[]) => void = () => undefined;
    const list = vi.fn(() => new Promise<readonly RemediationAgent[]>((done) => { resolve = done; }));
    render(<FindingRemediation finding={finding("agent_role_administrator_access")} api={api({ listRemediationAgents: list })} disabled={false} onNavigate={() => undefined} />);
    expect(screen.getByText("Loading Security Agents…")).toBeTruthy();
    expect(list).toHaveBeenCalledWith("detach_role_administrator_policy", expect.any(AbortSignal));
    resolve([agent]);
    expect(await screen.findByRole("button", { name: /Request approval/ })).toBeTruthy();
  });

  it("ignores an agent list that arrives after the view was removed", async () => {
    let resolve: (value: readonly RemediationAgent[]) => void = () => undefined;
    let signal: AbortSignal | undefined;
    const list = vi.fn((_action: string, given?: AbortSignal) => { signal = given; return new Promise<readonly RemediationAgent[]>((done) => { resolve = done; }); });
    const { unmount } = render(<FindingRemediation finding={finding("agent_guardrail_missing")} api={api({ listRemediationAgents: list })} disabled={false} onNavigate={() => undefined} />);
    unmount();
    expect(signal?.aborted).toBe(true);
    resolve([agent]);
    await Promise.resolve();
  });

  it("lets the person choose among several agents and starts the run on the chosen one", async () => {
    const second: RemediationAgent = { ...agent, id: "pid_20000002-0000-4000-8000-000000000002", name: "Second remediation", version: 9 };
    const remediation = api({ listRemediationAgents: vi.fn(async () => [agent, second]) });
    render(<FindingRemediation finding={finding("agent_role_administrator_access")} api={remediation} disabled={false} onNavigate={() => undefined} />);
    const select = await screen.findByLabelText("Security Agent");
    expect(select).toHaveValue(agent.id);
    fireEvent.change(select, { target: { value: second.id } });
    fireEvent.click(screen.getByRole("button", { name: /Request approval/ }));
    await waitFor(() => expect(remediation.startRemediation).toHaveBeenCalledWith(second, findingID, expect.objectContaining({ action: "detach_role_administrator_policy" })));
  });

  it("offers no agent choice when only one agent can run the action", async () => {
    render(<FindingRemediation finding={finding("agent_role_administrator_access")} api={api()} disabled={false} onNavigate={() => undefined} />);
    await screen.findByRole("button", { name: /Request approval/ });
    expect(screen.queryByLabelText("Security Agent")).toBeNull();
  });

  it("disables every control when the view is disabled", async () => {
    const remediation = api();
    render(<FindingRemediation finding={finding("agent_role_administrator_access")} api={remediation} disabled onNavigate={() => undefined} />);
    const button = (await screen.findByRole("button", { name: /Request approval/ })) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect((screen.getByLabelText("Policy ARN to detach") as HTMLInputElement).disabled).toBe(true);
    fireEvent.click(button);
    expect(remediation.startRemediation).not.toHaveBeenCalled();
  });

  it("refuses a policy that is not an IAM policy ARN and trims what is sent", async () => {
    const remediation = api();
    render(<FindingRemediation finding={finding("agent_role_administrator_access")} api={remediation} disabled={false} onNavigate={() => undefined} />);
    const button = (await screen.findByRole("button", { name: /Request approval/ })) as HTMLButtonElement;
    const field = screen.getByLabelText("Policy ARN to detach");
    fireEvent.change(field, { target: { value: "" } });
    expect(button.disabled).toBe(true);
    fireEvent.change(field, { target: { value: "  arn:aws:iam::aws:policy/AdministratorAccess  " } });
    expect(button.disabled).toBe(false);
    fireEvent.click(button);
    await waitFor(() => expect(remediation.startRemediation).toHaveBeenCalledWith(agent, findingID, { action: "detach_role_administrator_policy", parameters: { policy_arn: "arn:aws:iam::aws:policy/AdministratorAccess" } }));
  });

  it("opens Security Agents from the started run", async () => {
    const navigate = vi.fn();
    render(<FindingRemediation finding={finding("agent_role_administrator_access")} api={api()} disabled={false} onNavigate={navigate} />);
    fireEvent.click(await screen.findByRole("button", { name: /Request approval/ }));
    expect((await screen.findByRole("status")).textContent).toContain("pid_50000001-0000-4000-8000-000000000001");
    fireEvent.click(screen.getByRole("button", { name: "Open Security Agents" }));
    expect(navigate).toHaveBeenCalledWith("/security-agents");
  });

  it("does not list agents for a finding without a remediation", () => {
    const remediation = api();
    render(<FindingRemediation finding={finding("agent_guardrail_missing", "resolved")} api={remediation} disabled={false} onNavigate={() => undefined} />);
    expect(remediation.listRemediationAgents).not.toHaveBeenCalled();
  });

  it("renders nothing for a finding without a remediation", () => {
    const { container } = render(<FindingRemediation finding={finding("ownerless_agent")} api={api()} disabled={false} onNavigate={() => undefined} />);
    expect(container.textContent).toBe("");
  });
});

describe("finding remediation API", () => {
  const definition = (id: string, actions: string[], enabled = true) => ({ id, name: `agent ${id.slice(4, 12)}`, enabled, allowed_actions: actions, environment_ids: [agent.environmentID] });

  it("offers only enabled supervised agents whose single action is the remediation and starts the run through the Security Agent API", async () => {
    const supervised = "pid_20000001-0000-4000-8000-000000000001", validatedOnly = "pid_20000002-0000-4000-8000-000000000002";
    const agents = {
      listSecurityAgents: vi.fn(async () => ({ items: [definition(supervised, ["attach_bedrock_guardrail"]), definition(validatedOnly, ["attach_bedrock_guardrail"]), definition("pid_20000003-0000-4000-8000-000000000003", ["update_finding_response"]), definition("pid_20000004-0000-4000-8000-000000000004", ["attach_bedrock_guardrail"], false), definition("pid_20000005-0000-4000-8000-000000000005", ["attach_bedrock_guardrail", "update_finding_response"])], page_info: { has_next_page: false } })),
      getSecurityAgentActivation: vi.fn(async (id: string) => ({ id, activation: id === supervised ? "supervised" : "validated", enabled: id === supervised, version: 4 })),
      runSecurityAgent: vi.fn(async () => ({ value: { id: "pid_50000001-0000-4000-8000-000000000001", state: "waiting_approval" } })),
    };
    const remediationAPI = createFindingRemediationAPI(agents as never);
    const offered = await remediationAPI.listRemediationAgents("attach_bedrock_guardrail");
    expect(offered).toEqual([{ id: supervised, name: "agent 20000001", version: 4, environmentID: agent.environmentID }]);
    // Activation is read only for the candidates that passed the list filter.
    expect(agents.getSecurityAgentActivation).toHaveBeenCalledTimes(2);
    const remediation = { action: "attach_bedrock_guardrail", parameters: { guardrail_identifier: "gr1abc", guardrail_version: "3" } } as const;
    expect(await remediationAPI.startRemediation(offered[0]!, findingID, remediation)).toEqual({ runID: "pid_50000001-0000-4000-8000-000000000001", state: "waiting_approval" });
    const [id, version, body, attempt] = agents.runSecurityAgent.mock.calls[0] as unknown as [string, number, unknown, { idempotencyKey: string }];
    expect([id, version]).toEqual([supervised, 4]);
    expect(body).toEqual({ environment_id: agent.environmentID, trigger_kind: "finding", trigger_id: findingID, remediation });
    expect(attempt.idempotencyKey).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/);
    // The body is one the run endpoint's input contract accepts.
    expect(() => decodeSecurityAgentManualRunInput(body)).not.toThrow();
  });

  it("accepts only well formed remediations in a run input", () => {
    const base = { environment_id: agent.environmentID, trigger_kind: "finding", trigger_id: findingID };
    expect(validSecurityAgentRemediation({ action: "detach_role_administrator_policy", parameters: { policy_arn: "arn:aws:iam::123456789012:policy/everything" } })).toBe(true);
    expect(validSecurityAgentRemediation({ action: "detach_role_administrator_policy", parameters: { policy_arn: "arn:aws:iam::123456789012:role/admin" } })).toBe(false);
    expect(validSecurityAgentRemediation({ action: "attach_bedrock_guardrail", parameters: { guardrail_identifier: "gr1abc", guardrail_version: "0" } })).toBe(false);
    for (const body of [
      { ...base, remediation: { action: "attach_bedrock_guardrail", parameters: { guardrail_identifier: "gr1abc" } } },
      { ...base, remediation: { action: "attach_bedrock_guardrail", parameters: { guardrail_identifier: "gr1abc", guardrail_version: "1", agent_id: "OTHER" } } },
      { ...base, remediation: { action: "revoke_integration_connection", parameters: {} } },
      { ...base, trigger_kind: "attack_path", remediation: { action: "attach_bedrock_guardrail", parameters: { guardrail_identifier: "gr1abc", guardrail_version: "1" } } },
      { ...base, trigger_version: 2, trigger_source: "agent_guardrail_missing", remediation: { action: "attach_bedrock_guardrail", parameters: { guardrail_identifier: "gr1abc", guardrail_version: "1" } } },
    ]) expect(() => decodeSecurityAgentManualRunInput(body)).toThrow();
  });
});
