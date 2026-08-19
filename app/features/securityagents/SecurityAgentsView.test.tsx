import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { SecurityAgentDefinition, SecurityAgentTemplate } from "../../../apps/web/api/generated";
import { decodeSecurityAgentPage } from "../../../apps/web/api/decoders";
import { SecurityAgentsView, type SecurityAgentsAPI } from "./SecurityAgentsView";

const environmentID = "pid_10000003-0000-4000-8000-000000000003";
const agentID = "pid_40000001-0000-4000-8000-000000000001";
const auditID = "pid_40000002-0000-4000-8000-000000000002";
const receiptID = "pid_40000003-0000-4000-8000-000000000003";
const template: SecurityAgentTemplate = { id: "pid_70000001-0000-4000-8000-000000000001", name: "Prompt containment", version: 1, trigger_kind: "finding", default_actions: ["run_test"], verification_condition: "test_run" };
const created: SecurityAgentDefinition = { id: agentID, name: "Bounded response definition", trigger_kind: "finding", trigger_source: "credential", environment_ids: [environmentID], autonomy: "supervised", max_steps: 10, max_duration_seconds: 900, temporary_policy_seconds: 3600, ai_token_budget: 4000, concurrency_limit: 2, allowed_actions: ["run_test"], verification_kind: "test_run", definition_version: 1, enabled: true };

function fixtureAPI(overrides: Partial<SecurityAgentsAPI> = {}): SecurityAgentsAPI {
  return {
    listSecurityAgentTemplates: async () => [template],
    listSecurityAgents: async () => ({ items: [], page_info: { next_cursor: null, has_more: false } }),
    createSecurityAgent: async () => ({ value: created, version: `"1"`, auditID, receiptID }),
    getSecurityAgent: async () => ({ value: created, version: `"7"` }),
    updateSecurityAgent: async (_id, _version, value) => ({ value, version: `"8"`, auditID, receiptID }),
    deleteSecurityAgent: async () => ({ value: undefined, version: `"9"`, auditID, receiptID }),
    ...overrides,
  };
}

describe("Security Agent definition surface", () => {
  it("strictly rejects noncanonical or contradictory pagination metadata", () => {
    expect(() => decodeSecurityAgentPage({ items: [], page_info: { next_cursor: "bad=", has_more: true } })).toThrow();
    expect(() => decodeSecurityAgentPage({ items: [], page_info: { next_cursor: "b2s", has_more: false } })).toThrow();
    expect(() => decodeSecurityAgentPage({ items: [], page_info: { next_cursor: null, has_more: false }, unexpected: true })).toThrow();
  });
  it("creates only from locally supported templates and exposes no execution controls", async () => {
    const user = userEvent.setup();
    const createSecurityAgent = vi.fn(fixtureAPI().createSecurityAgent);
    render(<SecurityAgentsView api={fixtureAPI({ createSecurityAgent })} environmentID={environmentID} />);
    await user.click(await screen.findByRole("button", { name: "Create Security Agent" }));
    await user.click(screen.getByRole("button", { name: "Save Security Agent definition" }));
    await waitFor(() => expect(createSecurityAgent).toHaveBeenCalledWith(expect.objectContaining({ environment_ids: [environmentID], autonomy: "supervised", allowed_actions: ["run_test"], verification_kind: "test_run" }), expect.objectContaining({ idempotencyKey: expect.stringMatching(/^wf_/) })));
    expect(screen.queryByText(/simulate/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/approval/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /run/i })).not.toBeInTheDocument();
  });

  it("applies stale UI intent with the displayed ETag and never refetches before mutation", async () => {
    const user = userEvent.setup();
    const getSecurityAgent = vi.fn(fixtureAPI().getSecurityAgent);
    const updateSecurityAgent = vi.fn(fixtureAPI().updateSecurityAgent);
    const deleteSecurityAgent = vi.fn(fixtureAPI().deleteSecurityAgent);
    render(<SecurityAgentsView api={fixtureAPI({ getSecurityAgent, updateSecurityAgent, deleteSecurityAgent })} environmentID={environmentID} autoLoad={false} initialSnapshot={{ agents: [created], templates: [template] }} />);
    await user.click(screen.getByRole("button", { name: `Open ${created.name}` }));
    await screen.findByText("Resource version \"7\"");
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
    await screen.findByText("Resource version \"7\"");
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
    expect(await screen.findByRole("alert")).toHaveTextContent("Security Agent definitions are unavailable");
    expect(listSecurityAgents).toHaveBeenCalledTimes(100);
  });
});
