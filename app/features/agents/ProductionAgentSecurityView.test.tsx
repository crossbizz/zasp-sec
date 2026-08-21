import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import { APIProvider } from "../../api/APIProvider";
import { createProductionAgentSecurityAPI, inventoryDetailIDFromSearch, ProductionAgentSecurityView, type ProductionAgentSecurityAPI } from "./ProductionAgentSecurityView";

const ids = {
  first: "pid_10000001-0000-4000-8000-000000000001",
  second: "pid_10000002-0000-4000-8000-000000000002",
  evidence: "pid_20000001-0000-4000-8000-000000000001",
  relationship: "pid_20000002-0000-4000-8000-000000000002",
  session: "pid_20000003-0000-4000-8000-000000000003",
} as const;

function summary(id: string, name: string) {
  return { id, name, kind: "agent" as const, owner: "", team: "", tags: [], evidence_id: ids.evidence, confidence_basis_points: 9500, first_seen: "2026-08-19T00:00:00Z", last_seen: "2026-08-19T01:00:00Z", observed_at: "2026-08-19T01:00:00Z", fresh_until: "2026-08-19T01:15:00Z", freshness_state: "fresh" as const, version: 1 };
}

describe("production typed inventory API", () => {
  it("loads all cursor pages with exact limit, continuation, and abort authority", async () => {
    const signal = new AbortController().signal;
    const get = vi.fn(async (_path: string, options: { params?: { query?: { cursor?: string; limit?: number } }; signal?: AbortSignal }) => ({
      data: options.params?.query?.cursor
        ? { items: [summary(ids.second, "Second")], page_info: { next_cursor: null, has_more: false } }
        : { items: [summary(ids.first, "First")], page_info: { next_cursor: "Y3Vyc29y", has_more: true } },
      response: new Response(null, { status: 200 }),
    }));
    const api = createProductionAgentSecurityAPI({ GET: get } as unknown as APIClient);

    await expect(api.listAgents(signal)).resolves.toEqual([summary(ids.first, "First"), summary(ids.second, "Second")]);
    expect(get).toHaveBeenCalledTimes(2);
    expect(get.mock.calls.map((call) => call[1])).toEqual([
      { params: { query: { cursor: undefined, limit: 100 } }, signal },
      { params: { query: { cursor: "Y3Vyc29y", limit: 100 } }, signal },
    ]);
  });

  it("loads stable detail IDs through the strict typed detail decoder", async () => {
    const value = summary(ids.first, "First");
    const detail = {
      summary: value,
      sources: [{ integration_id: "pid_30000001-0000-4000-8000-000000000001", provider: "kubernetes", source: "kubernetes", source_identifier: `sha256:${"b".repeat(64)}`, snapshot_id: "pid_40000001-0000-4000-8000-000000000001", generation: 1, evidence_id: ids.evidence, confidence_basis_points: 9500, observed_at: value.observed_at, fresh_until: value.fresh_until, projection_version: 1, winning: true }],
      evidence: [{ id: ids.evidence, checksum: `sha256:${"a".repeat(64)}`, media_type: "application/json", schema_version: "raw_v1", parser_version: "parser_v1", tool_version: "tool_v1", collected_at: value.observed_at, size_bytes: 128 }],
    };
    const get = vi.fn(async () => ({ data: detail, response: new Response(null, { status: 200 }) }));
    const api = createProductionAgentSecurityAPI({ GET: get } as unknown as APIClient);

    await expect(api.getAgent(ids.first)).resolves.toEqual(detail);
    expect(get).toHaveBeenCalledWith("/api/v1/agents/{id}", { params: { path: { id: ids.first } }, signal: undefined });
  });

  it("sends exact ownership preconditions and verifies mutation evidence", async () => {
    const mutation = { agent: { ...summary(ids.first, "First"), owner: "security", team: "platform", tags: ["critical", "production"], version: 2 }, audit_id: "pid_50000001-0000-4000-8000-000000000001" };
    const patch = vi.fn(async () => ({ data: mutation, response: new Response(null, { status: 200, headers: { ETag: '"2"', "X-Audit-ID": mutation.audit_id } }) }));
    const api = createProductionAgentSecurityAPI({ PATCH: patch } as unknown as APIClient);

    await expect(api.updateAgent(ids.first, 1, { owner: "security", team: "platform", tags: ["critical", "production"] }, "agent_11111111-1111-4111-8111-111111111111")).resolves.toEqual(mutation);
    expect(patch).toHaveBeenCalledWith("/api/v1/agents/{id}", {
      params: { path: { id: ids.first }, header: { "Idempotency-Key": "agent_11111111-1111-4111-8111-111111111111", "If-Match": '"1"', "X-CSRF-Token": "" } },
      body: { owner: "security", team: "platform", tags: ["critical", "production"] }, signal: undefined,
    });
  });

  it("reloads an exact stable detail URL and rejects ambiguous detail queries", async () => {
    const value = summary(ids.first, "First");
    const detail = { summary: value, sources: [], evidence: [] } as never;
    const getAgent = vi.fn(async () => detail);
    const api: ProductionAgentSecurityAPI = {
      listAgents: async () => [value], listTools: async () => [], listIdentities: async () => [], listRuntimes: async () => [],
      getAgent, getTool: async () => detail, getIdentity: async () => detail, getRuntime: async () => detail,
      getAgentCapabilities: async () => [], getAgentRelationships: async () => [], listAgentSessions: async () => [],
      updateAgent: async () => ({ agent: value, audit_id: ids.evidence }),
      getHomeSummary: async () => ({ agent_count: 1, high_risk_paths: 0, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false }),
    };
    window.history.replaceState({}, "", `/discovery/assets?inventory=${ids.first}`);
    render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={api} onNavigate={() => undefined} /></APIProvider>);
    expect(await screen.findByRole("dialog", { name: "First" })).toBeVisible();
    expect(getAgent).toHaveBeenCalledWith(ids.first, expect.any(AbortSignal));
    expect(inventoryDetailIDFromSearch(`?inventory=${ids.first}&extra=1`)).toBe("");
  });

  it("renders production capability, relationship, session, and runtime-policy evidence", async () => {
    const user = userEvent.setup();
    const value = summary(ids.first, "First");
    const detail = { summary: value, sources: [], evidence: [] } as never;
    const getAgentCapabilities = vi.fn(async () => [{ agent_id: ids.first, target_id: ids.second, target_kind: "identity" as const, category: "identity_assume" as const, outcome: "assume" as const, state: "blocked" as const, reachable: true, evidence_ids: [ids.evidence] }]);
    const getAgentRelationships = vi.fn(async () => [{ id: ids.relationship, from_id: ids.first, to_id: ids.second, type: "uses_identity", evidence_id: ids.evidence }]);
    const listAgentSessions = vi.fn(async () => [{ id: ids.session, agent_id: ids.first, started_at: "2026-08-19T01:00:00Z" }]);
    const api: ProductionAgentSecurityAPI = {
      listAgents: async () => [value], listTools: async () => [], listIdentities: async () => [], listRuntimes: async () => [],
      getAgent: async () => detail, getTool: async () => detail, getIdentity: async () => detail, getRuntime: async () => detail,
      getAgentCapabilities, getAgentRelationships, listAgentSessions,
      updateAgent: async () => ({ agent: value, audit_id: ids.evidence }),
      getHomeSummary: async () => ({ agent_count: 1, high_risk_paths: 0, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false }),
    };
    render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={api} onNavigate={() => undefined} /></APIProvider>);
    await user.click(await screen.findByRole("button", { name: "Open First" }));
    for (const heading of ["Effective capabilities", "Relationships", "Sessions", "Runtime policy coverage"]) expect(await screen.findByRole("heading", { name: heading })).toBeVisible();
    expect(screen.getByText(/identity_assume.*blocked.*assume/)).toBeVisible();
    expect(screen.getByText(/uses_identity/)).toBeVisible();
    expect(screen.getByText(new RegExp(ids.session))).toBeVisible();
    expect(getAgentCapabilities).toHaveBeenCalledWith(ids.first, expect.any(AbortSignal));
    expect(getAgentRelationships).toHaveBeenCalledWith(ids.first, expect.any(AbortSignal));
    expect(listAgentSessions).toHaveBeenCalledWith(ids.first, expect.any(AbortSignal));
  });

  it("updates scoped ownership with canonical tags from the production drawer", async () => {
    const user = userEvent.setup();
    const value = summary(ids.first, "First");
    const detail = { summary: value, sources: [], evidence: [] } as never;
    const updateAgent = vi.fn(async (_id: string, _version: number, input: { owner: string; team: string; tags: readonly string[] }) => ({ agent: { ...value, ...input, version: 2 }, audit_id: ids.evidence }));
    const api: ProductionAgentSecurityAPI = {
      listAgents: async () => [value], listTools: async () => [], listIdentities: async () => [], listRuntimes: async () => [],
      getAgent: async () => detail, getTool: async () => detail, getIdentity: async () => detail, getRuntime: async () => detail,
      getAgentCapabilities: async () => [], getAgentRelationships: async () => [], listAgentSessions: async () => [], updateAgent,
      getHomeSummary: async () => ({ agent_count: 1, high_risk_paths: 0, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false }),
    };
    render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={api} canWrite onNavigate={() => undefined} /></APIProvider>);
    await user.click(await screen.findByRole("button", { name: "Open First" }));
    await user.type(await screen.findByLabelText("Owner"), "security");
    await user.type(screen.getByLabelText("Team"), "platform");
    await user.type(screen.getByRole("textbox", { name: /^Tags/ }), "production, critical");
    await user.click(screen.getByRole("button", { name: "Save ownership" }));
    await waitFor(() => expect(updateAgent).toHaveBeenCalledWith(ids.first, 1, { owner: "security", team: "platform", tags: ["critical", "production"] }, expect.stringMatching(/^agent_/)));
    expect(await screen.findByText("security · platform")).toBeVisible();
  });
});
