import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import { APIProvider } from "../../api/APIProvider";
import { createProductionAgentSecurityAPI, inventoryDetailIDFromSearch, ProductionAgentSecurityView, type ProductionAgentSecurityAPI } from "./ProductionAgentSecurityView";

const ids = {
  first: "pid_10000001-0000-4000-8000-000000000001",
  second: "pid_10000002-0000-4000-8000-000000000002",
  evidence: "pid_20000001-0000-4000-8000-000000000001",
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

  it("reloads an exact stable detail URL and rejects ambiguous detail queries", async () => {
    const value = summary(ids.first, "First");
    const detail = { summary: value, sources: [], evidence: [] } as never;
    const getAgent = vi.fn(async () => detail);
    const api: ProductionAgentSecurityAPI = {
      listAgents: async () => [value], listTools: async () => [], listIdentities: async () => [], listRuntimes: async () => [],
      getAgent, getTool: async () => detail, getIdentity: async () => detail, getRuntime: async () => detail,
      getAgentCapabilities: async () => [], getAgentRelationships: async () => [], listAgentSessions: async () => [],
      getHomeSummary: async () => ({ agent_count: 1, high_risk_paths: 0, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false }),
    };
    window.history.replaceState({}, "", `/discovery/assets?inventory=${ids.first}`);
    render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={api} onNavigate={() => undefined} /></APIProvider>);
    expect(await screen.findByRole("dialog", { name: "First" })).toBeVisible();
    expect(getAgent).toHaveBeenCalledWith(ids.first, expect.any(AbortSignal));
    expect(inventoryDetailIDFromSearch(`?inventory=${ids.first}&extra=1`)).toBe("");
  });
});
