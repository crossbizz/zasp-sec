import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { APIProductError, APITransportError } from "../../../apps/web/api/client";
import type { InventoryDetail, InventorySummary } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { ProductionAgentSecurityView, type ProductionAgentSecurityAPI } from "./ProductionAgentSecurityView";

const firstID = "pid_10000001-0000-4000-8000-000000000001";
const secondID = "pid_10000002-0000-4000-8000-000000000002";
const evidenceID = "pid_20000001-0000-4000-8000-000000000001";
const observed = "2026-08-19T01:00:00Z";
const freshUntil = "2026-08-19T01:15:00Z";

function agent(id: string, name: string): InventorySummary {
  return { id, name, kind: "agent", owner: "old-owner", team: "old-team", tags: [], evidence_id: evidenceID, confidence_basis_points: 9500, first_seen: observed, last_seen: observed, observed_at: observed, fresh_until: freshUntil, freshness_state: "fresh", version: 1 };
}

function detail(summary: InventorySummary): InventoryDetail {
  return {
    summary,
    sources: [{ integration_id: "pid_30000001-0000-4000-8000-000000000001", provider: "kubernetes", source: "kubernetes", source_identifier: `sha256:${"b".repeat(64)}`, snapshot_id: "pid_40000001-0000-4000-8000-000000000001", generation: 1, evidence_id: evidenceID, confidence_basis_points: 9500, observed_at: observed, fresh_until: freshUntil, projection_version: 1, winning: true }],
    evidence: [{ id: evidenceID, checksum: `sha256:${"a".repeat(64)}`, media_type: "application/json", schema_version: "raw_v1", parser_version: "parser_v1", tool_version: "tool_v1", collected_at: observed, size_bytes: 128 }],
  };
}

function inventoryAPI(rows: Map<string, InventorySummary>, updateAgent: ProductionAgentSecurityAPI["updateAgent"]): ProductionAgentSecurityAPI {
  const unavailable = async (): Promise<never> => { throw new Error("Unexpected inventory operation"); };
  return {
    listAgents: async () => [...rows.values()], listTools: unavailable, listIdentities: unavailable, listRuntimes: unavailable,
    getAgent: async (id) => { const row = rows.get(id); if (!row) throw new Error("Unknown agent"); return detail(row); },
    getTool: unavailable, getIdentity: unavailable, getRuntime: unavailable,
    getAgentCapabilities: async () => [], getAgentRelationships: async () => [], listAgentSessions: async () => [],
    updateAgent, getHomeSummary: unavailable,
  };
}

async function enterOwnership(user: ReturnType<typeof userEvent.setup>, owner: string) {
  await user.clear(screen.getByLabelText("Owner"));
  await user.type(screen.getByLabelText("Owner"), owner);
  await user.clear(screen.getByLabelText("Team"));
  await user.type(screen.getByLabelText("Team"), "platform");
  await user.type(screen.getByRole("textbox", { name: /^Tags/ }), "production, critical");
}

describe("inventory ownership retries", () => {
  // Break caught: a component-wide pending request lets B replay A and replaces
  // B's detail with A's summary; dropping that request loses A's exact replay.
  it.each([
    ["network loss", new TypeError("Response lost")],
    ["timeout", new APITransportError("timeout", "Response lost")],
    ["service unavailable", new APIProductError(503, { code: "dependency_unavailable", message: "Unavailable", retryable: true, correlation_id: evidenceID })],
  ])("keeps an accepted but unobserved A mutation recoverable while editing B after %s", async (_label, failure) => {
    window.history.replaceState({}, "", "/discovery/assets");
    const user = userEvent.setup();
    const rows = new Map([[firstID, agent(firstID, "First")], [secondID, agent(secondID, "Second")]]);
    const requests: Parameters<ProductionAgentSecurityAPI["updateAgent"]>[] = [];
    const api = inventoryAPI(rows, async (...request) => {
      requests.push(request);
      const [id, , input] = request;
      if (requests.length === 1) {
        rows.set(id, { ...rows.get(id)!, ...input, version: 2 });
        throw failure;
      }
      if (id === firstID) expect(request).toEqual(requests[0]);
      else rows.set(id, { ...rows.get(id)!, ...input, version: 2 });
      return { agent: rows.get(id)!, audit_id: evidenceID };
    });
    render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={api} canWrite onNavigate={() => undefined} /></APIProvider>);
    await user.click(await screen.findByRole("button", { name: "Open First" }));
    await screen.findByRole("dialog", { name: "First" });
    await enterOwnership(user, "first-owner");
    await user.click(screen.getByRole("button", { name: "Save ownership" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/interrupted/i);
    await user.click(screen.getByRole("button", { name: "Close" }));
    await user.click(screen.getByRole("button", { name: "Open Second" }));
    await screen.findByRole("dialog", { name: "Second" });
    expect(screen.getByLabelText("Owner")).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Retry ownership change" })).not.toBeInTheDocument();
    await enterOwnership(user, "second-owner");
    await user.click(screen.getByRole("button", { name: "Save ownership" }));
    expect(await within(screen.getByRole("dialog", { name: "Second" })).findByText("second-owner · platform")).toBeVisible();
    expect(requests[1].slice(0, 3)).toEqual([secondID, 1, { owner: "second-owner", team: "platform", tags: ["critical", "production"] }]);
    expect(requests[1][3]).not.toBe(requests[0][3]);
    await user.click(screen.getByRole("button", { name: "Close" }));
    await user.click(screen.getByRole("button", { name: "Open First" }));
    await screen.findByRole("dialog", { name: "First" });
    expect(screen.getByLabelText("Owner")).toBeDisabled();
    expect(screen.getByLabelText("Owner")).toHaveValue("first-owner");
    await user.click(screen.getByRole("button", { name: "Retry ownership change" }));
    expect(await screen.findByRole("button", { name: "Save ownership" })).toBeEnabled();
    expect(requests).toHaveLength(3);
    expect(requests[2]).toEqual(requests[0]);
    expect(requests[2].slice(0, 3)).toEqual([firstID, 1, { owner: "first-owner", team: "platform", tags: ["critical", "production"] }]);
    expect(screen.getByRole("dialog", { name: "First" })).toHaveTextContent("first-owner · platform");
  });

  // Break caught: definitive rejections are labelled interruptions and leave
  // the editor locked forever to an already rejected idempotency key.
  it.each([403, 404])("clears an ambiguous retry after a definitive %s rejection", async (status) => {
    window.history.replaceState({}, "", "/discovery/assets");
    const user = userEvent.setup();
    const rows = new Map([[firstID, agent(firstID, "First")]]);
    const requests: Parameters<ProductionAgentSecurityAPI["updateAgent"]>[] = [];
    const api = inventoryAPI(rows, async (...request) => {
      requests.push(request);
      if (requests.length === 1) throw new TypeError("Response lost");
      if (requests.length === 2) throw new APIProductError(status, { code: status === 403 ? "authorization_rejected" : "not_found", message: "Rejected", retryable: false, correlation_id: evidenceID });
      return { agent: { ...rows.get(firstID)!, ...request[2], version: 2 }, audit_id: evidenceID };
    });
    render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={api} canWrite onNavigate={() => undefined} /></APIProvider>);
    await user.click(await screen.findByRole("button", { name: "Open First" }));
    await screen.findByRole("dialog", { name: "First" });
    await enterOwnership(user, "first-owner");
    await user.click(screen.getByRole("button", { name: "Save ownership" }));
    await user.click(await screen.findByRole("button", { name: "Retry ownership change" }));
    expect(requests[1]).toEqual(requests[0]);
    expect(screen.getByRole("alert")).not.toHaveTextContent(/interrupted/i);
    expect(screen.getByLabelText("Owner")).toBeEnabled();
    await user.clear(screen.getByLabelText("Owner"));
    await user.type(screen.getByLabelText("Owner"), "revised-owner");
    await user.click(screen.getByRole("button", { name: "Save ownership" }));
    expect(await screen.findByText("revised-owner · platform")).toBeVisible();
    expect(requests[2][3]).not.toBe(requests[0][3]);
    expect(requests[2][2].owner).toBe("revised-owner");
  });
});
