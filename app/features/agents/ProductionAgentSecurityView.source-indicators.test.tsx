import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";

import { createAPIClient } from "../../../apps/web/api/client";
import type { InventoryDetail, InventorySummary } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { createProductionAgentSecurityAPI, ProductionAgentSecurityView } from "./ProductionAgentSecurityView";

const id = (n: number) => `pid_${n.toString(16).padStart(8, "0")}-0000-4000-8000-000000000001`;
function evidence(n: number) {
  return { id: id(n), checksum: `sha256:${"a".repeat(64)}`, media_type: "application/json", schema_version: "raw_v1", parser_version: "parser_v1", tool_version: "tool_v1", collected_at: "2026-08-19T00:00:00Z", size_bytes: 128 };
}
function detail(state: "fresh" | "stale"): InventoryDetail {
  const summary: InventorySummary = { id: id(1), name: "Source Agent", kind: "agent", owner: "security", team: "platform", tags: [], evidence_id: id(902), confidence_basis_points: 9500, first_seen: "2026-08-18T00:00:00Z", last_seen: "2026-08-19T01:02:03Z", observed_at: "2026-08-19T01:00:00Z", fresh_until: state === "stale" ? "2026-08-19T01:15:00Z" : "2099-08-19T01:15:00Z", freshness_state: state, version: 1 };
  return { summary, sources: [
    { integration_id: id(101), provider: "aws", source: "aws_resource", source_identifier: `sha256:${"b".repeat(64)}`, snapshot_id: id(201), generation: 3, evidence_id: id(901), confidence_basis_points: 9000, observed_at: "2026-08-18T00:00:00Z", fresh_until: state === "stale" ? "2099-08-18T01:15:00Z" : "2026-08-18T01:15:00Z", projection_version: 1, winning: false },
    { integration_id: id(102), provider: "kubernetes", source: "kubernetes_workload", source_identifier: `sha256:${"c".repeat(64)}`, snapshot_id: id(202), generation: 7, evidence_id: summary.evidence_id, confidence_basis_points: summary.confidence_basis_points, observed_at: summary.observed_at, fresh_until: summary.fresh_until, projection_version: 2, winning: true },
  ], evidence: [evidence(901), evidence(902)] };
}
function mount(value: InventoryDetail, blocked: boolean, refuse = false) {
  const requests: Request[] = [];
  const fetch = async (request: Request) => {
    requests.push(request); const path = new URL(request.url).pathname;
    if (path === "/api/v1/agents") return Response.json({ items: [value.summary], page_info: { has_more: false, next_cursor: null } });
    if (path === `/api/v1/agents/${value.summary.id}`) return refuse ? Response.json({ code: "permission_denied", message: "Detail unavailable", correlation_id: id(999), retryable: false }, { status: 403 }) : Response.json(value);
    const items = path.endsWith("/capabilities") && blocked ? [{ agent_id: value.summary.id, target_id: id(301), target_kind: "tool", category: "action_execute", outcome: "execute", state: "blocked", reachable: true, evidence_ids: [value.summary.evidence_id] }] : [];
    if (["capabilities", "relationships", "sessions"].some(suffix => path === `/api/v1/agents/${value.summary.id}/${suffix}`)) return Response.json({ items, page_info: { has_more: false, next_cursor: null } });
    throw new Error("Unexpected source-indicator request");
  };
  const api = createProductionAgentSecurityAPI(createAPIClient({ fetch }));
  render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={api} onNavigate={() => undefined} /></APIProvider>);
  return requests;
}
beforeEach(() => { window.history.replaceState({}, "", "/discovery/assets"); });

describe("M4-50c actual inventory-source indicators and coverage limits", () => {
  it.each([{ state: "stale", blocked: true }, { state: "fresh", blocked: false }] as const)("renders exact last-read source facts and mixed provenance without inferring runtime coverage ($state / blocked $blocked)", async ({ state, blocked }) => {
    const user = userEvent.setup(); const value = detail(state); const requests = mount(value, blocked);
    const open = await screen.findByRole("button", { name: "Open Source Agent" });
    const listRow = open.closest("tr")!;
    expect(within(listRow).getByText(`Source ${state} at last API read`)).toBeVisible();
    expect(within(listRow).getByText(value.summary.last_seen).closest("time")).toHaveAttribute("datetime", value.summary.last_seen);
    await user.click(open);
    expect(await screen.findByRole("dialog", { name: "Source Agent" })).toBeVisible();
    const provenance = screen.getByRole("region", { name: "Inventory source evidence" });
    const winner = within(provenance).getByText("Winning source").closest("tr")!;
    const additional = within(provenance).getByText("Additional source").closest("tr")!;
    for (const [source, element] of [[value.sources[1], winner], [value.sources[0], additional]] as const) {
      for (const text of [source.provider, source.source, source.snapshot_id, source.evidence_id, String(source.generation)]) expect(within(element).getByText(text, { exact: true })).toBeVisible();
      for (const stamp of [source.observed_at, source.fresh_until]) expect(within(element).getByText(stamp).closest("time")).toHaveAttribute("datetime", stamp);
    }
    // A nonwinning observation's opposite expiry never inherits the winner's status.
    expect(within(additional).queryByText(/Source (fresh|stale) at last API read/)).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Recorded blocking capability evidence" })).toBeVisible();
    expect(screen.getByText(blocked ? "1 recorded blocking capability." : "No blocking capability evidence recorded.")).toBeVisible();
    expect(screen.getByText("Policy coverage unavailable")).toBeVisible();
    expect(screen.getByText("Runtime sensor coverage unavailable")).toBeVisible();
    expect(screen.queryByText(/covered by active blocking evidence|healthy|protected/i)).not.toBeInTheDocument();
    await waitFor(() => expect(requests).toHaveLength(5));
    expect(requests.every(request => request.method === "GET" && new URL(request.url).pathname.startsWith("/api/v1/agents"))).toBe(true);
    expect(requests.filter(request => new URL(request.url).pathname === "/api/v1/agents")).toHaveLength(1);
  });

  it("keeps refused detail evidence unavailable without inventing provenance or reading sensors", async () => {
    const user = userEvent.setup(); const requests = mount(detail("stale"), true, true);
    await user.click(await screen.findByRole("button", { name: "Open Source Agent" }));
    expect(await screen.findByText("Inventory detail unavailable")).toBeVisible();
    expect(screen.queryByRole("region", { name: "Inventory source evidence" })).not.toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByText(/healthy|protected|covered by active blocking evidence/i)).not.toBeInTheDocument();
    expect(requests).toHaveLength(2);
  });
});
