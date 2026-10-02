import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { APIProvider } from "../../api/APIProvider";
import { createAPIClient } from "../../../apps/web/api/client";
import { ProductionSessionsView } from "./RuntimeSessionsView";

const id = "pid_10000001-0000-4000-8000-000000000001";
const run = "pid_10000002-0000-4000-8000-000000000002";
const scope = { organizationID: id, workspaceID: id, environmentID: id };
const at = "2026-09-16T00:00:00Z";
function fixture(unattributed = false, fault = "") {
  const selected = unattributed ? "unattributed" : id;
  const summary = { id: selected, kind: unattributed ? "unattributed" : "runtime", workspace_id: id, environment_id: id, agent_id: unattributed ? null : id, principal_id: null, first_event_at: at, last_event_at: at, projected_at: at, event_count: 1, confidence_counts: { exact: unattributed ? 0 : 1, strong: 0, probable: 0, unattributed: unattributed ? 1 : 0 } };
  const reads: Request[] = [];
  const client = createAPIClient({ fetch: async request => {
    reads.push(request); const path = new URL(request.url).pathname;
    let body: unknown;
    if (path === "/api/v1/sessions") body = { items: [summary], page_info: { next_cursor: null, has_more: false }, search: { state: "current", pending_batches: 0, pending_batches_capped: false, quarantined_batches: 0, quarantined_batches_capped: false, last_indexed_at: at, oldest_pending_at: null, checked_at: at, selector_coverage: "observed_only" } };
    else if (path === `/api/v1/sessions/${selected}`) body = fault === "identity" ? { ...summary, id: run } : summary;
    else if (path === `/api/v1/sessions/${selected}/events`) {
      if (fault === "events") throw new Error("Unavailable event provider");
      body = { items: [{ id, session_id: unattributed ? null : fault === "event identity" ? run : id, agent_id: unattributed ? null : id, class: "runtime", action: "exec", label: "Observed runtime activity", evidence_id: id, source: "tetragon", confidence: unattributed ? "unattributed" : "exact", at, projected_at: at }], page_info: { next_cursor: null, has_more: false } };
    } else if (path === `/api/v1/security-agent-activity/session/${id}/runs`) body = { items: [{ id: run, agent_id: id, state: "queued", evidence_ids: [id], definition_version: 1, version: 1 }], coverage: "partial" };
    else throw new Error(`Unexpected read ${path}`);
    return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  } });
  return { client, reads, selected };
}

describe("runtime session related run integration", () => {
  it.each([true, false])("opens scoped related runs (direct=%s) and removes them after permission loss", async direct => {
    const { client, reads } = fixture(); const onNavigate = vi.fn();
    const view = render(<APIProvider client={client}><ProductionSessionsView client={client} canRevokeConsole={false} selectedID={direct ? id : undefined} activityScope={scope} canReadRuns onNavigate={onNavigate} /></APIProvider>);
    if (!direct) await userEvent.click(await screen.findByRole("button", { name: /Open runtime timeline/ }));
    await userEvent.click(await screen.findByRole("button", { name: `Open run ${run}` }));
    expect(onNavigate).toHaveBeenCalledWith(`/protect/security-agents?entity_id=${run}&organization_id=${id}&workspace_id=${id}&environment_id=${id}`);
    const relations = reads.filter(request => request.url.includes("/security-agent-activity/"));
    expect(relations).toHaveLength(1);
    expect(relations[0].headers.get("X-Zasp-Expected-Scope")).toBe(`${id}/${id}/${id}`);
    if (direct) expect(reads.some(request => new URL(request.url).pathname === "/api/v1/sessions")).toBe(false);
    view.rerender(<APIProvider client={client}><ProductionSessionsView client={client} canRevokeConsole={false} selectedID={direct ? id : undefined} activityScope={scope} canReadRuns={false} onNavigate={onNavigate} /></APIProvider>);
    expect(screen.queryByRole("button", { name: `Open run ${run}` })).not.toBeInTheDocument();
    expect(reads.filter(request => request.url.includes("/security-agent-activity/"))).toHaveLength(1);
  });
  it.each(["identity", "events", "event identity"])("does not read relations after invalid %s authority", async fault => {
    const { client, reads } = fixture(false, fault);
    render(<APIProvider client={client}><ProductionSessionsView client={client} canRevokeConsole={false} selectedID={id} activityScope={scope} canReadRuns onNavigate={vi.fn()} /></APIProvider>);
    expect(await screen.findByRole("alert")).toHaveTextContent("Runtime timeline could not be loaded");
    expect(reads.some(request => request.url.includes("/security-agent-activity/"))).toBe(false);
  });
  it("does not infer a session relationship for the unattributed collection", async () => {
    const { client, reads, selected } = fixture(true);
    render(<APIProvider client={client}><ProductionSessionsView client={client} canRevokeConsole={false} selectedID={selected} activityScope={scope} canReadRuns onNavigate={vi.fn()} /></APIProvider>);
    await screen.findByText("Observed runtime activity");
    expect(screen.queryByText("Related Security Agent runs")).not.toBeInTheDocument();
    expect(reads.some(request => request.url.includes("/security-agent-activity/"))).toBe(false);
  });
});
