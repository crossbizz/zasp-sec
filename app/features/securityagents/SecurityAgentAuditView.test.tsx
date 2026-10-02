import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { APIProvider, useAPI } from "../../api/APIProvider";
import { createAPIClient as baseClient } from "../../../apps/web/api/client";
import { SecurityAgentAuditView } from "./SecurityAgentAuditView";

const scope = { organizationID: "pid_10000001-0000-4000-8000-000000000001", workspaceID: "pid_10000002-0000-4000-8000-000000000002", environmentID: "pid_10000003-0000-4000-8000-000000000003" };
const id = "pid_7b000003-0000-4000-8000-000000000003";
const second = "pid_7b000099-0000-4000-8000-000000000099";
const run = "pid_7b000002-0000-4000-8000-000000000002";
// These tests track exact-record reads; relation integration has its own suite.
function createAPIClient(options: { fetch(request: Request): Promise<Response> }) {
  return baseClient({ fetch: request => new URL(request.url).pathname.includes("/security-agent-activity/")
    ? Promise.resolve(new Response(JSON.stringify({ items: [], coverage: "complete" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }))
    : options.fetch(request) });
}
function response(actor = "worker-audit", recordID = id) { return new Response(JSON.stringify({ id: recordID, run_id: run, organization_id: scope.organizationID, workspace_id: scope.workspaceID, environment_id: scope.environmentID, actor_reference: actor, event_kind: "run_queued", correlation_id: second, occurred_at: "2026-09-16T12:00:00.123456Z" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }); }
function Suspend() { const api = useAPI(); return <button onClick={() => api.suspendQueryCache()}>Suspend scope</button>; }

describe("exact Security Agent audit detail", () => {
  it("reads a record directly and links its authoritative run with exact scope", async () => {
    const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => { requests.push(request); return response(); } });
    const onNavigate = vi.fn();
    render(<APIProvider client={client}><SecurityAgentAuditView auditID={id} scope={scope} permitted canReadRuns onNavigate={onNavigate} /></APIProvider>);
    expect(await screen.findByText("worker-audit")).toBeVisible();
    expect(screen.getByText("Actor reference")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Open Security Agent run" }));
    expect(onNavigate).toHaveBeenCalledWith(`/protect/security-agents?entity_id=${run}&organization_id=${scope.organizationID}&workspace_id=${scope.workspaceID}&environment_id=${scope.environmentID}`);
    expect(requests.map(request => new URL(request.url).pathname)).toEqual([`/api/v1/security-agent-audit-events/${id}`]);
  });
  it("refuses reads without audit permission", () => {
    const fetcher = vi.fn(async () => response());
    render(<APIProvider client={createAPIClient({ fetch: fetcher })}><SecurityAgentAuditView auditID={id} scope={scope} permitted={false} canReadRuns onNavigate={vi.fn()} /></APIProvider>);
    expect(screen.getByRole("alert")).toHaveTextContent("Audit access denied");
    expect(fetcher).not.toHaveBeenCalled();
  });
  it("immediately hides a loaded record when audit permission is removed", async () => {
    const client = createAPIClient({ fetch: async () => response() });
    const view = render(<APIProvider client={client}><SecurityAgentAuditView auditID={id} scope={scope} permitted canReadRuns onNavigate={vi.fn()} /></APIProvider>);
    await screen.findByText("worker-audit");
    view.rerender(<APIProvider client={client}><SecurityAgentAuditView auditID={id} scope={scope} permitted={false} canReadRuns onNavigate={vi.fn()} /></APIProvider>);
    expect(screen.getByRole("alert")).toHaveTextContent("Audit access denied");
    expect(screen.queryByText("worker-audit")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Open Security Agent run" })).not.toBeInTheDocument();
  });
  it("hides records and aborts reads when scope is suspended", async () => {
    const requests: Request[] = []; let resolve!: (value: Response) => void;
    const pending = new Promise<Response>(done => { resolve = done; });
    const client = createAPIClient({ fetch: async request => { requests.push(request); return requests.length === 1 ? response() : pending; } });
    render(<APIProvider client={client}><Suspend /><SecurityAgentAuditView auditID={id} scope={scope} permitted canReadRuns onNavigate={vi.fn()} /></APIProvider>);
    await screen.findByText("worker-audit");
    await userEvent.click(screen.getByRole("button", { name: "Reload audit record" }));
    await waitFor(() => expect(requests).toHaveLength(2));
    await userEvent.click(screen.getByRole("button", { name: "Suspend scope" }));
    expect(screen.queryByText("worker-audit")).not.toBeInTheDocument();
    await waitFor(() => expect(requests[1].signal.aborted).toBe(true));
    await act(async () => resolve(response("late-worker")));
    expect(screen.queryByText("late-worker")).not.toBeInTheDocument();
  });
  it("replaces selected IDs and ignores the earlier response", async () => {
    let resolve!: (value: Response) => void; const pending = new Promise<Response>(done => { resolve = done; });
    const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => { requests.push(request); return request.url.endsWith(id) ? pending : response("second-worker", second); } });
    const view = render(<APIProvider client={client}><SecurityAgentAuditView auditID={id} scope={scope} permitted canReadRuns={false} onNavigate={vi.fn()} /></APIProvider>);
    await waitFor(() => expect(requests).toHaveLength(1));
    view.rerender(<APIProvider client={client}><SecurityAgentAuditView auditID={second} scope={scope} permitted canReadRuns={false} onNavigate={vi.fn()} /></APIProvider>);
    expect(await screen.findByText("second-worker")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Open Security Agent run" })).not.toBeInTheDocument();
    await act(async () => resolve(response("late-worker")));
    expect(screen.queryByText("late-worker")).not.toBeInTheDocument();
  });
  it.each([403, 404, 503])("hides previously loaded authority after a %s reload", async status => {
    let reads = 0;
    const client = createAPIClient({ fetch: async () => ++reads === 1 ? response() : new Response(JSON.stringify({ code: status === 403 ? "forbidden" : status === 404 ? "not_found" : "service_unavailable", message: "Private failure detail must not be rendered", correlation_id: second, retryable: false }), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }) });
    render(<APIProvider client={client}><SecurityAgentAuditView auditID={id} scope={scope} permitted canReadRuns onNavigate={vi.fn()} /></APIProvider>);
    await screen.findByText("worker-audit");
    await userEvent.click(screen.getByRole("button", { name: "Reload audit record" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(status === 403 ? "Audit access denied" : status === 404 ? "Audit record not found" : "Audit detail is unavailable");
    expect(screen.queryByText("worker-audit")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Open Security Agent run" })).not.toBeInTheDocument();
    expect(screen.queryByText("Private failure detail must not be rendered")).not.toBeInTheDocument();
  });
});
