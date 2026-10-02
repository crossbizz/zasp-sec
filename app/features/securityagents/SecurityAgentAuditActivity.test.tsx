import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { APIProvider } from "../../api/APIProvider";
import { createAPIClient } from "../../../apps/web/api/client";
import { SecurityAgentAuditView } from "./SecurityAgentAuditView";

const scope = { organizationID: "pid_10000001-0000-4000-8000-000000000001", workspaceID: "pid_10000002-0000-4000-8000-000000000002", environmentID: "pid_10000003-0000-4000-8000-000000000003" };
const id = "pid_7b000003-0000-4000-8000-000000000003";
const run = "pid_7b000002-0000-4000-8000-000000000002";
const record = { id, run_id: run, organization_id: scope.organizationID, workspace_id: scope.workspaceID, environment_id: scope.environmentID, actor_reference: "worker-audit", event_kind: "run_queued", correlation_id: id, occurred_at: "2026-09-16T12:00:00.123456Z" };
const page = { items: [{ id: run, agent_id: id, state: "queued", evidence_ids: [id], definition_version: 1, version: 1 }], coverage: "complete" };
function json(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }); }

describe("audit detail relation integration", () => {
  it("reads reverse authority only after exact audit detail and opens its scoped run", async () => {
    const requests: Request[] = []; const onNavigate = vi.fn();
    const client = createAPIClient({ fetch: async request => { requests.push(request); return json(new URL(request.url).pathname.includes("/security-agent-activity/") ? page : record); } });
    render(<APIProvider client={client}><SecurityAgentAuditView auditID={id} scope={scope} permitted canReadRuns onNavigate={onNavigate} /></APIProvider>);
    await userEvent.click(await screen.findByRole("button", { name: `Open run ${run}` }));
    expect(requests.map(request => new URL(request.url).pathname)).toEqual([`/api/v1/security-agent-audit-events/${id}`, `/api/v1/security-agent-activity/audit/${id}/runs`]);
    expect(onNavigate).toHaveBeenCalledWith(`/protect/security-agents?entity_id=${run}&organization_id=${scope.organizationID}&workspace_id=${scope.workspaceID}&environment_id=${scope.environmentID}`);
  });
  it("removes loaded related runs without another request when run permission is revoked", async () => {
    const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => { requests.push(request); return json(new URL(request.url).pathname.includes("/security-agent-activity/") ? page : record); } });
    const view = render(<APIProvider client={client}><SecurityAgentAuditView auditID={id} scope={scope} permitted canReadRuns onNavigate={vi.fn()} /></APIProvider>);
    await screen.findByRole("button", { name: `Open run ${run}` });
    view.rerender(<APIProvider client={client}><SecurityAgentAuditView auditID={id} scope={scope} permitted canReadRuns={false} onNavigate={vi.fn()} /></APIProvider>);
    expect(screen.queryByRole("button", { name: `Open run ${run}` })).not.toBeInTheDocument();
    expect(screen.getByText("worker-audit")).toBeVisible();
    expect(requests).toHaveLength(2);
  });
  it.each([403, 404, 503])("does not read relations when audit detail fails with %s", async status => {
    const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => { requests.push(request); return json({ code: "unavailable", message: "Private detail", correlation_id: id, retryable: false }, status); } });
    render(<APIProvider client={client}><SecurityAgentAuditView auditID={id} scope={scope} permitted canReadRuns onNavigate={vi.fn()} /></APIProvider>);
    await screen.findByRole("alert");
    await waitFor(() => expect(requests).toHaveLength(1));
    expect(screen.queryByText("Related Security Agent runs")).not.toBeInTheDocument();
  });
  it("aborts a pending relation when a detail reload fails and ignores the late response", async () => {
    let resolve!: (value: Response) => void;
    const pending = new Promise<Response>(done => { resolve = done; });
    let relation: Request | undefined; let detailReads = 0;
    const client = createAPIClient({ fetch: async request => {
      if (new URL(request.url).pathname.includes("/security-agent-activity/")) { relation = request; return pending; }
      return ++detailReads === 1 ? json(record) : json({ code: "forbidden", message: "Private detail", correlation_id: id, retryable: false }, 403);
    } });
    render(<APIProvider client={client}><SecurityAgentAuditView auditID={id} scope={scope} permitted canReadRuns onNavigate={vi.fn()} /></APIProvider>);
    await waitFor(() => expect(relation).toBeDefined());
    await userEvent.click(screen.getByRole("button", { name: "Reload audit record" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Audit access denied");
    await waitFor(() => expect(relation!.signal.aborted).toBe(true));
    await act(async () => resolve(json(page)));
    expect(screen.queryByRole("button", { name: `Open run ${run}` })).not.toBeInTheDocument();
    expect(screen.queryByText("Related Security Agent runs")).not.toBeInTheDocument();
  });
});
