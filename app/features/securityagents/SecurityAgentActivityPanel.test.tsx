import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { APIProvider, useAPI } from "../../api/APIProvider";
import { createAPIClient } from "../../../apps/web/api/client";
import { SecurityAgentActivityPanel } from "./SecurityAgentActivityPanel";

const scope = { organizationID: "pid_10000001-0000-4000-8000-000000000001", workspaceID: "pid_10000002-0000-4000-8000-000000000002", environmentID: "pid_10000003-0000-4000-8000-000000000003" };
const id = "pid_78000005-0000-4000-8000-000000000005";
const other = "pid_78000009-0000-4000-8000-000000000009";
function response(items: unknown[], coverage = "complete", next?: string) { return new Response(JSON.stringify({ items, coverage, ...(next ? { next_cursor: next } : {}) }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }); }
function Suspend() { const api = useAPI(); return <button onClick={() => api.suspendQueryCache()}>Suspend scope</button>; }

describe("Security Agent activity panel", () => {
  it("opens exact scoped forward targets and distinguishes incomplete coverage", async () => {
    const onNavigate = vi.fn(); const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => { requests.push(request); return response([{ kind: "finding", id: other }], "partial"); } });
    render(<APIProvider client={client}><SecurityAgentActivityPanel direction="targets" kind="finding" entityID={id} scope={scope} permitted onNavigate={onNavigate} /></APIProvider>);
    await userEvent.click(await screen.findByRole("button", { name: `Open finding ${other}` }));
    expect(onNavigate).toHaveBeenCalledWith(`/violations?entity_id=${other}&organization_id=${scope.organizationID}&workspace_id=${scope.workspaceID}&environment_id=${scope.environmentID}`);
    expect(screen.getByText(/Coverage is incomplete/)).toBeVisible();
    expect(new URL(requests[0].url).pathname).toBe(`/api/v1/security-agent-runs/${id}/activity/finding`);
  });
  it("reads reverse runs without scanning the general run list", async () => {
    const onNavigate = vi.fn(); const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => { requests.push(request); return response([{ id: other, agent_id: id, state: "queued", evidence_ids: [id], definition_version: 1, version: 1 }]); } });
    render(<APIProvider client={client}><SecurityAgentActivityPanel direction="runs" kind="session" entityID={id} scope={scope} permitted onNavigate={onNavigate} /></APIProvider>);
    await userEvent.click(await screen.findByRole("button", { name: `Open run ${other}` }));
    expect(onNavigate.mock.calls[0][0]).toContain(`/protect/security-agents?entity_id=${other}`);
    expect(requests).toHaveLength(1); expect(new URL(requests[0].url).pathname).toBe(`/api/v1/security-agent-activity/session/${id}/runs`);
  });
  it("makes no request without permission", () => {
    const fetcher = vi.fn(async () => response([]));
    render(<APIProvider client={createAPIClient({ fetch: fetcher })}><SecurityAgentActivityPanel direction="runs" kind="audit" entityID={id} scope={scope} permitted={false} onNavigate={vi.fn()} /></APIProvider>);
    expect(screen.getByRole("alert")).toHaveTextContent("Related activity access denied"); expect(fetcher).not.toHaveBeenCalled();
  });
  it("hides links and aborts pending reads when scope is suspended", async () => {
    const requests: Request[] = []; let resolve!: (value: Response) => void;
    const pending = new Promise<Response>(done => { resolve = done; });
    const client = createAPIClient({ fetch: async request => { requests.push(request); return requests.length === 1 ? response([{ kind: "finding", id: other }]) : pending; } });
    render(<APIProvider client={client}><Suspend /><SecurityAgentActivityPanel direction="targets" kind="finding" entityID={id} scope={scope} permitted onNavigate={vi.fn()} /></APIProvider>);
    await screen.findByRole("button", { name: `Open finding ${other}` });
    await userEvent.click(screen.getByRole("button", { name: "Reload related activity" }));
    await waitFor(() => expect(requests).toHaveLength(2));
    await userEvent.click(screen.getByRole("button", { name: "Suspend scope" }));
    expect(screen.queryByRole("button", { name: `Open finding ${other}` })).not.toBeInTheDocument();
    await waitFor(() => expect(requests[1].signal.aborted).toBe(true));
    await act(async () => resolve(response([{ kind: "finding", id: other }])));
    expect(screen.queryByRole("button", { name: `Open finding ${other}` })).not.toBeInTheDocument();
  });
  it("pages next and previous without keeping links from the other page", async () => {
    const items = Array.from({ length: 20 }, (_, index) => ({ kind: "finding", id: `pid_7900${index.toString(16).padStart(4, "0")}-0000-4000-8000-${index.toString(16).padStart(12, "0")}` }));
    const last = "pid_7a000099-0000-4000-8000-000000000099"; const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => { requests.push(request); return new URL(request.url).searchParams.has("cursor") ? response([{ kind: "finding", id: last }]) : response(items, "complete", "abc"); } });
    render(<APIProvider client={client}><SecurityAgentActivityPanel direction="targets" kind="finding" entityID={id} scope={scope} permitted onNavigate={vi.fn()} /></APIProvider>);
    await screen.findByRole("button", { name: `Open finding ${items[0].id}` });
    expect(screen.getByRole("button", { name: "Previous related page" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Next related page" }));
    await screen.findByRole("button", { name: `Open finding ${last}` });
    expect(screen.queryByRole("button", { name: `Open finding ${items[0].id}` })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next related page" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Previous related page" }));
    await screen.findByRole("button", { name: `Open finding ${items[0].id}` });
    expect(requests.map(request => new URL(request.url).searchParams.get("cursor"))).toEqual([null, "abc", null]);
  });
  it.each([403, 404, 503])("hides prior links after a %s reload and never renders raw errors", async status => {
    let reads = 0;
    const client = createAPIClient({ fetch: async () => ++reads === 1 ? response([{ kind: "finding", id: other }]) : new Response(JSON.stringify({ code: status === 403 ? "forbidden" : status === 404 ? "not_found" : "service_unavailable", message: "Private failure detail", correlation_id: id, retryable: false }), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }) });
    render(<APIProvider client={client}><SecurityAgentActivityPanel direction="targets" kind="finding" entityID={id} scope={scope} permitted onNavigate={vi.fn()} /></APIProvider>);
    await screen.findByRole("button", { name: `Open finding ${other}` });
    await userEvent.click(screen.getByRole("button", { name: "Reload related activity" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(status === 403 ? "access denied" : status === 404 ? "not found" : "unavailable");
    expect(screen.queryByRole("button", { name: `Open finding ${other}` })).not.toBeInTheDocument();
    expect(screen.queryByText("Private failure detail")).not.toBeInTheDocument();
  });
  it("hides a loaded page immediately when permission is removed", async () => {
    const client = createAPIClient({ fetch: async () => response([{ kind: "finding", id: other }]) });
    const view = render(<APIProvider client={client}><SecurityAgentActivityPanel direction="targets" kind="finding" entityID={id} scope={scope} permitted onNavigate={vi.fn()} /></APIProvider>);
    await screen.findByRole("button", { name: `Open finding ${other}` });
    view.rerender(<APIProvider client={client}><SecurityAgentActivityPanel direction="targets" kind="finding" entityID={id} scope={scope} permitted={false} onNavigate={vi.fn()} /></APIProvider>);
    expect(screen.getByRole("alert")).toHaveTextContent("access denied");
    expect(screen.queryByRole("button", { name: `Open finding ${other}` })).not.toBeInTheDocument();
  });
  it("keeps incomplete empty coverage explicit", async () => {
    render(<APIProvider client={createAPIClient({ fetch: async () => response([], "partial") })}><SecurityAgentActivityPanel direction="targets" kind="finding" entityID={id} scope={scope} permitted onNavigate={vi.fn()} /></APIProvider>);
    expect(await screen.findByText("No verified links on this page.")).toBeVisible();
    expect(screen.getByText(/Coverage is incomplete/)).toBeVisible();
    expect(screen.queryByText("No related records on this page.")).not.toBeInTheDocument();
  });
  it("replaces record identity and refuses a late response for the old record", async () => {
    let resolve!: (value: Response) => void; const pending = new Promise<Response>(done => { resolve = done; }); const requests: Request[] = [];
    const late = "pid_7a000099-0000-4000-8000-000000000099";
    const client = createAPIClient({ fetch: async request => { requests.push(request); return requests.length === 1 ? pending : response([{ kind: "finding", id }]); } });
    const view = render(<APIProvider client={client}><SecurityAgentActivityPanel direction="targets" kind="finding" entityID={id} scope={scope} permitted onNavigate={vi.fn()} /></APIProvider>);
    await waitFor(() => expect(requests).toHaveLength(1));
    view.rerender(<APIProvider client={client}><SecurityAgentActivityPanel direction="targets" kind="finding" entityID={other} scope={scope} permitted onNavigate={vi.fn()} /></APIProvider>);
    await screen.findByRole("button", { name: `Open finding ${id}` });
    expect(requests[0].signal.aborted).toBe(true);
    await act(async () => resolve(response([{ kind: "finding", id: late }])));
    expect(screen.queryByRole("button", { name: `Open finding ${late}` })).not.toBeInTheDocument();
  });
  it("disables navigation while the containing detail is mutation-locked", async () => {
    const onNavigate = vi.fn();
    render(<APIProvider client={createAPIClient({ fetch: async () => response([{ kind: "finding", id: other }]) })}><SecurityAgentActivityPanel direction="targets" kind="finding" entityID={id} scope={scope} permitted disabled onNavigate={onNavigate} /></APIProvider>);
    const link = await screen.findByRole("button", { name: `Open finding ${other}` });
    expect(link).toBeDisabled(); await userEvent.click(link); expect(onNavigate).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Reload related activity" })).toBeDisabled();
  });
  it("refuses a cursor cycle instead of allowing repeated pages", async () => {
    const items = Array.from({ length: 20 }, (_, index) => ({ kind: "finding", id: `pid_7900${index.toString(16).padStart(4, "0")}-0000-4000-8000-${index.toString(16).padStart(12, "0")}` }));
    const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => { requests.push(request); const cursor = new URL(request.url).searchParams.get("cursor"); return response(items, "complete", cursor === "abc" ? "def" : "abc"); } });
    render(<APIProvider client={client}><SecurityAgentActivityPanel direction="targets" kind="finding" entityID={id} scope={scope} permitted onNavigate={vi.fn()} /></APIProvider>);
    await screen.findByRole("button", { name: `Open finding ${items[0].id}` });
    await userEvent.click(screen.getByRole("button", { name: "Next related page" }));
    await waitFor(() => expect(requests).toHaveLength(2));
    await waitFor(() => expect(screen.getByRole("button", { name: "Next related page" })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: "Next related page" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("unavailable");
    expect(screen.queryByRole("button", { name: `Open finding ${items[0].id}` })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next related page" })).toBeDisabled();
  });
});
