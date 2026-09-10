import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import type { RuntimeSessionPage } from "../../../apps/web/api/generated";
import { createRuntimeSessionsAPI, ProductionSessionsView, RuntimeSessionsView, type RuntimeSessionsAPI } from "./RuntimeSessionsView";
import type { RuntimeSessionTimelineAPI } from "./RuntimeSessionTimeline";

const id = "pid_10000001-0000-4000-8000-000000000001";
const at = "2026-09-09T10:00:00Z";
const item = { id: "unattributed", kind: "unattributed", workspace_id: id, environment_id: id, agent_id: null, principal_id: null, first_event_at: at, last_event_at: at, projected_at: at, event_count: 1, confidence_counts: { exact: 0, strong: 0, probable: 0, unattributed: 1 } } as const;
const page = (items: RuntimeSessionPage["items"] = [item]): RuntimeSessionPage => ({ items, page_info: { next_cursor: null, has_more: false }, search: { state: "current", pending_batches: 0, pending_batches_capped: false, quarantined_batches: 0, quarantined_batches_capped: false, last_indexed_at: at, oldest_pending_at: null, checked_at: at, selector_coverage: "observed_only" } });

describe("production runtime Sessions list", () => {
  it("uses a bounded runtime API page with all structured selectors and cancellation", async () => {
    const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => { requests.push(request); return new Response(JSON.stringify(page()), { headers: { "content-type": "application/json" } }); } });
    const api = createRuntimeSessionsAPI(client);
    const filters = { agent_id: id, principal_id: id, tool: "read_file", process: "/bin/agent", file: "/data/report", domain: "api.example.com", credential_id: id, resource: "report", decision: "allow" as const, from: at, to: at };
    expect(await api.list(filters, null, new AbortController().signal)).toEqual(page());
    const query = new URL(requests[0].url).searchParams;
    expect(query.get("kind")).toBe("runtime"); expect(query.get("limit")).toBe("25");
    for (const [key, value] of Object.entries(filters)) expect(query.get(key)).toBe(value);
    expect(requests).toHaveLength(1);
  });

  it("rejects successful API pages without indexing status", async () => {
    const missing = { ...page() }; delete missing.search;
    const client = createAPIClient({ fetch: async () => new Response(JSON.stringify(missing), { headers: { "content-type": "application/json" } }) });
    await expect(createRuntimeSessionsAPI(client).list({}, null, new AbortController().signal)).rejects.toThrow("checkpoint is missing");
  });

  it("starts with runtime investigations and keeps console logins separate", async () => {
    const queries: URLSearchParams[] = [];
    const client = createAPIClient({ fetch: async request => {
      const query = new URL(request.url).searchParams; queries.push(query);
      return new Response(JSON.stringify(query.get("kind") === "runtime" ? page() : { items: [], page_info: { next_cursor: null, has_more: false } }), { headers: { "content-type": "application/json" } });
    } });
    render(<ProductionSessionsView client={client} canRevokeConsole={false} />);
    await screen.findByText("Unattributed evidence");
    expect(queries[0].get("kind")).toBe("runtime");
    await userEvent.click(screen.getByRole("button", { name: "Console logins" }));
    expect(await screen.findByRole("heading", { name: "Console login sessions" })).toBeVisible();
    expect(screen.queryByText("Unattributed evidence")).not.toBeInTheDocument();
    expect(queries).toHaveLength(2);
  });

  it("renders honest unknown attribution and searches only on submit", async () => {
    const list = vi.fn<RuntimeSessionsAPI["list"]>().mockResolvedValue(page());
    render(<RuntimeSessionsView api={{ list }} />);
    expect(await screen.findByText("Unattributed evidence")).toBeVisible();
    expect(screen.getByText(/Unknown or multiple agents/)).toBeVisible();
    expect(screen.getByText(/Observed metadata only/)).toBeVisible();
    expect(screen.queryByRole("button", { name: /Revoke/ })).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Process"), "/bin/agent");
    expect(list).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole("button", { name: "Search sessions" }));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(list.mock.calls[1][0]).toEqual({ process: "/bin/agent" });
    expect(list.mock.calls[1][1]).toBeNull();
  });

  it("keeps indexing backlog visible when no sessions match and never calls it complete", async () => {
    const result: RuntimeSessionPage = { ...page([]), search: { ...page().search!, state: "catching_up", pending_batches: 1000, pending_batches_capped: true, oldest_pending_at: at } };
    render(<RuntimeSessionsView api={{ list: async () => result }} />);
    expect(await screen.findByText("No matching runtime sessions")).toBeVisible();
    expect(screen.getByText(/1,000\+ pending batches/)).toBeVisible();
    expect(screen.getByText(/Indexing is catching up/)).toBeVisible();
    expect(screen.queryByText(/All activity indexed/)).not.toBeInTheDocument();
  });

  it("does not turn unavailable search into empty results", async () => {
    render(<RuntimeSessionsView api={{ list: async () => { throw new Error("secret provider detail"); } }} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Runtime sessions could not be loaded");
    expect(screen.queryByText("No matching runtime sessions")).not.toBeInTheDocument();
    expect(screen.queryByText(/secret provider detail/)).not.toBeInTheDocument();
  });

  it("loads one next page, preserves filters and starts over when filters change", async () => {
    const first: RuntimeSessionPage = { ...page(), page_info: { next_cursor: "cursor_one", has_more: true } };
    const list = vi.fn<RuntimeSessionsAPI["list"]>().mockResolvedValueOnce(first).mockResolvedValue(page([]));
    render(<RuntimeSessionsView api={{ list }} />);
    await screen.findByText("Unattributed evidence");
    expect(list).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole("button", { name: "Next session page" }));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(list.mock.calls[1][1]).toBe("cursor_one");
    await userEvent.type(screen.getByLabelText("Tool"), "read_file");
    await userEvent.click(screen.getByRole("button", { name: "Search sessions" }));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(3));
    expect(list.mock.calls[2].slice(0, 2)).toEqual([{ tool: "read_file" }, null]);
  });

  it("discards a late response when the scoped API changes", async () => {
    let finish!: (value: RuntimeSessionPage) => void;
    const old = vi.fn<RuntimeSessionsAPI["list"]>(() => new Promise(resolve => { finish = resolve; }));
    const view = render(<RuntimeSessionsView api={{ list: old }} />);
    await waitFor(() => expect(old).toHaveBeenCalledTimes(1));
    view.rerender(<RuntimeSessionsView api={{ list: async () => page([]) }} />);
    await screen.findByText("No matching runtime sessions");
    expect(old.mock.calls[0][2].aborted).toBe(true);
    await act(async () => finish(page()));
    expect(screen.queryByText("Unattributed evidence")).not.toBeInTheDocument();
  });

  it("opens an authorized timeline and closes it when the submitted search changes", async () => {
    const timelineAPI: RuntimeSessionTimelineAPI = {
      get: async () => item,
      events: async () => ({ items: [{ id, session_id: null, agent_id: null, class: "runtime", action: "exec", label: "Worker evidence", evidence_id: id, source: "tetragon", confidence: "unattributed", at, projected_at: at }], page_info: { next_cursor: null, has_more: false } }),
    };
    render(<RuntimeSessionsView api={{ list: async () => page() }} timelineAPI={timelineAPI} />);
    await screen.findByText("Unattributed evidence");
    await userEvent.click(screen.getByRole("button", { name: "Open runtime timeline unattributed" }));
    expect(await screen.findByText("Worker evidence")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Open runtime timeline unattributed" }));
    await screen.findByText("Worker evidence");
    // Changing a query while an overlay is open is also possible through a
    // programmatic scope/query transition, not only pointer input.
    await act(async () => screen.getByRole("button", { name: "Search sessions", hidden: true }).click());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
