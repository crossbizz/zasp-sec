import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useLayoutEffect, useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { APIProductError, createAPIClient } from "../../../apps/web/api/client";
import type { InventoryPage, InventorySummary } from "../../../apps/web/api/generated";
import { APIProvider, useAPI } from "../../api/APIProvider";
import { createProductionAgentSecurityAPI, ProductionAgentSecurityView, type ProductionAgentSecurityAPI } from "./ProductionAgentSecurityView";

// The expected additive adapter capability is structural so the published
// implementation compiles before it exists. There is no runtime fallback.
type PageAPI = ProductionAgentSecurityAPI & {
  listAgentsPage(cursor?: string, signal?: AbortSignal): Promise<InventoryPage>;
};
const productID = (n: number) => `pid_${n.toString(16).padStart(8, "0")}-0000-4000-8000-000000000001`;
function row(name: string, n = 1): InventorySummary {
  return { id: productID(n), name, kind: "agent", owner: "", team: "", tags: [], evidence_id: productID(900), confidence_basis_points: 9500, first_seen: "2026-08-19T00:00:00Z", last_seen: "2026-08-19T01:00:00Z", observed_at: "2026-08-19T01:00:00Z", fresh_until: "2026-08-19T01:15:00Z", freshness_state: "fresh", version: 1 };
}
function page(items: readonly InventorySummary[], next: string | null = null): InventoryPage {
  return { items, page_info: next === null ? { has_more: false, next_cursor: null } : { has_more: true, next_cursor: next } };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function apiFixture(read: PageAPI["listAgentsPage"]): PageAPI {
  return {
    listAgentsPage: read,
    listAgents: vi.fn(async () => { throw new Error("Pagination must not aggregate the entire inventory"); }),
    listTools: async () => [], listIdentities: async () => [], listRuntimes: async () => [],
    getAgent: async (id) => ({ summary: row("Agent detail", Number.parseInt(id.slice(4, 12), 16)), sources: [], evidence: [] }),
    getTool: async () => { throw new Error("unused"); }, getIdentity: async () => { throw new Error("unused"); }, getRuntime: async () => { throw new Error("unused"); },
    getAgentCapabilities: async () => [], getAgentRelationships: async () => [], listAgentSessions: async () => [],
    updateAgent: async () => { throw new Error("unused"); },
    getHomeSummary: async () => ({ agent_count: 0, high_risk_paths: 0, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false }),
  };
}
type BoundaryActions = { refresh(): void; switchTenant(): void; selectDetail(id: string): void };
function Mounted({ api, changed, capture }: { api: PageAPI; changed?: (scope: string) => void; capture?: (actions: BoundaryActions) => void }) {
  const { setQueryScope, invalidate, clearQueryCache, suspendQueryCache, queryScopeKey } = useAPI();
  const [detailID, setDetailID] = useState<string | undefined>();
  useLayoutEffect(() => { setQueryScope("tenant-a"); }, [setQueryScope]);
  useLayoutEffect(() => { capture?.({ refresh: () => invalidate(["core:/discovery/assets"]), switchTenant: () => { changed?.("tenant-b"); setQueryScope("tenant-b"); }, selectDetail: setDetailID }); }, [invalidate, setQueryScope, capture, changed]);
  return <>
    <button onClick={() => invalidate(["core:/discovery/assets"])}>Refresh current inventory</button>
    <button onClick={() => { changed?.("tenant-b"); setQueryScope("tenant-b"); }}>Switch tenant</button>
    <button onClick={() => clearQueryCache()}>Revalidate same tenant</button>
    <button onClick={() => suspendQueryCache()}>Suspend authority</button>
    {queryScopeKey !== "__unscoped__" && <ProductionAgentSecurityView path="/discovery/assets" api={api} inventoryDetailID={detailID} canWrite onNavigate={() => undefined} />}
  </>;
}
function mount(api: PageAPI, changed?: (scope: string) => void, capture?: (actions: BoundaryActions) => void) {
  return render(<APIProvider><Mounted api={api} changed={changed} capture={capture} /></APIProvider>);
}
beforeEach(() => { window.history.replaceState({}, "", "/discovery/assets"); });

describe("M4-50a mounted production Agents server pagination", () => {
  it("requests one bounded page at a time and supports next, previous, first and terminal controls", async () => {
    const user = userEvent.setup();
    const next = deferred<InventoryPage>();
    const read = vi.fn(async (cursor?: string) => cursor === "second_page" ? next.promise : page([row("First page Agent")], "second_page"));
    const api = apiFixture(read); mount(api);
    expect(await screen.findByRole("button", { name: "Open First page Agent" })).toBeVisible();
    expect(read).toHaveBeenCalledTimes(1); expect(api.listAgents).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() => expect(read).toHaveBeenCalledWith("second_page", expect.any(AbortSignal)));
    expect(screen.queryByRole("button", { name: "Open First page Agent" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
    await act(async () => { next.resolve(page([row("Second page Agent", 2)])); });
    expect(await screen.findByRole("button", { name: "Open Second page Agent" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Previous page" }));
    expect(await screen.findByRole("button", { name: "Open First page Agent" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByRole("button", { name: "Open Second page Agent" });
    await user.click(screen.getByRole("button", { name: "First page" }));
    expect(await screen.findByRole("button", { name: "Open First page Agent" })).toBeVisible();
    expect(read.mock.calls.map(([cursor]) => cursor)).toEqual([undefined, "second_page", undefined, "second_page", undefined]);
    expect(screen.queryByText(/of \d+ pages|total agents/i)).not.toBeInTheDocument();
  });

  it("retains exact failed-page retry without showing stale rows or rewinding", async () => {
    const user = userEvent.setup(); let secondAttempts = 0;
    const read = vi.fn(async (cursor?: string) => {
      if (!cursor) return page([row("Old page")], "second_page");
      if (++secondAttempts === 1) throw new Error("private provider failure");
      return page([]);
    });
    mount(apiFixture(read)); await screen.findByRole("button", { name: "Open Old page" });
    await user.click(screen.getByRole("button", { name: "Next page" }));
    expect(await screen.findByRole("button", { name: "Retry page" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Open Old page" })).not.toBeInTheDocument();
    expect(screen.queryByText("private provider failure")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry page" }));
    await waitFor(() => expect(read).toHaveBeenCalledTimes(3));
    expect(read.mock.calls.map(([cursor]) => cursor)).toEqual([undefined, "second_page", "second_page"]);
    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
  });

  it("resets before requests on scope or generation replacement and ignores aborted late pages", async () => {
    const user = userEvent.setup(); let activeScope = "tenant-a";
    const pending = deferred<InventoryPage>(); let oldSignal: AbortSignal | undefined;
    const read = vi.fn(async (cursor?: string, signal?: AbortSignal) => {
      if (cursor && activeScope === "tenant-a") { oldSignal = signal; return pending.promise; }
      if (cursor) return page([row("Tenant B second page", 5)]);
      return page([row(activeScope === "tenant-a" ? "Tenant A" : "Tenant B")], "second_page");
    });
    const api = apiFixture(read); mount(api, (nextScope) => { activeScope = nextScope; });
    await screen.findByRole("button", { name: "Open Tenant A" });
    await user.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() => expect(oldSignal).toBeDefined());
    await user.click(screen.getByRole("button", { name: "Switch tenant" }));
    expect(await screen.findByRole("button", { name: "Open Tenant B" })).toBeVisible();
    expect(oldSignal?.aborted).toBe(true); expect(read.mock.calls.at(-1)?.[0]).toBeUndefined();
    await act(async () => { pending.resolve(page([row("LATE PRIVATE TENANT A", 4)])); });
    expect(screen.queryByText("LATE PRIVATE TENANT A")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next page" }));
    await user.click(screen.getByRole("button", { name: "Revalidate same tenant" }));
    expect(await screen.findByRole("button", { name: "Open Tenant B" })).toBeVisible();
    expect(read.mock.calls.at(-1)?.[0]).toBeUndefined();
    expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Suspend authority" }));
    expect(screen.queryByRole("button", { name: "Open Tenant B" })).not.toBeInTheDocument();
  });

  it("keeps unknown ownership intent mounted through same-scope refresh failure and retries exactly while navigation is locked", async () => {
    const user = userEvent.setup(); const refresh = deferred<InventoryPage>(); let loads = 0;
    const value = row("Ownership Agent");
    const read = vi.fn(async () => ++loads === 2 ? refresh.promise : page([value, row("Other Agent", 2)], "second_page"));
    const api = apiFixture(read);
    const detail = vi.fn(async () => ({ summary: value, sources: [], evidence: [] })); api.getAgent = detail;
    const update = vi.fn<ProductionAgentSecurityAPI["updateAgent"]>();
    update.mockRejectedValueOnce(new Error("response lost")).mockResolvedValueOnce({ agent: { ...value, owner: "security", team: "platform", tags: ["critical"], version: 2 }, audit_id: productID(901) });
    let boundary!: BoundaryActions;
    api.updateAgent = update; mount(api, undefined, (actions) => { boundary = actions; });
    await user.click(await screen.findByRole("button", { name: "Open Ownership Agent" }));
    await user.type(await screen.findByLabelText("Owner"), "security"); await user.type(screen.getByLabelText("Team"), "platform"); await user.type(screen.getByRole("textbox", { name: /^Tags/ }), "critical");
    await user.click(screen.getByRole("button", { name: "Save ownership" }));
    expect(await screen.findByRole("button", { name: "Retry ownership change" })).toBeVisible();
    const original = update.mock.calls[0]; expect(update).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Next page").closest("button")).toBeDisabled();
    const other = document.querySelector<HTMLButtonElement>('[aria-label="Open Other Agent"]')!;
    expect(other).toBeDisabled(); fireEvent.click(other); expect(detail).toHaveBeenCalledTimes(1);
    await act(async () => { boundary.refresh(); });
    await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole("button", { name: "Open Ownership Agent" })).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Owner" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry ownership change" })).toBeVisible();
    await act(async () => { refresh.reject(new Error("refresh unavailable")); });
    await waitFor(() => expect(screen.getByText("Retry page").closest("button")).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: "Retry ownership change" }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2));
    expect(update.mock.calls[1]).toEqual(original);
    expect(screen.queryByText("response lost")).not.toBeInTheDocument(); expect(screen.queryByText("refresh unavailable")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry page" }));
    expect(await screen.findByRole("dialog", { name: "Ownership Agent" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: /^Close$/ }));
    expect(await screen.findByRole("button", { name: "Open Ownership Agent" })).toBeVisible();
  });

  it("aborts an earlier detail transition before capturing ownership intent", async () => {
    const user = userEvent.setup(); const first = row("Original Agent"); const second = row("Deferred Agent", 2);
    const nextDetail = deferred<{ summary: InventorySummary; sources: []; evidence: [] }>();
    let detailSignal: AbortSignal | undefined;
    const api = apiFixture(async () => page([first, second]));
    api.getAgent = vi.fn(async (id, signal) => {
      if (id === second.id) { detailSignal = signal; return nextDetail.promise; }
      return { summary: first, sources: [], evidence: [] };
    });
    const update = vi.fn<ProductionAgentSecurityAPI["updateAgent"]>().mockRejectedValue(new Error("unknown commit")); api.updateAgent = update;
    mount(api);
    await user.click(await screen.findByRole("button", { name: "Open Original Agent" }));
    await user.type(await screen.findByLabelText("Owner"), "security"); await user.type(screen.getByLabelText("Team"), "platform");
    // Model a transition already dispatched before Save, without changing modal accessibility.
    fireEvent.click(document.querySelector('[aria-label="Open Deferred Agent"]')!);
    await waitFor(() => expect(detailSignal).toBeDefined());
    await user.click(screen.getByRole("button", { name: "Save ownership" }));
    await screen.findByRole("button", { name: "Retry ownership change" });
    expect(detailSignal?.aborted).toBe(true);
    await act(async () => { nextDetail.resolve({ summary: second, sources: [], evidence: [] }); });
    expect(screen.getByRole("dialog", { name: "Original Agent" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Retry ownership change" }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2));
    expect(update.mock.calls[1]).toEqual(update.mock.calls[0]); expect(update.mock.calls[0][0]).toBe(first.id);
  });

  it("keeps a superseding row selected after confirmed ownership instead of replaying the unfinished initial link", async () => {
    const user = userEvent.setup(); const first = row("Initial unfinished Agent"); const second = row("Explicitly selected Agent", 2);
    window.history.replaceState({}, "", `/discovery/assets?inventory=${first.id}`);
    const initial = deferred<{ summary: InventorySummary; sources: []; evidence: [] }>();
    let initialSignal: AbortSignal | undefined;
    const api = apiFixture(async () => page([first, second]));
    const detail = vi.fn(async (id: string, signal?: AbortSignal) => {
      if (id === first.id) { initialSignal = signal; return initial.promise; }
      return { summary: second, sources: [], evidence: [] };
    }); api.getAgent = detail;
    const update = vi.fn<ProductionAgentSecurityAPI["updateAgent"]>().mockResolvedValue({ agent: { ...second, owner: "security", team: "platform", version: 2 }, audit_id: productID(901) }); api.updateAgent = update;
    mount(api);
    await waitFor(() => expect(detail).toHaveBeenCalledWith(first.id, expect.any(AbortSignal)));
    await user.click(await screen.findByRole("button", { name: "Open Explicitly selected Agent" }));
    expect(initialSignal?.aborted).toBe(true);
    await user.type(await screen.findByLabelText("Owner"), "security"); await user.type(screen.getByLabelText("Team"), "platform");
    await user.click(screen.getByRole("button", { name: "Save ownership" }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.getByRole("button", { name: "Save ownership" })).toBeEnabled());
    expect(update.mock.calls[0][0]).toBe(second.id);
    expect(detail.mock.calls.map(([id]) => id)).toEqual([first.id, second.id]);
    await act(async () => { initial.resolve({ summary: first, sources: [], evidence: [] }); });
    expect(screen.getByRole("dialog", { name: "Explicitly selected Agent" })).toBeVisible();
    expect(screen.queryByRole("dialog", { name: "Initial unfinished Agent" })).not.toBeInTheDocument();
    expect(detail.mock.calls.map(([id]) => id)).toEqual([first.id, second.id]);
  });

  it("defers incoming same-scope detail navigation until retained ownership has a known outcome", async () => {
    const user = userEvent.setup(); const first = row("Retained original Agent"); const second = row("Incoming Agent", 2);
    const api = apiFixture(async () => page([first, second]));
    const detail = vi.fn(async (id: string) => ({ summary: id === first.id ? first : second, sources: [], evidence: [] })); api.getAgent = detail;
    const update = vi.fn<ProductionAgentSecurityAPI["updateAgent"]>().mockRejectedValueOnce(new Error("unknown commit")).mockResolvedValueOnce({ agent: { ...first, owner: "security", team: "platform", version: 2 }, audit_id: productID(901) }); api.updateAgent = update;
    let boundary!: BoundaryActions; mount(api, undefined, (actions) => { boundary = actions; });
    await user.click(await screen.findByRole("button", { name: "Open Retained original Agent" }));
    await user.type(await screen.findByLabelText("Owner"), "security"); await user.type(screen.getByLabelText("Team"), "platform");
    await user.click(screen.getByRole("button", { name: "Save ownership" }));
    await screen.findByRole("button", { name: "Retry ownership change" });
    const exact = update.mock.calls[0]; expect(detail).toHaveBeenCalledTimes(1);
    await act(async () => { boundary.selectDetail(second.id); });
    expect(detail).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("dialog", { name: "Retained original Agent" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Retry ownership change" }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2)); expect(update.mock.calls[1]).toEqual(exact);
    expect(exact[0]).toBe(first.id);
    expect(await screen.findByRole("dialog", { name: "Incoming Agent" })).toBeVisible();
    expect(detail.mock.calls.map(([id]) => id)).toEqual([first.id, second.id]);
  });

  it("never carries or replays an unresolved ownership intent into replacement authority", async () => {
    const user=userEvent.setup();let scope="tenant-a";
    const value=row("Pending owner Agent");
    const api=apiFixture(async()=>page([scope==="tenant-a"?value:row("New authority Agent",2)],"next_page"));
    api.getAgent=async()=>({summary:value,sources:[],evidence:[]});
    const update=vi.fn<ProductionAgentSecurityAPI["updateAgent"]>().mockRejectedValue(new Error("unknown commit"));api.updateAgent=update;
    let boundary!: BoundaryActions;
    mount(api,(next)=>{scope=next}, (actions) => { boundary=actions; });
    await user.click(await screen.findByRole("button",{name:"Open Pending owner Agent"}));
    await user.type(await screen.findByLabelText("Owner"),"security");await user.type(screen.getByLabelText("Team"),"platform");
    await user.click(screen.getByRole("button",{name:"Save ownership"}));
    await screen.findByRole("button",{name:"Retry ownership change"});
    await act(async () => { boundary.switchTenant(); });
    expect(await screen.findByRole("button",{name:"Open New authority Agent"})).toBeVisible();
    expect(screen.queryByRole("button",{name:"Retry ownership change"})).not.toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();expect(update).toHaveBeenCalledTimes(1);
  });

  it("traverses beyond the old aggregate ceiling without unbounded retained Previous history", async () => {
    const user = userEvent.setup();
    const read = vi.fn(async (cursor?: string) => {
      const number = cursor ? Number(cursor.slice(5)) : 0;
      return page([row(`Agent page ${number}`, number + 1)], number < 102 ? `page_${number + 1}` : null);
    });
    mount(apiFixture(read)); await screen.findByRole("button", { name: "Open Agent page 0" });
    for (let number = 1; number <= 102; number++) {
      await user.click(screen.getByRole("button", { name: "Next page" }));
      await screen.findByRole("button", { name: `Open Agent page ${number}` });
    }
    expect(read).toHaveBeenCalledTimes(103);
    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
    for (let number=101;number>=2;number--) {
      await user.click(screen.getByRole("button",{name:"Previous page"}));
      await screen.findByRole("button",{name:`Open Agent page ${number}`});
    }
    expect(screen.getByRole("button",{name:"Previous page"})).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "First page" }));
    expect(await screen.findByRole("button", { name: "Open Agent page 0" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled();
  }, 20_000);
});

describe("M4-50a generated single-page Agents adapter", () => {
  it("sends fixed bounded cursor/limit and returns actual page_info without eager reads", async () => {
    const calls: Request[] = [];
    const fetch = vi.fn(async (request: Request) => {
      calls.push(request);
      return Response.json(page([row("HTTP Agent")], new URL(request.url).searchParams.has("cursor") ? null : "opaque_server_cursor"));
    });
    const api = createProductionAgentSecurityAPI(createAPIClient({ fetch })) as PageAPI;
    expect(api.listAgentsPage).toBeTypeOf("function");
    const abort = new AbortController(); const result = await api.listAgentsPage(undefined, abort.signal);
    expect(result.page_info).toEqual({ has_more: true, next_cursor: "opaque_server_cursor" }); expect(fetch).toHaveBeenCalledTimes(1);
    const first = new URL(calls[0].url); expect(first.pathname).toBe("/api/v1/agents"); expect(first.searchParams.get("limit")).toBe("100"); expect(first.searchParams.has("cursor")).toBe(false);
    await api.listAgentsPage("opaque_server_cursor", abort.signal);
    expect(new URL(calls[1].url).searchParams.get("cursor")).toBe("opaque_server_cursor"); expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("refuses incomplete, overfull, repeated-cursor and denied page responses instead of falling back", async () => {
    for (const mode of ["empty-continuation", "overfull", "same-cursor", "terminal-with-cursor", "denied"] as const) {
      const fetch = vi.fn(async () => {
        if (mode === "denied") return Response.json({ code: "permission_denied", message: "Operation unavailable", correlation_id: productID(901), retryable: false }, { status: 403 });
        const value = page(mode === "empty-continuation" ? [] : mode === "overfull" ? Array.from({ length: 101 }, (_, i) => row("Agent", i + 1)) : [row("Agent")], mode === "same-cursor" ? "prior_cursor" : "next_cursor");
        return Response.json(mode === "terminal-with-cursor" ? { ...value, page_info: { has_more: false, next_cursor: "next_cursor" } } : value);
      });
      const api = createProductionAgentSecurityAPI(createAPIClient({ fetch })) as PageAPI;
      expect(api.listAgentsPage).toBeTypeOf("function");
      if (mode === "denied") await expect(api.listAgentsPage("prior_cursor")).rejects.toBeInstanceOf(APIProductError);
      else await expect(api.listAgentsPage("prior_cursor")).rejects.toThrow();
      expect(fetch).toHaveBeenCalledTimes(1);
    }
  });
});
