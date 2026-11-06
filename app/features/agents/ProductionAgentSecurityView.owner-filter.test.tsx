import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useLayoutEffect, useState, type ComponentProps, type ComponentType } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createAPIClient } from "../../../apps/web/api/client";
import type { InventoryPage, InventorySummary } from "../../../apps/web/api/generated";
import { APIProvider, useAPI } from "../../api/APIProvider";
import { createProductionAgentSecurityAPI, ProductionAgentSecurityView, type ProductionAgentSecurityAPI } from "./ProductionAgentSecurityView";

// Structural expected additive contract keeps tests executable on the published preimage.
type OwnerAPI = Omit<ProductionAgentSecurityAPI, "listAgentsPage"> & { listAgentsPage(cursor?: string, signal?: AbortSignal, owner?: string): Promise<InventoryPage> };
const OwnerView = ProductionAgentSecurityView as ComponentType<ComponentProps<typeof ProductionAgentSecurityView> & { ownerFilterAvailable?: boolean }>;
const productID = (n: number) => `pid_${n.toString(16).padStart(8, "0")}-0000-4000-8000-000000000001`;
function row(name: string, owner = "", n = 1): InventorySummary {
  return { id: productID(n), name, kind: "agent", owner, team: "platform", tags: [], evidence_id: productID(900), confidence_basis_points: 9500, first_seen: "2026-08-19T00:00:00Z", last_seen: "2026-08-19T01:00:00Z", observed_at: "2026-08-19T01:00:00Z", fresh_until: "2026-08-19T01:15:00Z", freshness_state: "fresh", version: 1 };
}
function page(items: readonly InventorySummary[], next: string | null = null): InventoryPage {
  return { items, page_info: next === null ? { has_more: false, next_cursor: null } : { has_more: true, next_cursor: next } };
}
function deferred<T>() {
  let resolve!: (value: T) => void; let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject };
}
function fixture(read: OwnerAPI["listAgentsPage"]): OwnerAPI {
  return {
    listAgentsPage: read, listAgents: vi.fn(async () => { throw new Error("No aggregate fallback"); }),
    listTools: async () => [], listIdentities: async () => [], listRuntimes: async () => [],
    getAgent: async id => ({ summary: row("Selected Agent", "security", Number.parseInt(id.slice(4, 12), 16)), sources: [], evidence: [] }),
    getTool: async () => { throw new Error("unused"); }, getIdentity: async () => { throw new Error("unused"); }, getRuntime: async () => { throw new Error("unused"); },
    getAgentCapabilities: async () => [], getAgentRelationships: async () => [], listAgentSessions: async () => [],
    updateAgent: async () => { throw new Error("unused"); },
    getHomeSummary: async () => ({ agent_count: 0, high_risk_paths: 0, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false }),
  };
}
type Controls = { capability(value: boolean): void; scope(value: string): void; generation(): void };
function Harness({ api, available, capture, onScope }: { api: OwnerAPI; available: boolean; capture(controls: Controls): void; onScope?(value: string): void }) {
  const { setQueryScope, clearQueryCache, queryScopeKey } = useAPI(); const [capability, setCapability] = useState(available);
  useLayoutEffect(() => { setQueryScope("tenant-a"); }, [setQueryScope]);
  useLayoutEffect(() => { capture({ capability: setCapability, scope: value => { onScope?.(value); setQueryScope(value); }, generation: clearQueryCache }); }, [capture, onScope, setQueryScope, clearQueryCache]);
  return queryScopeKey !== "__unscoped__" && <OwnerView path="/discovery/assets" api={api} ownerFilterAvailable={capability} canWrite onNavigate={() => undefined} />;
}
function mount(api: OwnerAPI, available = true, onScope?: (value: string) => void) {
  let controls!: Controls;
  const view = render(<APIProvider><Harness api={api} available={available} capture={value => { controls = value; }} onScope={onScope} /></APIProvider>);
  return { ...view, controls: () => controls };
}
async function exactOwner(user: ReturnType<typeof userEvent.setup>, owner: string) {
  await user.selectOptions(screen.getByLabelText("Owner filter"), "exact");
  await user.type(screen.getByLabelText("Exact owner"), owner);
  await user.click(screen.getByRole("button", { name: "Apply owner filter" }));
}
beforeEach(() => { window.history.replaceState({}, "", "/discovery/assets"); });

describe("M4-50b1 production owner selector request contract", () => {
  it("serializes absent, unowned and exact owner bytes through the generated bounded page request", async () => {
    const requests: Request[] = []; const fetch = vi.fn(async (request: Request) => { requests.push(request); return Response.json(page([])); });
    const api = createProductionAgentSecurityAPI(createAPIClient({ fetch })) as OwnerAPI;
    for (const owner of [undefined, "", " security ", "é😀"] as const) await api.listAgentsPage(undefined, undefined, owner);
    expect(requests).toHaveLength(4);
    requests.forEach((request, i) => {
      const params = new URL(request.url).searchParams; expect(params.get("limit")).toBe("100");
      expect(params.has("owner")).toBe(i !== 0); expect(params.get("owner")).toBe([null, "", " security ", "é😀"][i]);
    });
    for (const owner of ["a".repeat(129), "\u0000", "\u007f", "\ud800"]) await expect(api.listAgentsPage(undefined, undefined, owner)).rejects.toThrow();
    expect(requests).toHaveLength(4);
    await api.listAgentsPage(undefined, undefined, "😀".repeat(128)); expect(requests).toHaveLength(5);
  });
});

describe("M4-50b1 mounted production owner filtering", () => {
  it("separates draft and applied bytes, resets signed cursor history and retries the exact filtered page", async () => {
    const user = userEvent.setup(); let filteredAttempts = 0;
    const read = vi.fn(async (cursor?: string, _signal?: AbortSignal, owner?: string) => {
      if (owner !== undefined && ++filteredAttempts === 1) throw new Error("private filtered read failure");
      return page([row(owner === undefined ? "All Agent" : "Filtered Agent", owner)], cursor || owner !== undefined ? null : "all_second");
    }); const api = fixture(read); mount(api);
    await screen.findByRole("button", { name: "Open All Agent" }); await user.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
    await user.selectOptions(screen.getByLabelText("Owner filter"), "exact"); await user.type(screen.getByLabelText("Exact owner"), " security ");
    expect(read).toHaveBeenCalledTimes(2); await user.click(screen.getByRole("button", { name: "Apply owner filter" }));
    expect(await screen.findByRole("button", { name: "Retry page" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Open All Agent" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled();
    await user.clear(screen.getByLabelText("Exact owner")); await user.type(screen.getByLabelText("Exact owner"), "draft only");
    await user.click(screen.getByRole("button", { name: "Retry page" })); await screen.findByRole("button", { name: "Open Filtered Agent" });
    expect(read.mock.calls.slice(2).map(([cursor, , owner]) => [cursor, owner])).toEqual([[undefined, " security "], [undefined, " security "]]);
    await user.selectOptions(screen.getByLabelText("Owner filter"), "unowned"); await user.click(screen.getByRole("button", { name: "Apply owner filter" }));
    await waitFor(() => expect(read.mock.calls.at(-1)?.[2]).toBe("")); expect(api.listAgents).not.toHaveBeenCalled();
  });

  it("refetches the active server filter after confirmed ownership and never resurrects a nonmatching row", async () => {
    const user = userEvent.setup(); const value = row("Changing owner Agent", "security"); let changed = false;
    const read = vi.fn(async (_cursor?: string, _signal?: AbortSignal, owner?: string) => page(changed && owner === "security" ? [] : [value]));
    const api = fixture(read); api.getAgent = async () => ({ summary: value, sources: [], evidence: [] });
    const update = vi.fn<ProductionAgentSecurityAPI["updateAgent"]>().mockImplementation(async () => { changed = true; return { agent: { ...value, owner: "other", version: 2 }, audit_id: productID(901) }; }); api.updateAgent = update;
    mount(api); await screen.findByRole("button", { name: "Open Changing owner Agent" }); await exactOwner(user, "security");
    await user.click(await screen.findByRole("button", { name: "Open Changing owner Agent" }));
    await user.clear(await screen.findByLabelText("Owner")); await user.type(screen.getByLabelText("Owner"), "other"); await user.click(screen.getByRole("button", { name: "Save ownership" }));
    await waitFor(() => expect(read.mock.calls.filter(([, , owner]) => owner === "security")).toHaveLength(2));
    expect(document.querySelector('[aria-label="Open Changing owner Agent"]')).not.toBeInTheDocument();
    expect(screen.getByText("No records in this scope.")).toBeInTheDocument(); expect(update).toHaveBeenCalledTimes(1);
  });

  it("locks draft/apply/reset during unknown ownership and retries the exact original mutation", async () => {
    const user = userEvent.setup(); const value = row("Pending filtered Agent", "security");
    const read = vi.fn(async () => page([value])); const api = fixture(read); api.getAgent = async () => ({ summary: value, sources: [], evidence: [] });
    const update = vi.fn<ProductionAgentSecurityAPI["updateAgent"]>().mockRejectedValueOnce(new Error("unknown commit")).mockResolvedValueOnce({ agent: { ...value, owner: "other", version: 2 }, audit_id: productID(901) }); api.updateAgent = update;
    mount(api); await screen.findByRole("button", { name: "Open Pending filtered Agent" }); await exactOwner(user, "security");
    const selector = screen.getByLabelText("Owner filter"); const text = screen.getByLabelText("Exact owner");
    const apply = screen.getByRole("button", { name: "Apply owner filter" }); const reset = screen.getByRole("button", { name: "Reset owner filter" });
    await user.click(await screen.findByRole("button", { name: "Open Pending filtered Agent" }));
    await user.clear(await screen.findByLabelText("Owner")); await user.type(screen.getByLabelText("Owner"), "other"); await user.click(screen.getByRole("button", { name: "Save ownership" }));
    await screen.findByRole("button", { name: "Retry ownership change" }); const exact = update.mock.calls[0]; const count = read.mock.calls.length;
    for (const element of [selector, text, apply, reset]) expect(element).toBeDisabled();
    fireEvent.change(selector, { target: { value: "unowned" } }); fireEvent.change(text, { target: { value: "different" } }); fireEvent.click(apply); fireEvent.click(reset);
    expect(selector).toHaveValue("exact"); expect(text).toHaveValue("security"); expect(read).toHaveBeenCalledTimes(count);
    await user.click(screen.getByRole("button", { name: "Retry ownership change" })); await waitFor(() => expect(update).toHaveBeenCalledTimes(2)); expect(update.mock.calls[1]).toEqual(exact);
  });

  it("withdraws a lost capability without filtered rows, another filtered read or silent unfiltered fallback", async () => {
    const user = userEvent.setup(); const pending = deferred<InventoryPage>(); let filteredSignal: AbortSignal | undefined;
    const read = vi.fn(async (_cursor?: string, signal?: AbortSignal, owner?: string) => { if (owner !== undefined) { filteredSignal = signal; return pending.promise; } return page([row("Legacy all Agent")]); });
    const mounted = mount(fixture(read)); await screen.findByRole("button", { name: "Open Legacy all Agent" }); await exactOwner(user, "security");
    await waitFor(() => expect(filteredSignal).toBeDefined()); const count = read.mock.calls.length;
    await act(async () => { mounted.controls().capability(false); });
    expect(filteredSignal?.aborted).toBe(true); expect(await screen.findByText(/Owner filtering unavailable/)).toBeVisible();
    await act(async () => { pending.resolve(page([row("LATE filtered Agent", "security")])); });
    expect(screen.queryByText("LATE filtered Agent")).not.toBeInTheDocument(); expect(screen.queryByRole("button", { name: "Open Legacy all Agent" })).not.toBeInTheDocument(); expect(read).toHaveBeenCalledTimes(count);
    await user.click(screen.getByRole("button", { name: "Reset owner filter" }));
    expect(await screen.findByRole("button", { name: "Open Legacy all Agent" })).toBeVisible(); expect(read.mock.calls.at(-1)?.[2]).toBeUndefined();
  });

  it("keeps legacy requests unfiltered without capability and resets filters before scope or generation requests", async () => {
    const user = userEvent.setup(); let scope = "tenant-a";
    const read = vi.fn(async (_cursor?: string, _signal?: AbortSignal, owner?: string) => page([row(`${scope} Agent`, owner)])); const api = fixture(read);
    const mounted = mount(api, false, value => { scope = value; }); await screen.findByRole("button", { name: "Open tenant-a Agent" });
    expect(screen.queryByLabelText("Owner filter")).not.toBeInTheDocument(); expect(read.mock.calls[0][2]).toBeUndefined();
    await act(async () => { mounted.controls().capability(true); }); await exactOwner(user, "é😀"); await waitFor(() => expect(read.mock.calls.at(-1)?.[2]).toBe("é😀"));
    await act(async () => { mounted.controls().scope("tenant-b"); }); await screen.findByRole("button", { name: "Open tenant-b Agent" });
    expect(read.mock.calls.at(-1)?.[2]).toBeUndefined(); expect(screen.getByLabelText("Owner filter")).toHaveValue("all");
    await exactOwner(user, "security"); await act(async () => { mounted.controls().generation(); }); await waitFor(() => expect(read.mock.calls.at(-1)?.[2]).toBeUndefined());
    expect(screen.getByLabelText("Owner filter")).toHaveValue("all");
  });
});
