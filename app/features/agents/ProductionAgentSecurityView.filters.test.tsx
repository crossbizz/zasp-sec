import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useLayoutEffect, useState, type ComponentProps, type ComponentType } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createAPIClient } from "../../../apps/web/api/client";
import type { InventoryPage, InventorySummary } from "../../../apps/web/api/generated";
import { APIProvider, useAPI } from "../../api/APIProvider";
import { createProductionAgentSecurityAPI, ProductionAgentSecurityView, type ProductionAgentSecurityAPI } from "./ProductionAgentSecurityView";

type Filters = { risk?: "critical" | "high" | "medium" | "low" | "unknown"; execution?: "shell" | "code" | "shell_or_code" | "unknown"; impact?: "high" | "unknown" };
type FilterAPI = Omit<ProductionAgentSecurityAPI, "listAgentsPage"> & { listAgentsPage(cursor?: string, signal?: AbortSignal, owner?: string, filters?: Filters): Promise<InventoryPage> };
const FilterView = ProductionAgentSecurityView as ComponentType<ComponentProps<typeof ProductionAgentSecurityView> & { exposureFiltersAvailable?: boolean }>;
const id = (n: number) => `pid_${n.toString(16).padStart(8, "0")}-0000-4000-8000-000000000001`;
function row(name = "Filtered Agent"): InventorySummary { return { id: id(1), name, kind: "agent", owner: "security", team: "platform", tags: [], evidence_id: id(900), confidence_basis_points: 9500, first_seen: "2026-08-19T00:00:00Z", last_seen: "2026-08-19T01:00:00Z", observed_at: "2026-08-19T01:00:00Z", fresh_until: "2026-08-19T01:15:00Z", freshness_state: "fresh", version: 1 }; }
function page(items: readonly InventorySummary[], next: string | null = null): InventoryPage { return { items, page_info: next === null ? { has_more: false, next_cursor: null } : { has_more: true, next_cursor: next } }; }
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(yes => { resolve = yes; }); return { promise, resolve }; }
function fixture(read: FilterAPI["listAgentsPage"]): FilterAPI { return {
  listAgentsPage: read, listAgents: vi.fn(async () => { throw new Error("No aggregate fallback"); }), listTools: async () => [], listIdentities: async () => [], listRuntimes: async () => [],
  getAgent: async () => ({ summary: row(), sources: [], evidence: [] }), getTool: async () => { throw new Error("unused"); }, getIdentity: async () => { throw new Error("unused"); }, getRuntime: async () => { throw new Error("unused"); },
  getAgentCapabilities: async () => [], getAgentRelationships: async () => [], listAgentSessions: async () => [], updateAgent: async () => { throw new Error("unused"); },
  getHomeSummary: async () => ({ agent_count: 0, high_risk_paths: 0, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false }),
}; }
type Controls = { capability(value: boolean): void; scope(): void; generation(): void };
function Harness({ api, initial, capture }: { api: FilterAPI; initial: boolean; capture(value: Controls): void }) {
  const { setQueryScope, clearQueryCache, queryScopeKey } = useAPI(); const [available, setAvailable] = useState(initial);
  useLayoutEffect(() => { setQueryScope("tenant-a"); }, [setQueryScope]);
  useLayoutEffect(() => { capture({ capability: setAvailable, scope: () => setQueryScope("tenant-b"), generation: clearQueryCache }); }, [capture, setQueryScope, clearQueryCache]);
  return queryScopeKey !== "__unscoped__" && <FilterView path="/discovery/assets" api={api} ownerFilterAvailable exposureFiltersAvailable={available} canWrite onNavigate={() => undefined} />;
}
function mount(api: FilterAPI, initial = true) { let controls!: Controls; const view = render(<APIProvider><Harness api={api} initial={initial} capture={value => { controls = value; }} /></APIProvider>); return { ...view, controls: () => controls }; }
async function draft(user: ReturnType<typeof userEvent.setup>) {
  await user.selectOptions(screen.getByLabelText("Recorded finding severity"), "high");
  await user.selectOptions(screen.getByLabelText("Execution evidence"), "shell_or_code");
  await user.selectOptions(screen.getByLabelText("Sensitive / high-impact reach"), "high");
}
beforeEach(() => { window.history.replaceState({}, "", "/discovery/assets"); });

describe("Original Agents combined filter generated request contract", () => {
  it("serializes exact owner conjunction with closed recorded-risk/execution/impact selectors and preserves absent legacy requests", async () => {
    const requests: Request[] = []; const fetch = async (request: Request) => { requests.push(request); return Response.json(page([])); };
    const api = createProductionAgentSecurityAPI(createAPIClient({ fetch })) as FilterAPI;
    await api.listAgentsPage(undefined, undefined, " security ", { risk: "critical", execution: "shell_or_code", impact: "high" });
    const combined = new URL(requests[0].url).searchParams;
    expect(Object.fromEntries(combined)).toEqual({ limit: "100", owner: " security ", risk: "critical", execution: "shell_or_code", impact: "high" });
    await api.listAgentsPage("signed_cursor", undefined, "", { risk: "unknown", execution: "unknown", impact: "unknown" });
    expect(Object.fromEntries(new URL(requests[1].url).searchParams)).toEqual({ limit: "100", cursor: "signed_cursor", owner: "", risk: "unknown", execution: "unknown", impact: "unknown" });
    await api.listAgentsPage(undefined, undefined, undefined, {}); expect(Object.fromEntries(new URL(requests[2].url).searchParams)).toEqual({ limit: "100" });
    for (const invalid of [{ risk: "none" }, { execution: "no_execution" }, { impact: "low" }, { risk: "HIGH" }, { other: "high" }]) await expect(api.listAgentsPage(undefined, undefined, undefined, invalid as Filters)).rejects.toThrow();
    expect(requests).toHaveLength(3);
  });
});

describe("Original Agents combined recorded-evidence filter flow", () => {
  it("applies owner conjunction only on Apply, resets cursor/history and retains exact applied selectors on retry", async () => {
    const user = userEvent.setup(); let attempts = 0;
    const read = vi.fn(async (cursor?: string, _signal?: AbortSignal, _owner?: string, filters?: Filters) => {
      if (filters?.risk && ++attempts === 1) throw new Error("private read failure");
      return page([row()], cursor || filters?.risk ? null : "all_second");
    }); const api = fixture(read); mount(api);
    await screen.findByRole("button", { name: "Open Filtered Agent" }); await user.click(screen.getByRole("button", { name: "Next page" })); await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
    await user.selectOptions(screen.getByLabelText("Owner filter"), "exact"); await user.type(screen.getByLabelText("Exact owner"), " security "); await draft(user);
    expect(read).toHaveBeenCalledTimes(2); await user.click(screen.getByRole("button", { name: "Apply Agent filters" }));
    await screen.findByRole("button", { name: "Retry page" }); expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled(); expect(screen.queryByRole("button", { name: "Open Filtered Agent" })).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Recorded finding severity"), "low"); await user.click(screen.getByRole("button", { name: "Retry page" }));
    await screen.findByRole("button", { name: "Open Filtered Agent" });
    expect(read.mock.calls.slice(2).map(([cursor, , owner, filters]) => [cursor, owner, filters])).toEqual([[undefined, " security ", { risk: "high", execution: "shell_or_code", impact: "high" }], [undefined, " security ", { risk: "high", execution: "shell_or_code", impact: "high" }]]);
    expect(api.listAgents).not.toHaveBeenCalled();
  });

  it("refetches risk/exposure-only pages after a known ownership ACK without requiring an owner selector", async () => {
    const user = userEvent.setup(); let changed = false;
    const read = vi.fn(async (_cursor?: string, _signal?: AbortSignal, _owner?: string, filters?: Filters) => page(changed && filters?.risk ? [] : [row()]));
    const api = fixture(read); api.updateAgent = async () => { changed = true; return { agent: { ...row(), owner: "other", version: 2 }, audit_id: id(901) }; };
    mount(api); await screen.findByRole("button", { name: "Open Filtered Agent" }); await draft(user); await user.click(screen.getByRole("button", { name: "Apply Agent filters" }));
    await user.click(await screen.findByRole("button", { name: "Open Filtered Agent" })); await user.clear(await screen.findByLabelText("Owner")); await user.type(screen.getByLabelText("Owner"), "other"); await user.click(screen.getByRole("button", { name: "Save ownership" }));
    await waitFor(() => expect(read.mock.calls.filter(([, , , filters]) => filters?.risk === "high")).toHaveLength(2));
    expect(document.querySelector('[aria-label="Open Filtered Agent"]')).not.toBeInTheDocument(); expect(screen.getByText("No records in this scope.")).toBeInTheDocument();
  });

  it("locks all filter controls and handlers during unknown ownership and keeps the exact retry", async () => {
    const user = userEvent.setup(); const read = vi.fn(async (_cursor?: string, _signal?: AbortSignal, _owner?: string, _filters?: Filters) => page([row()])); const api = fixture(read);
    const update = vi.fn<ProductionAgentSecurityAPI["updateAgent"]>().mockRejectedValueOnce(new Error("unknown commit")).mockResolvedValueOnce({ agent: { ...row(), owner: "other", version: 2 }, audit_id: id(901) }); api.updateAgent = update;
    mount(api); await screen.findByRole("button", { name: "Open Filtered Agent" }); await draft(user); await user.click(screen.getByRole("button", { name: "Apply Agent filters" }));
    const selects = [screen.getByLabelText("Recorded finding severity"), screen.getByLabelText("Execution evidence"), screen.getByLabelText("Sensitive / high-impact reach")]; const apply = screen.getByRole("button", { name: "Apply Agent filters" }); const reset = screen.getByRole("button", { name: "Reset Agent filters" });
    await user.click(await screen.findByRole("button", { name: "Open Filtered Agent" })); await user.clear(await screen.findByLabelText("Owner")); await user.type(screen.getByLabelText("Owner"), "other"); await user.click(screen.getByRole("button", { name: "Save ownership" })); await screen.findByRole("button", { name: "Retry ownership change" });
    const exact = update.mock.calls[0]; const count = read.mock.calls.length; for (const control of [...selects, apply, reset]) expect(control).toBeDisabled();
    for (const control of selects) fireEvent.change(control, { target: { value: "unknown" } }); fireEvent.click(apply); fireEvent.click(reset);
    expect(selects[0]).toHaveValue("high"); expect(selects[1]).toHaveValue("shell_or_code"); expect(selects[2]).toHaveValue("high"); expect(read).toHaveBeenCalledTimes(count);
    await user.click(screen.getByRole("button", { name: "Retry ownership change" })); await waitFor(() => expect(update).toHaveBeenCalledTimes(2)); expect(update.mock.calls[1]).toEqual(exact);
  });

  it("aborts and hides revoked filter capabilities without silent all fallback, then allows explicit reset", async () => {
    const user = userEvent.setup(); const pending = deferred<InventoryPage>(); let signal: AbortSignal | undefined;
    const read = vi.fn(async (_cursor?: string, requestSignal?: AbortSignal, _owner?: string, filters?: Filters) => { if (filters?.risk) { signal = requestSignal; return pending.promise; } return page([row("All Agent")]); });
    const mounted = mount(fixture(read), false); await screen.findByRole("button", { name: "Open All Agent" }); expect(screen.queryByLabelText("Recorded finding severity")).not.toBeInTheDocument();
    await act(async () => { mounted.controls().capability(true); }); await draft(user); await user.click(screen.getByRole("button", { name: "Apply Agent filters" })); await waitFor(() => expect(signal).toBeDefined()); const count = read.mock.calls.length;
    await act(async () => { mounted.controls().capability(false); }); expect(signal?.aborted).toBe(true); expect(await screen.findByText(/Agent filters unavailable/)).toBeVisible();
    await act(async () => { pending.resolve(page([row("LATE filtered Agent")])); }); expect(screen.queryByText("LATE filtered Agent")).not.toBeInTheDocument(); expect(screen.queryByRole("button", { name: "Open All Agent" })).not.toBeInTheDocument(); expect(read).toHaveBeenCalledTimes(count);
    await user.click(screen.getByRole("button", { name: "Reset Agent filters" })); expect(await screen.findByRole("button", { name: "Open All Agent" })).toBeVisible(); expect(read.mock.calls.at(-1)?.[3]).toBeUndefined();
  });

  it("resets applied conjunctions before new scope/generation requests and never offers safe or negative evidence selectors", async () => {
    const user = userEvent.setup(); const read = vi.fn(async (_cursor?: string, _signal?: AbortSignal, _owner?: string, _filters?: Filters) => page([row()])); const mounted = mount(fixture(read));
    await screen.findByRole("button", { name: "Open Filtered Agent" }); await draft(user); await user.click(screen.getByRole("button", { name: "Apply Agent filters" })); await waitFor(() => expect(read.mock.calls.at(-1)?.[3]?.risk).toBe("high"));
    await act(async () => { mounted.controls().scope(); }); await waitFor(() => expect(read.mock.calls.at(-1)?.[3]).toBeUndefined()); for (const label of ["Recorded finding severity", "Execution evidence", "Sensitive / high-impact reach"]) expect(screen.getByLabelText(label)).toHaveValue("all");
    await draft(user); await user.click(screen.getByRole("button", { name: "Apply Agent filters" })); await act(async () => { mounted.controls().generation(); }); await waitFor(() => expect(read.mock.calls.at(-1)?.[3]).toBeUndefined());
    expect(screen.queryByRole("option", { name: /^(safe|no risk|no execution|no impact)$/i })).not.toBeInTheDocument();
  });
});
