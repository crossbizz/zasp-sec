import { useEffect, type ReactNode } from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { APIProvider, useAPI } from "../../api/APIProvider";
import { createAPIClient } from "../../../apps/web/api/client";
import type { ProductionRiskAPI } from "./api";
import { ProductionRiskView } from "./ProductionRiskView";

const finding = { id: "pid_20000001-0000-4000-8000-000000000001", source: "posture", rule: "unapproved_tool", title: "Public tool access", severity: "high", status: "open", agent_id: "pid_20000004-0000-4000-8000-000000000004", path_id: "pid_30000001-0000-4000-8000-000000000001", evidence_ids: ["pid_20000002-0000-4000-8000-000000000002"], risk_factors: [{ name: "Public input", evidence_id: "pid_20000002-0000-4000-8000-000000000002" }], version: 1, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z" } as const;
const path = { id: "pid_30000001-0000-4000-8000-000000000001", entry_id: "pid_30000002-0000-4000-8000-000000000002", sink_id: "pid_30000003-0000-4000-8000-000000000003", node_ids: ["pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003"], state: "verified", evidence_ids: [finding.evidence_ids[0]], blocked_edge: -1, version: 1, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z" } as const;
const activityScope = { organizationID: "pid_10000001-0000-4000-8000-000000000001", workspaceID: "pid_10000002-0000-4000-8000-000000000002", environmentID: "pid_10000003-0000-4000-8000-000000000003" };

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((next, fail) => { resolve = next; reject = fail; });
  return { promise, resolve, reject };
}

function QueryScope({ children }: { children: ReactNode }) {
  const { setQueryScope } = useAPI();
  useEffect(() => setQueryScope("risk-test-scope"), [setQueryScope]);
  return children;
}

function renderRisk(pathname: "/violations" | "/exposure/attack-paths", api: ProductionRiskAPI, canWrite = false, onNavigate = vi.fn(), selectedID?: string) {
  return render(<APIProvider><QueryScope><ProductionRiskView path={pathname} api={api} canWrite={canWrite} onNavigate={onNavigate} selectedID={selectedID} activityScope={activityScope} /></QueryScope></APIProvider>);
}

function fixtureAPI(overrides: Partial<ProductionRiskAPI> = {}): ProductionRiskAPI {
  return {
    async listFindings() { return [finding]; }, async getFinding() { return { value: finding, version: '"1"' }; },
    async updateFinding() { return { value: { ...finding, status: "under_review", version: 2 }, version: '"2"', auditID: "pid_40000001-0000-4000-8000-000000000001", receiptID: "pid_40000002-0000-4000-8000-000000000002" }; },
    async acceptFindingRisk() { return { value: { ...finding, status: "accepted", acceptance_reason: "Approved exception", version: 2 }, version: '"2"', auditID: "pid_40000001-0000-4000-8000-000000000001", receiptID: "pid_40000002-0000-4000-8000-000000000002" }; },
		async createFindingTicket() { return { ticket_id: "SEC-1234" }; },
    async listAttackPaths() { return [path]; }, async getAttackPath() { return path; }, async getAttackPathBreakOptions() { return [{ path_id: path.id, target_id: path.entry_id, evidence_id: finding.evidence_ids[0], kind: "remove_node", rank: 1 }]; },
    ...overrides,
  };
}

describe("production risk views", () => {
  it.each([
    { kind: "finding", direct: true }, { kind: "attack_path", direct: true },
    { kind: "finding", direct: false }, { kind: "attack_path", direct: false },
  ] as const)("loads $kind reverse authority (direct=$direct) and removes it after permission loss", async ({ kind, direct }) => {
    const requests: Request[] = []; const navigate = vi.fn();
    const entity = kind === "finding" ? finding : path;
    const pathname = kind === "finding" ? "/violations" : "/exposure/attack-paths";
    const runID = "pid_78000009-0000-4000-8000-000000000009";
    const client = createAPIClient({ fetch: async request => {
      requests.push(request);
      return new Response(JSON.stringify({ items: [{ id: runID, agent_id: finding.agent_id, state: "queued", evidence_ids: [finding.evidence_ids[0]], definition_version: 1, version: 1 }], coverage: "partial" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
    } });
    const api = fixtureAPI();
    const view = render(<APIProvider client={client}><ProductionRiskView path={pathname} api={api} canWrite={false} canReadRuns onNavigate={navigate} selectedID={direct ? entity.id : undefined} activityScope={activityScope} /></APIProvider>);
    if (!direct) await userEvent.click(await screen.findByRole("button", { name: kind === "finding" ? `Open ${finding.title}` : `Open attack path ${path.id}` }));
    await userEvent.click(await screen.findByRole("button", { name: `Open run ${runID}` }));
    expect(requests.map(request => new URL(request.url).pathname)).toEqual([`/api/v1/security-agent-activity/${kind}/${entity.id}/runs`]);
    expect(navigate).toHaveBeenCalledWith(`/protect/security-agents?entity_id=${runID}&organization_id=${activityScope.organizationID}&workspace_id=${activityScope.workspaceID}&environment_id=${activityScope.environmentID}`);
    expect(screen.getByText(/Coverage is incomplete/)).toBeVisible();
    view.rerender(<APIProvider client={client}><ProductionRiskView path={pathname} api={api} canWrite={false} canReadRuns={false} onNavigate={navigate} selectedID={direct ? entity.id : undefined} activityScope={activityScope} /></APIProvider>);
    expect(screen.queryByRole("button", { name: `Open run ${runID}` })).not.toBeInTheDocument();
    expect(requests).toHaveLength(1);
  });

  it("refuses mismatched list-open path detail before reading related runs", async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ items: [], coverage: "partial" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }));
    const api = fixtureAPI({ getAttackPath: async () => ({ ...path, id: finding.id }) });
    render(<APIProvider client={createAPIClient({ fetch: fetcher })}><ProductionRiskView path="/exposure/attack-paths" api={api} canWrite={false} canReadRuns activityScope={activityScope} /></APIProvider>);
    await userEvent.click(await screen.findByRole("button", { name: `Open attack path ${path.id}` }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Attack path detail identity mismatch");
    expect(screen.queryByText("Related Security Agent runs")).not.toBeInTheDocument();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("locks related run navigation while a finding mutation is unresolved", async () => {
    const pending = deferred<Awaited<ReturnType<ProductionRiskAPI["updateFinding"]>>>();
    const runID = "pid_78000009-0000-4000-8000-000000000009";
    const client = createAPIClient({ fetch: async () => new Response(JSON.stringify({ items: [{ id: runID, agent_id: finding.agent_id, state: "queued", evidence_ids: [finding.evidence_ids[0]], definition_version: 1, version: 1 }], coverage: "partial" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }) });
    render(<APIProvider client={client}><ProductionRiskView path="/violations" api={fixtureAPI({ updateFinding: () => pending.promise })} canWrite canReadRuns onNavigate={vi.fn()} selectedID={finding.id} activityScope={activityScope} /></APIProvider>);
    expect(await screen.findByRole("button", { name: `Open run ${runID}` })).toBeEnabled();
    await userEvent.click(screen.getByRole("button", { name: "Mark under review" }));
    expect(screen.getByRole("button", { name: `Open run ${runID}` })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Reload related activity" })).toBeDisabled();
    await act(async () => pending.resolve(await fixtureAPI().updateFinding(finding.id, "under_review", '"1"', { idempotencyKey: "test" })));
    expect(screen.getByRole("button", { name: `Open run ${runID}` })).toBeEnabled();
  });

  it("opens a linked finding directly without enumerating a list", async () => {
    const list = vi.fn(async () => { throw new Error("List must not be required for an exact link"); });
    const get = vi.fn(async (id: string) => {
      expect(id).toBe(finding.id);
      return { value: finding, version: '"1"' };
    });
    renderRisk("/violations", fixtureAPI({ listFindings: list, getFinding: get }), false, vi.fn(), finding.id);
    expect(await screen.findByRole("dialog", { name: finding.title })).toHaveTextContent(finding.evidence_ids[0]);
    expect(get).toHaveBeenCalledWith(finding.id, expect.any(AbortSignal));
    expect(list).not.toHaveBeenCalled();
    expect(screen.queryByText("No findings in this scope.")).not.toBeInTheDocument();
  });

  it("opens a linked attack path directly and binds break options to its fetched authority", async () => {
    const list = vi.fn(async () => { throw new Error("List must not be required for an exact link"); });
    const get = vi.fn(async (id: string) => { expect(id).toBe(path.id); return path; });
    const options = vi.fn(fixtureAPI().getAttackPathBreakOptions);
    renderRisk("/exposure/attack-paths", fixtureAPI({ listAttackPaths: list, getAttackPath: get, getAttackPathBreakOptions: options }), false, vi.fn(), path.id);
    const dialog = await screen.findByRole("dialog", { name: "Attack path detail" });
    await waitFor(() => expect(dialog).toHaveTextContent("1. Remove node"));
    expect(dialog).toHaveTextContent(path.node_ids.join(" → "));
    expect(options).toHaveBeenCalledWith(path, expect.any(AbortSignal));
    expect(list).not.toHaveBeenCalled();
    expect(screen.queryByText("No attack paths in this scope.")).not.toBeInTheDocument();
  });

  it("renders API findings, details, evidence, and capability-gated retained mutations", async () => {
    const update = vi.fn(fixtureAPI().updateFinding);
    const accept = vi.fn(fixtureAPI().acceptFindingRisk);
		const createTicket = vi.fn(fixtureAPI().createFindingTicket);
    renderRisk("/violations", fixtureAPI({ updateFinding: update, acceptFindingRisk: accept, createFindingTicket: createTicket }), true);
    await userEvent.click(await screen.findByRole("button", { name: "Open Public tool access" }));
    expect(await screen.findByRole("dialog", { name: "Public tool access" })).toHaveTextContent(finding.evidence_ids[0]);
		await userEvent.click(screen.getByRole("button", { name: "Create ticket" }));
		await waitFor(() => expect(createTicket).toHaveBeenCalledWith(finding.id, '"1"', expect.objectContaining({ idempotencyKey: expect.any(String) })));
		expect(await screen.findByText("Ticket SEC-1234 created.")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Mark under review" }));
    await waitFor(() => expect(update).toHaveBeenCalledWith(finding.id, "under_review", '"1"', expect.objectContaining({ idempotencyKey: expect.any(String) })));
    await userEvent.type(screen.getByLabelText("Risk acceptance reason"), "Approved exception");
    await userEvent.click(screen.getByRole("button", { name: "Accept risk" }));
    await waitFor(() => expect(accept).toHaveBeenCalledWith(finding.id, "Approved exception", expect.any(String), expect.objectContaining({ idempotencyKey: expect.any(String) })));
  });

  it("explains why, path, fix, and verification from authoritative finding fields", async () => {
    const navigate = vi.fn();
    renderRisk("/violations", fixtureAPI(), false, navigate);
    await userEvent.click(await screen.findByRole("button", { name: "Open Public tool access" }));
    const dialog = await screen.findByRole("dialog", { name: "Public tool access" });
    for (const heading of ["Why", "Evidence", "Path", "Fix", "Verify"]) expect(screen.getByRole("heading", { name: heading })).toBeInTheDocument();
    expect(dialog).toHaveTextContent("Public input");
    expect(dialog).toHaveTextContent(finding.evidence_ids[0]);
    expect(dialog).toHaveTextContent(finding.path_id);
    expect(dialog).toHaveTextContent("approved integration allowlist");
    await userEvent.click(screen.getByRole("button", { name: "Open attack path" }));
    expect(navigate).toHaveBeenCalledWith("/exposure/attack-paths?entity_id=pid_30000001-0000-4000-8000-000000000001&organization_id=pid_10000001-0000-4000-8000-000000000001&workspace_id=pid_10000002-0000-4000-8000-000000000002&environment_id=pid_10000003-0000-4000-8000-000000000003");
  });

  it("hides write controls without findings.write", async () => {
    renderRisk("/violations", fixtureAPI());
    await userEvent.click(await screen.findByRole("button", { name: "Open Public tool access" }));
    expect(await screen.findByRole("dialog", { name: "Public tool access" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Accept risk" })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Create ticket" })).not.toBeInTheDocument();
  });

	it("restores an exact scoped ticket result after reload without a second delivery", async () => {
		window.sessionStorage.clear();
		const createTicket = vi.fn(fixtureAPI().createFindingTicket);
		const api = fixtureAPI({ createFindingTicket: createTicket });
		const first = renderRisk("/violations", api, true);
		await userEvent.click(await screen.findByRole("button", { name: "Open Public tool access" }));
		await userEvent.click(screen.getByRole("button", { name: "Create ticket" }));
		expect(await screen.findByText("Ticket SEC-1234 created.")).toBeVisible();
		first.unmount();

		renderRisk("/violations", api, true);
		await userEvent.click(await screen.findByRole("button", { name: "Open Public tool access" }));
		expect(await screen.findByText("Ticket SEC-1234 created.")).toBeVisible();
		expect(createTicket).toHaveBeenCalledTimes(1);
		window.sessionStorage.clear();
	});

	it("removes a stored ticket result when the authoritative finding version changes", async () => {
		window.sessionStorage.clear();
		const first = renderRisk("/violations", fixtureAPI(), true);
		await userEvent.click(await screen.findByRole("button", { name: "Open Public tool access" }));
		await userEvent.click(screen.getByRole("button", { name: "Create ticket" }));
		expect(await screen.findByText("Ticket SEC-1234 created.")).toBeVisible();
		expect(window.sessionStorage.length).toBe(1);
		first.unmount();

		const changedFinding = { ...finding, status: "under_review" as const, version: 2 };
		renderRisk("/violations", fixtureAPI({ getFinding: async () => ({ value: changedFinding, version: '"2"' }) }), true);
		await userEvent.click(await screen.findByRole("button", { name: "Open Public tool access" }));
		expect(screen.queryByText("Ticket SEC-1234 created.")).not.toBeInTheDocument();
		expect(window.sessionStorage.length).toBe(0);
	});

  it("renders API attack-path order, evidence, and ranked path-local break options", async () => {
    renderRisk("/exposure/attack-paths", fixtureAPI());
    await userEvent.click(await screen.findByRole("button", { name: `Open attack path ${path.id}` }));
    const dialog = await screen.findByRole("dialog", { name: "Attack path detail" });
    expect(dialog).toHaveTextContent(`${path.node_ids[0]} → ${path.node_ids[1]}`);
    expect(dialog).toHaveTextContent("1. Remove node");
    expect(dialog).not.toHaveTextContent(/ticket|rerun|simulate/i);
  });

  it("opens attack-path detail immediately and preserves independent partial loading and error truth", async () => {
    const detail = deferred<typeof path>();
    const options = deferred<readonly []>();
    renderRisk("/exposure/attack-paths", fixtureAPI({
      getAttackPath: vi.fn(() => detail.promise),
      getAttackPathBreakOptions: vi.fn(() => options.promise),
    }));
    await userEvent.click(await screen.findByRole("button", { name: `Open attack path ${path.id}` }));

    const dialog = screen.getByRole("dialog", { name: "Attack path detail" });
    expect(dialog).toHaveTextContent("Loading path detail…");
    expect(dialog).toHaveTextContent("Loading break options…");
    await act(async () => detail.resolve(path));
    await waitFor(() => expect(dialog).toHaveTextContent(`${path.node_ids[0]} → ${path.node_ids[1]}`));
    expect(dialog).toHaveTextContent("Loading break options…");
    await act(async () => options.reject(new Error("Break-option provider unavailable")));
    expect(await screen.findByText("Break-option provider unavailable")).toHaveAttribute("role", "alert");
    expect(dialog).toHaveTextContent(`${path.node_ids[0]} → ${path.node_ids[1]}`);
  });

  it("aborts finding detail on route unmount and ignores a late response", async () => {
    const detail = deferred<{ value: typeof finding; version: string }>();
    let signal: AbortSignal | undefined;
    const api = fixtureAPI({ getFinding: vi.fn((_id, currentSignal) => { signal = currentSignal; return detail.promise; }) });
    const view = renderRisk("/violations", api);
    await userEvent.click(await screen.findByRole("button", { name: "Open Public tool access" }));
    expect(signal?.aborted).toBe(false);

    view.rerender(<APIProvider><QueryScope><ProductionRiskView path="/exposure/attack-paths" api={api} canWrite={false} /></QueryScope></APIProvider>);
    expect(signal?.aborted).toBe(true);
    await act(async () => detail.resolve({ value: finding, version: '"1"' }));
    expect(screen.queryByRole("dialog", { name: "Public tool access" })).not.toBeInTheDocument();
  });

  it("aborts both attack-path detail requests on route unmount and ignores late settlements", async () => {
    const detail = deferred<typeof path>();
    const options = deferred<readonly []>();
    const signals: AbortSignal[] = [];
    const api = fixtureAPI({
      getAttackPath: vi.fn((_id, signal) => { if (signal) signals.push(signal); return detail.promise; }),
      getAttackPathBreakOptions: vi.fn((_id, signal) => { if (signal) signals.push(signal); return options.promise; }),
    });
    const view = renderRisk("/exposure/attack-paths", api);
    await userEvent.click(await screen.findByRole("button", { name: `Open attack path ${path.id}` }));
    expect(signals).toHaveLength(2);

    view.rerender(<APIProvider><QueryScope><ProductionRiskView path="/violations" api={api} canWrite={false} /></QueryScope></APIProvider>);
    expect(signals.every((signal) => signal.aborted)).toBe(true);
    await act(async () => { detail.resolve(path); options.resolve([]); });
    expect(screen.queryByRole("dialog", { name: "Attack path detail" })).not.toBeInTheDocument();
  });
});
