import { useEffect, type ReactNode } from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { APIProvider, useAPI } from "../../api/APIProvider";
import type { ProductionRiskAPI } from "./api";
import { ProductionRiskView } from "./ProductionRiskView";

const finding = { id: "pid_20000001-0000-4000-8000-000000000001", source: "posture", rule: "unapproved_tool", title: "Public tool access", severity: "high", status: "open", agent_id: "pid_20000004-0000-4000-8000-000000000004", path_id: "pid_30000001-0000-4000-8000-000000000001", evidence_ids: ["pid_20000002-0000-4000-8000-000000000002"], risk_factors: [{ name: "Public input", evidence_id: "pid_20000002-0000-4000-8000-000000000002" }], version: 1, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z" } as const;
const path = { id: "pid_30000001-0000-4000-8000-000000000001", entry_id: "pid_30000002-0000-4000-8000-000000000002", sink_id: "pid_30000003-0000-4000-8000-000000000003", node_ids: ["pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003"], state: "verified", evidence_ids: [finding.evidence_ids[0]], blocked_edge: -1, version: 1, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z" } as const;

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

function renderRisk(pathname: "/violations" | "/exposure/attack-paths", api: ProductionRiskAPI, canWrite = false, onNavigate = vi.fn()) {
  return render(<APIProvider><QueryScope><ProductionRiskView path={pathname} api={api} canWrite={canWrite} onNavigate={onNavigate} /></QueryScope></APIProvider>);
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
    expect(navigate).toHaveBeenCalledWith("/exposure/attack-paths");
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
    expect(await screen.findByRole("alert")).toHaveTextContent("Break-option provider unavailable");
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
