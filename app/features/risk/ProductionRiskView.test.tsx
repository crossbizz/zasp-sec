import { useEffect, type ReactNode } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { APIProvider, useAPI } from "../../api/APIProvider";
import type { ProductionRiskAPI } from "./api";
import { ProductionRiskView } from "./ProductionRiskView";

const finding = { id: "pid_20000001-0000-4000-8000-000000000001", source: "posture", title: "Public tool access", severity: "high", status: "open", evidence_ids: ["pid_20000002-0000-4000-8000-000000000002"], risk_factors: [{ name: "Public input", evidence_id: "pid_20000002-0000-4000-8000-000000000002" }], version: 1, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z" } as const;
const path = { id: "pid_30000001-0000-4000-8000-000000000001", entry_id: "pid_30000002-0000-4000-8000-000000000002", sink_id: "pid_30000003-0000-4000-8000-000000000003", node_ids: ["pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003"], state: "verified", evidence_ids: [finding.evidence_ids[0]], blocked_edge: -1, version: 1, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z" } as const;

function QueryScope({ children }: { children: ReactNode }) {
  const { setQueryScope } = useAPI();
  useEffect(() => setQueryScope("risk-test-scope"), [setQueryScope]);
  return children;
}

function renderRisk(pathname: "/violations" | "/exposure/attack-paths", api: ProductionRiskAPI, canWrite = false) {
  return render(<APIProvider><QueryScope><ProductionRiskView path={pathname} api={api} canWrite={canWrite} /></QueryScope></APIProvider>);
}

function fixtureAPI(overrides: Partial<ProductionRiskAPI> = {}): ProductionRiskAPI {
  return {
    async listFindings() { return [finding]; }, async getFinding() { return { value: finding, version: '"1"' }; },
    async updateFinding() { return { value: { ...finding, status: "under_review", version: 2 }, version: '"2"', auditID: "pid_40000001-0000-4000-8000-000000000001", receiptID: "pid_40000002-0000-4000-8000-000000000002" }; },
    async acceptFindingRisk() { return { value: { ...finding, status: "accepted", acceptance_reason: "Approved exception", version: 2 }, version: '"2"', auditID: "pid_40000001-0000-4000-8000-000000000001", receiptID: "pid_40000002-0000-4000-8000-000000000002" }; },
    async listAttackPaths() { return [path]; }, async getAttackPath() { return path; }, async getAttackPathBreakOptions() { return [{ path_id: path.id, target_id: path.entry_id, evidence_id: finding.evidence_ids[0], kind: "remove_node", rank: 1 }]; },
    ...overrides,
  };
}

describe("production risk views", () => {
  it("renders API findings, details, evidence, and capability-gated retained mutations", async () => {
    const update = vi.fn(fixtureAPI().updateFinding);
    const accept = vi.fn(fixtureAPI().acceptFindingRisk);
    renderRisk("/violations", fixtureAPI({ updateFinding: update, acceptFindingRisk: accept }), true);
    await userEvent.click(await screen.findByRole("button", { name: "Open Public tool access" }));
    expect(await screen.findByRole("dialog", { name: "Public tool access" })).toHaveTextContent(finding.evidence_ids[0]);
    await userEvent.click(screen.getByRole("button", { name: "Mark under review" }));
    await waitFor(() => expect(update).toHaveBeenCalledWith(finding.id, "under_review", '"1"', expect.objectContaining({ idempotencyKey: expect.any(String) })));
    await userEvent.type(screen.getByLabelText("Risk acceptance reason"), "Approved exception");
    await userEvent.click(screen.getByRole("button", { name: "Accept risk" }));
    await waitFor(() => expect(accept).toHaveBeenCalledWith(finding.id, "Approved exception", expect.any(String), expect.objectContaining({ idempotencyKey: expect.any(String) })));
  });

  it("hides write controls without findings.write", async () => {
    renderRisk("/violations", fixtureAPI());
    await userEvent.click(await screen.findByRole("button", { name: "Open Public tool access" }));
    expect(await screen.findByRole("dialog", { name: "Public tool access" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Accept risk" })).not.toBeInTheDocument();
  });

  it("renders API attack-path order, evidence, and ranked path-local break options", async () => {
    renderRisk("/exposure/attack-paths", fixtureAPI());
    await userEvent.click(await screen.findByRole("button", { name: `Open attack path ${path.id}` }));
    const dialog = await screen.findByRole("dialog", { name: "Attack path detail" });
    expect(dialog).toHaveTextContent(`${path.node_ids[0]} → ${path.node_ids[1]}`);
    expect(dialog).toHaveTextContent("1. Remove node");
    expect(dialog).not.toHaveTextContent(/ticket|rerun|simulate/i);
  });
});
