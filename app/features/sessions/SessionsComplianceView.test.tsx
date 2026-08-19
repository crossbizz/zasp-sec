import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SessionsComplianceView, type SessionsComplianceAPI } from "./SessionsComplianceView";

const principal = "pid_10000004-0000-4000-8000-000000000004";
const workspace = "pid_10000002-0000-4000-8000-000000000002";
const environment = "pid_10000003-0000-4000-8000-000000000003";
function api(overrides: Partial<SessionsComplianceAPI> = {}): SessionsComplianceAPI { return {
  listSessions: async () => [{ id: "session-live", agent_id: "product-console", principal_id: principal, workspace_id: workspace, environment_id: environment, state: "active", authenticated_at: "2026-08-19T00:00:00Z", expires_at: "2026-08-20T00:00:00Z", version: 1, events: [{ id: "event-1", session_id: "session-live", class: "tool", label: "Shell requested", evidence_id: "evidence-1", source: "product", confidence: "exact", at: "2026-08-19T00:00:01Z" }] }],
  revokeSession: async () => undefined,
  listControls: async () => [{ id: "access-control", framework: "SOC 2", name: "Security", evidence_ids: ["evidence-1"], fresh_until: "2026-08-20T00:00:00Z" }],
  listEvidence: async () => [{ control: { id: "access-control", framework: "SOC 2", name: "Security", evidence_ids: ["evidence-1"], fresh_until: "2026-08-20T00:00:00Z" }, freshness: "fresh", evidence: [{ id: "evidence-1", asset_id: "asset-1", source: "runtime", at: "2026-08-19T00:00:00Z" }] }],
  getDataControls: async () => ({ environment_id: environment, environment_class: "production", collection_mode: "metadata_only", retention_days: 30, deletion_enabled: true, version: 1 }),
  updateDataControls: async (value) => ({ ...value, version: value.version + 1 }),
  ...overrides,
}; }

describe("Sessions, compliance, and data controls", () => {
  it("renders ordered evidence and revokes the exact version", async () => { const revoke = vi.fn(api().revokeSession); render(<SessionsComplianceView surface="sessions" api={api({ revokeSession: revoke })} canMutate />); expect(await screen.findByText(/Shell requested/)).toHaveTextContent("evidence-1"); await userEvent.click(screen.getByRole("button", { name: "Revoke session" })); expect(revoke).toHaveBeenCalledWith("session-live", 1); expect(await screen.findByRole("status")).toHaveTextContent("Session revoked"); });
  it("renders local evidence and keeps exports unavailable", async () => { render(<SessionsComplianceView surface="compliance" api={api()} />); expect(await screen.findByText(/SOC 2/)).toBeVisible(); expect(screen.getByText(/asset-1/)).toBeVisible(); expect(screen.getByText("Evidence exports unavailable")).toBeVisible(); expect(screen.queryByRole("button", { name: /export/i })).not.toBeInTheDocument(); });
  it("updates versioned metadata-only production controls", async () => { const update = vi.fn(api().updateDataControls); render(<SessionsComplianceView surface="data-controls" api={api({ updateDataControls: update })} canMutate />); expect(await screen.findByDisplayValue("30")).toBeVisible(); await userEvent.clear(screen.getByLabelText("Retention days")); await userEvent.type(screen.getByLabelText("Retention days"), "60"); await userEvent.click(screen.getByRole("button", { name: "Save data controls" })); expect(update).toHaveBeenCalledWith(expect.objectContaining({ retention_days: 60, version: 1 })); });
});
