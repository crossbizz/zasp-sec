import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AdminOperationsView, type AdminOperationsAPI } from "./AdminOperationsView";

const productID = "pid_10000001-0000-4000-8000-000000000001";
function api(overrides: Partial<AdminOperationsAPI> = {}): AdminOperationsAPI { return {
  getHealth: async () => ({ status: { security_plane_healthy: false, optional_degraded: false, fresh_at: "2026-08-19T00:00:00Z" }, components: [{ id: "postgresql", required: true, state: "healthy", fresh_at: "2026-08-19T00:00:00Z" }, { id: "identity-provider", required: true, state: "unavailable", fresh_at: "2026-08-19T00:00:00Z" }], version: "1.0.0" }),
  getExternalFlows: async () => [{ id: "identity-provider", required: true, categories: ["identity_metadata"], enabled: true, health: "degraded" }],
  listAuditEvents: async () => [{ id: productID, workspace_id: productID, environment_id: productID, actor_id: productID, action: "member.role.update", target_id: productID, outcome: "succeeded", metadata: {}, occurred_at: "2026-08-19T00:00:00Z" }],
  ...overrides,
}; }

describe("production administration state", () => {
  it("renders only real probed components", async () => { render(<AdminOperationsView surface="health" api={api()} />); expect(await screen.findByText("Security plane degraded")).toBeVisible(); expect(screen.getByText("postgresql")).toBeVisible(); expect(screen.getByText("identity-provider")).toBeVisible(); expect(screen.queryByText(/remote telemetry/i)).not.toBeInTheDocument(); });
  it("derives external flow inventory from the registered adapter", async () => { render(<AdminOperationsView surface="external" api={api()} />); expect(await screen.findByText("identity-provider")).toBeVisible(); expect(screen.queryByText(/product analytics/i)).not.toBeInTheDocument(); });
  it("keeps durable audit readable and export unmounted", async () => { render(<AdminOperationsView surface="audit" api={api()} />); expect(await screen.findByText("member.role.update")).toBeVisible(); expect(screen.getByText("Audit exports unavailable")).toBeVisible(); expect(screen.queryByRole("button", { name: /export/i })).not.toBeInTheDocument(); });
});
