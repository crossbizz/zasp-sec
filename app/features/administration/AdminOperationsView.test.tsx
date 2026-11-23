import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createAPIClient } from "../../../apps/web/api/client";
import { describe, expect, it, vi } from "vitest";
import { AdminOperationsView, type AdminOperationsAPI } from "./AdminOperationsView";

const productID = "pid_10000001-0000-4000-8000-000000000001";
function api(overrides: Partial<AdminOperationsAPI> = {}): AdminOperationsAPI { return {
  getHealth: async () => ({ status: { security_plane_healthy: false, optional_degraded: false, fresh_at: "2026-08-19T00:00:00Z" }, components: [{ id: "postgresql", required: true, state: "healthy", fresh_at: "2026-08-19T00:00:00Z" }, { id: "identity-provider", required: true, state: "unavailable", fresh_at: "2026-08-19T00:00:00Z" }], version: "1.0.0" }),
  getExternalFlows: async () => [{ id: "identity-provider", required: true, categories: ["identity_metadata"], enabled: true, health: "degraded" }],
  ...overrides,
}; }

describe("production administration state", () => {
  it("distinguishes an unavailable adapter inventory from a confirmed empty result and retries", async () => {
    const getExternalFlows = vi.fn(api().getExternalFlows).mockRejectedValueOnce(new Error("unavailable"));
    render(<AdminOperationsView surface="external" api={api({ getExternalFlows })} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Administration data could not be loaded");
    expect(screen.queryByText("No external adapters registered")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("identity-provider")).toBeVisible();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
  it("exposes organization export independently of a failed browse request when installed and authorized", async () => {
    const exports = { api: { create: async () => { throw new Error("unused"); }, read: async () => { throw new Error("unused"); } }, authority: { principalID: productID, organizationID: productID, workspaceID: productID, environmentID: productID, generation: 1, permitted: true, fresh: true }, retrySession: async () => {}, reauthenticate: () => {} };
    render(<AdminOperationsView surface="audit" auditAPI={{ page: async () => { throw new Error("browse unavailable"); } }} {...{ auditExport: exports }} />);
    expect(screen.getByRole("button", { name: "Create export" })).toBeEnabled();
    expect(screen.getByText(/unaffected by visible list filters/)).toBeVisible();
  });
  it("loads only the current audit page and sends applied exact filters on Next", async () => {
    const requests: URL[] = [];
    const client = createAPIClient({ fetch: async (request) => {
      const url = new URL(request.url); requests.push(url);
      return new Response(JSON.stringify({ items: [{ id: productID, workspace_id: productID, environment_id: productID, actor_id: productID, action: "identity_provider.createSSOConnection", target_id: productID, outcome: "succeeded", metadata: {}, occurred_at: "2026-08-19T00:00:00Z" }], page_info: { has_more: true, next_cursor: `cursor-${requests.length}` } }), { headers: { "Content-Type": "application/json" } });
    } });
    render(<AdminOperationsView surface="audit" client={client} />);
    expect(await screen.findByText("identity_provider.createSSOConnection")).toBeVisible();
    expect(requests).toHaveLength(1);
    await userEvent.type(screen.getByLabelText("Action (exact)"), "identity_provider.createSSOConnection");
    await userEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(requests[1].searchParams.get("action")).toBe("identity_provider.createSSOConnection");
    expect(requests[1].searchParams.has("cursor")).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(requests).toHaveLength(3));
    expect(requests[2].searchParams.get("cursor")).toBe("cursor-2");
    expect(requests[2].searchParams.get("action")).toBe("identity_provider.createSSOConnection");
  });
  it("distinguishes optional model degradation from required enforcement health", async () => {
    render(<AdminOperationsView surface="health" api={api({ getHealth: async () => ({
      status: { security_plane_healthy: true, optional_degraded: true, fresh_at: "2026-08-19T00:00:00Z" },
      components: [{ id: "private-model", required: false, state: "unknown", fresh_at: "2026-08-19T00:00:00Z" }], version: "1.0.0",
    }) })} />);
    expect(await screen.findByText("Security plane healthy")).toBeVisible();
    expect(screen.getByText("Optional components need attention.")).toBeVisible();
    expect(screen.getByText("unknown")).toBeVisible();
  });
  it("shows a registered adapter's actual egress categories and enablement", async () => {
    render(<AdminOperationsView surface="external" api={api({ getExternalFlows: async () => [
      { id: "private-model", required: false, enabled: true, health: "unknown", categories: ["redacted_summary", "approved_code_snippet", "private_addon"] },
    ] })} />);
    expect(await screen.findByText("private-model")).toBeVisible();
    expect(screen.getByText("Yes")).toBeVisible();
    expect(screen.getByText("redacted_summary · approved_code_snippet · private_addon")).toBeVisible();
  });
  it("labels both dimensions of the release evidence table", async () => {
    render(<AdminOperationsView surface="health" api={api()} />);
    const table = await screen.findByRole("table", { name: "Test scope and evidence needed for a live deployment" });
    expect(within(table).getByRole("rowheader", { name: "Local skill scan" })).toHaveAttribute("scope", "row");
    expect(within(table).getByRole("columnheader", { name: "Covered by release tests" })).toHaveAttribute("scope", "col");
  });
  it("renders only real probed components", async () => { render(<AdminOperationsView surface="health" api={api()} />); expect(await screen.findByText("Security plane degraded")).toBeVisible(); expect(screen.getByText("postgresql")).toBeVisible(); expect(screen.getByText("identity-provider")).toBeVisible(); expect(screen.queryByText(/remote telemetry/i)).not.toBeInTheDocument(); });
  it("derives external flow inventory from the registered adapter", async () => { render(<AdminOperationsView surface="external" api={api()} />); expect(await screen.findByText("identity-provider")).toBeVisible(); expect(screen.queryByText(/product analytics/i)).not.toBeInTheDocument(); });
  it("keeps durable audit readable and export disabled without claiming an installation state", async () => { render(<AdminOperationsView surface="audit" auditAPI={{ page: async () => ({ items: [{ id: productID, workspace_id: productID, environment_id: productID, actor_id: productID, action: "member.role.update", target_id: productID, outcome: "succeeded", metadata: {}, occurred_at: "2026-08-19T00:00:00Z" }], page_info: { has_more: false, next_cursor: null } }) }} />); expect(await screen.findByText("member.role.update")).toBeVisible(); expect(screen.getByText("Audit exports unavailable")).toBeVisible(); expect(screen.getByText("Export is unavailable for this session or installation.")).toBeVisible(); expect(screen.queryByText(/no export mutation is mounted/i)).not.toBeInTheDocument(); expect(screen.queryByRole("button", { name: /export/i })).not.toBeInTheDocument(); });
});
