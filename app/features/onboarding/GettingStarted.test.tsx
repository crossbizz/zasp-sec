import { act, fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import { APIProvider } from "../../api/APIProvider";
import { GettingStarted } from "./GettingStarted";

const admin = { read: true, write: true };
const viewer = { read: true, write: false };
const hidden = { read: false, write: false };
const id = "pid_20000001-0000-4000-8000-000000000001";
const now = "2026-08-19T00:00:00Z";
const integration = { id, connector_key: "slack", name: "Engineering", configuration: { workspace_label: "Engineering" }, status: "active", created_at: now, updated_at: now };
const sensor = { id, name: "Cluster", kind: "tetragon", mode: "metadata_only", state: "active", version: 1, token_expires_at: "2026-10-19T00:00:00Z", last_heartbeat_at: now, created_at: now, updated_at: now };

function setup({ integrations = admin, sensors = admin, environmentVisible = true, rows = {}, unavailable = "" }: {
  integrations?: typeof admin; sensors?: typeof admin; environmentVisible?: boolean; rows?: Record<string, unknown[]>; unavailable?: string;
} = {}) {
  const navigate = vi.fn();
  const GET = vi.fn(async (path: string) => {
    if (path === unavailable) throw new Error("Offline");
    return { data: { items: rows[path] ?? [], page_info: { has_more: false, next_cursor: null } }, response: new Response(null) };
  });
  render(<APIProvider client={{ GET } as unknown as APIClient}><GettingStarted integrations={integrations} sensors={sensors} environmentVisible={environmentVisible} onNavigate={navigate} /></APIProvider>);
  return { GET, navigate };
}

describe("getting started in the active environment", () => {
  it("opens the catalog and sensor enrollment from an empty environment", async () => {
    const { navigate } = setup();
    fireEvent.click(await screen.findByRole("button", { name: "Connect an integration" }));
    fireEvent.click(await screen.findByRole("button", { name: "Enroll a sensor" }));
    expect(navigate.mock.calls).toEqual([["/connectors#add-source"], ["/integrations/sensors?enroll=1"]]);
  });
  it("continues configured sources without prompting to create duplicates", async () => {
    const { navigate } = setup({ rows: { "/api/v1/integrations": [integration], "/api/v1/sensors": [sensor] } });
    fireEvent.click(await screen.findByRole("button", { name: "View integrations" }));
    fireEvent.click(await screen.findByRole("button", { name: "View sensors" }));
    expect(screen.getByRole("heading", { name: "Check your data collection" })).toBeVisible();
    expect(navigate.mock.calls).toEqual([["/connectors"], ["/integrations/sensors"]]);
  });
  it("explains who can set up discovery to a reader and skips inaccessible source requests", async () => {
    const { GET } = setup({ integrations: viewer, sensors: hidden });
    expect(await screen.findByText(/Ask your administrator to connect a provider/)).toBeVisible();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(GET.mock.calls.map(([path]) => path)).not.toContain("/api/v1/sensors");
  });
  it("offers an enabled Nango source when the only saved record is native", async () => {
    const native = { ...integration, connector_key: "github", configuration: { authorization_mode: "github_app" } };
    setup({ rows: { "/api/v1/integrations": [native] } });
    expect(await screen.findByRole("button", { name: "Connect an integration" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "View integrations" })).not.toBeInTheDocument();
  });
  it("does not infer tenant emptiness from an incomplete inventory read", async () => {
    const { GET } = setup({ unavailable: "/api/v1/tools" });
    expect(await screen.findByRole("button", { name: "Retry setup status" })).toBeVisible();
    expect(screen.queryByRole("heading", { name: /Get started/ })).not.toBeInTheDocument();
    expect(GET.mock.calls.map(([path]) => path)).not.toContain("/api/v1/integrations");
  });
  it("keeps the setup guide closed when discovery has already found an identity", async () => {
    const identity = {
      id, kind: "identity", name: "Deployment role", owner: "security", team: "platform", tags: [],
      evidence_id: id, confidence_basis_points: 9500, first_seen: now, last_seen: now, observed_at: now,
      fresh_until: "2026-08-19T01:00:00Z", freshness_state: "fresh", version: 1, provider: "aws",
      source_kind: "aws_role", discovery: { method: "provider_api", platform: "aws_role", signals: [] },
      management_state: "not_applicable", last_activity_at: null, activity_state: "not_applicable",
    };
    const { GET } = setup({ rows: { "/api/v1/identities": [identity] } });
    await act(async () => {});
    expect(GET.mock.calls.map(([path]) => path)).toEqual(["/api/v1/tools", "/api/v1/identities", "/api/v1/runtimes"]);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.queryByRole("heading")).not.toBeInTheDocument();
  });
  it("keeps an unavailable source distinct from a first-time enrollment", async () => {
    setup({ unavailable: "/api/v1/integrations" });
    expect(await screen.findByRole("button", { name: "Retry integrations" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Connect an integration" })).not.toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Enroll a sensor" })).toBeVisible();
  });
  it("keeps collection-restricted visibility scoped to the member", () => {
    const { GET } = setup({ environmentVisible: false });
    expect(screen.getByText(/No agents are visible in your scope/)).toBeVisible();
    expect(GET).not.toHaveBeenCalled();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
