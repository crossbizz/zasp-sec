import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { Integration, IntegrationFreshness } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { ProductionIntegrationsView } from "./ProductionWorkflowViews";

const integrationID = "pid_20000001-0000-4000-8000-000000000001";
const syncID = "pid_20000002-0000-4000-8000-000000000002";
const snapshotID = "pid_20000003-0000-4000-8000-000000000003";
const integration: Integration = { id: integrationID, connector_key: "github", name: "GitHub", configuration: { authorization_mode: "github_app" }, status: "active", created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:01:00Z" };
const manifest = { key: "github", provider: "GitHub", category: "source", description: "GitHub inventory", data_types: ["repositories"], actions: ["inventory_read"], auth_mode: "github_app", setup_schema: [{ key: "installation_reference", label: "Installation reference", type: "reference", required: true, description: "Opaque installation reference" }], access_guidance: "Read-only inventory", test_semantics: "Read-only probe" };
const sync = { id: syncID, integration_id: integrationID, trigger_kind: "manual", status: "succeeded", attempt: 1, requested_at: "2026-08-19T00:00:00Z", started_at: "2026-08-19T00:00:01Z", completed_at: "2026-08-19T00:00:02Z", discovered_count: 10, changed_count: 3, removed_count: 1, snapshot_id: snapshotID, last_error_code: null, retry_at: null };
const queued = { ...sync, status: "queued", attempt: 0, started_at: null, completed_at: null, discovered_count: 0, changed_count: 0, removed_count: 0, snapshot_id: null };
const schedule = { integration_id: integrationID, cadence_seconds: 3600, state: "enabled", time_zone: "UTC", next_run_at: "2026-08-19T01:00:00Z", version: 1, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z" };
const freshness = { integration_id: integrationID, version: 7, last_good: { snapshot_id: snapshotID, collected_at: "2026-08-19T00:00:02Z", discovered_count: 10, changed_count: 3, removed_count: 1 }, latest_sync: sync, projections: { risk: { state: "current", snapshot_id: snapshotID, completed_at: "2026-08-19T00:00:03Z", last_error_code: null }, graph: { state: "pending", snapshot_id: snapshotID, completed_at: null, last_error_code: null }, search: { state: "degraded", snapshot_id: snapshotID, completed_at: "2026-08-19T00:00:03Z", last_error_code: "terminal" } }, updated_at: "2026-08-19T00:00:04Z" };
const receiptHeaders = { ETag: '"1"', "Cache-Control": "no-store", "X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001", "X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002" };

describe("production integration discovery workflows", () => {
  it("renders independent freshness, bounded history, and UTC schedule without internal identifiers or errors", async () => {
    const user = userEvent.setup();
    renderSurface(discoveryClient());
    await user.click(await screen.findByRole("button", { name: "Open GitHub" }));
    const dialog = screen.getByRole("dialog", { name: "GitHub" });

    expect(await within(dialog).findByText("Risk projection: current")).toBeVisible();
    expect(within(dialog).getByText("Graph projection: pending")).toBeVisible();
    expect(within(dialog).getByText("Search projection: degraded")).toBeVisible();
    expect(within(dialog).getByText("Every 3600 seconds · UTC")).toBeVisible();
    expect(within(dialog).getByRole("button", { name: "Open succeeded sync" })).toBeVisible();
    expect(dialog).not.toHaveTextContent(syncID);
    expect(dialog).not.toHaveTextContent(snapshotID);
    expect(dialog).not.toHaveTextContent("retryable");
  });

  it("gates manual sync on active first-party inventory authority and write permission", async () => {
    const user = userEvent.setup();
    const noInventory = { ...manifest, actions: ["connection_test"] };
    const view = renderSurface(discoveryClient({ catalog: noInventory }), true);
    await user.click(await screen.findByRole("button", { name: "Open GitHub" }));
    expect(screen.queryByRole("button", { name: "Sync inventory now" })).not.toBeInTheDocument();

    view.unmount();
    renderSurface(discoveryClient(), false);
    await user.click(await screen.findByRole("button", { name: "Open GitHub" }));
    expect(screen.queryByRole("button", { name: "Sync inventory now" })).not.toBeInTheDocument();
  });

  it("keeps sync pending until the canonical 202 receipt and then shows only a safe result", async () => {
    const user = userEvent.setup();
    const accepted = deferred<ReturnType<typeof jsonResult>>();
    const client = discoveryClient({ POST: vi.fn(() => accepted.promise) });
    renderSurface(client);
    await user.click(await screen.findByRole("button", { name: "Open GitHub" }));
    await user.click(await screen.findByRole("button", { name: "Sync inventory now" }));
    expect(screen.getByRole("button", { name: "Sync inventory now" })).toBeDisabled();
    expect(screen.queryByText(/Sync queued/)).not.toBeInTheDocument();

    accepted.resolve(jsonResult(queued, 202, receiptHeaders));
    expect(await screen.findByRole("status")).toHaveTextContent("Inventory sync queued. Audit pid_30000001-0000-4000-8000-000000000001");
    expect(document.body.innerHTML).not.toContain(syncID);
    expect(document.body.innerHTML).not.toContain(snapshotID);
  });

  it("keeps a sync 409 locked until the authoritative integration refetch succeeds", async () => {
    const user = userEvent.setup();
    const changed = { ...integration, name: "GitHub current", updated_at: "2026-08-19T00:02:00Z" };
    const POST = vi.fn(async () => productError(409, "conflict"));
    renderSurface(discoveryClient({ POST, details: [integration, changed] }));
    await user.click(await screen.findByRole("button", { name: "Open GitHub" }));
    await user.click(await screen.findByRole("button", { name: "Sync inventory now" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Discovery settings changed. Review the authoritative state before retrying.");
    expect(screen.getByRole("dialog", { name: "GitHub current" })).toBeVisible();
    expect(screen.queryByText(/Inventory sync queued/)).not.toBeInTheDocument();
    expect(POST).toHaveBeenCalledOnce();
  });

  it("updates and deletes the singleton only after canonical mutation receipts", async () => {
    const user = userEvent.setup();
    const updated = { ...schedule, cadence_seconds: 7200, version: 2, next_run_at: "2026-08-19T02:00:00Z", updated_at: "2026-08-19T00:00:02Z" };
    const PUT = vi.fn(async () => jsonResult(updated, 200, { ...receiptHeaders, ETag: '"2"' }));
    const DELETE = vi.fn(async () => ({ response: new Response(null, { status: 204, headers: { ...receiptHeaders, ETag: '"3"' } }) }));
    renderSurface(discoveryClient({ PUT, DELETE }));
    await user.click(await screen.findByRole("button", { name: "Open GitHub" }));
    const cadence = await screen.findByLabelText("Automatic sync cadence seconds");
    fireEvent.change(cadence, { target: { value: "7200" } });
    await user.click(screen.getByRole("button", { name: "Save automatic sync" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Automatic sync schedule saved");
    expect(screen.getByText("Every 7200 seconds · UTC")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Delete automatic sync" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Automatic sync schedule deleted");
    await waitFor(() => expect(screen.queryByText(/Every 7200 seconds/)).not.toBeInTheDocument());
  });

  it("keeps denied AWS coverage incomplete and gives exact read-role remediation", async () => {
    const user = userEvent.setup();
    const aws: Integration = { ...integration, connector_key: "aws", name: "Production AWS", configuration: { role_arn: "arn:aws:iam::123456789012:role/zasp-discovery", external_id_reference: "ref:aws/external-id/customer-0001", region: "us-east-1" }, status: "degraded" };
    const awsManifest = {
      ...manifest, key: "aws", provider: "Amazon Web Services", data_types: ["identity", "policy", "resource"], actions: ["inventory_read", "posture_read"], auth_mode: "aws_assume_role",
      setup_schema: [
        { key: "role_arn", label: "Read role ARN", type: "string", required: true, description: "Customer read role" },
        { key: "external_id_reference", label: "External ID", type: "secret_reference", required: true, description: "Opaque trust reference" },
        { key: "region", label: "Home region", type: "string", required: true, description: "Inventory region" },
      ],
      access_guidance: "Grant the documented read-only policy to one external-ID-bound role.", test_semantics: "Assume the role and verify the returned account identity.",
    };
    const failed = { ...sync, integration_id: aws.id, trigger_kind: "manual" as const, status: "failed" as const, snapshot_id: null, discovered_count: 0, changed_count: 0, removed_count: 0, last_error_code: "denied" as const };
    const deniedFreshness = { ...freshness, integration_id: aws.id, last_good: null, latest_sync: failed, projections: {
      risk: { state: "unavailable", snapshot_id: null, completed_at: null, last_error_code: null },
      graph: { state: "unavailable", snapshot_id: null, completed_at: null, last_error_code: null },
      search: { state: "unavailable", snapshot_id: null, completed_at: null, last_error_code: null },
    } } satisfies IntegrationFreshness;
    renderSurface(discoveryClient({ catalog: awsManifest, integration: aws, freshness: deniedFreshness }));

    await user.click(await screen.findByRole("button", { name: "Open Production AWS" }));
    const dialog = screen.getByRole("dialog", { name: "Production AWS" });
    expect(await within(dialog).findByText("AWS read role was denied. Add the documented read-only permissions, then run Test connection again.")).toBeVisible();
    expect(within(dialog).getByText("Review coverage").closest("li")).toHaveTextContent("Pending");
    expect(document.body.innerHTML).not.toContain("ref:aws/external-id/customer-0001");
  });
});

function renderSurface(client: APIClient, canWrite = true) {
  return render(<APIProvider client={client}><ProductionIntegrationsView canWrite={canWrite} /></APIProvider>);
}

function discoveryClient(overrides: { catalog?: typeof manifest; integration?: Integration; freshness?: IntegrationFreshness; POST?: ReturnType<typeof vi.fn>; PUT?: ReturnType<typeof vi.fn>; DELETE?: ReturnType<typeof vi.fn>; details?: Integration[] } = {}): APIClient {
  let detail = 0;
  const currentIntegration = overrides.integration ?? integration;
  const GET = vi.fn(async (path: string) => {
    if (path === "/api/v1/integration-catalog") return jsonResult({ items: [overrides.catalog ?? manifest] });
    if (path === "/api/v1/integrations") return jsonResult({ items: [currentIntegration], page_info: { next_cursor: null, has_more: false } });
    if (path === "/api/v1/integrations/{id}") return jsonResult(overrides.details?.[Math.min(detail++, overrides.details.length - 1)] ?? currentIntegration, 200, { ETag: detail > 1 ? '"6"' : '"5"' });
    if (path === "/api/v1/integrations/{id}/freshness") return jsonResult(overrides.freshness ?? freshness, 200, { ETag: '"7"', "Cache-Control": "no-store" });
    if (path === "/api/v1/integrations/{id}/schedule") return jsonResult(schedule, 200, { ETag: '"1"', "Cache-Control": "no-store" });
    if (path === "/api/v1/integrations/{id}/syncs") return jsonResult({ items: [sync], page_info: { next_cursor: null, has_more: false } }, 200, { "Cache-Control": "no-store" });
    if (path === "/api/v1/integrations/{id}/syncs/{syncId}") return jsonResult(sync, 200, { ETag: '"1"', "Cache-Control": "no-store" });
    throw new Error(`unexpected GET ${path}`);
  });
  return { GET, POST: overrides.POST ?? vi.fn(async () => jsonResult(queued, 202, receiptHeaders)), PUT: overrides.PUT, DELETE: overrides.DELETE } as unknown as APIClient;
}

function productError(status: number, code: string) {
  const error = { code, message: "request rejected", correlation_id: "pid_90000001-0000-4000-8000-000000000001", retryable: false };
  return { error, response: new Response(JSON.stringify(error), { status, headers: { "Content-Type": "application/json" } }) };
}

function jsonResult(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return { data, response: new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } }) };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
