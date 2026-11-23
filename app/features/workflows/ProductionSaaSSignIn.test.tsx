import { useEffect } from "react";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { Integration } from "../../../apps/web/api/generated";
import { APIProvider, useAPI } from "../../api/APIProvider";
import { ZaspProductionApp } from "../../components/ZaspProductionApp";
import { SessionProvider } from "../../auth/SessionProvider";
import { isSaaSCallback } from "./saasSignIn";
import { ProductionIntegrationsView } from "./ProductionWorkflowViews";
import { WorkflowMutationProvider } from "./useRetainedWorkflowMutation";

// "acme_ai" is a platform this web app has never heard of. Its catalog entry
// says a person signs in to it, so its setup form asks for the tenant only.
const manifest = {
  key: "saas-acme_ai", platform: "acme_ai", provider: "Acme AI", category: "saas",
  description: "Inventory the agents and AI apps of one Acme account through a Nango connection.",
  data_types: ["agent", "application"], actions: ["inventory_read"], auth_mode: "nango_sign_in",
  setup_schema: [{ key: "tenant_id", label: "Account ID", type: "string", required: true, description: "The account id shown in Acme settings." }],
  access_guidance: "Sign in as an Acme administrator.",
  test_semantics: "Sign in to the platform, then ask it which tenant the connection reaches.",
};
const integrationID = "pid_20000001-0000-4000-8000-000000000001";
const connectionID = "11111111-1111-4111-8111-111111111111";
const waiting: Integration = {
  id: integrationID, connector_key: "saas", name: "Acme production", configuration: { tenant_id: "acct-42", platform: "acme_ai" }, status: "pending_authorization",
  created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:01:00Z",
};
const connected: Integration = { ...waiting, configuration: { ...waiting.configuration, connection_reference: `ref:nango/connection/${connectionID}` }, updated_at: "2026-08-19T00:02:00Z" };
const receiptHeaders = { "X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001", "X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002" };
const notFound = { code: "not_found", message: "not found", correlation_id: "pid_90000001-0000-4000-8000-000000000001", retryable: false };

function jsonResult(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return { data, response: new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } }) };
}

function sessionBootstrap() {
  return {
    principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "org-production", member_reference: "member-production", role: "admin", active: true },
    organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
    permissions: ["view", "manage_workflows"], capabilities: ["integrations.read", "integrations.write"], csrf_token: "csrf_12345678901234567890123456789012",
    fresh_auth_expires_at: new Date(Date.now() + 60_000).toISOString(), correlation_id: "pid_10000005-0000-4000-8000-000000000005",
  };
}

function reads(current: () => Integration) {
  return vi.fn(async (path: string) => {
    if (path === "/api/v1/session/bootstrap") return jsonResult(sessionBootstrap());
    if (path === "/api/v1/integration-catalog") return jsonResult({ items: [manifest] });
    if (path === "/api/v1/integrations") return jsonResult({ items: [current()], page_info: { next_cursor: null, has_more: false } });
    if (path === "/api/v1/integrations/{id}") return jsonResult(current(), 200, { ETag: current() === waiting ? '"1"' : '"2"' });
    // Setup status, freshness, schedule and sync history are not part of these tests.
    return jsonResult(notFound, 404);
  });
}

function renderIntegrations(client: APIClient, navigateAuthorization = vi.fn()) {
  render(<APIProvider client={client}><SessionProvider><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ProductionIntegrationsView canWrite navigateAuthorization={navigateAuthorization} /></WorkflowMutationProvider></SessionProvider></APIProvider>);
  return navigateAuthorization;
}

afterEach(() => { window.history.replaceState(null, "", "/connectors"); });

describe("SaaS sign-in from the Integrations page", () => {
  it("sets up a sign-in platform with its tenant and exposes a user-activated provider link", async () => {
    const user = userEvent.setup();
    const authorizationURL = "https://login.acme.example/oauth/authorize?client_id=zasp&state=nango_state_12345678";
    const POST = vi.fn(async (path: string) => {
      if (path === "/api/v1/integrations") return jsonResult(waiting, 201, { ...receiptHeaders, ETag: '"1"' });
      if (path === "/api/v1/integrations/{id}/authorize") return jsonResult({ authorization_attempt_id: "pid_40000001-0000-4000-8000-000000000001", authorization_url: authorizationURL, expires_at: new Date(Date.now() + 9 * 60_000).toISOString() }, 200, { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
      throw new Error(`unexpected POST ${path}`);
    });
    const navigate = renderIntegrations({ GET: reads(() => waiting), POST } as unknown as APIClient);

    await user.click(await screen.findByRole("button", { name: "Configure Acme AI" }, { timeout: 4000 }));
    const dialog = screen.getByRole("dialog", { name: "Configure Acme AI" });
    // No reference is asked for: the person will sign in instead.
    expect(within(dialog).queryByLabelText(/Nango connection/)).toBeNull();
    await user.clear(within(dialog).getByLabelText("Integration name"));
    await user.type(within(dialog).getByLabelText("Integration name"), "Acme production");
    await user.type(within(dialog).getByLabelText(/^Account ID/), "acct-42");
    await user.click(within(dialog).getByRole("button", { name: "Save integration" }));

    const detail = await screen.findByRole("dialog", { name: "Acme production" });
    const [, created] = POST.mock.calls[0] as unknown as [string, { body: unknown }];
    expect(created.body).toEqual({ connector_key: "saas", name: "Acme production", configuration: { tenant_id: "acct-42", platform: "acme_ai" } });
    // It cannot be authorized by reference yet: it names no connection.
    expect(within(detail).queryByRole("button", { name: /reference/ })).toBeNull();
    expect(within(detail).getByText(/Sign in to the platform to connect this integration/)).toBeVisible();
    await user.click(within(detail).getByRole("button", { name: "Sign in to Acme AI" }));

    const link = await within(detail).findByRole("link", { name: "Continue to provider" });
    expect(link).toHaveAttribute("href", authorizationURL);
    expect(link).toHaveAttribute("target", "_blank"); expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(navigate).not.toHaveBeenCalled();
  });

  const attemptID = "pid_40000001-0000-4000-8000-000000000001";
  const statusPath = "/api/v1/integrations/{id}/sign-in-attempts/{attemptId}";
  const result = { attempt_id: attemptID, integration_id: integrationID, integration_version: 1, status: "completed", connection_reference: connected.configuration.connection_reference, failure_code: null };
  function ScopeControls({ suspended }: { suspended: boolean }) {
    const { suspendQueryCache } = useAPI();
    useEffect(() => { if (suspended) suspendQueryCache(); }, [suspended, suspendQueryCache]);
    return null;
  }
  function workflow(status: () => unknown, version = () => '"1"') {
    const user = userEvent.setup(vi.isFakeTimers() ? { advanceTimers: vi.advanceTimersByTimeAsync } : {});
    let current = waiting;
    const listing = reads(() => current);
    const GET = vi.fn(async (path: string, _options?: { params?: { path?: Record<string, string> } }) => {
      if (path === statusPath) return jsonResult(await status(), 200, { "Cache-Control": "no-store" });
      if (path === "/api/v1/integrations/{id}") return jsonResult(current, 200, { ETag: current === waiting ? version() : '"2"' });
      return listing(path);
    });
    const PATCH = vi.fn(async (_path: string, _options: unknown) => { current = connected; return jsonResult(connected, 200, { ...receiptHeaders, ETag: '"2"' }); });
    let authorizationCount = 0;
    const POST = vi.fn(async (path: string) => {
      if (path === "/api/v1/integrations/{id}/authorize") return jsonResult({ authorization_attempt_id: ++authorizationCount === 1 ? attemptID : "pid_40000002-0000-4000-8000-000000000002", authorization_url: "https://login.acme.example/sign-in", expires_at: new Date(Date.now() + 540000).toISOString() }, 200, { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
      if (path === "/api/v1/integrations/{id}/reference-authorization") return jsonResult({ ...connected, status: "active" }, 200, { ...receiptHeaders, ETag: '"3"' });
      throw new Error(path);
    });
    const client = { GET, POST, PATCH } as unknown as APIClient;
    const view = (canWrite: boolean, suspended = false) => <APIProvider client={client}><SessionProvider><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ScopeControls suspended={suspended} /><ProductionIntegrationsView canWrite={canWrite} /></WorkflowMutationProvider></SessionProvider></APIProvider>;
    const rendered = render(view(true));
    const start = async () => {
      await user.click(await screen.findByRole("button", { name: "Open Acme production" }, { timeout: 4000 }));
      await user.click(await screen.findByRole("button", { name: "Sign in to Acme AI" }, { timeout: 4000 }));
      return screen.findByRole("button", { name: "Finish sign-in" }, { timeout: 4000 });
    };
    return { user, GET, POST, PATCH, start, disable: () => rendered.rerender(view(false)), suspend: () => rendered.rerender(view(true, true)), unmount: () => rendered.unmount() };
  }
  it("uses the initiating attempt and checked version before saving and authorizing the provider reference", async () => {
    let state = "pending";
    const m = workflow(() => ({ ...result, status: state, connection_reference: state === "completed" ? result.connection_reference : null }));
    const finish = await m.start();
    await m.user.click(finish);
    expect(await screen.findByText(/Waiting for the provider/)).toBeVisible();
    expect(m.PATCH).not.toHaveBeenCalled();
    state = "completed"; await m.user.click(finish);
    expect(await screen.findByText(/Signed in. Authorize the integration/)).toBeVisible();
    expect(m.GET.mock.calls.filter(([p]) => p === statusPath).map(([, o]) => o?.params?.path)).toEqual([1, 2].map(() => ({ id: integrationID, attemptId: attemptID })));
    expect(m.PATCH).toHaveBeenCalledWith("/api/v1/integrations/{id}", expect.objectContaining({ params: expect.objectContaining({ path: { id: integrationID }, header: expect.objectContaining({ "If-Match": '"1"' }) }), body: { name: waiting.name, configuration: connected.configuration } }));
    await m.user.click(await screen.findByRole("button", { name: "Authorize Acme AI reference" }));
    expect(m.POST.mock.calls.map(([path]) => path)).toContain("/api/v1/integrations/{id}/reference-authorization");
  });
  it.each([
    ["superseded", { ...result, status: "superseded", connection_reference: null }],
    ["stale version", { ...result, integration_version: 2 }],
    ["different attempt", { ...result, attempt_id: "pid_40000002-0000-4000-8000-000000000002" }],
    ["missing version", { ...result, integration_version: undefined }],
    ["different integration", { ...result, integration_id: "pid_20000003-0000-4000-8000-000000000003" }],
    ["failed", { ...result, status: "failed", connection_reference: null, failure_code: "tenant_mismatch" }],
  ])("refuses to save a %s result", async (_label, value) => {
    const m = workflow(() => value); await m.user.click(await m.start());
    await waitFor(() => expect(screen.getAllByRole("alert").length).toBeGreaterThan(0));
    expect(m.PATCH).not.toHaveBeenCalled();
  });
  it("requires the same current integration version at save time", async () => {
    let version = '"1"'; const m = workflow(() => result, () => version); const finish = await m.start(); version = '"2"';
    await m.user.click(finish); expect(await screen.findByText(/integration configuration changed/)).toBeVisible();
    expect(m.PATCH).not.toHaveBeenCalled();
  });
  it("drops authority after write capability is lost", async () => {
    const m = workflow(() => result); await m.start(); m.disable();
    expect(screen.queryByRole("button", { name: "Finish sign-in" })).toBeNull();
    expect(m.PATCH).not.toHaveBeenCalled();
  });
  it("expires the attempt before issuing a status request", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const m = workflow(() => result);
      await m.start();
      await act(async () => { await vi.advanceTimersByTimeAsync(540_005); });
      expect(screen.getByText("This provider sign-in expired. Start a new sign-in.")).toBeVisible();
      expect(screen.queryByRole("button", { name: "Finish sign-in" })).toBeNull();
      expect(m.GET.mock.calls.filter(([path]) => path === statusPath)).toHaveLength(0);
      expect(m.PATCH).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
  it("checks only the latest attempt after signing in again", async () => {
    const next = "pid_40000002-0000-4000-8000-000000000002";
    const m = workflow(() => ({ ...result, attempt_id: next }));
    await m.start();
    await m.user.click(screen.getByRole("button", { name: "Start a new sign-in" }));
    await m.user.click(await screen.findByRole("button", { name: "Finish sign-in" }));
    expect(await screen.findByText(/Signed in. Authorize the integration/)).toBeVisible();
    expect(m.GET.mock.calls.filter(([p]) => p === statusPath).map(([, o]) => o?.params?.path)).toEqual([{ id: integrationID, attemptId: next }]);
  });
  it("requires current scope after the status request returns", async () => {
    let complete: (value: typeof result) => void = () => { throw new Error("missing status request"); };
    const m = workflow(() => new Promise<typeof result>(resolve => { complete = resolve; }));
    const finish = await m.start();
    await m.user.click(finish);
    await waitFor(() => expect(m.GET.mock.calls.some(([p]) => p === statusPath)).toBe(true));
    m.suspend();
    await act(async () => { complete(result); });
    expect(m.PATCH).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Finish sign-in" })).toBeNull();
  });
  it("accepts only the exact provider return route as a display page", () => {
    const valid = `/connectors?saas_connection=${connectionID}&saas_sign_in=${integrationID}`;
    expect(isSaaSCallback(valid)).toBe(true);
    for (const address of [valid + "&extra=1", valid + "#extra", valid + "&saas_connection=" + connectionID,
      valid.replace("/connectors", "/agents"), valid.replace(connectionID, "invalid"), valid.replace("&", "&saas_sign_in_error=test&")]) {
      expect(isSaaSCallback(address)).toBe(false);
    }
  });
  it.each([`saas_connection=${connectionID}&saas_sign_in=${integrationID}`, `saas_sign_in=${integrationID}&saas_sign_in_error=provider_access_denied`])("renders the return address passively", async (search) => {
    window.history.replaceState(null, "", "/connectors?" + search);
    const GET = reads(() => waiting), PATCH = vi.fn(), POST = vi.fn();
    render(<ZaspProductionApp client={{ GET, POST, PATCH } as unknown as APIClient} />);
    expect(await screen.findByText(/Return to the Zasp tab/)).toBeVisible();
    expect(PATCH).not.toHaveBeenCalled(); expect(POST).not.toHaveBeenCalled();
    expect(GET.mock.calls.filter(([path]) => path.startsWith("/api/v1/integrations"))).toEqual([]);
  });
});
