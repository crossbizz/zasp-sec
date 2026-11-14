import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { Integration } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { SessionProvider } from "../../auth/SessionProvider";
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

afterEach(() => {
	window.sessionStorage.clear();
	window.history.replaceState(null, "", "/integrations");
});

describe("SaaS sign-in from the Integrations page", () => {
	it("sets a sign-in platform up with its tenant only and sends the browser to the provider", async () => {
		const user = userEvent.setup();
		const authorizationURL = "https://login.acme.example/oauth/authorize?client_id=zasp&state=nango_state_12345678";
		const POST = vi.fn(async (path: string) => {
			if (path === "/api/v1/integrations") return jsonResult(waiting, 201, { ...receiptHeaders, ETag: '"1"' });
			if (path === "/api/v1/integrations/{id}/authorize") return jsonResult({ authorization_attempt_id: "pid_40000001-0000-4000-8000-000000000001", authorization_url: authorizationURL, expires_at: new Date(Date.now() + 9 * 60_000).toISOString() }, 200, { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
			throw new Error(`unexpected POST ${path}`);
		});
		const navigate = renderIntegrations({ GET: reads(() => waiting), POST } as unknown as APIClient);

		await user.click(await screen.findByRole("button", { name: "Configure Acme AI" }));
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

		await waitFor(() => expect(navigate).toHaveBeenCalledWith(authorizationURL));
		const [path, options] = POST.mock.calls[1] as unknown as [string, { params: { path: { id: string } } }];
		expect(path).toBe("/api/v1/integrations/{id}/authorize");
		expect(options.params.path.id).toBe(integrationID);
		// This tab started the sign-in of this integration.
		expect(window.sessionStorage.getItem("zasp.saas-sign-in")).toBe(integrationID);
	});

	it("stores the connection the sign-in created and then offers the reference authorization", async () => {
		window.sessionStorage.setItem("zasp.saas-sign-in", integrationID);
		window.history.replaceState(null, "", `/integrations?saas_connection=${connectionID}&saas_sign_in=${integrationID}`);
		let current = waiting;
		const PATCH = vi.fn(async () => { current = connected; return jsonResult(connected, 200, { ...receiptHeaders, ETag: '"2"' }); });
		renderIntegrations({ GET: reads(() => current), PATCH } as unknown as APIClient);

		const detail = await screen.findByRole("dialog", { name: "Acme production" });
		await waitFor(() => expect(PATCH).toHaveBeenCalledOnce());
		const [path, options] = PATCH.mock.calls[0] as unknown as [string, { params: { path: { id: string }; header: Record<string, string> }; body: unknown }];
		expect(path).toBe("/api/v1/integrations/{id}");
		expect(options.params.path.id).toBe(integrationID);
		expect(options.params.header["If-Match"]).toBe('"1"');
		// The update adds the reference and changes nothing else.
		expect(options.body).toEqual({ name: "Acme production", configuration: connected.configuration });
		expect(await screen.findByText("Signed in. Authorize the integration to start collecting.")).toBeVisible();
		expect(await within(detail).findByRole("button", { name: "Authorize Acme AI reference" })).toBeVisible();
		expect(within(detail).queryByRole("button", { name: "Sign in to Acme AI" })).toBeNull();
		// The return is used once: the address and the tab's marker are cleared.
		expect(window.location.search).toBe("");
		expect(window.sessionStorage.getItem("zasp.saas-sign-in")).toBeNull();
	});

	it("does not store a connection for a sign-in this tab did not start", async () => {
		// A link with a connection id, opened without having started a sign-in.
		window.history.replaceState(null, "", `/integrations?saas_connection=${connectionID}&saas_sign_in=${integrationID}`);
		const PATCH = vi.fn();
		const GET = reads(() => waiting);
		renderIntegrations({ GET, PATCH } as unknown as APIClient);

		expect(await screen.findByText(/This sign-in was not started from this browser tab/)).toBeVisible();
		expect(PATCH).not.toHaveBeenCalled();
		expect(GET.mock.calls.some(([path]) => path === "/api/v1/integrations/{id}")).toBe(false);
		expect(window.location.search).toBe("");
	});

	it("does not store a connection for another integration than the one this tab signed in for", async () => {
		window.sessionStorage.setItem("zasp.saas-sign-in", "pid_20000009-0000-4000-8000-000000000009");
		window.history.replaceState(null, "", `/integrations?saas_connection=${connectionID}&saas_sign_in=${integrationID}`);
		const PATCH = vi.fn();
		renderIntegrations({ GET: reads(() => waiting), PATCH } as unknown as APIClient);

		expect(await screen.findByText(/This sign-in was not started from this browser tab/)).toBeVisible();
		expect(PATCH).not.toHaveBeenCalled();
	});

	it("explains a sign-in that failed and connects nothing", async () => {
		window.sessionStorage.setItem("zasp.saas-sign-in", integrationID);
		window.history.replaceState(null, "", `/integrations?saas_sign_in=${integrationID}&saas_sign_in_error=tenant_mismatch`);
		const PATCH = vi.fn();
		renderIntegrations({ GET: reads(() => waiting), PATCH } as unknown as APIClient);

		expect(await screen.findByText(/The sign-in did not reach the tenant this integration names/)).toBeVisible();
		expect(PATCH).not.toHaveBeenCalled();
		expect(window.location.search).toBe("");
	});

	it("ignores an address that is not a sign-in return", async () => {
		for (const search of [`?saas_sign_in=${integrationID}`, `?saas_sign_in=not-an-id&saas_connection=${connectionID}`, `?saas_sign_in=${integrationID}&saas_connection=ref:nango/connection/x`, `?saas_sign_in=${integrationID}&saas_connection=${connectionID}&saas_sign_in_error=denied`]) {
			window.sessionStorage.setItem("zasp.saas-sign-in", integrationID);
			window.history.replaceState(null, "", `/integrations${search}`);
			const PATCH = vi.fn();
			const view = render(<APIProvider client={{ GET: reads(() => waiting), PATCH } as unknown as APIClient}><SessionProvider><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ProductionIntegrationsView canWrite /></WorkflowMutationProvider></SessionProvider></APIProvider>);
			await screen.findByRole("button", { name: "Open Acme production" });
			expect(PATCH).not.toHaveBeenCalled();
			expect(screen.queryByRole("alert")).toBeNull();
			view.unmount();
		}
	});
});
