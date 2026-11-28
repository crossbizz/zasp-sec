import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { Integration } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { SessionProvider } from "../../auth/SessionProvider";
import { ProductionIntegrationsView } from "./ProductionWorkflowViews";
import { WorkflowMutationProvider } from "./useRetainedWorkflowMutation";

// "acme_ai" is a platform this web app has never heard of. The catalog entry
// is all it knows: a platform the API registers needs no web code.
const manifest = {
	key: "saas-acme_ai", platform: "acme_ai", provider: "Acme AI", category: "saas",
	description: "Inventory the agents and AI apps of one Acme account through a Nango connection.",
	data_types: ["agent", "application"], actions: ["inventory_read"], auth_mode: "nango_connection",
	setup_schema: [
		{ key: "tenant_id", label: "Account ID", type: "string", required: true, description: "The account id shown in Acme settings." },
		{ key: "connection_reference", label: "Nango connection", type: "connection_reference", required: true, description: "Opaque reference to the Nango connection created for this tenant." },
	],
	access_guidance: "Authorize a read-only Acme connection in Nango.",
	test_semantics: "Ask the platform, through the Nango connection, which tenant the connection reaches and require it to be the configured tenant.",
};
const { platform: _platform, ...withoutPlatform } = manifest;
const awsManifest = { ...withoutPlatform, key: "aws", provider: "Amazon Web Services", category: "cloud", auth_mode: "aws_assume_role" };
const connection = "ref:nango/connection/11111111-1111-4111-8111-111111111111";
const configuration = { tenant_id: "acct-42", connection_reference: connection, platform: "acme_ai" };
const created: Integration = {
	id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "saas", name: "Acme production", configuration, status: "pending_authorization",
	created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:01:00Z",
};
const receiptHeaders = { ETag: '"1"', "X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001", "X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002" };

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

function renderIntegrations(client: APIClient, location = "/connectors", canWrite = true) {
	return render(<APIProvider client={client}><SessionProvider><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ProductionIntegrationsView canWrite={canWrite} location={location} /></WorkflowMutationProvider></SessionProvider></APIProvider>);
}

describe("generic SaaS connector", () => {
	it("shows only returned Nango integrations even when an older API supplies native sources", async () => {
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/session/bootstrap") return jsonResult(sessionBootstrap());
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [awsManifest, manifest] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [{ ...created, connector_key: "aws", name: "Legacy AWS" }], page_info: { next_cursor: null, has_more: false } });
			throw new Error(`unexpected GET ${path}`);
		});
		renderIntegrations({ GET } as unknown as APIClient, "/connectors#add-source");
		expect(await screen.findByRole("button", { name: "Configure Acme AI" })).toBeVisible();
		expect(screen.queryByRole("button", { name: "Configure Amazon Web Services" })).toBeNull();
		expect(screen.getByRole("searchbox", { name: "Filter connectors" })).toHaveFocus();
		expect(screen.queryByRole("button", { name: "Open Legacy AWS" })).toBeNull();
		expect(screen.queryByRole("heading", { name: "Slack" })).toBeNull();
		expect(screen.queryByRole("button", { name: "Native connectors" })).toBeNull();
		expect(screen.queryByText("Kubernetes")).toBeNull();
	});

	it("offers Slack discovery once and keeps the saved workspace authorization accessible", async () => {
		const user = userEvent.setup();
		const managed = { ...withoutPlatform, key: "slack", provider: "Slack", category: "collaboration", auth_mode: "managed_oauth" };
		const discovery = { ...manifest, key: "saas-slack", platform: "slack", provider: "Slack", description: "Discover approved AI apps." };
		const legacy = { ...created, connector_key: "slack", name: "Previously authorized workspace", configuration: { workspace_label: "Engineering" } };
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/session/bootstrap") return jsonResult(sessionBootstrap());
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [managed, discovery] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [legacy], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(legacy, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		renderIntegrations({ GET } as unknown as APIClient);
		expect(await screen.findByRole("button", { name: "Configure Slack" })).toBeVisible();
		expect(screen.getByText("Discover approved AI apps.")).toBeVisible();
		expect(screen.queryByText("Workspace authorization only")).toBeNull();
		await user.click(await screen.findByRole("button", { name: "Open Previously authorized workspace" }));
		expect(await screen.findByRole("button", { name: "Authorize Slack" })).toBeVisible();
	});

	it("tells a read-only member who can connect the first source", async () => {
		const GET = vi.fn(async (path: string) => path === "/api/v1/session/bootstrap" ? jsonResult(sessionBootstrap()) :
			path === "/api/v1/integration-catalog" ? jsonResult({ items: [] }) :
			jsonResult({ items: [], page_info: { next_cursor: null, has_more: false } }));
		renderIntegrations({ GET } as unknown as APIClient, "/connectors", false);
		expect(await screen.findByText(/Ask an environment administrator to connect a Nango source/)).toBeVisible();
		expect(screen.queryByText("Add a source")).toBeNull();
	});

	it("keeps saved integrations visible when their provider is no longer available", async () => {
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/session/bootstrap") return jsonResult(sessionBootstrap());
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [awsManifest] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [created], page_info: { next_cursor: null, has_more: false } });
			throw new Error(`unexpected GET ${path}`);
		});
		renderIntegrations({ GET } as unknown as APIClient);
		expect(await screen.findByText(/No Nango integrations are available/)).toBeVisible();
		expect(screen.getByText("./zasp --profile kubernetes nango dashboard")).toBeVisible();
		expect(screen.getByRole("button", { name: "Refresh sources" })).toBeEnabled();
		expect(await screen.findByRole("button", { name: "Open Acme production" })).toBeVisible();
		expect(screen.queryByRole("button", { name: "Configure Acme AI" })).toBeNull();
	});

	it("lists a platform from the catalog and saves its integration with the saas connector key", async () => {
		const user = userEvent.setup();
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/session/bootstrap") return jsonResult(sessionBootstrap());
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [manifest] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [], page_info: { next_cursor: null, has_more: false } });
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn(async () => jsonResult(created, 201, receiptHeaders));
		renderIntegrations({ GET, POST } as unknown as APIClient);

		await user.click(await screen.findByRole("button", { name: "Configure Acme AI" }));
		const dialog = screen.getByRole("dialog", { name: "Configure Acme AI" });
		expect(dialog).toHaveTextContent("Authorize a read-only Acme connection in Nango.");
		// The form asks for the entry's fields only; the platform is not a question.
		expect(within(dialog).queryByLabelText(/platform/i)).toBeNull();
		expect(within(dialog).getByRole("button", { name: "Save integration" })).toBeDisabled();
		await user.clear(within(dialog).getByLabelText("Integration name"));
		await user.paste("Acme production");
		await user.click(within(dialog).getByLabelText(/^Account ID/));
		await user.paste("acct-42");
		await user.click(within(dialog).getByLabelText(/^Nango connection/));
		await user.paste(connection);
		await user.click(within(dialog).getByRole("button", { name: "Save integration" }));

		const detail = await screen.findByRole("dialog", { name: "Acme production" });
		expect(POST).toHaveBeenCalledOnce();
		const [path, options] = POST.mock.calls[0] as unknown as [string, { body: unknown }];
		expect(path).toBe("/api/v1/integrations");
		// The integration is of the saas connector; the entry's platform is its configuration.
		expect(options.body).toEqual({ connector_key: "saas", name: "Acme production", configuration });
		// The saved integration finds its catalog entry by platform: it is
		// authorized by reference, under the platform's name.
		expect(within(detail).getByRole("button", { name: "Authorize Acme AI reference" })).toBeVisible();
		expect(within(detail).getByLabelText("connection reference")).toHaveValue("Configured reference");
		expect(within(detail).getByLabelText("connection reference")).toBeDisabled();
		expect(within(detail).getByLabelText("platform")).toHaveValue("acme_ai");
		expect(within(detail).getByLabelText("platform")).toBeDisabled();
		expect(within(detail).getByLabelText("tenant id")).toBeEnabled();
		expect(within(detail).getByText("Authorization uses the configured reference without exposing its value.")).toBeVisible();
		expect(document.body.innerHTML).not.toContain(connection);
	});

	it("shows a saved SaaS integration under its platform and its bound tenant", async () => {
		const user = userEvent.setup();
		const active: Integration = { ...created, status: "active" };
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/session/bootstrap") return jsonResult(sessionBootstrap());
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [awsManifest, manifest] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [active], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(active, 200, { ETag: '"2"' });
			if (path === "/api/v1/integrations/{id}/setup-status") return jsonResult({
				integration_id: active.id, connector_key: "saas",
				authorization: { state: "verified", scope_kind: "saas_tenant", scope_label: "acme_ai/acct-42", repository_selection: null, permissions: [] },
				runtime_coverage: { state: "not_applicable", reason: "not_applicable", sensor_count: 0, healthy_sensor_count: 0 }, updated_at: "2026-08-19T00:02:00Z",
			}, 200, { "Cache-Control": "no-store" });
			// Freshness, schedule and sync history are not part of this test.
			return jsonResult({ code: "not_found", message: "not found", correlation_id: "pid_90000001-0000-4000-8000-000000000001", retryable: false }, 404);
		});
		renderIntegrations({ GET } as unknown as APIClient);

		const row = await screen.findByRole("button", { name: "Open Acme production" });
		// The list names the platform, not the generic connector.
		expect(row).toHaveTextContent("acme_ai");
		expect(row).not.toHaveTextContent("saas");
		await user.click(row);
		const detail = await screen.findByRole("dialog", { name: "Acme production" });
		const setup = await within(detail).findByRole("region", { name: "Acme AI setup" });
		await waitFor(() => expect(setup).toHaveTextContent("Tenant acme_ai/acct-42"));
		expect(within(detail).getByText("Reference authorization is active.")).toBeVisible();
		expect(within(detail).queryByRole("button", { name: /Authorize/ })).toBeNull();
	});
});
