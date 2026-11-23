import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { Integration } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { SessionProvider } from "../../auth/SessionProvider";
import { ProductionIntegrationsView } from "./ProductionWorkflowViews";
import { WorkflowMutationProvider } from "./useRetainedWorkflowMutation";

const manifest = {
	key: "gcp", provider: "Google Cloud", category: "cloud",
	description: "Inventory Vertex AI agents, model endpoints, Cloud Run services and functions that call a model, and their service accounts, through a customer-owned read-only service account.",
	data_types: ["agent", "identity", "resource"], actions: ["inventory_read", "posture_read"], auth_mode: "gcp_service_account",
	setup_schema: [
		{ key: "scope", label: "Organization, folder or project", type: "string", required: true, description: "What to read: organizations/<number>, folders/<number> or projects/<project id>." },
		{ key: "identity_reference", label: "Service account", type: "secret_reference", required: true, description: "ref:gcp/workload-identity/<project id>/<service account name>, or ref:gcp/service-account-key/<id>." },
		{ key: "audience", label: "Workload identity provider", type: "string", required: false, description: "Required with workload identity federation, empty with a key." },
	],
	access_guidance: "Create a service account, grant it the read-only roles of the runbook on the organization, folder or project, and let the product's AWS roles impersonate it through a workload identity pool.",
	test_semantics: "Obtain a short-lived access token for the service account and read the named organization, folder or project.",
};
const audience = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/zasp-pool/providers/zasp-aws";
const federation = "ref:gcp/workload-identity/acme-security/zasp-reader";
const keyReference = "ref:gcp/service-account-key/customer-0001";
const pending: Integration = {
	id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "gcp", name: "Acme Google Cloud", configuration: { identity_reference: keyReference, scope: "organizations/123456789012" }, status: "pending_authorization",
	created_at: "2026-11-14T00:00:00Z", updated_at: "2026-11-14T00:01:00Z",
};
const receiptHeaders = { ETag: '"1"', "X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001", "X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002" };

function jsonResult(data: unknown, status = 200, headers: Record<string, string> = {}) {
	return { data, response: new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } }) };
}

// A session with fresh authentication: authorizing a reference needs one.
function sessionBootstrap() {
	return {
		principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "org-production", member_reference: "member-production", role: "admin", active: true },
		organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
		permissions: ["view", "manage_workflows"], capabilities: ["integrations.read", "integrations.write"], csrf_token: "csrf_12345678901234567890123456789012",
		fresh_auth_expires_at: new Date(Date.now() + 60_000).toISOString(), correlation_id: "pid_10000005-0000-4000-8000-000000000005",
	};
}

function catalogClient(integrations: readonly Integration[], extra: Record<string, unknown> = {}) {
	return vi.fn(async (path: string) => {
		if (path === "/api/v1/session/bootstrap") return jsonResult(sessionBootstrap());
		if (path === "/api/v1/integration-catalog") return jsonResult({ items: [manifest] });
		if (path === "/api/v1/integrations") return jsonResult({ items: integrations, page_info: { next_cursor: null, has_more: false } });
		if (path === "/api/v1/integrations/{id}") return jsonResult(integrations[0], 200, { ETag: '"1"' });
		if (Object.hasOwn(extra, path)) return jsonResult(extra[path]);
		throw new Error(`unexpected GET ${path}`);
	});
}

describe("Google Cloud connector", () => {
	it("saves a key-based integration without the audience and shows the setup steps", async () => {
		const user = userEvent.setup();
		const GET = catalogClient([]);
		const POST = vi.fn(async () => jsonResult(pending, 201, receiptHeaders));
		render(<APIProvider client={{ GET, POST } as unknown as APIClient}><ProductionIntegrationsView canWrite /></APIProvider>);

		await user.click(await screen.findByRole("button", { name: "Configure Google Cloud" }));
		const dialog = screen.getByRole("dialog", { name: "Configure Google Cloud" });
		for (const step of ["Create the read-only service account", "Configure", "Authorize scope", "Initial sync", "Review coverage"]) expect(within(dialog).getByText(step)).toBeVisible();
		expect(dialog).toHaveTextContent("workload identity pool");
		// The reference is typed like a secret; the audience is optional.
		expect(within(dialog).getByLabelText(/^Service account/)).toHaveAttribute("type", "password");
		expect(within(dialog).getByRole("button", { name: "Save integration" })).toBeDisabled();
		await user.clear(within(dialog).getByLabelText("Integration name"));
		await user.type(within(dialog).getByLabelText("Integration name"), "Acme Google Cloud");
		await user.type(within(dialog).getByLabelText(/^Organization, folder or project/), "organizations/123456789012");
		await user.click(within(dialog).getByLabelText(/^Service account/));
		await user.paste(keyReference);
		expect(within(dialog).getByRole("button", { name: "Save integration" })).toBeEnabled();
		await user.click(within(dialog).getByRole("button", { name: "Save integration" }));

		await screen.findByRole("dialog", { name: "Acme Google Cloud" });
		expect(POST).toHaveBeenCalledOnce();
		const [path, options] = POST.mock.calls[0] as unknown as [string, { body: { connector_key: string; configuration: Record<string, string> } }];
		expect(path).toBe("/api/v1/integrations");
		expect(options.body.connector_key).toBe("gcp");
		expect(options.body.configuration).toEqual({ scope: "organizations/123456789012", identity_reference: keyReference });
	});

	it("saves a federated integration with its audience", async () => {
		const user = userEvent.setup();
		const federated: Integration = { ...pending, configuration: { audience, identity_reference: federation, scope: "folders/42" } };
		const GET = catalogClient([]);
		const POST = vi.fn(async () => jsonResult(federated, 201, receiptHeaders));
		render(<APIProvider client={{ GET, POST } as unknown as APIClient}><ProductionIntegrationsView canWrite /></APIProvider>);

		await user.click(await screen.findByRole("button", { name: "Configure Google Cloud" }));
		const dialog = screen.getByRole("dialog", { name: "Configure Google Cloud" });
		await user.clear(within(dialog).getByLabelText("Integration name"));
		await user.type(within(dialog).getByLabelText("Integration name"), "Acme Google Cloud");
		await user.type(within(dialog).getByLabelText(/^Organization, folder or project/), "folders/42");
		await user.click(within(dialog).getByLabelText(/^Service account/));
		await user.paste(federation);
		await user.click(within(dialog).getByLabelText(/^Workload identity provider/));
		await user.paste(audience);
		await user.click(within(dialog).getByRole("button", { name: "Save integration" }));

		await screen.findByRole("dialog", { name: "Acme Google Cloud" });
		const [, options] = POST.mock.calls[0] as unknown as [string, { body: { configuration: Record<string, string> } }];
		expect(options.body.configuration).toEqual({ scope: "folders/42", identity_reference: federation, audience });
	});

	it("offers reference authorization without showing the reference", async () => {
		const user = userEvent.setup();
		render(<APIProvider client={{ GET: catalogClient([pending]) } as unknown as APIClient}><SessionProvider><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ProductionIntegrationsView canWrite /></WorkflowMutationProvider></SessionProvider></APIProvider>);

		await user.click(await screen.findByRole("button", { name: "Open Acme Google Cloud" }));
		expect(screen.getByRole("button", { name: "Authorize Google Cloud reference" })).toBeEnabled();
		expect(screen.getByLabelText("identity reference")).toHaveValue("Configured reference");
		expect(screen.getByLabelText("identity reference")).toBeDisabled();
		expect(screen.getByLabelText("scope")).toHaveValue("organizations/123456789012");
		expect(document.body.innerHTML).not.toContain("service-account-key/customer-0001");
	});
});
