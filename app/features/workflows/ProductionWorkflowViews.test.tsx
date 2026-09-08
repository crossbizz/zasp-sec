import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { Integration, Policy } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { SessionProvider } from "../../auth/SessionProvider";
import { ProductionIntegrationsView, ProductionPoliciesView } from "./ProductionWorkflowViews";
import { WorkflowMutationProvider } from "./useRetainedWorkflowMutation";

const integration: Integration = {
  id: "pid_20000001-0000-4000-8000-000000000001",
  connector_key: "github",
  name: "GitHub",
  configuration: { authorization_mode: "github_app" },
  status: "active",
  created_at: "2026-08-19T00:00:00Z",
  updated_at: "2026-08-19T00:01:00Z",
};
const revoking: Integration = { ...integration, status: "revoking", updated_at: "2026-08-19T00:02:00Z" };
const awsPending: Integration = {
	...integration,
	connector_key: "aws",
	name: "AWS",
	configuration: { role_arn: "arn:aws:iam::123456789012:role/zasp-discovery", external_id_reference: "ref:aws/external-id/customer-0001", region: "us-east-1" },
	status: "pending_authorization",
};
const awsActive: Integration = { ...awsPending, status: "active", updated_at: "2026-08-19T00:02:00Z" };
const githubManifest = { key: "github", provider: "GitHub", category: "developer", description: "GitHub inventory", data_types: ["repository"], actions: ["inventory_read"], auth_mode: "github_app_oauth", setup_schema: [{ key: "authorization_mode", label: "Authorization mode", type: "string", required: true, description: "First-party application" }], access_guidance: "Authorize selected repositories.", test_semantics: "Verify the installation." };
const slackIntegration: Integration = { ...integration, connector_key: "slack", name: "Slack workspace", configuration: { workspace_label: "Security operations" }, status: "configured" };
const slackManifest = { key: "slack", provider: "Slack", category: "collaboration", description: "Slack inventory", data_types: ["workspace"], actions: ["inventory_read"], auth_mode: "managed_oauth", setup_schema: [{ key: "workspace_label", label: "Workspace label", type: "string", required: true, description: "Approved workspace label" }], access_guidance: "Authorize one workspace.", test_semantics: "Verify the workspace." };
const receiptHeaders = {
  ETag: '"2"',
  "X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001",
  "X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002",
};

const runtimePolicy: Policy = { id: "policy-runtime-history", name: "Runtime history", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "invoke" }], action: "block", rollout: "monitor", failure_mode: "closed" };

describe("production policy evidence", () => {
	it("simulates bounded runtime history and renders durable tenant decisions", async () => {
		const user = userEvent.setup();
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/session/bootstrap") return jsonResult(sessionBootstrap(new Date(Date.now() + 60_000).toISOString()));
			if (path === "/api/v1/policies") return jsonResult({ items: [runtimePolicy], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/policies/{id}") return jsonResult(runtimePolicy, 200, { ETag: '"3"' });
			if (path === "/api/v1/policies/{id}/decisions") return jsonResult({ items: [{ id: "pid_70000002-0000-4000-8000-000000000002", policy_id: runtimePolicy.id, environment_id: "pid_10000003-0000-4000-8000-000000000003", result: "block", correlation_id: "pid_70000002-0000-4000-8000-000000000002", at: "2026-08-28T12:00:00Z" }] });
			throw new Error(`unexpected GET ${path}`);
		});
		const simulation = { matches: 2, would_block: 1, example_session_ids: ["pid_70000001-0000-4000-8000-000000000001"] };
		const POST = vi.fn(async () => jsonResult(simulation));
		render(<APIProvider client={{ GET, POST } as unknown as APIClient}><SessionProvider><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ProductionPoliciesView canWrite /></WorkflowMutationProvider></SessionProvider></APIProvider>);

		await user.click(await screen.findByRole("button", { name: "Open Runtime history" }));
		await user.click(await screen.findByRole("button", { name: "Simulate against runtime history" }));
		expect(await screen.findByText("2 matched historical actions · 1 would block")).toBeVisible();
		expect(await screen.findByText("block · 2026-08-28T12:00:00Z")).toBeVisible();
		expect(screen.getByText("pid_70000001-0000-4000-8000-000000000001")).toBeVisible();
		expect(POST).toHaveBeenCalledWith("/api/v1/policies/{id}/simulate", { params: { path: { id: runtimePolicy.id } }, body: {} });
		expect(GET).toHaveBeenCalledWith("/api/v1/policies/{id}/decisions", { params: { path: { id: runtimePolicy.id }, query: { limit: 100 } }, signal: undefined });
	});

	it("keeps late decision history from a previously selected policy out of the current detail", async () => {
		const user = userEvent.setup();
		const secondPolicy: Policy = { ...runtimePolicy, id: "policy-second", name: "Second policy" };
		const firstHistory = deferred<ReturnType<typeof jsonResult>>();
		const secondHistory = deferred<ReturnType<typeof jsonResult>>();
		const GET = vi.fn(async (path: string, options?: { params?: { path?: { id?: string } } }) => {
			if (path === "/api/v1/session/bootstrap") return jsonResult(sessionBootstrap(new Date(Date.now() + 60_000).toISOString()));
			if (path === "/api/v1/policies") return jsonResult({ items: [runtimePolicy, secondPolicy], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/policies/{id}") return jsonResult(options?.params?.path?.id === secondPolicy.id ? secondPolicy : runtimePolicy, 200, { ETag: '"3"' });
			if (path === "/api/v1/policies/{id}/decisions") return options?.params?.path?.id === secondPolicy.id ? secondHistory.promise : firstHistory.promise;
			throw new Error(`unexpected GET ${path}`);
		});
		render(<APIProvider client={{ GET } as unknown as APIClient}><SessionProvider><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ProductionPoliciesView canWrite /></WorkflowMutationProvider></SessionProvider></APIProvider>);

		await user.click(await screen.findByRole("button", { name: "Open Runtime history" }));
		await user.click(await screen.findByRole("button", { name: "Open Second policy" }));
		secondHistory.resolve(jsonResult({ items: [{ id: "pid_70000004-0000-4000-8000-000000000004", policy_id: secondPolicy.id, environment_id: "pid_10000003-0000-4000-8000-000000000003", result: "monitor", correlation_id: "pid_70000004-0000-4000-8000-000000000004", at: "2026-08-28T13:00:00Z" }] }));
		expect(await screen.findByText("monitor · 2026-08-28T13:00:00Z")).toBeVisible();
		firstHistory.resolve(jsonResult({ items: [{ id: "pid_70000002-0000-4000-8000-000000000002", policy_id: runtimePolicy.id, environment_id: "pid_10000003-0000-4000-8000-000000000003", result: "block", correlation_id: "pid_70000002-0000-4000-8000-000000000002", at: "2026-08-28T12:00:00Z" }] }));
		await act(async () => { await firstHistory.promise; });

		expect(screen.getByText("monitor · 2026-08-28T13:00:00Z")).toBeVisible();
		expect(screen.queryByText("block · 2026-08-28T12:00:00Z")).not.toBeInTheDocument();
	});
});

describe("production integration deletion", () => {
	it("starts GitHub OAuth from the capability-gated product UI and retries the exact retained attempt", async () => {
		const user = userEvent.setup();
		const target = "https://github.com/login/oauth/authorize?state=opaque-state";
		const navigation = vi.fn();
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [githubManifest] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [integration], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(integration, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		const success = jsonResult({
			authorization_attempt_id: "pid_70000002-0000-4000-8000-000000000002",
			authorization_url: target,
			expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
		}, 200, { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
		const POST = vi.fn()
			.mockRejectedValueOnce(new TypeError("response lost"))
			.mockRejectedValueOnce(new TypeError("replay response lost"))
			.mockResolvedValueOnce(success);
		renderFreshIntegrations({ GET, POST } as unknown as APIClient, new Date(Date.now() + 60_000).toISOString(), navigation);

		await user.click(await screen.findByRole("button", { name: "Open GitHub" }));
		await user.click(screen.getByRole("button", { name: "Authorize GitHub" }));
		expect(await screen.findByText(/The response was lost\. The exact operation and idempotency key are retained\./)).toBeVisible();
		expect(navigation).not.toHaveBeenCalled();
		await user.click(screen.getByRole("button", { name: "Retry retained integration operation" }));
		await waitFor(() => expect(navigation).toHaveBeenCalledWith(target));
		expect(document.body.innerHTML).not.toContain(target);
		const calls = POST.mock.calls as unknown as Array<[string, { params: { header: Record<string, string> }; body: unknown }] >;
		expect(calls).toHaveLength(3);
		expect(calls.every(([path]) => path === "/api/v1/integrations/{id}/authorize")).toBe(true);
		expect(new Set(calls.map(([, options]) => options.params.header["Idempotency-Key"])).size).toBe(1);
		expect(calls.every(([, options]) => JSON.stringify(options.body) === "{}")).toBe(true);
	});

	it("starts a capability-gated managed Slack authorization without exposing Nango", async () => {
		const user = userEvent.setup();
		const target = "https://slack.com/oauth/v2/authorize?state=opaque-state";
		const navigation = vi.fn();
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [slackManifest] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [slackIntegration], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(slackIntegration, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn(async () => jsonResult({ authorization_attempt_id: "pid_70000002-0000-4000-8000-000000000002", authorization_url: target, expires_at: new Date(Date.now() + 10 * 60_000).toISOString() }, 200, { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" }));
		renderFreshIntegrations({ GET, POST } as unknown as APIClient, new Date(Date.now() + 60_000).toISOString(), navigation);

		await user.click(await screen.findByRole("button", { name: "Open Slack workspace" }));
		const dialog = screen.getByRole("dialog", { name: "Slack workspace" });
		expect(within(dialog).getByRole("button", { name: "Authorize Slack" })).toBeEnabled();
		expect(dialog).toHaveTextContent("Provider credentials are never returned to this browser.");
		expect(dialog).not.toHaveTextContent(/Nango/i);
		await user.click(within(dialog).getByRole("button", { name: "Authorize Slack" }));
		await waitFor(() => expect(navigation).toHaveBeenCalledWith(target));
		expect(POST).toHaveBeenCalledOnce();
	});

	it("fails closed when reference authorization has no session authority", async () => {
		const user = userEvent.setup();
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(awsPending, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn();
		render(<APIProvider client={{ GET, POST } as unknown as APIClient}><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ProductionIntegrationsView canWrite /></WorkflowMutationProvider></APIProvider>);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		expect(screen.getByRole("button", { name: "Authorize AWS reference" })).toBeDisabled();
		expect(screen.getByRole("alert")).toHaveTextContent("Fresh authentication is required to authorize this reference.");
		expect(screen.queryByRole("button", { name: "Reauthenticate" })).not.toBeInTheDocument();
		expect(POST).not.toHaveBeenCalled();
	});

	it("authorizes a supported reference integration and keeps its references redacted", async () => {
		const user = userEvent.setup();
		const authorization = deferred<ReturnType<typeof jsonResult>>();
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(awsPending, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn(() => authorization.promise);
		renderFreshIntegrations({ GET, POST } as unknown as APIClient);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		const authorize = screen.getByRole("button", { name: "Authorize AWS reference" });
		await user.click(authorize);
		expect(authorize).toBeDisabled();
		expect(screen.getByRole("dialog", { name: "AWS" })).not.toHaveTextContent("ref:aws/external-id/customer-0001");

		authorization.resolve(jsonResult(awsActive, 200, { ...receiptHeaders, "Cache-Control": "no-store" }));
		expect(await screen.findByRole("status")).toHaveTextContent("Integration authorized. Audit pid_30000001-0000-4000-8000-000000000001");
		expect(screen.getByRole("dialog", { name: "AWS" })).toHaveTextContent("active");
		expect(screen.queryByRole("button", { name: "Authorize AWS reference" })).not.toBeInTheDocument();
		expect(document.body.innerHTML).not.toContain("ref:aws/external-id/customer-0001");
	});

	it("refetches a 409 reference authorization conflict before enabling a new attempt", async () => {
		const user = userEvent.setup();
		let detailCalls = 0;
		const changed = { ...awsPending, name: "AWS current", status: "degraded" as const, updated_at: "2026-08-19T00:03:00Z" };
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") {
				detailCalls += 1;
				return detailCalls === 1 ? jsonResult(awsPending, 200, { ETag: '"1"' }) : jsonResult(changed, 200, { ETag: '"2"' });
			}
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn(async () => productErrorResult(409, "conflict", "Resource version changed"));
		renderFreshIntegrations({ GET, POST } as unknown as APIClient);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		await user.click(screen.getByRole("button", { name: "Authorize AWS reference" }));

		expect(await screen.findByRole("alert")).toHaveTextContent("Integration changed. Review the current version before authorizing again.");
		expect(screen.getByRole("dialog", { name: "AWS current" })).toHaveTextContent('Version "2"');
		expect(screen.getByRole("button", { name: "Authorize AWS reference" })).toBeEnabled();
		expect(POST).toHaveBeenCalledOnce();
		expect(detailCalls).toBe(2);
	});

	it("retains the exact reference authorization attempt across lost responses", async () => {
		const user = userEvent.setup();
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(awsPending, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn()
			.mockRejectedValueOnce(new TypeError("response lost after commit"))
			.mockRejectedValueOnce(new TypeError("replay response lost"))
			.mockResolvedValueOnce(jsonResult(awsActive, 200, { ...receiptHeaders, "Cache-Control": "no-store" }));
		renderFreshIntegrations({ GET, POST } as unknown as APIClient);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		await user.click(screen.getByRole("button", { name: "Authorize AWS reference" }));
		expect(await screen.findByText(/The response was lost\. The exact operation and idempotency key are retained\./)).toBeVisible();
		await user.click(screen.getByRole("button", { name: "Retry retained integration operation" }));
		expect(await screen.findByRole("status")).toHaveTextContent("Integration authorized");
		const calls = POST.mock.calls as unknown as Array<[string, { params: { header: Record<string, string> } }] >;
		expect(calls).toHaveLength(3);
		expect(new Set(calls.map(([, options]) => options.params.header["Idempotency-Key"])).size).toBe(1);
		expect(new Set(calls.map(([, options]) => options.params.header["If-Match"]))).toEqual(new Set(['"1"']));
	});

	it("blocks a retained reference authorization retry when fresh authentication expires", async () => {
		const user = userEvent.setup();
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(awsPending, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn()
			.mockRejectedValueOnce(new TypeError("response lost after commit"))
			.mockRejectedValueOnce(new TypeError("replay response lost"));
		renderFreshIntegrations({ GET, POST } as unknown as APIClient, new Date(Date.now() + 500).toISOString());

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		await user.click(screen.getByRole("button", { name: "Authorize AWS reference" }));
		expect(await screen.findByText(/The response was lost\. The exact operation and idempotency key are retained\./)).toBeVisible();
		await act(async () => { await new Promise((resolve) => setTimeout(resolve, 510)); });

		expect(screen.getByRole("button", { name: "Retry retained integration operation" })).toBeDisabled();
		expect(screen.getByText("Fresh authentication is required to retry this reference authorization.")).toBeVisible();
		expect(screen.getByRole("button", { name: "Reauthenticate" })).toBeEnabled();
		fireEvent.click(screen.getByRole("button", { name: "Retry retained integration operation" }));
		expect(POST).toHaveBeenCalledTimes(2);
	});

	it("keeps a retained reference authorization locked through 409 refetch failures", async () => {
		const user = userEvent.setup();
		let listCalls = 0;
		let detailCalls = 0;
		const changed = { ...awsPending, name: "AWS current", status: "degraded" as const, updated_at: "2026-08-19T00:03:00Z" };
		const foreign = { ...changed, id: "pid_20000001-0000-4000-8000-000000000099" };
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") {
				listCalls += 1;
				return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			}
			if (path === "/api/v1/integrations/{id}") {
				detailCalls += 1;
				if (detailCalls === 1) return jsonResult(awsPending, 200, { ETag: '"1"' });
				if (detailCalls === 2) throw new TypeError("authoritative refetch failed");
				if (detailCalls === 3) return jsonResult(foreign, 200, { ETag: '"2"' });
				return jsonResult(changed, 200, { ETag: '"2"' });
			}
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn()
			.mockRejectedValueOnce(new TypeError("response lost after commit"))
			.mockRejectedValueOnce(new TypeError("replay response lost"))
			.mockResolvedValueOnce(productErrorResult(409, "conflict", "Resource version changed"));
		renderFreshIntegrations({ GET, POST } as unknown as APIClient);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		const listCallsBeforeConflictReconciliation = listCalls;
		await user.click(screen.getByRole("button", { name: "Authorize AWS reference" }));
		await user.click(await screen.findByRole("button", { name: "Retry retained integration operation" }));

		expect(await screen.findByRole("button", { name: "Retry authoritative integration refetch" })).toBeEnabled();
		expect(screen.getByRole("alert")).toHaveTextContent("The current integration could not be confirmed. Retry the authoritative refetch.");
		for (const close of screen.getAllByRole("button", { name: "Close" })) expect(close).toBeDisabled();
		await user.click(screen.getByRole("button", { name: "Retry authoritative integration refetch" }));
		expect(screen.getByRole("button", { name: "Retry authoritative integration refetch" })).toBeEnabled();
		for (const close of screen.getAllByRole("button", { name: "Close" })) expect(close).toBeDisabled();
		await user.click(screen.getByRole("button", { name: "Retry authoritative integration refetch" }));

		expect(await screen.findByRole("alert")).toHaveTextContent("Integration changed. Review the current version before authorizing again.");
		expect(screen.getByRole("dialog", { name: "AWS current" })).toHaveTextContent('Version "2"');
		expect(screen.getByRole("button", { name: "Authorize AWS reference" })).toBeEnabled();
		await waitFor(() => expect(listCalls).toBe(listCallsBeforeConflictReconciliation + 1));
		expect(detailCalls).toBe(4);
		expect(POST).toHaveBeenCalledTimes(3);
		const calls = POST.mock.calls as unknown as Array<[string, { params: { header: Record<string, string> } }] >;
		expect(new Set(calls.map(([, options]) => options.params.header["Idempotency-Key"])).size).toBe(1);
		expect(new Set(calls.map(([, options]) => options.params.header["If-Match"]))).toEqual(new Set(['"1"']));
	});

	it("requires fresh authentication before offering a reference authorization mutation", async () => {
		const user = userEvent.setup();
		const bootstrap = {
			principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "org-production", member_reference: "member-production", role: "admin", active: true },
			organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
			permissions: ["view", "manage_workflows"], capabilities: ["integrations.read", "integrations.write"], csrf_token: "csrf_12345678901234567890123456789012",
			fresh_auth_expires_at: "2026-08-18T00:00:00Z", correlation_id: "pid_10000005-0000-4000-8000-000000000005",
		};
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/session/bootstrap") return jsonResult(bootstrap);
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(awsPending, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		render(<APIProvider client={{ GET } as unknown as APIClient}><SessionProvider><ProductionIntegrationsView canWrite /></SessionProvider></APIProvider>);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		expect(screen.getByRole("button", { name: "Authorize AWS reference" })).toBeDisabled();
		expect(screen.getByRole("alert")).toHaveTextContent("Fresh authentication is required to authorize this reference.");
		expect(screen.getByRole("button", { name: "Reauthenticate" })).toBeEnabled();
	});

	it("offers the same capability-gated reference authorization for Kubernetes", async () => {
		const user = userEvent.setup();
		const kubernetes: Integration = { ...awsPending, connector_key: "kubernetes", name: "Kubernetes", configuration: { connection_reference: "ref:kubernetes/connection/customer-0001" } };
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [kubernetes], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(kubernetes, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		renderFreshIntegrations({ GET } as unknown as APIClient);

		await user.click(await screen.findByRole("button", { name: "Open Kubernetes" }));
		expect(screen.getByRole("button", { name: "Authorize Kubernetes reference" })).toBeEnabled();
		expect(screen.getByLabelText("connection reference")).toHaveValue("Configured reference");
		expect(document.body.innerHTML).not.toContain("ref:kubernetes/connection/customer-0001");
	});

	it("renders the production AWS setup flow from the live catalog authority", async () => {
		const user = userEvent.setup();
		const manifest = {
			key: "aws", provider: "Amazon Web Services", category: "cloud",
			description: "Inventory AWS accounts, identities, policies, and selected resources through a customer-owned read role.",
			data_types: ["identity", "policy", "resource"], actions: ["inventory_read", "posture_read"], auth_mode: "aws_assume_role",
			setup_schema: [
				{ key: "role_arn", label: "Read role ARN", type: "string", required: true, description: "Customer role trusted for the product's external-ID-bound session." },
				{ key: "external_id_reference", label: "External ID", type: "secret_reference", required: true, description: "Opaque product reference for the customer trust condition." },
				{ key: "region", label: "Home region", type: "string", required: true, description: "AWS region used for the identity check and regional inventory." },
			],
			access_guidance: "Grant the documented read-only policy to one external-ID-bound role.",
			test_semantics: "Assume the role, verify the returned account identity, and prove an unauthorized action is denied.",
		};
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [manifest] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [], page_info: { next_cursor: null, has_more: false } });
			throw new Error(`unexpected GET ${path}`);
		});
		const created = { ...awsPending, name: "Production AWS", status: "configured" as const };
		const POST = vi.fn(async () => jsonResult(created, 201, { ...receiptHeaders, ETag: '"1"' }));
		render(<APIProvider client={{ GET, POST } as unknown as APIClient}><ProductionIntegrationsView canWrite /></APIProvider>);

		await user.click(await screen.findByRole("button", { name: "Configure Amazon Web Services" }));
		const dialog = screen.getByRole("dialog", { name: "Configure Amazon Web Services" });
		expect(within(dialog).getByRole("heading", { name: "Setup progress" })).toBeVisible();
		for (const step of ["Review access", "Configure", "Test connection", "Initial sync", "Review coverage"]) expect(within(dialog).getByText(step)).toBeVisible();
		expect(dialog).toHaveTextContent("Grant the documented read-only policy to one external-ID-bound role.");
		expect(dialog).toHaveTextContent("Assume the role, verify the returned account identity, and prove an unauthorized action is denied.");
		expect(dialog).toHaveTextContent("Identity");
		expect(within(dialog).getByLabelText(/^External ID/)).toHaveAttribute("type", "password");
		await user.clear(within(dialog).getByLabelText("Integration name"));
		await user.type(within(dialog).getByLabelText("Integration name"), "Production AWS");
		await user.type(within(dialog).getByLabelText(/^Read role ARN/), "arn:aws:iam::123456789012:role/zasp-discovery");
		await user.type(within(dialog).getByLabelText(/^External ID/), "ref:aws/external-id/customer-0001");
		await user.type(within(dialog).getByLabelText(/^Home region/), "us-east-1");
		await user.click(within(dialog).getByRole("button", { name: "Save integration" }));

		const detail = await screen.findByRole("dialog", { name: "Production AWS" });
		expect(await screen.findByRole("status")).toHaveTextContent("Integration created");
		expect(within(detail).getByText("Test connection").closest("li")).toHaveTextContent("Current");
		expect(document.body.innerHTML).not.toContain("ref:aws/external-id/customer-0001");
		expect(POST).toHaveBeenCalledOnce();
		const [path, options] = POST.mock.calls[0] as unknown as [string, { body: unknown }];
		expect(path).toBe("/api/v1/integrations");
		expect(options.body).toEqual({ connector_key: "aws", name: "Production AWS", configuration: { role_arn: "arn:aws:iam::123456789012:role/zasp-discovery", external_id_reference: "ref:aws/external-id/customer-0001", region: "us-east-1" } });
	});

  it("keeps revocation pending with the exact DELETE until terminal 204", async () => {
    const user = userEvent.setup();
    let listCalls = 0;
    const GET = vi.fn(async (path: string) => {
      if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
      if (path === "/api/v1/integrations") {
        listCalls += 1;
        return jsonResult({ items: [integration], page_info: { next_cursor: null, has_more: false } });
      }
      if (path === "/api/v1/integrations/{id}") return jsonResult(integration, 200, { ETag: '"1"' });
      throw new Error(`unexpected GET ${path}`);
    });
    const DELETE = vi.fn()
      .mockResolvedValueOnce(jsonResult(revoking, 202, { ...receiptHeaders, "Retry-After": "2" }))
      .mockResolvedValueOnce({ response: new Response(null, { status: 204, headers: receiptHeaders }) });
    const client = { GET, DELETE } as unknown as APIClient;

    const surface = (canWrite: boolean, route: "integrations" | "other" = "integrations") => <APIProvider client={client}><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a">{route === "integrations" ? <ProductionIntegrationsView canWrite={canWrite} /> : <p>Other route</p>}</WorkflowMutationProvider></APIProvider>;
    const view = render(surface(true));
    await user.click(await screen.findByRole("button", { name: "Open GitHub" }));
		expect(screen.queryByRole("button", { name: /Authorize .* reference/ })).not.toBeInTheDocument();
    vi.useFakeTimers();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Delete integration" }));
      await Promise.resolve();
    });

    expect(screen.getByRole("status")).toHaveTextContent("Provider revocation is pending");
    const dialog = screen.getByRole("dialog", { name: "GitHub" });
    expect(dialog).toHaveTextContent("revoking");
    for (const button of within(dialog).getAllByRole("button", { name: "Close" })) expect(button).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Save changes" })).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Delete integration" })).toBeDisabled();
    expect(screen.queryByText(/Integration deleted/)).not.toBeInTheDocument();
    expect(listCalls).toBe(1);

    view.rerender(surface(true, "other"));
    expect(screen.getByText("Other route")).toBeVisible();
    expect(DELETE).toHaveBeenCalledTimes(1);
    view.rerender(surface(false));
    expect(screen.getByRole("status")).toHaveTextContent("Provider revocation is pending");
    expect(screen.queryByText(/The response was lost/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry pending integration deletion" })).not.toBeInTheDocument();
    view.rerender(surface(true));
    const retry = screen.getByRole("button", { name: "Retry pending integration deletion" });
    expect(retry).toBeDisabled();
    fireEvent.click(retry);
    expect(DELETE).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(1_999); });
    expect(retry).toBeDisabled();
    expect(DELETE).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(retry).toBeEnabled();
    await act(async () => { fireEvent.click(retry); });
    vi.useRealTimers();
    expect(await screen.findByRole("status")).toHaveTextContent("Integration deleted. Audit pid_30000001-0000-4000-8000-000000000001");
    expect(screen.queryByRole("dialog", { name: "GitHub" })).not.toBeInTheDocument();
    await waitFor(() => expect(listCalls).toBe(3));
    const calls = DELETE.mock.calls as unknown as Array<[string, { params: { header: Record<string, string> } }]>;
    expect(calls).toHaveLength(2);
    expect(new Set(calls.map(([, options]) => options.params.header["Idempotency-Key"])).size).toBe(1);
    expect(calls.map(([, options]) => options.params.header["If-Match"])).toEqual(['"1"', '"1"']);
  });

  it("enables an already-due retained revocation when the effect observes an elapsed deadline", async () => {
    const now = vi.spyOn(Date, "now").mockImplementation(() => {
      const stack = new Error().stack ?? "";
      return stack.includes("ProductionWorkflowViews.tsx") && stack.includes("commitHookEffectListMount") ? 4_000 : 1_000;
    });
    const GET = vi.fn(async (path: string) => {
      if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
      if (path === "/api/v1/integrations") return jsonResult({ items: [integration], page_info: { next_cursor: null, has_more: false } });
      if (path === "/api/v1/integrations/{id}") return jsonResult(integration, 200, { ETag: '"1"' });
      throw new Error(`unexpected GET ${path}`);
    });
    const DELETE = vi.fn(async () => jsonResult(revoking, 202, { ...receiptHeaders, "Retry-After": "2" }));
    try {
      render(<APIProvider client={{ GET, DELETE } as unknown as APIClient}><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ProductionIntegrationsView canWrite /></WorkflowMutationProvider></APIProvider>);
      fireEvent.click(await screen.findByRole("button", { name: "Open GitHub" }));
      fireEvent.click(await screen.findByRole("button", { name: "Delete integration" }));
      const retry = await screen.findByRole("button", { name: "Retry pending integration deletion" });
      await waitFor(() => expect(retry).toBeEnabled());
    } finally {
      now.mockRestore();
    }
  });

	it("tests the saved webhook, retains a lost delivery, and shows durable signature status without discovery claims", async () => {
		const user = userEvent.setup();
		const webhook = {...integration,connector_key:"generic-webhook",name:"Webhook",status:"configured",configuration:{destination_url:"https://hooks.example.test/zasp",signing_secret_reference:"secret_ref_webhook_prod"}};
		const manifest = {...githubManifest,key:"generic-webhook",provider:"Generic Webhook",category:"notification",auth_mode:"signed_webhook",actions:["response_notification","approval_response"],data_types:["response","approval"],setup_schema:[{key:"destination_url",label:"HTTPS destination",type:"uri",required:true,description:"Saved HTTPS endpoint"},{key:"signing_secret_reference",label:"Signing secret",type:"secret_reference",required:true,description:"Product secret reference"}]};
		const delivery = {integration_id:integration.id,delivery_id:"pid_41000001-0000-4000-8000-000000000001",audit_id:receiptHeaders["X-Audit-ID"],delivery_status:"succeeded",signature_status:"signed",attempted_at:"2026-09-08T00:00:00Z",completed_at:"2026-09-08T00:00:01Z",error_code:""};
		const GET = vi.fn(async (path:string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({items:[manifest]});
			if (path === "/api/v1/integrations") return jsonResult({items:[webhook],page_info:{next_cursor:null,has_more:false}});
			if (path === "/api/v1/integrations/{id}") return jsonResult(webhook,200,{ETag:'"3"'});
			if (path === "/api/v1/integrations/{id}/delivery-status") return productErrorResult(404,"not_found","No current test");
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn().mockRejectedValueOnce(new TypeError("lost")).mockRejectedValueOnce(new TypeError("lost")).mockResolvedValue(jsonResult(delivery,200,{"Cache-Control":"no-store","X-Audit-ID":delivery.audit_id}));
		renderFreshIntegrations({GET,POST} as unknown as APIClient);
		await user.click(await screen.findByRole("button",{name:"Open Webhook"}));
		expect(await screen.findByText("No delivery test for the current configuration.")).toBeVisible();
		expect(screen.queryByRole("region",{name:"Automatic discovery"})).not.toBeInTheDocument();
		await user.click(screen.getByRole("button",{name:"Test signed delivery"}));
		const retry = await screen.findByRole("button",{name:"Retry retained integration operation"});
		expect(screen.getByRole("button",{name:"Test signed delivery"})).toBeDisabled();
		expect(screen.getByRole("button",{name:"Save changes"})).toBeDisabled();
		await user.click(retry);
		expect(await screen.findByText("Signed by Zasp; endpoint accepted the test.")).toBeVisible();
		expect(screen.getByText(`Delivery ID: ${delivery.delivery_id}`)).toBeVisible();
		expect(document.body.innerHTML).not.toContain("secret_ref_webhook_prod");
		expect(POST).toHaveBeenCalledTimes(3); expect(POST.mock.calls[1]).toEqual(POST.mock.calls[0]); expect(POST.mock.calls[2]).toEqual(POST.mock.calls[0]);
		expect(GET.mock.calls.some(([path]) => /freshness|syncs|schedule|setup-status/.test(path))).toBe(false);
	});

	it("formats opaque configuration references without rendering their values", async () => {
		const user = userEvent.setup();
		const aws: Integration = { ...integration, connector_key: "aws", name: "AWS", configuration: { role_arn: "arn:aws:iam::123456789012:role/zasp-discovery", external_id_reference: "ref:aws/external-id/customer-0001", region: "us-east-1" } };
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [aws], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(aws, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		render(<APIProvider client={{ GET } as unknown as APIClient}><ProductionIntegrationsView canWrite={false} /></APIProvider>);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		const reference = screen.getByLabelText("external id reference");
		expect(reference).toHaveValue("Configured reference");
		expect(reference).toBeDisabled();
		expect(document.body.innerHTML).not.toContain("ref:aws/external-id/customer-0001");
		expect(screen.queryByRole("button", { name: "Authorize AWS reference" })).not.toBeInTheDocument();
	});
});

function jsonResult(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return {
    data,
    response: new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } }),
  };
}

function productErrorResult(status: number, code: string, message: string) {
	const error = { code, message, correlation_id: "pid_90000001-0000-4000-8000-000000000001", retryable: false };
	return { error, response: new Response(JSON.stringify(error), { status, headers: { "Content-Type": "application/json" } }) };
}

function renderFreshIntegrations(client: APIClient, expiresAt = new Date(Date.now() + 60_000).toISOString(), navigateAuthorization?: (target: string) => void) {
	const GET = client.GET.bind(client);
	const sessionClient = {
		...client,
		GET: (path: Parameters<APIClient["GET"]>[0], options?: unknown) => path === "/api/v1/session/bootstrap"
			? Promise.resolve(jsonResult(sessionBootstrap(expiresAt)))
			: GET(path as never, options as never),
	} as APIClient;
	return render(<APIProvider client={sessionClient}><SessionProvider><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ProductionIntegrationsView canWrite navigateAuthorization={navigateAuthorization} /></WorkflowMutationProvider></SessionProvider></APIProvider>);
}

function sessionBootstrap(freshAuthExpiresAt: string) {
	return {
		principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "org-production", member_reference: "member-production", role: "admin", active: true },
		organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
		permissions: ["view", "manage_workflows"], capabilities: ["integrations.read", "integrations.write"], csrf_token: "csrf_12345678901234567890123456789012",
		fresh_auth_expires_at: freshAuthExpiresAt, correlation_id: "pid_10000005-0000-4000-8000-000000000005",
	};
}

function deferred<T>() {
	let resolve!: (value: T) => void;
	let reject!: (error: unknown) => void;
	const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
	return { promise, resolve, reject };
}
