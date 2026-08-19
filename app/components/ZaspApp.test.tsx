import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";
import { createAPIClient } from "../../apps/web/api/client";
import { ZaspApp, ZaspDemoApp } from "./ZaspApp";

describe("Zasp application", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState({}, "", "/");
  });

  it.each([
    ["Agents", "Agentic assets"],
    ["Identities", "Non-human identities"],
    ["Findings", "Identity violations"],
    ["Policies", "Identity policies"],
    ["Red Team", "Red team results"],
    ["Connections", "Connectors"],
  ])("navigates from %s to its workspace", async (link, heading) => {
    render(<ZaspDemoApp />);
    await userEvent.click(screen.getByRole("link", { name: link }));
    expect(screen.getByRole("heading", { name: heading })).toBeVisible();
  });

  it("investigates a risky identity and remediates its critical violation", async () => {
    render(<ZaspDemoApp />);
    await userEvent.click(screen.getByRole("link", { name: "Identities" }));
    await userEvent.click(screen.getByRole("tab", { name: /Risky identities/ }));
    await userEvent.click(screen.getByRole("button", { name: /aws-prod-agent-key/ }));
    expect(screen.getByText("Maya Chen → Release Agent → aws-prod-agent-key → AWS Production")).toBeVisible();
    await userEvent.click(screen.getByRole("tab", { name: /Violations/ }));
    await userEvent.click(screen.getByRole("button", { name: "Admin credential exposed to agent runtime" }));
    await userEvent.click(screen.getByRole("tab", { name: "Remediation" }));
    await userEvent.click(screen.getByRole("button", { name: "Rotate credential" }));
    await userEvent.click(screen.getByRole("button", { name: "Confirm remediation" }));
    expect(screen.getByText("Fixed")).toBeVisible();
  });

  it("connects a cloud inventory source", async () => {
    render(<ZaspDemoApp />);
    await userEvent.click(screen.getByRole("link", { name: "Connections" }));
    await userEvent.click(screen.getByRole("button", { name: "Connect Amazon Web Services" }));
    await userEvent.type(screen.getByLabelText("Role ARN"), "arn:aws:iam::123456789012:role/ZaspReadOnly");
    await userEvent.type(screen.getByLabelText("External ID"), "northstar-prod");
    await userEvent.click(screen.getByRole("button", { name: "Connect now" }));
    expect(screen.getByRole("status")).toHaveTextContent("Amazon Web Services connected");
  });

  it("renders connection catalog, freshness list, bounded detail history, and supported actions", async () => {
    render(<ZaspDemoApp />);
    await userEvent.click(screen.getByRole("link", { name: "Connections" }));
    expect(screen.getByRole("heading", { name: "Connected integrations" })).toBeVisible();
    expect(screen.getByRole("button", { name: "View Microsoft Azure connection" })).toBeVisible();
    expect(screen.queryByText(/cartography|prowler|nango/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "View Kubernetes connection" }));
    const dialog = screen.getByRole("dialog", { name: "Kubernetes" });
    expect(dialog).toHaveTextContent("Production / us-west");
    expect(dialog).toHaveTextContent("Runtime signals");
    expect(dialog).toHaveTextContent("3h ago");
    expect(dialog).toHaveTextContent("failed");
    expect(screen.getByRole("button", { name: "Sync now" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Delete connection" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Review access" })).toBeVisible();
  });

  it("renders provider-specific connection setup and remediation flows", async () => {
    render(<ZaspDemoApp />);
    await userEvent.click(screen.getByRole("link", { name: "Connections" }));
    await userEvent.click(screen.getByRole("button", { name: "Connect Amazon Web Services" }));
    const aws = screen.getByRole("dialog", { name: "Connect Amazon Web Services" });
    for (const label of ["Review access", "Role and external ID", "Test connection", "Initial sync", "Coverage"]) expect(aws).toHaveTextContent(label);
    expect(aws).toHaveTextContent("Missing iam:GetRole permission");
    await userEvent.click(screen.getByRole("button", { name: "Close" }));

    await userEvent.click(screen.getByRole("button", { name: "View GitHub connection" }));
    await userEvent.click(screen.getByRole("button", { name: "Review access" }));
    expect(screen.getByRole("dialog", { name: "Review GitHub access" })).toHaveTextContent("Repository and Organization scope");
    expect(screen.getByRole("dialog", { name: "Review GitHub access" })).toHaveTextContent("Scope validation");
  });

  it("keeps directory security and signed webhooks separate and bounded", async () => {
    render(<ZaspDemoApp />);
    await userEvent.click(screen.getByRole("link", { name: "Connections" }));
    await userEvent.click(screen.getByRole("button", { name: "Connect Workforce Directory" }));
    expect(screen.getByRole("dialog", { name: "Connect Workforce Directory" })).toHaveTextContent("Directory security integration");
    expect(screen.getByRole("dialog", { name: "Connect Workforce Directory" })).toHaveTextContent("separate from product sign-in");
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    await userEvent.click(screen.getByRole("button", { name: "Connect Generic Webhook" }));
    expect(screen.getByRole("dialog", { name: "Connect Generic Webhook" })).toHaveTextContent("Signature status");
    expect(screen.queryByLabelText(/action url/i)).not.toBeInTheDocument();
  });

  it("renders sensor list, coverage, enrollment, rotation, and deletion controls", async () => {
    render(<ZaspDemoApp />);
    await userEvent.click(screen.getByRole("link", { name: "Sensors" }));
    expect(screen.getByRole("heading", { name: "Runtime sensors" })).toBeVisible();
    expect(screen.getByText("Unsupported kernel")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "View production-us-west sensor" }));
    expect(screen.getByRole("dialog", { name: "production-us-west" })).toHaveTextContent("Coverage");
    expect(screen.getByRole("button", { name: "Rotate enrollment token" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Delete sensor" })).toBeVisible();
  });

  it.each([
    [/^Protected interactions/, "Security agents"],
    [/^Runtime guardrails/, "Security agents"],
    [/^Enforce the secure code guardrail/, "Identity policies"],
    [/^Market Research Agent first observed/, "Agentic assets"],
  ])("keeps the Overview action %s inside the canonical product routes", async (action, heading) => {
    render(<ZaspDemoApp />);
    await userEvent.click(screen.getByRole("button", { name: action }));
    expect(screen.getByRole("heading", { name: heading })).toBeVisible();
  });

  it("opens the bounded Attack Lab destination from Red Team", async () => {
    render(<ZaspDemoApp />);
    await userEvent.click(screen.getByRole("link", { name: "Red Team" }));
    await userEvent.click(screen.getByRole("button", { name: "Run scan" }));
    expect(screen.getByRole("heading", { name: "Attack lab" })).toBeVisible();
  });

  it("routes Identity & Access through the generated-client product surface", () => {
    window.history.replaceState({}, "", "/administration/identity-access");
    render(<ZaspDemoApp />);
    expect(screen.getByText("Loading identity and access…")).toBeVisible();
  });

  it("uses server capabilities for production navigation without the demo store", async () => {
    const client = createAPIClient({
      generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
      fetch: async (request) => {
        const path = new URL(request.url).pathname;
        if (path === "/api/v1/session/bootstrap") return apiJSON({
          principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "organization-live", member_reference: "member-live", role: "security_admin", active: true },
          organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
		  permissions: ["view"], capabilities: ["inventory.read", "scope.switch"], csrf_token: "cccccccccccccccccccccccccccccccc", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        });
		if (path === "/api/v1/session/scopes") return apiJSON({ items: [
			{ organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003", label: "Production" },
			{ organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000022-0000-4000-8000-000000000022", environment_id: "pid_10000023-0000-4000-8000-000000000023", label: "Staging" },
		] });
        if (path === "/api/v1/home/summary") return apiJSON({ agent_count: 1, high_risk_paths: 1, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false });
        if (path === "/api/v1/agents") return apiJSON({ items: [] });
        return apiJSON({ code: "not_found", message: "Resource not found", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false }, 404);
      },
    });
    render(<ZaspApp client={client} />);
    expect(await screen.findByRole("heading", { name: "Security overview" })).toBeVisible();
    expect(screen.getByRole("link", { name: "Agents" })).toBeVisible();
    expect(screen.queryByRole("link", { name: "Policies" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Red Team" })).not.toBeInTheDocument();
	expect(screen.getByRole("combobox", { name: "Authorized scope" })).toBeVisible();
    await userEvent.click(screen.getByRole("link", { name: "Agents" }));
    expect(await screen.findByText("No records in this scope.")).toBeVisible();
  });

	it("routes authenticated workflow capabilities to real API-backed production surfaces", async () => {
		window.history.replaceState({}, "", "/policies");
		const requests: string[] = [];
		const client = createAPIClient({
			generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
			fetch: async (request) => {
				const path = new URL(request.url).pathname;
				requests.push(path);
				if (path === "/api/v1/session/bootstrap") return apiJSON({
					principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "organization-live", member_reference: "member-live", role: "security_admin", active: true },
					organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
					permissions: ["view", "manage_workflows"], capabilities: ["policies.read", "policies.write", "integrations.read", "sensors.read", "security-agents.read"], csrf_token: "cccccccccccccccccccccccccccccccc", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
				});
				if (path === "/api/v1/policies") return apiJSON({ items: [{ id: "policy-production", name: "Production policy", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" }] });
				if (path === "/api/v1/policies/policy-production") return apiJSON({ id: "policy-production", name: "Production policy", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" }, 200, { ETag: '"1"' });
				if (path === "/api/v1/integrations") return apiJSON({ items: [] });
				if (path === "/api/v1/integration-catalog") return apiJSON({ items: [] });
				throw new Error(`unexpected product fetch ${path}`);
			},
		});
		render(<ZaspApp client={client} />);
		expect(await screen.findByRole("heading", { name: "Policies" })).toBeVisible();
		expect(screen.getByRole("link", { name: "Integrations" })).toBeVisible();
		expect(screen.getByRole("button", { name: "Create policy" })).toBeVisible();
		await userEvent.click(await screen.findByRole("button", { name: "Open Production policy" }));
		expect(await screen.findByText("Policy detail · policy-production")).toBeVisible();
		expect(screen.queryByRole("button", { name: /simulate policy/i })).not.toBeInTheDocument();
		expect(screen.queryByRole("heading", { name: "Decision history" })).not.toBeInTheDocument();
		await userEvent.click(screen.getByRole("link", { name: "Integrations" }));
		expect(await screen.findByRole("heading", { name: "Integrations" })).toBeVisible();
		expect(screen.queryByRole("button", { name: /authorize|sync/i })).not.toBeInTheDocument();
		expect(requests).toEqual(expect.arrayContaining(["/api/v1/session/bootstrap", "/api/v1/policies", "/api/v1/policies/policy-production", "/api/v1/integrations", "/api/v1/integration-catalog"]));
		expect(requests).not.toContain("/api/v1/policies/policy-production/decisions");
	});

	it("restores one retryable committed policy attempt after navigating away and back", async () => {
		window.history.replaceState({}, "", "/policies");
		const keys: string[] = [];
		const policy = { id: "policy-production", name: "Production runtime policy", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" };
		const client = createAPIClient({
			generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
			fetch: async (request) => {
				const path = new URL(request.url).pathname;
				if (path === "/api/v1/session/bootstrap") return apiJSON({
					principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "organization-live", member_reference: "member-live", role: "security_admin", active: true },
					organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
					permissions: ["view", "manage_workflows"], capabilities: ["policies.read", "policies.write", "integrations.read"], csrf_token: "cccccccccccccccccccccccccccccccc", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
				});
				if (path === "/api/v1/policies" && request.method === "GET") return apiJSON({ items: [{ ...policy, id: "policy-existing", name: "Existing policy" }] });
				if (path === "/api/v1/policies" && request.method === "POST") {
					keys.push(request.headers.get("Idempotency-Key") ?? "");
					if (keys.length < 3) return apiJSON({ code: "temporarily_unavailable", message: "Committed response is not available yet.", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 503);
					return apiJSON(policy, 201, { ETag: '"1"', "X-Audit-ID": "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" });
				}
				if (path === "/api/v1/integrations" || path === "/api/v1/integration-catalog") return apiJSON({ items: [] });
				throw new Error(`unexpected product fetch ${request.method} ${path}`);
			},
		});
		render(<ZaspApp client={client} />);
		await userEvent.click(await screen.findByRole("button", { name: "Create policy" }));
		expect(await screen.findByRole("button", { name: "Retry retained policy operation" })).toBeVisible();
		expect(screen.getByRole("button", { name: "Open Existing policy" })).toBeDisabled();
		await userEvent.click(screen.getByRole("link", { name: "Integrations" }));
		expect(await screen.findByRole("heading", { name: "Integrations" })).toBeVisible();
		await userEvent.click(screen.getByRole("link", { name: "Policies" }));
		expect(await screen.findByRole("button", { name: "Retry retained policy operation" })).toBeVisible();
		await userEvent.click(screen.getByRole("button", { name: "Retry retained policy operation" }));
		expect(await screen.findByText(/Policy created\. Audit pid_/)).toBeVisible();
		await waitFor(() => expect(keys).toHaveLength(3));
		expect(new Set(keys).size).toBe(1);
	});

	it("locks every integration control except exact retained retry after an ambiguous save", async () => {
		window.history.replaceState({}, "", "/connectors");
		const manifest = {
			key: "generic-webhook", provider: "Generic Webhook", category: "notification",
			description: "Store one scoped HTTPS webhook configuration for a future delivery adapter.", data_types: ["configuration"], actions: ["store_configuration"], auth_mode: "secret_reference",
			setup_schema: [
				{ key: "destination_url", label: "HTTPS destination", type: "uri", required: true, description: "One allowlisted HTTPS endpoint for all actions." },
				{ key: "signing_secret_reference", label: "Signing secret", type: "secret_reference", required: true, description: "Product secret reference used to sign each delivery." },
			],
			access_guidance: "Save only an HTTPS destination and an opaque product secret reference.", test_semantics: "Validate and durably persist the local configuration without contacting the destination.",
		};
		const client = createAPIClient({
			generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
			fetch: async (request) => {
				const path = new URL(request.url).pathname;
				if (path === "/api/v1/session/bootstrap") return apiJSON({
					principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "organization-live", member_reference: "member-live", role: "security_admin", active: true },
					organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
					permissions: ["view", "manage_workflows"], capabilities: ["integrations.read", "integrations.write"], csrf_token: "cccccccccccccccccccccccccccccccc", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
				});
				if (path === "/api/v1/integrations" && request.method === "GET") return apiJSON({ items: [] });
				if (path === "/api/v1/integration-catalog") return apiJSON({ items: [manifest] });
				if (path === "/api/v1/integrations" && request.method === "POST") return apiJSON({}, 201);
				throw new Error(`unexpected product fetch ${request.method} ${path}`);
			},
		});
		render(<ZaspApp client={client} />);
		await userEvent.click(await screen.findByRole("button", { name: "Configure Generic Webhook" }));
		await userEvent.type(screen.getByRole("textbox", { name: /HTTPS destination/ }), "https://hooks.customer.invalid/zasp");
		await userEvent.type(screen.getByRole("textbox", { name: /Signing secret/ }), "secret-reference");
		await userEvent.click(screen.getByRole("button", { name: "Save integration" }));
		expect(await screen.findByRole("button", { name: "Retry retained integration operation" })).toBeEnabled();
		for (const label of ["Integration name", "HTTPS destination", "Signing secret"]) expect(screen.getByRole("textbox", { name: new RegExp(label) })).toBeDisabled();
		for (const label of ["Configure Generic Webhook", "Close modal", "Close", "Cancel", "Save integration"]) expect(screen.getByRole("button", { name: label })).toBeDisabled();
	});

	it("capability-hides sensor enrollment even when stale server capabilities advertise it", async () => {
		window.history.replaceState({}, "", "/integrations/sensors");
		const requests: string[] = [];
		const client = createAPIClient({
			generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
			fetch: async (request) => {
				const path = new URL(request.url).pathname;
				requests.push(path);
				if (path === "/api/v1/session/bootstrap") return apiJSON({
					principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "organization-live", member_reference: "member-live", role: "security_admin", active: true },
					organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
					permissions: ["view", "manage_workflows"], capabilities: ["inventory.read", "sensors.read", "sensors.write"], csrf_token: "cccccccccccccccccccccccccccccccc", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
				});
				if (path === "/api/v1/home/summary") return apiJSON({ agent_count: 0, high_risk_paths: 0, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false });
				throw new Error(`unexpected product fetch ${request.method} ${path}`);
			},
		});
		render(<ZaspApp client={client} />);
		expect(await screen.findByRole("heading", { name: "Security overview" })).toBeVisible();
		expect(window.location.pathname).toBe("/");
		expect(screen.queryByRole("link", { name: "Sensors" })).not.toBeInTheDocument();
		expect(requests).not.toContain("/api/v1/sensors");
	});

	it("clears visible workflow state while switching scopes and remounts on the exact new scope", async () => {
		window.history.replaceState({}, "", "/policies");
		let switched = false;
		let releaseReconciliation: (() => void) | undefined;
		const reconciliationGate = new Promise<void>((resolve) => { releaseReconciliation = resolve; });
		const organizationID = "pid_10000001-0000-4000-8000-000000000001";
		const productionWorkspace = "pid_10000002-0000-4000-8000-000000000002";
		const productionEnvironment = "pid_10000003-0000-4000-8000-000000000003";
		const stagingWorkspace = "pid_10000022-0000-4000-8000-000000000022";
		const stagingEnvironment = "pid_10000023-0000-4000-8000-000000000023";
		const client = createAPIClient({
			generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
			fetch: async (request) => {
				const path = new URL(request.url).pathname;
				if (path === "/api/v1/session/bootstrap") { if (switched) await reconciliationGate; return apiJSON({ principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: organizationID, organization_reference: "organization-live", member_reference: "member-live", role: "security_admin", active: true }, organization_id: organizationID, workspace_id: switched ? stagingWorkspace : productionWorkspace, environment_id: switched ? stagingEnvironment : productionEnvironment, permissions: ["view", "manage_workflows"], capabilities: ["policies.read", "policies.write", "scope.switch"], csrf_token: "cccccccccccccccccccccccccccccccc", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }); }
				if (path === "/api/v1/session/scopes") return apiJSON({ items: [{ organization_id: organizationID, workspace_id: productionWorkspace, environment_id: productionEnvironment, label: "Production" }, { organization_id: organizationID, workspace_id: stagingWorkspace, environment_id: stagingEnvironment, label: "Staging" }] });
				if (path === "/api/v1/session/scope" && request.method === "PUT") { switched = true; return new Response(null, { status: 204 }); }
				if (path === "/api/v1/policies") return apiJSON({ items: [{ id: switched ? "policy-staging" : "policy-production", name: switched ? "Staging policy" : "Production policy", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" }] });
				if (path === "/api/v1/policies/policy-production") return apiJSON({ id: "policy-production", name: "Production policy", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" }, 200, { ETag: '"1"' });
				throw new Error(`unexpected product fetch ${request.method} ${path}`);
			},
		});
		render(<ZaspApp client={client} />);
		await userEvent.click(await screen.findByRole("button", { name: "Open Production policy" }));
		expect(await screen.findByText("Policy detail · policy-production")).toBeVisible();
		await userEvent.selectOptions(screen.getByRole("combobox", { name: "Authorized scope" }), `${stagingWorkspace}/${stagingEnvironment}`);
		expect(await screen.findByText("Switching authorized scope…")).toBeVisible();
		expect(screen.queryByText("Policy detail · policy-production")).not.toBeInTheDocument();
		releaseReconciliation?.();
		expect(await screen.findByRole("button", { name: "Open Staging policy" })).toBeVisible();
		expect(screen.queryByText("Policy detail · policy-production")).not.toBeInTheDocument();
	});

	it.each(["initial", "popstate"])("blocks %s navigation to a capability-hidden production route before fetching", async (mode) => {
		const requests: string[] = [];
		if (mode === "initial") window.history.replaceState({}, "", "/violations");
		const client = createAPIClient({
			generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
			fetch: async (request) => {
				const path = new URL(request.url).pathname;
				requests.push(path);
				if (path === "/api/v1/session/bootstrap") return apiJSON({
					principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "organization-live", member_reference: "member-live", role: "security_admin", active: true },
					organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
					permissions: ["view"], capabilities: ["inventory.read"], csrf_token: "cccccccccccccccccccccccccccccccc", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
				});
				if (path === "/api/v1/home/summary") return apiJSON({ agent_count: 0, high_risk_paths: 0, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false });
				return apiJSON({ code: "not_found", message: "Resource not found", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false }, 404);
			},
		});
		render(<ZaspApp client={client} />);
		expect(await screen.findByRole("heading", { name: "Security overview" })).toBeVisible();
		if (mode === "popstate") {
			window.history.pushState({}, "", "/violations");
			window.dispatchEvent(new PopStateEvent("popstate"));
			expect(await screen.findByRole("heading", { name: "Security overview" })).toBeVisible();
		}
		expect(requests).not.toContain("/api/v1/findings");
		expect(screen.queryByRole("link", { name: "Findings" })).not.toBeInTheDocument();
		if (mode === "initial") expect(window.location.pathname).toBe("/");
	});

	it("renders no capabilities without product fetch and canonicalizes a recognized hidden URL", async () => {
		window.history.replaceState({}, "", "/inventory/tools");
		const requests: string[] = [];
		const client = createAPIClient({
			generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
			fetch: async (request) => {
				const path = new URL(request.url).pathname;
				requests.push(path);
				if (path === "/api/v1/session/bootstrap") return apiJSON({
					principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "organization-live", member_reference: "member-live", role: "read_only_viewer", active: true },
					organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
					permissions: [], capabilities: [], csrf_token: "cccccccccccccccccccccccccccccccc", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
				});
				throw new Error(`unexpected product fetch ${path}`);
			},
		});
		render(<ZaspApp client={client} />);
		expect(await screen.findByRole("heading", { name: "No product capabilities" })).toBeVisible();
		expect(window.location.pathname).toBe("/");
		expect(requests).toEqual(["/api/v1/session/bootstrap"]);
	});
});

function apiJSON(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}
