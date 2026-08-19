import { render, screen } from "@testing-library/react";
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
          permissions: ["view", "manage_findings"], capabilities: ["inventory.read", "findings.read", "findings.manage", "attack_paths.read"], csrf_token: "cccccccccccccccccccccccccccccccc", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        });
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
    await userEvent.click(screen.getByRole("link", { name: "Agents" }));
    expect(await screen.findByText("No records in this scope.")).toBeVisible();
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
	});
});

function apiJSON(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
