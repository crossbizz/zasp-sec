import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { createAPIClient } from "../../apps/web/api/client";
import { APIProvider } from "../api/APIProvider";
import { AgentSecurityView } from "../features/agents/AgentSecurityView";

describe("connected core risk workflow", () => {
	it("loads API inventory detail and reloads the authoritative result", async () => {
    const fetch = vi.fn(async (request: Request) => {
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/agents") return jsonResponse({ items: [agent()] });
			if (path === `/api/v1/agents/${agent().id}`) return jsonResponse(agent());
      return jsonResponse({ code: "not_found", message: "Resource not found", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false }, 404);
    });
		const client = createAPIClient({ fetch, generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" });
		const { unmount } = render(<APIProvider client={client}><AgentSecurityView path="/discovery/assets" onNavigate={() => undefined} /></APIProvider>);
    await waitFor(() => expect(screen.getByText("Support agent")).toBeVisible());
		await userEvent.click(screen.getByRole("button", { name: "Open Support agent" }));
		expect(await screen.findByRole("dialog", { name: "Support agent" })).toHaveTextContent(agent().evidence_id);

    unmount();
		render(<APIProvider client={client}><AgentSecurityView path="/discovery/assets" onNavigate={() => undefined} /></APIProvider>);
		await waitFor(() => expect(screen.getByText("Support agent")).toBeVisible());
		expect(fetch.mock.calls.some(([request]) => new URL((request as Request).url).pathname.includes("findings"))).toBe(false);
  });

	it("loads overview and durable tool detail without advertising hidden providers", async () => {
    const fetch = vi.fn(async (request: Request) => {
      const url = new URL(request.url);
      if (url.pathname === "/api/v1/home/summary") return jsonResponse({ agent_count: 1, high_risk_paths: 1, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false });
      if (url.pathname === "/api/v1/tools") return jsonResponse({ items: [{ ...agent(), id: "pid_20000003-0000-4000-8000-000000000003", name: "Customer records MCP", kind: "tool" }] });
      if (url.pathname === "/api/v1/tools/pid_20000003-0000-4000-8000-000000000003") return jsonResponse({ ...agent(), id: "pid_20000003-0000-4000-8000-000000000003", name: "Customer records MCP", kind: "tool" });
      return jsonResponse({ code: "not_found", message: "Resource not found", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false }, 404);
    });
    const client = createAPIClient({ fetch, generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", getCSRFToken: () => "cccccccccccccccccccccccccccccccc" });
    function Workflow() {
      const [path, setPath] = useState("/");
			return <><button onClick={() => setPath("/inventory/tools")}>Tools</button><AgentSecurityView path={path} onNavigate={setPath} /></>;
    }
    render(<APIProvider client={client}><Workflow /></APIProvider>);

    await screen.findByRole("heading", { name: "Security overview" });
		expect(screen.queryByRole("searchbox")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Tools" }));
    await userEvent.click(await screen.findByRole("button", { name: "Open Customer records MCP" }));
    expect(await screen.findByRole("dialog", { name: "Customer records MCP" })).toHaveTextContent("pid_20000006-0000-4000-8000-000000000006");
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
		expect(fetch.mock.calls.some(([request]) => /search|attack-paths|findings/.test(new URL((request as Request).url).pathname))).toBe(false);
  });
});

function agent() {
  return { id: "pid_20000001-0000-4000-8000-000000000001", name: "Support agent", kind: "agent", owner: "security", team: "platform", tags: [], evidence_id: "pid_20000006-0000-4000-8000-000000000006", first_seen: "2026-08-18T09:00:00Z", last_seen: "2026-08-18T10:00:00Z" };
}
function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
