import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { createAPIClient } from "../../apps/web/api/client";
import { APIProvider } from "../api/APIProvider";
import { AgentSecurityView } from "../features/agents/AgentSecurityView";

describe("connected core risk workflow", () => {
  it("loads API inventory, mutates a finding, and reloads the authoritative result", async () => {
    let findingStatus = "open";
    const fetch = vi.fn(async (request: Request) => {
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/agents") return jsonResponse({ items: [agent()] });
      if (path === "/api/v1/findings" && request.method === "GET") return jsonResponse({ items: [finding(findingStatus)] });
      if (path.endsWith("/pid_20000005-0000-4000-8000-000000000005") && request.method === "PATCH") {
        findingStatus = "under_review";
        return jsonResponse(finding(findingStatus));
      }
      return jsonResponse({ code: "not_found", message: "Resource not found", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false }, 404);
    });
    const client = createAPIClient({ fetch, generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", getCSRFToken: () => "cccccccccccccccccccccccccccccccc" });

    function Workflow() {
      const [path, setPath] = useState("/discovery/assets");
      return <><button onClick={() => setPath("/violations")}>Findings</button><AgentSecurityView path={path} onNavigate={setPath} /></>;
    }
    const { unmount } = render(<APIProvider client={client}><Workflow /></APIProvider>);
    await waitFor(() => expect(screen.getByText("Support agent")).toBeVisible());
    await userEvent.click(screen.getByRole("button", { name: "Findings" }));
    await waitFor(() => expect(screen.getByText("Owner missing on production agent")).toBeVisible());
    await userEvent.click(screen.getByRole("button", { name: "Mark Owner missing on production agent under review" }));
    await waitFor(() => expect(screen.getByText("under_review")).toBeVisible());

    unmount();
    render(<APIProvider client={client}><AgentSecurityView path="/violations" onNavigate={() => undefined} /></APIProvider>);
    await waitFor(() => expect(screen.getByText("under_review")).toBeVisible());
    expect(fetch).toHaveBeenCalled();
  });

  it("loads global search, durable inventory detail, and attack-path break options", async () => {
    const fetch = vi.fn(async (request: Request) => {
      const url = new URL(request.url);
      if (url.pathname === "/api/v1/home/summary") return jsonResponse({ agent_count: 1, high_risk_paths: 1, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false });
      if (url.pathname === "/api/v1/search") return jsonResponse({ items: [{ id: agent().id, name: agent().name, type: "agent" }] });
      if (url.pathname === "/api/v1/tools") return jsonResponse({ items: [{ ...agent(), id: "pid_20000003-0000-4000-8000-000000000003", name: "Customer records MCP", kind: "tool" }] });
      if (url.pathname === "/api/v1/tools/pid_20000003-0000-4000-8000-000000000003") return jsonResponse({ ...agent(), id: "pid_20000003-0000-4000-8000-000000000003", name: "Customer records MCP", kind: "tool" });
      if (url.pathname === "/api/v1/attack-paths") return jsonResponse({ items: [{ id: "pid_20000007-0000-4000-8000-000000000007", entry_id: agent().id, sink_id: "pid_20000003-0000-4000-8000-000000000003", node_ids: [agent().id, "pid_20000003-0000-4000-8000-000000000003"], state: "observed", evidence_ids: ["pid_20000006-0000-4000-8000-000000000006"], blocked_edge: -1 }] });
      if (url.pathname.endsWith("/break-options")) return jsonResponse({ items: [{ path_id: "pid_20000007-0000-4000-8000-000000000007", target_id: "pid_20000003-0000-4000-8000-000000000003", evidence_id: "pid_20000006-0000-4000-8000-000000000006", kind: "enforce_policy", rank: 1 }] });
      return jsonResponse({ code: "not_found", message: "Resource not found", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false }, 404);
    });
    const client = createAPIClient({ fetch, generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", getCSRFToken: () => "cccccccccccccccccccccccccccccccc" });
    function Workflow() {
      const [path, setPath] = useState("/");
      return <><button onClick={() => setPath("/inventory/tools")}>Tools</button><button onClick={() => setPath("/exposure/attack-paths")}>Paths</button><AgentSecurityView path={path} onNavigate={setPath} /></>;
    }
    render(<APIProvider client={client}><Workflow /></APIProvider>);

    await screen.findByRole("heading", { name: "Security overview" });
    await userEvent.type(screen.getByRole("searchbox", { name: "Search authorized records" }), "Support");
    await userEvent.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByRole("button", { name: "Open search result Support agent" })).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Tools" }));
    await userEvent.click(await screen.findByRole("button", { name: "Open Customer records MCP" }));
    expect(await screen.findByRole("dialog", { name: "Customer records MCP" })).toHaveTextContent("pid_20000006-0000-4000-8000-000000000006");
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    await userEvent.click(screen.getByRole("button", { name: "Paths" }));
    await userEvent.click(await screen.findByRole("button", { name: /Open attack path/ }));
    expect(await screen.findByText(/Enforce policy/)).toBeVisible();
  });
});

function agent() {
  return { id: "pid_20000001-0000-4000-8000-000000000001", name: "Support agent", kind: "agent", owner: "security", team: "platform", tags: [], evidence_id: "pid_20000006-0000-4000-8000-000000000006", first_seen: "2026-08-18T09:00:00Z", last_seen: "2026-08-18T10:00:00Z" };
}
function finding(status: string) {
  return { id: "pid_20000005-0000-4000-8000-000000000005", source: "posture", rule: "ownerless_agent", title: "Owner missing on production agent", severity: "high", status, agent_id: "pid_20000001-0000-4000-8000-000000000001", evidence_ids: ["pid_20000006-0000-4000-8000-000000000006"], risk_factors: [] };
}
function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
