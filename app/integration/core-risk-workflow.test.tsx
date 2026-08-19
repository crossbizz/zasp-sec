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
