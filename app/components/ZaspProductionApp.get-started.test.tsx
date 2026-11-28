import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";

import type { SessionBootstrap } from "../../apps/web/api/generated";
import { ZaspProductionApp } from "./ZaspProductionApp";

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState({}, "", "/");
});

it.each([
  ["Connect an integration", "/connectors#add-source"],
  ["Enroll a sensor", "/integrations/sensors?enroll=1"],
])("opens the authorized setup destination through %s", async (action, destination) => {
  const reads: string[] = [];
  const empty = { items: [], page_info: { next_cursor: null, has_more: false } };
  const inventory = new Set(["tools", "identities", "runtimes", "integrations", "sensors"]);
  window.history.replaceState({}, "", "/");
  vi.stubGlobal("fetch", async (request: Request) => {
    const url = new URL(request.url);
    const endpoint = url.pathname.replace("/api/v1/", "");
    expect(request.method).toBe("GET");
    reads.push(endpoint);
    let data: unknown;
    if (endpoint === "session/bootstrap") {
      const org = "pid_10000001-0000-4000-8000-000000000001";
      const principal = "pid_10000004-0000-4000-8000-000000000004";
      data = {
        principal: { id: principal, organization_id: org, organization_reference: "organization-postlogin", member_reference: "member-postlogin", role: "security_admin", active: true },
        organization_id: org, workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
        permissions: ["view", "manage_workflows"], capabilities: ["inventory.read", "integrations.read", "integrations.write", "sensors.read", "sensors.write"],
        csrf_token: "c".repeat(32), fresh_auth_expires_at: new Date(Date.now() + 240_000).toISOString(), correlation_id: principal,
      } satisfies SessionBootstrap;
    } else if (inventory.has(endpoint)) {
      data = empty;
    } else if (endpoint === "home/summary") {
      data = { agent_count: 0, high_risk_paths: 0, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false };
    } else if (endpoint === "workflow-mutation-receipts" || endpoint === "integration-catalog") {
      data = { items: [] };
    } else {
      throw new Error(`Unexpected onboarding read: ${endpoint}`);
    }
    return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  });

  render(<ZaspProductionApp />);
  await userEvent.click(await screen.findByRole("button", { name: action }, { timeout: 5000 }));
  await waitFor(() => expect(window.location.pathname + window.location.search + window.location.hash).toBe(destination));
  expect(reads).toEqual(expect.arrayContaining(["session/bootstrap", "home/summary", ...inventory]));
  if (action === "Enroll a sensor") {
    const enrollment = await screen.findByRole("dialog", { name: "Enroll runtime sensor" });
    expect(enrollment).toBeVisible();
  } else {
    expect(await screen.findByRole("heading", { level: 1, name: "Integrations" })).toBeVisible();
    const search = await screen.findByRole("searchbox", { name: "Filter connectors" });
    expect(search.closest("#add-source")).toBeInTheDocument();
    await waitFor(() => expect(search).toHaveFocus());
  }
});
