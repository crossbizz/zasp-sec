import { useEffect, type ReactNode } from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import type { InventorySummary } from "../../../apps/web/api/generated";
import { APIProvider, useAPI } from "../../api/APIProvider";
import type { ProductionRiskAPI } from "./api";
import { ProductionRiskView } from "./ProductionRiskView";

const agentID = "pid_20000004-0000-4000-8000-000000000004";
const evidence = "pid_20000002-0000-4000-8000-000000000002";
const finding = { id: "pid_20000001-0000-4000-8000-000000000001", source: "posture", rule: "ownerless_agent", title: "Agent has no owner", severity: "high", status: "open", agent_id: agentID, path_id: null, evidence_ids: [evidence], risk_factors: [{ name: "Agent has no owner", evidence_id: evidence }], version: 1, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z" } as const;
const activityScope = { organizationID: "pid_10000001-0000-4000-8000-000000000001", workspaceID: "pid_10000002-0000-4000-8000-000000000002", environmentID: "pid_10000003-0000-4000-8000-000000000003" };

function agent(attribution?: InventorySummary["attribution"]): InventorySummary {
  return {
    id: agentID, name: "order-support-assistant", kind: "agent", owner: "", team: "", tags: [], evidence_id: evidence, confidence_basis_points: 9500,
    first_seen: "2026-08-19T00:00:00Z", last_seen: "2026-08-19T01:00:00Z", observed_at: "2026-08-19T01:00:00Z", fresh_until: "2026-08-19T01:15:00Z", freshness_state: "fresh",
    provider: "aws", source_kind: "aws_agentcore_runtime", discovery: { method: "provider_api", platform: "agentcore_runtime", signals: [] }, management_state: "unmanaged", last_activity_at: null, activity_state: "unknown", version: 1,
    ...(attribution ? { attribution } : {}),
  };
}

function riskAPI(value: InventorySummary): ProductionRiskAPI {
  const unused = async () => { throw new Error("unused"); };
  return {
    async listFindings() { return [finding] as never; }, async getFinding() { return { value: finding, version: '"1"' } as never; },
    updateFinding: unused, acceptFindingRisk: unused, createFindingTicket: unused,
    async listAttackPaths() { return []; }, getAttackPath: unused, async getAttackPathBreakOptions() { return []; },
    async listFindingAgents() { return { [agentID]: value }; },
  } as ProductionRiskAPI;
}

function QueryScope({ children }: { children: ReactNode }) {
  const { setQueryScope } = useAPI();
  useEffect(() => setQueryScope("risk-attribution-scope"), [setQueryScope]);
  return children;
}

function renderFindings(value: InventorySummary) {
  return render(<APIProvider><QueryScope><ProductionRiskView path="/violations" api={riskAPI(value)} canWrite={false} onNavigate={() => undefined} activityScope={activityScope} /></QueryScope></APIProvider>);
}

describe("findings show where the affected agent lives and who created it", () => {
  it("lists the location in the table and the creator and suggestion in the affected agent block of an ownerless agent", async () => {
    const user = userEvent.setup();
    renderFindings(agent({
      location: { kind: "aws_account", id: "123456789012", label: "123456789012" },
      integration: { id: "pid_20000005-0000-4000-8000-000000000005", name: "Production account" },
      creator: { identity: "dana.reyes@example.com", created_at: "2026-10-01T09:30:15Z", source: "cloudtrail" },
      suggested_owner: { value: "dana.reyes@example.com", source: "cloudtrail" },
      suggested_team: { value: "Customer Platform", source: "okta" },
    }));
    const open = await screen.findByRole("button", { name: "Open Agent has no owner" });
    expect(screen.getByRole("columnheader", { name: "Location" })).toBeVisible();
    const row = open.closest("tr")!;
    expect(await within(row).findByText("AWS account 123456789012")).toBeVisible();
    // The owner column still says nobody owns it: a suggestion is not an owner.
    expect(within(row).getByText("No owner")).toBeVisible();
    await user.click(open);
    const block = await screen.findByRole("region", { name: "Affected agent" });
    expect(within(block).getByText("Owner").nextElementSibling).toHaveTextContent("No owner assigned");
    expect(within(block).getByText("Where it runs").nextElementSibling).toHaveTextContent("AWS · AgentCore runtime");
    expect(within(block).getByText("Location").nextElementSibling).toHaveTextContent("AWS account 123456789012");
    expect(within(block).getByText("Found by integration").nextElementSibling).toHaveTextContent("Production account");
    expect(within(block).getByText("Created by").nextElementSibling).toHaveTextContent("dana.reyes@example.com on 1 Oct 2026, 09:30 UTC, from the AWS CloudTrail create event");
    expect(within(block).getByText("Suggested owner").nextElementSibling).toHaveTextContent("dana.reyes@example.com, from the AWS CloudTrail create event. Not assigned yet.");
    expect(within(block).getByText("Suggested team").nextElementSibling).toHaveTextContent("Customer Platform, from the creator's department in Okta. Not assigned yet.");
  });

  it("says what the provider does not report and adds no rows for an agent without attribution", async () => {
    const user = userEvent.setup();
    const view = renderFindings(agent({ location: null, integration: null, creator: null, suggested_owner: null, suggested_team: null }));
    await user.click(await screen.findByRole("button", { name: "Open Agent has no owner" }));
    const block = await screen.findByRole("region", { name: "Affected agent" });
    expect(within(block).getByText("Location").nextElementSibling).toHaveTextContent("Not reported by the provider");
    expect(within(block).getByText("Created by").nextElementSibling).toHaveTextContent("Not reported by the provider");
    expect(within(block).queryByText("Suggested owner")).not.toBeInTheDocument();
    view.unmount();
    renderFindings(agent());
    await user.click(await screen.findByRole("button", { name: "Open Agent has no owner" }));
    const plain = await screen.findByRole("region", { name: "Affected agent" });
    expect(within(plain).getByText("Where it runs")).toBeVisible();
    expect(within(plain).queryByText("Location")).not.toBeInTheDocument();
  });
});
