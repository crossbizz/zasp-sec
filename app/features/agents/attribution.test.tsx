import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { InventorySummary } from "../../../apps/web/api/generated";
import { decodeInventorySummary } from "../../../apps/web/api/decoders";
import { APIProvider } from "../../api/APIProvider";
import { locationLabel } from "./attribution";
import { ProductionAgentSecurityView, type ProductionAgentSecurityAPI } from "./ProductionAgentSecurityView";

const ids = { agent: "pid_10000001-0000-4000-8000-000000000001", tool: "pid_10000002-0000-4000-8000-000000000002", evidence: "pid_20000001-0000-4000-8000-000000000001", integration: "pid_20000002-0000-4000-8000-000000000002" } as const;

type Attribution = NonNullable<InventorySummary["attribution"]>;

function agent(attribution?: Attribution, overrides: Partial<InventorySummary> = {}): InventorySummary {
  return {
    id: ids.agent, name: "order-support-assistant", kind: "agent", owner: "", team: "", tags: [], evidence_id: ids.evidence, confidence_basis_points: 9500,
    first_seen: "2026-08-19T00:00:00Z", last_seen: "2026-08-19T01:00:00Z", observed_at: "2026-08-19T01:00:00Z", fresh_until: "2026-08-19T01:15:00Z", freshness_state: "fresh",
    provider: "aws", source_kind: "aws_bedrock_agent", discovery: { method: "provider_api", platform: "bedrock_agent", signals: [] }, management_state: "unmanaged", last_activity_at: null, activity_state: "unknown", version: 1,
    ...(attribution ? { attribution } : {}), ...overrides,
  };
}

const full: Attribution = {
  location: { kind: "aws_account", id: "123456789012", label: "123456789012" },
  integration: { id: ids.integration, name: "Production account" },
  creator: { identity: "dana.reyes@example.com", created_at: "2026-10-01T09:30:15Z", source: "cloudtrail" },
  suggested_owner: { value: "dana.reyes@example.com", source: "cloudtrail" },
  suggested_team: { value: "Customer Platform", source: "okta" },
};

function agentsAPI(value: InventorySummary, updateAgent: ProductionAgentSecurityAPI["updateAgent"] = async () => { throw new Error("unused"); }): ProductionAgentSecurityAPI {
  const detail = { summary: value, sources: [], evidence: [] } as never;
  return {
    listAgents: async () => [value], listTools: async () => [value], listIdentities: async () => [], listRuntimes: async () => [],
    getAgent: async () => detail, getTool: async () => detail, getIdentity: async () => detail, getRuntime: async () => detail,
    getAgentCapabilities: async () => [], getAgentRelationships: async () => [], listAgentSessions: async () => [], updateAgent,
    getHomeSummary: async () => ({ agent_count: 1, high_risk_paths: 0, verified_changes: 0, blocked_changes: 0, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0, healthy: true, attention_required: false }),
  };
}

describe("inventory attribution", () => {
  it("shows where an agent lives, who found it and who created it, in the table and the drawer", async () => {
    const user = userEvent.setup();
    render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={agentsAPI(agent(full))} onNavigate={() => undefined} /></APIProvider>);
    const row = (await screen.findByRole("button", { name: "Open order-support-assistant" })).closest("tr")!;
    expect(screen.getByRole("columnheader", { name: "Location" })).toBeVisible();
    expect(within(row).getByText("AWS account 123456789012")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Open order-support-assistant" }));
    const section = await screen.findByRole("region", { name: "Location and creator" });
    expect(within(section).getByText("Location").nextElementSibling).toHaveTextContent("AWS account 123456789012");
    expect(within(section).getByText("Found by integration").nextElementSibling).toHaveTextContent("Production account");
    expect(within(section).getByText("Created by").nextElementSibling).toHaveTextContent("dana.reyes@example.com on 1 Oct 2026, 09:30 UTC, from the AWS CloudTrail create event");
    expect(within(section).getByText("Suggested owner").nextElementSibling).toHaveTextContent("dana.reyes@example.com, from the AWS CloudTrail create event. Not assigned yet.");
    expect(within(section).getByText("Suggested team").nextElementSibling).toHaveTextContent("Customer Platform, from the creator's department in Okta. Not assigned yet.");
    // A reader sees the suggestion and cannot assign it.
    expect(screen.queryByRole("button", { name: "Assign suggested owner" })).not.toBeInTheDocument();
  });

  it("fills the owner and team from the suggestion and saves them through the ownership save", async () => {
    const user = userEvent.setup();
    const value = agent(full);
    const updateAgent = vi.fn(async (_id: string, _version: number, input: { owner: string; team: string; tags: readonly string[] }) => ({ agent: { ...value, ...input, management_state: "managed" as const, version: 2, attribution: { ...full, suggested_owner: null, suggested_team: null } }, audit_id: ids.evidence }));
    render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={agentsAPI(value, updateAgent as never)} canWrite onNavigate={() => undefined} /></APIProvider>);
    await user.click(await screen.findByRole("button", { name: "Open order-support-assistant" }));
    expect(await screen.findByLabelText("Owner")).toHaveValue("");
    await user.click(screen.getByRole("button", { name: "Assign suggested owner" }));
    // Nothing is saved by the button: it fills the two fields.
    expect(updateAgent).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Owner")).toHaveValue("dana.reyes@example.com");
    expect(screen.getByLabelText("Team")).toHaveValue("Customer Platform");
    await user.click(screen.getByRole("button", { name: "Save ownership" }));
    await waitFor(() => expect(updateAgent).toHaveBeenCalledWith(ids.agent, 1, { owner: "dana.reyes@example.com", team: "Customer Platform", tags: [] }, expect.stringMatching(/^agent_/)));
    expect(await screen.findByText("dana.reyes@example.com · Customer Platform")).toBeVisible();
    // Once assigned there is no suggestion left to assign.
    await waitFor(() => expect(screen.queryByRole("button", { name: "Assign suggested owner" })).not.toBeInTheDocument());
  });

  it("leaves the team to the person when only an owner is suggested, and calls a CODEOWNERS owner a named owner", async () => {
    const user = userEvent.setup();
    const codeowners: Attribution = { location: { kind: "github_repository", id: "acme/alpha", label: "acme/alpha" }, integration: { id: ids.integration, name: "GitHub" }, creator: { identity: "@acme/platform", created_at: null, source: "codeowners" }, suggested_owner: { value: "@acme/platform", source: "codeowners" }, suggested_team: null };
    render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={agentsAPI(agent(codeowners, { provider: "github", source_kind: "github_agent_project", discovery: { method: "inferred", platform: "github_repository", signals: ["manifest:mcp_config"] } }))} canWrite onNavigate={() => undefined} /></APIProvider>);
    await user.click(await screen.findByRole("button", { name: "Open order-support-assistant" }));
    const section = await screen.findByRole("region", { name: "Location and creator" });
    expect(within(section).getByText("Named owner").nextElementSibling).toHaveTextContent("@acme/platform, from the repository's CODEOWNERS file");
    expect(within(section).queryByText("Created by")).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Team"), "typed-team");
    await user.click(screen.getByRole("button", { name: "Assign suggested owner" }));
    expect(screen.getByLabelText("Owner")).toHaveValue("@acme/platform");
    expect(screen.getByLabelText("Team")).toHaveValue("typed-team");
  });

  it("says plainly when the provider reports no creator, and shows the provider's name for an opaque tenant", async () => {
    const user = userEvent.setup();
    const tenant: Attribution = { location: { kind: "salesforce_org", id: "00D5g000004C9ACEA0", label: "Acme Sales" }, integration: { id: ids.integration, name: "Salesforce" }, creator: null, suggested_owner: null, suggested_team: null };
    render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={agentsAPI(agent(tenant, { provider: "salesforce", source_kind: "salesforce_agent", discovery: { method: "provider_api", platform: "agentforce", signals: [] } }))} canWrite onNavigate={() => undefined} /></APIProvider>);
    await user.click(await screen.findByRole("button", { name: "Open order-support-assistant" }));
    const section = await screen.findByRole("region", { name: "Location and creator" });
    expect(within(section).getByText("Location").nextElementSibling).toHaveTextContent("Salesforce org Acme Sales (00D5g000004C9ACEA0)");
    expect(within(section).getByText("Created by").nextElementSibling).toHaveTextContent("Not reported by the provider");
    expect(within(section).queryByText("Suggested owner")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Assign suggested owner" })).not.toBeInTheDocument();
  });

  it("shows the location of other inventory without a creator row, and nothing for a record without attribution", async () => {
    const user = userEvent.setup();
    const located: Attribution = { location: { kind: "kubernetes_namespace", id: "prod-us/tools", label: "prod-us/tools" }, integration: { id: ids.integration, name: "Cluster" }, creator: null, suggested_owner: null, suggested_team: null };
    const tool = agent(located, { id: ids.tool, name: "tickets-mcp", kind: "tool", provider: "kubernetes", source_kind: "kubernetes_mcp_server", discovery: { method: "provider_api", platform: "kubernetes_mcp_server", signals: [] }, management_state: "not_applicable", activity_state: "not_applicable" });
    const view = render(<APIProvider><ProductionAgentSecurityView path="/inventory/tools" api={agentsAPI(tool)} onNavigate={() => undefined} /></APIProvider>);
    await user.click(await screen.findByRole("button", { name: "Open tickets-mcp" }));
    const section = await screen.findByRole("region", { name: "Location and creator" });
    expect(within(section).getByText("Location").nextElementSibling).toHaveTextContent("Kubernetes namespace prod-us/tools");
    expect(within(section).queryByText("Created by")).not.toBeInTheDocument();
    view.unmount();
    expect(locationLabel(agent())).toBe("");
    render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={agentsAPI(agent())} onNavigate={() => undefined} /></APIProvider>);
    await user.click(await screen.findByRole("button", { name: "Open order-support-assistant" }));
    expect(await screen.findByText("Canonical record")).toBeVisible();
    expect(screen.queryByRole("region", { name: "Location and creator" })).not.toBeInTheDocument();
  });
});

describe("inventory attribution decoder", () => {
  it("accepts a summary with and without attribution", () => {
    expect(decodeInventorySummary(agent(full))).toEqual(agent(full));
    expect(decodeInventorySummary(agent())).toEqual(agent());
    const empty: Attribution = { location: null, integration: null, creator: null, suggested_owner: null, suggested_team: null };
    expect(decodeInventorySummary(agent(empty))).toEqual(agent(empty));
  });

  it.each([
    ["an unknown location kind", { ...full, location: { kind: "datacenter", id: "x", label: "x" } }],
    ["a location without a label", { ...full, location: { kind: "aws_account", id: "123456789012" } }],
    ["a creator that is free text", { ...full, creator: { ...full.creator, identity: "Dana Reyes (platform)" }, suggested_owner: null }],
    ["a creator source the product does not know", { ...full, creator: { ...full.creator, source: "guess" }, suggested_owner: null }],
    ["a suggested owner that is not the creator", { ...full, suggested_owner: { value: "someone.else@example.com", source: "cloudtrail" } }],
    ["a suggested owner without a creator", { ...full, creator: null }],
    ["a team source the product does not know", { ...full, suggested_team: { value: "Customer Platform", source: "guess" } }],
    ["a missing member", { location: full.location, integration: full.integration, creator: full.creator, suggested_owner: full.suggested_owner }],
    ["an extra member", { ...full, confidence: 1 }],
  ])("refuses %s", (_name, attribution) => {
    expect(() => decodeInventorySummary({ ...agent(), attribution })).toThrow("schema mismatch");
  });

  it("refuses a suggestion beside an assigned owner or team, and a creator on anything but an agent", () => {
    expect(() => decodeInventorySummary({ ...agent(full), owner: "Priya", management_state: "managed" })).toThrow("schema mismatch");
    expect(() => decodeInventorySummary({ ...agent({ ...full, suggested_owner: null }), owner: "Priya", team: "Risk", management_state: "managed" })).toThrow("schema mismatch");
    expect(decodeInventorySummary({ ...agent({ ...full, suggested_owner: null, suggested_team: null }), owner: "Priya", team: "Risk", management_state: "managed" }).owner).toBe("Priya");
    const tool = { ...agent(full), kind: "tool", discovery: { method: "provider_api", platform: "aws_mcp_server", signals: [] }, management_state: "not_applicable", activity_state: "not_applicable" };
    expect(() => decodeInventorySummary(tool)).toThrow("schema mismatch");
  });
});
