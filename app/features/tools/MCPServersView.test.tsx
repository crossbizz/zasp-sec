import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import { APIProductError } from "../../../apps/web/api/client";
import type { AgentAccess, MCPRegistryEntry, MCPServer } from "../../../apps/web/api/mcp-decoders";
import { APIProvider } from "../../api/APIProvider";
import { ProductionAgentSecurityView, type ProductionAgentSecurityAPI } from "../agents/ProductionAgentSecurityView";
import { AgentAccessPanel, createMCPInventoryAPI, MCPServersPanel, type MCPInventoryAPI } from "./MCPServersView";

const ids = { gateway: "pid_70000001-0000-4000-8000-000000000001", tracker: "pid_70000002-0000-4000-8000-000000000002", tool: "pid_70000003-0000-4000-8000-000000000003", agent: "pid_10000001-0000-4000-8000-000000000001", audit: "pid_60000001-0000-4000-8000-000000000001", principal: "pid_50000001-0000-4000-8000-000000000001" } as const;

const gateway: MCPServer = {
  id: ids.gateway, name: "tools", provider: "aws", source_kind: "aws_agentcore_gateway", source: "agentcore_gateway", transport: "http", endpoint_host: "gw-1.gateway.example", command: null, package: null, package_pinned: null, plain_http: false,
  auth: "none", identity: "host:gw-1.gateway.example", approval: "unapproved", tools: [{ id: ids.tool, name: "run_query", risk: "execute" }], tool_count: 3, agents: [{ id: ids.agent, name: "support" }], agent_count: 1,
  first_seen_at: "2026-08-19T01:00:00Z", last_seen_at: "2026-08-19T02:00:00Z",
};
const tracker: MCPServer = {
  ...gateway, id: ids.tracker, name: "tracker", provider: "github", source_kind: "github_mcp_server", source: "repository_config", transport: "stdio", endpoint_host: null, command: "npx", package: "@acme/tracker-mcp", package_pinned: false,
  auth: "not_applicable", identity: "package:@acme/tracker-mcp", approval: "blocked", tools: [], tool_count: 0, agents: [], agent_count: 0,
};
const access: AgentAccess = {
  agent_id: ids.agent,
  ai_actions: { window_days: 7, granted: ["bedrock:InvokeAgent", "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], used: ["bedrock:InvokeModel"], unused: ["bedrock:InvokeModelWithResponseStream"] },
  mcp_servers: [{ id: ids.gateway, name: "tools", identity: "host:gw-1.gateway.example", approval: "unapproved" }],
  data_stores: [{ id: "pid_70000004-0000-4000-8000-000000000004", name: "All DynamoDB tables", service: "dynamodb", access: "write", scope: "service" }],
  skills: [{ id: "pid_70000005-0000-4000-8000-000000000005", path: ".claude/skills/release", kind: "skill" }],
};

function entry(identity: string, status: MCPRegistryEntry["status"], version: number): MCPRegistryEntry {
  return { identity, status, note: "", version, updated_by: ids.principal, updated_at: "2026-08-19T03:00:00Z", server_count: 1, audit_id: ids.audit };
}

function fixtureAPI(overrides: Partial<MCPInventoryAPI> = {}): MCPInventoryAPI {
  return {
    listMCPServers: async () => [gateway, tracker],
    listMCPRegistry: async () => [{ ...entry(tracker.identity, "blocked", 4), audit_id: undefined }],
    putMCPRegistryEntry: async (identity, status, expectedVersion) => entry(identity, status, status === "unapproved" ? 0 : expectedVersion + 1),
    getAgentAccess: async () => access,
    ...overrides,
  };
}

describe("MCP servers", () => {
  it("lists each server with how it was found, its tools, its users and the registry's decision", async () => {
    render(<APIProvider><MCPServersPanel api={fixtureAPI()} canWrite={false} /></APIProvider>);
    const table = await screen.findByRole("table", { name: "MCP servers" });
    const gatewayRow = within(table).getByRole("row", { name: /host:gw-1\.gateway\.example/ });
    for (const text of ["tools", "AgentCore gateway", "https://gw-1.gateway.example", "None declared", "run_query · execute", "and 2 more", "support", "Unapproved"]) expect(gatewayRow).toHaveTextContent(text);
    const trackerRow = within(table).getByRole("row", { name: /package:@acme\/tracker-mcp/ });
    for (const text of ["tracker", "Repository configuration", "npx @acme/tracker-mcp (no version)", "Local process", "Not listed", "No agent", "Blocked"]) expect(trackerRow).toHaveTextContent(text);
    expect(screen.getByText("2 found · 1 unapproved in use")).toBeVisible();
    // Reading is not deciding.
    expect(screen.queryByRole("button", { name: "Approve tools" })).toBeNull();
  });

  it("saves a decision under the version last read and shows it", async () => {
    const user = userEvent.setup();
    const put = vi.fn(async (identity: string, status: "approved" | "blocked" | "unapproved", expectedVersion: number) => entry(identity, status, status === "unapproved" ? 0 : expectedVersion + 1));
    render(<APIProvider><MCPServersPanel api={fixtureAPI({ putMCPRegistryEntry: put })} canWrite /></APIProvider>);
    await user.click(await screen.findByRole("button", { name: "Approve tools" }));
    await waitFor(() => expect(screen.getByRole("row", { name: /host:gw-1/ })).toHaveTextContent("Approved"));
    // The gateway had no decision (version 0); the blocked package was read at version 4.
    await user.click(screen.getByRole("button", { name: "Clear the decision for tracker" }));
    await waitFor(() => expect(screen.getByRole("row", { name: /package:@acme/ })).toHaveTextContent("Unapproved"));
    // A second decision for the gateway carries the version the first one returned.
    await user.click(screen.getByRole("button", { name: "Block tools" }));
    await waitFor(() => expect(screen.getByRole("row", { name: /host:gw-1/ })).toHaveTextContent("Blocked"));
    expect(put.mock.calls.map((call) => call.slice(0, 3))).toEqual([["host:gw-1.gateway.example", "approved", 0], ["package:@acme/tracker-mcp", "unapproved", 4], ["host:gw-1.gateway.example", "blocked", 1]]);
  });

  it("says when a decision changed elsewhere and keeps what the registry says", async () => {
    const user = userEvent.setup();
    const put = vi.fn(async () => { throw new APIProductError(409, { code: "version_conflict", message: "Resource version conflict", correlation_id: ids.audit, retryable: false }); });
    render(<APIProvider><MCPServersPanel api={fixtureAPI({ putMCPRegistryEntry: put })} canWrite /></APIProvider>);
    await user.click(await screen.findByRole("button", { name: "Approve tools" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The decision changed elsewhere");
    expect(screen.getByRole("row", { name: /host:gw-1/ })).toHaveTextContent("Unapproved");
  });

  it("sends the exact requests of the contract", async () => {
    const get = vi.fn(async (path: string) => ({
      data: path === "/api/v1/mcp-servers" ? { items: [gateway], page_info: { next_cursor: null, has_more: false } } : path === "/api/v1/mcp-registry" ? { items: [] } : access,
      response: new Response(null, { status: 200 }),
    }));
    const put = vi.fn(async () => ({ data: entry(gateway.identity, "approved", 1), response: new Response(null, { status: 200, headers: { "X-Audit-ID": ids.audit } }) }));
    const api = createMCPInventoryAPI({ GET: get, PUT: put } as unknown as APIClient);
    await expect(api.listMCPServers()).resolves.toEqual([gateway]);
    await expect(api.listMCPRegistry()).resolves.toEqual([]);
    await expect(api.getAgentAccess(ids.agent)).resolves.toEqual(access);
    await expect(api.putMCPRegistryEntry(gateway.identity, "approved", 0)).resolves.toEqual(entry(gateway.identity, "approved", 1));
    expect(get.mock.calls.map((call) => call[0])).toEqual(["/api/v1/mcp-servers", "/api/v1/mcp-registry", "/api/v1/agents/{id}/access"]);
    expect(put).toHaveBeenCalledWith("/api/v1/mcp-registry", { params: { header: { "X-CSRF-Token": "" } }, body: { identity: gateway.identity, status: "approved", note: "", expected_version: 0 }, signal: undefined });
    // An answer for another identity, or without its audit header, is refused.
    put.mockResolvedValueOnce({ data: entry("host:other.example", "approved", 1), response: new Response(null, { status: 200, headers: { "X-Audit-ID": ids.audit } }) });
    await expect(api.putMCPRegistryEntry(gateway.identity, "approved", 0)).rejects.toThrow("Registry decision omitted exact evidence");
    put.mockResolvedValueOnce({ data: entry(gateway.identity, "approved", 1), response: new Response(null, { status: 200 }) });
    await expect(api.putMCPRegistryEntry(gateway.identity, "approved", 0)).rejects.toThrow("Registry decision omitted exact evidence");
  });
});

describe("agent access", () => {
  it("shows used against granted, MCP servers, data stores and skills", async () => {
    render(<AgentAccessPanel api={fixtureAPI()} agentID={ids.agent} />);
    expect(await screen.findByText("3 granted · 1 used in the last 7 days · 1 unused")).toBeVisible();
    const granted = within(screen.getByRole("list", { name: "Granted model permissions" }));
    expect(granted.getByText(/bedrock:InvokeModelWithResponseStream/).closest("li")).toHaveTextContent("granted, not used");
    expect(granted.getByText("bedrock:InvokeModel").closest("li")).toHaveTextContent("used");
    // An action the audit log cannot show is not called unused.
    expect(granted.getByText("bedrock:InvokeAgent").closest("li")).toHaveTextContent("granted, use not recorded by the audit log");
    expect(screen.getByRole("list", { name: "MCP servers of the agent" })).toHaveTextContent("tools · host:gw-1.gateway.example · Unapproved");
    expect(screen.getByRole("list", { name: "Data stores of the agent" })).toHaveTextContent("All DynamoDB tables · dynamodb · read and write · every resource of the service");
    expect(screen.getByRole("list", { name: "Skills of the agent" })).toHaveTextContent(".claude/skills/release · Skill");
  });

  it("says when the audit log was not read instead of showing zero", async () => {
    render(<AgentAccessPanel api={fixtureAPI({ getAgentAccess: async () => ({ ...access, ai_actions: null, mcp_servers: [], data_stores: [], skills: [] }) })} agentID={ids.agent} />);
    expect(await screen.findByText(/audit log of this agent's role was not read/)).toBeVisible();
    expect(screen.getByText("No MCP server use was found.")).toBeVisible();
  });
});

describe("Tools & MCP page", () => {
  it("shows the MCP servers above the tools, and an agent's access in its detail", async () => {
    const user = userEvent.setup();
    const summary = { id: ids.agent, name: "support", kind: "agent" as const, owner: "", team: "", tags: [], evidence_id: "pid_20000001-0000-4000-8000-000000000001", confidence_basis_points: 9500, first_seen: "2026-08-19T00:00:00Z", last_seen: "2026-08-19T01:00:00Z", observed_at: "2026-08-19T01:00:00Z", fresh_until: "2026-08-19T01:15:00Z", freshness_state: "fresh" as const, provider: "aws" as const, source_kind: "aws_bedrock_agent", discovery: { method: "provider_api" as const, platform: "bedrock_agent", signals: [] }, management_state: "unmanaged" as const, activity_state: "unknown" as const, last_activity_at: null, version: 1 };
    const detail = { summary, sources: [], evidence: [] } as unknown as Awaited<ReturnType<ProductionAgentSecurityAPI["getAgent"]>>;
    const api: ProductionAgentSecurityAPI = {
      listAgents: async () => [summary], listTools: async () => [], listIdentities: async () => [], listRuntimes: async () => [],
      getAgent: async () => detail, getTool: async () => { throw new Error("unused"); }, getIdentity: async () => { throw new Error("unused"); }, getRuntime: async () => { throw new Error("unused"); },
      getAgentCapabilities: async () => [], getAgentRelationships: async () => [], listAgentSessions: async () => [],
      updateAgent: async () => { throw new Error("unused"); }, getHomeSummary: async () => { throw new Error("unused"); },
    };
    const tools = render(<APIProvider><ProductionAgentSecurityView path="/inventory/tools" api={api} mcpAPI={fixtureAPI()} onNavigate={() => undefined} /></APIProvider>);
    expect(await screen.findByRole("table", { name: "MCP servers" })).toBeVisible();
    tools.unmount();
    render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={api} mcpAPI={fixtureAPI()} onNavigate={() => undefined} /></APIProvider>);
    await user.click(await screen.findByRole("button", { name: "Open support" }));
    expect(await screen.findByText("3 granted · 1 used in the last 7 days · 1 unused")).toBeVisible();
  });
});
