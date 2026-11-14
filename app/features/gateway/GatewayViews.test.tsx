import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { GatewayDecision, GatewayPolicy, GatewayPolicyInput, MCPGatewayServer, MCPGatewayServerInput } from "../../../apps/web/api/gateway-decoders";
import { GUARDRAIL_RULE_IDS, type GuardrailPolicy } from "../../../apps/web/api/decoders";
import { APIProvider } from "../../api/APIProvider";
import { ProductionGuardrailsView } from "../guardrails/ProductionGuardrailsView";
import { createGatewayAPI, GatewayConflict, type GatewayAPI } from "./gateway-api";
import { GatewayActivityCard, GatewayPolicyCard, GatewayServersPanel, HostedGatewaySetupCard } from "./GatewayViews";

const environmentID = "pid_10000003-0000-4000-8000-000000000003";
const serverID = "pid_61000001-0000-4000-8000-000000000001";
const principalID = "pid_50000001-0000-4000-8000-000000000001";

function policy(version: number, changed: Partial<GatewayPolicy> = {}): GatewayPolicy {
  return { environment_id: environmentID, unapproved_servers: "allow", denied_tool_risks: [], requests_per_minute: 600, version, updated_at: version === 0 ? null : "2026-11-14T10:00:00.000000Z", gateway_enabled: true, ...changed };
}

function server(changed: Partial<MCPGatewayServer> = {}): MCPGatewayServer {
  return {
    id: serverID, name: "Tickets", upstream_url: "https://mcp.tickets.test/mcp", upstream_host: "mcp.tickets.test", gateway_path: `/api/v1/gateway/mcp/${serverID}`, identity: "host:mcp.tickets.test", approval: "approved", enabled: true,
    allowed_tools: [], denied_tools: ["delete_ticket"], tools: [{ name: "run_report", risk: "execute", last_seen_at: "2026-11-14T10:00:00.000000Z" }, { name: "search_tickets", risk: "read", last_seen_at: "2026-11-14T10:00:00.000000Z" }], tool_count: 2,
    last_activity_at: "2026-11-14T10:05:00.000000Z", version: 2, created_at: "2026-11-14T09:00:00.000000Z", updated_at: "2026-11-14T10:00:00.000000Z", ...changed,
  };
}

function decision(n: number, changed: Partial<GatewayDecision> = {}): GatewayDecision {
  return {
    id: `pid_6200000${n}-0000-4000-8000-00000000000${n}`, created_at: `2026-11-14T10:0${9 - n}:00.000000Z`, surface: "mcp", operation: "tools/call", direction: "response", decision: "block", reason: "guardrail",
    rules: [{ id: "injection.instruction_override", category: "prompt_injection", mode: "block", count: 1 }], bytes: 412, content_digest: `sha256:${"ab".repeat(32)}`, server_id: serverID, server_name: "Tickets",
    tool_name: "read_page", provider: null, model: null, agent_id: "support-agent", principal_id: principalID, ...changed,
  };
}

function fixtureAPI(overrides: Partial<GatewayAPI> = {}): GatewayAPI {
  return {
    getPolicy: async () => policy(0),
    savePolicy: async (input: GatewayPolicyInput, version: number) => policy(version + 1, input),
    listServers: async () => ({ items: [server()], gateway_enabled: true }),
    saveServer: async (id: string, input: MCPGatewayServerInput, version: number) => server({ id, gateway_path: `/api/v1/gateway/mcp/${id}`, name: input.name, upstream_url: input.upstream_url, enabled: input.enabled, allowed_tools: input.allowed_tools, denied_tools: input.denied_tools, version: version + 1 }),
    removeServer: async () => undefined,
    listActivity: async () => ({ items: [], next_cursor: null }),
    ...overrides,
  };
}

function response(status: number, body: unknown, headers: Record<string, string> = {}) {
  const result = new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
  return status < 400 ? { data: body, response: result } : { error: body, response: result };
}

describe("Hosted gateway policy", () => {
  it("edits the policy and saves it as a whole against the loaded version", async () => {
    const user = userEvent.setup();
    const savePolicy = vi.fn(fixtureAPI().savePolicy);
    render(<GatewayPolicyCard api={fixtureAPI({ savePolicy })} canWrite />);
    expect(await screen.findByText("Defaults")).toBeInTheDocument();
    const save = screen.getByRole("button", { name: "Save gateway policy" });
    expect(save).toBeDisabled();
    await user.selectOptions(screen.getByLabelText("MCP servers the registry has no decision for"), "refuse");
    await user.click(screen.getByLabelText(/Execute \(runs code or commands\)/));
    await user.click(screen.getByLabelText(/Write \(changes something\)/));
    const rate = screen.getByLabelText("Requests a minute for one token (0 is no limit)");
    await user.clear(rate);
    // A rate that is not a whole number in range cannot be saved.
    await user.type(rate, "12x");
    expect(save).toBeDisabled();
    expect(screen.getByText("Enter a whole number from 0 to 100000")).toBeInTheDocument();
    await user.clear(rate);
    await user.type(rate, "120");
    await user.click(save);
    await waitFor(() => expect(savePolicy).toHaveBeenCalledWith({ unapproved_servers: "refuse", denied_tool_risks: ["execute", "write"], requests_per_minute: 120 }, 0));
    expect(await screen.findByRole("status")).toHaveTextContent("Gateway policy saved as version 1.");
    expect(screen.getByText("Version 1")).toBeInTheDocument();
    expect(save).toBeDisabled();
  });

  it("shows the other person's policy after a conflict and applies nothing of the draft", async () => {
    const user = userEvent.setup();
    const getPolicy = vi.fn().mockResolvedValueOnce(policy(2)).mockResolvedValueOnce(policy(3, { unapproved_servers: "refuse" }));
    render(<GatewayPolicyCard api={fixtureAPI({ getPolicy, savePolicy: async () => { throw new GatewayConflict(); } })} canWrite />);
    await screen.findByText("Version 2");
    await user.click(screen.getByLabelText(/^Read$/));
    await user.click(screen.getByRole("button", { name: "Save gateway policy" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("changed by someone else");
    expect(screen.getByText("Version 3")).toBeInTheDocument();
    expect(screen.getByLabelText("MCP servers the registry has no decision for")).toHaveValue("refuse");
    expect(screen.getByLabelText(/^Read$/)).not.toBeChecked();
  });

  it("is read-only without write access, and says when the deployment does not host the gateway", async () => {
    render(<GatewayPolicyCard api={fixtureAPI({ getPolicy: async () => policy(1, { gateway_enabled: false, denied_tool_risks: ["execute"] }) })} canWrite={false} />);
    expect(await screen.findByText(/This deployment does not host the gateway's traffic routes/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save gateway policy" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("MCP servers the registry has no decision for")).toBeDisabled();
    expect(screen.getByLabelText(/Execute \(runs code or commands\)/)).toBeChecked();
    expect(screen.getByText(/Changing it needs permission to manage workflows/)).toBeInTheDocument();
  });

  it("offers a retry when the policy cannot be read", async () => {
    const user = userEvent.setup();
    const getPolicy = vi.fn().mockRejectedValueOnce(new Error("offline")).mockResolvedValueOnce(policy(0));
    render(<GatewayPolicyCard api={fixtureAPI({ getPolicy })} canWrite />);
    expect(await screen.findByRole("alert")).toHaveTextContent("The gateway policy is unavailable.");
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("Defaults")).toBeInTheDocument();
  });
});

describe("MCP servers behind the hosted gateway", () => {
  it("lists a server with the address for the agent, its registry decision and the tools seen", async () => {
    render(<GatewayServersPanel api={fixtureAPI()} canWrite origin="https://zasp.example" />);
    const table = await screen.findByRole("table", { name: "Gateway MCP servers" });
    const row = within(table).getAllByRole("row")[1];
    expect(within(row).getByText(`https://zasp.example/api/v1/gateway/mcp/${serverID}`)).toBeInTheDocument();
    expect(within(row).getByText("https://mcp.tickets.test/mcp")).toBeInTheDocument();
    expect(within(row).getByText("Approved")).toBeInTheDocument();
    expect(within(row).getByText("run_report · execute")).toBeInTheDocument();
    expect(within(row).getByText("Never: delete_ticket")).toBeInTheDocument();
    expect(within(row).getByText("2026-11-14T10:05:00.000000Z")).toBeInTheDocument();
  });

  it("registers a server and shows the gateway address to paste, without asking for a credential", async () => {
    const user = userEvent.setup();
    const saveServer = vi.fn(fixtureAPI().saveServer);
    render(<GatewayServersPanel api={fixtureAPI({ listServers: async () => ({ items: [], gateway_enabled: true }), saveServer })} canWrite origin="https://zasp.example" />);
    expect(await screen.findByText("No MCP server is registered behind the gateway.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Register a server" }));
    const form = screen.getByRole("group", { name: "Register an MCP server" });
    expect(within(form).queryByLabelText(/token|secret|password|credential/i)).not.toBeInTheDocument();
    const register = within(form).getByRole("button", { name: "Register" });
    await user.type(within(form).getByLabelText("Name"), "CRM");
    // An address with a key in its query is refused before it is sent.
    await user.type(within(form).getByLabelText("Server address (https)"), "https://mcp.crm.test/mcp?key=abc");
    expect(register).toBeDisabled();
    expect(within(form).getByText(/The server's token is not entered here/)).toBeInTheDocument();
    await user.clear(within(form).getByLabelText("Server address (https)"));
    await user.type(within(form).getByLabelText("Server address (https)"), "http://mcp.crm.test/mcp");
    expect(register).toBeDisabled();
    await user.clear(within(form).getByLabelText("Server address (https)"));
    await user.type(within(form).getByLabelText("Server address (https)"), "https://mcp.crm.test/mcp");
    await user.type(within(form).getByLabelText("These tools may never be called"), "delete_account, export_all");
    await user.type(within(form).getByLabelText("Only these tools may be called (empty: every tool)"), "delete_account");
    expect(within(form).getByText("A tool cannot be on both lists.")).toBeInTheDocument();
    await user.clear(within(form).getByLabelText("Only these tools may be called (empty: every tool)"));
    await user.click(register);
    await waitFor(() => expect(saveServer).toHaveBeenCalledTimes(1));
    const [id, input, version] = saveServer.mock.calls[0];
    expect(id).toMatch(/^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(input).toEqual({ name: "CRM", upstream_url: "https://mcp.crm.test/mcp", enabled: true, allowed_tools: [], denied_tools: ["delete_account", "export_all"] });
    expect(version).toBe(0);
    expect(await screen.findByRole("status")).toHaveTextContent(`CRM is registered. Put https://zasp.example/api/v1/gateway/mcp/${id} in the agent's MCP configuration`);
  });

  it("changes and removes a server against the version it shows", async () => {
    const user = userEvent.setup();
    const saveServer = vi.fn(fixtureAPI().saveServer);
    const removeServer = vi.fn(async () => undefined);
    render(<GatewayServersPanel api={fixtureAPI({ saveServer, removeServer })} canWrite origin="https://zasp.example" />);
    await user.click(await screen.findByRole("button", { name: "Change Tickets" }));
    const form = screen.getByRole("group", { name: "Change the MCP server" });
    expect(within(form).getByLabelText("Server address (https)")).toHaveValue("https://mcp.tickets.test/mcp");
    await user.click(within(form).getByLabelText(/Enabled/));
    await user.click(within(form).getByRole("button", { name: "Save server" }));
    await waitFor(() => expect(saveServer).toHaveBeenCalledWith(serverID, { name: "Tickets", upstream_url: "https://mcp.tickets.test/mcp", enabled: false, allowed_tools: [], denied_tools: ["delete_ticket"] }, 2));
    await user.click(await screen.findByRole("button", { name: "Remove Tickets" }));
    await waitFor(() => expect(removeServer).toHaveBeenCalledWith(serverID, 2));
    expect(await screen.findByRole("status")).toHaveTextContent("Its decision records are kept.");
  });

  it("is read-only without write access and says when the gateway is not hosted", async () => {
    render(<GatewayServersPanel api={fixtureAPI({ listServers: async () => ({ items: [server()], gateway_enabled: false }) })} canWrite={false} />);
    await screen.findByRole("table", { name: "Gateway MCP servers" });
    expect(screen.getByText(/does not host the gateway's traffic routes yet/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Register a server" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove Tickets" })).not.toBeInTheDocument();
  });
});

describe("Gateway activity", () => {
  it("shows decisions without any text, filters them and loads older ones", async () => {
    const user = userEvent.setup();
    const model = decision(2, { surface: "llm", operation: "chat.completions", direction: "request", decision: "redact", rules: [{ id: "pii.email", category: "sensitive_data", mode: "redact", count: 2 }], server_id: null, server_name: null, tool_name: null, provider: "openai", model: "gpt-test" });
    const listActivity = vi.fn(async (filter: { before?: string; decision?: string }) => filter.before ? { items: [decision(3, { decision: "allow", reason: "none", rules: [] })], next_cursor: null }
      : filter.decision === "block" ? { items: [decision(1)], next_cursor: null } : { items: [decision(1), model], next_cursor: model.id });
    render(<GatewayActivityCard api={fixtureAPI({ listActivity })} />);
    const table = await screen.findByRole("table", { name: "Gateway activity" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(within(rows[1]).getByText("Tickets · read_page")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Guardrail rule")).toBeInTheDocument();
    expect(within(rows[1]).getByText("injection.instruction_override ×1 (block)")).toBeInTheDocument();
    expect(within(rows[2]).getByText("openai · gpt-test")).toBeInTheDocument();
    expect(within(rows[2]).getByText("pii.email ×2 (redact)")).toBeInTheDocument();
    expect(within(rows[1]).getByTitle(`sha256:${"ab".repeat(32)}`)).toHaveTextContent("412 bytes");
    await user.click(screen.getByRole("button", { name: "Load older decisions" }));
    await waitFor(() => expect(within(screen.getByRole("table", { name: "Gateway activity" })).getAllByRole("row")).toHaveLength(4));
    expect(listActivity).toHaveBeenLastCalledWith({ limit: 25, before: model.id });
    expect(screen.queryByRole("button", { name: "Load older decisions" })).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Decision"), "block");
    await waitFor(() => expect(listActivity).toHaveBeenLastCalledWith({ decision: "block", limit: 25 }, expect.anything()));
    await waitFor(() => expect(within(screen.getByRole("table", { name: "Gateway activity" })).getAllByRole("row")).toHaveLength(2));
  });

  it("says when nothing was recorded and when activity cannot be read", async () => {
    const { unmount } = render(<GatewayActivityCard api={fixtureAPI()} />);
    expect(await screen.findByText(/No decision was recorded\. Decisions appear here once an agent sends traffic/)).toBeInTheDocument();
    unmount();
    render(<GatewayActivityCard api={fixtureAPI({ listActivity: async () => { throw new Error("offline"); } })} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Gateway activity is unavailable.");
  });
});

describe("Hosted gateway on the Guardrails page", () => {
  it("shows the gateway's policy, the setup and the activity beside the guardrail rules", async () => {
    const guardrails: GuardrailPolicy = { environment_id: environmentID, version: 0, updated_at: null, rules: GUARDRAIL_RULE_IDS.map((id) => {
      const injection = id.startsWith("injection.");
      return { id, category: injection ? "prompt_injection" as const : "sensitive_data" as const, description: `Matches ${id}`, mode: injection ? "block" as const : "redact" as const, default_mode: injection ? "block" as const : "redact" as const, redactable: !injection };
    }) };
    const onNavigate = vi.fn();
    const user = userEvent.setup();
    render(<APIProvider client={{} as APIClient}><ProductionGuardrailsView canWrite api={{ getPolicy: async () => guardrails, savePolicy: async () => guardrails }} gatewayAPI={fixtureAPI()} origin="https://zasp.example" onNavigate={onNavigate} /></APIProvider>);
    expect(await screen.findByRole("heading", { name: "Hosted gateway policy" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Gateway activity" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Route an agent through the hosted gateway" })).toBeInTheDocument();
    // The setup names the two addresses and the headers, and nothing to install.
    expect(screen.getByLabelText("MCP configuration example")).toHaveTextContent("https://zasp.example/api/v1/gateway/mcp/<gateway server id>");
    expect(screen.getByLabelText("MCP configuration example")).toHaveTextContent("X-Zasp-Upstream-Authorization");
    expect(screen.getByLabelText("Model SDK configuration example")).toHaveTextContent("https://zasp.example/api/v1/gateway/llm/v1");
    expect(screen.getByText(/Nothing is installed in your environment\./)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "MCP servers" }));
    expect(onNavigate).toHaveBeenCalledWith("/inventory/tools");
  });

  it("renders the setup without navigation", () => {
    render(<HostedGatewaySetupCard origin="https://zasp.example" />);
    expect(screen.getByText(/Administration, API Access/)).toBeInTheDocument();
  });
});

describe("gateway API client", () => {
  const policyBody = policy(4, { unapproved_servers: "refuse" });
  it("reads and saves the policy with its version, and reports a conflict", async () => {
    const GET = vi.fn(async () => response(200, policy(3), { ETag: '"3"', "Cache-Control": "no-store" }));
    const PUT = vi.fn(async () => response(200, policyBody, { ETag: '"4"', "Cache-Control": "no-store" }));
    const api = createGatewayAPI({ GET, PUT } as unknown as APIClient);
    expect((await api.getPolicy()).version).toBe(3);
    const saved = await api.savePolicy({ unapproved_servers: "refuse", denied_tool_risks: [], requests_per_minute: 600 }, 3);
    expect(saved.version).toBe(4);
    const [path, options] = PUT.mock.calls[0] as unknown as [string, { params: { header: Record<string, string> }; body: unknown }];
    expect(path).toBe("/api/v1/gateway/policy");
    expect(options.params.header["If-Match"]).toBe('"3"');
    expect(options.params.header["Idempotency-Key"]).toMatch(/^[A-Za-z0-9_-]{16,}$/);
    expect(options.body).toEqual({ unapproved_servers: "refuse", denied_tool_risks: [], requests_per_minute: 600 });
    // A saved policy that is not the one sent is not accepted.
    await expect(api.savePolicy({ unapproved_servers: "allow", denied_tool_risks: [], requests_per_minute: 600 }, 3)).rejects.toThrow("different policy");
    PUT.mockResolvedValueOnce(response(409, { code: "operation_conflict", message: "Operation conflicted", correlation_id: principalID, retryable: false }) as never);
    await expect(api.savePolicy({ unapproved_servers: "refuse", denied_tool_risks: [], requests_per_minute: 600 }, 3)).rejects.toBeInstanceOf(GatewayConflict);
    GET.mockResolvedValueOnce(response(200, policy(3), { ETag: '"2"', "Cache-Control": "no-store" }) as never);
    await expect(api.getPolicy()).rejects.toThrow("invalid version metadata");
  });

  it("registers, removes and lists with exact evidence", async () => {
    const created = server({ version: 1 });
    const PUT = vi.fn(async () => response(201, created, { ETag: '"1"' }));
    const DELETE = vi.fn(async () => response(204, undefined));
    const GET = vi.fn(async (path: string) => path === "/api/v1/gateway/activity" ? response(200, { items: [decision(1)], next_cursor: null }) : response(200, { items: [created], gateway_enabled: true }));
    const api = createGatewayAPI({ GET, PUT, DELETE } as unknown as APIClient);
    const input = { name: "Tickets", upstream_url: "https://mcp.tickets.test/mcp", enabled: true, allowed_tools: [], denied_tools: ["delete_ticket"] };
    expect((await api.saveServer(serverID, input, 0)).gateway_path).toBe(`/api/v1/gateway/mcp/${serverID}`);
    const [path, options] = PUT.mock.calls[0] as unknown as [string, { params: { path: { id: string }; header: Record<string, string> } }];
    expect(path).toBe("/api/v1/gateway/mcp-servers/{id}");
    expect(options.params.path.id).toBe(serverID);
    expect(options.params.header["If-Match"]).toBe('"0"');
    await expect(api.saveServer(serverID, { ...input, name: "Other" }, 0)).rejects.toThrow("different server");
    await api.removeServer(serverID, 1);
    expect((DELETE.mock.calls[0] as unknown as [string, { params: { header: Record<string, string> } }])[1].params.header["If-Match"]).toBe('"1"');
    await expect(api.removeServer(serverID, 0)).rejects.toThrow("Invalid gateway version");
    expect((await api.listServers()).items).toHaveLength(1);
    expect((await api.listActivity({ surface: "mcp", serverID, agentID: "support-agent", limit: 10 })).items).toHaveLength(1);
    expect((GET.mock.calls.at(-1) as unknown as [string, { params: { query: unknown } }])[1].params.query).toEqual({ limit: 10, surface: "mcp", server_id: serverID, agent_id: "support-agent" });
    GET.mockResolvedValueOnce(response(200, { items: [decision(1), decision(2)], next_cursor: null }) as never);
    await expect(api.listActivity({ limit: 1 })).rejects.toThrow("more records than asked for");
  });
});
