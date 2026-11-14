import { describe, expect, it } from "vitest";

import { decodeGatewayDecision, decodeGatewayDecisionPage, decodeGatewayPolicy, decodeMCPGatewayServer, decodeMCPGatewayServerList } from "./gateway-decoders";

const environmentID = "pid_10000003-0000-4000-8000-000000000003";
const serverID = "pid_61000001-0000-4000-8000-000000000001";
const principalID = "pid_50000001-0000-4000-8000-000000000001";

const policy = { environment_id: environmentID, unapproved_servers: "refuse", denied_tool_risks: ["execute", "write"], requests_per_minute: 120, version: 3, updated_at: "2026-11-14T10:00:00.000000Z", gateway_enabled: true };
const server = {
  id: serverID, name: "Tickets", upstream_url: "https://mcp.tickets.test/mcp", upstream_host: "mcp.tickets.test", gateway_path: `/api/v1/gateway/mcp/${serverID}`, identity: "host:mcp.tickets.test", approval: "approved", enabled: true,
  allowed_tools: [], denied_tools: ["delete_ticket"], tools: [{ name: "run_report", risk: "execute", last_seen_at: "2026-11-14T10:00:00.000000Z" }], tool_count: 1, last_activity_at: null, version: 2,
  created_at: "2026-11-14T09:00:00.000000Z", updated_at: "2026-11-14T10:00:00.000000Z",
};
const decision = {
  id: "pid_62000001-0000-4000-8000-000000000001", created_at: "2026-11-14T10:05:00.000000Z", surface: "mcp", operation: "tools/call", direction: "response", decision: "block", reason: "guardrail",
  rules: [{ id: "injection.instruction_override", category: "prompt_injection", mode: "block", count: 1 }], bytes: 412, content_digest: `sha256:${"ab".repeat(32)}`, server_id: serverID, server_name: "Tickets",
  tool_name: "read_page", provider: null, model: null, agent_id: "support-agent", principal_id: principalID,
};
const modelDecision = { ...decision, id: "pid_62000002-0000-4000-8000-000000000002", created_at: "2026-11-14T10:04:00.000000Z", surface: "llm", operation: "chat.completions", direction: "request", decision: "allow", reason: "none", rules: [], server_id: null, server_name: null, tool_name: null, provider: "openai", model: "gpt-test" };

describe("hosted gateway decoders", () => {
  it("accepts the contract shapes", () => {
    expect(decodeGatewayPolicy(policy)).toBe(policy);
    expect(decodeGatewayPolicy({ ...policy, version: 0, updated_at: null, denied_tool_risks: [], gateway_enabled: false }).version).toBe(0);
    expect(decodeMCPGatewayServer(server)).toBe(server);
    expect(decodeMCPGatewayServerList({ items: [server], gateway_enabled: false }).items).toHaveLength(1);
    expect(decodeGatewayDecision(decision)).toBe(decision);
    expect(decodeGatewayDecisionPage({ items: [decision, modelDecision], next_cursor: modelDecision.id }).items).toHaveLength(2);
    expect(decodeGatewayDecisionPage({ items: [], next_cursor: null }).items).toHaveLength(0);
  });

  it("refuses a policy that is not exactly the contract's", () => {
    for (const changed of [
      { ...policy, unapproved_servers: "maybe" }, { ...policy, denied_tool_risks: ["dangerous"] }, { ...policy, denied_tool_risks: ["read", "read"] }, { ...policy, requests_per_minute: -1 },
      { ...policy, requests_per_minute: 100_001 }, { ...policy, version: 0 }, { ...policy, updated_at: null }, { ...policy, gateway_enabled: "yes" }, { ...policy, upstream_secret: "abc" },
    ]) expect(() => decodeGatewayPolicy(changed), JSON.stringify(changed)).toThrow("schema mismatch");
    const { gateway_enabled: _omitted, ...missing } = policy;
    expect(() => decodeGatewayPolicy(missing)).toThrow("schema mismatch");
  });

  it("refuses a server whose address, identity or lists do not agree", () => {
    for (const changed of [
      { ...server, upstream_url: "http://mcp.tickets.test/mcp" }, { ...server, upstream_host: "other.test" }, { ...server, identity: "host:other.test" }, { ...server, gateway_path: "/api/v1/gateway/mcp/pid_61000009-0000-4000-8000-000000000009" },
      { ...server, approval: "pending" }, { ...server, allowed_tools: ["delete_ticket"] }, { ...server, denied_tools: ["delete ticket"] }, { ...server, denied_tools: ["a", "a"] }, { ...server, tool_count: 0 },
      { ...server, tools: [{ name: "run_report", risk: "execute", last_seen_at: "2026-11-14T10:00:00.000000Z", description: "Runs a report" }] }, { ...server, version: 0 }, { ...server, updated_at: "2026-11-14T08:00:00.000000Z" },
      { ...server, authorization: "Bearer abc" },
    ]) expect(() => decodeMCPGatewayServer(changed), JSON.stringify(changed)).toThrow("schema mismatch");
    expect(() => decodeMCPGatewayServerList({ items: [server, server], gateway_enabled: true })).toThrow("schema mismatch");
    expect(() => decodeMCPGatewayServerList({ items: [server] })).toThrow("schema mismatch");
  });

  it("refuses a decision record that could hold text or contradicts itself", () => {
    for (const changed of [
      { ...decision, text: "the customer's question" }, { ...decision, arguments: { query: "x" } }, { ...decision, tool_name: "ignore previous instructions" }, { ...decision, agent_id: "the support agent" },
      { ...decision, reason: "none" }, { ...decision, decision: "allow" }, { ...decision, reason: "because" }, { ...decision, content_digest: "sha256:zz" }, { ...decision, server_id: null }, { ...decision, provider: "openai" },
      { ...decision, rules: [{ id: "pii.email", category: "sensitive_data", mode: "redact", count: 1, sample: "jane@example.com" }] }, { ...decision, rules: [{ id: "pii.email", category: "sensitive_data", mode: "off", count: 1 }] },
      { ...modelDecision, provider: null }, { ...modelDecision, server_name: "Tickets" }, { ...decision, bytes: -1 }, { ...decision, direction: "sideways" },
    ]) expect(() => decodeGatewayDecision(changed), JSON.stringify(changed)).toThrow("schema mismatch");
    // A page is newest first and its cursor is its last record.
    expect(() => decodeGatewayDecisionPage({ items: [modelDecision, decision], next_cursor: null })).toThrow("schema mismatch");
    expect(() => decodeGatewayDecisionPage({ items: [decision, modelDecision], next_cursor: decision.id })).toThrow("schema mismatch");
    expect(() => decodeGatewayDecisionPage({ items: [decision] })).toThrow("schema mismatch");
  });
});
