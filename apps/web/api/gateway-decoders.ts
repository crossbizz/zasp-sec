import type { components } from "./generated";

// The hosted gateway, exactly as the API answers it: the gateway policy, the
// MCP servers registered behind the gateway and the decision records.

export type GatewayPolicy = components["schemas"]["GatewayPolicy"];
export type GatewayPolicyInput = components["schemas"]["GatewayPolicyInput"];
export type MCPGatewayServer = components["schemas"]["MCPGatewayServer"];
export type MCPGatewayServerInput = components["schemas"]["MCPGatewayServerInput"];
export type MCPGatewayServerList = components["schemas"]["MCPGatewayServerList"];
export type GatewayDecision = components["schemas"]["GatewayDecision"];
export type GatewayDecisionPage = components["schemas"]["GatewayDecisionPage"];
export type MCPToolRiskClass = components["schemas"]["MCPToolRiskClass"];

const PRODUCT_ID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const RULE_ID = /^[a-z][a-z0-9_]{1,31}\.[a-z][a-z0-9_]{1,47}$/;

export const GATEWAY_TOOL_RISKS = ["execute", "write", "network", "read", "unclassified"] as const;
export const GATEWAY_REASONS = ["none", "guardrail", "server_blocked", "server_unapproved", "server_disabled", "tool_denied", "tool_not_allowed", "tool_risk_denied", "tools_hidden", "stream_window_exceeded"] as const;

function fail(): never { throw new Error("schema mismatch"); }
function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const record = value as Record<string, unknown>;
  if (keys.some((key) => !Object.hasOwn(record, key)) || Object.keys(record).some((key) => !keys.includes(key))) fail();
  return record;
}
function list(value: unknown, maximum: number): readonly unknown[] { if (!Array.isArray(value) || value.length > maximum) fail(); return value; }
function id(value: unknown): asserts value is string { if (typeof value !== "string" || !PRODUCT_ID.test(value)) fail(); }
function one(value: unknown, allowed: readonly string[]): void { if (typeof value !== "string" || !allowed.includes(value)) fail(); }
function count(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): void { if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) fail(); }
function time(value: unknown): asserts value is string { if (typeof value !== "string" || !DATE_TIME.test(value) || Number.isNaN(Date.parse(value))) fail(); }
function identifier(value: unknown): void { if (typeof value !== "string" || !IDENTIFIER.test(value)) fail(); }
function names(value: unknown): readonly string[] {
  const values = list(value, 128);
  for (const name of values) identifier(name);
  if (new Set(values).size !== values.length) fail();
  return values as readonly string[];
}

export function decodeGatewayPolicy(value: unknown): GatewayPolicy {
  const record = exact(value, ["environment_id", "unapproved_servers", "denied_tool_risks", "requests_per_minute", "version", "updated_at", "gateway_enabled"]);
  id(record.environment_id); one(record.unapproved_servers, ["allow", "refuse"]);
  const risks = list(record.denied_tool_risks, 5);
  for (const risk of risks) one(risk, GATEWAY_TOOL_RISKS);
  if (new Set(risks).size !== risks.length || typeof record.gateway_enabled !== "boolean") fail();
  count(record.requests_per_minute, 0, 100_000); count(record.version, 0, 1_000_000);
  // A policy that was never saved has version 0 and no time.
  if (record.updated_at !== null) time(record.updated_at);
  if ((record.version === 0) !== (record.updated_at === null)) fail();
  return value as GatewayPolicy;
}

export function decodeMCPGatewayServer(value: unknown): MCPGatewayServer {
  const record = exact(value, ["id", "name", "upstream_url", "upstream_host", "gateway_path", "identity", "approval", "enabled", "allowed_tools", "denied_tools", "tools", "tool_count", "last_activity_at", "version", "created_at", "updated_at"]);
  id(record.id);
  if (typeof record.name !== "string" || record.name.length < 1 || record.name.length > 128 || typeof record.upstream_url !== "string" || !record.upstream_url.startsWith("https://") || record.upstream_url.length > 2048 ||
    typeof record.upstream_host !== "string" || record.upstream_host.length < 1 || record.upstream_host.length > 253 || typeof record.enabled !== "boolean") fail();
  // The gateway address is this server's own, and the identity its host's.
  if (record.gateway_path !== `/api/v1/gateway/mcp/${record.id}` || record.identity !== `host:${record.upstream_host}`) fail();
  let host = "";
  try { host = new URL(record.upstream_url).hostname.toLowerCase(); } catch { fail(); }
  if (host !== record.upstream_host) fail();
  one(record.approval, ["approved", "unapproved", "blocked"]);
  const allowed = names(record.allowed_tools); const denied = names(record.denied_tools);
  if (allowed.some((name) => denied.includes(name))) fail();
  const tools = list(record.tools, 64);
  for (const item of tools) { const tool = exact(item, ["name", "risk", "last_seen_at"]); identifier(tool.name); one(tool.risk, GATEWAY_TOOL_RISKS); time(tool.last_seen_at); }
  count(record.tool_count, tools.length);
  if (record.last_activity_at !== null) time(record.last_activity_at);
  count(record.version, 1, 1_000_000); time(record.created_at); time(record.updated_at);
  if (Date.parse(record.updated_at) < Date.parse(record.created_at)) fail();
  return value as MCPGatewayServer;
}

export function decodeMCPGatewayServerList(value: unknown): MCPGatewayServerList {
  const record = exact(value, ["items", "gateway_enabled"]);
  if (typeof record.gateway_enabled !== "boolean") fail();
  const seen = new Set<string>();
  for (const item of list(record.items, 200)) { const server = decodeMCPGatewayServer(item); if (seen.has(server.id)) fail(); seen.add(server.id); }
  return value as MCPGatewayServerList;
}

// A decision record. It has no member for a prompt, an argument, a result
// or an answer, and a record with one more member is refused.
export function decodeGatewayDecision(value: unknown): GatewayDecision {
  const record = exact(value, ["id", "created_at", "surface", "operation", "direction", "decision", "reason", "rules", "bytes", "content_digest", "server_id", "server_name", "tool_name", "provider", "model", "agent_id", "principal_id"]);
  id(record.id); time(record.created_at); one(record.surface, ["mcp", "llm"]); one(record.direction, ["request", "response"]); one(record.decision, ["allow", "redact", "block"]); one(record.reason, GATEWAY_REASONS);
  if (typeof record.operation !== "string" || record.operation.length < 1 || record.operation.length > 64 || (record.decision === "allow") !== (record.reason === "none")) fail();
  for (const item of list(record.rules, 64)) {
    const rule = exact(item, ["id", "category", "mode", "count"]);
    if (typeof rule.id !== "string" || !RULE_ID.test(rule.id)) fail();
    one(rule.category, ["prompt_injection", "sensitive_data"]); one(rule.mode, ["block", "redact", "monitor"]); count(rule.count, 1, 9999);
  }
  count(record.bytes, 0);
  if (typeof record.content_digest !== "string" || !DIGEST.test(record.content_digest)) fail();
  // An MCP decision names its server, a model decision its provider.
  if ((record.surface === "mcp") !== (record.server_id !== null) || (record.surface === "llm") !== (record.provider !== null)) fail();
  if (record.server_id !== null) id(record.server_id);
  if (record.server_name !== null && (typeof record.server_name !== "string" || record.server_name.length < 1 || record.server_name.length > 128 || record.server_id === null)) fail();
  for (const name of [record.tool_name, record.model, record.agent_id]) if (name !== null) identifier(name);
  if (record.provider !== null && (typeof record.provider !== "string" || !/^[a-z][a-z0-9_]{1,31}$/.test(record.provider))) fail();
  id(record.principal_id);
  return value as GatewayDecision;
}

export function decodeGatewayDecisionPage(value: unknown): GatewayDecisionPage {
  const record = exact(value, ["items", "next_cursor"]);
  const items = list(record.items, 100);
  let prior = Number.POSITIVE_INFINITY;
  let last = "";
  for (const item of items) {
    const decision = decodeGatewayDecision(item);
    // Newest first.
    const at = Date.parse(decision.created_at);
    if (at > prior) fail();
    prior = at; last = decision.id;
  }
  if (record.next_cursor !== null) { id(record.next_cursor); if (record.next_cursor !== last) fail(); }
  return value as GatewayDecisionPage;
}
