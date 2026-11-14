import type { components } from "./generated";

export type MCPServer = components["schemas"]["MCPServer"];
export type MCPServerPage = components["schemas"]["MCPServerPage"];
export type MCPRegistryEntry = components["schemas"]["MCPRegistryEntry"];
export type MCPRegistryPage = components["schemas"]["MCPRegistryPage"];
export type AgentAccess = components["schemas"]["AgentAccess"];

const PRODUCT_ID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const CURSOR = /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$/;
const MCP_IDENTITY = /^(host|package|repository|workload|arn|saas|name):.{1,480}$/;
const IAM_ACTION = /^[a-z][a-z0-9-]{1,31}:[A-Za-z]{1,64}$/;

export const MCP_TOOL_RISKS = ["execute", "write", "network", "read", "unclassified"] as const;
export const MCP_APPROVALS = ["approved", "unapproved", "blocked"] as const;

function fail(): never { throw new Error("schema mismatch"); }
function exact(value: unknown, keys: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const record = value as Record<string, unknown>;
  if (keys.some((key) => !Object.hasOwn(record, key)) || Object.keys(record).some((key) => !keys.includes(key) && !optional.includes(key))) fail();
  return record;
}
function list(value: unknown, maximum: number): readonly unknown[] { if (!Array.isArray(value) || value.length > maximum) fail(); return value; }
function text(value: unknown, minimum: number, maximum: number): asserts value is string {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum || value.trim() !== value || [...value].some((character) => { const code = character.codePointAt(0) ?? 0; return code < 32 || code === 127; })) fail();
}
function id(value: unknown): asserts value is string { if (typeof value !== "string" || !PRODUCT_ID.test(value)) fail(); }
function one(value: unknown, allowed: readonly string[]): void { if (typeof value !== "string" || !allowed.includes(value)) fail(); }
function count(value: unknown, minimum: number): void { if (!Number.isSafeInteger(value) || (value as number) < minimum) fail(); }
function time(value: unknown): asserts value is string { if (typeof value !== "string" || !DATE_TIME.test(value) || Number.isNaN(Date.parse(value))) fail(); }
function identity(value: unknown): asserts value is string { text(value, 3, 512); if (!MCP_IDENTITY.test(value)) fail(); }

// An MCP server exactly as GET /mcp-servers answers it. A package always
// says whether it is pinned; the counts are never below the bounded lists.
export function decodeMCPServer(value: unknown): MCPServer {
  const record = exact(value, ["id", "name", "provider", "source_kind", "source", "transport", "endpoint_host", "command", "package", "package_pinned", "plain_http", "auth", "identity", "approval", "tools", "tool_count", "agents", "agent_count", "first_seen_at", "last_seen_at"]);
  id(record.id); text(record.name, 1, 256); one(record.provider, ["aws", "github", "kubernetes", "saas"]);
  one(record.source_kind, ["aws_agentcore_gateway", "aws_mcp_server", "github_mcp_server", "kubernetes_mcp_server", "saas_mcp_server"]);
  one(record.source, ["agentcore_gateway", "egress", "gateway_target", "repository_config", "workload", "saas_api", "provider_api"]);
  if (record.transport !== null) one(record.transport, ["stdio", "http", "sse"]);
  if (record.endpoint_host !== null) text(record.endpoint_host, 1, 253);
  if (record.command !== null) text(record.command, 1, 64);
  if (record.package !== null) text(record.package, 1, 256);
  if ((record.package === null) !== (record.package_pinned === null) || record.package_pinned !== null && typeof record.package_pinned !== "boolean" || typeof record.plain_http !== "boolean") fail();
  one(record.auth, ["declared", "none", "not_applicable", "unknown"]); identity(record.identity); one(record.approval, MCP_APPROVALS);
  const tools = list(record.tools, 64);
  for (const item of tools) { const tool = exact(item, ["id", "name", "risk"]); id(tool.id); text(tool.name, 1, 256); one(tool.risk, MCP_TOOL_RISKS); }
  const agents = list(record.agents, 50);
  for (const item of agents) { const agent = exact(item, ["id", "name"]); id(agent.id); text(agent.name, 1, 256); }
  count(record.tool_count, tools.length); count(record.agent_count, agents.length);
  time(record.first_seen_at); time(record.last_seen_at);
  if (Date.parse(record.last_seen_at) < Date.parse(record.first_seen_at)) fail();
  return value as MCPServer;
}

export function decodeMCPServerPage(value: unknown): MCPServerPage {
  const record = exact(value, ["items", "page_info"]);
  let prior = "";
  for (const item of list(record.items, 100)) { const server = decodeMCPServer(item); if (prior !== "" && server.id <= prior) fail(); prior = server.id; }
  const pageInfo = exact(record.page_info, ["next_cursor", "has_more"]);
  if (pageInfo.has_more === true) { if (typeof pageInfo.next_cursor !== "string" || pageInfo.next_cursor.length < 2 || pageInfo.next_cursor.length > 512 || !CURSOR.test(pageInfo.next_cursor)) fail(); }
  else if (pageInfo.has_more !== false || pageInfo.next_cursor !== null) fail();
  return value as MCPServerPage;
}

// A registry decision. Only a decision that was just removed is unapproved,
// and then it has version 0; a saved decision carries the audit id.
export function decodeMCPRegistryEntry(value: unknown, saved = false): MCPRegistryEntry {
  const record = exact(value, ["identity", "status", "note", "version", "updated_by", "updated_at", "server_count"], saved ? ["audit_id"] : []);
  identity(record.identity); one(record.status, saved ? ["approved", "blocked", "unapproved"] : ["approved", "blocked"]);
  if (typeof record.note !== "string" || record.note.length > 512) fail();
  count(record.version, 0); if ((record.version as number) > 1_000_000 || (record.status === "unapproved") !== (record.version === 0)) fail();
  id(record.updated_by); time(record.updated_at); count(record.server_count, 0);
  if (saved) id(record.audit_id);
  return value as MCPRegistryEntry;
}

export function decodeMCPRegistryPage(value: unknown): MCPRegistryPage {
  const record = exact(value, ["items"]);
  let prior = "";
  for (const item of list(record.items, 500)) { const entry = decodeMCPRegistryEntry(item); if (prior !== "" && entry.identity <= prior) fail(); prior = entry.identity; }
  return value as MCPRegistryPage;
}

// What an agent may use, exactly as GET /agents/{id}/access answers it.
export function decodeAgentAccess(value: unknown, expectedAgentID?: string): AgentAccess {
  const record = exact(value, ["agent_id", "ai_actions", "mcp_servers", "data_stores", "skills"]);
  id(record.agent_id); if (expectedAgentID !== undefined && record.agent_id !== expectedAgentID) fail();
  if (record.ai_actions !== null) {
    const actions = exact(record.ai_actions, ["window_days", "granted", "used", "unused"]);
    count(actions.window_days, 1); if ((actions.window_days as number) > 90) fail();
    const granted = list(actions.granted, 32); if (granted.length < 1) fail();
    for (const values of [granted, list(actions.used, 32), list(actions.unused, 32)]) for (const action of values) if (typeof action !== "string" || !IAM_ACTION.test(action)) fail();
    for (const action of actions.unused as readonly string[]) if (!granted.includes(action)) fail();
  }
  for (const item of list(record.mcp_servers, 64)) { const server = exact(item, ["id", "name", "identity", "approval"]); id(server.id); text(server.name, 1, 256); identity(server.identity); one(server.approval, MCP_APPROVALS); }
  for (const item of list(record.data_stores, 64)) { const store = exact(item, ["id", "name", "service", "access", "scope"]); id(store.id); text(store.name, 1, 256); if (typeof store.service !== "string" || !/^[a-z][a-z0-9-]{1,31}$/.test(store.service)) fail(); one(store.access, ["read", "write"]); one(store.scope, ["resource", "service"]); }
  for (const item of list(record.skills, 64)) { const skill = exact(item, ["id", "path", "kind"]); id(skill.id); text(skill.path, 1, 512); one(skill.kind, ["skill", "agent_instructions", "editor_rules"]); }
  return value as AgentAccess;
}
