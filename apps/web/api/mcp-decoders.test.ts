import { describe, expect, it } from "vitest";

import { decodeAgentAccess, decodeMCPRegistryEntry, decodeMCPRegistryPage, decodeMCPServer, decodeMCPServerPage } from "./mcp-decoders";

const serverID = "pid_70000001-0000-4000-8000-000000000001";
const agentID = "pid_10000001-0000-4000-8000-000000000001";
const server = {
  id: serverID, name: "tracker", provider: "github", source_kind: "github_mcp_server", source: "repository_config", transport: "stdio", endpoint_host: null, command: "npx", package: "@acme/tracker-mcp", package_pinned: false, plain_http: false,
  auth: "not_applicable", identity: "package:@acme/tracker-mcp", approval: "unapproved", tools: [{ id: "pid_70000002-0000-4000-8000-000000000002", name: "run_command", risk: "execute" }], tool_count: 1,
  agents: [{ id: agentID, name: "acme/alpha" }], agent_count: 1, first_seen_at: "2026-08-19T01:00:00Z", last_seen_at: "2026-08-19T02:00:00Z",
};
const entry = { identity: "package:@acme/tracker-mcp", status: "blocked", note: "unreviewed", version: 2, updated_by: "pid_50000001-0000-4000-8000-000000000001", updated_at: "2026-08-19T03:00:00Z", server_count: 1 };
const access = {
  agent_id: agentID,
  ai_actions: { window_days: 7, granted: ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], used: ["bedrock:InvokeModel"], unused: ["bedrock:InvokeModelWithResponseStream"] },
  mcp_servers: [{ id: serverID, name: "tracker", identity: "package:@acme/tracker-mcp", approval: "blocked" }],
  data_stores: [{ id: "pid_70000003-0000-4000-8000-000000000003", name: "All S3 buckets", service: "s3", access: "read", scope: "service" }],
  skills: [{ id: "pid_70000004-0000-4000-8000-000000000004", path: ".claude/skills/release", kind: "skill" }],
};

describe("MCP decoders", () => {
  it("accepts the contract shapes", () => {
    expect(decodeMCPServer(server)).toBe(server);
    expect(decodeMCPServerPage({ items: [server], page_info: { next_cursor: null, has_more: false } }).items).toHaveLength(1);
    expect(decodeMCPRegistryPage({ items: [entry] }).items).toHaveLength(1);
    expect(decodeMCPRegistryEntry({ ...entry, audit_id: "pid_60000001-0000-4000-8000-000000000001" }, true).version).toBe(2);
    expect(decodeMCPRegistryEntry({ ...entry, status: "unapproved", version: 0, note: "", audit_id: "pid_60000001-0000-4000-8000-000000000001" }, true).status).toBe("unapproved");
    expect(decodeAgentAccess(access, agentID)).toBe(access);
    expect(decodeAgentAccess({ ...access, ai_actions: null }).ai_actions).toBeNull();
  });

  it.each([
    ["an unknown member", { ...server, env: { TOKEN: "x" } }],
    ["an unknown approval", { ...server, approval: "trusted" }],
    ["an unknown tool risk", { ...server, tools: [{ ...server.tools[0], risk: "dangerous" }] }],
    ["a package that does not say whether it is pinned", { ...server, package_pinned: null }],
    ["a pin without a package", { ...server, package: null }],
    ["a count below its list", { ...server, tool_count: 0 }],
    ["an identity without a prefix", { ...server, identity: "tracker" }],
    ["a tool description", { ...server, tools: [{ ...server.tools[0], description: "runs anything" }] }],
    ["a last seen before the first", { ...server, last_seen_at: "2026-08-18T00:00:00Z" }],
  ])("refuses a server with %s", (_name, value) => {
    expect(() => decodeMCPServer(value)).toThrow("schema mismatch");
  });

  it("refuses registry and access answers outside the contract", () => {
    expect(() => decodeMCPRegistryPage({ items: [{ ...entry, status: "unapproved", version: 0 }] })).toThrow("schema mismatch");
    expect(() => decodeMCPRegistryPage({ items: [entry, entry] })).toThrow("schema mismatch");
    expect(() => decodeMCPRegistryEntry({ ...entry, version: 0 }, true)).toThrow("schema mismatch");
    expect(() => decodeMCPRegistryEntry(entry, true)).toThrow("schema mismatch");
    expect(() => decodeAgentAccess(access, serverID)).toThrow("schema mismatch");
    expect(() => decodeAgentAccess({ ...access, ai_actions: { ...access.ai_actions, unused: ["bedrock:InvokeAgent"] } })).toThrow("schema mismatch");
    expect(() => decodeAgentAccess({ ...access, ai_actions: { ...access.ai_actions, granted: ["bedrock:*"] } })).toThrow("schema mismatch");
    expect(() => decodeAgentAccess({ ...access, skills: [{ ...access.skills[0], contents: "# Release" }] })).toThrow("schema mismatch");
    expect(() => decodeAgentAccess({ ...access, data_stores: [{ ...access.data_stores[0], access: "admin" }] })).toThrow("schema mismatch");
  });
});
