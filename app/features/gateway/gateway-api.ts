import { APIProductError, APITransportError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import {
  decodeGatewayDecisionPage, decodeGatewayPolicy, decodeMCPGatewayServer, decodeMCPGatewayServerList,
  type GatewayDecisionPage, type GatewayPolicy, type GatewayPolicyInput, type MCPGatewayServer, type MCPGatewayServerInput, type MCPGatewayServerList,
} from "../../../apps/web/api/gateway-decoders";
import { createWorkflowMutationAttempt } from "../workflows/api";

// The hosted gateway of the current Environment:
//   GET    /api/v1/gateway/policy             getGatewayPolicy        (view)
//   PUT    /api/v1/gateway/policy             putGatewayPolicy        (manage_workflows)
//   GET    /api/v1/gateway/mcp-servers        listMCPGatewayServers   (view)
//   PUT    /api/v1/gateway/mcp-servers/{id}   putMCPGatewayServer     (manage_workflows)
//   DELETE /api/v1/gateway/mcp-servers/{id}   deleteMCPGatewayServer  (manage_workflows)
//   GET    /api/v1/gateway/activity           listGatewayActivity     (view)
// The gateway's traffic routes are called by agents with an API token, never
// by the product's pages. A change names the version it was made from; when
// the object changed in the meantime the server refuses it and
// GatewayConflict is thrown.
export class GatewayConflict extends Error {
  constructor() { super("The gateway object changed"); this.name = "GatewayConflict"; }
}

export type GatewayActivityFilter = Readonly<{ surface?: "mcp" | "llm"; decision?: "allow" | "redact" | "block"; serverID?: string; agentID?: string; before?: string; limit?: number }>;

export type GatewayAPI = Readonly<{
  getPolicy(signal?: AbortSignal): Promise<GatewayPolicy>;
  savePolicy(input: GatewayPolicyInput, version: number): Promise<GatewayPolicy>;
  listServers(signal?: AbortSignal): Promise<MCPGatewayServerList>;
  saveServer(id: string, input: MCPGatewayServerInput, version: number): Promise<MCPGatewayServer>;
  removeServer(id: string, version: number): Promise<void>;
  listActivity(filter: GatewayActivityFilter, signal?: AbortSignal): Promise<GatewayDecisionPage>;
}>;

type MutationHeaders = { "Idempotency-Key": string; "If-Match": string };

function mutationHeaders(version: number): MutationHeaders {
  if (!Number.isSafeInteger(version) || version < 0 || version > 1_000_000) throw new APITransportError("invalid_configuration", "Invalid gateway version");
  return { "Idempotency-Key": createWorkflowMutationAttempt().idempotencyKey, "If-Match": `"${version}"` };
}

function conflict(error: unknown): never {
  if (error instanceof APIProductError && (error.status === 409 || error.status === 412)) throw new GatewayConflict();
  throw error;
}

// A new server's identifier is chosen here: a product identifier.
export function newGatewayServerID(): string {
  return `pid_${crypto.randomUUID()}`;
}

function versionedPolicy(result: { data?: unknown; error?: unknown; response: Response }): GatewayPolicy {
  const policy = requireAPIData(result, decodeGatewayPolicy);
  if (result.response.headers.get("ETag") !== `"${policy.version}"` || result.response.headers.get("Cache-Control") !== "no-store") throw new APITransportError("invalid_response", "Gateway policy returned invalid version metadata");
  return policy;
}

export function createGatewayAPI(client: APIClient): GatewayAPI {
  return {
    async getPolicy(signal) { return versionedPolicy(await client.GET("/api/v1/gateway/policy", { signal })); },
    async savePolicy(input, version) {
      try {
        const saved = versionedPolicy(await client.PUT("/api/v1/gateway/policy", { params: { header: mutationHeaders(version) }, body: { unapproved_servers: input.unapproved_servers, denied_tool_risks: [...input.denied_tool_risks], requests_per_minute: input.requests_per_minute } }));
        // A save makes exactly the next version, with what was sent.
        if (saved.version !== version + 1 || saved.unapproved_servers !== input.unapproved_servers || saved.requests_per_minute !== input.requests_per_minute ||
          [...saved.denied_tool_risks].sort().join() !== [...input.denied_tool_risks].sort().join()) throw new APITransportError("invalid_response", "Gateway policy save returned a different policy");
        return saved;
      } catch (error) { return conflict(error); }
    },
    async listServers(signal) { return requireAPIData(await client.GET("/api/v1/gateway/mcp-servers", { signal }), decodeMCPGatewayServerList); },
    async saveServer(id, input, version) {
      try {
        const result = await client.PUT("/api/v1/gateway/mcp-servers/{id}", { params: { path: { id }, header: mutationHeaders(version) }, body: { name: input.name, upstream_url: input.upstream_url, enabled: input.enabled, allowed_tools: [...input.allowed_tools], denied_tools: [...input.denied_tools] } });
        const saved = requireAPIData(result, decodeMCPGatewayServer);
        if (saved.id !== id || saved.version !== version + 1 || saved.name !== input.name || saved.upstream_url !== input.upstream_url || saved.enabled !== input.enabled || result.response.headers.get("ETag") !== `"${saved.version}"`) throw new APITransportError("invalid_response", "Gateway server save returned a different server");
        return saved;
      } catch (error) { return conflict(error); }
    },
    async removeServer(id, version) {
      if (version < 1) throw new APITransportError("invalid_configuration", "Invalid gateway version");
      try {
        const result = await client.DELETE("/api/v1/gateway/mcp-servers/{id}", { params: { path: { id }, header: mutationHeaders(version) } });
        if (result.error) requireAPIData<never>(result);
        if (result.response.status !== 204) throw new APITransportError("invalid_response", "Gateway server removal returned an unexpected status");
      } catch (error) { conflict(error); }
    },
    async listActivity(filter, signal) {
      const query: { surface?: "mcp" | "llm"; decision?: "allow" | "redact" | "block"; server_id?: string; agent_id?: string; before?: string; limit: number } = { limit: filter.limit ?? 50 };
      if (filter.surface) query.surface = filter.surface;
      if (filter.decision) query.decision = filter.decision;
      if (filter.serverID) query.server_id = filter.serverID;
      if (filter.agentID) query.agent_id = filter.agentID;
      if (filter.before) query.before = filter.before;
      const page = requireAPIData(await client.GET("/api/v1/gateway/activity", { params: { query }, signal }), decodeGatewayDecisionPage);
      if (page.items.length > query.limit) throw new APITransportError("invalid_response", "Gateway activity returned more records than asked for");
      return page;
    },
  };
}
