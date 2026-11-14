"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import type { APIClient } from "../../../apps/web/api/client";
import { APIProductError, APITransportError, createAPIClient, requireAPIData } from "../../../apps/web/api/client";
import type { AgentAccess, MCPRegistryEntry, MCPServer } from "../../../apps/web/api/mcp-decoders";
import { decodeAgentAccess, decodeMCPRegistryEntry, decodeMCPRegistryPage, decodeMCPServerPage } from "../../../apps/web/api/mcp-decoders";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";
import { useAPIQuery } from "../../api/query";
import { Badge, Button, Card } from "../../components/ui";

export type MCPDecision = "approved" | "blocked" | "unapproved";

export type MCPInventoryAPI = {
  listMCPServers(signal?: AbortSignal): Promise<readonly MCPServer[]>;
  listMCPRegistry(signal?: AbortSignal): Promise<readonly MCPRegistryEntry[]>;
  putMCPRegistryEntry(identity: string, status: MCPDecision, expectedVersion: number, signal?: AbortSignal): Promise<MCPRegistryEntry>;
  getAgentAccess(agentID: string, signal?: AbortSignal): Promise<AgentAccess>;
};

export function createMCPInventoryAPI(client: APIClient = createAPIClient()): MCPInventoryAPI {
  return {
    async listMCPServers(signal) {
      return (await loadAllCursorPages(async (cursor) => requireAPIData(await client.GET("/api/v1/mcp-servers", { params: { query: { cursor, limit: 100 } }, signal }), decodeMCPServerPage), { maximumItems: 10_000, maximumPages: 100 })).items;
    },
    async listMCPRegistry(signal) { return requireAPIData(await client.GET("/api/v1/mcp-registry", { signal }), decodeMCPRegistryPage).items; },
    async putMCPRegistryEntry(identity, status, expectedVersion, signal) {
      if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0 || expectedVersion > 999_999) throw new APITransportError("invalid_configuration", "Invalid registry version");
      const result = await client.PUT("/api/v1/mcp-registry", { params: { header: { "X-CSRF-Token": "" } }, body: { identity, status, note: "", expected_version: expectedVersion }, signal });
      const entry = requireAPIData(result, (value) => decodeMCPRegistryEntry(value, true));
      if (entry.identity !== identity || entry.status !== status || result.response.headers.get("X-Audit-ID") !== entry.audit_id) throw new APITransportError("invalid_response", "Registry decision omitted exact evidence");
      return entry;
    },
    async getAgentAccess(agentID, signal) { return requireAPIData(await client.GET("/api/v1/agents/{id}/access", { params: { path: { id: agentID } }, signal }), (value) => decodeAgentAccess(value, agentID)); },
  };
}

const sourceLabels: Readonly<Record<MCPServer["source"], string>> = {
  agentcore_gateway: "AgentCore gateway", egress: "Seen in network logs", gateway_target: "Gateway target", repository_config: "Repository configuration", workload: "Kubernetes workload", saas_api: "SaaS platform", provider_api: "Provider record",
};
const authLabels: Readonly<Record<MCPServer["auth"], string>> = { declared: "Declared", none: "None declared", not_applicable: "Local process", unknown: "Not known" };
const approvalTone = { approved: "success", unapproved: "warning", blocked: "critical" } as const;
const approvalLabels = { approved: "Approved", unapproved: "Unapproved", blocked: "Blocked" } as const;
const riskTone = { execute: "critical", write: "warning", network: "info", read: "neutral", unclassified: "neutral" } as const;

// What the server is: the host of a remote server, or the command and
// package of a local one.
function endpoint(server: MCPServer): string {
  if (server.endpoint_host) return `${server.plain_http ? "http" : "https"}://${server.endpoint_host}`;
  if (server.package) return `${server.command ?? "run"} ${server.package}${server.package_pinned ? " (pinned)" : " (no version)"}`;
  return server.command ?? "—";
}

// The MCP servers found in this scope, with their tools, the agents that use
// them and the registry's decision. A person with write access approves or
// blocks a server by its identity; the decision applies to every server with
// that identity and refreshes the findings.
export function MCPServersPanel({ api, canWrite }: { api: MCPInventoryAPI; canWrite: boolean }) {
  const load = useCallback(async (signal?: AbortSignal) => {
    const [servers, registry] = await Promise.all([api.listMCPServers(signal), api.listMCPRegistry(signal)]);
    return { servers, registry };
  }, [api]);
  const query = useAPIQuery("mcp:servers", load, true);
  const [decided, setDecided] = useState<Readonly<Record<string, MCPRegistryEntry>>>({});
  const [saving, setSaving] = useState("");
  const [error, setError] = useState("");
  const versions = useMemo(() => {
    const result: Record<string, number> = {};
    for (const entry of query.data?.registry ?? []) result[entry.identity] = entry.version;
    for (const [identity, entry] of Object.entries(decided)) result[identity] = entry.version;
    return result;
  }, [decided, query.data]);
  const decide = async (server: MCPServer, status: MCPDecision) => {
    if (!canWrite || saving !== "") return;
    setSaving(server.identity); setError("");
    try {
      const entry = await api.putMCPRegistryEntry(server.identity, status, versions[server.identity] ?? 0);
      setDecided((current) => ({ ...current, [server.identity]: entry }));
    } catch (failure) {
      setError(failure instanceof APIProductError && failure.status === 409 ? "The decision changed elsewhere. Reload and decide again." : "The decision was not saved.");
      if (failure instanceof APIProductError && failure.status === 409) void query.retry();
    } finally { setSaving(""); }
  };
  if (query.status === "loading" || query.status === "idle") return <Card title="MCP servers"><p role="status">Loading MCP servers…</p></Card>;
  if (query.status === "forbidden") return <Card title="MCP servers"><p role="alert">MCP servers are not authorized in this scope.</p></Card>;
  if (query.status === "error" || !query.data) return <Card title="MCP servers"><p role="alert">MCP servers are unavailable.</p><Button onClick={() => void query.retry()}>Retry</Button></Card>;
  const servers = query.data.servers.map((server) => decided[server.identity] ? { ...server, approval: decided[server.identity].status } : server);
  const unapproved = servers.filter((server) => server.approval === "unapproved" && server.agent_count > 0).length;
  return <Card title="MCP servers" action={servers.length > 0 ? <span>{servers.length} found · {unapproved} unapproved in use</span> : undefined}>
    {error && <p role="alert" className="form-error">{error}</p>}
    {servers.length === 0 ? <p>No MCP server found in this scope. Servers are read from AgentCore gateways, repository MCP configuration, Kubernetes workloads, network logs and connected SaaS platforms.</p> :
      <div className="table-scroll"><table className="data-table" aria-label="MCP servers"><thead><tr><th>Server</th><th>Found by</th><th>Endpoint or command</th><th>Authentication</th><th>Tools</th><th>Used by</th><th>Registry</th>{canWrite && <th>Decision</th>}</tr></thead><tbody>
        {servers.map((server) => <tr key={server.id}>
          <td><strong>{server.name}</strong><br /><code>{server.identity}</code></td>
          <td>{sourceLabels[server.source]}</td>
          <td>{endpoint(server)}</td>
          <td>{authLabels[server.auth]}</td>
          <td>{server.tool_count === 0 ? "Not listed" : <>{server.tools.map((tool) => <span key={tool.id} title={`${tool.risk} tool`}><Badge tone={riskTone[tool.risk]}>{tool.name} · {tool.risk}</Badge> </span>)}{server.tool_count > server.tools.length && <span>and {server.tool_count - server.tools.length} more</span>}</>}</td>
          <td>{server.agent_count === 0 ? "No agent" : <>{server.agents.map((agent) => agent.name).join(", ")}{server.agent_count > server.agents.length ? ` and ${server.agent_count - server.agents.length} more` : ""}</>}</td>
          <td><Badge tone={approvalTone[server.approval]}>{approvalLabels[server.approval]}</Badge></td>
          {canWrite && <td><div className="page-actions">
            {server.approval !== "approved" && <Button disabled={saving !== ""} aria-label={`Approve ${server.name}`} onClick={() => void decide(server, "approved")}>Approve</Button>}
            {server.approval !== "blocked" && <Button disabled={saving !== ""} aria-label={`Block ${server.name}`} onClick={() => void decide(server, "blocked")}>Block</Button>}
            {server.approval !== "unapproved" && <Button disabled={saving !== ""} aria-label={`Clear the decision for ${server.name}`} onClick={() => void decide(server, "unapproved")}>Clear</Button>}
          </div></td>}
        </tr>)}
      </tbody></table></div>}
  </Card>;
}

const skillKindLabels = { skill: "Skill", agent_instructions: "Agent instructions", editor_rules: "Editor rules" } as const;

// What one agent may use: the model actions its role is granted against the
// ones it used, its MCP servers, the data stores its role reaches and the
// skills of its repository. The caller keys the panel by the agent, so a
// panel only ever shows the agent it was mounted for.
export function AgentAccessPanel({ api, agentID }: { api: MCPInventoryAPI; agentID: string }) {
  const [access, setAccess] = useState<AgentAccess | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    api.getAgentAccess(agentID, controller.signal).then(
      (value) => { if (!controller.signal.aborted) setAccess(value); },
      () => { if (!controller.signal.aborted) setFailed(true); },
    );
    return () => controller.abort();
  }, [api, agentID]);
  if (failed) return <><h3>Access</h3><p role="alert">Agent access is unavailable.</p></>;
  if (!access) return <><h3>Access</h3><p role="status">Loading agent access…</p></>;
  const actions = access.ai_actions;
  return <>
    <h3>Model permissions: used against granted</h3>
    {actions === null ? <p>The audit log of this agent&apos;s role was not read, so used and granted permissions cannot be compared.</p> : <>
      <p>{actions.granted.length} granted · {actions.used.length} used in the last {actions.window_days} days · {actions.unused.length} unused</p>
      <ul aria-label="Granted model permissions">{actions.granted.map((action) => <li key={action}><code>{action}</code> · {actions.used.includes(action) ? "used" : actions.unused.includes(action) ? "granted, not used" : "granted, use not recorded by the audit log"}</li>)}</ul>
    </>}
    <h3>MCP servers</h3>
    {access.mcp_servers.length === 0 ? <p>No MCP server use was found.</p> : <ul aria-label="MCP servers of the agent">{access.mcp_servers.map((server) => <li key={server.id}>{server.name} · <code>{server.identity}</code> · <Badge tone={approvalTone[server.approval]}>{approvalLabels[server.approval]}</Badge></li>)}</ul>}
    <h3>Data stores the agent&apos;s role reaches</h3>
    {access.data_stores.length === 0 ? <p>No data grant was found in the role&apos;s policies.</p> : <ul aria-label="Data stores of the agent">{access.data_stores.map((store) => <li key={store.id}>{store.name} · {store.service} · {store.access === "write" ? "read and write" : "read"}{store.scope === "service" ? " · every resource of the service" : ""}</li>)}</ul>}
    <h3>Skills and instruction files</h3>
    {access.skills.length === 0 ? <p>None found in the agent&apos;s repository.</p> : <ul aria-label="Skills of the agent">{access.skills.map((skill) => <li key={skill.id}><code>{skill.path}</code> · {skillKindLabels[skill.kind]}</li>)}</ul>}
  </>;
}
