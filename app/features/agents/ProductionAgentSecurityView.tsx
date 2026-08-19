"use client";

import { useCallback, useMemo, useState } from "react";

import type { APIClient } from "../../../apps/web/api/client";
import { createAPIClient, requireAPIData } from "../../../apps/web/api/client";
import { decodeAgentSessionPage, decodeCapabilityPage, decodeHomeSummary, decodeInventoryPage, decodeInventoryRecord, decodeRelationshipPage } from "../../../apps/web/api/decoders";
import type { AgentSession, Capability, HomeSummary, InventoryRecord, Relationship } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button, Card, Drawer, MetricGrid, PageHeader } from "../../components/ui";

type ProductionAgentSecurityAPI = {
  listAgents(signal?: AbortSignal): Promise<readonly InventoryRecord[]>;
  listTools(signal?: AbortSignal): Promise<readonly InventoryRecord[]>;
  listIdentities(signal?: AbortSignal): Promise<readonly InventoryRecord[]>;
  listRuntimes(signal?: AbortSignal): Promise<readonly InventoryRecord[]>;
  getAgent(id: string): Promise<InventoryRecord>;
  getTool(id: string): Promise<InventoryRecord>;
  getIdentity(id: string): Promise<InventoryRecord>;
  getRuntime(id: string): Promise<InventoryRecord>;
  getAgentCapabilities(id: string): Promise<readonly Capability[]>;
  getAgentRelationships(id: string): Promise<readonly Relationship[]>;
  listAgentSessions(id: string): Promise<readonly AgentSession[]>;
  getHomeSummary(signal?: AbortSignal): Promise<HomeSummary>;
};

export function createProductionAgentSecurityAPI(client: APIClient = createAPIClient()): ProductionAgentSecurityAPI {
  return {
    async listAgents(signal) { return requireAPIData(await client.GET("/api/v1/agents", { signal }), decodeInventoryPage).items; },
    async listTools(signal) { return requireAPIData(await client.GET("/api/v1/tools", { signal }), decodeInventoryPage).items; },
    async listIdentities(signal) { return requireAPIData(await client.GET("/api/v1/identities", { signal }), decodeInventoryPage).items; },
    async listRuntimes(signal) { return requireAPIData(await client.GET("/api/v1/runtimes", { signal }), decodeInventoryPage).items; },
    async getAgent(id) { return requireAPIData(await client.GET("/api/v1/agents/{id}", { params: { path: { id } } }), decodeInventoryRecord); },
    async getTool(id) { return requireAPIData(await client.GET("/api/v1/tools/{id}", { params: { path: { id } } }), decodeInventoryRecord); },
    async getIdentity(id) { return requireAPIData(await client.GET("/api/v1/identities/{id}", { params: { path: { id } } }), decodeInventoryRecord); },
    async getRuntime(id) { return requireAPIData(await client.GET("/api/v1/runtimes/{id}", { params: { path: { id } } }), decodeInventoryRecord); },
    async getAgentCapabilities(id) { return requireAPIData(await client.GET("/api/v1/agents/{id}/capabilities", { params: { path: { id } } }), decodeCapabilityPage).items; },
    async getAgentRelationships(id) { return requireAPIData(await client.GET("/api/v1/agents/{id}/relationships", { params: { path: { id } } }), decodeRelationshipPage).items; },
    async listAgentSessions(id) { return requireAPIData(await client.GET("/api/v1/agents/{id}/sessions", { params: { path: { id } } }), decodeAgentSessionPage).items; },
    async getHomeSummary(signal) { return requireAPIData(await client.GET("/api/v1/home/summary", { signal }), decodeHomeSummary); },
  };
}

type ConnectedData =
  | { kind: "home"; value: HomeSummary }
  | { kind: "inventory"; title: string; category: "agent" | "tool" | "identity" | "runtime"; values: readonly InventoryRecord[] };

export function ProductionAgentSecurityView({ path, onNavigate }: { path: string; onNavigate(path: string): void }) {
  const { client } = useAPI();
  const api = useMemo(() => createProductionAgentSecurityAPI(client), [client]);
  const supported = connectedPaths.has(path);
  const load = useCallback(async (signal?: AbortSignal): Promise<ConnectedData> => {
    switch (path) {
    case "/": return { kind: "home", value: await api.getHomeSummary(signal) };
    case "/discovery/assets": return { kind: "inventory", title: "Agents", category: "agent", values: await api.listAgents(signal) };
    case "/inventory/tools": return { kind: "inventory", title: "Tools & MCP", category: "tool", values: await api.listTools(signal) };
    case "/identities": return { kind: "inventory", title: "Identities", category: "identity", values: await api.listIdentities(signal) };
    case "/inventory/runtimes": return { kind: "inventory", title: "Runtimes", category: "runtime", values: await api.listRuntimes(signal) };
    default: throw new Error("Production route unavailable");
    }
  }, [api, path]);
  const query = useAPIQuery(`core:${path}`, load, supported);
  if (!supported) return <State title="Unavailable" alert="Product route unavailable" />;
  if (query.status === "loading" || query.status === "idle") return <State title="Loading" status="Loading authorized data…" />;
  if (query.status === "forbidden") return <State title="Forbidden" alert="Authorization rejected" />;
  if (query.status === "error") return <State title="Unavailable" alert="Product API unavailable" retry={() => void query.retry()} />;
  if (!query.data) return <State title="Empty" status="No records in this scope." />;
  return <>{query.status === "stale" && <div role="alert" className="form-error">Showing stale data.</div>}<ConnectedDataView data={query.data} api={api} onNavigate={onNavigate} /></>;
}

const connectedPaths = new Set(["/", "/discovery/assets", "/inventory/tools", "/identities", "/inventory/runtimes"]);

function ConnectedDataView({ data, api, onNavigate }: { data: ConnectedData; api: ProductionAgentSecurityAPI; onNavigate(path: string): void }) {
  return data.kind === "home" ? <ConnectedHome value={data.value} onNavigate={onNavigate} /> : <ConnectedInventory title={data.title} category={data.category} values={data.values} api={api} />;
}

function ConnectedHome({ value, onNavigate }: { value: HomeSummary; onNavigate(path: string): void }) {
  return <div className="page"><PageHeader title="Security overview" description="Authoritative posture for the selected scope." /><MetricGrid metrics={[{ label: "Agents", value: value.agent_count, onClick: () => onNavigate("/discovery/assets") }, { label: "High-risk paths", value: value.high_risk_paths, tone: value.high_risk_paths > 0 ? "danger" : undefined, onClick: () => onNavigate("/exposure/attack-paths") }, { label: "Verified changes", value: value.verified_changes }, { label: "Blocked changes", value: value.blocked_changes }]} />{value.attention_required && <div role="alert" className="form-error">Attention required</div>}</div>;
}

function ConnectedInventory({ title, category, values, api }: { title: string; category: "agent" | "tool" | "identity" | "runtime"; values: readonly InventoryRecord[]; api: ProductionAgentSecurityAPI }) {
  const [selected, setSelected] = useState<InventoryRecord | null>(null);
  const [detailError, setDetailError] = useState(false);
  const open = async (item: InventoryRecord) => {
    try { const loaders = { agent: api.getAgent, tool: api.getTool, identity: api.getIdentity, runtime: api.getRuntime }; setSelected(await loaders[category](item.id)); setDetailError(false); }
    catch { setDetailError(true); }
  };
  return <div className="page"><PageHeader title={title} description="Authorized canonical inventory." />{detailError && <div role="alert">Inventory detail unavailable</div>}<Card>{values.length === 0 ? <p>No records in this scope.</p> : <div className="table-scroll"><table className="data-table"><thead><tr><th>Name</th><th>Owner</th><th>Last seen</th></tr></thead><tbody>{values.map((item) => <tr key={item.id}><td><button className="row-title" aria-label={`Open ${item.name}`} onClick={() => void open(item)}>{item.name}</button></td><td>{item.owner || "Unowned"}</td><td>{item.last_seen}</td></tr>)}</tbody></table></div>}</Card>{selected && <Drawer open title={selected.name} onClose={() => setSelected(null)}><div className="detail-content"><h3>Canonical record</h3><code>{selected.id}</code><h3>Ownership</h3><p>{selected.owner || "Unowned"} · {selected.team || "No team"}</p><h3>Evidence and freshness</h3><p>{selected.evidence_id} · last seen {selected.last_seen}</p></div></Drawer>}</div>;
}

function State({ title, status, alert, retry }: { title: string; status?: string; alert?: string; retry?: () => void }) {
  return <div className="page"><PageHeader title={title} description="Authorized product data for the selected scope." />{status && <p role="status">{status}</p>}{alert && <div role="alert">{alert}</div>}{retry && <Button onClick={retry}>Retry</Button>}</div>;
}
