"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import type { APIClient } from "../../../apps/web/api/client";
import { createAPIClient, requireAPIData } from "../../../apps/web/api/client";
import { decodeAgentSessionPage, decodeCapabilityPage, decodeHomeSummary, decodeInventoryDetail, decodeInventoryPage, decodeRelationshipPage } from "../../../apps/web/api/decoders";
import type { AgentSession, Capability, HomeSummary, InventoryDetail, InventorySummary, Relationship } from "../../../apps/web/api/generated";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button, Card, Drawer, MetricGrid, PageHeader } from "../../components/ui";

export type ProductionAgentSecurityAPI = {
  listAgents(signal?: AbortSignal): Promise<readonly InventorySummary[]>;
  listTools(signal?: AbortSignal): Promise<readonly InventorySummary[]>;
  listIdentities(signal?: AbortSignal): Promise<readonly InventorySummary[]>;
  listRuntimes(signal?: AbortSignal): Promise<readonly InventorySummary[]>;
  getAgent(id: string, signal?: AbortSignal): Promise<InventoryDetail>;
  getTool(id: string, signal?: AbortSignal): Promise<InventoryDetail>;
  getIdentity(id: string, signal?: AbortSignal): Promise<InventoryDetail>;
  getRuntime(id: string, signal?: AbortSignal): Promise<InventoryDetail>;
  getAgentCapabilities(id: string, signal?: AbortSignal): Promise<readonly Capability[]>;
  getAgentRelationships(id: string, signal?: AbortSignal): Promise<readonly Relationship[]>;
  listAgentSessions(id: string, signal?: AbortSignal): Promise<readonly AgentSession[]>;
  getHomeSummary(signal?: AbortSignal): Promise<HomeSummary>;
};

export function createProductionAgentSecurityAPI(client: APIClient = createAPIClient()): ProductionAgentSecurityAPI {
  return {
    async listAgents(signal) { return (await loadAllCursorPages(async (cursor) => requireAPIData(await client.GET("/api/v1/agents", { params: { query: { cursor, limit: 100 } }, signal }), decodeInventoryPage), inventoryPageBounds)).items; },
    async listTools(signal) { return (await loadAllCursorPages(async (cursor) => requireAPIData(await client.GET("/api/v1/tools", { params: { query: { cursor, limit: 100 } }, signal }), decodeInventoryPage), inventoryPageBounds)).items; },
    async listIdentities(signal) { return (await loadAllCursorPages(async (cursor) => requireAPIData(await client.GET("/api/v1/identities", { params: { query: { cursor, limit: 100 } }, signal }), decodeInventoryPage), inventoryPageBounds)).items; },
    async listRuntimes(signal) { return (await loadAllCursorPages(async (cursor) => requireAPIData(await client.GET("/api/v1/runtimes", { params: { query: { cursor, limit: 100 } }, signal }), decodeInventoryPage), inventoryPageBounds)).items; },
    async getAgent(id, signal) { return requireAPIData(await client.GET("/api/v1/agents/{id}", { params: { path: { id } }, signal }), decodeInventoryDetail); },
    async getTool(id, signal) { return requireAPIData(await client.GET("/api/v1/tools/{id}", { params: { path: { id } }, signal }), decodeInventoryDetail); },
    async getIdentity(id, signal) { return requireAPIData(await client.GET("/api/v1/identities/{id}", { params: { path: { id } }, signal }), decodeInventoryDetail); },
    async getRuntime(id, signal) { return requireAPIData(await client.GET("/api/v1/runtimes/{id}", { params: { path: { id } }, signal }), decodeInventoryDetail); },
    async getAgentCapabilities(id, signal) { return (await loadAllCursorPages(async (cursor) => requireAPIData(await client.GET("/api/v1/agents/{id}/capabilities", { params: { path: { id }, query: { cursor, limit: 100 } }, signal }), decodeCapabilityPage), inventoryPageBounds)).items; },
    async getAgentRelationships(id, signal) { return (await loadAllCursorPages(async (cursor) => requireAPIData(await client.GET("/api/v1/agents/{id}/relationships", { params: { path: { id }, query: { cursor, limit: 100 } }, signal }), decodeRelationshipPage), inventoryPageBounds)).items; },
    async listAgentSessions(id, signal) { return (await loadAllCursorPages(async (cursor) => requireAPIData(await client.GET("/api/v1/agents/{id}/sessions", { params: { path: { id }, query: { cursor, limit: 100 } }, signal }), decodeAgentSessionPage), inventoryPageBounds)).items; },
    async getHomeSummary(signal) { return requireAPIData(await client.GET("/api/v1/home/summary", { signal }), decodeHomeSummary); },
  };
}

const inventoryPageBounds = { maximumItems: 10_000, maximumPages: 100 } as const;

type ConnectedData =
  | { kind: "home"; value: HomeSummary }
  | { kind: "inventory"; title: string; category: "agent" | "tool" | "identity" | "runtime"; values: readonly InventorySummary[] };

export function ProductionAgentSecurityView({ path, onNavigate, api: suppliedAPI }: { path: string; onNavigate(path: string): void; api?: ProductionAgentSecurityAPI }) {
  const { client } = useAPI();
  const api = useMemo(() => suppliedAPI ?? createProductionAgentSecurityAPI(client), [client, suppliedAPI]);
  const initialDetailID = typeof window === "undefined" ? "" : inventoryDetailIDFromSearch(window.location.search);
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
  return <>{query.status === "stale" && <div role="alert" className="form-error">Showing stale data.</div>}<ConnectedDataView data={query.data} api={api} initialDetailID={initialDetailID} onNavigate={onNavigate} /></>;
}

const connectedPaths = new Set(["/", "/discovery/assets", "/inventory/tools", "/identities", "/inventory/runtimes"]);

function ConnectedDataView({ data, api, initialDetailID, onNavigate }: { data: ConnectedData; api: ProductionAgentSecurityAPI; initialDetailID: string; onNavigate(path: string): void }) {
  return data.kind === "home" ? <ConnectedHome value={data.value} onNavigate={onNavigate} /> : <ConnectedInventory key={data.category} title={data.title} category={data.category} values={data.values} api={api} initialDetailID={initialDetailID} />;
}

function ConnectedHome({ value, onNavigate }: { value: HomeSummary; onNavigate(path: string): void }) {
  return <div className="page"><PageHeader title="Security overview" description="Authoritative posture for the selected scope." /><MetricGrid metrics={[{ label: "Agents", value: value.agent_count, onClick: () => onNavigate("/discovery/assets") }, { label: "High-risk paths", value: value.high_risk_paths, tone: value.high_risk_paths > 0 ? "danger" : undefined, onClick: () => onNavigate("/exposure/attack-paths") }, { label: "Verified changes", value: value.verified_changes }, { label: "Blocked changes", value: value.blocked_changes }]} />{value.attention_required && <div role="alert" className="form-error">Attention required</div>}</div>;
}

function ConnectedInventory({ title, category, values, api, initialDetailID }: { title: string; category: "agent" | "tool" | "identity" | "runtime"; values: readonly InventorySummary[]; api: ProductionAgentSecurityAPI; initialDetailID: string }) {
  const [selected, setSelected] = useState<InventoryDetail | null>(null);
  const [detailError, setDetailError] = useState(false);
  const loadDetail = useCallback(async (id: string, signal?: AbortSignal) => {
    const loaders = { agent: api.getAgent, tool: api.getTool, identity: api.getIdentity, runtime: api.getRuntime };
    try { setSelected(await loaders[category](id, signal)); setDetailError(false); }
    catch { if (!signal?.aborted) setDetailError(true); }
  }, [api, category]);
  useEffect(() => {
    if (initialDetailID === "") return;
    const controller = new AbortController();
    const loaders = { agent: api.getAgent, tool: api.getTool, identity: api.getIdentity, runtime: api.getRuntime };
    void loaders[category](initialDetailID, controller.signal).then(
      (detail) => { if (!controller.signal.aborted) { setSelected(detail); setDetailError(false); } },
      () => { if (!controller.signal.aborted) setDetailError(true); },
    );
    return () => controller.abort();
  }, [api, category, initialDetailID]);
  const open = (item: InventorySummary) => { setInventoryDetailURL(item.id); void loadDetail(item.id); };
  const close = () => { setInventoryDetailURL(""); setSelected(null); };
  return <div className="page"><PageHeader title={title} description="Authorized canonical inventory." />{detailError && <div role="alert">Inventory detail unavailable</div>}<Card>{values.length === 0 ? <p>No records in this scope.</p> : <div className="table-scroll"><table className="data-table"><thead><tr><th>Name</th><th>Owner</th><th>Freshness</th><th>Last seen</th></tr></thead><tbody>{values.map((item) => <tr key={item.id}><td><button className="row-title" aria-label={`Open ${item.name}`} onClick={() => open(item)}>{item.name}</button></td><td>{item.owner || "Unowned"}</td><td>{item.freshness_state}</td><td>{item.last_seen}</td></tr>)}</tbody></table></div>}</Card>{selected && <Drawer open title={selected.summary.name} onClose={close}><div className="detail-content"><h3>Canonical record</h3><code>{selected.summary.id}</code><h3>Ownership</h3><p>{selected.summary.owner || "Unowned"} · {selected.summary.team || "No team"}</p><h3>Evidence and freshness</h3><p>{selected.summary.evidence_id} · observed {selected.summary.observed_at} · {selected.summary.freshness_state}</p><h3>Source authority</h3><p>{selected.sources.length} source observation{selected.sources.length === 1 ? "" : "s"} · confidence {selected.summary.confidence_basis_points / 100}%</p></div></Drawer>}</div>;
}

const PRODUCT_ID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function inventoryDetailIDFromSearch(search: string): string {
  const values = new URLSearchParams(search); const entries = [...values.keys()]; const id = values.get("inventory");
  return entries.length === 1 && entries[0] === "inventory" && id !== null && PRODUCT_ID.test(id) ? id : "";
}

function setInventoryDetailURL(id: string) {
  if (typeof window === "undefined") return;
  const url = new URL(window.location.href); if (id === "") url.searchParams.delete("inventory"); else url.searchParams.set("inventory", id);
  window.history.pushState({}, "", `${url.pathname}${url.search}`);
}

function State({ title, status, alert, retry }: { title: string; status?: string; alert?: string; retry?: () => void }) {
  return <div className="page"><PageHeader title={title} description="Authorized product data for the selected scope." />{status && <p role="status">{status}</p>}{alert && <div role="alert">{alert}</div>}{retry && <Button onClick={retry}>Retry</Button>}</div>;
}
