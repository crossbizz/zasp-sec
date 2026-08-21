"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { APIClient } from "../../../apps/web/api/client";
import { APIProductError, APITransportError, createAPIClient, requireAPIData } from "../../../apps/web/api/client";
import { decodeAgentMutation, decodeAgentSessionPage, decodeCapabilityPage, decodeHomeSummary, decodeInventoryDetail, decodeInventoryPage, decodeRelationshipPage } from "../../../apps/web/api/decoders";
import type { AgentMutation, AgentOwnershipInput, AgentSession, Capability, HomeSummary, InventoryDetail, InventorySummary, Relationship } from "../../../apps/web/api/generated";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button, Card, Drawer, Field, MetricGrid, PageHeader } from "../../components/ui";

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
  updateAgent(id: string, expectedVersion: number, input: AgentOwnershipInput, idempotencyKey: string, signal?: AbortSignal): Promise<AgentMutation>;
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
    async updateAgent(id, expectedVersion, input, idempotencyKey, signal) {
      if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1 || expectedVersion >= 1_000_000 || !/^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/.test(idempotencyKey)) throw new APITransportError("invalid_configuration", "Invalid Agent mutation precondition");
      const result = await client.PATCH("/api/v1/agents/{id}", { params: { path: { id }, header: { "Idempotency-Key": idempotencyKey, "If-Match": `"${expectedVersion}"`, "X-CSRF-Token": "" } }, body: input, signal });
      const mutation = requireAPIData(result, decodeAgentMutation);
      if (result.response.headers.get("ETag") !== `"${mutation.agent.version}"` || result.response.headers.get("X-Audit-ID") !== mutation.audit_id) throw new APITransportError("invalid_response", "Agent mutation omitted exact evidence headers");
      return mutation;
    },
    async getHomeSummary(signal) { return requireAPIData(await client.GET("/api/v1/home/summary", { signal }), decodeHomeSummary); },
  };
}

const inventoryPageBounds = { maximumItems: 10_000, maximumPages: 100 } as const;

type ConnectedData =
  | { kind: "home"; value: HomeSummary }
  | { kind: "inventory"; title: string; category: "agent" | "tool" | "identity" | "runtime"; values: readonly InventorySummary[] };

type AgentContext = {
  capabilities: readonly Capability[];
  relationships: readonly Relationship[];
  sessions: readonly AgentSession[];
};

export function ProductionAgentSecurityView({ path, onNavigate, api: suppliedAPI, canWrite = false }: { path: string; onNavigate(path: string): void; api?: ProductionAgentSecurityAPI; canWrite?: boolean }) {
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
  return <>{query.status === "stale" && <div role="alert" className="form-error">Showing stale data.</div>}<ConnectedDataView data={query.data} api={api} initialDetailID={initialDetailID} onNavigate={onNavigate} canWrite={canWrite} /></>;
}

const connectedPaths = new Set(["/", "/discovery/assets", "/inventory/tools", "/identities", "/inventory/runtimes"]);

function ConnectedDataView({ data, api, initialDetailID, onNavigate, canWrite }: { data: ConnectedData; api: ProductionAgentSecurityAPI; initialDetailID: string; onNavigate(path: string): void; canWrite: boolean }) {
  return data.kind === "home" ? <ConnectedHome value={data.value} onNavigate={onNavigate} /> : <ConnectedInventory key={data.category} title={data.title} category={data.category} values={data.values} api={api} initialDetailID={initialDetailID} canWrite={canWrite} />;
}

function ConnectedHome({ value, onNavigate }: { value: HomeSummary; onNavigate(path: string): void }) {
  return <div className="page"><PageHeader title="Security overview" description="Authoritative posture for the selected scope." /><MetricGrid metrics={[{ label: "Agents", value: value.agent_count, onClick: () => onNavigate("/discovery/assets") }, { label: "High-risk paths", value: value.high_risk_paths, tone: value.high_risk_paths > 0 ? "danger" : undefined, onClick: () => onNavigate("/exposure/attack-paths") }, { label: "Verified changes", value: value.verified_changes }, { label: "Blocked changes", value: value.blocked_changes }]} />{value.attention_required && <div role="alert" className="form-error">Attention required</div>}</div>;
}

function ConnectedInventory({ title, category, values, api, initialDetailID, canWrite }: { title: string; category: "agent" | "tool" | "identity" | "runtime"; values: readonly InventorySummary[]; api: ProductionAgentSecurityAPI; initialDetailID: string; canWrite: boolean }) {
  const [mutatedRows, setMutatedRows] = useState<Record<string, InventorySummary>>({});
  const rows = values.map((value) => mutatedRows[value.id] && mutatedRows[value.id].version >= value.version ? mutatedRows[value.id] : value);
  const [selected, setSelected] = useState<InventoryDetail | null>(null);
  const [agentContext, setAgentContext] = useState<AgentContext | null>(null);
  const [detailError, setDetailError] = useState(false);
  const [owner, setOwner] = useState("");
  const [team, setTeam] = useState("");
  const [tags, setTags] = useState("");
  const [mutationError, setMutationError] = useState("");
  const [saving, setSaving] = useState(false);
  const [pending, setPending] = useState<{ id: string; version: number; input: AgentOwnershipInput; key: string } | null>(null);
  const detailRequest = useRef<AbortController | null>(null);
  const loadDetail = async (id: string, signal?: AbortSignal) => {
    const loaders = { agent: api.getAgent, tool: api.getTool, identity: api.getIdentity, runtime: api.getRuntime };
    try {
      const detail = await loaders[category](id, signal);
      const context = category === "agent" ? await loadAgentContext(api, id, signal) : null;
      if (signal?.aborted) return;
      setSelected(detail); setAgentContext(context); setOwner(detail.summary.owner); setTeam(detail.summary.team); setTags(detail.summary.tags.join(", ")); setDetailError(false);
    }
    catch { if (!signal?.aborted) setDetailError(true); }
  };
  useEffect(() => {
    if (initialDetailID === "") return;
    const controller = new AbortController();
    detailRequest.current?.abort(); detailRequest.current = controller;
    const loaders = { agent: api.getAgent, tool: api.getTool, identity: api.getIdentity, runtime: api.getRuntime };
    void loaders[category](initialDetailID, controller.signal).then(async (detail) => ({ detail, context: category === "agent" ? await loadAgentContext(api, initialDetailID, controller.signal) : null })).then(
      ({ detail, context }) => { if (!controller.signal.aborted) { setSelected(detail); setAgentContext(context); setOwner(detail.summary.owner); setTeam(detail.summary.team); setTags(detail.summary.tags.join(", ")); setDetailError(false); } },
      () => { if (!controller.signal.aborted) setDetailError(true); },
    );
    return () => { controller.abort(); if (detailRequest.current === controller) detailRequest.current = null; };
  }, [api, category, initialDetailID]);
  useEffect(() => () => detailRequest.current?.abort(), []);
  const open = (item: InventorySummary) => {
    detailRequest.current?.abort(); const controller = new AbortController(); detailRequest.current = controller;
    setInventoryDetailURL(item.id); void loadDetail(item.id, controller.signal);
  };
  const close = () => { if (saving) return; detailRequest.current?.abort(); detailRequest.current = null; setInventoryDetailURL(""); setSelected(null); setAgentContext(null); setMutationError(""); };
  const save = async () => {
    if (!canWrite || category !== "agent" || !selected || saving) return;
    let retained = pending;
    if (!retained) {
      const canonicalTags = [...new Set(tags.split(",").map((value) => value.trim()).filter(Boolean))].sort();
      if (owner.trim() !== owner || team.trim() !== team || owner.length < 1 || owner.length > 128 || team.length < 1 || team.length > 128 || canonicalTags.length > 32 || canonicalTags.some((value) => value.length > 64)) { setMutationError("Enter bounded ownership and canonical tags."); return; }
      retained = { id: selected.summary.id, version: selected.summary.version, input: { owner, team, tags: canonicalTags }, key: `agent_${globalThis.crypto.randomUUID()}` };
      setPending(retained);
    }
    setSaving(true); setMutationError("");
    try {
      const result = await api.updateAgent(retained.id, retained.version, retained.input, retained.key);
      const next = { ...selected, summary: result.agent };
      setSelected(next); setMutatedRows((current) => ({ ...current, [result.agent.id]: result.agent })); setPending(null);
    } catch (error) {
      if (error instanceof APIProductError && error.status === 409) {
        setPending(null);
        try { const authoritative = await api.getAgent(retained.id); setSelected(authoritative); setOwner(authoritative.summary.owner); setTeam(authoritative.summary.team); setTags(authoritative.summary.tags.join(", ")); setMutationError("Ownership changed elsewhere. The authoritative record was reloaded."); }
        catch { setMutationError("Ownership changed elsewhere and could not be reloaded."); }
      } else setMutationError("The response was interrupted. Retry reuses the exact ownership change.");
    } finally { setSaving(false); }
  };
  return <div className="page"><PageHeader title={title} description="Authorized canonical inventory." />{detailError && <div role="alert">Inventory detail unavailable</div>}<Card>{rows.length === 0 ? <p>No records in this scope.</p> : <div className="table-scroll"><table className="data-table"><thead><tr><th>Name</th><th>Owner</th><th>Freshness</th><th>Last seen</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><button className="row-title" aria-label={`Open ${item.name}`} onClick={() => open(item)}>{item.name}</button></td><td>{item.owner || "Unowned"}</td><td>{item.freshness_state}</td><td>{item.last_seen}</td></tr>)}</tbody></table></div>}</Card>{selected && <Drawer open title={selected.summary.name} closeDisabled={saving} onClose={close}><div className="detail-content"><h3>Canonical record</h3><code>{selected.summary.id}</code><h3>Ownership</h3><p>{selected.summary.owner || "Unowned"} · {selected.summary.team || "No team"}</p>{canWrite && category === "agent" && <section aria-label="Agent ownership controls"><Field label="Owner" value={owner} disabled={saving || pending !== null} maxLength={128} onChange={(event) => setOwner(event.target.value)} /><Field label="Team" value={team} disabled={saving || pending !== null} maxLength={128} onChange={(event) => setTeam(event.target.value)} /><Field label="Tags" hint="Comma-separated, up to 32 tags." value={tags} disabled={saving || pending !== null} maxLength={2078} onChange={(event) => setTags(event.target.value)} /><Button disabled={saving} onClick={() => void save()}>{pending ? "Retry ownership change" : "Save ownership"}</Button></section>}{mutationError && <p role="alert">{mutationError}</p>}<h3>Evidence and freshness</h3><p>{selected.summary.evidence_id} · observed {selected.summary.observed_at} · {selected.summary.freshness_state}</p><h3>Source authority</h3><p>{selected.sources.length} source observation{selected.sources.length === 1 ? "" : "s"} · confidence {selected.summary.confidence_basis_points / 100}%</p>{category === "agent" && agentContext && <AgentContextDetail value={agentContext} />}</div></Drawer>}</div>;
}

async function loadAgentContext(api: ProductionAgentSecurityAPI, id: string, signal?: AbortSignal): Promise<AgentContext> {
  const [capabilities, relationships, sessions] = await Promise.all([
    api.getAgentCapabilities(id, signal),
    api.getAgentRelationships(id, signal),
    api.listAgentSessions(id, signal),
  ]);
  return { capabilities, relationships, sessions };
}

function AgentContextDetail({ value }: { value: AgentContext }) {
  const blocked = value.capabilities.filter((capability) => capability.state === "blocked");
  return <><h3>Effective capabilities</h3>{value.capabilities.length === 0 ? <p>No capability evidence recorded.</p> : <ul>{value.capabilities.map((capability) => <li key={`${capability.category}/${capability.target_id}/${capability.outcome}`}>{capability.category} · {capability.state} · {capability.outcome} <code>{capability.target_id}</code> · evidence {capability.evidence_ids.map((id) => <code key={id}>{id}</code>)}</li>)}</ul>}<h3>Relationships</h3>{value.relationships.length === 0 ? <p>No Agent relationships recorded.</p> : <ul>{value.relationships.map((relationship) => <li key={relationship.id}>{relationship.type} · <code>{relationship.from_id}</code> → <code>{relationship.to_id}</code> · evidence <code>{relationship.evidence_id}</code></li>)}</ul>}<h3>Sessions</h3>{value.sessions.length === 0 ? <p>No observed sessions.</p> : <ul>{value.sessions.map((session) => <li key={session.id}><code>{session.id}</code> · started {session.started_at}</li>)}</ul>}<h3>Runtime policy coverage</h3><p>{blocked.length === 0 ? "No blocking capability evidence is active." : `${blocked.length} capability ${blocked.length === 1 ? "is" : "are"} covered by active blocking evidence.`}</p></>;
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
