"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { APIClient } from "../../../apps/web/api/client";
import { APIProductError, APITransportError, createAPIClient, requireAPIData } from "../../../apps/web/api/client";
import { decodeAgentMutation, decodeAgentSessionPage, decodeCapabilityPage, decodeHomeSummary, decodeInventoryDetail, decodeInventoryPage, decodeRelationshipPage } from "../../../apps/web/api/decoders";
import type { AgentMutation, AgentOwnershipInput, AgentSession, Capability, HomeSummary, InventoryDetail, InventoryPage, InventorySummary, Relationship } from "../../../apps/web/api/generated";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery, type QueryStatus } from "../../api/query";
import { Button, Card, Drawer, Field, MetricGrid, PageHeader } from "../../components/ui";

export type AgentListFilters = {
  risk?: "critical" | "high" | "medium" | "low" | "unknown";
  execution?: "shell" | "code" | "shell_or_code" | "unknown";
  impact?: "high" | "unknown";
};

export type ProductionAgentSecurityAPI = {
  listAgentsPage(cursor?: string, signal?: AbortSignal, owner?: string, filters?: AgentListFilters): Promise<InventoryPage>;
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
    async listAgentsPage(cursor, signal, owner, filters) {
      if (!validAgentListFilters(filters)) throw new APITransportError("invalid_configuration", "Invalid Agent evidence filters");
      if (owner !== undefined && !validOwnerSelector(owner)) throw new APITransportError("invalid_configuration", "Invalid Agent owner selector");
      if (cursor !== undefined && (!/^[A-Za-z0-9_-]{2,512}$/.test(cursor))) throw new APITransportError("invalid_configuration", "Invalid Agent page cursor");
      signal?.throwIfAborted();
      const page = requireAPIData(await client.GET("/api/v1/agents", { params: { query: { limit: 100, ...(cursor === undefined ? {} : { cursor }), ...(owner === undefined ? {} : { owner }), ...filters } }, signal }), decodeInventoryPage);
      signal?.throwIfAborted();
      if (page.items.length > 100 || (page.page_info.has_more && (page.items.length === 0 || page.page_info.next_cursor === cursor))) throw new APITransportError("invalid_response", "Invalid Agent page continuation");
      return page;
    },
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

function validAgentListFilters(filters: AgentListFilters | undefined): boolean {
  if (filters === undefined) return true;
  if (!filters || typeof filters !== "object" || Object.getPrototypeOf(filters) !== Object.prototype || Object.getOwnPropertySymbols(filters).length !== 0) return false;
  const allowed = { risk: ["critical", "high", "medium", "low", "unknown"], execution: ["shell", "code", "shell_or_code", "unknown"], impact: ["high", "unknown"] };
  return Object.getOwnPropertyNames(filters).every(key => {
    if (!(key === "risk" || key === "execution" || key === "impact")) return false;
    const descriptor = Object.getOwnPropertyDescriptor(filters, key)!;
    return descriptor.enumerable === true && "value" in descriptor && (descriptor.value === undefined || allowed[key].includes(descriptor.value));
  });
}

function hasAgentListFilters(filters: AgentListFilters | undefined): boolean {
  return filters?.risk !== undefined || filters?.execution !== undefined || filters?.impact !== undefined;
}

function validOwnerSelector(owner: string): boolean {
  const characters = Array.from(owner);
  if (characters.length > 128 || new TextEncoder().encode(owner).length > 512) return false;
  return characters.every(character => { const code = character.codePointAt(0)!; return code >= 0x20 && code !== 0x7f && !(code >= 0xd800 && code <= 0xdfff); });
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

export function ProductionAgentSecurityView({ path, onNavigate, api: suppliedAPI, canWrite = false, inventoryDetailID, ownerFilterAvailable = false, exposureFiltersAvailable = false }: { path: string; onNavigate(path: string): void; api?: ProductionAgentSecurityAPI; canWrite?: boolean; inventoryDetailID?: string; ownerFilterAvailable?: boolean; exposureFiltersAvailable?: boolean }) {
  const { client, queryScopeKey, queryGeneration } = useAPI();
  const api = useMemo(() => suppliedAPI ?? createProductionAgentSecurityAPI(client), [client, suppliedAPI]);
  const initialDetailID = inventoryDetailID ?? (typeof window === "undefined" ? "" : inventoryDetailIDFromSearch(window.location.search));
  const agentAuthority = JSON.stringify([path, queryScopeKey, queryGeneration]);
  // A URL written by an open drawer is not a new deep link after authority replacement.
  const [initialAgentDetail] = useState(() => ({ authority: agentAuthority, id: initialDetailID }));
  const supported = connectedPaths.has(path);
  const load = useCallback(async (signal?: AbortSignal): Promise<ConnectedData> => {
    switch (path) {
    case "/": return { kind: "home", value: await api.getHomeSummary(signal) };
    case "/inventory/tools": return { kind: "inventory", title: "Tools & MCP", category: "tool", values: await api.listTools(signal) };
    case "/identities": return { kind: "inventory", title: "Identities", category: "identity", values: await api.listIdentities(signal) };
    case "/inventory/runtimes": return { kind: "inventory", title: "Runtimes", category: "runtime", values: await api.listRuntimes(signal) };
    default: throw new Error("Production route unavailable");
    }
  }, [api, path]);
  const query = useAPIQuery(`core:${path}`, load, supported && path !== "/discovery/assets");
  if (path === "/discovery/assets") {
    if (queryScopeKey === null) return <State title="Agents" status="Revalidating inventory access…" />;
    return <ConnectedAgentPages key={agentAuthority} api={api} initialDetailID={inventoryDetailID !== undefined ? inventoryDetailID : initialAgentDetail.authority === agentAuthority ? initialAgentDetail.id : ""} canWrite={canWrite} ownerFilterAvailable={ownerFilterAvailable} exposureFiltersAvailable={exposureFiltersAvailable} />;
  }
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
  const environmentHealthUnavailable = value.healthy === null;
  const operational = value.high_risk_paths + value.pending_approvals + value.needs_human_runs + value.failed_runs + value.inconclusive_runs > 0 || value.healthy === false;
  return <div className="page"><PageHeader title="Security overview" description={environmentHealthUnavailable ? "Authorized resources only" : "Authoritative posture for the selected scope."} /><MetricGrid metrics={[{ label: "Agents", value: value.agent_count, onClick: () => onNavigate("/discovery/assets") }, { label: "High-risk paths", value: value.high_risk_paths, tone: value.high_risk_paths > 0 ? "danger" : undefined, onClick: () => onNavigate("/exposure/attack-paths") }, { label: "Verified changes", value: value.verified_changes }, { label: "Blocked changes", value: value.blocked_changes }]} />
    {environmentHealthUnavailable && <p role="status">Environment health unavailable</p>}
    {value.healthy === false && <div role="alert" className="form-error">Coverage is degraded</div>}
    {operational && <Card title="Needs attention"><div className="review-summary">
      <button type="button" onClick={() => onNavigate("/exposure/attack-paths")}><span>Critical exposures</span><strong>{value.high_risk_paths}</strong></button>
      <button type="button" onClick={() => onNavigate("/protect/approvals")}><span>Pending approvals</span><strong>{value.pending_approvals} · oldest {value.oldest_approval_age_seconds}s</strong></button>
      <button type="button" onClick={() => onNavigate("/protect/security-agents")}><span>Needs human</span><strong>{value.needs_human_runs}</strong></button>
      <button type="button" onClick={() => onNavigate("/protect/security-agents")}><span>Failed or inconclusive</span><strong>{value.failed_runs + value.inconclusive_runs}</strong></button>
      {!environmentHealthUnavailable && <button type="button" onClick={() => onNavigate("/integrations/sensors")}><span>Stale launch coverage</span><strong>{value.healthy ? "Healthy" : "Degraded"}</strong></button>}
      <button type="button" onClick={() => onNavigate("/protect/security-agents")}><span>Recent containment</span><strong>{value.recent_contained + value.recent_remediated}</strong></button>
    </div></Card>}
  </div>;
}

type InventoryNavigation = {
  status: QueryStatus;
  visible: boolean;
  previous: boolean;
  next: boolean;
  first: boolean;
  onPrevious(): void;
  onNext(): void;
  onFirst(): void;
  retry(): Promise<void>;
  ownerFilterAvailable: boolean;
  ownerFilterBlocked: boolean;
  owner?: string;
  onOwner(owner?: string): void;
  onOwnershipConfirmed(): void;
  exposureFiltersAvailable: boolean;
  agentFiltersBlocked: boolean;
  filtered: boolean;
  onFilters(owner?: string, filters?: AgentListFilters): void;
};

function ConnectedAgentPages({ api, initialDetailID, canWrite, ownerFilterAvailable, exposureFiltersAvailable }: { api: ProductionAgentSecurityAPI; initialDetailID: string; canWrite: boolean; ownerFilterAvailable: boolean; exposureFiltersAvailable: boolean }) {
  const { revisions, invalidate } = useAPI();
  const [navigation, setNavigation] = useState<{ cursor?: string; history: (string | undefined)[]; owner?: string; filters?: AgentListFilters }>({ history: [] });
  const ownerFilterBlocked = navigation.owner !== undefined && !ownerFilterAvailable;
  const agentFiltersBlocked = hasAgentListFilters(navigation.filters) && !exposureFiltersAvailable;
  const filtersBlocked = ownerFilterBlocked || agentFiltersBlocked;
  const revision = revisions.get("core:/discovery/assets") ?? 0;
  const load = useCallback(async (signal?: AbortSignal) => {
    const page = hasAgentListFilters(navigation.filters) ? await api.listAgentsPage(navigation.cursor, signal, navigation.owner, navigation.filters) : navigation.owner === undefined ? await api.listAgentsPage(navigation.cursor, signal) : await api.listAgentsPage(navigation.cursor, signal, navigation.owner);
    const next = page.page_info.next_cursor;
    if (page.page_info.has_more && (!next || page.items.length === 0 || next === navigation.cursor || navigation.history.includes(next))) throw new APITransportError("invalid_response", "Repeated Agent page continuation");
    return page;
  }, [api, navigation]);
  const query = useAPIQuery(JSON.stringify(["core:/discovery/assets", 100, navigation.cursor ?? null, revision, navigation.owner ?? null, navigation.filters?.risk ?? null, navigation.filters?.execution ?? null, navigation.filters?.impact ?? null, filtersBlocked]), load, !filtersBlocked);
  const visible = !filtersBlocked && (query.status === "success" || query.status === "empty") && query.data !== undefined;
  const loading = filtersBlocked || query.status === "idle" || query.status === "loading";
  const controls: InventoryNavigation = {
    status: query.status, visible,
    previous: !loading && query.status !== "forbidden" && navigation.history.length > 0,
    first: !loading && query.status !== "forbidden" && navigation.cursor !== undefined,
    next: visible && query.data?.page_info.has_more === true,
    onNext() {
      const next = query.data?.page_info.next_cursor;
      if (!visible || !next) return;
      setNavigation((current) => ({ ...current, cursor: next, history: [...current.history, current.cursor].slice(-100) }));
    },
    onPrevious() { setNavigation((current) => current.history.length ? { ...current, cursor: current.history.at(-1), history: current.history.slice(0, -1) } : current); },
    onFirst() { setNavigation(current => ({ ...current, cursor: undefined, history: [] })); },
    retry: query.retry,
    ownerFilterAvailable, ownerFilterBlocked, owner: navigation.owner,
    onOwner(owner) { if (owner !== undefined && !ownerFilterAvailable) return; setNavigation(current => ({ owner, filters: current.filters, history: [] })); },
    onOwnershipConfirmed() { invalidate(["core:/discovery/assets"]); },
    exposureFiltersAvailable, agentFiltersBlocked, filtered: navigation.owner !== undefined || hasAgentListFilters(navigation.filters),
    onFilters(owner, filters) {
      if (owner !== undefined && !ownerFilterAvailable || hasAgentListFilters(filters) && !exposureFiltersAvailable || !validAgentListFilters(filters)) return;
      setNavigation({ owner, filters: hasAgentListFilters(filters) ? filters : undefined, history: [] });
    },
  };
  // Keep this state owner mounted through same-scope revision/load/refusal. Its
  // retained ownership intent must outlive a transient list refresh failure.
  return <ConnectedInventory title="Agents" category="agent" values={visible ? query.data!.items : []} api={api} initialDetailID={initialDetailID} canWrite={canWrite} page={controls} />;
}

function ConnectedInventory({ title, category, values, api, initialDetailID, canWrite, page }: { title: string; category: "agent" | "tool" | "identity" | "runtime"; values: readonly InventorySummary[]; api: ProductionAgentSecurityAPI; initialDetailID: string; canWrite: boolean; page?: InventoryNavigation }) {
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
  const [ownerMode, setOwnerMode] = useState<"all" | "unowned" | "exact">("all");
  const [ownerDraft, setOwnerDraft] = useState("");
  const [ownerFilterError, setOwnerFilterError] = useState("");
  const [riskDraft, setRiskDraft] = useState<NonNullable<AgentListFilters["risk"]> | "all">("all");
  const [executionDraft, setExecutionDraft] = useState<NonNullable<AgentListFilters["execution"]> | "all">("all");
  const [impactDraft, setImpactDraft] = useState<NonNullable<AgentListFilters["impact"]> | "all">("all");
  const detailRequest = useRef<AbortController | null>(null);
  const processedDetailIntent = useRef<{ api: ProductionAgentSecurityAPI; category: typeof category; id: string; superseded: boolean } | null>(null);
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
    // Defer an incoming link until the captured ownership change is confirmed.
    // Remember processed links so lock toggles do not reload the old identity.
    if (saving || pending !== null) return;
    const processed = processedDetailIntent.current;
    if (processed?.api === api && processed.category === category && processed.id === initialDetailID) return;
    const intent = { api, category, id: initialDetailID, superseded: false };
    processedDetailIntent.current = intent;
    if (initialDetailID === "") return;
    let completed = false;
    const controller = new AbortController();
    detailRequest.current?.abort(); detailRequest.current = controller;
    const loaders = { agent: api.getAgent, tool: api.getTool, identity: api.getIdentity, runtime: api.getRuntime };
    void loaders[category](initialDetailID, controller.signal).then(async (detail) => ({ detail, context: category === "agent" ? await loadAgentContext(api, initialDetailID, controller.signal) : null })).then(
      ({ detail, context }) => { if (!controller.signal.aborted) { completed = true; setSelected(detail); setAgentContext(context); setOwner(detail.summary.owner); setTeam(detail.summary.team); setTags(detail.summary.tags.join(", ")); setDetailError(false); } },
      () => { if (!controller.signal.aborted) { completed = true; setDetailError(true); } },
    );
    return () => {
      controller.abort();
      // A cleanup-aborted attempt was never processed; StrictMode may set it up again.
      if (!completed && !intent.superseded && processedDetailIntent.current === intent) processedDetailIntent.current = null;
      if (detailRequest.current === controller) detailRequest.current = null;
    };
  }, [api, category, initialDetailID, pending, saving]);
  useEffect(() => () => detailRequest.current?.abort(), []);
  const open = (item: InventorySummary) => {
    if (saving || pending !== null) return;
    // An accepted row selection supersedes the unfinished initial link permanently.
    if (processedDetailIntent.current) processedDetailIntent.current.superseded = true;
    detailRequest.current?.abort(); const controller = new AbortController(); detailRequest.current = controller;
    setInventoryDetailURL(item.id); void loadDetail(item.id, controller.signal);
  };
  const close = () => { if (saving || pending !== null) return; detailRequest.current?.abort(); detailRequest.current = null; setInventoryDetailURL(""); setSelected(null); setAgentContext(null); setMutationError(""); };
  const save = async () => {
    if (!canWrite || category !== "agent" || !selected || saving) return;
    let retained = pending;
    if (!retained) {
      const canonicalTags = [...new Set(tags.split(",").map((value) => value.trim()).filter(Boolean))].sort();
      if (owner.trim() !== owner || team.trim() !== team || owner.length < 1 || owner.length > 128 || team.length < 1 || team.length > 128 || canonicalTags.length > 32 || canonicalTags.some((value) => value.length > 64)) { setMutationError("Enter bounded ownership and canonical tags."); return; }
      retained = { id: selected.summary.id, version: selected.summary.version, input: { owner, team, tags: canonicalTags }, key: `agent_${globalThis.crypto.randomUUID()}` };
      // No earlier detail response may replace the identity whose intent was captured.
      detailRequest.current?.abort(); detailRequest.current = null;
      setPending(retained);
    }
    setSaving(true); setMutationError("");
    try {
      const result = await api.updateAgent(retained.id, retained.version, retained.input, retained.key);
      const next = { ...selected, summary: result.agent };
      setSelected(next);
      if (page?.filtered) { setMutatedRows({}); page.onOwnershipConfirmed(); }
      else setMutatedRows((current) => ({ ...current, [result.agent.id]: result.agent }));
      setPending(null);
    } catch (error) {
      if (error instanceof APIProductError && error.status === 409) {
        setPending(null);
        try { const authoritative = await api.getAgent(retained.id); setSelected(authoritative); setOwner(authoritative.summary.owner); setTeam(authoritative.summary.team); setTags(authoritative.summary.tags.join(", ")); setMutationError("Ownership changed elsewhere. The authoritative record was reloaded."); }
        catch { setMutationError("Ownership changed elsewhere and could not be reloaded."); }
      } else setMutationError("The response was interrupted. Retry reuses the exact ownership change.");
    } finally { setSaving(false); }
  };
  const ownershipLocked = saving || pending !== null;
  const changePage = (navigate: () => void) => {
    if (ownershipLocked) return;
    detailRequest.current?.abort(); detailRequest.current = null;
    setInventoryDetailURL(""); setSelected(null); setAgentContext(null); setDetailError(false);
    setMutationError(""); setMutatedRows({});
    navigate();
  };
  const applyOwnerFilter = () => {
    if (ownershipLocked || !page?.ownerFilterAvailable) return;
    const owner = ownerMode === "all" ? undefined : ownerMode === "unowned" ? "" : ownerDraft;
    if (ownerMode === "exact" && (ownerDraft.length === 0 || !validOwnerSelector(ownerDraft))) { setOwnerFilterError("Enter an exact owner label of 1–128 Unicode characters without control characters."); return; }
    setOwnerFilterError(""); changePage(() => page.onOwner(owner));
  };
  const resetOwnerFilter = () => {
    if (ownershipLocked || !page) return;
    setOwnerMode("all"); setOwnerDraft(""); setOwnerFilterError(""); changePage(() => page.onOwner(undefined));
  };
  const applyAgentFilters = () => {
    if (ownershipLocked || !page?.exposureFiltersAvailable) return;
    const owner = ownerMode === "all" ? undefined : ownerMode === "unowned" ? "" : ownerDraft;
    if (owner !== undefined && !page.ownerFilterAvailable) { setOwnerFilterError("Owner filtering unavailable. Reset the owner filter first."); return; }
    if (ownerMode === "exact" && (ownerDraft.length === 0 || !validOwnerSelector(ownerDraft))) { setOwnerFilterError("Enter an exact owner label of 1–128 Unicode characters without control characters."); return; }
    const filters: AgentListFilters = { ...(riskDraft === "all" ? {} : { risk: riskDraft }), ...(executionDraft === "all" ? {} : { execution: executionDraft }), ...(impactDraft === "all" ? {} : { impact: impactDraft }) };
    setOwnerFilterError(""); changePage(() => page.onFilters(owner, filters));
  };
  const resetAgentFilters = () => {
    if (ownershipLocked || !page) return;
    setOwnerMode("all"); setOwnerDraft(""); setOwnerFilterError(""); setRiskDraft("all"); setExecutionDraft("all"); setImpactDraft("all");
    changePage(() => page.onFilters());
  };
  const filtersBlocked = page?.ownerFilterBlocked || page?.agentFiltersBlocked;
  const visible = page?.visible ?? true;
  const pendingDetail = selected && !visible && ownershipLocked;
  return <div className="page">
    <PageHeader title={title} description="Authorized canonical inventory." />
    {detailError && visible && <div role="alert">Inventory detail unavailable</div>}
    {page && <>
      {(page.ownerFilterAvailable || page.ownerFilterBlocked) && <section aria-label="Agent owner filter">
        {page.ownerFilterAvailable && <>
          <label>Owner filter<select value={ownerMode} disabled={ownershipLocked} onChange={event => { const mode = event.target.value; if (!ownershipLocked && page.ownerFilterAvailable && (mode === "all" || mode === "unowned" || mode === "exact")) { setOwnerMode(mode); setOwnerFilterError(""); } }}><option value="all">All owners</option><option value="unowned">Unowned</option><option value="exact">Exact owner</option></select></label>
          {ownerMode === "exact" && <Field label="Exact owner" value={ownerDraft} maxLength={512} disabled={ownershipLocked} onChange={event => { if (!ownershipLocked && page.ownerFilterAvailable) setOwnerDraft(event.target.value); }} />}
          <Button disabled={ownershipLocked} onClick={applyOwnerFilter}>Apply owner filter</Button>
        </>}
        <Button disabled={ownershipLocked} onClick={resetOwnerFilter}>Reset owner filter</Button>
        {page.ownerFilterBlocked && <p role="alert">Owner filtering unavailable. Reset the filter to request all authorized owners.</p>}
        {ownerFilterError && <p role="alert">{ownerFilterError}</p>}
      </section>}
      {(page.exposureFiltersAvailable || page.agentFiltersBlocked) && <section aria-label="Agent evidence filters">
        {page.exposureFiltersAvailable && <>
          <label>Recorded finding severity<select value={riskDraft} disabled={ownershipLocked} onChange={event => { const value = event.target.value; if (!ownershipLocked && page.exposureFiltersAvailable && (value === "all" || value === "critical" || value === "high" || value === "medium" || value === "low" || value === "unknown")) setRiskDraft(value); }}><option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unknown">Unknown</option></select></label>
          <label>Execution evidence<select value={executionDraft} disabled={ownershipLocked} onChange={event => { const value = event.target.value; if (!ownershipLocked && page.exposureFiltersAvailable && (value === "all" || value === "shell" || value === "code" || value === "shell_or_code" || value === "unknown")) setExecutionDraft(value); }}><option value="all">All</option><option value="shell">Shell observed</option><option value="code">Code permission observed</option><option value="shell_or_code">Shell or code evidence</option><option value="unknown">Unknown evidence</option></select></label>
          <label>Sensitive / high-impact reach<select value={impactDraft} disabled={ownershipLocked} onChange={event => { const value = event.target.value; if (!ownershipLocked && page.exposureFiltersAvailable && (value === "all" || value === "high" || value === "unknown")) setImpactDraft(value); }}><option value="all">All</option><option value="high">Supported reach</option><option value="unknown">Unknown evidence</option></select></label>
          <p>Severity is the highest recorded unresolved finding you may view. Execution and reach reflect supported source evidence, not proof of runtime execution. Unknown is not a safe or negative result.</p>
          <Button disabled={ownershipLocked} onClick={applyAgentFilters}>Apply Agent filters</Button>
        </>}
        <Button disabled={ownershipLocked} onClick={resetAgentFilters}>Reset Agent filters</Button>
        {page.agentFiltersBlocked && <p role="alert">Agent filters unavailable. Reset the filters to request all authorized Agents.</p>}
      </section>}
      {!filtersBlocked && (page.status === "idle" || page.status === "loading") && <p role="status">Loading authorized Agent page…</p>}
      {!filtersBlocked && page.status === "forbidden" && <p role="alert">Authorization rejected</p>}
      {!filtersBlocked && (page.status === "error" || page.status === "stale") && <div role="alert">Agent page unavailable. Reload before making changes.</div>}
      {!filtersBlocked && (page.status === "error" || page.status === "stale") && <Button onClick={() => void page.retry()}>Retry page</Button>}
      <nav aria-label="Agent pages">
        <Button disabled={!page.first || ownershipLocked} onClick={() => changePage(page.onFirst)}>First page</Button>
        <Button disabled={!page.previous || ownershipLocked} onClick={() => changePage(page.onPrevious)}>Previous page</Button>
        <Button disabled={!page.next || ownershipLocked} onClick={() => changePage(page.onNext)}>Next page</Button>
      </nav>
    </>}
    {visible && <Card>{rows.length === 0 ? <p>No records in this scope.</p> : <div className="table-scroll"><table className="data-table"><thead><tr><th>Name</th><th>Owner</th><th>Freshness</th><th>Last seen</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><button className="row-title" aria-label={`Open ${item.name}`} disabled={ownershipLocked} onClick={() => open(item)}>{item.name}</button></td><td>{item.owner || "Unowned"}</td><td>{category === "agent" ? sourceFreshnessLabel(item.freshness_state) : item.freshness_state}</td><td>{category === "agent" ? <time dateTime={item.last_seen}>{item.last_seen}</time> : item.last_seen}</td></tr>)}</tbody></table></div>}</Card>}
    {pendingDetail && <Drawer open title="Ownership change pending" closeDisabled onClose={close}>
      <p role="status">The ownership response is unconfirmed. Retry retains the exact change while this scope remains authorized.</p>
      {mutationError && <p role="alert">{mutationError}</p>}
      <Button disabled={saving || !canWrite || page?.status === "forbidden"} onClick={() => void save()}>Retry ownership change</Button>
    </Drawer>}
    {selected && visible && <Drawer open title={selected.summary.name} closeDisabled={ownershipLocked} onClose={close}>
      <div className="detail-content"><h3>Canonical record</h3><code>{selected.summary.id}</code><h3>Ownership</h3><p>{selected.summary.owner || "Unowned"} · {selected.summary.team || "No team"}</p>
        {canWrite && category === "agent" && <section aria-label="Agent ownership controls">
          <Field label="Owner" value={owner} disabled={ownershipLocked} maxLength={128} onChange={(event) => setOwner(event.target.value)} />
          <Field label="Team" value={team} disabled={ownershipLocked} maxLength={128} onChange={(event) => setTeam(event.target.value)} />
          <Field label="Tags" hint="Comma-separated, up to 32 tags." value={tags} disabled={ownershipLocked} maxLength={2078} onChange={(event) => setTags(event.target.value)} />
          <Button disabled={saving} onClick={() => void save()}>{pending ? "Retry ownership change" : "Save ownership"}</Button>
        </section>}
        {mutationError && <p role="alert">{mutationError}</p>}
        <h3>Evidence and freshness</h3>{category === "agent" ? <p>{selected.summary.evidence_id} · observed <time dateTime={selected.summary.observed_at}>{selected.summary.observed_at}</time> · {sourceFreshnessLabel(selected.summary.freshness_state)} · source expiry <time dateTime={selected.summary.fresh_until}>{selected.summary.fresh_until}</time></p> : <p>{selected.summary.evidence_id} · observed {selected.summary.observed_at} · {selected.summary.freshness_state}</p>}
        <h3>Source authority</h3><p>{selected.sources.length} source observation{selected.sources.length === 1 ? "" : "s"} · confidence {selected.summary.confidence_basis_points / 100}%</p>
        {category === "agent" && <InventorySourceEvidence detail={selected} />}
        {category === "agent" && agentContext && <AgentContextDetail value={agentContext} />}
      </div>
    </Drawer>}
  </div>;
}

function sourceFreshnessLabel(state: InventorySummary["freshness_state"]): string {
  return state === "fresh" ? "Source fresh at last API read" : "Source stale at last API read";
}

function InventorySourceEvidence({ detail }: { detail: InventoryDetail }) {
  return <section aria-label="Inventory source evidence">
    <h3>Inventory source evidence</h3>
    <p>Source observations and expiry timestamps from this inventory read.</p>
    <div className="table-scroll"><table className="data-table"><thead><tr><th>Selection</th><th>Provider</th><th>Source</th><th>Observed</th><th>Expires</th><th>Snapshot</th><th>Generation</th><th>Evidence</th></tr></thead>
      <tbody>{detail.sources.map(source => <tr key={`${source.integration_id}/${source.provider}/${source.source}/${source.source_identifier}`}>
        <td>{source.winning ? "Winning source" : "Additional source"}</td><td>{source.provider}</td><td>{source.source}</td>
        <td><time dateTime={source.observed_at}>{source.observed_at}</time></td><td><time dateTime={source.fresh_until}>{source.fresh_until}</time></td>
        <td><code>{source.snapshot_id}</code></td><td>{source.generation}</td><td><code>{source.evidence_id}</code></td>
      </tr>)}</tbody>
    </table></div>
  </section>;
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
  return <><h3>Effective capabilities</h3>{value.capabilities.length === 0 ? <p>No capability evidence recorded.</p> : <ul>{value.capabilities.map((capability) => <li key={`${capability.category}/${capability.target_id}/${capability.outcome}`}>{capability.category} · {capability.state} · {capability.outcome} <code>{capability.target_id}</code> · evidence {capability.evidence_ids.map((id) => <code key={id}>{id}</code>)}</li>)}</ul>}<h3>Relationships</h3>{value.relationships.length === 0 ? <p>No Agent relationships recorded.</p> : <ul>{value.relationships.map((relationship) => <li key={relationship.id}>{relationship.type} · <code>{relationship.from_id}</code> → <code>{relationship.to_id}</code> · evidence <code>{relationship.evidence_id}</code></li>)}</ul>}<h3>Sessions</h3>{value.sessions.length === 0 ? <p>No observed sessions.</p> : <ul>{value.sessions.map((session) => <li key={session.id}><code>{session.id}</code> · started {session.started_at}</li>)}</ul>}<h3>Recorded blocking capability evidence</h3><p>{blocked.length === 0 ? "No blocking capability evidence recorded." : `${blocked.length} recorded blocking ${blocked.length === 1 ? "capability" : "capabilities"}.`}</p><h3>Runtime policy coverage</h3><p>Policy coverage unavailable</p><h3>Runtime sensor coverage</h3><p>Runtime sensor coverage unavailable</p></>;
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
