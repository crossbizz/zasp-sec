"use client";

import { useEffect, useMemo, useState } from "react";
import { APITransportError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import type { RuntimeSession, RuntimeSessionPage, RuntimeSessionSearchStatus } from "../../../apps/web/api/generated";
import { decodeRuntimeSessionPage } from "../../../apps/web/api/runtime-session-decoders";
import { Badge, Button, Card, Drawer, EmptyState, Field, LoadingState, PageHeader, Select } from "../../components/ui";
import { SessionsComplianceView } from "./SessionsComplianceView";
import { createRuntimeSessionTimelineAPI, RuntimeSessionTimeline, type RuntimeSessionTimelineAPI } from "./RuntimeSessionTimeline";

const textSelectors = [
  ["agent_id", "Agent ID", 40], ["principal_id", "Principal ID", 40],
  ["tool", "Tool", 256], ["process", "Process", 4096], ["file", "File", 4096],
  ["domain", "Domain", 253], ["credential_id", "Credential ID", 40], ["resource", "Resource", 4096],
] as const;
type TextSelector = typeof textSelectors[number][0];
export type RuntimeSessionFilters = Partial<Record<TextSelector | "from" | "to", string>> & { decision?: "allow" | "monitor" | "block" };
export interface RuntimeSessionsAPI {
  list(filters: RuntimeSessionFilters, cursor: string | null, signal: AbortSignal): Promise<RuntimeSessionPage>;
}

export function createRuntimeSessionsAPI(client: APIClient): RuntimeSessionsAPI {
  return {
    async list(filters, cursor, signal) {
      const result = requireAPIData<RuntimeSessionPage>(await client.GET("/api/v1/sessions", {
        params: { query: { ...filters, kind: "runtime", limit: 25, ...(cursor ? { cursor } : {}) } }, signal,
      }), decodeRuntimeSessionPage);
      if (!result.search) throw new APITransportError("invalid_response", "Runtime search checkpoint is missing");
      return result;
    },
  };
}

export function ProductionSessionsView({ client, canRevokeConsole }: { client: APIClient; canRevokeConsole: boolean }) {
  const [surface, setSurface] = useState<"runtime" | "console">("runtime");
  const api = useMemo(() => createRuntimeSessionsAPI(client), [client]);
  const timelineAPI = useMemo(() => createRuntimeSessionTimelineAPI(client), [client]);
  return <>
    <div className="page" aria-label="Session types">
      <Button aria-pressed={surface === "runtime"} onClick={() => setSurface("runtime")}>Agent runtime</Button>
      <Button aria-pressed={surface === "console"} onClick={() => setSurface("console")}>Console logins</Button>
    </div>
    {surface === "runtime" ? <RuntimeSessionsView api={api} timelineAPI={timelineAPI} /> : <SessionsComplianceView surface="sessions" client={client} canMutate={canRevokeConsole} />}
  </>;
}

type Query = { filters: RuntimeSessionFilters; cursor: string | null; page: number };
type Load = { api: RuntimeSessionsAPI; query: Query; page?: RuntimeSessionPage; error?: boolean };

export function RuntimeSessionsView({ api, timelineAPI }: { api: RuntimeSessionsAPI; timelineAPI?: RuntimeSessionTimelineAPI }) {
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [filterError, setFilterError] = useState<string | null>(null);
  const [query, setQuery] = useState<Query>({ filters: {}, cursor: null, page: 1 });
  const [load, setLoad] = useState<Load | null>(null);
  const [selection, setSelection] = useState<{ id: string; query: Query; api: RuntimeSessionsAPI } | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => {
      if (controller.signal.aborted) return;
      void api.list(query.filters, query.cursor, controller.signal).then(page => {
        if (!controller.signal.aborted) setLoad({ api, query, page });
      }).catch(() => {
        if (!controller.signal.aborted) setLoad({ api, query, error: true });
      });
    });
    return () => controller.abort();
  }, [api, query]);
  // Hide old data synchronously when query or scoped API identity changes,
  // including the render before effect cleanup cancels an in-flight response.
  const current = load?.api === api && load.query === query ? load : null;
  const page = current?.page;
  const loading = !current;
  const search = () => {
    try {
      const filters: RuntimeSessionFilters = {};
      for (const [key] of textSelectors) if (draft[key]) filters[key] = draft[key];
      if (draft.decision) {
        if (!["allow", "monitor", "block"].includes(draft.decision)) throw new Error();
        filters.decision = draft.decision as RuntimeSessionFilters["decision"];
      }
      for (const key of ["from", "to"] as const) if (draft[key]) filters[key] = utcInput(draft[key]);
      if (filters.from && filters.to && Date.parse(filters.from) > Date.parse(filters.to)) throw new Error();
      setFilterError(null);
      setQuery({ filters, cursor: null, page: 1 });
    } catch { setFilterError("Enter a valid UTC time range with From no later than To."); }
  };
  return <div className="page">
    <PageHeader title="Runtime session investigations" description="Search observed agent activity in this authorized scope. Unknown attribution stays explicit." />
    <Card title="Structured filters">
      <form onSubmit={event => { event.preventDefault(); search(); }}>
        <div className="dashboard-grid">
          {textSelectors.map(([key, label, maximum]) => <Field key={key} label={label} value={draft[key] ?? ""} maxLength={maximum} onChange={event => setDraft({ ...draft, [key]: event.target.value })} />)}
          <Select label="Decision" value={draft.decision ?? ""} onChange={event => setDraft({ ...draft, decision: event.target.value })}>
            <option value="">Any observed decision</option><option value="allow">Allow</option><option value="monitor">Monitor</option><option value="block">Block</option>
          </Select>
          <Field label="From (UTC)" type="datetime-local" step="1" value={draft.from ?? ""} onChange={event => setDraft({ ...draft, from: event.target.value })} />
          <Field label="To (UTC)" type="datetime-local" step="1" value={draft.to ?? ""} onChange={event => setDraft({ ...draft, to: event.target.value })} />
        </div>
        <p>All filters must match the same observed event. Counts describe the whole investigation. Unobserved metadata cannot match a filter.</p>
        {filterError && <p role="alert">{filterError}</p>}
        <Button type="submit">Search sessions</Button>
        <Button type="button" onClick={() => { setDraft({}); setFilterError(null); setQuery({ filters: {}, cursor: null, page: 1 }); }}>Clear filters</Button>
      </form>
    </Card>
    {loading && <LoadingState label="Searching runtime sessions…" />}
    {current?.error && <div role="alert"><p>Runtime sessions could not be loaded. Results are unavailable, not empty.</p><Button onClick={() => setQuery({ ...query })}>Retry runtime search</Button></div>}
    {page && <>
      {page.search ? <SearchCheckpoint status={page.search} /> : <p role="alert">Indexing status is unavailable. Search completeness is unknown.</p>}
      {page.items.length === 0 ? <EmptyState title="No matching runtime sessions" description="No indexed events matched these filters. Check indexing status and collection coverage before drawing conclusions." /> : page.items.map(item => <RuntimeSessionSummary key={item.id} item={item} onSelect={timelineAPI ? () => setSelection({ id: item.id, query, api }) : undefined} />)}
      <nav aria-label="Runtime session pages">
        <Button disabled={loading || query.page === 1} onClick={() => setQuery({ ...query, cursor: null, page: 1 })}>First session page</Button>
        <span>Page {query.page}</span>
        <Button disabled={loading || !page.page_info.has_more} onClick={() => setQuery({ ...query, cursor: page.page_info.next_cursor, page: query.page + 1 })}>Next session page</Button>
      </nav>
      <p>Pages are not a snapshot. Newly indexed activity may change results; start again from the first page to refresh.</p>
    </>}
    {selection && selection.query === query && selection.api === api && timelineAPI && <Drawer open title="Runtime timeline" onClose={() => setSelection(null)}><RuntimeSessionTimeline key={selection.id} id={selection.id} api={timelineAPI} /></Drawer>}
  </div>;
}

function SearchCheckpoint({ status }: { status: RuntimeSessionSearchStatus }) {
  const label = { empty: "No indexing checkpoints yet", catching_up: "Indexing is catching up", blocked: "Some indexing work is quarantined", current: "Known indexing work is current" }[status.state];
  const count = (value: number, capped: boolean) => `${value.toLocaleString("en-US")}${capped ? "+" : ""}`;
  return <Card title="Search indexing status">
    <p><Badge tone={status.state === "blocked" || status.state === "catching_up" ? "warning" : "neutral"}>{label}</Badge></p>
    <p>{count(status.pending_batches, status.pending_batches_capped)} pending batches · {count(status.quarantined_batches, status.quarantined_batches_capped)} quarantined batches</p>
    <p>Checked <time dateTime={status.checked_at}>{status.checked_at}</time>{status.last_indexed_at && <> · Last indexed <time dateTime={status.last_indexed_at}>{status.last_indexed_at}</time></>}</p>
    {status.oldest_pending_at && <p>Oldest pending batch: <time dateTime={status.oldest_pending_at}>{status.oldest_pending_at}</time></p>}
    <p>Observed metadata only. Checkpoints do not establish complete collection, complete selector coverage, or current provider health.</p>
  </Card>;
}

function RuntimeSessionSummary({ item, onSelect }: { item: RuntimeSession; onSelect?: () => void }) {
  return <Card title={item.kind === "unattributed" ? "Unattributed evidence" : item.id} action={onSelect && <Button aria-label={`Open runtime timeline ${item.id}`} onClick={onSelect}>View timeline</Button>}>
    {item.kind === "unattributed" && <p>This is an evidence collection, not an inferred agent session.</p>}
    <p>{item.agent_id ?? "Unknown or multiple agents"} · Principal: {item.principal_id ?? "Unknown"}</p>
    <p>{item.event_count.toLocaleString("en-US")} canonical events</p>
    <p>{(["exact", "strong", "probable", "unattributed"] as const).map(confidence => <Badge key={confidence} tone={confidence === "exact" ? "success" : confidence === "strong" ? "info" : confidence === "probable" ? "warning" : "neutral"}>{confidence}: {item.confidence_counts[confidence].toLocaleString("en-US")}</Badge>)}</p>
    <p>First event <time dateTime={item.first_event_at}>{item.first_event_at}</time> · Last event <time dateTime={item.last_event_at}>{item.last_event_at}</time></p>
    <p>Summary projected <time dateTime={item.projected_at}>{item.projected_at}</time></p>
  </Card>;
}

function utcInput(value: string): string {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(value)) throw new Error();
  const canonical = value.length === 16 ? `${value}:00Z` : `${value}Z`;
  const parsed = new Date(canonical);
  if (!Number.isFinite(parsed.valueOf()) || parsed.toISOString().replace(".000Z", "Z") !== canonical) throw new Error();
  return canonical;
}
