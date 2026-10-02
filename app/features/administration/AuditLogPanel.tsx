"use client";

import { useEffect, useRef, useState } from "react";
import { normalizeAuditFilters, type AuditFilters, type AuditLogAPI } from "../../../apps/web/api/audit-log";
import { APIProductError } from "../../../apps/web/api/client";
import type { AuditEventPage } from "../../../apps/web/api/generated";
import { Badge, Button, Card, EmptyState, Field, LoadingState, Select } from "../../components/ui";

export type AuditReadBoundary = {
  identityKey: string | null;
  getSessionInvalidationGeneration?(): number;
  getScopeStaleGeneration?(): number;
};
type Query = { filters: AuditFilters; cursor?: string };
type Result = { api: AuditLogAPI | null; query: Query; error?: boolean };
const unscoped: AuditReadBoundary = { identityKey: "standalone" };

export function AuditLogPanel({ api, boundary = unscoped }: { api: AuditLogAPI | null; boundary?: AuditReadBoundary }) {
  if (boundary.identityKey === null) return <LoadingState label="Revalidating audit access…" />;
  return <AuditLogBrowser key={boundary.identityKey} api={api} boundary={boundary} />;
}

function AuditLogBrowser({ api, boundary }: { api: AuditLogAPI | null; boundary: AuditReadBoundary }) {
  const [draft, setDraft] = useState<AuditFilters>({});
  const [filterError, setFilterError] = useState<string | null>(null);
  const [query, setQuery] = useState<Query>({ filters: {} });
  const [result, setResult] = useState<Result | null>(null);
  const [retained, setRetained] = useState<{ api: AuditLogAPI; filters: AuditFilters; page: AuditEventPage } | null>(null);
  const controller = useRef<AbortController | null>(null);
  const { getSessionInvalidationGeneration, getScopeStaleGeneration } = boundary;
  useEffect(() => {
    const read = new AbortController();
    controller.current = read;
    const sessionGeneration = getSessionInvalidationGeneration?.();
    const scopeGeneration = getScopeStaleGeneration?.();
    const current = () => !read.signal.aborted && getSessionInvalidationGeneration?.() === sessionGeneration && getScopeStaleGeneration?.() === scopeGeneration;
    queueMicrotask(() => {
      if (!current()) return;
      if (!api) { setResult({ api, query, error: true }); return; }
      void api.page(query.filters, query.cursor, 50, read.signal).then(page => {
        if (!current()) return;
        setRetained({ api, filters: query.filters, page });
        setResult({ api, query });
      }).catch(error => {
        if (current()) {
          if (error instanceof APIProductError && error.status === 403 && error.product.code === "request_forbidden") setRetained(null);
          setResult({ api, query, error: true });
        }
      });
    });
    return () => read.abort();
  }, [api, query, getSessionInvalidationGeneration, getScopeStaleGeneration]);

  const page = retained?.api === api && retained.filters === query.filters ? retained.page : null;
  const settled = result?.api === api && result?.query === query;
  const loading = !settled;
  const error = settled && result.error;
  const read = (next: Query) => { controller.current?.abort(); setQuery(next); };
  const apply = () => {
    try {
      const filters = normalizeAuditFilters(draft);
      setFilterError(null);
      setRetained(null);
      read({ filters });
    } catch (error) { setFilterError(error instanceof Error ? error.message : "Check the audit filters."); }
  };
  const change = (key: "actor_id" | "action" | "from" | "to", value: string) => setDraft({ ...draft, [key]: value || undefined });

  return <>
    <Card title="Audit filters">
      <form onSubmit={event => { event.preventDefault(); apply(); }}>
        <div className="dashboard-grid">
          <Field label="Actor ID (exact)" value={draft.actor_id ?? ""} onChange={event => change("actor_id", event.target.value)} />
          <Field label="Action (exact)" value={draft.action ?? ""} onChange={event => change("action", event.target.value)} />
          <Select label="Outcome" value={draft.outcome ?? ""} onChange={event => {
            const value = event.target.value;
            if (value === "" || value === "succeeded" || value === "denied" || value === "failed") setDraft({ ...draft, outcome: value || undefined });
          }}><option value="">Any outcome</option><option value="succeeded">Succeeded</option><option value="denied">Denied</option><option value="failed">Failed</option></Select>
          <Field label="From (UTC, inclusive)" placeholder="2026-09-12T00:00:00.000000Z" value={draft.from ?? ""} onChange={event => change("from", event.target.value)} />
          <Field label="To (UTC, exclusive)" placeholder="2026-09-13T00:00:00.000000Z" value={draft.to ?? ""} onChange={event => change("to", event.target.value)} />
        </div>
        <p>All filters must match. Actor and action are exact values, with case preserved. Use UTC timestamps ending Z, with up to six fractional digits. Blank filters include all retained organization audit records.</p>
        {filterError && <p role="alert">{filterError}</p>}
        <Button type="submit">Apply filters</Button>
        <Button type="button" onClick={() => { setDraft({}); setFilterError(null); setRetained(null); read({ filters: {} }); }}>Clear filters</Button>
      </form>
    </Card>
    <p aria-label="Applied audit filters">Applied filters: {Object.entries(query.filters).map(([key, value]) => `${key}=${value}`).join(" · ") || "All retained organization audit records"}</p>
    <p>Live source, not a snapshot. Later pages can change as records are added, updated or removed. Refresh starts at the newest matching records. The selected scope binds your access and cursor; it does not limit records to one workspace.</p>
    {loading && <LoadingState label="Loading matching audit events…" />}
    {error && <div role="alert"><p>Matching audit events could not be loaded. {page ? "The last successful page is still shown." : "Results are unavailable, not empty."} Refresh starts a new browse if the cursor is no longer valid.</p><Button onClick={() => read({ ...query })}>{query.cursor ? "Retry next page" : "Retry page"}</Button></div>}
    {page && <>
      <p role="status">Showing {page.items.length} matching audit events</p>
      {page.items.length === 0 ? <EmptyState title="No matching audit events" /> : page.items.map(event => <Card key={event.id} id={`audit-event-${event.id}`} title={event.action}>
        <p>Actor {event.actor_id} · Target {event.target_id}</p>
        <p><Badge tone={event.outcome === "succeeded" ? "success" : "warning"}>{event.outcome}</Badge> · {event.occurred_at}</p>
        <Button onClick={() => change("action", event.action)}>Use this action</Button>
        <Button onClick={() => change("actor_id", event.actor_id)}>Use this actor</Button>
      </Card>)}
      <p>{page.page_info.has_more ? "More matching events" : "No older matching events"}</p>
    </>}
    <nav aria-label="Audit pages">
      <Button disabled={loading || !query.cursor} onClick={() => { setRetained(null); read({ filters: query.filters }); }}>First</Button>
      <Button disabled={loading || !page?.page_info.has_more || Boolean(error)} onClick={() => { if (page?.page_info.next_cursor) read({ filters: query.filters, cursor: page.page_info.next_cursor }); }}>Next</Button>
      <Button onClick={() => { setRetained(null); read({ filters: query.filters }); }}>Refresh</Button>
    </nav>
  </>;
}
