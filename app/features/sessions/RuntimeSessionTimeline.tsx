"use client";

import { useEffect, useMemo, useState } from "react";
import { APITransportError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import type { RuntimeSession, RuntimeSessionEvent, RuntimeSessionEventPage } from "../../../apps/web/api/generated";
import { compareRuntimeSessionEventOrder, decodeRuntimeSession, decodeRuntimeSessionEventPage } from "../../../apps/web/api/runtime-session-decoders";
import { Button, Card, LoadingState, Modal } from "../../components/ui";
import { RuntimeSessionEventRow } from "./RuntimeSessionEventRow";
import { RuntimeSessionEvidence, type RuntimeSessionEvidenceAPI } from "./RuntimeSessionEvidence";

export interface RuntimeSessionTimelineAPI {
  get(id: string, signal: AbortSignal): Promise<RuntimeSession>;
  events(id: string, cursor: string | null, signal: AbortSignal): Promise<RuntimeSessionEventPage>;
}

function targetedSummary(value: unknown, id: string): RuntimeSession {
  const summary = decodeRuntimeSession(value);
  if (summary.id !== id) throw new APITransportError("invalid_response", "Runtime investigation identity mismatch");
  return summary;
}

function targetedEvents(value: unknown, id: string): RuntimeSessionEventPage {
  const page = decodeRuntimeSessionEventPage(value);
  if (page.items.some(event => event.session_id !== (id === "unattributed" ? null : id))) throw new APITransportError("invalid_response", "Runtime event investigation mismatch");
  return page;
}

export function createRuntimeSessionTimelineAPI(client: APIClient): RuntimeSessionTimelineAPI {
  return {
    async get(id, signal) {
      return targetedSummary(requireAPIData(await client.GET("/api/v1/sessions/{id}", { params: { path: { id } }, signal })), id);
    },
    async events(id, cursor, signal) {
      return targetedEvents(requireAPIData(await client.GET("/api/v1/sessions/{id}/events", { params: { path: { id }, query: { limit: 25, ...(cursor ? { cursor } : {}) } }, signal })), id);
    },
  };
}

type Query = { id: string; api: RuntimeSessionTimelineAPI; cursor: string | null; page: number; after?: RuntimeSessionEvent };
type Load = { query: Query; summary?: RuntimeSession; events?: RuntimeSessionEventPage; error?: boolean };

export function RuntimeSessionTimeline({ id, api, evidenceAPI }: { id: string; api: RuntimeSessionTimelineAPI; evidenceAPI?: RuntimeSessionEvidenceAPI }) {
  const initial = useMemo<Query>(() => ({ id, api, cursor: null, page: 1 }), [id, api]);
  const [requested, setRequested] = useState(initial);
  const query = requested.id === id && requested.api === api ? requested : initial;
  const [load, setLoad] = useState<Load | null>(null);
  const [evidence, setEvidence] = useState<{ event: RuntimeSessionEvent; query: Query; api: RuntimeSessionEvidenceAPI } | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => {
      if (controller.signal.aborted) return;
      void (async () => {
        const [detail, result] = await Promise.all([api.get(id, controller.signal), api.events(id, query.cursor, controller.signal)]);
        const summary = targetedSummary(detail, id), events = targetedEvents(result, id);
        if (query.after && events.items[0] && compareRuntimeSessionEventOrder(query.after, events.items[0]) >= 0) throw new Error("non-advancing canonical page");
        if (!query.cursor && events.items.length === 0) throw new Error("canonical summary has no initial events");
        if (!controller.signal.aborted) setLoad({ query, summary, events });
      })().catch(() => { if (!controller.signal.aborted) setLoad({ query, error: true }); });
    });
    return () => controller.abort();
  }, [api, id, query]);
  const current = load?.query === query ? load : null;
  if (!current) return <LoadingState label="Loading runtime timeline…" />;
  if (current.error || !current.summary || !current.events) return <div role="alert"><p>Runtime timeline could not be loaded. Evidence is unavailable, not empty.</p><Button onClick={() => setRequested({ ...query })}>Retry runtime timeline</Button></div>;
  const summary = current.summary, events = current.events;
  return <div>
    <Card title={id === "unattributed" ? "Unattributed evidence timeline" : "Runtime session timeline"}>
      {id === "unattributed" && <p>Unrelated observations may share this collection. They are not inferred to belong to one agent session.</p>}
      <p>Agent: {summary.agent_id ?? "Unknown or multiple agents"} · Principal: {summary.principal_id ?? "Unknown"}</p>
      <p>{summary.event_count.toLocaleString("en-US")} canonical events · Summary projected <time dateTime={summary.projected_at}>{summary.projected_at}</time></p>
      <p>Events are ordered by canonical event time, then event ID. Pages and the summary are not a snapshot; restart at the first page to include newly projected earlier events.</p>
    </Card>
    <ol aria-label="Runtime evidence timeline">
      {events.items.map(event => <RuntimeSessionEventRow key={event.id} event={event} onEvidence={evidenceAPI ? event => setEvidence({ event, query, api: evidenceAPI }) : undefined} />)}
    </ol>
    {events.items.length === 0 && <p>No further committed events on this page.</p>}
    <nav aria-label="Runtime event pages">
      <Button disabled={query.page === 1} onClick={() => setRequested({ ...initial })}>First event page</Button>
      <span>Page {query.page}</span>
      <Button disabled={!events.page_info.has_more} onClick={() => setRequested({ ...query, cursor: events.page_info.next_cursor, page: query.page + 1, after: events.items.at(-1) })}>Next event page</Button>
    </nav>
    <Modal open={!!evidence && evidence.query === query && evidence.api === evidenceAPI} title="Evidence metadata" onClose={() => setEvidence(null)}>
      {evidence && evidence.query === query && evidence.api === evidenceAPI && evidenceAPI && <RuntimeSessionEvidence target={{ investigationID: id, eventID: evidence.event.id, evidenceID: evidence.event.evidence_id }} api={evidenceAPI} />}
    </Modal>
  </div>;
}
