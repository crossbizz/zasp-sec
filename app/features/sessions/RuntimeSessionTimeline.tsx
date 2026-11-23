"use client";

import { useEffect, useMemo, useState } from "react";
import { APITransportError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import type { RuntimeSession, RuntimeSessionEvent, RuntimeSessionEventPage } from "../../../apps/web/api/generated";
import { compareRuntimeSessionEventOrder, decodeRuntimeSession, decodeRuntimeSessionEventPage } from "../../../apps/web/api/runtime-session-decoders";
import { Button, Card, LoadingState } from "../../components/ui";
import { RuntimeSessionEventRow } from "./RuntimeSessionEventRow";
import { RuntimeSessionEvidence, type RuntimeSessionEvidenceAPI } from "./RuntimeSessionEvidence";
import type { ActivityScope } from "../../domain/activity-links";
import { SecurityAgentActivityPanel } from "../securityagents/SecurityAgentActivityPanel";
import { loadSessionIntent } from "../../../apps/web/api/runtime-intent";
import type { SessionIntent } from "../../../apps/web/api/generated";
import { SessionInvestigation } from "../securityagents/SessionInvestigation";
import { SessionIntentPanel } from "./SessionIntent";
import { InlineSessionDetail } from "./InlineSessionDetail";
import { Time } from "../../components/time";

export type RuntimeSessionActivity = { scope: ActivityScope; canReadRuns: boolean; onNavigate(path: string): void };

export interface RuntimeSessionTimelineAPI {
  intent?(id: string, signal: AbortSignal): Promise<SessionIntent>;
  get(id: string, signal: AbortSignal): Promise<RuntimeSession>;
  events(id: string, cursor: string | null, signal: AbortSignal): Promise<RuntimeSessionEventPage>;
}

export function verifyRuntimeSessionScope(session: RuntimeSession, scope?: ActivityScope): void {
  if (scope && (session.workspace_id !== scope.workspaceID || session.environment_id !== scope.environmentID)) {
    throw new APITransportError("invalid_response", "Runtime investigation scope mismatch");
  }
}

function targetedSummary(value: unknown, id: string, scope?: ActivityScope): RuntimeSession {
  const summary = decodeRuntimeSession(value);
  verifyRuntimeSessionScope(summary, scope);
  if (summary.id !== id) throw new APITransportError("invalid_response", "Runtime investigation identity mismatch");
  return summary;
}

function targetedEvents(value: unknown, id: string): RuntimeSessionEventPage {
  const page = decodeRuntimeSessionEventPage(value);
  if (page.items.some(event => event.session_id !== (id === "unattributed" ? null : id))) throw new APITransportError("invalid_response", "Runtime event investigation mismatch");
  return page;
}

export function createRuntimeSessionTimelineAPI(client: APIClient, scope?: ActivityScope): RuntimeSessionTimelineAPI {
  return {
    intent: (id, signal) => loadSessionIntent(client, id, signal),
    async get(id, signal) {
      return targetedSummary(requireAPIData(await client.GET("/api/v1/sessions/{id}", { params: { path: { id } }, signal })), id, scope);
    },
    async events(id, cursor, signal) {
      return targetedEvents(requireAPIData(await client.GET("/api/v1/sessions/{id}/events", { params: { path: { id }, query: { limit: 25, ...(cursor ? { cursor } : {}) } }, signal })), id);
    },
  };
}

type Query = { id: string; api: RuntimeSessionTimelineAPI; cursor: string | null; page: number; after?: RuntimeSessionEvent };
type Load = { query: Query; summary?: RuntimeSession; events?: RuntimeSessionEventPage; error?: boolean };

export function RuntimeSessionTimeline({ id, api, evidenceAPI, activity, enableInvestigation = false }: { id: string; enableInvestigation?: boolean; api: RuntimeSessionTimelineAPI; evidenceAPI?: RuntimeSessionEvidenceAPI; activity?: RuntimeSessionActivity }) {
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
      <p>{summary.event_count.toLocaleString("en-US")} canonical events · Summary projected <time dateTime={summary.projected_at}><Time value={summary.projected_at} /></time></p>
      <p>Events are ordered by canonical event time, then event ID. Pages and the summary are not a snapshot; restart at the first page to include newly projected earlier events.</p>
    </Card>
    {id !== "unattributed" && api.intent && <SessionIntentPanel key={id} id={id} read={api.intent} />}
    {enableInvestigation && id !== "unattributed" && api.intent && <SessionInvestigation key={"chat:"+id} sessionID={id} />}
    <ol aria-label="Runtime evidence timeline">
      {events.items.map(event => <RuntimeSessionEventRow key={event.id} event={event} onEvidence={evidenceAPI ? event => setEvidence({ event, query, api: evidenceAPI }) : undefined} />)}
    </ol>
    {events.items.length === 0 && <p>No further committed events on this page.</p>}
    <nav aria-label="Runtime event pages">
      <Button disabled={query.page === 1} onClick={() => setRequested({ ...initial })}>First event page</Button>
      <span>Page {query.page}</span>
      <Button disabled={!events.page_info.has_more} onClick={() => setRequested({ ...query, cursor: events.page_info.next_cursor, page: query.page + 1, after: events.items.at(-1) })}>Next event page</Button>
    </nav>
    {id !== "unattributed" && activity && <SecurityAgentActivityPanel direction="runs" kind="session" entityID={summary.id} scope={activity.scope} permitted={activity.canReadRuns} onNavigate={activity.onNavigate} />}
    {evidence && evidence.query === query && evidence.api === evidenceAPI && evidenceAPI && <InlineSessionDetail title="Evidence metadata" onClose={() => setEvidence(null)}>
      <RuntimeSessionEvidence target={{ investigationID: id, eventID: evidence.event.id, evidenceID: evidence.event.evidence_id }} api={evidenceAPI} />
    </InlineSessionDetail>}
  </div>;
}
