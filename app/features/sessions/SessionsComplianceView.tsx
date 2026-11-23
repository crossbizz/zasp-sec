"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { APITransportError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import type { ComplianceControlPage, ComplianceEvidencePage, DataControls, ConsoleSessionEventPage as SessionEventPage, ConsoleSessionPage as SessionPage } from "../../../apps/web/api/generated";
import { decodeComplianceControlPage, decodeComplianceEvidencePage, decodeDataControls, decodeSessionEventPage, decodeSessionPage } from "../../../apps/web/api/administration-decoders";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";
import { useOptionalSession } from "../../auth/SessionProvider";
import { Badge, Button, Card, EmptyState, Field, LoadingState, PageHeader } from "../../components/ui";
import { ComplianceEvidenceView, type ComplianceViewProps } from "./ComplianceEvidenceView";
import type { ComplianceReadMode } from "./compliance-api";

const aiControlsRoute = "/administration/ai-controls";

type Surface = "sessions" | "compliance" | "data-controls";
type SessionItem = SessionPage["items"][number];
export type HydratedSession = SessionItem & { eventsUnavailable?: boolean };

export interface SessionsComplianceAPI {
  listSessions(): Promise<readonly HydratedSession[]>;
  revokeSession(id: string, version: number): Promise<void>;
  listControls(signal?: AbortSignal): Promise<ComplianceControlPage["items"]>;
  listEvidence(signal: AbortSignal | undefined, mode: ComplianceReadMode): Promise<ComplianceEvidencePage["items"]>;
  getDataControls(): Promise<DataControls>;
  updateDataControls(value: DataControls): Promise<DataControls>;
}

export function createSessionsComplianceAPI(client: APIClient): SessionsComplianceAPI {
  return {
    async listSessions() {
      const sessions = await loadAllCursorPages(async (cursor) => requireAPIData<SessionPage>(await client.GET("/api/v1/sessions", { params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } } }), decodeSessionPage), { maximumItems: 2_000, maximumPages: 20 });
      return hydrateSessionEvents(sessions.items, async (session) => {
        const events = await loadAllCursorPages(async (cursor) => requireAPIData<SessionEventPage>(await client.GET("/api/v1/sessions/{id}/events", { params: { path: { id: session.id }, query: { limit: 100, ...(cursor ? { cursor } : {}) } } }), decodeSessionEventPage), { maximumItems: 2_000, maximumPages: 20 });
        return events.items;
      }, 6);
    },
    async revokeSession(id, version) { const result = await client.DELETE("/api/v1/sessions/{id}", { params: { path: { id }, header: { "X-CSRF-Token": "", "If-Match": `"${version}"` } } }); if (result.error) requireAPIData<never>(result); if (result.response.status !== 204) throw new APITransportError("invalid_response", "Session revocation returned an invalid status"); },
    async listControls(signal) {
      const loaded = await loadAllCursorPages(async (cursor) => requireAPIData<ComplianceControlPage>(
        await client.GET("/api/v1/compliance/controls", { signal, params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } } }),
        decodeComplianceControlPage,
      ), { maximumItems: 2_000, maximumPages: 20, signal });
      return loaded.items;
    },
    async listEvidence(signal, mode) {
      const items: ComplianceEvidencePage["items"][number][] = [];
      // Cursors bind their framework. Each framework starts its own chain and
      // shares the effect's cancellation signal, including between chains.
      for (const framework of mode === "current" ? ["soc2_security", "hipaa"] as const : [undefined]) {
        const loaded = await loadAllCursorPages(async (cursor) => requireAPIData<ComplianceEvidencePage>(
          await client.GET("/api/v1/compliance/evidence", { signal, params: { query: { ...(framework ? { framework } : {}), limit: 100, ...(cursor ? { cursor } : {}) } } }),
          decodeComplianceEvidencePage,
        ), { maximumItems: 2_000, maximumPages: 20, signal });
        items.push(...loaded.items);
      }
      return items;
    },
    async getDataControls() { return requireAPIData<DataControls>(await client.GET("/api/v1/settings/data-controls"), decodeDataControls); },
    async updateDataControls(value) { return requireAPIData<DataControls>(await client.PATCH("/api/v1/settings/data-controls", { params: { header: { "X-CSRF-Token": "", "If-Match": `"${value.version}"` } }, body: { environment_id: value.environment_id, environment_class: value.environment_class, collection_mode: value.collection_mode, retention_days: value.retention_days, deletion_enabled: value.deletion_enabled } }), decodeDataControls); },
  };
}

export async function hydrateSessionEvents(
  sessions: readonly SessionItem[],
  loadEvents: (session: SessionItem) => Promise<SessionItem["events"]>,
  concurrency: number,
): Promise<HydratedSession[]> {
  const limit = Math.max(1, Math.min(16, Math.floor(concurrency)));
  const hydrated: HydratedSession[] = new Array(sessions.length);
  let next = 0;
  const worker = async () => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= sessions.length) return;
      const session = sessions[index];
      try {
        hydrated[index] = { ...session, events: await loadEvents(session) };
      } catch {
        hydrated[index] = { ...session, events: [], eventsUnavailable: true };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, sessions.length) }, worker));
  return hydrated;
}

type ViewProps = { surface: Surface; api?: SessionsComplianceAPI; client?: APIClient; canMutate?: boolean } & Pick<ComplianceViewProps, "complianceBoundary" | "selectedSource" | "selectedExport" | "selectedCatalog" | "onNavigate">;
export function SessionsComplianceView(props: ViewProps) {
  const api = useMemo(() => props.api ?? (props.client ? createSessionsComplianceAPI(props.client) : null), [props.api, props.client]);
  if (props.surface === "compliance") return <ComplianceEvidenceView api={api} client={props.client} complianceBoundary={props.complianceBoundary} selectedSource={props.selectedSource} selectedExport={props.selectedExport} selectedCatalog={props.selectedCatalog} onNavigate={props.onNavigate} />;
  return <SessionsAdministrationView {...props} />;
}
function SessionsAdministrationView({ surface, api: suppliedAPI, client, canMutate = false, onNavigate }: ViewProps) {
  const api = useMemo(() => suppliedAPI ?? (client ? createSessionsComplianceAPI(client) : null), [suppliedAPI, client]);
  const sessionContext = useOptionalSession();
  const fresh = sessionContext?.status === "authenticated" ? sessionContext.isFreshAuthenticated : true;
  const [sessions, setSessions] = useState<readonly HydratedSession[]>([]);
  const [dataControls, setDataControls] = useState<DataControls | null>(null);
  const [retentionInput, setRetentionInput] = useState<string | null>(null);
  const [savingControls, setSavingControls] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const load = useCallback(async () => {
    setError(null);
    setLoading(true);
    try {
      if (!api) throw new Error();
      if (surface === "sessions") setSessions(await api.listSessions());
      else setDataControls(await api.getDataControls());
    } catch { setError("Authorized administration data could not be loaded"); }
    finally { setLoading(false); }
  }, [api, surface]);
  useEffect(() => { let active = true; queueMicrotask(() => { if (active) void load(); }); return () => { active = false; }; }, [load]);
  if (loading) return <div className="page"><LoadingState label="Loading administration data…" /></div>;
  if (surface === "sessions") return <div className="page"><PageHeader title="Console login sessions" description="Console authentication sessions and exact-scope revocation. Agent runtime evidence is separate." />{error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}{!fresh && canMutate && <p role="alert">Fresh authentication expired. <Button onClick={() => sessionContext?.reauthenticate()}>Reauthenticate</Button></p>}{sessions.length === 0 ? <EmptyState title="No sessions in this scope" /> : sessions.map((session) => <Card key={session.id} title={session.id}><p>{session.principal_id} · <Badge tone={session.state === "active" ? "success" : "neutral"}>{session.state}</Badge> · version {session.version}</p>{session.eventsUnavailable && <p role="alert">Events for this session could not be loaded. Other session results remain available.</p>}{session.events.map((event) => <p key={event.id}>{event.label} · <Badge tone={event.confidence === "exact" ? "success" : event.confidence === "strong" ? "info" : event.confidence === "probable" ? "warning" : "neutral"}>{event.confidence}</Badge> · {event.evidence_id}</p>)}{canMutate && session.state === "active" && <Button disabled={!fresh} variant="danger" aria-label={`Revoke session ${session.id}`} onClick={() => void (async () => { try { if (!api) throw new Error(); await api.revokeSession(session.id, session.version); setSessions((current) => current.map((item) => item.id === session.id ? { ...item, state: "revoked", version: item.version + 1 } : item)); setNotice("Session revoked"); } catch { setError("Session could not be revoked; reload before retrying"); } })()}>Revoke session</Button>}</Card>)}</div>;
  if (!dataControls) return <div className="page"><PageHeader title="Data and retention" />{error && <div role="alert"><p>{error}</p><Button onClick={() => void load()}>Retry</Button></div>}</div>;
  const retention = retentionInput ?? String(dataControls.retention_days);
  const days = Number(retention);
  const validDays = retention.trim() !== "" && Number.isInteger(days) && days >= 1 && days <= 3650;
  const saveControls = async () => {
    if (!api || !canMutate || !fresh || !validDays || savingControls || error) return;
    setSavingControls(true);
    setError(null);
    setNotice(null);
    try {
      setDataControls(await api.updateDataControls({ ...dataControls, retention_days: days }));
      setRetentionInput(null);
      setNotice("Data controls updated");
    } catch {
      setError("The change could not be verified. Reload data controls before retrying.");
    } finally {
      setSavingControls(false);
    }
  };
  return (
    <div className="page">
      <PageHeader title="Data and retention" description="Environment-scoped durable collection and retention controls." />
      {error && <div role="alert"><p>{error}</p><Button onClick={() => { setRetentionInput(null); void load(); }}>Reload data controls</Button></div>}
      {notice && <p role="status">{notice}</p>}
      {!fresh && canMutate && <p role="alert">Fresh authentication expired. <Button onClick={() => sessionContext?.reauthenticate()}>Reauthenticate</Button></p>}
      <Card title={`${dataControls.environment_class} controls`}>
        <p><Badge tone="info">{dataControls.collection_mode.replaceAll("_", " ")}</Badge></p>
        <Field label="Retention days" type="number" min={1} max={3650} step={1} value={retention}
          aria-describedby="retention-days-hint" aria-invalid={!validDays}
          disabled={!canMutate || !fresh || savingControls} onChange={event => setRetentionInput(event.target.value)} />
        <p id="retention-days-hint">Enter a whole number from 1 to 3650.</p>
        <p>{dataControls.deletion_enabled ? "Deletion enabled" : "Deletion disabled"}</p>
        {canMutate && <Button disabled={!fresh || !validDays || savingControls || Boolean(error) || days === dataControls.retention_days} onClick={() => void saveControls()}>Save data controls</Button>}
      </Card>
      <Card title="AI content permissions"><p>{dataControls.collection_mode === "metadata_only" ? "Metadata-only collection blocks private code snippets and add-on contents. Redacted summaries require explicit consent." : "Extended collection permits private content only when both organization and environment AI controls allow it."}</p><p><a href={aiControlsRoute} onClick={event => { if (onNavigate && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) { event.preventDefault(); onNavigate(aiControlsRoute); } }}>Review AI &amp; Models</a></p></Card>
      <Card title="Data deletion unavailable"><p>Deletion requests remain disabled until the durable job and artifact lifecycle is installed.</p></Card>
    </div>
  );
}
