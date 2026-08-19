"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import type { ComplianceControlPage, ComplianceEvidencePage, DataControls, SessionPage } from "../../../apps/web/api/generated";
import { decodeComplianceControlPage, decodeComplianceEvidencePage, decodeDataControls, decodeSessionPage } from "../../../apps/web/api/administration-decoders";
import { Badge, Button, Card, EmptyState, Field, LoadingState, PageHeader } from "../../components/ui";

type Surface = "sessions" | "compliance" | "data-controls";
type SessionItem = SessionPage["items"][number];

export interface SessionsComplianceAPI {
  listSessions(): Promise<readonly SessionItem[]>;
  revokeSession(id: string, version: number): Promise<void>;
  listControls(): Promise<ComplianceControlPage["items"]>;
  listEvidence(): Promise<ComplianceEvidencePage["items"]>;
  getDataControls(): Promise<DataControls>;
  updateDataControls(value: DataControls): Promise<DataControls>;
}

export function createSessionsComplianceAPI(client: APIClient): SessionsComplianceAPI {
  return {
    async listSessions() { return requireAPIData<SessionPage>(await client.GET("/api/v1/sessions"), decodeSessionPage).items; },
    async revokeSession(id, version) { const result = await client.DELETE("/api/v1/sessions/{id}", { params: { path: { id }, header: { "X-CSRF-Token": "", "If-Match": `"${version}"` } } }); if (result.error) requireAPIData<never>(result); },
    async listControls() { return requireAPIData<ComplianceControlPage>(await client.GET("/api/v1/compliance/controls"), decodeComplianceControlPage).items; },
    async listEvidence() { return requireAPIData<ComplianceEvidencePage>(await client.GET("/api/v1/compliance/evidence"), decodeComplianceEvidencePage).items; },
    async getDataControls() { return requireAPIData<DataControls>(await client.GET("/api/v1/settings/data-controls"), decodeDataControls); },
    async updateDataControls(value) { return requireAPIData<DataControls>(await client.PATCH("/api/v1/settings/data-controls", { params: { header: { "X-CSRF-Token": "", "If-Match": `"${value.version}"` } }, body: { environment_id: value.environment_id, environment_class: value.environment_class, collection_mode: value.collection_mode, retention_days: value.retention_days, deletion_enabled: value.deletion_enabled } }), decodeDataControls); },
  };
}

export function SessionsComplianceView({ surface, api: suppliedAPI, client, canMutate = false }: { surface: Surface; api?: SessionsComplianceAPI; client?: APIClient; canMutate?: boolean }) {
  const api = useMemo(() => suppliedAPI ?? (client ? createSessionsComplianceAPI(client) : null), [suppliedAPI, client]);
  const [sessions, setSessions] = useState<readonly SessionItem[]>([]);
  const [controls, setControls] = useState<ComplianceControlPage["items"]>([]);
  const [evidence, setEvidence] = useState<ComplianceEvidencePage["items"]>([]);
  const [dataControls, setDataControls] = useState<DataControls | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      if (!api) throw new Error();
      if (surface === "sessions") setSessions(await api.listSessions());
      else if (surface === "compliance") { const [nextControls, nextEvidence] = await Promise.all([api.listControls(), api.listEvidence()]); setControls(nextControls); setEvidence(nextEvidence); }
      else setDataControls(await api.getDataControls());
    } catch { setError("Authorized administration data could not be loaded"); }
    finally { setLoading(false); }
  }, [api, surface]);
  useEffect(() => { let active = true; queueMicrotask(() => { if (active) void load(); }); return () => { active = false; }; }, [load]);
  if (loading) return <div className="page"><LoadingState label="Loading administration data…" /></div>;
  if (surface === "sessions") return <div className="page"><PageHeader title="Session investigations" description="Ordered durable session activity with evidence confidence and exact-scope revocation." />{error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}{sessions.length === 0 ? <EmptyState title="No sessions in this scope" /> : sessions.map((session) => <Card key={session.id} title={session.id}><p>{session.principal_id} · <Badge tone={session.state === "active" ? "success" : "neutral"}>{session.state}</Badge> · version {session.version}</p>{session.events.map((event) => <p key={event.id}>{event.label} · <Badge tone={event.confidence === "exact" ? "success" : event.confidence === "strong" ? "info" : event.confidence === "probable" ? "warning" : "neutral"}>{event.confidence}</Badge> · {event.evidence_id}</p>)}{canMutate && session.state === "active" && <Button variant="danger" onClick={() => void (async () => { try { if (!api) throw new Error(); await api.revokeSession(session.id, session.version); setSessions((current) => current.map((item) => item.id === session.id ? { ...item, state: "revoked", version: item.version + 1 } : item)); setNotice("Session revoked"); } catch { setError("Session could not be revoked; reload before retrying"); } })()}>Revoke session</Button>}</Card>)}</div>;
  if (surface === "compliance") return <div className="page"><PageHeader title="Compliance evidence" description="Locally complete control evidence and source freshness without certification claims." />{error && <p role="alert">{error}</p>}<div className="dashboard-grid">{controls.map((control) => { const record = evidence.find((item) => item.control.id === control.id); return <Card key={control.id} title={`${control.framework} · ${control.name}`}><Badge tone={record?.freshness === "fresh" ? "success" : record?.freshness === "stale" ? "warning" : "neutral"}>{record?.freshness ?? "missing"}</Badge>{record?.evidence.map((item) => <p key={item.id}>{item.asset_id} · {item.source} · {item.id}</p>)}</Card>; })}</div><Card title="Evidence exports unavailable"><p>Exports remain disabled until a durable job, artifact, one-time grant, expiry, and recovery lifecycle is installed.</p></Card></div>;
  if (!dataControls) return <div className="page"><PageHeader title="Data and retention" />{error && <p role="alert">{error}</p>}</div>;
  return <div className="page"><PageHeader title="Data and retention" description="Environment-scoped durable collection and retention controls." />{error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}<Card title={`${dataControls.environment_class} controls`}><p><Badge tone="info">{dataControls.collection_mode.replaceAll("_", " ")}</Badge></p><Field label="Retention days" type="number" value={String(dataControls.retention_days)} disabled={!canMutate} onChange={(event) => setDataControls({ ...dataControls, retention_days: Number(event.target.value) })} /><p>{dataControls.deletion_enabled ? "Deletion enabled" : "Deletion disabled"}</p>{canMutate && <Button onClick={() => void (async () => { try { if (!api) throw new Error(); setDataControls(await api.updateDataControls(dataControls)); setNotice("Data controls updated"); } catch { setError("Data controls could not be updated; reload before retrying"); } })()}>Save data controls</Button>}</Card><Card title="Data deletion unavailable"><p>Deletion requests remain disabled until the durable job and artifact lifecycle is installed.</p></Card></div>;
}
