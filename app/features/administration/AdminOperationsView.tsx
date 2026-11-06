"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { APIProductError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { createAuditLogAPI, type AuditLogAPI } from "../../../apps/web/api/audit-log";
import type { ExternalFlowPage, ExternalFlowUpdate, ExternalFlowMutation, SystemComponentPage, SystemStatus, SystemVersion } from "../../../apps/web/api/generated";
import { decodeSystemComponentPage, decodeSystemStatus, decodeSystemVersion } from "../../../apps/web/api/administration-decoders";
import { Badge, Button, Card, EmptyState, LoadingState, PageHeader } from "../../components/ui";
import { AuditLogPanel, type AuditReadBoundary } from "./AuditLogPanel";
import { AuditExportPanel, type AuditExportPanelProps } from "./AuditExportPanel";

import { decodeExternalFlows, updateExternalFlow, optionalFlowID, policyVersion, readOnlyExternalFlowBoundary, type ExternalFlowBoundary } from "./external-flow-api";

type Surface = "health" | "external" | "audit";
export interface AdminOperationsAPI {
  getHealth(): Promise<{ status: SystemStatus; components: SystemComponentPage["items"]; version: string }>;
  getExternalFlows(signal?: AbortSignal): Promise<ExternalFlowPage["items"]>;
  updateExternalFlow?(intent: ExternalFlowUpdate, signal: AbortSignal): Promise<ExternalFlowMutation>;
}

export function createAdminOperationsAPI(client: APIClient): AdminOperationsAPI {
  return {
    async getHealth() { const [status, components, version] = await Promise.all([requireAPIData<SystemStatus>(await client.GET("/api/v1/system/status"), decodeSystemStatus), requireAPIData<SystemComponentPage>(await client.GET("/api/v1/system/components"), decodeSystemComponentPage), requireAPIData<SystemVersion>(await client.GET("/api/v1/system/version"), decodeSystemVersion)]); return { status, components: components.items, version: version.version }; },
    async getExternalFlows(signal) { return requireAPIData(await client.GET("/api/v1/settings/external-data-flows", { signal }), decodeExternalFlows); },
    async updateExternalFlow(intent, signal) { return updateExternalFlow(client, intent, signal); },
  };
}

export function AdminOperationsView({ surface, api, client, auditAPI, auditBoundary, auditExport, externalBoundary = readOnlyExternalFlowBoundary }: { surface: Surface; api?: AdminOperationsAPI; client?: APIClient; auditAPI?: AuditLogAPI; auditBoundary?: AuditReadBoundary; auditExport?: AuditExportPanelProps; externalBoundary?: ExternalFlowBoundary }) {
  const audit = useMemo(() => auditAPI ?? (client ? createAuditLogAPI(client) : null), [auditAPI, client]);
  if (surface === "audit") return <div className="page"><PageHeader title="Audit log" description="Durable product-owned mutation evidence across the organization." /><AuditLogPanel api={audit} boundary={auditBoundary} />{auditExport ? <AuditExportPanel {...auditExport} /> : <Card title="Audit exports unavailable"><p>Export is unavailable for this session or installation.</p></Card>}</div>;
  if (surface === "external") return <ExternalFlowSettings api={api} client={client} boundary={externalBoundary} />;
  return <AdminStatusView key={surface} surface={surface} api={api} client={client} />;
}

function AdminStatusView({ surface, api: suppliedAPI, client }: { surface: "health"; api?: AdminOperationsAPI; client?: APIClient }) {
  const api = useMemo(() => suppliedAPI ?? (client ? createAdminOperationsAPI(client) : null), [suppliedAPI, client]);
  const [health, setHealth] = useState<Awaited<ReturnType<AdminOperationsAPI["getHealth"]>> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => { try { if (!api) throw new Error(); setHealth(await api.getHealth()); } catch { setError("Administration data could not be loaded"); } finally { setLoading(false); } }, [api]);
  useEffect(() => { let active = true; queueMicrotask(() => { if (active) void load(); }); return () => { active = false; }; }, [load]);
  if (loading) return <div className="page"><LoadingState label="Loading administration data…" /></div>;
  if (surface === "health") return <div className="page"><PageHeader title="System health" description="Only registered components with live readiness probes are shown." />{error && <p role="alert">{error}</p>}{health && <><Card title={health.status.security_plane_healthy ? "Security plane healthy" : "Security plane degraded"}><Badge tone={health.status.security_plane_healthy ? "success" : "warning"}>{health.status.security_plane_healthy ? "Required components healthy" : "Required component unavailable"}</Badge><p>{health.version}</p><p>Fresh {health.status.fresh_at}</p></Card>{health.components.map((component) => <Card key={component.id} title={component.id}><Badge tone={component.state === "healthy" ? "success" : "warning"}>{component.state}</Badge><p>{component.required ? "Required" : "Optional"} · fresh {component.fresh_at}</p></Card>)}</>}</div>;

  return null;
}

function ExternalFlowSettings({ api: suppliedAPI, client, boundary }: { api?: AdminOperationsAPI; client?: APIClient; boundary: ExternalFlowBoundary }) {
  const api = useMemo(() => suppliedAPI ?? (client ? createAdminOperationsAPI(client) : null), [suppliedAPI, client]);
  if (boundary.identityKey === null || boundary.isCurrent?.() === false) return <LoadingState label="Revalidating external flow access…" />;
  return <ExternalFlowCatalog key={JSON.stringify([boundary.identityKey, boundary.permitted, boundary.fresh])} api={api} boundary={boundary} />;
}
function ExternalFlowCatalog({ api, boundary }: { api: AdminOperationsAPI | null; boundary: ExternalFlowBoundary }) {
  const [flows, setFlows] = useState<ExternalFlowPage["items"] | null>(null);
  const [loading, setLoading] = useState(false), [error, setError] = useState(false);
  const read = useRef<AbortController | null>(null), mounted = useRef(true);
  const { isCurrent } = boundary;
  const reload = useCallback(async () => {
    read.current?.abort(); const controller = new AbortController(); read.current = controller;
    const current = () => mounted.current && !controller.signal.aborted && read.current === controller && isCurrent?.() !== false;
    if (!current()) throw Error("External flow access changed");
    setLoading(true); setError(false);
    try { if (!api) throw Error("External flow API unavailable"); const next = await api.getExternalFlows(controller.signal); if (!current()) throw Error("External flow access changed"); setFlows(next); }
    catch (error) { if (current()) setError(true); throw error; }
    finally { if (current()) setLoading(false); }
  }, [api, isCurrent]);
  useEffect(() => { mounted.current = true; let active = true; queueMicrotask(() => { if (active) void reload().catch(() => {}); }); return () => { active = false; mounted.current = false; read.current?.abort(); }; }, [reload]);
  return <div className="page"><PageHeader title="External data flows" description="Current server policy and registered adapter readiness." />
    <Button disabled={loading} onClick={() => void reload().catch(() => {})}>Reload external data flows</Button>
    {loading && <LoadingState label="Loading external data flows…" />}{error && <p role="alert">External flow settings could not be loaded. Existing values have not been refreshed.</p>}
    {!boundary.permitted && <p>Changing optional destinations requires data control permission.</p>}
    {boundary.permitted && !boundary.fresh && <p>Sign in again before changing optional destinations. {boundary.reauthenticate && <Button onClick={boundary.reauthenticate}>Reauthenticate</Button>}</p>}
    {flows?.length === 0 && <EmptyState title="No external adapters registered" />}
    {flows?.map(flow => <ExternalFlowRow key={flow.id} flow={flow} api={api} boundary={boundary} reload={reload} catalogCurrent={!loading && !error} />)}
  </div>;
}
function ExternalFlowRow({ flow, api, boundary, reload, catalogCurrent }: { flow: ExternalFlowPage["items"][number]; api: AdminOperationsAPI | null; boundary: ExternalFlowBoundary; reload(): Promise<void>; catalogCurrent: boolean }) {
  const [attempt, setAttempt] = useState<ExternalFlowUpdate | null>(null), [busy, setBusy] = useState(false);
  const [confirmed, setConfirmed] = useState(false), [conflict, setConflict] = useState(false), [error, setError] = useState(false), [saved, setSaved] = useState(false);
  const active = useRef<AbortController | null>(null), mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; active.current?.abort(); active.current = null; }; }, []);
  const admitted = boundary.permitted && boundary.fresh && boundary.isCurrent?.() !== false && Boolean(api?.updateExternalFlow) && !flow.required && optionalFlowID(flow.id);
  const canChange = admitted && catalogCurrent && policyVersion(flow.version) && (flow.enabled || flow.available === true);
  // Resolving a retained intent is distinct from choosing a new enable action.
  // A later catalog change must not trap a lost-response retry behind availability.
  const canRetry = admitted && attempt !== null && policyVersion(attempt.expected_version);
  const name = flow.name ?? flow.id;
  async function change(retry: boolean) {
    if (active.current || (retry ? !canRetry : !canChange) || !api?.updateExternalFlow || !optionalFlowID(flow.id)) return;
    const selected = retry ? attempt : policyVersion(flow.version) ? { flow_id: flow.id, enabled: !flow.enabled, expected_version: flow.version, idempotency_key: `wf_${crypto.randomUUID()}` } : null;
    if (!selected || !retry && attempt) return;
    const controller = new AbortController(); active.current = controller;
    const current = () => mounted.current && !controller.signal.aborted && active.current === controller && boundary.isCurrent?.() !== false;
    setAttempt(selected); setBusy(true); setError(false); setSaved(false);
    try {
      if (!confirmed && !conflict) { await api.updateExternalFlow(selected, controller.signal); if (!current()) return; setConfirmed(true); }
      await reload(); if (!current()) return;
      setAttempt(null); setConfirmed(false); setConflict(false); setSaved(!conflict);
    } catch (error) {
      if (!current()) return;
      if (error instanceof APIProductError && error.status === 409 && error.product.code === "operation_conflict") setConflict(true);
      setError(true);
    } finally { if (current()) { active.current = null; setBusy(false); } }
  }
  return <Card title={name}><Badge tone={flow.required ? "info" : "neutral"}>{flow.required ? "Required" : "Optional"}</Badge>
    <p>{flow.categories.join(" · ")} · {flow.health}</p><p>{flow.enabled ? "Enabled" : "Disabled"}{flow.version !== undefined ? ` · policy version ${flow.version}` : ""}</p>
    {flow.required ? <p>This required destination cannot be disabled.</p> : <>
      {flow.available !== true && <p>Enabling this destination is unavailable for this installation.</p>}
      {!policyVersion(flow.version) && <p>Policy changes are unavailable for this catalog.</p>}
      {!attempt ? <Button disabled={!canChange || busy} onClick={event => { if (event.detail < 2) void change(false); }}>{flow.enabled ? "Disable" : "Enable"} {name}</Button> : <Button disabled={!canRetry || busy} onClick={event => { if (event.detail < 2) void change(true); }}>{confirmed ? "Reload policy status for" : conflict ? "Reload before a new change for" : "Retry change for"} {name}</Button>}
    </>}
    {busy && <p role="status">Confirming policy change…</p>}{error && <p role="alert">{conflict ? "The policy changed. Reload before choosing a new change." : confirmed ? "Change recorded, but the current policy could not be reloaded." : "The change outcome is unknown. Retry the same change before starting another."}</p>}
    {saved && <p role="status">Change recorded. Current server policy reloaded.</p>}
  </Card>;
}
