"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";
import type { AuditEventPage, ExternalFlowPage, SystemComponentPage, SystemStatus, SystemVersion } from "../../../apps/web/api/generated";
import { decodeAuditEventPage, decodeExternalFlowPage, decodeSystemComponentPage, decodeSystemStatus, decodeSystemVersion } from "../../../apps/web/api/administration-decoders";
import { Badge, Card, EmptyState, LoadingState, PageHeader } from "../../components/ui";

type Surface = "health" | "external" | "audit";
export interface AdminOperationsAPI {
  getHealth(): Promise<{ status: SystemStatus; components: SystemComponentPage["items"]; version: string }>;
  getExternalFlows(): Promise<ExternalFlowPage["items"]>;
  listAuditEvents(): Promise<AuditEventPage["items"]>;
}

export function createAdminOperationsAPI(client: APIClient): AdminOperationsAPI {
  return {
    async getHealth() { const [status, components, version] = await Promise.all([requireAPIData<SystemStatus>(await client.GET("/api/v1/system/status"), decodeSystemStatus), requireAPIData<SystemComponentPage>(await client.GET("/api/v1/system/components"), decodeSystemComponentPage), requireAPIData<SystemVersion>(await client.GET("/api/v1/system/version"), decodeSystemVersion)]); return { status, components: components.items, version: version.version }; },
    async getExternalFlows() { return requireAPIData<ExternalFlowPage>(await client.GET("/api/v1/settings/external-data-flows"), decodeExternalFlowPage).items; },
    async listAuditEvents() { return (await loadAllCursorPages(async (cursor) => requireAPIData<AuditEventPage>(await client.GET("/api/v1/audit-events", { params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } } }), decodeAuditEventPage), { maximumItems: 2_000, maximumPages: 20 })).items; },
  };
}

export function AdminOperationsView({ surface, api: suppliedAPI, client }: { surface: Surface; api?: AdminOperationsAPI; client?: APIClient }) {
  const api = useMemo(() => suppliedAPI ?? (client ? createAdminOperationsAPI(client) : null), [suppliedAPI, client]);
  const [health, setHealth] = useState<Awaited<ReturnType<AdminOperationsAPI["getHealth"]>> | null>(null);
  const [flows, setFlows] = useState<ExternalFlowPage["items"]>([]);
  const [audit, setAudit] = useState<AuditEventPage["items"]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => { try { if (!api) throw new Error(); if (surface === "health") setHealth(await api.getHealth()); else if (surface === "external") setFlows(await api.getExternalFlows()); else setAudit(await api.listAuditEvents()); } catch { setError("Administration data could not be loaded"); } finally { setLoading(false); } }, [api, surface]);
  useEffect(() => { let active = true; queueMicrotask(() => { if (active) void load(); }); return () => { active = false; }; }, [load]);
  if (loading) return <div className="page"><LoadingState label="Loading administration data…" /></div>;
  if (surface === "health") return <div className="page"><PageHeader title="System health" description="Only registered components with live readiness probes are shown." />{error && <p role="alert">{error}</p>}{health && <><Card title={health.status.security_plane_healthy ? "Security plane healthy" : "Security plane degraded"}><Badge tone={health.status.security_plane_healthy ? "success" : "warning"}>{health.status.security_plane_healthy ? "Required components healthy" : "Required component unavailable"}</Badge><p>{health.version}</p><p>Fresh {health.status.fresh_at}</p></Card>{health.components.map((component) => <Card key={component.id} title={component.id}><Badge tone={component.state === "healthy" ? "success" : "warning"}>{component.state}</Badge><p>{component.required ? "Required" : "Optional"} · fresh {component.fresh_at}</p></Card>)}</>}</div>;
  if (surface === "external") return <div className="page"><PageHeader title="External data flows" description="Inventory derived only from mounted adapters and their real readiness." />{error && <p role="alert">{error}</p>}{flows.length === 0 ? <EmptyState title="No external adapters registered" /> : flows.map((flow) => <Card key={flow.id} title={flow.id}><Badge tone={flow.required ? "info" : "neutral"}>{flow.required ? "Required" : "Optional"}</Badge><p>{flow.categories.join(" · ")} · {flow.health}</p></Card>)}</div>;
  return <div className="page"><PageHeader title="Audit log" description="Durable product-owned mutation evidence. Export remains unavailable until its job and artifact lifecycle exists." />{error && <p role="alert">{error}</p>}{audit.length === 0 ? <EmptyState title="No audit events" /> : audit.map((event) => <Card key={event.id} title={event.action}><p>{event.actor_id} · {event.target_id}</p><p><Badge tone={event.outcome === "succeeded" ? "success" : "warning"}>{event.outcome}</Badge> · {event.occurred_at}</p></Card>)}<Card title="Audit exports unavailable"><p>No export mutation is mounted.</p></Card></div>;
}
