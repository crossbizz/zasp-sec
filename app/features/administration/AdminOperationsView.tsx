"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { createAuditLogAPI, type AuditLogAPI } from "../../../apps/web/api/audit-log";
import type { ExternalFlowPage, SystemComponentPage, SystemStatus, SystemVersion } from "../../../apps/web/api/generated";
import { decodeExternalFlowPage, decodeSystemComponentPage, decodeSystemStatus, decodeSystemVersion } from "../../../apps/web/api/administration-decoders";
import { Badge, Card, EmptyState, LoadingState, PageHeader } from "../../components/ui";
import { AuditLogPanel, type AuditReadBoundary } from "./AuditLogPanel";
import { AuditExportPanel, type AuditExportPanelProps } from "./AuditExportPanel";

type Surface = "health" | "external" | "audit";
export interface AdminOperationsAPI {
  getHealth(): Promise<{ status: SystemStatus; components: SystemComponentPage["items"]; version: string }>;
  getExternalFlows(): Promise<ExternalFlowPage["items"]>;
}

export function createAdminOperationsAPI(client: APIClient): AdminOperationsAPI {
  return {
    async getHealth() { const [status, components, version] = await Promise.all([requireAPIData<SystemStatus>(await client.GET("/api/v1/system/status"), decodeSystemStatus), requireAPIData<SystemComponentPage>(await client.GET("/api/v1/system/components"), decodeSystemComponentPage), requireAPIData<SystemVersion>(await client.GET("/api/v1/system/version"), decodeSystemVersion)]); return { status, components: components.items, version: version.version }; },
    async getExternalFlows() { return requireAPIData<ExternalFlowPage>(await client.GET("/api/v1/settings/external-data-flows"), decodeExternalFlowPage).items; },
  };
}

export function AdminOperationsView({ surface, api, client, auditAPI, auditBoundary, auditExport }: { surface: Surface; api?: AdminOperationsAPI; client?: APIClient; auditAPI?: AuditLogAPI; auditBoundary?: AuditReadBoundary; auditExport?: AuditExportPanelProps }) {
  const audit = useMemo(() => auditAPI ?? (client ? createAuditLogAPI(client) : null), [auditAPI, client]);
  if (surface === "audit") return <div className="page"><PageHeader title="Audit log" description="Durable product-owned mutation evidence across the organization." /><AuditLogPanel api={audit} boundary={auditBoundary} />{auditExport ? <AuditExportPanel {...auditExport} /> : <Card title="Audit exports unavailable"><p>Export is unavailable for this session or installation.</p></Card>}</div>;
  return <AdminStatusView key={surface} surface={surface} api={api} client={client} />;
}

function AdminStatusView({ surface, api: suppliedAPI, client }: { surface: "health" | "external"; api?: AdminOperationsAPI; client?: APIClient }) {
  const api = useMemo(() => suppliedAPI ?? (client ? createAdminOperationsAPI(client) : null), [suppliedAPI, client]);
  const [health, setHealth] = useState<Awaited<ReturnType<AdminOperationsAPI["getHealth"]>> | null>(null);
  const [flows, setFlows] = useState<ExternalFlowPage["items"]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => { try { if (!api) throw new Error(); if (surface === "health") setHealth(await api.getHealth()); else setFlows(await api.getExternalFlows()); } catch { setError("Administration data could not be loaded"); } finally { setLoading(false); } }, [api, surface]);
  useEffect(() => { let active = true; queueMicrotask(() => { if (active) void load(); }); return () => { active = false; }; }, [load]);
  if (loading) return <div className="page"><LoadingState label="Loading administration data…" /></div>;
  if (surface === "health") return <div className="page"><PageHeader title="System health" description="Only registered components with live readiness probes are shown." />{error && <p role="alert">{error}</p>}{health && <><Card title={health.status.security_plane_healthy ? "Security plane healthy" : "Security plane degraded"}><Badge tone={health.status.security_plane_healthy ? "success" : "warning"}>{health.status.security_plane_healthy ? "Required components healthy" : "Required component unavailable"}</Badge><p>{health.version}</p><p>Fresh {health.status.fresh_at}</p></Card>{health.components.map((component) => <Card key={component.id} title={component.id}><Badge tone={component.state === "healthy" ? "success" : "warning"}>{component.state}</Badge><p>{component.required ? "Required" : "Optional"} · fresh {component.fresh_at}</p></Card>)}</>}</div>;
  if (surface === "external") return <div className="page"><PageHeader title="External data flows" description="Inventory derived only from mounted adapters and their real readiness." />{error && <p role="alert">{error}</p>}{flows.length === 0 ? <EmptyState title="No external adapters registered" /> : flows.map((flow) => <Card key={flow.id} title={flow.id}><Badge tone={flow.required ? "info" : "neutral"}>{flow.required ? "Required" : "Optional"}</Badge><p>{flow.categories.join(" · ")} · {flow.health}</p></Card>)}</div>;
  return null;
}
