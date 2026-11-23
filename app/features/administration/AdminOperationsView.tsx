"use client";

import { useEffect, useMemo, useState } from "react";
import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { createAuditLogAPI, type AuditLogAPI } from "../../../apps/web/api/audit-log";
import type { ExternalFlowPage, SystemComponentPage, SystemStatus, SystemVersion } from "../../../apps/web/api/generated";
import { decodeExternalFlowPage, decodeSystemComponentPage, decodeSystemStatus, decodeSystemVersion } from "../../../apps/web/api/administration-decoders";
import { Badge, Button, Card, EmptyState, LoadingState, PageHeader } from "../../components/ui";
import { ReleaseCoverage } from "./ReleaseCoverage";
import { AuditLogPanel, type AuditReadBoundary } from "./AuditLogPanel";
import { AuditExportPanel, type AuditExportPanelProps } from "./AuditExportPanel";
import { Time } from "../../components/time";

type Surface = "health" | "external" | "audit";
export interface AdminOperationsAPI {
  getHealth(): Promise<{ status: SystemStatus; components: SystemComponentPage["items"]; version: string }>;
  getExternalFlows(): Promise<ExternalFlowPage["items"]>;
}

export function createAdminOperationsAPI(client: APIClient): AdminOperationsAPI {
  return {
    async getHealth() { const [status, components, version] = await Promise.all([client.GET("/api/v1/system/status").then(result => requireAPIData<SystemStatus>(result, decodeSystemStatus)), client.GET("/api/v1/system/components").then(result => requireAPIData<SystemComponentPage>(result, decodeSystemComponentPage)), client.GET("/api/v1/system/version").then(result => requireAPIData<SystemVersion>(result, decodeSystemVersion))]); return { status, components: components.items, version: version.version }; },
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
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let active = true;
    async function load() {
      try {
        if (!api) throw Error("Missing administration client");
        if (surface === "health") {
          const result = await api.getHealth(); if (active) setHealth(result);
        } else {
          const result = await api.getExternalFlows(); if (active) setFlows(result);
        }
      } catch { if (active) setError("Administration data could not be loaded"); }
      finally { if (active) setLoading(false); }
    }
    void load();
    return () => { active = false; };
  }, [api, surface, revision]);
  function refresh() { setLoading(true); setError(null); setRevision(value => value + 1); }
  const title = surface === "health" ? "System health" : "External data flows";
  const description = surface === "health" ? "Readiness of the security plane and its optional components." : "Enabled adapters, their health, and the categories of data each can receive.";
  return <div className="page"><PageHeader title={title} description={description} actions={api && !error && <Button disabled={loading} onClick={refresh}>Refresh</Button>} />
    {loading ? <LoadingState label="Loading administration data…" /> : error ? <div role="alert"><p>{error}</p>{api && <Button onClick={refresh}>Retry</Button>}</div> : surface === "health" && health ? <>
      <Card title={health.status.security_plane_healthy ? "Security plane healthy" : "Security plane degraded"}>
        <Badge tone={health.status.security_plane_healthy ? "success" : "warning"}>{health.status.security_plane_healthy ? "Required components healthy" : "Required component unavailable"}</Badge>
        {health.status.optional_degraded && <p role="status">Optional components need attention.</p>}
        <p>Version {health.version} · Checked <Time value={health.status.fresh_at} /></p>
      </Card>
      <Card title="Components"><table className="data-table"><thead><tr><th scope="col">Component</th><th scope="col">Availability</th><th scope="col">Health</th><th scope="col">Checked</th></tr></thead><tbody>
        {health.components.map(component => <tr key={component.id}><td>{component.id}</td><td>{component.required ? "Required" : "Optional"}</td><td><Badge tone={component.state === "healthy" ? "success" : "warning"}>{component.state}</Badge></td><td><Time value={component.fresh_at} /></td></tr>)}
      </tbody></table></Card>
      <ReleaseCoverage version={health.version} />
    </> : surface === "external" && (flows.length === 0 ? <EmptyState title="No external adapters registered" description="Registered adapters for this environment appear here." /> :
      <Card title="Registered adapters"><table className="data-table"><thead><tr><th scope="col">Adapter</th><th scope="col">Availability</th><th scope="col">Enabled</th><th scope="col">Health</th><th scope="col">Data categories</th></tr></thead><tbody>
        {flows.map(flow => <tr key={flow.id}><td>{flow.id}</td><td>{flow.required ? "Required" : "Optional"}</td><td>{flow.enabled ? "Yes" : "No"}</td><td><Badge tone={flow.health === "healthy" ? "success" : "neutral"}>{flow.health}</Badge></td><td>{flow.categories.join(" · ") || "None"}</td></tr>)}
      </tbody></table></Card>)}
  </div>;
}
