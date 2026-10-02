"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { APIProductError, type APIClient } from "../../../apps/web/api/client";
import type { ComplianceControl, ComplianceDownloadFormat, ComplianceEvidence, ComplianceEvidenceDetail, ComplianceEvidenceTarget, ComplianceExport, ComplianceExportInput } from "../../../apps/web/api/generated";
import type { ActivityScope } from "../../domain/activity-links";
import { complianceLink } from "../../domain/compliance-links";
import { Badge, Button, Card, LoadingState, PageHeader } from "../../components/ui";
import type { SessionsComplianceAPI } from "./SessionsComplianceView";
import { complianceReadMode, createComplianceAPI } from "./compliance-api";

export type ComplianceBoundary = ActivityScope & { principalID: string; generation: number; permitted: boolean; fresh: boolean; isCurrent(): boolean; reauthenticate?(): void };
export type ComplianceViewProps = { api: SessionsComplianceAPI | null; client?: APIClient; complianceBoundary?: ComplianceBoundary; selectedSource?: ComplianceEvidenceTarget; onNavigate?(path: string): void };
function message(error: unknown) {
  if (error instanceof APIProductError) {
    if (error.status === 401) return "Session expired. Sign in again.";
    if (error.status === 403) return "Access denied. Recheck your scope and permissions.";
    if (error.status === 404) return "Source unavailable in this scope.";
    if (error.status === 409 && error.product.code === "source_changed") return "Source changed. Return to the evidence list for its current version.";
    if (error.status === 409) return "Request conflicts with current state. Reload before retrying.";
    if (error.status === 410) return "Export expired. Create a new export.";
  }
  return "Compliance request failed. Evidence inspection remains available; retry the request.";
}
function frameworkID(value: string): ComplianceExportInput["framework"] { return value === "hipaa" || value === "HIPAA" ? "hipaa" : value === "soc2_security" || value.startsWith("SOC 2") ? "soc2_security" : undefined; }
function remember(key: string, id?: string) { try { if (id) sessionStorage.setItem(key, id); else sessionStorage.removeItem(key); } catch { /* Reload recovery is optional if storage is blocked. */ } }
function recalled(key: string): string | undefined { try { const id = sessionStorage.getItem(key); return id && /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id) ? id : undefined; } catch { return undefined; } }

export function ComplianceEvidenceView(props: ComplianceViewProps) {
  const b = props.complianceBoundary;
  const key = b ? `${b.principalID}/${b.organizationID}/${b.workspaceID}/${b.environmentID}/${b.generation}` : "legacy";
  // A changed principal, selected scope or session generation owns fresh state.
  const source = props.selectedSource;
  return <ComplianceEvidenceContent key={`${key}/${source ? `${source.source_kind}/${source.source_id}/${source.source_version}` : "list"}`} {...props} />;
}
function ComplianceEvidenceContent({ api, client, complianceBoundary: boundary, selectedSource, onNavigate }: ComplianceViewProps) {
  const remote = useMemo(() => client && boundary ? createComplianceAPI(client, boundary) : null, [client, boundary]);
  const [controls, setControls] = useState<readonly ComplianceControl[]>([]);
  const [evidence, setEvidence] = useState<readonly ComplianceEvidence[]>([]);
  const [detail, setDetail] = useState<ComplianceEvidenceDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [framework, setFramework] = useState<"" | NonNullable<ComplianceExportInput["framework"]>>("");
  const [controlID, setControlID] = useState("");
  const [job, setJob] = useState<ComplianceExport | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [clock, setClock] = useState(Date.now);
  const lifetime = useRef<AbortController | null>(null);
  const retryIntent = useRef<{ input: ComplianceExportInput; key: string } | null>(null);
  const storageKey = boundary ? `zasp.compliance.export/${boundary.principalID}/${boundary.organizationID}/${boundary.workspaceID}/${boundary.environmentID}` : "";
  const permitted = !boundary || boundary.permitted && boundary.isCurrent();
  const current = () => !lifetime.current?.signal.aborted && (!boundary || boundary.permitted && boundary.isCurrent());
  useEffect(() => {
    const controller = new AbortController(); lifetime.current = controller;
    return () => { controller.abort(); };
  }, []);
  useEffect(() => {
    const timer = setInterval(() => setClock(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const sourceKey = selectedSource ? `${selectedSource.source_kind}/${selectedSource.source_id}/${selectedSource.source_version}` : "";
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    const valid = () => active && (!boundary || boundary.permitted && boundary.isCurrent());
    queueMicrotask(async () => {
      if (!valid()) { if (active) { setLoading(false); if (storageKey) remember(storageKey); } return; }
      setLoading(true); setError(null); setDetail(null);
      try {
        if (selectedSource) {
          if (!remote) throw new Error();
          const value = await remote.detail(selectedSource, controller.signal);
          if (valid()) setDetail(value);
        } else {
          if (!api) throw new Error();
          const nextControls = await api.listControls(controller.signal);
          controller.signal.throwIfAborted();
          if (!valid()) return;
          const nextEvidence = await api.listEvidence(controller.signal, complianceReadMode(nextControls));
          if (valid()) { setControls(nextControls); setEvidence(nextEvidence); }
        }
      } catch (e) { if (valid()) setError(message(e)); }
      finally { if (valid()) setLoading(false); }
    });
    return () => { active = false; controller.abort(); };
  }, [api, remote, boundary, sourceKey, selectedSource, revision, storageKey]);
  useEffect(() => {
    if (!remote || !boundary?.permitted) return;
    let active = true; const controller = new AbortController();
    const id = recalled(storageKey);
    if (id) void remote.status(id, controller.signal).then(value => { if (active && boundary.isCurrent()) setJob(value); }).catch(e => { if (active && boundary.isCurrent()) { setExportError(message(e)); remember(storageKey); } });
    return () => { active = false; controller.abort(); };
  }, [remote, storageKey, boundary]);
  const registered = controls.length > 0 && controls.every(control => control.freshness !== undefined);
  async function refreshJob() {
    if (!remote || !job || !current() || busy) return;
    setBusy(true); setExportError(null);
    try { const value = await remote.status(job.id, lifetime.current!.signal); if (current()) setJob(value); }
    catch (e) { if (current()) setExportError(message(e)); }
    finally { if (current()) setBusy(false); }
  }
  async function createJob() {
    if (!remote || !registered || !boundary?.fresh || !current() || busy) return;
    const input: ComplianceExportInput = { ...(framework ? { framework } : {}), ...(controlID ? { control_id: controlID } : {}) };
    if (!retryIntent.current || JSON.stringify(retryIntent.current.input) !== JSON.stringify(input)) retryIntent.current = { input, key: `compliance-${crypto.randomUUID()}` };
    setBusy(true); setExportError(null); setNotice(null);
    try {
      const value = await remote.create(input, retryIntent.current.key, lifetime.current!.signal);
      if (current()) { setJob(value); remember(storageKey, value.id); retryIntent.current = null; }
    } catch (e) { if (current()) setExportError(message(e)); }
    finally { if (current()) setBusy(false); }
  }
  async function download(format: ComplianceDownloadFormat) {
    if (!remote || !job || job.status !== "completed" || Date.parse(job.expires_at) <= Date.now() || !current() || busy) return;
    setBusy(true); setExportError(null); setNotice(null);
    try {
      const blob = await remote.download(job.id, format, lifetime.current!.signal, current);
      if (!current()) return;
      const url = URL.createObjectURL(blob);
      try {
        const anchor = document.createElement("a"); anchor.href = url; anchor.download = `compliance-${job.id}.${format === "human" ? "txt" : format}`;
        document.body.appendChild(anchor); anchor.click(); anchor.remove();
        setNotice("Download handed to your browser. Check its downloads for the saved file.");
      } finally { setTimeout(() => URL.revokeObjectURL(url), 1000); }
    } catch (e) { if (current()) setExportError(message(e)); }
    finally { if (current()) setBusy(false); }
  }
  if (!permitted) return <div className="page"><p role="alert">Access denied. Select an authorized scope and session.</p></div>;
  const header = <PageHeader title="Compliance evidence" description="Product evidence for review. Freshness and exports do not establish certification or control effectiveness." />;
  if (loading) return <div className="page">{header}<LoadingState label="Loading compliance evidence…" /></div>;
if (selectedSource) return <div className="page">{header}<Button onClick={() => onNavigate ? onNavigate("/compliance/evidence") : window.location.assign("/compliance/evidence")}>Back to evidence</Button>{error && <p role="alert">{error}</p>}{detail && <section><h2>Evidence source</h2><p>{detail.record.target?.source_kind} · {detail.record.id} · version {detail.record.target?.source_version}</p><time dateTime={detail.record.at}>{detail.record.at}</time><p>{detail.freshness}</p><pre>{JSON.stringify(detail.record.metadata, null, 2)}</pre></section>}</div>;
  const matches = controls.filter(c => !framework || frameworkID(c.framework) === framework);
  return <div className="page">{header}{error && <p role="alert">{error} <Button onClick={() => setRevision(v => v + 1)}>Retry evidence</Button></p>}
    <label>Framework <select aria-label="Framework" value={framework} onChange={e => { setFramework(e.target.value as typeof framework); setControlID(""); }}><option value="">All frameworks</option><option value="soc2_security">SOC 2 Security</option><option value="hipaa">HIPAA</option></select></label>
    <label>Control <select aria-label="Control" value={controlID} onChange={e => setControlID(e.target.value)}><option value="">All controls</option>{matches.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>
    <div className="dashboard-grid">{matches.filter(c => !controlID || c.id === controlID).map(control => {
      const rows = evidence.filter(e => e.control.id === control.id);
      return <Card key={control.id} title={`${control.framework} · ${control.name}`}><Badge tone={control.freshness === "fresh" ? "success" : control.freshness === "stale" ? "warning" : "neutral"}>{control.freshness ?? "Legacy evidence (current freshness unavailable)"}</Badge>{control.freshness === "missing" && <p>Missing required evidence</p>}<p>Source freshness deadline: <time dateTime={control.fresh_until}>{control.fresh_until}</time></p>{rows.flatMap(row => row.evidence).map((item, index) => <p key={`${item.source}/${item.id}/${index}`}>{item.asset_id} · {item.source} · <time dateTime={item.at}>{item.at}</time>{item.target && boundary ? <> · <a href={complianceLink(item.target, boundary)} aria-label={`Open ${item.target.source_kind} ${item.target.source_id} version ${item.target.source_version}`} onClick={onNavigate ? e => { e.preventDefault(); onNavigate(complianceLink(item.target!, boundary)); } : undefined}>Open evidence (version {item.target.source_version})</a></> : <> · {item.id}</>}</p>)}</Card>;
    })}</div>
{!registered || !remote ? <Card title="Evidence exports unavailable"><p>Current source and export service are not available for this view. Legacy records are not current-source proof.</p></Card> : <Card title="Evidence exports"><p>Exports capture the selected framework and control. Retrieval expires at the displayed time.</p>{!boundary?.fresh && <p>Fresh authentication required. <Button onClick={() => boundary?.reauthenticate?.()}>Reauthenticate</Button></p>}<Button disabled={busy || !boundary?.fresh} onClick={() => void createJob()}>Create evidence export</Button>{exportError && <p role="alert">{exportError}</p>}{notice && <p role="status">{notice}</p>}{job && <section aria-label="Compliance export status"><p>{job.id}</p><p>{Date.parse(job.expires_at) <= clock ? "Export expired" : job.status === "pending" ? "Export queued" : job.status === "completed" ? "Export completed" : `Export failed: ${job.failure_code ?? "unavailable"}`}</p><p>Retrieval expires: {job.expires_at}</p><Button disabled={busy} onClick={() => void refreshJob()}>Refresh export status</Button>{job.status === "completed" && Date.parse(job.expires_at) > clock && <><Button disabled={busy} onClick={() => void download("json")}>Download JSON</Button><Button disabled={busy} onClick={() => void download("csv")}>Download CSV</Button><Button disabled={busy} onClick={() => void download("human")}>Download readable</Button></>}</section>}</Card>}
  </div>;
}
