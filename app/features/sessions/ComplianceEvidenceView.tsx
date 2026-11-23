"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { APIProductError, type APIClient } from "../../../apps/web/api/client";
import type { ComplianceControl, ComplianceDownloadFormat, ComplianceEvidence, ComplianceEvidenceDetail, ComplianceEvidenceTarget, ComplianceExport, ComplianceExportInput } from "../../../apps/web/api/generated";
import type { ActivityScope } from "../../domain/activity-links";
import { activityLink } from "../../domain/activity-links";
import { complianceExportLink, complianceLink } from "../../domain/compliance-links";
import { Badge, Button, Card, LoadingState, PageHeader } from "../../components/ui";
import type { SessionsComplianceAPI } from "./SessionsComplianceView";
import { complianceReadMode, createComplianceAPI } from "./compliance-api";
import type { CatalogTarget } from "../../domain/coverage-links";
import { FrameworkCoverage } from "./FrameworkCoverage";
import { PilotEvidenceForm } from "./PilotEvidenceForm";
import { Time } from "../../components/time";

export type ComplianceBoundary = ActivityScope & { principalID: string; generation: number; permitted: boolean; fresh: boolean; isCurrent(): boolean; reauthenticate?(): void };
export type ComplianceViewProps = { api: SessionsComplianceAPI | null; client?: APIClient; complianceBoundary?: ComplianceBoundary; selectedSource?: ComplianceEvidenceTarget; selectedExport?: string; selectedCatalog?: CatalogTarget; onNavigate?(path: string): void };
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
type FrameworkID = NonNullable<ComplianceExportInput["framework"]>;
// The two product evidence frameworks, then the AI security frameworks. The
// controls of an AI framework are the framework's own; the evidence of one is
// the findings whose rule maps to it.
export const complianceFrameworks: readonly (readonly [FrameworkID, string])[] = [
  ["soc2_security", "SOC 2 Security"], ["hipaa", "HIPAA"],
  ["owasp_agentic_top10_2026", "OWASP Top 10 for Agentic Applications"], ["owasp_llm_top10_2025", "OWASP Top 10 for LLM Applications"],
  ["mitre_atlas", "MITRE ATLAS"], ["nist_ai_rmf_1_0", "NIST AI RMF 1.0"], ["iso_iec_42001_2023", "ISO/IEC 42001"], ["eu_ai_act", "EU AI Act"],
];
function frameworkID(value: string): FrameworkID | undefined { return value === "HIPAA" ? "hipaa" : value.startsWith("SOC 2") ? "soc2_security" : complianceFrameworks.find(([id]) => id === value)?.[0]; }
function frameworkName(value: string) { return complianceFrameworks.find(([id]) => id === value)?.[1] ?? value; }

export function ComplianceEvidenceView(props: ComplianceViewProps) {
  const b = props.complianceBoundary;
  const key = b ? `${b.principalID}/${b.organizationID}/${b.workspaceID}/${b.environmentID}/${b.generation}` : "legacy";
  // A changed principal, selected scope or session generation owns fresh state.
  const source = props.selectedSource;
  const catalog = props.selectedCatalog;
  return <ComplianceEvidenceContent key={`${key}/${source ? `${source.source_kind}/${source.source_id}/${source.source_version}` : catalog ? `${catalog.framework}/${catalog.edition}/${catalog.upstream_id}` : "list"}`} {...props} />;
}
function ComplianceEvidenceContent({ api, client, complianceBoundary: boundary, selectedSource, selectedCatalog, selectedExport, onNavigate }: ComplianceViewProps) {
  const remote = useMemo(() => client && boundary ? createComplianceAPI(client, boundary) : null, [client, boundary]);
  const [showCatalog, setShowCatalog] = useState(Boolean(selectedCatalog));
  const [controls, setControls] = useState<readonly ComplianceControl[]>([]);
  const [evidence, setEvidence] = useState<readonly ComplianceEvidence[]>([]);
  const [detail, setDetail] = useState<ComplianceEvidenceDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [framework, setFramework] = useState<"" | FrameworkID>("");
  const [controlID, setControlID] = useState("");
  const [job, setJob] = useState<ComplianceExport | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [clock, setClock] = useState(Date.now);
  const lifetime = useRef<AbortController | null>(null);
  const retryIntent = useRef<{ input: ComplianceExportInput; key: string } | null>(null);
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
    if (showCatalog && !selectedSource) return () => { active = false; controller.abort(); };
    queueMicrotask(async () => {
      if (!valid()) { if (active) setLoading(false); return; }
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
  }, [api, remote, boundary, sourceKey, selectedSource, revision, showCatalog]);
  useEffect(() => {
    if (!remote || !boundary?.permitted) return;
    let active = true; const controller = new AbortController();
    if (selectedExport) void remote.status(selectedExport, controller.signal).then(value => { if (active && boundary.isCurrent()) setJob(value); }).catch(e => { if (active && boundary.isCurrent()) { setExportError(message(e)); } });
    return () => { active = false; controller.abort(); };
  }, [remote, selectedExport, boundary]);
  const registered = controls.length > 0 && controls.every(control => control.freshness !== undefined);
  async function refreshJob() {
    if (!remote || !job || !current() || busy) return;
    setBusy(true); setExportError(null);
    try { const value = await remote.status(job.id, lifetime.current!.signal); if (current()) setJob(value); }
    catch (e) { if (current()) setExportError(message(e)); }
    finally { if (current()) setBusy(false); }
  }
  async function createJob(pilot?: ComplianceExportInput) {
    if (!remote || (!registered && !pilot) || !boundary?.fresh || !current() || busy) return;
    const input: ComplianceExportInput = pilot ?? { ...(framework ? { framework } : {}), ...(controlID ? { control_id: controlID } : {}) };
    if (!retryIntent.current || JSON.stringify(retryIntent.current.input) !== JSON.stringify(input)) retryIntent.current = { input, key: `compliance-${crypto.randomUUID()}` };
    setBusy(true); setExportError(null); setNotice(null);
    try {
      const value = await remote.create(input, retryIntent.current.key, lifetime.current!.signal);
      if (current()) {
        setJob(value); retryIntent.current = null;
        const link = complianceExportLink(value.id, boundary);
        if (onNavigate) onNavigate(link);
        else window.history.replaceState(window.history.state, "", link);
      }
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
  const views = !selectedSource && client && boundary && <div className="page-actions" role="group" aria-label="Compliance views">
    <Button aria-pressed={!showCatalog} onClick={() => setShowCatalog(false)}>Evidence controls</Button>
    <Button aria-pressed={showCatalog} onClick={() => setShowCatalog(true)}>Framework coverage</Button>
  </div>;
  if (loading && !showCatalog) return <div className="page">{header}{views}<LoadingState label="Loading compliance evidence…" /></div>;
if (selectedSource) return <div className="page">{header}<Button onClick={() => onNavigate ? onNavigate("/compliance/evidence") : window.location.assign("/compliance/evidence")}>Back to evidence</Button>{error && <p role="alert">{error}</p>}{detail && <section><h2>Evidence source</h2><p>{detail.record.target?.source_kind} · {detail.record.id} · version {detail.record.target?.source_version}</p><time dateTime={detail.record.at}>{detail.record.at}</time><p>{detail.freshness}</p><pre>{JSON.stringify(detail.record.metadata, null, 2)}</pre></section>}</div>;
  const matches = controls.filter(c => !framework || frameworkID(c.framework) === framework);
  return <div className="page">{header}{views}{!showCatalog && error && <p role="alert">{error} <Button onClick={() => setRevision(v => v + 1)}>Retry evidence</Button></p>}
    {showCatalog && client && boundary ? <FrameworkCoverage client={client} boundary={boundary} initial={selectedCatalog}
      busy={busy} create={selector => void createJob(selector)} /> : <>
    <label>Framework <select aria-label="Framework" value={framework} onChange={e => { setFramework(e.target.value as typeof framework); setControlID(""); }}><option value="">All frameworks</option>{complianceFrameworks.map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></label>
    <label>Control <select aria-label="Control" value={controlID} onChange={e => setControlID(e.target.value)}><option value="">All controls</option>{matches.map(c => <option key={c.id} value={c.id}>{c.finding_count === undefined ? c.name : `${c.id} · ${c.name}`}</option>)}</select></label>
    <div className="dashboard-grid">{matches.filter(c => !controlID || c.id === controlID).map(control => {
      const rows = evidence.filter(e => e.control.id === control.id);
      if (control.finding_count !== undefined) {
        // An AI framework control: its evidence is the findings mapped to it.
        const count = control.finding_count;
        return <Card key={control.id} title={`${frameworkName(control.framework)} · ${control.id} · ${control.name}`}><Badge tone={count > 0 ? "warning" : "neutral"}>{count === 0 ? "No findings" : count === 1 ? "1 finding" : `${count} findings`}</Badge>{count === 0 ? <p>No finding you can read is mapped to this control.</p> : <p>Findings relevant to this control. A finding is evidence for review; it does not state that the control is met or failed.</p>}{count > control.evidence_ids.length && <p>Showing the first {control.evidence_ids.length} of {count} findings.</p>}{control.evidence_ids.length > 0 && <ul aria-label={`Findings for ${control.id}`}>{control.evidence_ids.map(id => <li key={id}>{boundary ? <a href={activityLink({ kind: "finding", id }, boundary)} aria-label={`Open finding ${id}`} onClick={onNavigate ? e => { e.preventDefault(); onNavigate(activityLink({ kind: "finding", id }, boundary)); } : undefined}>Finding {id}</a> : <>Finding {id}</>}</li>)}</ul>}</Card>;
      }
      return <Card key={control.id} title={`${control.framework} · ${control.name}`}><Badge tone={control.freshness === "fresh" ? "success" : control.freshness === "stale" ? "warning" : "neutral"}>{control.freshness ?? "Legacy evidence (current freshness unavailable)"}</Badge>{control.freshness === "missing" && <p>Missing required evidence</p>}<p>Source freshness deadline: <time dateTime={control.fresh_until}><Time value={control.fresh_until} /></time></p>{rows.flatMap(row => row.evidence).map((item, index) => <p key={`${item.source}/${item.id}/${index}`}>{item.asset_id} · {item.source} · <time dateTime={item.at}>{item.at}</time>{item.target && boundary ? <> · <a href={complianceLink(item.target, boundary)} aria-label={`Open ${item.target.source_kind} ${item.target.source_id} version ${item.target.source_version}`} onClick={onNavigate ? e => { e.preventDefault(); onNavigate(complianceLink(item.target!, boundary)); } : undefined}>Open evidence (version {item.target.source_version})</a></> : <> · {item.id}</>}</p>)}</Card>;
    })}</div>
{client && remote && boundary?.permitted && <PilotEvidenceForm client={client} environmentID={boundary.environmentID} fresh={boundary.fresh} busy={busy} reauthenticate={boundary.reauthenticate} create={(input) => void createJob(input)} />}</>}
{exportError && <p role="alert">{exportError}</p>}
{(!registered && !job && !showCatalog) || !remote ? <Card title="Evidence exports unavailable"><p>Current source and export service are not available for this view. Legacy records are not current-source proof.</p></Card> : <Card title="Evidence exports"><p>Exports capture the selected framework and control. Retrieval expires at the displayed time.</p>{!boundary?.fresh && <p>Fresh authentication required. <Button onClick={() => boundary?.reauthenticate?.()}>Reauthenticate</Button></p>}{!showCatalog && <Button disabled={busy || !registered || !boundary?.fresh} onClick={() => void createJob()}>Create evidence export</Button>}{notice && <p role="status">{notice}</p>}{job && <section aria-label="Compliance export status"><p>{job.id}</p><p>{Date.parse(job.expires_at) <= clock ? "Export expired" : job.status === "pending" ? "Export queued" : job.status === "completed" ? "Export completed" : `Export failed: ${job.failure_code ?? "unavailable"}`}</p><p>Retrieval expires: <Time value={job.expires_at} /></p><Button disabled={busy} onClick={() => void refreshJob()}>Refresh export status</Button>{job.status === "completed" && Date.parse(job.expires_at) > clock && <><Button disabled={busy} onClick={() => void download("json")}>Download JSON</Button><Button disabled={busy} onClick={() => void download("csv")}>Download CSV</Button><Button disabled={busy} onClick={() => void download("human")}>Download readable</Button></>}</section>}</Card>}
  </div>;
}
