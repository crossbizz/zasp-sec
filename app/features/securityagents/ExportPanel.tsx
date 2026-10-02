"use client";
import { useEffect, useRef, useState } from "react";
import { APIProductError } from "../../../apps/web/api/client";
import type { ComplianceDownloadFormat, SecurityAgentExportStatus } from "../../../apps/web/api/generated";
import { Button } from "../../components/ui";
import type { createSecurityAgentExportAPI } from "./export-api";
export type AgentExportAPI = ReturnType<typeof createSecurityAgentExportAPI>;
type Props = { api: AgentExportAPI; runID: string; stepID: string; disabled?: boolean };
function message(error: unknown) {
  if (error instanceof APIProductError) {
    if (error.status === 401) return "Session expired. Sign in again.";
    if (error.status === 403) return "Access denied. Recheck your scope and source permissions.";
    if (error.status === 404) return "Export unavailable in this scope or server release.";
    if (error.status === 410) return "Export expired. A new export is required.";
  }
  return "Export request failed. Refresh status before retrying.";
}
export function ExportPanel(props: Props) {
  return <ExportContent key={`${props.runID}/${props.stepID}`} {...props} />;
}
function ExportContent({ api, runID, stepID, disabled = false }: Props) {
  const [job, setJob] = useState<SecurityAgentExportStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const [clock, setClock] = useState(Date.now);
  const lifetime = useRef<AbortController | null>(null);
  const downloading = useRef(false);
  useEffect(() => {
    const controller = new AbortController(); lifetime.current = controller;
    const current = () => !controller.signal.aborted && lifetime.current === controller;
    queueMicrotask(async () => {
      if (!current()) return;
      setJob(null); setNotice(null); setError(null); setBusy(!disabled);
      if (disabled) return;
      try { const value = await api.status(runID, stepID, controller.signal, current); if (current()) setJob(value); }
      catch (e) { if (current()) setError(message(e)); }
      finally { if (current()) setBusy(false); }
    });
    return () => controller.abort();
  }, [api, runID, stepID, disabled, revision]);
  useEffect(() => { const timer = setInterval(() => setClock(Date.now()), 1000); return () => clearInterval(timer); }, []);
  async function download(format: ComplianceDownloadFormat) {
    const controller = lifetime.current;
    if (!controller || controller.signal.aborted || disabled || busy || downloading.current || !job || job.state !== "completed" || job.cleanup_state !== "retained" || Date.parse(job.retrieval_expires_at) <= Date.now()) return;
    const current = () => !controller.signal.aborted && lifetime.current === controller;
    downloading.current = true; setBusy(true); setError(null); setNotice(null);
    try {
      const blob = await api.download(runID, stepID, format, controller.signal, current);
      if (!current()) return;
      const url = URL.createObjectURL(blob);
      try {
        const anchor = document.createElement("a");
        anchor.href = url; anchor.download = `agent-export-${job.export_id}.${format === "human" ? "txt" : format}`;
        document.body.appendChild(anchor);
        try { anchor.click(); } finally { anchor.remove(); }
        setNotice("Download handed to your browser. Check its downloads for the saved file.");
      } finally { setTimeout(() => URL.revokeObjectURL(url), 1000); }
    } catch (e) { if (current()) { setJob(null); setError(message(e)); } }
    finally { downloading.current = false; if (current()) setBusy(false); }
  }
  const expired = job !== null && Date.parse(job.retrieval_expires_at) <= clock;
  return <section aria-label="Security Agent evidence export">
    <h4>Evidence export</h4><p>Frozen product evidence. An export does not establish remediation or certification.</p>
    {busy && <p role="status">Export request in progress</p>}
    {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    <Button disabled={disabled || busy} onClick={() => setRevision(v => v + 1)}>Refresh export status</Button>
    {job && !disabled && <>
      <p>{expired ? "Export expired" : job.state === "pending" ? `Export ${job.phase}` : job.state === "failed" ? `Export failed: ${job.failure_code ?? "unavailable"}` : "Export completed"}</p>
      <p>Retrieval expires: {job.retrieval_expires_at}</p><p>Cleanup: {job.cleanup_state}</p>
      <ul>{job.selection.map(s => <li key={`${s.source_kind}/${s.source_id}`}>{s.source_kind} · {s.source_id} · version {s.source_version}</li>)}</ul>
      {job.artifact && <p>Artifact SHA-256: {job.artifact.sha256} · {job.artifact.size} bytes</p>}
      {job.state === "completed" && job.cleanup_state === "retained" && !expired && <>
        <Button disabled={busy} onClick={() => void download("json")}>Download JSON</Button>
        <Button disabled={busy} onClick={() => void download("csv")}>Download CSV</Button>
        <Button disabled={busy} onClick={() => void download("human")}>Download readable</Button>
      </>}
    </>}
  </section>;
}
