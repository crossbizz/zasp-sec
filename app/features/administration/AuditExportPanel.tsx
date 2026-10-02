"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import type { AuditExportsAPI } from "../../../apps/web/api/audit-exports";
import { Button, Card } from "../../components/ui";
import { AuditExportController, exportSaveNotice, type AuditExportAuthority } from "./audit-export-controller";
import { exportIdentityKey } from "./audit-export-resume";
import { directoryPicker } from "./audit-export-save";

export type AuditExportPanelProps = { api: AuditExportsAPI; authority: AuditExportAuthority; retrySession(): Promise<void>; reauthenticate(): void };
export function AuditExportPanel(props: AuditExportPanelProps) {
  if (!props.authority.permitted) return <Card title="Audit exports unavailable"><p>This session has no installed, authorized export access.</p></Card>;
  return <ActiveAuditExportPanel key={`${exportIdentityKey(props.authority)}/${props.authority.generation}`} {...props} />;
}
// Only the non-sensitive close outcome survives an identity/scope teardown.
export function AuditExportSaveNotice() {
  const notice = useSyncExternalStore(exportSaveNotice.subscribe, exportSaveNotice.snapshot, () => "");
  return notice ? <p role="status">Last finalized local export: {notice}</p> : null;
}
function browserStorage(): Pick<Storage, "getItem" | "setItem" | "removeItem"> {
  try { return window.sessionStorage; } catch {
    return { getItem: () => null, setItem: () => { throw new Error("Per-tab resume storage is unavailable"); }, removeItem: () => {} };
  }
}
function ActiveAuditExportPanel({ api, authority, retrySession, reauthenticate }: AuditExportPanelProps) {
  const [controller] = useState(() => new AuditExportController({ api, authority, retrySession, storage: browserStorage() }));
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot, controller.snapshot);
  useEffect(() => { controller.attach(); return () => { void controller.dispose(); }; }, [controller]);
  useEffect(() => { controller.setFresh(authority.fresh); }, [controller, authority.fresh]);
  const picker = directoryPicker();
  const descriptor = state.descriptor;
  const saving = ["saving", "read-retry", "finalizing"].includes(state.phase);
  const failedMessage = descriptor?.status === "failed" ? {
    capacity_exceeded: "The export exceeds the configured capacity. No truncated export was created.",
    invalid_source: "The source records could not be verified.",
    execution_failed: "The export could not be produced.",
  }[descriptor.failure_code] : null;
  return <Card title="Export organization audit log">
    <p>Captures the organization&apos;s retained audit records when processing begins, including authorized source workspaces. This export is unaffected by visible list filters.</p>
    <p>Organization: {authority.organizationID}<br />Workspace: {authority.workspaceID}<br />Environment: {authority.environmentID}</p>
    {!authority.fresh && <p>Creating an export requires fresh authentication. <Button onClick={reauthenticate}>Reauthenticate</Button></p>}
    {!state.resume?.exportID && <Button disabled={state.busy || !authority.fresh} onClick={() => void controller.create()}>{state.resume ? "Retry create export" : "Create export"}</Button>}
    {state.resume?.exportID && !saving && <Button disabled={state.busy} onClick={() => void controller.check()}>Check status</Button>}
    {state.phase === "creating" && <p role="status">Creating export...</p>}
    {state.phase === "checking" && <p role="status">Checking export status...</p>}
    {descriptor && <p>Export: {descriptor.id}<br />Requested: {descriptor.created_at}</p>}
    {descriptor && ["queued", "processing"].includes(descriptor.status) && <p role="status">{descriptor.status === "queued" ? "Queued" : "Processing"}. Snapshot time and totals are available when ready.</p>}
    {descriptor?.status === "ready" && <>
      <p>Captured: {descriptor.captured_at}<br />{descriptor.event_count} events; {descriptor.chunk_count} chunks; {descriptor.chunk_bytes} chunk bytes.</p>
      <Button disabled={state.busy || !picker} onClick={() => {
        // Invoke the real picker within this trusted click, before any await.
        if (picker) void controller.save(picker());
      }}>Save complete export</Button>
      {!picker && <p>Saving requires a secure browser with directory access. This browser cannot save a complete export here.</p>}
      <p>Choose a parent folder. Each save creates a fresh child folder. Existing entries are refused; checks cannot guarantee exclusive creation against another local process. Partial files are never deleted.</p>
    </>}
    {state.progress && <p role="status">Saved {state.progress.chunkCount} of {descriptor?.status === "ready" ? descriptor.chunk_count : "?"} chunks; {state.progress.eventCount} of {descriptor?.status === "ready" ? descriptor.event_count : "?"} events; {state.progress.chunkBytes} bytes.</p>}
    {state.phase === "finalizing" && <p role="status">Finalizing manifest. Waiting for its actual write and close result.</p>}
    {state.phase === "read-retry" && <Button onClick={controller.retryRead}>Retry page read</Button>}
    {(state.busy || ["queued", "processing"].includes(state.phase)) && <Button onClick={() => void controller.stop()}>{state.phase === "finalizing" ? "Stop after finalization" : "Stop"}</Button>}
    {failedMessage && <p role="alert">{failedMessage} Correlation: {descriptor?.audit_correlation_id}</p>}
    {state.message && <p role={state.phase === "saved" || state.phase === "paused" || state.phase === "revalidating" ? "status" : "alert"}>{state.message}</p>}
    {descriptor?.status === "failed" && <Button disabled={state.busy || !authority.fresh} onClick={() => void controller.create(true)}>Create new export</Button>}
  </Card>;
}
