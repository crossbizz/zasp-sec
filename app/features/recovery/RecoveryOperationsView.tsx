"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import { parseRecoveryLink, recoveryLink, type RecoverySelection } from "../../domain/recovery-links";
import type { APIClient } from "../../../apps/web/api/client";
import type { RecoveryBackup, RecoveryRestore } from "../../../apps/web/api/generated";
import { Badge, Button, Card, EmptyState, Field, LoadingState, PageHeader } from "../../components/ui";
import { createRecoveryAPI, type RecoveryAPI, type StartBackupInput, type StartRestoreInput } from "./api";

type RetainedRecovery = Readonly<{
  backup: Readonly<{ id: string; retention_days: number; idempotency_key: string }> | null;
  restore: Readonly<{ id: string; target_environment: string; idempotency_key: string }> | null;
}>;

type RecoveryOperationsViewProps = Readonly<{
  expectedScope: string;
  canWrite: boolean;
  fresh: boolean;
  onReauthenticate(): void;
  api?: RecoveryAPI;
  client?: APIClient;
  pollIntervalMs?: number;
  maximumPolls?: number;
}>;

const DEFAULT_POLL_INTERVAL_MS = 2_000;
const DEFAULT_MAXIMUM_POLLS = 120;

export function RecoveryOperationsView({ expectedScope, canWrite, fresh, onReauthenticate, api: suppliedAPI, client, pollIntervalMs = DEFAULT_POLL_INTERVAL_MS, maximumPolls = DEFAULT_MAXIMUM_POLLS }: RecoveryOperationsViewProps) {
  const api = useMemo(() => suppliedAPI ?? (client ? createRecoveryAPI(client, expectedScope) : null), [suppliedAPI, client, expectedScope]);
  const scope = useMemo(() => { const [organizationID, workspaceID, environmentID] = expectedScope.split("/"); return {organizationID, workspaceID, environmentID}; }, [expectedScope]);
  const [initialLink, setInitialLink] = useState(() => typeof window === "undefined" ? null : parseRecoveryLink(window.location.pathname + window.location.search + window.location.hash, scope));
  const linked = initialLink?.state === "selected" ? initialLink.ids : null;
  const [reference, setReference] = useState<RecoverySelection | null>(linked);
  const [retained, setRetained] = useState<RetainedRecovery>({ backup: null, restore: null });
  const [lookupVersion, setLookupVersion] = useState(0);
  const [backup, setBackup] = useState<RecoveryBackup | null>(null);
  const [restore, setRestore] = useState<RecoveryRestore | null>(null);
  const [retentionDays, setRetentionDays] = useState(30);
  const [targetEnvironment, setTargetEnvironment] = useState("recovery-rehearsal");
  const [loading, setLoading] = useState(Boolean(linked || retained.backup || retained.restore));
  const [busy, setBusy] = useState(false);
  const [ambiguous, setAmbiguous] = useState<"backup" | "restore" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mutation = useRef<AbortController | null>(null);
  const backupPollingSeed = useRef(backup);
  const restorePollingSeed = useRef(restore);

  useEffect(() => {
    const controller = new AbortController(); let current = true;
    const load = async () => {
      let startup: RetainedRecovery = { backup: null, restore: null };
      if (!api) { if (current) { setError("Recovery operations are unavailable."); setLoading(false); } return; }
      // Bookmarks hold resource IDs. Read the original parameters from the
      // authenticated server before offering an exact retry after reload.
      if (linked) {
        try {
          const saved = await api.getIntent(linked.restore ?? linked.backup, controller.signal);
          if (controller.signal.aborted) return;
          const p = saved.parameters;
          if (p.backup_id !== linked.backup || p.kind !== (linked.restore ? "restore" : "backup")) throw Error("Recovery request mismatch");
          if (p.kind === "backup") startup = {backup: {id: linked.backup, retention_days: p.retention_days, idempotency_key: operationKey("backup", linked.backup)}, restore: null};
          else startup = {backup: null, restore: {id: saved.id, target_environment: p.target_environment, idempotency_key: operationKey("restore", saved.id)}};
          setRetained(startup);
          if (p.kind === "restore") setTargetEnvironment(p.target_environment);
          else setRetentionDays(p.retention_days);
        } catch { if (controller.signal.aborted) return; }
      }
      const backupID = linked?.backup ?? startup.backup?.id;
      const restoreID = linked?.restore ?? startup.restore?.id;
      const [backupResult, restoreResult] = await Promise.allSettled([
        backupID ? api.getBackup(backupID, controller.signal) : Promise.resolve(null),
        restoreID ? api.getRestore(restoreID, controller.signal) : Promise.resolve(null),
      ]);
      if (controller.signal.aborted || !current) return;
      if (backupResult.status === "fulfilled") setBackup(backupResult.value);
      if (restoreResult.status === "fulfilled") setRestore(restoreResult.value);
      if (backupResult.status === "rejected" || restoreResult.status === "rejected") {
        setAmbiguous(restoreResult.status === "rejected" && startup.restore ? "restore" : "backup");
        setError("Recovery state could not be verified. Retry the authoritative status check.");
      } else {
        setAmbiguous(null);
        setError(null);
      }
      setLoading(false);
    };
    void load();
    return () => { current = false; controller.abort(new DOMException("Recovery page changed", "AbortError")); };
  }, [api, linked, lookupVersion]);

  useEffect(() => { backupPollingSeed.current = backup; }, [backup]);
  useEffect(() => { restorePollingSeed.current = restore; }, [restore]);
  useEffect(() => pollBackup(api, backupPollingSeed.current, pollIntervalMs, maximumPolls, setBackup, setError), [api, backup?.id, pollIntervalMs, maximumPolls]);
  useEffect(() => pollRestore(api, restorePollingSeed.current, pollIntervalMs, maximumPolls, setRestore, setError), [api, restore?.id, pollIntervalMs, maximumPolls]);
  useEffect(() => () => mutation.current?.abort(new DOMException("Recovery page changed", "AbortError")), []);

  const startBackup = async (retry: boolean) => {
    if (!api || busy || !canWrite) return;
    if (!retry && !validRetentionDays(retentionDays)) return;
    if (!fresh) { onReauthenticate(); return; }
    if (!retry && !window.confirm("Start a tenant-scoped signed backup? Mutations in this scope will drain briefly.")) return;
    const newID = retry ? retained.backup?.id : recoveryProductID();
    if (!newID) return;
    const input: StartBackupInput = retry && retained.backup
      ? { backupID: retained.backup.id, retentionDays: retained.backup.retention_days, idempotencyKey: retained.backup.idempotency_key }
      : { backupID: newID, retentionDays, idempotencyKey: operationKey("backup", newID) };
    const pending: RetainedRecovery = { backup: { id: input.backupID, retention_days: input.retentionDays, idempotency_key: input.idempotencyKey }, restore: null };
    setRetained(pending); setBusy(true); setAmbiguous(null); setError(null); mutation.current?.abort(); mutation.current = new AbortController();
    try {
      await api.putIntent(input.backupID, {kind: "backup", backup_id: input.backupID, retention_days: input.retentionDays}, mutation.current.signal);
      const ids = {backup: input.backupID};
      window.history.replaceState(window.history.state, "", recoveryLink(ids, scope)); setReference(ids);
      const value = await api.startBackup(input, mutation.current.signal); setBackup(value); setRestore(null); setAmbiguous(null);
      setRetained({ ...pending, backup: { ...pending.backup!, id: value.id } });
    } catch {
      if (mutation.current.signal.aborted) return;
      setAmbiguous("backup"); setError("The backup request may have committed. Retry only with the retained operation.");
    } finally { setBusy(false); }
  };

  const startRestore = async (retry: boolean) => {
    if (!api || busy || !canWrite || backup?.state !== "succeeded" || !backup.manifest) return;
    if (!retry && !validRecoveryTarget(targetEnvironment, expectedScope)) return;
    if (!fresh) { onReauthenticate(); return; }
    if (!retry && !window.confirm("Start an isolated restore rehearsal and delete its temporary resources after validation?")) return;
    const newID = retry ? retained.restore?.id : recoveryProductID();
    if (!newID) return;
    const input: StartRestoreInput = retry && retained.restore
      ? { restoreID: retained.restore.id, targetEnvironment: retained.restore.target_environment, manifest: backup.manifest, idempotencyKey: retained.restore.idempotency_key }
      : { restoreID: newID, targetEnvironment, manifest: backup.manifest, idempotencyKey: operationKey("restore", newID) };
    const pending: RetainedRecovery = { ...retained, restore: { id: input.restoreID, target_environment: input.targetEnvironment, idempotency_key: input.idempotencyKey } };
    setRetained(pending); setBusy(true); setAmbiguous(null); setError(null); mutation.current?.abort(); mutation.current = new AbortController();
    try {
      await api.putIntent(input.restoreID, {kind: "restore", backup_id: backup.id, target_environment: input.targetEnvironment}, mutation.current.signal);
      const ids = {backup: backup.id, restore: input.restoreID};
      window.history.replaceState(window.history.state, "", recoveryLink(ids, scope)); setReference(ids);
      const value = await api.startRestore(input, mutation.current.signal); setRestore(value); setAmbiguous(null);
      setRetained({ ...pending, restore: { ...pending.restore!, id: value.id } });
    } catch {
      if (mutation.current.signal.aborted) return;
      setAmbiguous("restore"); setError("The restore request may have committed. Retry only with the retained operation.");
    } finally { setBusy(false); }
  };

  const refresh = async () => {
    if (!api || busy || loading) return;
    if (linked && linked.backup === reference?.backup && linked.restore === reference.restore) { setLoading(true); setLookupVersion(version => version + 1); return; }
    setBusy(true); setError(null); mutation.current?.abort(); mutation.current = new AbortController();
    try {
      const backupID = reference?.backup ?? retained.backup?.id;
      const restoreID = reference?.restore ?? retained.restore?.id;
      if (backupID) setBackup(await api.getBackup(backupID, mutation.current.signal));
      if (restoreID) setRestore(await api.getRestore(restoreID, mutation.current.signal));
      setAmbiguous(null);
    } catch { if (!mutation.current.signal.aborted) setError("Recovery state could not be verified. Retry the authoritative status check."); } finally { setBusy(false); }
  };

  const clearSelection = () => {
    window.history.replaceState(window.history.state, "", "/administration/recovery");
    setInitialLink(null); setReference(null); setRetained({backup: null, restore: null});
    setBackup(null); setRestore(null); setAmbiguous(null); setError(null);
    setRetentionDays(30); setTargetEnvironment("recovery-rehearsal");
  };
  const unavailableLink = initialLink?.state === "invalid" || initialLink?.state === "scope_mismatch";
  const backupAction = !fresh ? <Button disabled={!canWrite} onClick={onReauthenticate}>Reauthenticate to start backup</Button> : <Button variant="primary" disabled={!canWrite || busy || loading || reference !== null || retained.backup !== null || unavailableLink || backup !== null || !validRetentionDays(retentionDays)} onClick={() => void startBackup(false)}>Start signed backup</Button>;
  return <div className="page">
    <PageHeader eyebrow="Administration" title="Recovery operations" description="Create a signed tenant backup and validate it through an isolated restore rehearsal." actions={backupAction} />
    {unavailableLink && <p role="alert">{initialLink?.state === "scope_mismatch" ? "This recovery link belongs to a different scope." : "This recovery link is invalid."}</p>}
    {!canWrite && <p role="status">Recovery operations are read-only for this account.</p>}
    <Card title="Backup settings"><Field label="Retention days" type="number" min={7} max={90} value={retentionDays} disabled={reference !== null || retained.backup !== null || backup !== null || busy || unavailableLink} onChange={(event) => setRetentionDays(Number(event.target.value))} /></Card>
    {loading && <LoadingState label="Loading recovery state…" />}
    {!loading && backup === null && !error && !unavailableLink && <EmptyState title="No recovery operation in this scope" description="Start with a signed tenant backup." />}
    {backup && <RecoveryBackupCard value={backup} />}
    {backup?.state === "succeeded" && <Card title="Restore rehearsal"><Field label="Recovery target" value={targetEnvironment} disabled={restore !== null || retained.restore !== null || Boolean(reference?.restore) || busy} onChange={(event) => setTargetEnvironment(event.target.value)} /><Button variant="primary" disabled={!canWrite || busy || restore !== null || retained.restore !== null || Boolean(reference?.restore) || !validRecoveryTarget(targetEnvironment, expectedScope)} onClick={() => fresh ? void startRestore(false) : onReauthenticate()}>{fresh ? "Start restore rehearsal" : "Reauthenticate to start restore"}</Button></Card>}
    {restore && <RecoveryRestoreCard value={restore} />}
    {error && <p role="alert">{error}</p>}
    {ambiguous === "backup" && retained.backup && <Button disabled={!canWrite || busy} onClick={() => void startBackup(true)}>Retry retained backup</Button>}
    {ambiguous === "restore" && retained.restore && <Button disabled={!canWrite || busy || backup?.state !== "succeeded"} onClick={() => void startRestore(true)}>Retry retained restore</Button>}
    {(backup !== null || restore !== null || reference !== null) && <Button disabled={busy || loading} onClick={() => void refresh()}>Refresh authoritative status</Button>}
    {(unavailableLink || reference !== null || retained.backup !== null) && <Button disabled={busy || loading} onClick={clearSelection}>Close recovery details</Button>}
  </div>;
}

function RecoveryBackupCard({ value }: { value: RecoveryBackup }) {
  return <Card title={`Backup ${stateLabel(value.state)}`}><Badge tone={stateTone(value.state)}>{stateLabel(value.state)}</Badge><p>Reference {value.id}</p><p>Retention {value.retention_days} days · attempt {value.attempt}</p>{value.state === "failed" && <p role="alert">The backup did not complete. Review recovery worker health before retrying.</p>}</Card>;
}

function RecoveryRestoreCard({ value }: { value: RecoveryRestore }) {
  return <Card title={`Restore ${stateLabel(value.state)}`}><Badge tone={stateTone(value.state)}>{stateLabel(value.state)}</Badge><p>Reference {value.id}</p><p>Target {value.target_environment} · attempt {value.attempt}</p>{value.observed_counts && <ul><li>{value.observed_counts.assets} assets</li><li>{value.observed_counts.findings} findings</li><li>{value.observed_counts.policies} policies</li></ul>}{value.cleanup_evidence?.state === "deleted" && <p>Temporary resources deleted</p>}{value.state === "failed_cleanup" && <p role="alert">Temporary recovery resources require manual cleanup. Follow the recovery runbook before another rehearsal.</p>}{value.state === "failed" && <p role="alert">The restore did not validate. Review recovery worker health and the public operation reference.</p>}</Card>;
}

function pollBackup(api: RecoveryAPI | null, initial: RecoveryBackup | null, delay: number, maximum: number, update: (value: RecoveryBackup) => void, fail: (message: string) => void): (() => void) | undefined {
  if (!api || !initial || terminalBackup(initial.state)) return undefined; const controller = new AbortController(); let stopped = false;
  void (async () => { let current = initial; for (let count = 0; count < maximum && !terminalBackup(current.state); count += 1) { await wait(delay, controller.signal); current = await api.getBackup(current.id, controller.signal); if (!stopped) update(current); } if (!stopped && !terminalBackup(current.state)) fail("Automatic status checks paused after reaching the safe polling limit. Refresh authoritative status to continue."); })().catch(() => { if (!controller.signal.aborted && !stopped) fail("Recovery state could not be verified. Retry the authoritative status check."); });
  return () => { stopped = true; controller.abort(new DOMException("Recovery status superseded", "AbortError")); };
}

function pollRestore(api: RecoveryAPI | null, initial: RecoveryRestore | null, delay: number, maximum: number, update: (value: RecoveryRestore) => void, fail: (message: string) => void): (() => void) | undefined {
  if (!api || !initial || terminalRestore(initial.state)) return undefined; const controller = new AbortController(); let stopped = false;
  void (async () => { let current = initial; for (let count = 0; count < maximum && !terminalRestore(current.state); count += 1) { await wait(delay, controller.signal); current = await api.getRestore(current.id, controller.signal); if (!stopped) update(current); } if (!stopped && !terminalRestore(current.state)) fail("Automatic status checks paused after reaching the safe polling limit. Refresh authoritative status to continue."); })().catch(() => { if (!controller.signal.aborted && !stopped) fail("Recovery state could not be verified. Retry the authoritative status check."); });
  return () => { stopped = true; controller.abort(new DOMException("Recovery status superseded", "AbortError")); };
}

function wait(delay: number, signal: AbortSignal): Promise<void> { return new Promise((resolve, reject) => { const timer = window.setTimeout(resolve, delay); signal.addEventListener("abort", () => { window.clearTimeout(timer); reject(signal.reason); }, { once: true }); }); }
function terminalBackup(state: RecoveryBackup["state"]): boolean { return state === "succeeded" || state === "failed"; }
function terminalRestore(state: RecoveryRestore["state"]): boolean { return state === "succeeded" || state === "failed" || state === "failed_cleanup"; }
function stateLabel(value: string): string { return value === "failed_cleanup" ? "cleanup failed" : value.replaceAll("_", " "); }
function stateTone(value: string): "success" | "warning" | "info" { return value === "succeeded" ? "success" : value === "failed" || value === "failed_cleanup" ? "warning" : "info"; }
function validRetentionDays(value: number): boolean { return Number.isSafeInteger(value) && value >= 7 && value <= 90; }
function validRecoveryTarget(value: string, expectedScope: string): boolean { return /^[a-z][a-z0-9-]{0,62}$/.test(value) && value !== "production" && value !== expectedScope.split("/")[2]; }
function recoveryProductID(): string { return `pid_${globalThis.crypto.randomUUID()}`; }
function operationKey(kind: "backup" | "restore", id: string): string { return `recovery_${kind}_${id.slice(4)}`; }
