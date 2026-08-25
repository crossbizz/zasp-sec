"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import type { APIClient } from "../../../apps/web/api/client";
import type { RecoveryBackup, RecoveryRestore } from "../../../apps/web/api/generated";
import { Badge, Button, Card, EmptyState, Field, LoadingState, PageHeader } from "../../components/ui";
import { createRecoveryAPI, type RecoveryAPI, type StartBackupInput, type StartRestoreInput } from "./api";

type RetainedRecovery = Readonly<{
  version: 1;
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
  storage?: Storage;
  pollIntervalMs?: number;
  maximumPolls?: number;
}>;

const PRODUCT_ID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;
const DEFAULT_POLL_INTERVAL_MS = 2_000;
const DEFAULT_MAXIMUM_POLLS = 120;

export function RecoveryOperationsView({ expectedScope, canWrite, fresh, onReauthenticate, api: suppliedAPI, client, storage: suppliedStorage, pollIntervalMs = DEFAULT_POLL_INTERVAL_MS, maximumPolls = DEFAULT_MAXIMUM_POLLS }: RecoveryOperationsViewProps) {
  const api = useMemo(() => suppliedAPI ?? (client ? createRecoveryAPI(client, expectedScope) : null), [suppliedAPI, client, expectedScope]);
  const storage = useMemo(() => suppliedStorage ?? browserSessionStorage(), [suppliedStorage]);
  const storageKey = `zasp:recovery:v1:${expectedScope}`;
  const [retained, setRetained] = useState<RetainedRecovery>(() => readRetained(storage, storageKey));
  const startupRetained = useRef(retained);
  const [backup, setBackup] = useState<RecoveryBackup | null>(null);
  const [restore, setRestore] = useState<RecoveryRestore | null>(null);
  const [retentionDays, setRetentionDays] = useState(30);
  const [targetEnvironment, setTargetEnvironment] = useState("recovery-rehearsal");
  const [loading, setLoading] = useState(retained.backup !== null || retained.restore !== null);
  const [busy, setBusy] = useState(false);
  const [ambiguous, setAmbiguous] = useState<"backup" | "restore" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mutation = useRef<AbortController | null>(null);
  const backupPollingSeed = useRef(backup);
  const restorePollingSeed = useRef(restore);

  const persist = (next: RetainedRecovery) => { setRetained(next); writeRetained(storage, storageKey, next); };

  useEffect(() => {
    const controller = new AbortController(); let current = true;
    const load = async () => {
      const startup = startupRetained.current;
      if (!api) { if (current) { setError("Recovery operations are unavailable."); setLoading(false); } return; }
      const [backupResult, restoreResult] = await Promise.allSettled([
        startup.backup ? api.getBackup(startup.backup.id, controller.signal) : Promise.resolve(null),
        startup.restore ? api.getRestore(startup.restore.id, controller.signal) : Promise.resolve(null),
      ]);
      if (controller.signal.aborted || !current) return;
      if (backupResult.status === "fulfilled") setBackup(backupResult.value);
      if (restoreResult.status === "fulfilled") setRestore(restoreResult.value);
      if (backupResult.status === "rejected" || restoreResult.status === "rejected") {
        setAmbiguous(restoreResult.status === "rejected" && startup.restore ? "restore" : "backup");
        setError("Recovery state could not be verified. Retry the authoritative status check.");
      } else {
        setError(null);
      }
      setLoading(false);
    };
    void load();
    return () => { current = false; controller.abort(new DOMException("Recovery page changed", "AbortError")); };
  }, [api]);

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
    const input: StartBackupInput = retry && retained.backup
      ? { backupID: retained.backup.id, retentionDays: retained.backup.retention_days, idempotencyKey: retained.backup.idempotency_key }
      : { backupID: recoveryProductID(), retentionDays, idempotencyKey: recoveryIdempotencyKey("backup") };
    const pending: RetainedRecovery = { version: 1, backup: { id: input.backupID, retention_days: input.retentionDays, idempotency_key: input.idempotencyKey }, restore: null };
    persist(pending); setBusy(true); setAmbiguous(null); setError(null); mutation.current?.abort(); mutation.current = new AbortController();
    try {
      const value = await api.startBackup(input, mutation.current.signal); setBackup(value); setRestore(null); setAmbiguous(null);
      persist({ ...pending, backup: { ...pending.backup!, id: value.id } });
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
    const input: StartRestoreInput = retry && retained.restore
      ? { restoreID: retained.restore.id, targetEnvironment: retained.restore.target_environment, manifest: backup.manifest, idempotencyKey: retained.restore.idempotency_key }
      : { restoreID: recoveryProductID(), targetEnvironment, manifest: backup.manifest, idempotencyKey: recoveryIdempotencyKey("restore") };
    const pending: RetainedRecovery = { ...retained, restore: { id: input.restoreID, target_environment: input.targetEnvironment, idempotency_key: input.idempotencyKey } };
    persist(pending); setBusy(true); setAmbiguous(null); setError(null); mutation.current?.abort(); mutation.current = new AbortController();
    try {
      const value = await api.startRestore(input, mutation.current.signal); setRestore(value); setAmbiguous(null);
      persist({ ...pending, restore: { ...pending.restore!, id: value.id } });
    } catch {
      if (mutation.current.signal.aborted) return;
      setAmbiguous("restore"); setError("The restore request may have committed. Retry only with the retained operation.");
    } finally { setBusy(false); }
  };

  const refresh = async () => {
    if (!api || busy) return; setBusy(true); setError(null); mutation.current?.abort(); mutation.current = new AbortController();
    try {
      if (retained.backup) setBackup(await api.getBackup(retained.backup.id, mutation.current.signal));
      if (retained.restore) setRestore(await api.getRestore(retained.restore.id, mutation.current.signal));
    } catch { if (!mutation.current.signal.aborted) setError("Recovery state could not be verified. Retry the authoritative status check."); } finally { setBusy(false); }
  };

  const backupAction = !fresh ? <Button disabled={!canWrite} onClick={onReauthenticate}>Reauthenticate to start backup</Button> : <Button variant="primary" disabled={!canWrite || busy || backup !== null || !validRetentionDays(retentionDays)} onClick={() => void startBackup(false)}>Start signed backup</Button>;
  return <div className="page">
    <PageHeader eyebrow="Administration" title="Recovery operations" description="Create a signed tenant backup and validate it through an isolated restore rehearsal." actions={backupAction} />
    {!canWrite && <p role="status">Recovery operations are read-only for this account.</p>}
    <Card title="Backup settings"><Field label="Retention days" type="number" min={7} max={90} value={retentionDays} disabled={backup !== null || busy} onChange={(event) => setRetentionDays(Number(event.target.value))} /></Card>
    {loading && <LoadingState label="Loading recovery state…" />}
    {!loading && backup === null && <EmptyState title="No recovery operation in this scope" description="Start with a signed tenant backup." />}
    {backup && <RecoveryBackupCard value={backup} />}
    {backup?.state === "succeeded" && <Card title="Restore rehearsal"><Field label="Recovery target" value={targetEnvironment} disabled={restore !== null || busy} onChange={(event) => setTargetEnvironment(event.target.value)} /><Button variant="primary" disabled={!canWrite || busy || restore !== null || !fresh || !validRecoveryTarget(targetEnvironment, expectedScope)} onClick={() => void startRestore(false)}>{fresh ? "Start restore rehearsal" : "Reauthenticate to start restore"}</Button></Card>}
    {restore && <RecoveryRestoreCard value={restore} />}
    {error && <p role="alert">{error}</p>}
    {ambiguous === "backup" && <Button disabled={busy} onClick={() => void startBackup(true)}>Retry retained backup</Button>}
    {ambiguous === "restore" && <Button disabled={busy || backup?.state !== "succeeded"} onClick={() => void startRestore(true)}>Retry retained restore</Button>}
    {(backup !== null || restore !== null) && <Button disabled={busy} onClick={() => void refresh()}>Refresh authoritative status</Button>}
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
function recoveryIdempotencyKey(kind: "backup" | "restore"): string { return `recovery_${kind}_${globalThis.crypto.randomUUID()}`; }

function browserSessionStorage(): Storage | undefined { try { return typeof window === "undefined" ? undefined : window.sessionStorage; } catch { return undefined; } }
function emptyRetained(): RetainedRecovery { return { version: 1, backup: null, restore: null }; }
function readRetained(storage: Storage | undefined, key: string): RetainedRecovery {
  if (!storage) return emptyRetained(); let parsed: unknown; try { const raw = storage.getItem(key); if (raw === null || raw.length > 2_048) return emptyRetained(); parsed = JSON.parse(raw); } catch { return emptyRetained(); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return emptyRetained(); const record = parsed as Record<string, unknown>; if (record.version !== 1 || Object.keys(record).some((field) => !["version", "backup", "restore"].includes(field))) return emptyRetained();
  const backup = retainedBackup(record.backup); const restore = retainedRestore(record.restore); if (record.backup !== null && !backup || record.restore !== null && !restore || restore && !backup) return emptyRetained(); return { version: 1, backup, restore };
}
function retainedBackup(value: unknown): RetainedRecovery["backup"] { if (value === null) return null; if (!value || typeof value !== "object" || Array.isArray(value)) return null; const record = value as Record<string, unknown>; if (Object.keys(record).sort().join() !== "id,idempotency_key,retention_days" || typeof record.id !== "string" || !PRODUCT_ID.test(record.id) || typeof record.idempotency_key !== "string" || !IDEMPOTENCY_KEY.test(record.idempotency_key) || !Number.isSafeInteger(record.retention_days) || (record.retention_days as number) < 7 || (record.retention_days as number) > 90) return null; return { id: record.id, idempotency_key: record.idempotency_key, retention_days: record.retention_days as number }; }
function retainedRestore(value: unknown): RetainedRecovery["restore"] { if (value === null) return null; if (!value || typeof value !== "object" || Array.isArray(value)) return null; const record = value as Record<string, unknown>; if (Object.keys(record).sort().join() !== "id,idempotency_key,target_environment" || typeof record.id !== "string" || !PRODUCT_ID.test(record.id) || typeof record.idempotency_key !== "string" || !IDEMPOTENCY_KEY.test(record.idempotency_key) || typeof record.target_environment !== "string" || !/^[a-z][a-z0-9-]{0,62}$/.test(record.target_environment) || record.target_environment === "production") return null; return { id: record.id, idempotency_key: record.idempotency_key, target_environment: record.target_environment }; }
function writeRetained(storage: Storage | undefined, key: string, value: RetainedRecovery): void { try { storage?.setItem(key, JSON.stringify(value)); } catch { /* recovery remains available in memory */ } }
