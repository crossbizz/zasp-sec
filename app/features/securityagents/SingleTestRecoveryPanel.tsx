"use client";

import { useRef, useState } from "react";
import { Button } from "../../components/ui";
import { createSingleTestRecoveryIntent, type RecoveryIntent, type RecoveryIntentSource } from "./recovery-intent";

export type RecoveryPanelView = RecoveryIntentSource & {
  readonly completion: { readonly receipt_id: string; readonly outcome: string } | null;
};
export type SingleTestRecoveryPanelProps = {
  runID: string;
  version: number;
  state: "loading" | "ready" | "stale" | "forbidden" | "unavailable";
  value?: RecoveryPanelView;
  canManage: boolean;
  blocked?: boolean;
  canRetry?: boolean;
  hasRetainedRequest?: boolean;
  onRequest(intent: RecoveryIntent): Promise<void>;
  onRetry(): Promise<void>;
  onRefresh(): void;
};
const statusLabels: Record<string, string> = {
  not_requested: "Cleanup recovery has not been requested.",
  queued: "Cleanup recovery is queued. Completion is not yet verified.",
  pending: "Cleanup is pending. Unverified work may still retain capacity.",
  repair_required: "Cleanup needs operator attention. Outstanding work remains unresolved.",
  complete: "Cleanup complete.",
};
const outcomes = new Set(["cancelled", "failed", "inconclusive", "needs_human", "contained", "remediated"]);
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function SingleTestRecoveryPanel({ runID, version, state, value, canManage, blocked = false, canRetry = false, hasRetainedRequest = canRetry, onRequest, onRetry, onRefresh }: SingleTestRecoveryPanelProps) {
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const inFlight = useRef(false);
  const identityKey = JSON.stringify([runID, version, value?.run_id, value?.parent_version, value?.request_identity, state, canManage]);
  const [retainedIdentityKey, setRetainedIdentityKey] = useState(identityKey);
  if (retainedIdentityKey !== identityKey) {
    setRetainedIdentityKey(identityKey);
    setConfirmed(false);
    setFailed(false);
  }
  let unavailable: string | null = state === "loading" ? "Loading cleanup recovery status."
    : state === "forbidden" ? "Current permission to read cleanup recovery is unavailable."
    : state === "stale" ? "Recovery status changed. Refresh before making another request."
    : state === "unavailable" ? "Cleanup recovery is unavailable for this run."
    : null;
  if (!unavailable && (!value || value.run_id !== runID || !canRetry && value.parent_version !== version)) unavailable = "Recovery status changed. Refresh before making another request.";
  if (!unavailable && value && (!Object.hasOwn(statusLabels, value.status)
    || value.status === "complete" && (!value.completion || !productID.test(value.completion.receipt_id) || !outcomes.has(value.completion.outcome)))) {
    unavailable = "Verified cleanup recovery evidence is unavailable.";
  }
  const submit = async (retry: boolean) => {
    if (inFlight.current || unavailable || !canManage || (!retry && (blocked || !confirmed || !value)) || (retry && !canRetry)) return;
    inFlight.current = true; setBusy(true); setFailed(false); setConfirmed(false);
    try {
      if (retry) await onRetry();
      else await onRequest(createSingleTestRecoveryIntent(value!, runID, version));
    } catch { setFailed(true); }
    finally { inFlight.current = false; setBusy(false); }
  };
  return <section aria-label="SingleTest cleanup recovery">
    <h3>SingleTest cleanup recovery</h3>
    {unavailable ? <p role="status">{unavailable}</p> : <>
      <p role="status">{hasRetainedRequest ? "Cleanup recovery request outcome is unknown." : statusLabels[value!.status]}</p>
      <p>This does not mean the security issue was remediated. Recovery only processes the original run&apos;s cleanup obligations.</p>
      {value!.status === "complete" && value!.completion && <>
        <p>Recorded run outcome: {value!.completion.outcome}</p>
        <p>Completion receipt: {value!.completion.receipt_id}</p>
      </>}
      {canManage && (canRetry ? <Button disabled={busy} onClick={() => void submit(true)}>Retry retained cleanup request</Button>
        : value!.status === "not_requested" && <>
          <label><input type="checkbox" checked={confirmed} disabled={busy || blocked} onChange={event => setConfirmed(event.target.checked)} />
            I confirm the original workflow history is unavailable and request stopping further work before cleanup recovery.</label>
          <p>The server rechecks workflow status and current authority. This request does not start a new test or send new provider work.</p>
          <Button variant="danger" disabled={!confirmed || busy || blocked} onClick={() => void submit(false)}>Request cleanup recovery</Button>
        </>)}
      {failed && <p role="alert">{canRetry ? "The response was lost. Retry reuses the exact retained request." : "Recovery was rejected or is unavailable. Refresh current authority before retrying."}</p>}
    </>}
    {state !== "loading" && state !== "forbidden" && <Button disabled={busy || blocked} onClick={onRefresh}>Refresh recovery status</Button>}
  </section>;
}
