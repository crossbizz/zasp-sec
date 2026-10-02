"use client";

import { useEffect, useState } from "react";
import { APIProductError } from "../../../apps/web/api/client";
import type { SingleTestRecoveryView } from "../../../apps/web/api/single-test-recovery";
import { isAmbiguousWorkflowMutationError, type WorkflowMutationAttempt, type WorkflowReceipt } from "../workflows/api";
import type { useRetainedWorkflowMutation } from "../workflows/useRetainedWorkflowMutation";
import type { RecoveryIntent } from "./recovery-intent";
import { SingleTestRecoveryPanel } from "./SingleTestRecoveryPanel";

export type SingleTestRecoveryAPI = {
  get(id: string, signal?: AbortSignal): Promise<SingleTestRecoveryView>;
  request(intent: RecoveryIntent, attempt: WorkflowMutationAttempt): Promise<WorkflowReceipt<SingleTestRecoveryView>>;
};
export type SingleTestRecoveryMutation = ReturnType<typeof useRetainedWorkflowMutation<RecoveryIntent>>;
type Props = { api: SingleTestRecoveryAPI; runID: string; version: number; canManage: boolean; blocked: boolean;
  mutation: SingleTestRecoveryMutation; onSettled(): Promise<void> };
type Loaded = { api: SingleTestRecoveryAPI; runID: string; version: number; epoch: number;
  state: "ready" | "forbidden" | "unavailable"; value?: SingleTestRecoveryView };

export function SingleTestRecovery({ api, runID, version, canManage, blocked, mutation, onSettled }: Props) {
  const [epoch, setEpoch] = useState(0);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const current = loaded?.api === api && loaded.runID === runID && loaded.version === version && loaded.epoch === epoch ? loaded : null;
  useEffect(() => {
    const controller = new AbortController();
    void api.get(runID, controller.signal).then(value => {
      if (!controller.signal.aborted) setLoaded({ api, runID, version, epoch, state: "ready", value });
    }, error => {
      if (!controller.signal.aborted) setLoaded({ api, runID, version, epoch,
        state: error instanceof APIProductError && [401, 403].includes(error.status) ? "forbidden" : "unavailable" });
    });
    return () => controller.abort();
  }, [api, runID, version, epoch]);
  useEffect(() => {
    if (blocked || current?.state !== "ready" || !current.value || !["queued", "pending", "repair_required"].includes(current.value.status)) return;
    const timer = window.setInterval(() => setEpoch(value => value + 1), 5000);
    return () => window.clearInterval(timer);
  }, [blocked, current]);
  const settled = async () => { setEpoch(value => value + 1); await onSettled(); };
  const submit = async (send: () => Promise<unknown>) => {
    try { await send(); }
    catch (error) {
      if (!isAmbiguousWorkflowMutationError(error)) setEpoch(value => value + 1);
      throw error;
    }
    await settled();
  };
  return <SingleTestRecoveryPanel runID={runID} version={version} state={current?.state ?? "loading"} value={current?.value}
    canManage={canManage} blocked={blocked} canRetry={mutation.canRetry} hasRetainedRequest={mutation.retainedIntent !== null}
    onRequest={intent => submit(() => mutation.execute(intent, (frozen, attempt) => api.request(frozen, attempt)))}
    onRetry={() => submit(() => mutation.retry())} onRefresh={() => setEpoch(value => value + 1)} />;
}
