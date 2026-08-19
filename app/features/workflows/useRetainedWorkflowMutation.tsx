"use client";

import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useState, useSyncExternalStore } from "react";

import type { WorkflowMutationReceipt } from "../../../apps/web/api/generated";
import { APIProductError, APITransportError } from "../../../apps/web/api/client";
import { useAPI } from "../../api/APIProvider";
import { Button } from "../../components/ui";
import {
  createRetainedWorkflowMutationController,
  createWorkflowRecoveryAPI,
  type WorkflowMutationAttempt,
  type WorkflowRecoveryAPI,
} from "./api";
import { workflowReceiptSummary } from "./workflowReceiptSummary";

type Controller = ReturnType<typeof createRetainedWorkflowMutationController<unknown>>;
type RecoveryState = {
  status: "loading" | "ready" | "error";
  receipts: readonly WorkflowMutationReceipt[];
  error: string | null;
  acknowledging: ReadonlySet<string>;
  acknowledgementErrors: ReadonlyMap<string, string>;
  generation: number;
};

type ScopeSnapshot = {
  isUnresolved: boolean;
  canRetry: boolean;
  recovery: RecoveryState | null;
};

type CapturedScopeTransport = {
  scopeKey: string;
  generation: number;
  service: WorkflowRecoveryAPI;
};

class WorkflowMutationStore {
  private readonly controllers = new Map<string, Controller>();
  private readonly recovery = new Map<string, RecoveryState>();
  private readonly services = new Map<string, WorkflowRecoveryAPI>();
  private readonly recoveredCallbacks = new Map<string, () => void>();
  private readonly listeners = new Set<() => void>();
  private revision = 0;
  private activeScope = "";
  private activeScopeGeneration = 0;
  private recoveryActivity = 0;

  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  readonly getRevision = () => this.revision;

  activate(scopeKey: string, service?: WorkflowRecoveryAPI, onRecovered?: () => void) {
    const serviceChanged = Boolean(service) && this.services.get(scopeKey) !== service;
    if (this.activeScope !== scopeKey || serviceChanged) {
      this.activeScope = scopeKey;
      this.activeScopeGeneration++;
    }
    if (onRecovered) this.recoveredCallbacks.set(scopeKey, onRecovered);
    if (!service) return;
    this.services.set(scopeKey, service);
    if (!this.recovery.has(scopeKey)) {
      this.recovery.set(scopeKey, emptyRecovery("loading"));
      this.revision++;
    }
  }

  snapshot(scopeKey: string, operationKey?: string): ScopeSnapshot {
    const recovery = this.recovery.get(scopeKey) ?? null;
    const scopeControllers = this.scopeControllers(scopeKey);
    const isUnresolved = this.recoveryActivity > 0 || recovery !== null && (recovery.status !== "ready" || recovery.receipts.length > 0)
      || scopeControllers.some((controller) => controller.isUnresolved());
    const owner = operationKey ? this.controllers.get(registryKey(scopeKey, operationKey)) : undefined;
    const canRetry = this.recoveryActivity === 0 && Boolean(owner?.canRetry()) && recovery?.status !== "loading" && recovery?.status !== "error" && !recovery?.receipts.length;
    return { isUnresolved, canRetry, recovery };
  }

  execute<I, T>(scopeKey: string, operationKey: string, intent: I, send: (intent: I, attempt: WorkflowMutationAttempt) => Promise<T>): Promise<T> {
    const controller = this.get<I>(scopeKey, operationKey);
    const competing = this.scopeControllers(scopeKey).find((candidate) => candidate !== controller && candidate.isUnresolved());
    const recovery = this.recovery.get(scopeKey);
    if (this.recoveryActivity > 0 || competing || recovery && (recovery.status !== "ready" || recovery.receipts.length > 0)) {
      return Promise.reject(new Error("Another workflow mutation or recovery is unresolved in this scope"));
    }
    const transport = this.captureTransport(scopeKey);
    const promise = controller.execute(intent, async (frozen, attempt) => {
      const result = await send(frozen as I, attempt);
      const receiptID = mutationReceiptID(result);
      if (receiptID && transport) await this.acknowledgeSuccessfulResult(transport, receiptID);
      return result;
    }) as Promise<T>;
    this.notify();
    void promise.then(() => this.notify(), () => this.notify());
    return promise;
  }

  retry<T>(scopeKey: string, operationKey: string): Promise<T> {
    const controller = this.get<unknown>(scopeKey, operationKey);
    if (!this.snapshot(scopeKey, operationKey).canRetry) return Promise.reject(new Error("No settled ambiguous workflow mutation is available to retry"));
    const promise = controller.retry<T>();
    this.notify();
    void promise.then(() => this.notify(), () => this.notify());
    return promise;
  }

  resolve(scopeKey: string, operationKey: string) {
    this.get<unknown>(scopeKey, operationKey).resolveAfterServerReconciliation();
    this.notify();
  }

  async reconcile(scopeKey: string, signal?: AbortSignal) {
    const transport = this.captureTransport(scopeKey);
    if (!transport) return;
    const current = this.recovery.get(scopeKey) ?? emptyRecovery("loading");
    const generation = current.generation + 1;
    this.recovery.set(scopeKey, { ...current, status: "loading", error: null, generation });
    this.recoveryActivity++;
    this.notify();
    try {
      const receipts = await transport.service.listReceipts(signal);
      if (signal?.aborted || !this.isTransportCurrent(transport) || this.recovery.get(scopeKey)?.generation !== generation) return;
      this.recovery.set(scopeKey, { status: "ready", receipts, error: null, acknowledging: new Set(), acknowledgementErrors: new Map(), generation });
      this.notify();
    } catch (error) {
      if (signal?.aborted || !this.isTransportCurrent(transport) || this.recovery.get(scopeKey)?.generation !== generation) return;
      this.recovery.set(scopeKey, { ...current, status: "error", error: errorMessage(error, "Committed-operation recovery is unavailable."), generation });
      this.notify();
    } finally {
      this.recoveryActivity--;
      this.notify();
    }
  }

  async acknowledge(scopeKey: string, receiptID: string) {
    const transport = this.captureTransport(scopeKey);
    const current = this.recovery.get(scopeKey);
    if (!transport || !current || current.acknowledging.has(receiptID)) return;
    const acknowledging = new Set(current.acknowledging); acknowledging.add(receiptID);
    const acknowledgementErrors = new Map(current.acknowledgementErrors); acknowledgementErrors.delete(receiptID);
    this.recovery.set(scopeKey, { ...current, acknowledging, acknowledgementErrors });
    this.recoveryActivity++;
    this.notify();
    try {
      try {
        await transport.service.acknowledgeReceipt(receiptID);
      } catch (error) {
        if (!isMissingReceipt(error)) throw error;
      }
      const receipts = await transport.service.listReceipts();
      if (!this.isTransportCurrent(transport)) throw scopeGenerationDrift();
      const latest = this.recovery.get(scopeKey);
      if (!latest) return;
      const nextAcknowledging = new Set(latest.acknowledging); nextAcknowledging.delete(receiptID);
      const nextErrors = new Map(latest.acknowledgementErrors); nextErrors.delete(receiptID);
      this.recovery.set(scopeKey, { ...latest, status: "ready", receipts, error: null, acknowledging: nextAcknowledging, acknowledgementErrors: nextErrors });
      if (receipts.length === 0) for (const controller of this.scopeControllers(scopeKey)) if (controller.canRetry()) controller.resolveAfterServerReconciliation();
      this.recoveredCallbacks.get(scopeKey)?.();
      this.notify();
    } catch (error) {
      const latest = this.recovery.get(scopeKey);
      if (!latest) return;
      const nextAcknowledging = new Set(latest.acknowledging); nextAcknowledging.delete(receiptID);
      const nextErrors = new Map(latest.acknowledgementErrors); nextErrors.set(receiptID, errorMessage(error, "Acknowledgement failed."));
      this.recovery.set(scopeKey, { ...latest, acknowledging: nextAcknowledging, acknowledgementErrors: nextErrors });
      this.notify();
    } finally {
      this.recoveryActivity--;
      this.notify();
    }
  }

  private get<I>(scopeKey: string, operationKey: string) {
    if (!scopeKey || !operationKey) throw new Error("Workflow mutation scope and operation keys are required");
    const key = registryKey(scopeKey, operationKey);
    let controller = this.controllers.get(key);
    if (!controller) {
      controller = createRetainedWorkflowMutationController<unknown>();
      this.controllers.set(key, controller);
    }
    return controller as ReturnType<typeof createRetainedWorkflowMutationController<I>>;
  }

  private scopeControllers(scopeKey: string): Controller[] {
    const prefix = `${JSON.stringify(scopeKey)}:`;
    return [...this.controllers.entries()].filter(([key]) => key.startsWith(prefix)).map(([, controller]) => controller);
  }

  private async acknowledgeSuccessfulResult(transport: CapturedScopeTransport, receiptID: string) {
    const { scopeKey, service } = transport;
    this.recoveryActivity++;
    this.notify();
    try {
      try {
        await service.acknowledgeReceipt(receiptID);
      } catch (error) {
        if (!isMissingReceipt(error)) throw error;
      }
      const receipts = await service.listReceipts();
      if (!this.isTransportCurrent(transport)) throw scopeGenerationDrift();
      const current = this.recovery.get(scopeKey) ?? emptyRecovery("ready");
      this.recovery.set(scopeKey, { ...current, status: "ready", receipts, error: null, acknowledging: new Set(), acknowledgementErrors: new Map() });
      if (receipts.length === 0) for (const controller of this.scopeControllers(scopeKey)) if (controller.canRetry()) controller.resolveAfterServerReconciliation();
      this.recoveredCallbacks.get(scopeKey)?.();
      this.notify();
    } catch (error) {
      const current = this.recovery.get(scopeKey) ?? emptyRecovery("error");
      this.recovery.set(scopeKey, { ...current, status: "error", error: errorMessage(error, "The committed result could not be acknowledged.") });
      this.notify();
      throw error instanceof APITransportError ? error : new APITransportError("invalid_response", "The committed result could not be reconciled in its captured scope");
    } finally {
      this.recoveryActivity--;
      this.notify();
    }
  }

  private captureTransport(scopeKey: string): CapturedScopeTransport | undefined {
    const service = this.services.get(scopeKey);
    if (!service || this.activeScope !== scopeKey) return undefined;
    return Object.freeze({ scopeKey, generation: this.activeScopeGeneration, service });
  }

  private isTransportCurrent(transport: CapturedScopeTransport): boolean {
    return this.activeScope === transport.scopeKey
      && this.activeScopeGeneration === transport.generation
      && this.services.get(transport.scopeKey) === transport.service;
  }

  private notify() {
    this.revision++;
    for (const listener of this.listeners) listener();
  }
}

type WorkflowMutationRegistry = { store: WorkflowMutationStore; scopeKey: string };
const WorkflowMutationRegistryContext = createContext<WorkflowMutationRegistry | null>(null);

export function WorkflowMutationProvider({ scopeKey, recovery, onRecovered, children }: { scopeKey: string; recovery?: WorkflowRecoveryAPI; onRecovered?: () => void; children: ReactNode }) {
  const [store] = useState(() => new WorkflowMutationStore());
  store.activate(scopeKey, recovery, onRecovered);
  useSyncExternalStore(store.subscribe, store.getRevision, store.getRevision);
  const snapshot = store.snapshot(scopeKey);
  useEffect(() => {
    if (!recovery) return;
    const controller = new AbortController();
    void store.reconcile(scopeKey, controller.signal);
    return () => controller.abort();
  }, [recovery, scopeKey, store]);
  useEffect(() => {
    if (!snapshot.isUnresolved) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [snapshot.isUnresolved]);
  const value = useMemo(() => ({ store, scopeKey }), [scopeKey, store]);
  return <WorkflowMutationRegistryContext.Provider value={value}>
    {recovery && <WorkflowRecoveryPanel store={store} scopeKey={scopeKey} />}
    {children}
  </WorkflowMutationRegistryContext.Provider>;
}

export function ProductionWorkflowMutationProvider({ scopeKey, expectedScope, children }: { scopeKey: string; expectedScope: string; children: ReactNode }) {
  const { client, invalidate } = useAPI();
	const recovery = useMemo(() => createWorkflowRecoveryAPI(client, expectedScope), [client, expectedScope]);
  const recovered = useCallback(() => invalidate(["workflow:policies", "workflow:integrations", "workflow:security-agents", "risk:findings", "risk:attack-paths"]), [invalidate]);
  return <WorkflowMutationProvider scopeKey={scopeKey} recovery={recovery} onRecovered={recovered}>{children}</WorkflowMutationProvider>;
}

const emptySubscribe = () => () => undefined;
const zeroRevision = () => 0;

export function useWorkflowMutationScopeLock(): boolean {
  const registry = useContext(WorkflowMutationRegistryContext);
  useSyncExternalStore(registry?.store.subscribe ?? emptySubscribe, registry?.store.getRevision ?? zeroRevision, registry?.store.getRevision ?? zeroRevision);
  return registry?.store.snapshot(registry.scopeKey).isUnresolved ?? false;
}

export function useRetainedWorkflowMutation<I>(operationKey = "component-local") {
  const registry = useContext(WorkflowMutationRegistryContext);
  const [localStore] = useState(() => { const store = new WorkflowMutationStore(); store.activate("component-local-scope"); return store; });
  const store = registry?.store ?? localStore;
  const scopeKey = registry?.scopeKey ?? "component-local-scope";
  useSyncExternalStore(store.subscribe, store.getRevision, store.getRevision);
  const snapshot = store.snapshot(scopeKey, operationKey);
  const execute = useCallback(<T,>(intent: I, send: (frozenIntent: I, attempt: WorkflowMutationAttempt) => Promise<T>) => store.execute(scopeKey, operationKey, intent, send), [operationKey, scopeKey, store]);
  const retry = useCallback(<T,>() => store.retry<T>(scopeKey, operationKey), [operationKey, scopeKey, store]);
  const resolveAfterServerReconciliation = useCallback(() => store.resolve(scopeKey, operationKey), [operationKey, scopeKey, store]);
  return { execute, retry, isUnresolved: snapshot.isUnresolved, canRetry: snapshot.canRetry, hasAmbiguousAttempt: snapshot.canRetry, resolveAfterServerReconciliation } as const;
}

function WorkflowRecoveryPanel({ store, scopeKey }: { store: WorkflowMutationStore; scopeKey: string }) {
  useSyncExternalStore(store.subscribe, store.getRevision, store.getRevision);
  const recovery = store.snapshot(scopeKey).recovery;
  if (!recovery) return null;
  if (recovery.status === "loading") return <section aria-label="Mutation recovery"><p role="status">Checking committed operations before enabling changes…</p></section>;
  if (recovery.status === "error") return <section aria-label="Mutation recovery"><p role="alert">{recovery.error}</p><Button onClick={() => void store.reconcile(scopeKey)}>Retry committed-operation recovery</Button></section>;
  if (recovery.receipts.length === 0) return null;
  return <section aria-label="Mutation recovery"><h2>Recover committed operations</h2><p>These changes committed before their browser responses were acknowledged. Review the frozen request and authoritative result before making another change.</p>{recovery.receipts.map((receipt) => {
    const summary = workflowReceiptSummary(receipt);
    return <article key={receipt.id}>
      <h3>{operationLabel(receipt.operation)}</h3>
      <h4>Frozen request</h4><ReceiptSummaryFields fields={summary.intent} />
      <h4>Committed result</h4><ReceiptSummaryFields fields={summary.result} />
      <p>Audit {receipt.audit_id} · correlation {receipt.correlation_id}</p>
      {recovery.acknowledgementErrors.get(receipt.id) && <p role="alert">{recovery.acknowledgementErrors.get(receipt.id)}</p>}
      <Button disabled={recovery.acknowledging.has(receipt.id)} onClick={() => void store.acknowledge(scopeKey, receipt.id)}>{recovery.acknowledging.has(receipt.id) ? "Acknowledging recovered result…" : "Acknowledge recovered result"}</Button>
    </article>;
  })}</section>;
}

function ReceiptSummaryFields({ fields }: { fields: ReturnType<typeof workflowReceiptSummary>["intent"] }) {
  return <dl>{fields.map(({ label, value }) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>;
}

function emptyRecovery(status: RecoveryState["status"]): RecoveryState {
  return { status, receipts: [], error: null, acknowledging: new Set(), acknowledgementErrors: new Map(), generation: 0 };
}

function registryKey(scopeKey: string, operationKey: string): string { return `${JSON.stringify(scopeKey)}:${JSON.stringify(operationKey)}`; }

function mutationReceiptID(value: unknown): string | undefined {
  if (!value || typeof value !== "object") return undefined;
  const record = value as Record<string, unknown>;
  if (typeof record.receiptID === "string") return record.receiptID;
  return mutationReceiptID(record.receipt);
}

function operationLabel(operation: string): string {
  return operation.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/^./, (value) => value.toUpperCase());
}

function errorMessage(error: unknown, fallback: string): string { return error instanceof Error && error.message ? error.message : fallback; }

function isMissingReceipt(error: unknown): boolean {
  return error instanceof APIProductError && error.status === 404 && error.product.code === "not_found";
}

function scopeGenerationDrift(): APITransportError {
  return new APITransportError("invalid_response", "Workflow recovery scope changed before reconciliation completed");
}
