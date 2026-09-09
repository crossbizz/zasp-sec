import { APIProductError } from "../../../apps/web/api/client";
import { decodeTestDefinition } from "../../../apps/web/api/decoders";
import type { TestDefinition, TestDefinitionInput, TestDefinitionUpdateInput, TestRun } from "../../../apps/web/api/generated";
import { redTeamIdempotencyKey, type ProductionRedTeamAPI } from "./api";

export type RedTeamIntent =
  | Readonly<{ kind: "create"; input: TestDefinitionInput }>
  | Readonly<{ kind: "update"; id: string; version: number; input: TestDefinitionUpdateInput }>
  | Readonly<{ kind: "run"; id: string; version: number; runID: string }>
  | Readonly<{ kind: "cancel"; id: string; version: number }>;
export type RedTeamMutationResult = Readonly<{ intent: RedTeamIntent; value: TestDefinition | TestRun }>;
export type RecoveryStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;
type Checkpoint = Readonly<{ schema: 1; scope: string; key: string; intent: RedTeamIntent }>;
type Snapshot = Readonly<{ pending: RedTeamIntent | null; busy: boolean; error: string | null; unavailable: boolean }>;
const id = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const key = /^redteam_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const epoch = "2026-01-01T00:00:00Z";

export function validRedTeamRecoveryScope(scope: string): boolean {
  const parts = scope.split("/"); return parts.length === 4 && parts.every((part) => id.test(part));
}

// One frozen request, without credential fields, per principal and tenant scope.
// Storage is required before I/O, so losing a page cannot allocate a new run.
export function createRedTeamMutationRecovery(scope: string, storage: RecoveryStorage | undefined, api: ProductionRedTeamAPI, authorized: () => boolean) {
  const storageKey = `zasp:red-team:request:v1:${scope}`;
  let checkpoint: Checkpoint | null = null;
  let uncertain = false;
  let disposed = false;
  let request: AbortController | null = null;
  let snapshot: Snapshot = { pending: null, busy: false, error: null, unavailable: false };
  const listeners = new Set<() => void>();
  const publish = (value: Snapshot) => { snapshot = Object.freeze(value); listeners.forEach((listener) => listener()); };
  try {
    if (!validRedTeamRecoveryScope(scope) || !storage) throw new Error("storage unavailable");
    const saved = storage.getItem(storageKey);
    if (saved !== null) {
      if (saved.length > 16_384) throw new Error("checkpoint too large");
      checkpoint = validateCheckpoint(JSON.parse(saved), scope);
      uncertain = true;
      snapshot = { pending: checkpoint.intent, busy: false, error: "A retained Red Team request needs reconciliation. Retry its original operation.", unavailable: false };
    }
  } catch {
    snapshot = { pending: null, busy: false, error: "Safe request recovery is unavailable. No new changes can be sent.", unavailable: true };
  }

  async function send(): Promise<RedTeamMutationResult> {
    if (!checkpoint || snapshot.busy || snapshot.unavailable || disposed || !authorized()) throw new Error("Red Team mutation is locked");
    const active = checkpoint;
    try {
      if (storage!.getItem(storageKey) !== JSON.stringify(active)) throw new Error("Recovery ownership changed");
    } catch {
      publish({ ...snapshot, unavailable: true, error: "Retained request changed. No retry was sent." });
      throw new Error("Recovery ownership changed");
    }
    const wasUncertain = uncertain;
    request = new AbortController();
    publish({ pending: active.intent, busy: true, error: null, unavailable: false });
    try {
      const value = await dispatch(api, active.intent, { idempotencyKey: active.key }, request.signal);
      if (disposed || request.signal.aborted || !authorized()) throw new Error("Authorization changed before response reconciliation");
      if (storage!.getItem(storageKey) !== JSON.stringify(active)) throw new Error("Recovery ownership changed before acknowledgement");
      storage!.removeItem(storageKey);
      if (storage!.getItem(storageKey) !== null) throw new Error("Recovery acknowledgement was not persisted");
      checkpoint = null; uncertain = false;
      publish({ pending: null, busy: false, error: null, unavailable: false });
      return { intent: active.intent, value };
    } catch (error) {
      if (!disposed) {
        let unavailable = false;
        const rejected = !wasUncertain && !request.signal.aborted && authorized() && error instanceof APIProductError && !error.product.retryable && error.status >= 400 && error.status < 500 && ![408,429].includes(error.status) && (error.status !== 409 || error.product.code === "version_conflict");
        if (rejected) {
          try {
            if (storage!.getItem(storageKey) !== JSON.stringify(active)) throw new Error("Recovery ownership changed");
            storage!.removeItem(storageKey); if (storage!.getItem(storageKey) !== null) throw new Error("retained"); checkpoint = null;
          } catch { unavailable = true; }
        }
        uncertain = checkpoint !== null;
        publish({ pending: checkpoint?.intent ?? null, busy: false, error: unavailable ? "Retained request ownership could not be verified. No new changes can be sent." : checkpoint ? "The request may have committed. Retry the retained operation; do not create a replacement." : "The request was rejected before confirmation. Review its inputs and target safety.", unavailable });
      }
      throw error;
    } finally { request = null; }
  }

  return {
    subscribe(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    getSnapshot: () => snapshot,
    execute(intent: RedTeamIntent): Promise<RedTeamMutationResult> {
      if (checkpoint || snapshot.busy || snapshot.unavailable || disposed || !authorized()) return Promise.reject(new Error("Red Team mutation is locked"));
      try {
        if (storage!.getItem(storageKey) !== null) throw new Error("Another operation is retained");
        const next = validateCheckpoint({ schema: 1, scope, key: redTeamIdempotencyKey(), intent }, scope);
        const encoded = JSON.stringify(next);
        if (encoded.length > 16_384) throw new Error("checkpoint too large");
        storage!.setItem(storageKey, encoded);
        if (storage!.getItem(storageKey) !== encoded) throw new Error("checkpoint write was not durable");
        checkpoint = next;
      } catch (error) {
        publish({ pending: null, busy: false, error: "Safe request retention failed. No request was sent.", unavailable: true });
        return Promise.reject(error);
      }
      return send();
    },
    retry: send,
    activate() { disposed = false; },
    abort() { request?.abort(); },
    dispose() { disposed = true; request?.abort(); listeners.clear(); },
  };
}

function dispatch(api: ProductionRedTeamAPI, intent: RedTeamIntent, attempt: Readonly<{ idempotencyKey: string }>, signal: AbortSignal) {
  switch (intent.kind) {
    case "create": return api.createDefinition(intent.input, attempt, signal);
    case "update": return api.updateDefinition(intent.id, intent.version, intent.input, attempt, signal);
    case "run": return api.runDefinition(intent.id, intent.version, intent.runID, attempt, signal);
    case "cancel": return api.cancelRun(intent.id, intent.version, attempt, signal);
  }
}

function validateCheckpoint(value: unknown, scope: string): Checkpoint {
  const record = exact(value, ["schema", "scope", "key", "intent"]);
  if (record.schema !== 1 || record.scope !== scope || !validRedTeamRecoveryScope(scope) || typeof record.key !== "string" || !key.test(record.key)) throw new Error("Invalid recovery authority");
  const operation = exact(record.intent, typeof (record.intent as { kind?: unknown })?.kind === "string" ? ({ create: ["kind", "input"], update: ["kind", "id", "version", "input"], run: ["kind", "id", "version", "runID"], cancel: ["kind", "id", "version"] } as Record<string,string[]>)[(record.intent as { kind: string }).kind] ?? [] : []);
  if (!["create","update","run","cancel"].includes(String(operation.kind))) throw new Error("Invalid recovery operation");
  if (operation.kind !== "create" && (typeof operation.id !== "string" || !id.test(operation.id) || !Number.isSafeInteger(operation.version) || Number(operation.version) < 1 || Number(operation.version) > 999_999)) throw new Error("Invalid recovery version");
  if (operation.kind === "run" && (typeof operation.runID !== "string" || !id.test(operation.runID) || operation.runID === operation.id)) throw new Error("Invalid recovery run");
  if (operation.kind === "create" || operation.kind === "update") {
    const input = exact(operation.input, operation.kind === "create" ? ["id","name","target_id","target_kind","categories","safety"] : ["name","target_id","target_kind","categories","safety","enabled"]);
    decodeTestDefinition({ ...input, id: operation.kind === "create" ? input.id : operation.id, version: 1, enabled: operation.kind === "create" ? true : input.enabled, created_at: epoch, updated_at: epoch });
  }
  return freeze(JSON.parse(JSON.stringify(value))) as Checkpoint;
}
function exact(value: unknown, keys: readonly string[]): Record<string,unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join() !== [...keys].sort().join()) throw new Error("Invalid recovery record");
  return value as Record<string,unknown>;
}
function freeze(value: unknown): unknown { if (value && typeof value === "object") { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }
