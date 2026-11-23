import type { APIClient } from "../../../apps/web/api/client";
import { APITransportError, requireAPIData } from "../../../apps/web/api/client";
import { decodeRecoveryBackup, decodeRecoveryRestore } from "../../../apps/web/api/decoders";
import type { RecoveryBackup, RecoveryIntent, RecoveryIntentInput, RecoveryManifestLocator, RecoveryRestore } from "../../../apps/web/api/generated";

const PRODUCT_ID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;
const QUOTED_VERSION = /^"[1-9][0-9]{0,5}"$/;

export type StartBackupInput = Readonly<{ backupID: string; retentionDays: number; idempotencyKey: string }>;
export type StartRestoreInput = Readonly<{ restoreID: string; targetEnvironment: string; manifest: RecoveryManifestLocator; idempotencyKey: string }>;

export type RecoveryAPI = Readonly<{
  putIntent(id: string, parameters: RecoveryIntentInput, signal: AbortSignal): Promise<RecoveryIntent>;
  getIntent(id: string, signal: AbortSignal): Promise<RecoveryIntent>;
  startBackup(input: StartBackupInput, signal?: AbortSignal): Promise<RecoveryBackup>;
  getBackup(id: string, signal?: AbortSignal): Promise<RecoveryBackup>;
  startRestore(input: StartRestoreInput, signal?: AbortSignal): Promise<RecoveryRestore>;
  getRestore(id: string, signal?: AbortSignal): Promise<RecoveryRestore>;
}>;

export function createRecoveryAPI(client: APIClient, expectedScope: string): RecoveryAPI {
  requireScope(expectedScope);
  function intent(value: unknown, id: string): RecoveryIntent {
    if (typeof value !== "object" || value === null || Object.keys(value).sort().join() !== "id,parameters") invalidResponse("Unexpected recovery request");
    const raw = value as Partial<RecoveryIntent>;
    const p = raw?.parameters;
    if (raw?.id !== id || !p || !PRODUCT_ID.test(p.backup_id)) invalidResponse("Unexpected recovery request");
    const fields = Object.keys(p).sort().join();
    if (p.kind === "backup" && fields === "backup_id,kind,retention_days" && p.backup_id === id && Number.isSafeInteger(p.retention_days) && p.retention_days >= 7 && p.retention_days <= 90) return raw as RecoveryIntent;
    if (p.kind !== "restore" || fields !== "backup_id,kind,target_environment" || p.backup_id === id || typeof p.target_environment !== "string" || !validTarget(p.target_environment, expectedScope)) invalidResponse("Unexpected recovery request type");
    return raw as RecoveryIntent;
  }
  return {
    async getIntent(id, signal) {
      requireProductID(id);
      const response = await client.GET("/api/v1/recovery/intents/{id}", {params: {path: {id}}, headers: {"X-Zasp-Expected-Scope": expectedScope}, signal});
      return requireAPIData(response, raw => intent(raw, id));
    },
    async putIntent(id, parameters, signal) {
      requireProductID(id);
      intent({id, parameters}, id);
      const response = await client.PUT("/api/v1/recovery/intents/{id}", {params: {path: {id}, header: {"X-CSRF-Token": ""}}, headers: {"X-Zasp-Expected-Scope": expectedScope}, body: parameters, signal});
      const saved = requireAPIData(response, raw => intent(raw, id));
      if (saved.parameters.kind !== parameters.kind || saved.parameters.backup_id !== parameters.backup_id || (parameters.kind === "restore" && (saved.parameters.kind !== "restore" || saved.parameters.target_environment !== parameters.target_environment)) || (parameters.kind === "backup" && (saved.parameters.kind !== "backup" || saved.parameters.retention_days !== parameters.retention_days))) invalidResponse("Saved recovery parameters changed");
      return saved;
    },
    async startBackup(input, signal) {
      requireProductID(input.backupID); requireIdempotencyKey(input.idempotencyKey);
      if (!Number.isSafeInteger(input.retentionDays) || input.retentionDays < 7 || input.retentionDays > 90) invalidConfiguration();
      const result = await client.POST("/api/v1/recovery/backups", { params: { header: { "Idempotency-Key": input.idempotencyKey, "If-Match": '"0"', "X-Zasp-Fresh-Auth": "confirmed" } }, body: { backup_id: input.backupID, retention_days: input.retentionDays }, signal });
      const value = recoveryResult(result, (body) => decodeRecoveryBackup(body, expectedScope), input.backupID, true, 202);
      if (value.state !== "queued" || value.version !== 1 || value.retention_days !== input.retentionDays) invalidResponse("Recovery backup start returned contradictory authority");
      return value;
    },
    async getBackup(id, signal) {
      requireProductID(id);
      return recoveryResult(await client.GET("/api/v1/recovery/backups/{id}", { params: { path: { id } }, signal }), (body) => decodeRecoveryBackup(body, expectedScope), id, false, 200);
    },
    async startRestore(input, signal) {
      requireProductID(input.restoreID); requireIdempotencyKey(input.idempotencyKey); requireTarget(input.targetEnvironment, expectedScope);
      const result = await client.POST("/api/v1/recovery/restores", { params: { header: { "Idempotency-Key": input.idempotencyKey, "If-Match": '"0"', "X-Zasp-Fresh-Auth": "confirmed" } }, body: { restore_id: input.restoreID, target_environment: input.targetEnvironment, manifest: input.manifest }, signal });
      const value = recoveryResult(result, (body) => decodeRecoveryRestore(body, expectedScope), input.restoreID, true, 202);
      if (value.state !== "queued" || value.version !== 1 || value.target_environment !== input.targetEnvironment || !sameManifest(value.manifest, input.manifest)) invalidResponse("Recovery restore start returned contradictory authority");
      return value;
    },
    async getRestore(id, signal) {
      requireProductID(id);
      return recoveryResult(await client.GET("/api/v1/recovery/restores/{id}", { params: { path: { id } }, signal }), (body) => decodeRecoveryRestore(body, expectedScope), id, false, 200);
    },
  };
}

function recoveryResult<T extends { readonly id: string; readonly version: number }>(result: { data?: unknown; error?: unknown; response: Response }, decode: (value: unknown) => T, expectedID: string, mutation: boolean, expectedStatus: number): T {
  const value = requireAPIData(result, decode);
  if (result.response.status !== expectedStatus || value.id !== expectedID) invalidResponse("Recovery response returned a different resource");
  if (result.response.headers.get("Cache-Control")?.trim().toLowerCase() !== "no-store") invalidResponse("Recovery response was cacheable");
  const etag = result.response.headers.get("ETag"); if (!etag || !QUOTED_VERSION.test(etag) || etag !== `"${value.version}"`) invalidResponse("Recovery response version did not match its body");
  if (mutation) {
    const auditID = result.response.headers.get("X-Audit-ID"); const receiptID = result.response.headers.get("X-Mutation-Receipt-ID");
    if (!auditID || !receiptID || !PRODUCT_ID.test(auditID) || !PRODUCT_ID.test(receiptID) || auditID === receiptID) invalidResponse("Recovery mutation omitted durable evidence");
  }
  return value;
}

function requireScope(value: string): void { const parts = value.split("/"); if (parts.length !== 3 || parts.some((part) => !PRODUCT_ID.test(part))) invalidConfiguration(); }
function requireProductID(value: string): void { if (!PRODUCT_ID.test(value)) invalidConfiguration(); }
function requireIdempotencyKey(value: string): void { if (!IDEMPOTENCY_KEY.test(value)) invalidConfiguration(); }
function validTarget(value: string, expectedScope: string): boolean { return /^[a-z][a-z0-9-]{0,62}$/.test(value) && value !== "production" && value !== expectedScope.split("/")[2]; }
function requireTarget(value: string, expectedScope: string): void { if (!validTarget(value, expectedScope)) invalidConfiguration(); }
function sameManifest(left: RecoveryManifestLocator, right: RecoveryManifestLocator): boolean { return left.reference === right.reference && left.version_id === right.version_id && left.sha256 === right.sha256 && left.size_bytes === right.size_bytes && left.media_type === right.media_type && left.schema === right.schema && left.signing_key_id === right.signing_key_id && left.signature === right.signature; }
function invalidConfiguration(): never { throw new APITransportError("invalid_configuration", "Invalid recovery request configuration"); }
function invalidResponse(message: string): never { throw new APITransportError("invalid_response", message); }
