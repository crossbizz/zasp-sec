import type { APIClient } from "../../../apps/web/api/client";
import { APITransportError, requireAPIData } from "../../../apps/web/api/client";
import { decodeAttackPath, decodeAttackPathPage, decodeBreakOptionPage, decodeFinding, decodeFindingPage } from "../../../apps/web/api/decoders";
import type { AttackPath, BreakOption, Finding } from "../../../apps/web/api/generated";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";

const quotedVersion = /^"[1-9][0-9]*"$/;
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

type CredentialKind = "browser" | "pat";
type APIResult = { data?: unknown; error?: unknown; response: Response };

export type RiskMutationAttempt = Readonly<{ idempotencyKey: string }>;
export type VersionedRisk<T> = Readonly<{ value: T; version: string }>;
export type RiskMutationResult = VersionedRisk<Finding> & Readonly<{ auditID: string; receiptID?: string }>;

export type ProductionRiskAPI = Readonly<{
  listFindings(signal?: AbortSignal): Promise<readonly Finding[]>;
  getFinding(id: string, signal?: AbortSignal): Promise<VersionedRisk<Finding>>;
  updateFinding(id: string, status: "open" | "under_review" | "resolved", version: string, attempt: RiskMutationAttempt, signal?: AbortSignal): Promise<RiskMutationResult>;
  acceptFindingRisk(id: string, reason: string, version: string, attempt: RiskMutationAttempt, signal?: AbortSignal): Promise<RiskMutationResult>;
  listAttackPaths(signal?: AbortSignal): Promise<readonly AttackPath[]>;
  getAttackPath(id: string, signal?: AbortSignal): Promise<AttackPath>;
  getAttackPathBreakOptions(id: string, signal?: AbortSignal): Promise<readonly BreakOption[]>;
}>;

export function createProductionRiskAPI(client: APIClient, credentialKind: CredentialKind = "browser"): ProductionRiskAPI {
  return {
    async listFindings(signal) {
      const loaded = await loadAllCursorPages(async (cursor) => requireAPIData(await client.GET("/api/v1/findings", { params: { query: { cursor, limit: 100 } }, signal }), decodeFindingPage), { maximumItems: 10_000, maximumPages: 100 });
      return loaded.items;
    },
    async getFinding(id, signal) {
      const result = await client.GET("/api/v1/findings/{id}", { params: { path: { id } }, signal });
      return requireRiskVersioned(result, decodeFinding);
    },
    async updateFinding(id, status, version, attempt, signal) {
      const result = await client.PATCH("/api/v1/findings/{id}", { params: { path: { id }, header: mutationHeaders(version, attempt) }, body: { status }, signal });
      return requireRiskMutation(result, credentialKind);
    },
    async acceptFindingRisk(id, reason, version, attempt, signal) {
      const result = await client.POST("/api/v1/findings/{id}/accept-risk", { params: { path: { id }, header: mutationHeaders(version, attempt) }, body: { reason }, signal });
      return requireRiskMutation(result, credentialKind);
    },
    async listAttackPaths(signal) {
      const loaded = await loadAllCursorPages(async (cursor) => requireAPIData(await client.GET("/api/v1/attack-paths", { params: { query: { cursor, limit: 100 } }, signal }), decodeAttackPathPage), { maximumItems: 10_000, maximumPages: 100 });
      return loaded.items;
    },
    async getAttackPath(id, signal) {
      return requireAPIData(await client.GET("/api/v1/attack-paths/{id}", { params: { path: { id } }, signal }), decodeAttackPath);
    },
    async getAttackPathBreakOptions(id, signal) {
      return requireAPIData(await client.GET("/api/v1/attack-paths/{id}/break-options", { params: { path: { id } }, signal }), decodeBreakOptionPage).items;
    },
  };
}

function requireRiskVersioned<T>(result: APIResult, decode: (value: unknown) => T): VersionedRisk<T> {
  const value = requireAPIData(result, decode);
  const version = result.response.headers.get("ETag");
  if (!version || !quotedVersion.test(version)) throw new APITransportError("invalid_response", "Risk response omitted a valid resource version");
  return { value, version };
}

function requireRiskMutation(result: APIResult, credentialKind: CredentialKind): RiskMutationResult {
  const versioned = requireRiskVersioned(result, decodeFinding);
  const auditID = result.response.headers.get("X-Audit-ID");
  const receiptID = result.response.headers.get("X-Mutation-Receipt-ID") ?? undefined;
  if (!auditID || !productID.test(auditID) || credentialKind === "browser" && (!receiptID || !productID.test(receiptID)) || credentialKind === "pat" && receiptID !== undefined) {
    throw new APITransportError("invalid_response", "Risk mutation omitted exact durable evidence headers");
  }
  return { ...versioned, auditID, ...(receiptID ? { receiptID } : {}) };
}

function mutationHeaders(version: string, attempt: RiskMutationAttempt): { "If-Match": string; "Idempotency-Key": string } {
  if (!quotedVersion.test(version) || !/^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/.test(attempt.idempotencyKey)) throw new APITransportError("invalid_configuration", "Invalid risk mutation precondition");
  return { "If-Match": version, "Idempotency-Key": attempt.idempotencyKey };
}
