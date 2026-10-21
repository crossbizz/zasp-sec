import type { APIClient } from "../../../apps/web/api/client";
import { APITransportError, requireAPIData } from "../../../apps/web/api/client";

export type FindingExplanationIntent = Readonly<{ finding_id: string; finding_version: number; idempotency_key: string }>;
export type FindingExplanationResponse = Readonly<{
  request_id: string;
  state: "reserved" | "started" | "complete" | "failed" | "unknown";
  result_retained: false;
  source: Readonly<{ finding_id: string; finding_version: number }>;
  sent_fields: readonly ["rule", "severity", "evidence_count"];
  explanation?: string;
  recommendation?: string;
}>;
export type FindingExplanationAPI = Readonly<{
  createAIExplanation(intent: FindingExplanationIntent, signal: AbortSignal): Promise<FindingExplanationResponse>;
}>;
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
export function findingExplanationVersion(value: string): number | null {
  if (!/^"[1-9][0-9]*"$(?![\s\S])/.test(value)) return null;
  const version = Number(value.slice(1, -1));
  return Number.isSafeInteger(version) && version > 0 && version <= 1000000 ? version : null;
}
function invalid(): never { throw new APITransportError("invalid_response", "Finding explanation is unavailable."); }
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return invalid();
  return value as Record<string, unknown>;
}
export function decodeFindingExplanation(value: unknown, intent: FindingExplanationIntent): FindingExplanationResponse {
  const record = object(value), source = object(record.source);
  const required = ["request_id", "state", "result_retained", "source", "sent_fields"];
  const allowed = [...required, "explanation", "recommendation"];
  if (required.some(key => !Object.hasOwn(record, key)) || Object.keys(record).some(key => !allowed.includes(key)) ||
      typeof record.request_id !== "string" || !productID.test(record.request_id) || record.result_retained !== false ||
      typeof record.state !== "string" || !["reserved", "started", "complete", "failed", "unknown"].includes(record.state) ||
      Object.keys(source).length !== 2 || source.finding_id !== intent.finding_id || source.finding_version !== intent.finding_version ||
      !Array.isArray(record.sent_fields) || record.sent_fields.length !== 3 || record.sent_fields.some((field, index) => field !== ["rule", "severity", "evidence_count"][index])) return invalid();
  for (const field of ["explanation", "recommendation"] as const) {
    if (Object.hasOwn(record, field) && (record.state !== "complete" || typeof record[field] !== "string" || record[field].length < 1 || record[field].length > 2048)) return invalid();
  }
  return record as unknown as FindingExplanationResponse;
}
export function createFindingExplanationAPI(client: APIClient): FindingExplanationAPI {
  return {
    async createAIExplanation(intent, signal) {
      if (!productID.test(intent.finding_id) || !Number.isSafeInteger(intent.finding_version) || intent.finding_version < 1 || intent.finding_version > 1000000 ||
          !/^[A-Za-z0-9][A-Za-z0-9_.:-]{15,127}$(?![\s\S])/.test(intent.idempotency_key)) throw new TypeError("Finding explanation intent is unavailable.");
      // Session, CSRF, expected-scope and cancellation use the shared transport.
      const result = await client.POST("/api/v1/ai/explanations", { body: intent, params: { header: { "Idempotency-Key": intent.idempotency_key, "X-CSRF-Token": "" } }, signal });
      return requireAPIData(result, value => decodeFindingExplanation(value, intent));
    },
  };
}
