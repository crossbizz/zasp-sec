import type { APIClient } from "../../../apps/web/api/client";
import { APITransportError, requireAPIData } from "../../../apps/web/api/client";
import type { ExternalFlow, ExternalFlowUpdate, ExternalFlowMutation } from "../../../apps/web/api/generated";

export type ExternalFlowBoundary = Readonly<{ identityKey: string | null; permitted: boolean; fresh: boolean; isCurrent?(): boolean; reauthenticate?(): void }>;
export const readOnlyExternalFlowBoundary: ExternalFlowBoundary = { identityKey: "standalone", permitted: false, fresh: false };
export const optionalFlowID = (value: string): value is ExternalFlowUpdate["flow_id"] => ["posthog", "openrouter", "remote-otlp"].includes(value);
export const policyVersion = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 1 && (value as number) <= 100000000000000;
const bad = (): never => { throw new APITransportError("invalid_response", "External flow settings are unavailable."); };
function exact(value: unknown, required: string[], optional: string[] = []): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return bad();
  const record = value as Record<string, unknown>;
  if (required.some(key => !Object.hasOwn(record, key)) || Object.keys(record).some(key => !required.includes(key) && !optional.includes(key))) return bad();
  return record;
}
export function decodeExternalFlows(value: unknown): readonly ExternalFlow[] {
  const page = exact(value, ["items"]);
  if (!Array.isArray(page.items) || page.items.length > 32) return bad();
  const seen = new Set<string>();
  for (const item of page.items) {
    const row = exact(item, ["id", "required", "categories", "enabled", "health"], ["name", "version", "available"]);
    if (typeof row.id !== "string" || !/^[a-z][a-z0-9-]{0,63}$(?![\s\S])/.test(row.id) || seen.has(row.id) || typeof row.required !== "boolean" || typeof row.enabled !== "boolean" ||
        typeof row.health !== "string" || !["healthy", "degraded", "disabled", "unknown"].includes(row.health) || !Array.isArray(row.categories) || row.categories.length > 16 || new Set(row.categories).size !== row.categories.length ||
        row.categories.some(category => typeof category !== "string" || !["identity_metadata", "product_metadata", "security_metadata", "product_usage", "redacted_summary", "remote_telemetry"].includes(category))) return bad();
    if (Object.hasOwn(row, "available") && typeof row.available !== "boolean" || Object.hasOwn(row, "version") && !policyVersion(row.version) || Object.hasOwn(row, "name") && (typeof row.name !== "string" || !row.name.length || row.name.length > 128)) return bad();
    seen.add(row.id);
  }
  return page.items as readonly ExternalFlow[];
}
export async function updateExternalFlow(client: APIClient, intent: ExternalFlowUpdate, signal: AbortSignal): Promise<ExternalFlowMutation> {
  exact(intent, ["flow_id", "enabled", "expected_version", "idempotency_key"]);
  if (!optionalFlowID(intent.flow_id) || typeof intent.enabled !== "boolean" || !policyVersion(intent.expected_version) || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{15,127}$(?![\s\S])/.test(intent.idempotency_key)) throw new TypeError("External flow change is unavailable.");
  const result = await client.PATCH("/api/v1/settings/external-data-flows", {
    params: { header: { "Idempotency-Key": intent.idempotency_key, "X-CSRF-Token": "", "X-Zasp-Fresh-Auth": "confirmed" } }, body: intent, signal,
  });
  return requireAPIData(result, value => {
    const receipt = exact(value, ["flow_id", "enabled", "version", "idempotency_key"]);
    if (receipt.flow_id !== intent.flow_id || receipt.enabled !== intent.enabled || receipt.idempotency_key !== intent.idempotency_key || receipt.version !== intent.expected_version + 1) return bad();
    return receipt as unknown as ExternalFlowMutation;
  });
}
