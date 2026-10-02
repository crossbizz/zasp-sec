import type { APIClient } from "./client";
import { APITransportError, requireAPIData } from "./client";
import type { SecurityAgentAuditEvent } from "./generated";

export type SecurityAgentAuditScope = Pick<SecurityAgentAuditEvent, "organization_id" | "workspace_id" | "environment_id">;

const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fields = ["id", "run_id", "organization_id", "workspace_id", "environment_id", "actor_reference", "event_kind", "correlation_id", "occurred_at"];
function mismatch(): never { throw new APITransportError("invalid_response", "Security Agent audit schema mismatch"); }

export function decodeSecurityAgentAuditEvent(value: unknown): SecurityAgentAuditEvent {
  if (!value || typeof value !== "object" || Array.isArray(value)) mismatch();
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== fields.length || Object.keys(record).some((field) => !fields.includes(field)) || fields.some((field) => !Object.hasOwn(record, field))) mismatch();
  for (const field of ["id", "run_id", "organization_id", "workspace_id", "environment_id", "correlation_id"]) {
    if (typeof record[field] !== "string" || !productID.test(record[field])) mismatch();
  }
  for (const field of ["actor_reference", "event_kind"]) {
    const text = record[field];
    if (typeof text !== "string" || text.length < 1 || new TextEncoder().encode(text).length > 128) mismatch();
    for (const scalar of text) { const point = scalar.codePointAt(0)!; if (point < 32 || point === 127 || point >= 0xd800 && point <= 0xdfff) mismatch(); }
  }
  const at = record.occurred_at;
  if (typeof at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(at) || at.startsWith("0000")) mismatch();
  const parsed = new Date(at);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 19) !== at.slice(0, 19)) mismatch();
  return value as SecurityAgentAuditEvent;
}

export async function getSecurityAgentAuditEvent(client: APIClient, id: string, scope: SecurityAgentAuditScope, signal?: AbortSignal): Promise<SecurityAgentAuditEvent> {
  if (![id, scope.organization_id, scope.workspace_id, scope.environment_id].every((value) => typeof value === "string" && productID.test(value))) throw new APITransportError("invalid_configuration", "Invalid audit record scope");
  const result = await client.GET("/api/v1/security-agent-audit-events/{id}", { params: { path: { id } }, headers: { "X-Zasp-Expected-Scope": [scope.organization_id, scope.workspace_id, scope.environment_id].join("/") }, signal });
  if (result.response.headers.get("Cache-Control") !== "no-store") mismatch();
  const value = requireAPIData(result, decodeSecurityAgentAuditEvent);
  if (value.id !== id || value.organization_id !== scope.organization_id || value.workspace_id !== scope.workspace_id || value.environment_id !== scope.environment_id) mismatch();
  return value;
}
