import type { APIClient } from "./client";
import { APITransportError, requireAPIData } from "./client";
import { decodeSecurityAgentRun } from "./decoders";
import type { SecurityAgentActivityRunPage, SecurityAgentActivityTarget, SecurityAgentActivityTargetPage } from "./generated";
import type { SecurityAgentAuditScope } from "./security-agent-audit";

export type SecurityAgentActivityKind = SecurityAgentActivityTarget["kind"];
export type SecurityAgentActivityOptions = { readonly limit?: number; readonly cursor?: string; readonly signal?: AbortSignal };
function mismatch(): never { throw new APITransportError("invalid_response", "Security Agent activity schema mismatch"); }
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const kinds: readonly string[] = ["finding", "attack_path", "session", "audit"];
function validID(value: unknown): value is string { return typeof value === "string" && productID.test(value); }
function validCursor(value: unknown): value is string { return typeof value === "string" && value.length >= 2 && value.length <= 2048 && /^[A-Za-z0-9_-]+$/.test(value); }
function record(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) mismatch();
  const result = value as Record<string, unknown>;
  if (required.some((key) => !Object.hasOwn(result, key)) || Object.keys(result).some((key) => !required.includes(key) && !optional.includes(key))) mismatch();
  return result;
}
function pageRecord(value: unknown, kind: SecurityAgentActivityKind, limit: number): Record<string, unknown> & { items: unknown[] } {
  if (!kinds.includes(kind) || !Number.isInteger(limit) || limit < 1 || limit > 100) mismatch();
  const page = record(value, ["items", "coverage"], ["next_cursor"]);
  if (!Array.isArray(page.items) || page.items.length > limit || !["complete", "partial"].includes(page.coverage as string) || kind === "audit" && page.coverage !== "complete") mismatch();
  if (Object.hasOwn(page, "next_cursor") && (!validCursor(page.next_cursor) || page.items.length !== limit)) mismatch();
  return page as Record<string, unknown> & { items: unknown[] };
}
export function decodeSecurityAgentActivityRuns(value: unknown, kind: SecurityAgentActivityKind, limit: number): SecurityAgentActivityRunPage {
  const page = pageRecord(value, kind, limit);
  if (kind === "audit" && (page.items.length > 1 || Object.hasOwn(page, "next_cursor"))) mismatch();
  const seen = new Set<string>();
  for (const item of page.items) { const run = decodeSecurityAgentRun(item); if (seen.has(run.id)) mismatch(); seen.add(run.id); }
  return value as SecurityAgentActivityRunPage;
}
export function decodeSecurityAgentActivityTargets(value: unknown, kind: SecurityAgentActivityKind, limit: number): SecurityAgentActivityTargetPage {
  const page = pageRecord(value, kind, limit);
  let last = "";
  for (const item of page.items) { const target = record(item, ["kind", "id"]); if (target.kind !== kind || !validID(target.id) || target.id <= last) mismatch(); last = target.id; }
  return value as SecurityAgentActivityTargetPage;
}
function requestOptions(id: string, kind: SecurityAgentActivityKind, scope: SecurityAgentAuditScope, options: SecurityAgentActivityOptions) {
  const limit = options.limit === undefined ? 50 : options.limit;
  const cursor = options.cursor;
  if (!validID(id) || !scope || ![scope.organization_id, scope.workspace_id, scope.environment_id].every(validID) || !kinds.includes(kind) || !Number.isInteger(limit) || limit < 1 || limit > 100 || cursor !== undefined && !validCursor(cursor)) throw new APITransportError("invalid_configuration", "Invalid Security Agent activity request");
  return { limit, cursor, signal: options.signal, headers: { "X-Zasp-Expected-Scope": [scope.organization_id, scope.workspace_id, scope.environment_id].join("/") } };
}
export async function listSecurityAgentActivityRuns(client: APIClient, id: string, kind: SecurityAgentActivityKind, scope: SecurityAgentAuditScope, options: SecurityAgentActivityOptions = {}): Promise<SecurityAgentActivityRunPage> {
  const bound = requestOptions(id, kind, scope, options);
  const result = await client.GET("/api/v1/security-agent-activity/{kind}/{id}/runs", { params: { path: { kind, id }, query: { limit: bound.limit, ...(bound.cursor !== undefined ? { cursor: bound.cursor } : {}) } }, headers: bound.headers, signal: bound.signal });
  if (result.response.headers.get("Cache-Control") !== "no-store") mismatch();
  const page = requireAPIData(result, (value) => decodeSecurityAgentActivityRuns(value, kind, bound.limit));
  if (page.next_cursor !== undefined && page.next_cursor === bound.cursor) mismatch();
  return page;
}
export async function listSecurityAgentRunActivity(client: APIClient, id: string, kind: SecurityAgentActivityKind, scope: SecurityAgentAuditScope, options: SecurityAgentActivityOptions = {}): Promise<SecurityAgentActivityTargetPage> {
  const bound = requestOptions(id, kind, scope, options);
  const result = await client.GET("/api/v1/security-agent-runs/{id}/activity/{kind}", { params: { path: { kind, id }, query: { limit: bound.limit, ...(bound.cursor !== undefined ? { cursor: bound.cursor } : {}) } }, headers: bound.headers, signal: bound.signal });
  if (result.response.headers.get("Cache-Control") !== "no-store") mismatch();
  const page = requireAPIData(result, (value) => decodeSecurityAgentActivityTargets(value, kind, bound.limit));
  if (page.next_cursor !== undefined && page.next_cursor === bound.cursor) mismatch();
  return page;
}
