import type { AgentSession, Capability, HomeSummary, InventoryRecord, Principal, Relationship, SessionBootstrap, SessionCallbackResult, SessionScope, SessionScopePage } from "./generated";

const PRODUCT_ID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

export type Decoder<T> = (value: unknown) => T;

export function decodeSessionCallbackResult(value: unknown): SessionCallbackResult {
  const record = exactRecord(value, ["return_to"]);
  boundedString(record.return_to, 1, 2048);
  if (!record.return_to.startsWith("/") || record.return_to.startsWith("//") || record.return_to.includes("\\") || record.return_to.includes("\n") || record.return_to.includes("\r")) fail();
  return value as SessionCallbackResult;
}

export function decodeSessionBootstrap(value: unknown): SessionBootstrap {
  const record = exactRecord(value, ["principal", "organization_id", "workspace_id", "environment_id", "permissions", "capabilities", "csrf_token", "correlation_id"]);
  decodePrincipal(record.principal);
  for (const key of ["organization_id", "workspace_id", "environment_id", "correlation_id"] as const) productID(record[key]);
  stringArray(record.permissions, 32); stringArray(record.capabilities, 128);
  boundedString(record.csrf_token, 32, 256);
  return value as SessionBootstrap;
}

export function decodeSessionScopePage(value: unknown): SessionScopePage {
  const record = exactRecord(value, ["items"]); const items = array(record.items, 100);
  for (const item of items) decodeSessionScope(item);
  return value as SessionScopePage;
}

export function decodeInventoryPage(value: unknown): { readonly items: readonly InventoryRecord[] } {
  const record = exactRecord(value, ["items"]); const items = array(record.items, 10000);
  for (const item of items) decodeInventoryRecord(item);
  return value as { readonly items: readonly InventoryRecord[] };
}

export function decodeInventoryRecord(value: unknown): InventoryRecord {
  const required = ["id", "name", "kind", "owner", "team", "tags", "evidence_id", "first_seen", "last_seen"];
  const record = exactRecord(value, required, ["credential_reference", "credential_fingerprint", "workload_id", "sandbox_id", "isolation"]);
  productID(record.id); boundedString(record.name, 1, 256); enumValue(record.kind, ["asset", "agent", "tool", "identity", "runtime"]);
  boundedString(record.owner, 0, 128); boundedString(record.team, 0, 128); stringArray(record.tags, 32); productID(record.evidence_id); dateTime(record.first_seen); dateTime(record.last_seen);
  for (const key of ["credential_reference", "workload_id", "sandbox_id"] as const) if (record[key] !== undefined) boundedString(record[key], 1, 256);
  if (record.credential_fingerprint !== undefined && (typeof record.credential_fingerprint !== "string" || !/^sha256:[0-9a-f]{64}$/.test(record.credential_fingerprint))) fail();
  if (record.isolation !== undefined) enumValue(record.isolation, ["container", "sandbox"]);
  return value as InventoryRecord;
}

export function decodeCapabilityPage(value: unknown): { readonly items: readonly Capability[] } {
  const record = exactRecord(value, ["items"]); for (const item of array(record.items, 10000)) {
    const entry = exactRecord(item, ["agent_id", "target_id", "target_kind", "category", "outcome", "state", "reachable", "evidence_ids"]);
    productID(entry.agent_id); productID(entry.target_id); enumValue(entry.target_kind, ["tool", "identity", "resource", "action"]); boundedString(entry.category, 1, 64); boundedString(entry.outcome, 1, 32); enumValue(entry.state, ["reachable", "observed", "verified", "blocked"]); if (typeof entry.reachable !== "boolean") fail(); productIDArray(entry.evidence_ids, 64);
  } return value as { readonly items: readonly Capability[] };
}

export function decodeRelationshipPage(value: unknown): { readonly items: readonly Relationship[] } {
  const record = exactRecord(value, ["items"]); for (const item of array(record.items, 10000)) { const entry = exactRecord(item, ["from_id", "to_id", "type", "evidence_id"]); productID(entry.from_id); productID(entry.to_id); boundedString(entry.type, 1, 64); productID(entry.evidence_id); } return value as { readonly items: readonly Relationship[] };
}

export function decodeAgentSessionPage(value: unknown): { readonly items: readonly AgentSession[] } {
  const record = exactRecord(value, ["items"]); for (const item of array(record.items, 10000)) { const entry = exactRecord(item, ["id", "agent_id", "started_at"]); productID(entry.id); productID(entry.agent_id); dateTime(entry.started_at); } return value as { readonly items: readonly AgentSession[] };
}

export function decodeHomeSummary(value: unknown): HomeSummary {
  const integers = ["agent_count", "high_risk_paths", "verified_changes", "blocked_changes", "pending_approvals", "oldest_approval_age_seconds", "needs_human_runs", "failed_runs", "inconclusive_runs", "recent_contained", "recent_remediated"];
  const record = exactRecord(value, [...integers, "healthy", "attention_required"]);
  for (const key of integers) if (!Number.isSafeInteger(record[key]) || (record[key] as number) < 0) fail();
  if (typeof record.healthy !== "boolean" || typeof record.attention_required !== "boolean") fail();
  return value as HomeSummary;
}

function decodePrincipal(value: unknown): Principal { const record = exactRecord(value, ["id", "organization_id", "organization_reference", "member_reference", "role", "active"]); productID(record.id); productID(record.organization_id); boundedString(record.organization_reference, 2, 128); boundedString(record.member_reference, 2, 128); boundedString(record.role, 1, 64); if (typeof record.active !== "boolean") fail(); return value as Principal; }
function decodeSessionScope(value: unknown): SessionScope { const record = exactRecord(value, ["organization_id", "workspace_id", "environment_id", "label"]); productID(record.organization_id); productID(record.workspace_id); productID(record.environment_id); boundedString(record.label, 1, 128); return value as SessionScope; }
function exactRecord(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> { if (!value || typeof value !== "object" || Array.isArray(value)) fail(); const record = value as Record<string, unknown>; const allowed = new Set([...required, ...optional]); if (Object.keys(record).some((key) => !allowed.has(key)) || required.some((key) => !(key in record))) fail(); return record; }
function array(value: unknown, maximum: number): readonly unknown[] { if (!Array.isArray(value) || value.length > maximum) fail(); return value; }
function boundedString(value: unknown, minimum: number, maximum: number): asserts value is string { if (typeof value !== "string" || value.length < minimum || value.length > maximum) fail(); }
function productID(value: unknown): asserts value is string { if (typeof value !== "string" || !PRODUCT_ID.test(value)) fail(); }
function dateTime(value: unknown): asserts value is string { if (typeof value !== "string" || !DATE_TIME.test(value) || Number.isNaN(Date.parse(value))) fail(); }
function stringArray(value: unknown, maximum: number): asserts value is readonly string[] { const values = array(value, maximum); if (new Set(values).size !== values.length || values.some((item) => typeof item !== "string" || item.length < 1 || item.length > 128)) fail(); }
function productIDArray(value: unknown, maximum: number): void { const values = array(value, maximum); if (values.length < 1 || new Set(values).size !== values.length) fail(); for (const item of values) productID(item); }
function enumValue(value: unknown, allowed: readonly string[]): void { if (typeof value !== "string" || !allowed.includes(value)) fail(); }
function fail(): never { throw new Error("schema mismatch"); }
