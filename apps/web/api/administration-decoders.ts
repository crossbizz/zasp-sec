import type { ApiToken, ApiTokenCredential, ApiTokenPage, AuditEventPage, BuiltInRolePage, ComplianceControlPage, ComplianceEvidencePage, DataControls, EnvironmentMutation, EnvironmentPage, ExternalFlowPage, GroupMapping, GroupMappingPage, Organization, Principal, PrincipalPage, Session, SessionEventPage, SessionPage, SystemComponentPage, SystemStatus, SystemVersion, WorkspaceMutation, WorkspacePage } from "./generated";

const PRODUCT_ID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SESSION_ID = /^session-[a-z0-9][a-z0-9-]*$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

export const decodeOrganization = (value: unknown) => decoded<Organization>(value, ["id", "name", "domain", "version"], (record) => { id(record.id); text(record.name, 128); text(record.domain, 253); version(record.version); });
export const decodeWorkspace = (value: unknown) => decoded<WorkspaceMutation>(value, ["id", "organization_id", "name", "version"], (record) => { id(record.id); id(record.organization_id); text(record.name, 128); version(record.version); }, ["audit_correlation_id"]);
export const decodeWorkspacePage = (value: unknown) => page<WorkspacePage>(value, decodeWorkspace);
export const decodeEnvironment = (value: unknown) => decoded<EnvironmentMutation>(value, ["id", "organization_id", "workspace_id", "name", "environment_class", "version"], (record) => { id(record.id); id(record.organization_id); id(record.workspace_id); text(record.name, 128); one(record.environment_class, ["development", "test", "staging", "production"]); version(record.version); }, ["audit_correlation_id"]);
export const decodeEnvironmentPage = (value: unknown) => page<EnvironmentPage>(value, decodeEnvironment);
export const decodePrincipal = (value: unknown) => decoded<Principal>(value, ["id", "organization_id", "organization_reference", "member_reference", "role", "active"], (record) => { id(record.id); id(record.organization_id); text(record.organization_reference, 128); text(record.member_reference, 128); role(record.role); if (typeof record.active !== "boolean") bad(); if (record.version !== undefined) version(record.version); }, ["version", "audit_correlation_id"]);
export const decodePrincipalPage = (value: unknown) => page<PrincipalPage>(value, decodePrincipal);
export const decodeBuiltInRolePage = (value: unknown) => page<BuiltInRolePage>(value, (entry) => decoded(entry, ["role", "permissions"], (record) => { role(record.role); strings(record.permissions, 32); }));
export const decodeGroupMapping = (value: unknown) => decoded<GroupMapping>(value, ["group_reference", "role", "workspace_id", "environment_id", "version"], (record) => { if (typeof record.group_reference !== "string" || !/^idp-group-[A-Za-z0-9_-]+$/.test(record.group_reference)) bad(); role(record.role); id(record.workspace_id); id(record.environment_id); version(record.version); }, ["audit_correlation_id"]);
export const decodeGroupMappingPage = (value: unknown) => page<GroupMappingPage>(value, decodeGroupMapping);

export function decodeAPIToken(value: unknown): ApiToken {
  return decoded<ApiToken>(value, ["id", "name", "principal_id", "workspace_id", "environment_id", "permissions", "created_at", "expires_at", "last_used_at", "revoked_at", "version"], (record) => {
    id(record.id); text(record.name, 128); id(record.principal_id); id(record.workspace_id); id(record.environment_id); strings(record.permissions, 10); date(record.created_at); date(record.expires_at); nullableDate(record.last_used_at); nullableDate(record.revoked_at); version(record.version);
  }, ["audit_correlation_id"]);
}
export const decodeAPITokenCredential = (value: unknown) => {
  const record = exact(value, ["id", "name", "principal_id", "workspace_id", "environment_id", "permissions", "created_at", "expires_at", "last_used_at", "revoked_at", "version", "raw_token", "audit_correlation_id"]);
  decodeAPIToken(Object.fromEntries(Object.entries(record).filter(([key]) => key !== "raw_token")));
  if (typeof record.raw_token !== "string" || !/^zasp_pat_[A-Za-z0-9_-]{43}$/.test(record.raw_token)) bad(); id(record.audit_correlation_id);
  return value as ApiTokenCredential;
};
export const decodeAPITokenPage = (value: unknown) => page<ApiTokenPage>(value, decodeAPIToken);

export const decodeSession = (value: unknown) => decoded<Session>(value, ["id", "agent_id", "principal_id", "workspace_id", "environment_id", "state", "authenticated_at", "expires_at", "version", "events"], (record) => { if (typeof record.id !== "string" || !SESSION_ID.test(record.id)) bad(); text(record.agent_id, 128); id(record.principal_id); id(record.workspace_id); id(record.environment_id); one(record.state, ["active", "revoked", "expired"]); date(record.authenticated_at); date(record.expires_at); version(record.version); for (const event of list(record.events, 1000)) sessionEvent(event); });
export const decodeSessionPage = (value: unknown) => page<SessionPage>(value, decodeSession);
export const decodeSessionEventPage = (value: unknown) => decoded<SessionEventPage>(value, ["items"], (record) => { for (const event of list(record.items, 1000)) sessionEvent(event); });

export const decodeComplianceControlPage = (value: unknown) => decoded<ComplianceControlPage>(value, ["items"], (record) => { for (const item of list(record.items, 500)) control(item); });
export const decodeComplianceEvidencePage = (value: unknown) => decoded<ComplianceEvidencePage>(value, ["items"], (record) => { for (const item of list(record.items, 500)) { const entry = exact(item, ["control", "freshness", "evidence"]); control(entry.control); one(entry.freshness, ["fresh", "stale", "missing"]); for (const evidence of list(entry.evidence, 100)) { const evidenceRecord = exact(evidence, ["id", "asset_id", "source", "at"]); text(evidenceRecord.id, 128); text(evidenceRecord.asset_id, 128); text(evidenceRecord.source, 64); date(evidenceRecord.at); } } });
export const decodeDataControls = (value: unknown) => decoded<DataControls>(value, ["environment_id", "environment_class", "collection_mode", "retention_days", "deletion_enabled", "version"], (record) => { id(record.environment_id); one(record.environment_class, ["development", "test", "staging", "production"]); one(record.collection_mode, ["metadata_only", "extended"]); integer(record.retention_days, 1, 3650); if (typeof record.deletion_enabled !== "boolean") bad(); version(record.version); }, ["audit_correlation_id"]);
export const decodeExternalFlowPage = (value: unknown) => decoded<ExternalFlowPage>(value, ["items"], (record) => { for (const item of list(record.items, 32)) { const entry = exact(item, ["id", "required", "categories", "enabled", "health"]); text(entry.id, 64); if (typeof entry.required !== "boolean" || typeof entry.enabled !== "boolean") bad(); strings(entry.categories, 16); one(entry.health, ["healthy", "degraded", "disabled"]); } });
export const decodeAuditEventPage = (value: unknown) => page<AuditEventPage>(value, (item) => decoded(item, ["id", "workspace_id", "environment_id", "actor_id", "action", "target_id", "outcome", "metadata", "occurred_at"], (record) => { id(record.id); id(record.workspace_id); id(record.environment_id); id(record.actor_id); text(record.action, 127); id(record.target_id); one(record.outcome, ["succeeded", "failed", "denied"]); stringRecord(record.metadata, 32); date(record.occurred_at); }));
export const decodeSystemStatus = (value: unknown) => decoded<SystemStatus>(value, ["security_plane_healthy", "optional_degraded", "fresh_at"], (record) => { if (typeof record.security_plane_healthy !== "boolean" || typeof record.optional_degraded !== "boolean") bad(); date(record.fresh_at); });
export const decodeSystemComponentPage = (value: unknown) => decoded<SystemComponentPage>(value, ["items"], (record) => { for (const item of list(record.items, 64)) { const entry = exact(item, ["id", "required", "state", "fresh_at"]); text(entry.id, 64); if (typeof entry.required !== "boolean") bad(); one(entry.state, ["healthy", "degraded", "unavailable"]); date(entry.fresh_at); } });
export const decodeSystemVersion = (value: unknown) => decoded<SystemVersion>(value, ["version"], (record) => text(record.version, 64));

function page<T>(value: unknown, decodeItem: (item: unknown) => unknown): T { return decoded<T>(value, ["items", "page_info"], (record) => { for (const item of list(record.items, 100)) decodeItem(item); const info = exact(record.page_info, ["next_cursor", "has_more"]); if (info.has_more === true) text(info.next_cursor, 512); else if (info.has_more !== false || info.next_cursor !== null) bad(); }); }
function sessionEvent(value: unknown) { const record = exact(value, ["id", "session_id", "class", "label", "evidence_id", "source", "confidence", "at"]); text(record.id, 128); if (typeof record.session_id !== "string" || !SESSION_ID.test(record.session_id)) bad(); one(record.class, ["tool", "runtime", "network", "file", "credential", "policy"]); text(record.label, 256); text(record.evidence_id, 128); text(record.source, 64); one(record.confidence, ["exact", "strong", "probable", "unattributed"]); date(record.at); }
function control(value: unknown) { const record = exact(value, ["id", "framework", "name", "evidence_ids", "fresh_until"]); text(record.id, 128); text(record.framework, 64); text(record.name, 256); strings(record.evidence_ids, 100); date(record.fresh_until); }
function decoded<T>(value: unknown, required: string[], validate: (record: Record<string, unknown>) => void, optional: string[] = []): T { const record = exact(value, required, optional); validate(record); for (const key of optional) if (record[key] !== undefined && key.includes("correlation")) id(record[key]); return value as T; }
function exact(value: unknown, required: string[], optional: string[] = []) { if (!value || typeof value !== "object" || Array.isArray(value)) bad(); const record = value as Record<string, unknown>; const allowed = new Set([...required, ...optional]); if (Object.keys(record).some((key) => !allowed.has(key)) || required.some((key) => !(key in record))) bad(); return record; }
function id(value: unknown) { if (typeof value !== "string" || !PRODUCT_ID.test(value)) bad(); }
function text(value: unknown, maximum: number) { if (typeof value !== "string" || value.length < 1 || value.length > maximum) bad(); }
function role(value: unknown) { one(value, ["organization_admin", "security_admin", "security_engineer", "developer_owner", "compliance_viewer", "read_only_viewer"]); }
function one(value: unknown, values: string[]) { if (typeof value !== "string" || !values.includes(value)) bad(); }
function date(value: unknown) { if (typeof value !== "string" || !DATE_TIME.test(value) || Number.isNaN(Date.parse(value))) bad(); }
function nullableDate(value: unknown) { if (value !== null) date(value); }
function version(value: unknown) { integer(value, 1, Number.MAX_SAFE_INTEGER); }
function integer(value: unknown, minimum: number, maximum: number) { if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) bad(); }
function list(value: unknown, maximum: number): unknown[] { if (!Array.isArray(value) || value.length > maximum) bad(); return value; }
function strings(value: unknown, maximum: number) { const items = list(value, maximum); if (new Set(items).size !== items.length || items.some((item) => typeof item !== "string" || item.length < 1 || item.length > 128)) bad(); }
function stringRecord(value: unknown, maximum: number) { if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length > maximum || Object.values(value).some((entry) => typeof entry !== "string" || entry.length > 512)) bad(); }
function bad(): never { throw new Error("schema mismatch"); }
