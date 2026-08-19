import type { AgentSession, Capability, ConnectorManifest, HomeSummary, Integration, InventoryRecord, Policy, PolicyRollout, PolicySimulation, Principal, Relationship, RuntimeDecision, SecurityAgentDefinition, SecurityAgentTemplate, SessionBootstrap, SessionCallbackResult, SessionScope, SessionScopePage } from "./generated";

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

export function decodePolicy(value: unknown): Policy {
  const record = exactRecord(value, ["id", "name", "scope", "trigger", "conditions", "action", "rollout", "failure_mode"]);
  if (typeof record.id !== "string" || !/^policy-[a-z0-9][a-z0-9-]{0,120}$/.test(record.id)) fail();
  boundedString(record.name, 1, 256); enumValue(record.scope, ["environment"]); boundedString(record.trigger, 1, 64);
  const conditions = array(record.conditions, 32); if (conditions.length < 1) fail();
  for (const condition of conditions) { const item = exactRecord(condition, ["field", "operator", "value"]); boundedString(item.field, 1, 128); enumValue(item.operator, ["equals"]); boundedString(item.value, 1, 256); }
  enumValue(record.action, ["monitor", "block"]); enumValue(record.rollout, ["draft", "monitor", "enforced", "disabled"]); enumValue(record.failure_mode, ["open", "closed"]);
  return value as Policy;
}

export function decodePolicyPage(value: unknown): { readonly items: readonly Policy[] } { const record = exactRecord(value, ["items"]); for (const item of array(record.items, 1000)) decodePolicy(item); return value as { readonly items: readonly Policy[] }; }
export function decodePolicySimulation(value: unknown): PolicySimulation { const record = exactRecord(value, ["matches", "would_block", "example_session_ids"]); boundedInteger(record.matches, 0, 100); boundedInteger(record.would_block, 0, 100); stringArray(record.example_session_ids, 5); return value as PolicySimulation; }
export function decodePolicyRollout(value: unknown): PolicyRollout { const record = exactRecord(value, ["policy_id", "state", "target_id"]); if (typeof record.policy_id !== "string" || !/^policy-[a-z0-9][a-z0-9-]{0,120}$/.test(record.policy_id)) fail(); enumValue(record.state, ["draft", "monitor", "enforced", "disabled"]); boundedString(record.target_id, 1, 128); return value as PolicyRollout; }
export function decodeRuntimeDecisionPage(value: unknown): { readonly items: readonly RuntimeDecision[] } { const record = exactRecord(value, ["items"]); for (const item of array(record.items, 1000)) { const entry = exactRecord(item, ["id", "policy_id", "environment_id", "result", "correlation_id", "at"]); boundedString(entry.id, 1, 128); if (typeof entry.policy_id !== "string" || !/^policy-[a-z0-9][a-z0-9-]{0,120}$/.test(entry.policy_id)) fail(); boundedString(entry.environment_id, 1, 128); enumValue(entry.result, ["allow", "monitor", "block"]); boundedString(entry.correlation_id, 1, 128); dateTime(entry.at); } return value as { readonly items: readonly RuntimeDecision[] }; }

export function decodeConnectorManifest(value: unknown): ConnectorManifest { const record = exactRecord(value, ["key", "provider", "category", "description", "data_types", "actions", "auth_mode", "setup_schema", "access_guidance", "test_semantics"]); boundedString(record.key, 1, 63); boundedString(record.provider, 1, 128); boundedString(record.category, 1, 63); boundedString(record.description, 1, 512); stringArray(record.data_types, 64, 63, 1); stringArray(record.actions, 64, 63, 1); boundedString(record.auth_mode, 1, 63); const setup = array(record.setup_schema, 64); if (setup.length < 1) fail(); for (const field of setup) { const item = exactRecord(field, ["key", "label", "type", "required", "description"]); boundedString(item.key, 1, 63); boundedString(item.label, 1, 128); boundedString(item.type, 1, 63); if (typeof item.required !== "boolean") fail(); boundedString(item.description, 1, 512); } boundedString(record.access_guidance, 1, 512); boundedString(record.test_semantics, 1, 512); return value as ConnectorManifest; }
export function decodeConnectorManifestPage(value: unknown): { readonly items: readonly ConnectorManifest[] } { const record = exactRecord(value, ["items"]); for (const item of array(record.items, 100)) decodeConnectorManifest(item); return value as { readonly items: readonly ConnectorManifest[] }; }
export function decodeIntegration(value: unknown): Integration { const record = exactRecord(value, ["id", "connector_key", "name", "configuration", "status", "created_at", "updated_at"]); productID(record.id); boundedString(record.connector_key, 1, 63); boundedString(record.name, 1, 128); stringRecord(record.configuration, 16, 1, 1); enumValue(record.status, ["configured", "pending_authorization", "active"]); dateTime(record.created_at); dateTime(record.updated_at); return value as Integration; }
export function decodeIntegrationPage(value: unknown): { readonly items: readonly Integration[] } { const record = exactRecord(value, ["items"]); for (const item of array(record.items, 1000)) decodeIntegration(item); return value as { readonly items: readonly Integration[] }; }

export function decodeSecurityAgentDefinition(value: unknown): SecurityAgentDefinition { const record = exactRecord(value, ["id", "name", "trigger_kind", "trigger_source", "environment_ids", "autonomy", "max_steps", "max_duration_seconds", "temporary_policy_seconds", "ai_token_budget", "concurrency_limit", "allowed_actions", "verification_kind", "definition_version", "enabled"]); productID(record.id); boundedString(record.name, 1, 256); enumValue(record.trigger_kind, ["finding", "attack_path", "runtime_decision"]); boundedString(record.trigger_source, 1, 64); productIDArray(record.environment_ids, 100); enumValue(record.autonomy, ["supervised", "autonomous"]); boundedInteger(record.max_steps, 1, 100); boundedInteger(record.max_duration_seconds, 1, 86400); boundedInteger(record.temporary_policy_seconds, 1, 86400); boundedInteger(record.ai_token_budget, 1, 12000); boundedInteger(record.concurrency_limit, 1, 10); positiveInteger(record.definition_version); stringArray(record.allowed_actions, 32, 128, 1); boundedString(record.verification_kind, 1, 64); if (typeof record.enabled !== "boolean") fail(); return value as SecurityAgentDefinition; }
export function decodeSecurityAgentPage(value: unknown): { readonly items: readonly SecurityAgentDefinition[]; readonly next_cursor?: string } { const record = exactRecord(value, ["items"], ["next_cursor"]); for (const item of array(record.items, 100)) decodeSecurityAgentDefinition(item); if (record.next_cursor !== undefined) boundedString(record.next_cursor, 1, 128); return value as { readonly items: readonly SecurityAgentDefinition[]; readonly next_cursor?: string }; }
export function decodeSecurityAgentTemplate(value: unknown): SecurityAgentTemplate { const record = exactRecord(value, ["id", "name", "version", "trigger_kind", "default_actions", "verification_condition"]); productID(record.id); boundedString(record.name, 1, 256); positiveInteger(record.version); enumValue(record.trigger_kind, ["finding", "attack_path", "runtime_decision"]); stringArray(record.default_actions, 32, 128, 1); boundedString(record.verification_condition, 1, 256); return value as SecurityAgentTemplate; }
export function decodeSecurityAgentTemplatePage(value: unknown): { readonly items: readonly SecurityAgentTemplate[] } { const record = exactRecord(value, ["items"]); for (const item of array(record.items, 20)) decodeSecurityAgentTemplate(item); return value as { readonly items: readonly SecurityAgentTemplate[] }; }

function decodePrincipal(value: unknown): Principal { const record = exactRecord(value, ["id", "organization_id", "organization_reference", "member_reference", "role", "active"]); productID(record.id); productID(record.organization_id); boundedString(record.organization_reference, 2, 128); boundedString(record.member_reference, 2, 128); boundedString(record.role, 1, 64); if (typeof record.active !== "boolean") fail(); return value as Principal; }
function decodeSessionScope(value: unknown): SessionScope { const record = exactRecord(value, ["organization_id", "workspace_id", "environment_id", "label"]); productID(record.organization_id); productID(record.workspace_id); productID(record.environment_id); boundedString(record.label, 1, 128); return value as SessionScope; }
function exactRecord(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> { if (!value || typeof value !== "object" || Array.isArray(value)) fail(); const record = value as Record<string, unknown>; const allowed = new Set([...required, ...optional]); if (Object.keys(record).some((key) => !allowed.has(key)) || required.some((key) => !(key in record))) fail(); return record; }
function array(value: unknown, maximum: number): readonly unknown[] { if (!Array.isArray(value) || value.length > maximum) fail(); return value; }
function boundedString(value: unknown, minimum: number, maximum: number): asserts value is string { if (typeof value !== "string" || value.length < minimum || value.length > maximum) fail(); }
function productID(value: unknown): asserts value is string { if (typeof value !== "string" || !PRODUCT_ID.test(value)) fail(); }
function dateTime(value: unknown): asserts value is string { if (typeof value !== "string" || !DATE_TIME.test(value) || Number.isNaN(Date.parse(value))) fail(); }
function stringArray(value: unknown, maximumItems: number, maximumLength = 128, minimumItems = 0): asserts value is readonly string[] { const values = array(value, maximumItems); if (values.length < minimumItems || new Set(values).size !== values.length || values.some((item) => typeof item !== "string" || item.length < 1 || item.length > maximumLength)) fail(); }
function productIDArray(value: unknown, maximum: number): void { const values = array(value, maximum); if (values.length < 1 || new Set(values).size !== values.length) fail(); for (const item of values) productID(item); }
function positiveInteger(value: unknown): void { if (!Number.isSafeInteger(value) || (value as number) < 1) fail(); }
function boundedInteger(value: unknown, minimum: number, maximum: number): void { if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) fail(); }
function stringRecord(value: unknown, maximum: number, minimum = 0, minimumValueLength = 0): void { if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length < minimum || Object.keys(value).length > maximum || Object.entries(value).some(([key, item]) => key.length < 1 || key.length > 128 || typeof item !== "string" || item.length < minimumValueLength || item.length > 2048)) fail(); }
function enumValue(value: unknown, allowed: readonly string[]): void { if (typeof value !== "string" || !allowed.includes(value)) fail(); }
function fail(): never { throw new Error("schema mismatch"); }
