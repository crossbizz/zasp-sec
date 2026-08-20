import type { AgentSessionPage, AttackPath, AttackPathPage, BreakOptionPage, CapabilityPage, ConnectorManifest, Finding, FindingPage, HomeSummary, Integration, IntegrationFreshness, IntegrationSchedule, IntegrationSync, IntegrationSyncPage, InventoryDetail, InventoryPage, InventoryRecord, InventorySourceObservation, InventorySummary, Policy, PolicyRollout, PolicySimulation, Principal, RelationshipPage, RuntimeDecision, SecurityAgentDefinition, SecurityAgentPage, SecurityAgentTemplate, Sensor, SensorCoverage, SensorEnrollment, SensorPage, SessionBootstrap, SessionCallbackResult, SessionScope, SessionScopePage, WorkflowMutationReceipt, WorkflowMutationReceiptPage } from "./generated";

const PRODUCT_ID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const CURSOR = /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;
const POLICY_ID = /^policy-[a-z0-9][a-z0-9-]{0,120}$/;
const AWS_ROLE_ARN = /^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,128}$/;
const AWS_EXTERNAL_ID_REFERENCE = /^ref:aws\/external-id\/[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/;
const AWS_REGION = /^[a-z]{2}-[a-z]+-[1-9][0-9]?$/;
const KUBERNETES_CONNECTION_REFERENCE = /^ref:kubernetes\/connection\/[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/;
const SENSOR_TOKEN = /^zasp_sensor_v1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;
const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

export type Decoder<T> = (value: unknown) => T;

export function decodeSessionCallbackResult(value: unknown): SessionCallbackResult {
  const record = exactRecord(value, ["return_to"]);
  boundedString(record.return_to, 1, 2048);
  if (!record.return_to.startsWith("/") || record.return_to.startsWith("//") || record.return_to.includes("\\") || record.return_to.includes("\n") || record.return_to.includes("\r")) fail();
  return value as SessionCallbackResult;
}

export function decodeSessionBootstrap(value: unknown): SessionBootstrap {
  const record = exactRecord(value, ["principal", "organization_id", "workspace_id", "environment_id", "permissions", "capabilities", "csrf_token", "fresh_auth_expires_at", "correlation_id"]);
  decodePrincipal(record.principal);
  for (const key of ["organization_id", "workspace_id", "environment_id", "correlation_id"] as const) productID(record[key]);
  stringArray(record.permissions, 32); stringArray(record.capabilities, 128);
  boundedString(record.csrf_token, 32, 256);
  dateTime(record.fresh_auth_expires_at);
  return value as SessionBootstrap;
}

export function decodeSessionScopePage(value: unknown): SessionScopePage {
  const record = exactRecord(value, ["items"]); const items = array(record.items, 100);
  for (const item of items) decodeSessionScope(item);
  return value as SessionScopePage;
}

export function decodeSensor(value: unknown): Sensor {
  const record = exactRecord(value, ["id", "name", "kind", "mode", "state", "version", "token_expires_at", "last_heartbeat_at", "created_at", "updated_at"]);
  decodeSensorFields(record);
  return value as Sensor;
}

export function decodeSensorEnrollment(value: unknown): SensorEnrollment {
  const record = exactRecord(value, ["id", "name", "kind", "mode", "state", "version", "token_expires_at", "last_heartbeat_at", "created_at", "updated_at", "token"]);
  decodeSensorFields(record);
  if (typeof record.token !== "string" || record.token.length !== 81 || !SENSOR_TOKEN.test(record.token) || record.token_expires_at === null || record.state === "revoked") fail();
  return value as SensorEnrollment;
}

export function decodeSensorPage(value: unknown): SensorPage {
  const record = exactRecord(value, ["items", "page_info"]); const items = array(record.items, 100); let prior = "";
  for (const item of items) { const decoded = decodeSensor(item); if (prior !== "" && decoded.id <= prior) fail(); prior = decoded.id; }
  decodePageInfo(record.page_info);
  return value as SensorPage;
}

export function decodeSensorCoverage(value: unknown, expectedSensorID?: string): SensorCoverage {
  const record = exactRecord(value, ["sensor_id", "supported", "status", "last_heartbeat", "kernel", "btf", "capabilities", "event_rate", "drops"]);
  productID(record.sensor_id); if (expectedSensorID !== undefined && record.sensor_id !== expectedSensorID) fail();
  if (typeof record.supported !== "boolean" || typeof record.btf !== "boolean") fail();
  enumValue(record.status, ["pending", "healthy", "degraded", "offline", "revoked"]);
  nullableDateTime(record.last_heartbeat); printableString(record.kernel, 0, 128);
  boundedInteger(record.event_rate, 0, 1_000_000_000); boundedInteger(record.drops, 0, 1_000_000_000);
  const capabilities = array(record.capabilities, 32); let prior = "";
  for (const capability of capabilities) { enumValue(capability, ["file", "network", "process", "runtime", "syscall"]); if ((capability as string) <= prior) fail(); prior = capability as string; }
  return value as SensorCoverage;
}

function decodeSensorFields(record: Record<string, unknown>): void {
  productID(record.id); printableString(record.name, 1, 128); enumValue(record.kind, ["tetragon", "otlp"]); enumValue(record.mode, ["metadata_only", "full"]); enumValue(record.state, ["pending", "active", "degraded", "revoked"]); positiveInteger(record.version);
  nullableDateTime(record.token_expires_at); nullableDateTime(record.last_heartbeat_at); dateTime(record.created_at); dateTime(record.updated_at);
  const created = Date.parse(record.created_at as string); const updated = Date.parse(record.updated_at as string);
  if (updated < created || record.last_heartbeat_at !== null && Date.parse(record.last_heartbeat_at as string) < created) fail();
  const hasToken = record.token_expires_at !== null;
  if ((record.state === "revoked") === hasToken || hasToken && Date.parse(record.token_expires_at as string) <= created) fail();
}

export function decodeInventoryPage(value: unknown): InventoryPage {
  const record = exactRecord(value, ["items", "page_info"]); const items = array(record.items, 100); let prior = "";
  for (const item of items) { const summary = decodeInventorySummary(item); if (prior !== "" && summary.id <= prior) fail(); prior = summary.id; }
  decodePageInfo(record.page_info);
  return value as InventoryPage;
}

export function decodeInventorySummary(value: unknown): InventorySummary {
  const required = ["id", "name", "kind", "owner", "team", "tags", "evidence_id", "confidence_basis_points", "first_seen", "last_seen", "observed_at", "fresh_until", "freshness_state", "version"];
  const record = exactRecord(value, required);
  productID(record.id); boundedString(record.name, 1, 256); enumValue(record.kind, ["asset", "agent", "tool", "identity", "runtime"]);
  boundedString(record.owner, 0, 128); boundedString(record.team, 0, 128); stringArray(record.tags, 32, 64); productID(record.evidence_id); boundedInteger(record.confidence_basis_points, 1, 10000); positiveInteger(record.version);
  for (const key of ["first_seen", "last_seen", "observed_at", "fresh_until"] as const) dateTime(record[key]);
  if (Date.parse(record.last_seen as string) < Date.parse(record.first_seen as string) || Date.parse(record.fresh_until as string) <= Date.parse(record.observed_at as string)) fail();
  enumValue(record.freshness_state, ["fresh", "stale"]);
  const tags = record.tags as readonly string[]; for (let index = 1; index < tags.length; index += 1) if (tags[index] <= tags[index - 1]) fail();
  return value as InventorySummary;
}

export function decodeInventoryRecord(value: unknown): InventoryRecord {
  decodeInventorySummary(value);
  return value as InventoryRecord;
}

export function decodeInventoryDetail(value: unknown): InventoryDetail {
  const record = exactRecord(value, ["summary", "sources", "evidence"]); const summary = decodeInventorySummary(record.summary);
  const evidenceValues = array(record.evidence, 64); if (evidenceValues.length < 1) fail();
  const evidence = new Set<string>(); let priorEvidence = "";
  for (const value of evidenceValues) {
    const item = exactRecord(value, ["id", "checksum", "media_type", "schema_version", "parser_version", "tool_version", "collected_at", "size_bytes"]);
    productID(item.id); checksum(item.checksum); boundedString(item.media_type, 1, 128); boundedString(item.schema_version, 1, 64); boundedString(item.parser_version, 1, 64); boundedString(item.tool_version, 1, 64); dateTime(item.collected_at); boundedInteger(item.size_bytes, 1, 536870912);
    if (evidence.has(item.id as string) || priorEvidence !== "" && (item.id as string) <= priorEvidence) fail(); evidence.add(item.id as string); priorEvidence = item.id as string;
  }
  const sources = array(record.sources, 64); if (sources.length < 1) fail(); let winners = 0; let priorSource = "";
  for (const value of sources) {
    const source = decodeInventorySourceObservation(value); const key = `${source.integration_id}\u001f${source.provider}\u001f${source.source}\u001f${source.source_identifier}`;
    if (priorSource !== "" && key <= priorSource || !evidence.has(source.evidence_id)) fail(); priorSource = key;
    if (source.winning) { winners += 1; if (source.evidence_id !== summary.evidence_id || source.confidence_basis_points !== summary.confidence_basis_points || source.observed_at !== summary.observed_at || source.fresh_until !== summary.fresh_until) fail(); }
  }
  if (winners !== 1) fail();
  return value as InventoryDetail;
}

function decodeInventorySourceObservation(value: unknown): InventorySourceObservation {
  const entry = exactRecord(value, ["integration_id", "provider", "source", "source_identifier", "snapshot_id", "generation", "evidence_id", "confidence_basis_points", "observed_at", "fresh_until", "projection_version", "winning"]);
  productID(entry.integration_id); enumValue(entry.provider, ["aws", "kubernetes", "github", "okta"]); if (typeof entry.source !== "string" || !/^[a-z][a-z0-9_]{1,63}$/.test(entry.source)) fail(); checksum(entry.source_identifier); productID(entry.snapshot_id); positiveInteger(entry.generation); productID(entry.evidence_id); boundedInteger(entry.confidence_basis_points, 1, 10000); dateTime(entry.observed_at); dateTime(entry.fresh_until); if (Date.parse(entry.fresh_until as string) <= Date.parse(entry.observed_at as string)) fail(); positiveInteger(entry.projection_version); if (typeof entry.winning !== "boolean") fail();
  return value as InventorySourceObservation;
}

export function decodeCapabilityPage(value: unknown): CapabilityPage {
  const record = exactRecord(value, ["items", "page_info"]); for (const item of array(record.items, 100)) {
    const entry = exactRecord(item, ["agent_id", "target_id", "target_kind", "category", "outcome", "state", "reachable", "evidence_ids"]);
    productID(entry.agent_id); productID(entry.target_id); enumValue(entry.target_kind, ["tool", "identity", "resource", "action"]); enumValue(entry.category, ["data_read", "data_write", "action_execute", "identity_assume", "network_egress", "administration"]); enumValue(entry.outcome, ["read", "write", "execute", "assume", "connect", "administer"]); enumValue(entry.state, ["reachable", "observed", "verified", "blocked"]); if (typeof entry.reachable !== "boolean") fail(); productIDArray(entry.evidence_ids, 64);
  } decodePageInfo(record.page_info); return value as CapabilityPage;
}

export function decodeRelationshipPage(value: unknown): RelationshipPage {
  const record = exactRecord(value, ["items", "page_info"]); for (const item of array(record.items, 100)) { const entry = exactRecord(item, ["id", "from_id", "to_id", "type", "evidence_id"]); productID(entry.id); productID(entry.from_id); productID(entry.to_id); if (entry.from_id === entry.to_id) fail(); boundedString(entry.type, 1, 64); productID(entry.evidence_id); } decodePageInfo(record.page_info); return value as RelationshipPage;
}

export function decodeAgentSessionPage(value: unknown): AgentSessionPage {
  const record = exactRecord(value, ["items", "page_info"]); for (const item of array(record.items, 100)) { const entry = exactRecord(item, ["id", "agent_id", "started_at"]); productID(entry.id); productID(entry.agent_id); dateTime(entry.started_at); } decodePageInfo(record.page_info); return value as AgentSessionPage;
}

export function decodeHomeSummary(value: unknown): HomeSummary {
  const integers = ["agent_count", "high_risk_paths", "verified_changes", "blocked_changes", "pending_approvals", "oldest_approval_age_seconds", "needs_human_runs", "failed_runs", "inconclusive_runs", "recent_contained", "recent_remediated"];
  const record = exactRecord(value, [...integers, "healthy", "attention_required"]);
  for (const key of integers) if (!Number.isSafeInteger(record[key]) || (record[key] as number) < 0) fail();
  if (typeof record.healthy !== "boolean" || typeof record.attention_required !== "boolean") fail();
  return value as HomeSummary;
}

export function decodeFinding(value: unknown): Finding {
  const required = ["id", "source", "title", "severity", "status", "evidence_ids", "risk_factors", "version", "created_at", "updated_at"];
  const record = exactRecord(value, required, ["rule", "agent_id", "path_id", "compliance_context", "acceptance_reason"]);
  productID(record.id); enumValue(record.source, ["posture", "prowler"]); boundedString(record.title, 1, 256);
  enumValue(record.severity, ["critical", "high", "medium", "low"]); enumValue(record.status, ["open", "under_review", "resolved", "accepted"]);
  for (const key of ["rule", "compliance_context", "acceptance_reason"] as const) if (record[key] !== undefined) boundedString(record[key], 1, key === "rule" ? 64 : key === "compliance_context" ? 128 : 512);
  for (const key of ["agent_id", "path_id"] as const) if (record[key] !== undefined) productID(record[key]);
  productIDArray(record.evidence_ids, 64);
  const evidenceIDs = new Set(record.evidence_ids as readonly string[]);
  const factors = array(record.risk_factors, 16); const factorNames = new Set<string>();
  for (const factor of factors) { const item = exactRecord(factor, ["name", "evidence_id"]); boundedString(item.name, 1, 64); productID(item.evidence_id); if (!evidenceIDs.has(item.evidence_id as string) || factorNames.has(item.name as string)) fail(); factorNames.add(item.name as string); }
  positiveInteger(record.version); dateTime(record.created_at); dateTime(record.updated_at);
  if (Date.parse(record.updated_at as string) < Date.parse(record.created_at as string)) fail();
  if ((record.status === "accepted") !== (typeof record.acceptance_reason === "string")) fail();
  return value as Finding;
}

export function decodeFindingPage(value: unknown): FindingPage {
  const record = exactRecord(value, ["items", "page_info"]); for (const item of array(record.items, 100)) decodeFinding(item); decodePageInfo(record.page_info); return value as FindingPage;
}

export function decodeAttackPath(value: unknown): AttackPath {
  const record = exactRecord(value, ["id", "entry_id", "sink_id", "node_ids", "state", "evidence_ids", "blocked_edge", "version", "created_at", "updated_at"]);
  productID(record.id); productID(record.entry_id); productID(record.sink_id); productIDArrayBounded(record.node_ids, 2, 8); productIDArray(record.evidence_ids, 16);
  const nodes = record.node_ids as readonly string[]; if (nodes[0] !== record.entry_id || nodes[nodes.length - 1] !== record.sink_id) fail();
  enumValue(record.state, ["potential", "observed", "verified", "blocked"]); boundedInteger(record.blocked_edge, -1, 6);
  if (record.state === "blocked" ? (record.blocked_edge as number) < 0 || (record.blocked_edge as number) >= nodes.length - 1 : record.blocked_edge !== -1) fail();
  positiveInteger(record.version); dateTime(record.created_at); dateTime(record.updated_at); if (Date.parse(record.updated_at as string) < Date.parse(record.created_at as string)) fail();
  return value as AttackPath;
}

export function decodeAttackPathPage(value: unknown): AttackPathPage {
  const record = exactRecord(value, ["items", "page_info"]); for (const item of array(record.items, 100)) decodeAttackPath(item); decodePageInfo(record.page_info); return value as AttackPathPage;
}

export function decodeBreakOptionPage(value: unknown, path: Pick<AttackPath, "id" | "evidence_ids">): BreakOptionPage {
  const record = exactRecord(value, ["items"]); const items = array(record.items, 8); let pathID: string | undefined; const targets = new Set<string>();
  productID(path.id); productIDArray(path.evidence_ids, 16); const evidenceIDs = new Set(path.evidence_ids);
  for (let index = 0; index < items.length; index++) { const item = exactRecord(items[index], ["path_id", "target_id", "evidence_id", "kind", "rank"]); productID(item.path_id); productID(item.target_id); productID(item.evidence_id); enumValue(item.kind, ["remove_node", "enforce_policy"]); if (item.rank !== index + 1 || item.path_id !== path.id || pathID !== undefined && item.path_id !== pathID || !evidenceIDs.has(item.evidence_id as string)) fail(); pathID = item.path_id as string; const key = `${item.kind}\u0000${item.target_id}`; if (targets.has(key)) fail(); targets.add(key); }
  return value as BreakOptionPage;
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

export function decodePolicyPage(value: unknown): { readonly items: readonly Policy[]; readonly page_info: { readonly next_cursor: string; readonly has_more: true } | { readonly next_cursor: null; readonly has_more: false } } { const record = exactRecord(value, ["items", "page_info"]); for (const item of array(record.items, 100)) decodePolicy(item); decodePageInfo(record.page_info); return value as { readonly items: readonly Policy[]; readonly page_info: { readonly next_cursor: string; readonly has_more: true } | { readonly next_cursor: null; readonly has_more: false } }; }
export function decodeWorkflowMutationReceiptPage(value: unknown, expectedScopeKey?: string): WorkflowMutationReceiptPage { const record = exactRecord(value, ["items"]); for (const item of array(record.items, 50)) decodeWorkflowMutationReceipt(item, expectedScopeKey); return value as WorkflowMutationReceiptPage; }
export function decodeWorkflowMutationReceipt(value: unknown, expectedScopeKey?: string): WorkflowMutationReceipt {
  const record = exactRecord(value, ["id", "operation", "idempotency_key", "intent", "result", "resource_kind", "resource_id", "resource_version", "audit_id", "correlation_id", "created_at", "expires_at"]);
  productID(record.id);
  if (typeof record.idempotency_key !== "string" || !IDEMPOTENCY_KEY.test(record.idempotency_key)) fail();
  enumValue(record.operation, ["createPolicy", "updatePolicy", "deletePolicy", "rolloutPolicy", "disablePolicy", "createIntegration", "updateIntegration", "deleteIntegration", "remediateIntegrationAuthorization", "completeIntegrationOAuth", "completeIntegrationReferenceAuthorization", "syncIntegration", "putIntegrationSchedule", "deleteIntegrationSchedule", "createSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent", "updateFinding", "acceptFindingRisk"]);
  enumValue(record.resource_kind, ["policy", "integration", "integration_sync", "integration_schedule", "security_agent", "finding"]);
  if (typeof record.resource_id !== "string" || !workflowResourceID(record.resource_kind, record.resource_id)) fail();
  positiveInteger(record.resource_version);
  productID(record.audit_id); productID(record.correlation_id);
  dateTime(record.created_at); dateTime(record.expires_at);
  const lifetime = Date.parse(record.expires_at) - Date.parse(record.created_at);
  if (lifetime <= 0 || lifetime > SEVEN_DAYS_MS || containsReadableWorkflowSecret(record.intent) || containsReadableWorkflowSecret(record.result)) fail();
  decodeWorkflowReceiptPayload(record.operation, record.resource_kind, record.resource_id, record.resource_version as number, record.idempotency_key as string, record.intent, record.result, expectedScopeKey);
  return value as WorkflowMutationReceipt;
}
export function decodePolicySimulation(value: unknown): PolicySimulation { const record = exactRecord(value, ["matches", "would_block", "example_session_ids"]); boundedInteger(record.matches, 0, 100); boundedInteger(record.would_block, 0, 100); stringArray(record.example_session_ids, 5); return value as PolicySimulation; }
export function decodePolicyRollout(value: unknown): PolicyRollout { const record = exactRecord(value, ["policy_id", "state", "target_id"]); if (typeof record.policy_id !== "string" || !/^policy-[a-z0-9][a-z0-9-]{0,120}$/.test(record.policy_id)) fail(); enumValue(record.state, ["draft", "monitor", "enforced", "disabled"]); boundedString(record.target_id, 1, 128); return value as PolicyRollout; }
export function decodeRuntimeDecisionPage(value: unknown): { readonly items: readonly RuntimeDecision[] } { const record = exactRecord(value, ["items"]); for (const item of array(record.items, 1000)) { const entry = exactRecord(item, ["id", "policy_id", "environment_id", "result", "correlation_id", "at"]); boundedString(entry.id, 1, 128); if (typeof entry.policy_id !== "string" || !/^policy-[a-z0-9][a-z0-9-]{0,120}$/.test(entry.policy_id)) fail(); boundedString(entry.environment_id, 1, 128); enumValue(entry.result, ["allow", "monitor", "block"]); boundedString(entry.correlation_id, 1, 128); dateTime(entry.at); } return value as { readonly items: readonly RuntimeDecision[] }; }

export function decodeConnectorManifest(value: unknown): ConnectorManifest { const record = exactRecord(value, ["key", "provider", "category", "description", "data_types", "actions", "auth_mode", "setup_schema", "access_guidance", "test_semantics"]); boundedString(record.key, 1, 63); boundedString(record.provider, 1, 128); boundedString(record.category, 1, 63); boundedString(record.description, 1, 512); stringArray(record.data_types, 64, 63, 1); stringArray(record.actions, 64, 63, 1); boundedString(record.auth_mode, 1, 63); const setup = array(record.setup_schema, 64); if (setup.length < 1) fail(); for (const field of setup) { const item = exactRecord(field, ["key", "label", "type", "required", "description"]); boundedString(item.key, 1, 63); boundedString(item.label, 1, 128); boundedString(item.type, 1, 63); if (typeof item.required !== "boolean") fail(); boundedString(item.description, 1, 512); } boundedString(record.access_guidance, 1, 512); boundedString(record.test_semantics, 1, 512); return value as ConnectorManifest; }
export function decodeConnectorManifestPage(value: unknown): { readonly items: readonly ConnectorManifest[] } { const record = exactRecord(value, ["items"]); for (const item of array(record.items, 100)) decodeConnectorManifest(item); return value as { readonly items: readonly ConnectorManifest[] }; }
export function decodeIntegration(value: unknown): Integration { const record = exactRecord(value, ["id", "connector_key", "name", "configuration", "status", "created_at", "updated_at"]); productID(record.id); boundedString(record.connector_key, 1, 63); boundedString(record.name, 1, 128); decodeIntegrationConfiguration(record.connector_key as string, record.configuration); enumValue(record.status, ["configured", "pending_authorization", "active", "degraded", "revoking"]); dateTime(record.created_at); dateTime(record.updated_at); return value as Integration; }
export function decodeIntegrationPage(value: unknown): { readonly items: readonly Integration[]; readonly page_info: { readonly next_cursor: string; readonly has_more: true } | { readonly next_cursor: null; readonly has_more: false } } { const record = exactRecord(value, ["items", "page_info"]); for (const item of array(record.items, 100)) decodeIntegration(item); decodePageInfo(record.page_info); return value as { readonly items: readonly Integration[]; readonly page_info: { readonly next_cursor: string; readonly has_more: true } | { readonly next_cursor: null; readonly has_more: false } }; }

const COLLECTION_FAILURE_CODES = ["retryable", "rate_limited", "denied", "revoked", "malformed", "partial", "terminal", "cancelled", "outcome_unknown"] as const;

export function decodeIntegrationSync(value: unknown): IntegrationSync {
  const record = exactRecord(value, ["id", "integration_id", "trigger_kind", "status", "attempt", "requested_at", "started_at", "completed_at", "discovered_count", "changed_count", "removed_count", "snapshot_id", "last_error_code", "retry_at"]);
  productID(record.id); productID(record.integration_id); enumValue(record.trigger_kind, ["manual", "schedule", "retry"]); enumValue(record.status, ["queued", "running", "succeeded", "failed", "cancelled"]);
  boundedInteger(record.attempt, 0, 100); dateTime(record.requested_at); nullableDateTime(record.started_at); nullableDateTime(record.completed_at); nullableDateTime(record.retry_at);
  for (const key of ["discovered_count", "changed_count", "removed_count"] as const) boundedInteger(record[key], 0, Number.MAX_SAFE_INTEGER);
  if (record.snapshot_id !== null) productID(record.snapshot_id);
  if (record.last_error_code !== null) enumValue(record.last_error_code, COLLECTION_FAILURE_CODES);
  const requested = Date.parse(record.requested_at as string);
  const started = record.started_at === null ? null : Date.parse(record.started_at as string);
  const completed = record.completed_at === null ? null : Date.parse(record.completed_at as string);
  const retry = record.retry_at === null ? null : Date.parse(record.retry_at as string);
  if (started !== null && started < requested || completed !== null && (completed < requested || started !== null && completed < started) || retry !== null && retry < requested) fail();
  if (record.status === "queued") {
    if (completed !== null || record.snapshot_id !== null) fail();
    if (record.attempt === 0) {
      if (started !== null || record.last_error_code !== null || retry !== null) fail();
    } else if (started === null || record.last_error_code === null || retry === null) {
      fail();
    }
  }
  if (record.status === "running" && (started === null || completed !== null || record.snapshot_id !== null || record.last_error_code !== null || retry !== null)) fail();
  if (record.status === "succeeded" && (started === null || completed === null || record.snapshot_id === null || record.last_error_code !== null || retry !== null)) fail();
  if ((record.status === "failed" || record.status === "cancelled") && (started === null || completed === null || record.last_error_code === null || record.snapshot_id !== null)) fail();
  if (record.status === "cancelled" && (record.last_error_code !== "cancelled" || retry !== null)) fail();
  return value as IntegrationSync;
}

export function decodeIntegrationSyncPage(value: unknown): IntegrationSyncPage {
  const record = exactRecord(value, ["items", "page_info"]);
  for (const item of array(record.items, 100)) decodeIntegrationSync(item);
  decodePageInfo(record.page_info);
  return value as IntegrationSyncPage;
}

export function decodeIntegrationSchedule(value: unknown): IntegrationSchedule {
  const record = exactRecord(value, ["integration_id", "cadence_seconds", "state", "time_zone", "next_run_at", "version", "created_at", "updated_at"]);
  productID(record.integration_id); boundedInteger(record.cadence_seconds, 300, 2_678_400); enumValue(record.state, ["enabled", "disabled", "deleted"]);
  if (record.time_zone !== "UTC") fail();
  nullableDateTime(record.next_run_at); positiveInteger(record.version); dateTime(record.created_at); dateTime(record.updated_at);
  if (Date.parse(record.updated_at as string) < Date.parse(record.created_at as string)) fail();
  if (record.state === "enabled" ? record.next_run_at === null : record.next_run_at !== null) fail();
  return value as IntegrationSchedule;
}

export function decodeIntegrationFreshness(value: unknown): IntegrationFreshness {
  const record = exactRecord(value, ["integration_id", "version", "last_good", "latest_sync", "projections", "updated_at"]);
  productID(record.integration_id); positiveInteger(record.version); dateTime(record.updated_at);
  if (record.last_good !== null) {
    const lastGood = exactRecord(record.last_good, ["snapshot_id", "collected_at", "discovered_count", "changed_count", "removed_count"]);
    productID(lastGood.snapshot_id); dateTime(lastGood.collected_at);
    for (const key of ["discovered_count", "changed_count", "removed_count"] as const) boundedInteger(lastGood[key], 0, Number.MAX_SAFE_INTEGER);
  }
  if (record.latest_sync !== null) {
    const latest = decodeIntegrationSync(record.latest_sync);
    if (latest.integration_id !== record.integration_id) fail();
  }
  const projections = exactRecord(record.projections, ["risk", "graph", "search"]);
  for (const key of ["risk", "graph", "search"] as const) decodeIntegrationProjectionStatus(projections[key]);
  return value as IntegrationFreshness;
}

function decodeIntegrationProjectionStatus(value: unknown): void {
  const record = exactRecord(value, ["state", "snapshot_id", "completed_at", "last_error_code"]);
  enumValue(record.state, ["current", "pending", "degraded", "unavailable"]);
  if (record.snapshot_id !== null) productID(record.snapshot_id);
  nullableDateTime(record.completed_at);
  if (record.last_error_code !== null) enumValue(record.last_error_code, COLLECTION_FAILURE_CODES);
  if (record.state === "current") {
    if (record.snapshot_id === null || record.completed_at === null || record.last_error_code !== null) fail();
  } else if (record.state === "pending") {
    if (record.snapshot_id === null || record.completed_at !== null || (record.last_error_code !== null && record.last_error_code !== "retryable")) fail();
  } else if (record.state === "degraded") {
    const terminal = record.completed_at !== null && (record.last_error_code === "terminal" || record.last_error_code === "cancelled");
    const bindingMismatch = record.completed_at === null && record.last_error_code === "outcome_unknown";
    if (record.snapshot_id === null || (!terminal && !bindingMismatch)) fail();
  } else if (record.snapshot_id !== null || record.completed_at !== null || record.last_error_code !== null) {
    fail();
  }
}

export function decodeSecurityAgentDefinition(value: unknown): SecurityAgentDefinition { const record = exactRecord(value, ["id", "name", "trigger_kind", "trigger_source", "environment_ids", "autonomy", "max_steps", "max_duration_seconds", "temporary_policy_seconds", "ai_token_budget", "concurrency_limit", "allowed_actions", "verification_kind", "definition_version", "enabled"]); productID(record.id); boundedString(record.name, 1, 256); enumValue(record.trigger_kind, ["finding", "attack_path", "runtime_decision"]); boundedString(record.trigger_source, 1, 64); productIDArray(record.environment_ids, 100); enumValue(record.autonomy, ["supervised", "autonomous"]); boundedInteger(record.max_steps, 1, 100); boundedInteger(record.max_duration_seconds, 1, 86400); boundedInteger(record.temporary_policy_seconds, 1, 86400); boundedInteger(record.ai_token_budget, 1, 12000); boundedInteger(record.concurrency_limit, 1, 10); positiveInteger(record.definition_version); stringArray(record.allowed_actions, 32, 128, 1); boundedString(record.verification_kind, 1, 64); if (typeof record.enabled !== "boolean") fail(); return value as SecurityAgentDefinition; }
export function decodeSecurityAgentPage(value: unknown): SecurityAgentPage { const record = exactRecord(value, ["items", "page_info"]); for (const item of array(record.items, 100)) decodeSecurityAgentDefinition(item); decodePageInfo(record.page_info); return value as SecurityAgentPage; }
export function decodeSecurityAgentTemplate(value: unknown): SecurityAgentTemplate { const record = exactRecord(value, ["id", "name", "version", "trigger_kind", "default_actions", "verification_condition"]); productID(record.id); boundedString(record.name, 1, 256); positiveInteger(record.version); enumValue(record.trigger_kind, ["finding", "attack_path", "runtime_decision"]); stringArray(record.default_actions, 32, 128, 1); boundedString(record.verification_condition, 1, 256); return value as SecurityAgentTemplate; }
export function decodeSecurityAgentTemplatePage(value: unknown): { readonly items: readonly SecurityAgentTemplate[] } { const record = exactRecord(value, ["items"]); for (const item of array(record.items, 20)) decodeSecurityAgentTemplate(item); return value as { readonly items: readonly SecurityAgentTemplate[] }; }

function decodeWorkflowReceiptPayload(operation: unknown, kind: unknown, resourceID: string, resourceVersion: number, idempotencyKey: string, intentValue: unknown, resultValue: unknown, expectedScopeKey?: string): void {
  if (operation === "syncIntegration") {
    if (kind !== "integration_sync") fail();
    const result = decodeIntegrationSync(resultValue);
    if (result.id !== resourceID || result.trigger_kind !== "manual" || result.status !== "queued" || result.attempt !== 0 || result.discovered_count !== 0 || result.changed_count !== 0 || result.removed_count !== 0 || resourceVersion < 1) fail();
    const intent = decodeScopedDiscoveryReceiptIntent(intentValue, idempotencyKey, expectedScopeKey);
    emptyRecord(intent.body);
    if (intent.expected_version < 1 || intent.integration_id !== result.integration_id) fail();
    return;
  }
  if (operation === "putIntegrationSchedule" || operation === "deleteIntegrationSchedule") {
    if (kind !== "integration_schedule") fail();
    const result = decodeIntegrationSchedule(resultValue);
    const intent = decodeScopedDiscoveryReceiptIntent(intentValue, idempotencyKey, expectedScopeKey);
    if (resourceID !== result.integration_id || intent.integration_id !== resourceID || intent.expected_version < 0 || intent.expected_version + 1 !== resourceVersion || result.version !== resourceVersion) fail();
    if (operation === "putIntegrationSchedule") {
      const body = exactRecord(intent.body, ["cadence_seconds", "state"]);
      boundedInteger(body.cadence_seconds, 300, 2_678_400); enumValue(body.state, ["enabled", "disabled"]);
      if (body.cadence_seconds !== result.cadence_seconds || body.state !== result.state) fail();
    } else {
      emptyRecord(intent.body);
      if (result.state !== "deleted" || result.next_run_at !== null) fail();
    }
    return;
  }
  const expectedKind = typeof operation === "string" && operation.includes("Integration") ? "integration"
    : typeof operation === "string" && operation.includes("SecurityAgent") ? "security_agent"
    : typeof operation === "string" && operation.includes("Finding") ? "finding"
    : typeof operation === "string" && ["createPolicy", "updatePolicy", "deletePolicy", "rolloutPolicy", "disablePolicy"].includes(operation) ? "policy" : fail();
  if (kind !== expectedKind) fail();
  if (operation === "completeIntegrationReferenceAuthorization") {
    decodeIntegration(resultValue);
    const result = resultValue as Integration;
    if (kind !== "integration" || result.id !== resourceID || result.status !== "active") fail();
    decodeReferenceAuthorizationReceiptIntent(intentValue, result, resourceID, resourceVersion, idempotencyKey, expectedScopeKey);
    return;
  }
  if (operation === "completeIntegrationOAuth") {
    decodeIntegration(resultValue);
    const result = resultValue as Integration;
    const intent = exactRecord(intentValue, ["authorization_attempt_id", "integration_id", "provider"]);
    productID(intent.authorization_attempt_id); productID(intent.integration_id);
    if (typeof intent.provider !== "string" || !/^(github|okta|nango:[a-z0-9][a-z0-9_-]{1,62})$/.test(intent.provider)) fail();
    if (kind !== "integration" || result.id !== resourceID || result.status !== "active" || intent.integration_id !== resourceID || intent.provider !== result.connector_key || idempotencyKey !== `oauth-completion:${intent.authorization_attempt_id}`) fail();
    return;
  }
  const intent = exactRecord(intentValue, ["body", "expected_version", "resource_id"]);
  const create = typeof operation === "string" && operation.startsWith("create");
  if (create) {
    if (intent.expected_version !== 0 || intent.resource_id !== "") fail();
  } else if (!Number.isSafeInteger(intent.expected_version) || (intent.expected_version as number) < 1 || intent.resource_id !== resourceID) fail();

  if (kind === "policy") {
    decodePolicy(resultValue);
    if ((resultValue as Policy).id !== resourceID) fail();
    decodePolicyReceiptIntent(operation as string, intent.body, resultValue as Policy);
    return;
  }
  if (kind === "integration") {
    if (operation === "createIntegration") {
      if (resourceVersion !== 1) fail();
    } else if ((operation === "updateIntegration" || operation === "deleteIntegration") && intent.expected_version !== resourceVersion - 1) fail();
    if (operation === "deleteIntegration") {
      const terminal = Boolean(resultValue) && typeof resultValue === "object" && !Array.isArray(resultValue) && (resultValue as Record<string, unknown>).status === "deleted";
      if (terminal) {
        const result = exactRecord(resultValue, ["id", "status"]);
        productID(result.id); enumValue(result.status, ["deleted"]);
        if (result.id !== resourceID) fail();
      } else {
        decodeIntegration(resultValue);
        const result = resultValue as Integration;
        if (result.id !== resourceID || result.status !== "revoking") fail();
      }
      emptyRecord(intent.body);
      return;
    }
    decodeIntegration(resultValue);
    if ((resultValue as Integration).id !== resourceID) fail();
    decodeIntegrationReceiptIntent(operation as string, intent.body, resultValue as Integration);
    return;
  }
  if (kind === "finding") {
    decodeFinding(resultValue);
    if ((resultValue as Finding).id !== resourceID) fail();
    const input = operation === "updateFinding" ? exactRecord(intent.body, ["status"]) : operation === "acceptFindingRisk" ? exactRecord(intent.body, ["reason"]) : fail();
    if (operation === "updateFinding") { enumValue(input.status, ["open", "under_review", "resolved"]); if ((resultValue as Finding).status !== input.status) fail(); }
    else { boundedString(input.reason, 1, 512); if ((resultValue as Finding).status !== "accepted" || (resultValue as Finding).acceptance_reason !== input.reason) fail(); }
    return;
  }
  decodeSecurityAgentDefinition(resultValue);
  if ((resultValue as SecurityAgentDefinition).id !== resourceID) fail();
  decodeSecurityAgentReceiptIntent(operation as string, intent.body, resultValue as SecurityAgentDefinition);
}

function decodeScopedDiscoveryReceiptIntent(value: unknown, receiptIdempotencyKey: string, expectedScopeKey?: string): { body: unknown; expected_version: number; integration_id: string } {
  const input = exactRecord(value, ["body", "expected_version", "idempotency_key", "integration_id", "scope"]);
  if (!Number.isSafeInteger(input.expected_version) || (input.expected_version as number) < 0 || input.idempotency_key !== receiptIdempotencyKey) fail();
  productID(input.integration_id);
  const scope = exactRecord(input.scope, ["environment_id", "organization_id", "workspace_id"]);
  productID(scope.environment_id); productID(scope.organization_id); productID(scope.workspace_id);
  if (!expectedScopeKey || `${scope.organization_id}/${scope.workspace_id}/${scope.environment_id}` !== expectedScopeKey) fail();
  return { body: input.body, expected_version: input.expected_version as number, integration_id: input.integration_id as string };
}

function decodePolicyReceiptIntent(operation: string, body: unknown, result: Policy): void {
  switch (operation) {
  case "createPolicy":
  case "updatePolicy":
    decodePolicy(body);
    if (!sameJSON(body, result)) fail();
    return;
  case "deletePolicy":
    emptyRecord(body);
    return;
  case "rolloutPolicy": {
    const rollout = exactRecord(body, ["state", "target_id"]);
    enumValue(rollout.state, ["monitor", "enforced"]); productID(rollout.target_id);
    if (result.rollout !== rollout.state) fail();
    return;
  }
  case "disablePolicy":
    emptyRecord(body);
    if (result.rollout !== "disabled") fail();
    return;
  default:
    fail();
  }
}

function decodeIntegrationReceiptIntent(operation: string, body: unknown, result: Integration): void {
  if (operation === "remediateIntegrationAuthorization") { const input = exactRecord(body, ["acknowledgement"]); enumValue(input.acknowledgement, ["provider_grant_revoked_manually", "provider_grant_verified_absent"]); enumValue(result.status, ["pending_authorization", "active", "revoking"]); return; }
  if (operation !== "createIntegration" && operation !== "updateIntegration") fail();
  const required = operation === "createIntegration" ? ["connector_key", "name", "configuration"] : ["name", "configuration"];
  const input = exactRecord(body, required);
  if (operation === "createIntegration") {
    boundedString(input.connector_key, 1, 63);
    if (input.connector_key !== result.connector_key) fail();
  }
  boundedString(input.name, 1, 128); decodeIntegrationConfiguration(result.connector_key, input.configuration);
  if (input.name !== result.name || !sameJSON(input.configuration, result.configuration)) fail();
}

function decodeReferenceAuthorizationReceiptIntent(value: unknown, result: Integration, resourceID: string, resourceVersion: number, receiptIdempotencyKey: string, expectedScopeKey?: string): void {
  const input = exactRecord(value, ["configuration", "expected_version", "idempotency_key", "integration_id", "provider", "scope"]);
  if (!Number.isSafeInteger(input.expected_version) || (input.expected_version as number) < 1 || (input.expected_version as number) + 1 !== resourceVersion) fail();
  if (input.idempotency_key !== receiptIdempotencyKey || input.integration_id !== resourceID) fail();
  enumValue(input.provider, ["aws", "kubernetes"]);
  if (input.provider !== result.connector_key) fail();
  const scope = exactRecord(input.scope, ["environment_id", "organization_id", "workspace_id"]);
  productID(scope.environment_id); productID(scope.organization_id); productID(scope.workspace_id);
  if (!expectedScopeKey || `${scope.organization_id}/${scope.workspace_id}/${scope.environment_id}` !== expectedScopeKey) fail();
  decodeIntegrationConfiguration(input.provider as string, input.configuration);
  if (!sameJSON(input.configuration, result.configuration)) fail();
}

function decodeIntegrationConfiguration(connectorKey: string, value: unknown): void {
  if (connectorKey === "aws") {
    const configuration = exactRecord(value, ["external_id_reference", "region", "role_arn"]);
    if (typeof configuration.role_arn !== "string" || !AWS_ROLE_ARN.test(configuration.role_arn)) fail();
    if (typeof configuration.external_id_reference !== "string" || !AWS_EXTERNAL_ID_REFERENCE.test(configuration.external_id_reference)) fail();
    if (typeof configuration.region !== "string" || !AWS_REGION.test(configuration.region)) fail();
    return;
  }
  if (connectorKey === "kubernetes") {
    const configuration = exactRecord(value, ["connection_reference"]);
    if (typeof configuration.connection_reference !== "string" || !KUBERNETES_CONNECTION_REFERENCE.test(configuration.connection_reference)) fail();
    return;
  }
  stringRecord(value, 16, 1, 1);
}

function decodeSecurityAgentReceiptIntent(operation: string, body: unknown, result: SecurityAgentDefinition): void {
  if (operation === "deleteSecurityAgent") { emptyRecord(body); return; }
  if (operation !== "createSecurityAgent" && operation !== "updateSecurityAgent") fail();
  const update = operation === "updateSecurityAgent";
  const input = decodeSecurityAgentReceiptBody(body, update);
  if (update) { if (!sameJSON(input, result)) fail(); return; }
  const resultInput = Object.fromEntries(Object.entries(result).filter(([key]) => key !== "id"));
  if (!sameJSON(input, resultInput)) fail();
}

function decodeSecurityAgentReceiptBody(value: unknown, includeID: boolean): Record<string, unknown> {
  const fields = ["name", "trigger_kind", "trigger_source", "environment_ids", "autonomy", "max_steps", "max_duration_seconds", "temporary_policy_seconds", "ai_token_budget", "concurrency_limit", "allowed_actions", "verification_kind", "definition_version", "enabled"];
  const record = exactRecord(value, includeID ? ["id", ...fields] : fields);
  if (includeID) productID(record.id);
  boundedString(record.name, 1, 256); enumValue(record.trigger_kind, ["finding", "attack_path", "runtime_decision"]); boundedString(record.trigger_source, 1, 64);
  productIDArray(record.environment_ids, 100); enumValue(record.autonomy, ["supervised", "autonomous"]);
  boundedInteger(record.max_steps, 1, 100); boundedInteger(record.max_duration_seconds, 1, 86400); boundedInteger(record.temporary_policy_seconds, 1, 86400);
  boundedInteger(record.ai_token_budget, 1, 12000); boundedInteger(record.concurrency_limit, 1, 10); stringArray(record.allowed_actions, 32, 128, 1);
  boundedString(record.verification_kind, 1, 64); positiveInteger(record.definition_version); if (typeof record.enabled !== "boolean") fail();
  return record;
}

function workflowResourceID(kind: unknown, value: string): boolean {
  return kind === "policy" ? POLICY_ID.test(value) : (kind === "integration" || kind === "integration_sync" || kind === "integration_schedule" || kind === "security_agent" || kind === "finding") && PRODUCT_ID.test(value);
}

function emptyRecord(value: unknown): void { exactRecord(value, []); }

function sameJSON(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (Array.isArray(left) || Array.isArray(right)) return Array.isArray(left) && Array.isArray(right) && left.length === right.length && left.every((item, index) => sameJSON(item, right[index]));
  if (!left || !right || typeof left !== "object" || typeof right !== "object") return false;
  const leftRecord = left as Record<string, unknown>; const rightRecord = right as Record<string, unknown>;
  const leftKeys = Object.keys(leftRecord).sort(); const rightKeys = Object.keys(rightRecord).sort();
  return leftKeys.length === rightKeys.length && leftKeys.every((key, index) => key === rightKeys[index] && sameJSON(leftRecord[key], rightRecord[key]));
}

function containsReadableWorkflowSecret(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsReadableWorkflowSecret);
  if (!value || typeof value !== "object") return false;
  return Object.entries(value as Record<string, unknown>).some(([key, nested]) => {
    const lower = key.toLowerCase(); const opaqueReference = lower.endsWith("_reference");
    return lower === "token" || lower.includes("password") || lower.includes("secret") && !opaqueReference || lower.includes("credential_value") || containsReadableWorkflowSecret(nested);
  });
}

function decodePrincipal(value: unknown): Principal { const record = exactRecord(value, ["id", "organization_id", "organization_reference", "member_reference", "role", "active"]); productID(record.id); productID(record.organization_id); boundedString(record.organization_reference, 2, 128); boundedString(record.member_reference, 2, 128); boundedString(record.role, 1, 64); if (typeof record.active !== "boolean") fail(); return value as Principal; }
function decodeSessionScope(value: unknown): SessionScope { const record = exactRecord(value, ["organization_id", "workspace_id", "environment_id", "label"]); productID(record.organization_id); productID(record.workspace_id); productID(record.environment_id); boundedString(record.label, 1, 128); return value as SessionScope; }
function exactRecord(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> { if (!value || typeof value !== "object" || Array.isArray(value)) fail(); const record = value as Record<string, unknown>; const allowed = new Set([...required, ...optional]); if (Object.keys(record).some((key) => !allowed.has(key)) || required.some((key) => !(key in record))) fail(); return record; }
function array(value: unknown, maximum: number): readonly unknown[] { if (!Array.isArray(value) || value.length > maximum) fail(); return value; }
function boundedString(value: unknown, minimum: number, maximum: number): asserts value is string { if (typeof value !== "string" || value.length < minimum || value.length > maximum) fail(); }
function printableString(value: unknown, minimum: number, maximum: number): asserts value is string { boundedString(value, minimum, maximum); if (value.trim() !== value || [...value].some((character) => { const code = character.codePointAt(0) ?? 0; return code < 32 || code >= 127 && code <= 159; })) fail(); }
function productID(value: unknown): asserts value is string { if (typeof value !== "string" || !PRODUCT_ID.test(value)) fail(); }
function dateTime(value: unknown): asserts value is string { if (typeof value !== "string" || !DATE_TIME.test(value) || Number.isNaN(Date.parse(value))) fail(); }
function checksum(value: unknown): asserts value is string { if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value)) fail(); }
function nullableDateTime(value: unknown): void { if (value !== null) dateTime(value); }
function stringArray(value: unknown, maximumItems: number, maximumLength = 128, minimumItems = 0): asserts value is readonly string[] { const values = array(value, maximumItems); if (values.length < minimumItems || new Set(values).size !== values.length || values.some((item) => typeof item !== "string" || item.length < 1 || item.length > maximumLength)) fail(); }
function productIDArray(value: unknown, maximum: number): void { const values = array(value, maximum); if (values.length < 1 || new Set(values).size !== values.length) fail(); for (const item of values) productID(item); }
function productIDArrayBounded(value: unknown, minimum: number, maximum: number): void { const values = array(value, maximum); if (values.length < minimum || new Set(values).size !== values.length) fail(); for (const item of values) productID(item); }
function positiveInteger(value: unknown): void { if (!Number.isSafeInteger(value) || (value as number) < 1) fail(); }
function boundedInteger(value: unknown, minimum: number, maximum: number): void { if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) fail(); }
function decodePageInfo(value: unknown): void { const pageInfo = exactRecord(value, ["next_cursor", "has_more"]); if (pageInfo.has_more === true) { boundedString(pageInfo.next_cursor, 2, 512); if (!CURSOR.test(pageInfo.next_cursor)) fail(); } else if (pageInfo.has_more !== false || pageInfo.next_cursor !== null) fail(); }
function stringRecord(value: unknown, maximum: number, minimum = 0, minimumValueLength = 0): void { if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length < minimum || Object.keys(value).length > maximum || Object.entries(value).some(([key, item]) => key.length < 1 || key.length > 128 || typeof item !== "string" || item.length < minimumValueLength || item.length > 2048)) fail(); }
function enumValue(value: unknown, allowed: readonly string[]): void { if (typeof value !== "string" || !allowed.includes(value)) fail(); }
function fail(): never { throw new Error("schema mismatch"); }
