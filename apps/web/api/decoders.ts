import type { AgentMutation, AgentSessionPage, AttackLabAttempt, AttackLabPreflight, AttackLabRun, AttackLabRunDetail, AttackLabRunPage, AttackPath, AttackPathPage, BreakOptionPage, CapabilityPage, ConnectorManifest, Finding, FindingPage, HomeSummary, Integration, IntegrationAuthorization, IntegrationFreshness, IntegrationSchedule, IntegrationSetupStatus, IntegrationSync, IntegrationSyncPage, InventoryDetail, InventoryPage, InventoryRecord, InventorySourceObservation, InventorySummary, Policy, PolicyRollout, PolicySimulation, Principal, RecoveryBackup, RecoveryCounts, RecoveryRestore, RelationshipPage, RuntimeDecision, SearchResultPage, SecurityAction, SecurityActionPage, SecurityAgentActivationState, SecurityAgentApproval, SecurityAgentApprovalPage, SecurityAgentDefinition, SecurityAgentExecutionControl, SecurityAgentExecutionControlResult, SecurityAgentExecutionControls, SecurityAgentPage, SecurityAgentRun, SecurityAgentRunDetail, SecurityAgentRunPage, SecurityAgentSimulation, SecurityAgentTemplate, Sensor, SensorCoverage, SensorEnrollment, SensorPage, SessionBootstrap, SessionCallbackResult, SessionScope, SessionScopePage, TestAttempt, TestDefinition, TestDefinitionPage, TestRun, TestRunDetail, TestRunPage, WorkflowMutationReceipt, WorkflowMutationReceiptPage } from "./generated";

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

export function decodeAgentMutation(value: unknown): AgentMutation {
  const record = exactRecord(value, ["agent", "audit_id"]);
  const agent = decodeInventorySummary(record.agent);
  if (agent.kind !== "agent") fail();
  productID(record.audit_id);
  return value as AgentMutation;
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

export function decodeGlobalSearchPage(value: unknown): SearchResultPage {
  const record = exactRecord(value, ["items"]); const items = array(record.items, 100); const seen = new Set<string>(); let prior = "";
  for (const value of items) {
    const item = exactRecord(value, ["id", "type", "name"]); productID(item.id); enumValue(item.type, ["asset", "agent", "tool", "identity", "runtime", "finding"]); printableString(item.name, 1, 256);
    const identity = `${item.type}\u001f${item.id}`; const order = `${item.type}\u001f${(item.name as string).toLocaleLowerCase("en-US")}\u001f${item.id}`;
    if (seen.has(identity) || prior !== "" && order <= prior) fail(); seen.add(identity); prior = order;
  }
  return value as SearchResultPage;
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
export function decodeRuntimeDecisionPage(value: unknown): { readonly items: readonly RuntimeDecision[] } { const record = exactRecord(value, ["items"]); for (const item of array(record.items, 100)) { const entry = exactRecord(item, ["id", "policy_id", "environment_id", "result", "correlation_id", "at"]); boundedString(entry.id, 1, 128); if (typeof entry.policy_id !== "string" || !/^policy-[a-z0-9][a-z0-9-]{0,120}$/.test(entry.policy_id)) fail(); boundedString(entry.environment_id, 1, 128); enumValue(entry.result, ["allow", "monitor", "block"]); boundedString(entry.correlation_id, 1, 128); dateTime(entry.at); } return value as { readonly items: readonly RuntimeDecision[] }; }

export function decodeConnectorManifest(value: unknown): ConnectorManifest { const record = exactRecord(value, ["key", "provider", "category", "description", "data_types", "actions", "auth_mode", "setup_schema", "access_guidance", "test_semantics"]); boundedString(record.key, 1, 63); boundedString(record.provider, 1, 128); boundedString(record.category, 1, 63); boundedString(record.description, 1, 512); stringArray(record.data_types, 64, 63, 1); stringArray(record.actions, 64, 63, 1); boundedString(record.auth_mode, 1, 63); const setup = array(record.setup_schema, 64); if (setup.length < 1) fail(); for (const field of setup) { const item = exactRecord(field, ["key", "label", "type", "required", "description"]); boundedString(item.key, 1, 63); boundedString(item.label, 1, 128); boundedString(item.type, 1, 63); if (typeof item.required !== "boolean") fail(); boundedString(item.description, 1, 512); } boundedString(record.access_guidance, 1, 512); boundedString(record.test_semantics, 1, 512); return value as ConnectorManifest; }
export function decodeConnectorManifestPage(value: unknown): { readonly items: readonly ConnectorManifest[] } { const record = exactRecord(value, ["items"]); for (const item of array(record.items, 100)) decodeConnectorManifest(item); return value as { readonly items: readonly ConnectorManifest[] }; }
export function decodeIntegration(value: unknown): Integration { const record = exactRecord(value, ["id", "connector_key", "name", "configuration", "status", "created_at", "updated_at"]); productID(record.id); boundedString(record.connector_key, 1, 63); boundedString(record.name, 1, 128); decodeIntegrationConfiguration(record.connector_key as string, record.configuration); enumValue(record.status, ["configured", "pending_authorization", "active", "degraded", "revoking"]); dateTime(record.created_at); dateTime(record.updated_at); return value as Integration; }
export function decodeIntegrationAuthorization(value: unknown): IntegrationAuthorization {
  const record = exactRecord(value, ["authorization_attempt_id", "authorization_url", "expires_at"]);
  productID(record.authorization_attempt_id); printableString(record.authorization_url, 1, 4096); dateTime(record.expires_at);
  let target: URL;
  try { target = new URL(record.authorization_url); } catch { return fail(); }
  if (target.protocol !== "https:" || target.hostname === "" || target.username !== "" || target.password !== "" || target.hash !== "") fail();
  return value as IntegrationAuthorization;
}
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

export function decodeIntegrationWebhookTestStatus(value: unknown, expectedIntegrationID?: string): import("./generated").IntegrationWebhookTestStatus {
  const record = exactRecord(value, ["integration_id", "delivery_id", "delivery_status", "signature_status", "attempted_at", "completed_at", "error_code", "audit_id"]);
  productID(record.integration_id); productID(record.delivery_id); productID(record.audit_id);
  if (expectedIntegrationID !== undefined && record.integration_id !== expectedIntegrationID) fail();
  enumValue(record.delivery_status, ["pending", "succeeded", "failed"]);
  enumValue(record.signature_status, ["signed", "unconfirmed"]);
  dateTime(record.attempted_at); nullableDateTime(record.completed_at);
  if (record.delivery_status === "pending") {
    if (record.signature_status !== "unconfirmed" || record.completed_at !== null || record.error_code !== "") fail();
  } else {
    if (record.completed_at === null || Date.parse(record.completed_at as string) < Date.parse(record.attempted_at)) fail();
    if (record.delivery_status === "succeeded" ? record.signature_status !== "signed" || record.error_code !== "" : record.signature_status !== "unconfirmed" || record.error_code !== "delivery_failed") fail();
  }
  return value as import("./generated").IntegrationWebhookTestStatus;
}

export function decodeIntegrationSetupStatus(value: unknown, expectedIntegrationID?: string): IntegrationSetupStatus {
  const record = exactRecord(value, ["integration_id", "connector_key", "authorization", "runtime_coverage", "updated_at"]);
  productID(record.integration_id); if (expectedIntegrationID !== undefined && record.integration_id !== expectedIntegrationID) fail();
  enumValue(record.connector_key, ["aws", "kubernetes", "github", "okta"]); dateTime(record.updated_at);
  const authorization = exactRecord(record.authorization, ["state", "scope_kind", "scope_label", "repository_selection", "permissions"]);
  enumValue(authorization.state, ["pending", "verified", "degraded"]); enumValue(authorization.scope_kind, ["none", "aws_account", "kubernetes_cluster", "github_organization", "okta_tenant"]);
  if (authorization.scope_label !== null) printableString(authorization.scope_label, 1, 128);
  if (authorization.repository_selection !== null) enumValue(authorization.repository_selection, ["all", "selected"]);
  stringArray(authorization.permissions, 8, 64); const permissions = authorization.permissions as readonly string[];
  if (permissions.some((permission, index) => !/^[a-z0-9._:-]+$/.test(permission) || index > 0 && permissions[index - 1] >= permission)) fail();
  if (authorization.state !== "verified") {
    if (authorization.scope_kind !== "none" || authorization.scope_label !== null || authorization.repository_selection !== null || permissions.length !== 0) fail();
  } else if (record.connector_key === "aws") {
    if (authorization.scope_kind !== "aws_account" || authorization.scope_label === null || authorization.repository_selection !== null || permissions.length !== 0) fail();
  } else if (record.connector_key === "kubernetes") {
    if (authorization.scope_kind !== "kubernetes_cluster" || authorization.scope_label === null || authorization.repository_selection !== null || permissions.length !== 0) fail();
  } else if (record.connector_key === "github") {
    if (authorization.scope_kind !== "github_organization" || authorization.scope_label === null || authorization.repository_selection === null || !sameJSON(permissions, ["actions:read", "contents:read", "metadata:read"])) fail();
  } else if (authorization.scope_kind !== "okta_tenant" || authorization.scope_label === null || authorization.repository_selection !== null || !sameJSON(permissions, ["offline_access", "okta.apps.read", "okta.groups.read", "okta.users.read"])) fail();
  const coverage = exactRecord(record.runtime_coverage, ["state", "reason", "sensor_count", "healthy_sensor_count"]);
  enumValue(coverage.state, ["not_applicable", "not_enrolled", "awaiting_heartbeat", "healthy", "degraded"]); enumValue(coverage.reason, ["not_applicable", "not_enrolled", "missing_gateway", "unsupported_kernel", "degraded", "verified"]);
  boundedInteger(coverage.sensor_count, 0, 1_000_000); boundedInteger(coverage.healthy_sensor_count, 0, coverage.sensor_count as number);
  if (record.connector_key !== "kubernetes") {
    if (coverage.state !== "not_applicable" || coverage.reason !== "not_applicable" || coverage.sensor_count !== 0 || coverage.healthy_sensor_count !== 0) fail();
  } else if (coverage.state === "not_enrolled") {
    if (coverage.reason !== "not_enrolled" || coverage.sensor_count !== 0 || coverage.healthy_sensor_count !== 0) fail();
  } else if (coverage.state === "awaiting_heartbeat") {
    if (coverage.reason !== "missing_gateway" || coverage.sensor_count === 0 || coverage.healthy_sensor_count === coverage.sensor_count) fail();
  } else if (coverage.state === "healthy") {
    if (coverage.reason !== "verified" || coverage.sensor_count === 0 || coverage.healthy_sensor_count !== coverage.sensor_count) fail();
  } else if (coverage.state === "degraded") {
    if ((coverage.reason !== "unsupported_kernel" && coverage.reason !== "degraded") || coverage.sensor_count === 0 || coverage.healthy_sensor_count === coverage.sensor_count) fail();
  } else fail();
  return value as IntegrationSetupStatus;
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

const RECOVERY_ERROR_CODES = ["dependency_unavailable", "outcome_unknown", "signature_invalid", "manifest_invalid", "manifest_expired", "validation_failed", "projection_mismatch", "cleanup_failed", "exhausted", "lease_lost", "cancelled"] as const;
const RECOVERY_OPTIONAL_FIELDS = ["manifest", "error_code", "started_at", "completed_at"] as const;

export function decodeRecoveryBackup(value: unknown, expectedScope: string): RecoveryBackup {
  const record = exactRecord(value, ["id", "version", "state", "retention_days", "attempt", "created_at"], RECOVERY_OPTIONAL_FIELDS);
  productID(record.id); boundedInteger(record.version, 1, 1_000_000); enumValue(record.state, ["queued", "draining", "capturing", "publishing", "succeeded", "retryable", "failed"]); boundedInteger(record.retention_days, 7, 90); boundedInteger(record.attempt, 0, 100); dateTime(record.created_at);
  const started = optionalRecoveryTime(record.started_at); const completed = optionalRecoveryTime(record.completed_at); recoveryTimeOrder(record.created_at as string, started, completed);
  if (record.manifest !== undefined) decodeRecoveryManifestLocator(record.manifest, expectedScope);
  if (record.error_code !== undefined) enumValue(record.error_code, RECOVERY_ERROR_CODES);
  if (record.state === "queued") {
    if (record.attempt !== 0 || started !== undefined || completed !== undefined || record.manifest !== undefined || record.error_code !== undefined) fail();
  } else if (record.state === "draining" || record.state === "capturing" || record.state === "publishing") {
    if ((record.attempt as number) < 1 || started === undefined || completed !== undefined || record.manifest !== undefined || record.error_code !== undefined) fail();
  } else if (record.state === "retryable") {
    if ((record.attempt as number) < 1 || started === undefined || completed !== undefined || record.manifest !== undefined || record.error_code === undefined) fail();
  } else if (record.state === "succeeded") {
    if ((record.attempt as number) < 1 || started === undefined || completed === undefined || record.manifest === undefined || record.error_code !== undefined) fail();
  } else if (completed === undefined || record.manifest !== undefined || record.error_code === undefined || !((record.attempt as number) >= 1 && started !== undefined || record.attempt === 0 && started === undefined && record.error_code === "exhausted")) {
    fail();
  }
  return value as RecoveryBackup;
}

export function decodeRecoveryRestore(value: unknown, expectedScope: string): RecoveryRestore {
  const optional = ["observed_counts", "validation_evidence", "cleanup_evidence", "error_code", "started_at", "completed_at"] as const;
  const record = exactRecord(value, ["id", "version", "state", "target_environment", "attempt", "manifest", "created_at"], optional);
  productID(record.id); boundedInteger(record.version, 1, 1_000_000); enumValue(record.state, ["queued", "verifying", "provisioning", "validating", "rebuilding", "cleanup_required", "cleaning", "succeeded", "retryable", "failed", "failed_cleanup"]); recoveryTarget(record.target_environment, expectedScope); boundedInteger(record.attempt, 0, 100); decodeRecoveryManifestLocator(record.manifest, expectedScope); dateTime(record.created_at);
  const started = optionalRecoveryTime(record.started_at); const completed = optionalRecoveryTime(record.completed_at); recoveryTimeOrder(record.created_at as string, started, completed);
  const observed = record.observed_counts === undefined ? undefined : decodeRecoveryCounts(record.observed_counts);
  const validation = record.validation_evidence === undefined ? undefined : decodeRecoveryValidationEvidence(record.validation_evidence, expectedScope);
  const cleanup = record.cleanup_evidence === undefined ? undefined : decodeRecoveryCleanupEvidence(record.cleanup_evidence, expectedScope);
  if (record.error_code !== undefined) enumValue(record.error_code, RECOVERY_ERROR_CODES);
  if (record.state === "queued") {
    if (record.attempt !== 0 || started !== undefined || completed !== undefined || observed !== undefined || validation !== undefined || cleanup !== undefined || record.error_code !== undefined) fail();
  } else if (["verifying", "provisioning", "validating", "rebuilding"].includes(record.state as string)) {
    if ((record.attempt as number) < 1 || started === undefined || completed !== undefined || observed !== undefined || cleanup !== undefined || record.error_code !== undefined) fail();
  } else if (record.state === "cleanup_required" || record.state === "cleaning") {
    if ((record.attempt as number) < 1 || started === undefined || completed !== undefined) fail();
  } else if (record.state === "retryable") {
    if ((record.attempt as number) < 1 || started === undefined || completed !== undefined || record.error_code === undefined) fail();
  } else if (record.state === "succeeded") {
    if ((record.attempt as number) < 1 || started === undefined || completed === undefined || record.error_code !== undefined || observed === undefined || validation === undefined || cleanup?.state !== "deleted" || !sameRecoveryCounts(observed, validation.observed_counts)) fail();
  } else if (record.state === "failed_cleanup") {
    if ((record.attempt as number) < 1 || started === undefined || completed === undefined || record.error_code === undefined || cleanup?.state !== "failed") fail();
  } else if (completed === undefined || record.error_code === undefined || !((record.attempt as number) >= 1 && started !== undefined || record.attempt === 0 && started === undefined && record.error_code === "exhausted" && observed === undefined && validation === undefined && cleanup === undefined)) {
    fail();
  }
  return value as RecoveryRestore;
}

function decodeRecoveryManifestLocator(value: unknown, expectedScope: string): void {
  const record = exactRecord(value, ["reference", "version_id", "sha256", "size_bytes", "media_type", "schema", "signing_key_id", "signature"]);
  decodeRecoveryArtifactFields(record, expectedScope);
  if (record.media_type !== "application/vnd.zasp.recovery-manifest+json" || record.schema !== "recovery_signed_manifest_v1" || typeof record.signing_key_id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(record.signing_key_id) || typeof record.signature !== "string" || record.signature.length < 43 || record.signature.length > 684 || record.signature.length % 4 === 1 || !/^[A-Za-z0-9+/]+$/.test(record.signature)) fail();
}

function decodeRecoveryArtifactLocator(value: unknown, expectedScope: string): void {
  decodeRecoveryArtifactFields(exactRecord(value, ["reference", "version_id", "sha256", "size_bytes", "media_type", "schema"]), expectedScope);
}

function decodeRecoveryArtifactFields(record: Record<string, unknown>, expectedScope: string): void {
  const [organizationID, workspaceID, environmentID, ...rest] = expectedScope.split("/");
  if (rest.length !== 0) fail(); productID(organizationID); productID(workspaceID); productID(environmentID);
  const prefix = `organizations/${organizationID}/workspaces/${workspaceID}/environments/${environmentID}/artifacts/`;
  if (typeof record.reference !== "string") fail();
  const match = /^s3:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\/(.+)$/.exec(record.reference);
  if (!match || !match[2].startsWith(prefix) || match[2].slice(prefix.length).includes("/")) fail(); productID(match[2]?.slice(prefix.length));
  printableString(record.version_id, 1, 1024); if (!/^[A-Za-z0-9._~+/=-]+$/.test(record.version_id)) fail();
  if (typeof record.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(record.sha256) || /^0{64}$/.test(record.sha256)) fail();
  boundedInteger(record.size_bytes, 1, 64 << 20); if (typeof record.media_type !== "string" || !/^[a-z0-9][a-z0-9.+-]{0,63}\/[a-z0-9][a-z0-9.+-]{0,127}$/.test(record.media_type)) fail(); if (typeof record.schema !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(record.schema)) fail();
}

function decodeRecoveryCounts(value: unknown): RecoveryCounts {
  const record = exactRecord(value, ["assets", "findings", "policies"]); for (const key of ["assets", "findings", "policies"] as const) boundedInteger(record[key], 0, 1_000_000_000); return value as RecoveryCounts;
}

function decodeRecoveryValidationEvidence(value: unknown, expectedScope: string): { state: "validated"; expected_counts: RecoveryCounts; observed_counts: RecoveryCounts } {
  const record = exactRecord(value, ["state", "expected_counts", "observed_counts", "evidence"]); if (record.state !== "validated") fail(); const expected = decodeRecoveryCounts(record.expected_counts); const observed = decodeRecoveryCounts(record.observed_counts); if (!sameRecoveryCounts(expected, observed)) fail(); decodeRecoveryArtifactLocator(record.evidence, expectedScope); return { state: "validated", expected_counts: expected, observed_counts: observed };
}

function decodeRecoveryCleanupEvidence(value: unknown, expectedScope: string): { state: "deleted" | "failed" } {
  const record = exactRecord(value, ["state", "evidence"]); enumValue(record.state, ["deleted", "failed"]); decodeRecoveryArtifactLocator(record.evidence, expectedScope); return { state: record.state as "deleted" | "failed" };
}

function sameRecoveryCounts(left: RecoveryCounts, right: RecoveryCounts): boolean { return left.assets === right.assets && left.findings === right.findings && left.policies === right.policies; }
function optionalRecoveryTime(value: unknown): string | undefined { if (value === undefined) return undefined; dateTime(value); return value; }
function recoveryTimeOrder(created: string, started?: string, completed?: string): void { if (started !== undefined && Date.parse(started) < Date.parse(created) || completed !== undefined && (Date.parse(completed) < Date.parse(created) || started !== undefined && Date.parse(completed) < Date.parse(started))) fail(); }
function recoveryTarget(value: unknown, expectedScope: string): void { printableString(value, 1, 63); if (!/^[a-z][a-z0-9-]{0,62}$/.test(value) || value === "production" || value === expectedScope.split("/")[2]) fail(); }

export function decodeSecurityAgentDefinition(value: unknown): SecurityAgentDefinition { const record = exactRecord(value, ["id", "name", "trigger_kind", "trigger_source", "environment_ids", "autonomy", "max_steps", "max_duration_seconds", "temporary_policy_seconds", "ai_token_budget", "concurrency_limit", "allowed_actions", "verification_kind", "definition_version", "enabled"]); productID(record.id); boundedString(record.name, 1, 256); enumValue(record.trigger_kind, ["finding", "attack_path", "runtime_decision"]); boundedString(record.trigger_source, 1, 64); productIDArray(record.environment_ids, 100); enumValue(record.autonomy, ["supervised", "autonomous"]); boundedInteger(record.max_steps, 1, 100); boundedInteger(record.max_duration_seconds, 1, 86400); boundedInteger(record.temporary_policy_seconds, 1, 86400); boundedInteger(record.ai_token_budget, 1, 12000); boundedInteger(record.concurrency_limit, 1, 10); positiveInteger(record.definition_version); stringArray(record.allowed_actions, 32, 128, 1); boundedString(record.verification_kind, 1, 64); if (typeof record.enabled !== "boolean") fail(); return value as SecurityAgentDefinition; }
export function decodeSecurityAgentPage(value: unknown): SecurityAgentPage { const record = exactRecord(value, ["items", "page_info"]); for (const item of array(record.items, 100)) decodeSecurityAgentDefinition(item); decodePageInfo(record.page_info); return value as SecurityAgentPage; }
export function decodeSecurityAgentTemplate(value: unknown): SecurityAgentTemplate { const record = exactRecord(value, ["id", "name", "version", "trigger_kind", "default_actions", "verification_condition"]); productID(record.id); boundedString(record.name, 1, 256); positiveInteger(record.version); enumValue(record.trigger_kind, ["finding", "attack_path", "runtime_decision"]); stringArray(record.default_actions, 32, 128, 1); boundedString(record.verification_condition, 1, 256); return value as SecurityAgentTemplate; }
export function decodeSecurityAgentTemplatePage(value: unknown): { readonly items: readonly SecurityAgentTemplate[] } { const record = exactRecord(value, ["items"]); for (const item of array(record.items, 20)) decodeSecurityAgentTemplate(item); return value as { readonly items: readonly SecurityAgentTemplate[] }; }
export function decodeSecurityAction(value: unknown): SecurityAction { const record = exactRecord(value, ["key", "risk_class", "target_types", "approval_floor", "reversible", "verification_kind"]); boundedString(record.key, 1, 128); enumValue(record.risk_class, ["low", "moderate", "containment", "destructive"]); stringArray(record.target_types, 32, 64, 1); enumValue(record.approval_floor, ["none", "operator", "admin"]); if (typeof record.reversible !== "boolean") fail(); boundedString(record.verification_kind, 1, 64); return value as SecurityAction; }
export function decodeSecurityActionPage(value: unknown): SecurityActionPage { const record = exactRecord(value, ["items"]); const items = array(record.items, 100); let prior = ""; for (const item of items) { const decoded = decodeSecurityAction(item); if (decoded.key <= prior) fail(); prior = decoded.key; } return value as SecurityActionPage; }
export function decodeSecurityAgentActivationState(value: unknown): SecurityAgentActivationState { const record = exactRecord(value, ["id", "activation", "enabled", "version"]); productID(record.id); enumValue(record.activation, ["draft", "validated", "supervised", "autonomous"]); if (typeof record.enabled !== "boolean" || record.enabled !== (record.activation === "supervised" || record.activation === "autonomous")) fail(); positiveInteger(record.version); return value as SecurityAgentActivationState; }
function decodeSecurityAgentExecutionControl(value: unknown, target: "global" | "environment" | "action", actionKey: "*" | "create_temporary_policy" | "isolate_session" | "revoke_integration_connection" | "update_finding_response", allowZero: boolean): SecurityAgentExecutionControl { const record = exactRecord(value, ["target", "action_key", "enabled", "version"]); if (record.target !== target || record.action_key !== actionKey || typeof record.enabled !== "boolean") fail(); boundedInteger(record.version, allowZero ? 0 : 1, 1000000); return value as SecurityAgentExecutionControl; }
export function decodeSecurityAgentExecutionControls(value: unknown): SecurityAgentExecutionControls { const record = exactRecord(value, ["global", "environment", "actions"]); decodeSecurityAgentExecutionControl(record.global, "global", "*", false); decodeSecurityAgentExecutionControl(record.environment, "environment", "*", true); const actions = array(record.actions, 4); if (actions.length !== 4) fail(); decodeSecurityAgentExecutionControl(actions[0], "action", "create_temporary_policy", true); decodeSecurityAgentExecutionControl(actions[1], "action", "isolate_session", true); decodeSecurityAgentExecutionControl(actions[2], "action", "revoke_integration_connection", true); decodeSecurityAgentExecutionControl(actions[3], "action", "update_finding_response", true); return value as SecurityAgentExecutionControls; }
export function decodeSecurityAgentExecutionControlResult(value: unknown): SecurityAgentExecutionControlResult { const record = exactRecord(value, ["target", "action_key", "enabled", "version", "audit_id", "correlation_id", "receipt_id", "replayed"]); if (record.target === "environment" && record.action_key !== "*" || record.target === "action" && record.action_key !== "create_temporary_policy" && record.action_key !== "isolate_session" && record.action_key !== "revoke_integration_connection" && record.action_key !== "update_finding_response" || record.target !== "environment" && record.target !== "action" || typeof record.enabled !== "boolean") fail(); boundedInteger(record.version, 1, 1000000); productID(record.audit_id); productID(record.correlation_id); productID(record.receipt_id); if (typeof record.replayed !== "boolean" || record.audit_id === record.correlation_id || record.audit_id === record.receipt_id || record.correlation_id === record.receipt_id) fail(); return value as SecurityAgentExecutionControlResult; }
export function decodeSecurityAgentSimulation(value: unknown): SecurityAgentSimulation { const record = exactRecord(value, ["run_id", "definition_id", "definition_version", "plan_hash", "catalog_version", "expires_at", "matched_evidence_ids", "summary", "steps", "side_effects", "version"]); productID(record.run_id); productID(record.definition_id); positiveInteger(record.definition_version); checksum(record.plan_hash); if (record.catalog_version !== "security-agent-actions-v1") fail(); dateTime(record.expires_at); productIDArray(record.matched_evidence_ids, 100); boundedString(record.summary, 1, 500); const steps = array(record.steps, 100); if (steps.length < 1) fail(); steps.forEach((step, index) => { const entry = exactRecord(step, ["index", "action", "authorization", "approval_required"]); if (entry.index !== index) fail(); boundedString(entry.action, 1, 128); enumValue(entry.authorization, ["allow", "approval_required", "deny"]); if (typeof entry.approval_required !== "boolean" || entry.approval_required !== (entry.authorization === "approval_required")) fail(); }); if (record.side_effects !== 0 || record.version !== 1) fail(); return value as SecurityAgentSimulation; }
export function decodeSecurityAgentRun(value: unknown): SecurityAgentRun { const record = exactRecord(value, ["id", "agent_id", "state", "evidence_ids", "definition_version", "version"]); productID(record.id); productID(record.agent_id); enumValue(record.state, ["queued", "planning", "waiting_approval", "running", "verifying", "contained", "remediated", "needs_human", "failed", "inconclusive", "cancelled"]); productIDArray(record.evidence_ids, 100); positiveInteger(record.definition_version); positiveInteger(record.version); return value as SecurityAgentRun; }
export function decodeSecurityAgentRunPage(value: unknown): SecurityAgentRunPage { const record = exactRecord(value, ["items"], ["next_cursor"]); for (const item of array(record.items, 100)) decodeSecurityAgentRun(item); optionalCursor(record.next_cursor); return value as SecurityAgentRunPage; }
export function decodeSecurityAgentApproval(value: unknown): SecurityAgentApproval {
  const record = exactRecord(value, ["id", "run_id", "step_id", "state", "expires_at", "version", "expected_effect", "reversible", "ttl_seconds", "evidence_summary"]);
  productID(record.id); productID(record.run_id); productID(record.step_id); enumValue(record.state, ["pending", "approved", "rejected", "cancelled", "expired"]); dateTime(record.expires_at); positiveInteger(record.version);
  printableString(record.expected_effect, 1, 128); const validEffect = record.expected_effect === "Move finding to under review" && record.ttl_seconds === 0 && record.reversible === true || record.expected_effect === "Apply temporary containment policy" && Number.isInteger(record.ttl_seconds) && (record.ttl_seconds as number) >= 60 && (record.ttl_seconds as number) <= 3600 && record.reversible === true || record.expected_effect === "Isolate runtime session" && Number.isInteger(record.ttl_seconds) && (record.ttl_seconds as number) >= 60 && (record.ttl_seconds as number) <= 3600 && record.reversible === true || record.expected_effect === "Revoke integration connection" && record.ttl_seconds === 0 && record.reversible === false; if (!validEffect) fail(); productIDArray(record.evidence_summary, 100);
  return value as SecurityAgentApproval;
}
export function decodeSecurityAgentApprovalPage(value: unknown): SecurityAgentApprovalPage { const record = exactRecord(value, ["items"], ["next_cursor"]); for (const item of array(record.items, 100)) decodeSecurityAgentApproval(item); optionalCursor(record.next_cursor); return value as SecurityAgentApprovalPage; }
export function decodeSecurityAgentRunDetail(value: unknown): SecurityAgentRunDetail {
  const record = exactRecord(value, ["run", "evidence_ids", "plan", "authorization", "approvals", "execution", "verification"]);
  const run = decodeSecurityAgentRun(record.run); productIDArray(record.evidence_ids, 100); if (!sameJSON(run.evidence_ids, record.evidence_ids)) fail();
  enumValue(record.authorization, ["not_planned", "authorized", "approval_required", "approved", "denied", "cancelled"]);
  enumValue(record.verification, ["not_started", "pending", "verified", "failed", "inconclusive"]);
  const expectedVerification = run.state === "contained" || run.state === "remediated" ? "verified" : run.state === "verifying" ? "pending" : run.state === "failed" ? "failed" : run.state === "inconclusive" || run.state === "needs_human" ? "inconclusive" : "not_started";
  if (record.verification !== expectedVerification) fail();
  const approvals = array(record.approvals, 100); const approvalIDs = new Set<string>();
  for (const item of approvals) { const approval = decodeSecurityAgentApproval(item); if (approval.run_id !== run.id || approvalIDs.has(approval.id) || !sameJSON(approval.evidence_summary, record.evidence_ids)) fail(); approvalIDs.add(approval.id); }
  if (record.plan === null) { if (record.authorization !== "not_planned" || approvals.length !== 0 || array(record.execution, 100).length !== 0) fail(); return value as SecurityAgentRunDetail; }
  const plan = exactRecord(record.plan, ["plan_hash", "catalog_version", "expires_at", "steps"]); checksum(plan.plan_hash); if (plan.catalog_version !== "security-agent-actions-v1") fail(); dateTime(plan.expires_at);
  const steps = array(plan.steps, 100); if (steps.length < 1) fail(); const stepIDs = new Set<string>(); const stepValues = new Map<string, { action: string; authorization: string }>();
  for (let index = 0; index < steps.length; index++) { const step = exactRecord(steps[index], ["id", "index", "action", "authorization", "state", "version"]); productID(step.id); if (step.index !== index || stepIDs.has(step.id as string)) fail(); printableString(step.action, 1, 128); enumValue(step.authorization, ["allow", "approval_required", "autonomous", "deny"]); enumValue(step.state, ["queued", "authorized", "waiting_approval", "executing", "verifying", "succeeded", "failed", "inconclusive", "cancelled"]); positiveInteger(step.version); stepIDs.add(step.id as string); stepValues.set(step.id as string, { action: step.action as string, authorization: step.authorization as string }); }
  for (const item of approvals) { const approval = item as SecurityAgentApproval; const step = stepValues.get(approval.step_id); const validEffect = step?.action === "update_finding_response" && approval.expected_effect === "Move finding to under review" && approval.ttl_seconds === 0 && approval.reversible || step?.action === "create_temporary_policy" && approval.expected_effect === "Apply temporary containment policy" && approval.ttl_seconds >= 60 && approval.ttl_seconds <= 3600 && approval.reversible || step?.action === "isolate_session" && approval.expected_effect === "Isolate runtime session" && approval.ttl_seconds >= 60 && approval.ttl_seconds <= 3600 && approval.reversible || step?.action === "revoke_integration_connection" && approval.expected_effect === "Revoke integration connection" && approval.ttl_seconds === 0 && !approval.reversible; if (!step || step.authorization !== "approval_required" || !validEffect) fail(); }
  const execution = array(record.execution, 100); if (execution.length !== steps.length) fail(); const executionIDs = new Set<string>();
  for (let index = 0; index < execution.length; index++) { const item = exactRecord(execution[index], ["step_id", "action", "state", "version"], ["outcome_id", "result_digest"]); productID(item.step_id); printableString(item.action, 1, 128); enumValue(item.state, ["queued", "authorized", "waiting_approval", "executing", "verifying", "succeeded", "failed", "inconclusive", "cancelled"]); positiveInteger(item.version); const step = stepValues.get(item.step_id as string); if (!step || executionIDs.has(item.step_id as string) || item.action !== step.action || item.step_id !== (steps[index] as Record<string, unknown>).id) fail(); executionIDs.add(item.step_id as string); const hasOutcome = item.outcome_id !== undefined; const hasDigest = item.result_digest !== undefined; if (hasOutcome !== hasDigest) fail(); if (hasOutcome) { productID(item.outcome_id); checksum(item.result_digest); } }
  const approvalStates = approvals.map((item) => (item as SecurityAgentApproval).state); const expectedAuthorization = approvalStates.includes("pending") ? "approval_required" : approvalStates.some((state) => state === "rejected" || state === "expired") ? "denied" : approvalStates.includes("cancelled") ? "cancelled" : approvalStates.includes("approved") ? "approved" : "authorized";
  if (record.authorization !== expectedAuthorization) fail();
  return value as SecurityAgentRunDetail;
}

const redTeamCategories = ["prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information"] as const;
const redTeamRetryErrors = ["retryable", "rate_limited", "denied", "malformed", "outcome_unknown"] as const;

export function decodeTestDefinition(value: unknown): TestDefinition {
  const record = exactRecord(value, ["id", "version", "name", "target_id", "target_kind", "categories", "safety", "enabled", "created_at", "updated_at"]);
  productID(record.id); positiveInteger(record.version); if ((record.version as number) > 1_000_000) fail(); printableString(record.name, 1, 128); productID(record.target_id); enumValue(record.target_kind, ["agent_endpoint", "mcp_server", "coding_agent"]); if (typeof record.enabled !== "boolean") fail(); dateTime(record.created_at); dateTime(record.updated_at); if (Date.parse(record.updated_at as string) < Date.parse(record.created_at as string)) fail();
  const categories = array(record.categories, 16); if (categories.length < 1) fail(); const uniqueCategories = new Set<string>(); for (const category of categories) { enumValue(category, redTeamCategories); if (uniqueCategories.has(category as string)) fail(); uniqueCategories.add(category as string); }
  const safety = exactRecord(record.safety, ["environment", "credential_class", "expected_side_effects"]); enumValue(safety.environment, ["development", "test", "staging"]); enumValue(safety.credential_class, ["read_only", "test_write"]); const effects = array(safety.expected_side_effects, 16); if (effects.length < 1) fail(); const uniqueEffects = new Set<string>(); for (const effect of effects) { printableString(effect, 1, 256); if (uniqueEffects.has(effect as string)) fail(); uniqueEffects.add(effect as string); }
  return value as TestDefinition;
}

export function decodeTestDefinitionPage(value: unknown): TestDefinitionPage {
  const record = exactRecord(value, ["items"], ["next_cursor"]); const items = array(record.items, 100); let prior = "";
  for (const item of items) { const definition = decodeTestDefinition(item); if (prior !== "" && definition.id <= prior) fail(); prior = definition.id; }
  redTeamCursor(record.next_cursor, 512); if (record.next_cursor !== undefined && items.length === 0) fail();
  return value as TestDefinitionPage;
}

export function decodeTestRun(value: unknown): TestRun {
  const record = exactRecord(value, ["id", "version", "definition_id", "definition_version", "status", "attempt", "cancel_requested", "queued_at"], ["started_at", "completed_at", "verdict", "error_code", "evidence_reference"]);
  productID(record.id); positiveInteger(record.version); if ((record.version as number) > 1_000_000) fail(); productID(record.definition_id); positiveInteger(record.definition_version); if ((record.definition_version as number) > 1_000_000) fail(); enumValue(record.status, ["queued", "leased", "retryable", "complete", "failed", "cancelled"]); boundedInteger(record.attempt, 0, 5); if (typeof record.cancel_requested !== "boolean") fail(); dateTime(record.queued_at);
  if (record.started_at !== undefined) { dateTime(record.started_at); if (Date.parse(record.started_at) < Date.parse(record.queued_at as string)) fail(); }
  if (record.completed_at !== undefined) { dateTime(record.completed_at); if (Date.parse(record.completed_at) < Date.parse((record.started_at ?? record.queued_at) as string)) fail(); }
  if (record.verdict !== undefined) enumValue(record.verdict, ["pass", "fail", "engine_error"]); if (record.error_code !== undefined) enumValue(record.error_code, [...redTeamRetryErrors, "cancelled", "exhausted"]); if (record.evidence_reference !== undefined) printableString(record.evidence_reference, 1, 1024);
  const attempt = record.attempt as number; const hasStarted = record.started_at !== undefined; const hasCompleted = record.completed_at !== undefined; const hasVerdict = record.verdict !== undefined; const hasError = record.error_code !== undefined; const hasEvidence = record.evidence_reference !== undefined;
  const coherent = record.status === "queued" ? attempt === 0 && !record.cancel_requested && !hasStarted && !hasCompleted && !hasVerdict && !hasError && !hasEvidence
    : record.status === "leased" ? attempt >= 1 && hasStarted && !hasCompleted && !hasVerdict && !hasError && !hasEvidence
      : record.status === "retryable" ? attempt >= 1 && attempt < 5 && !record.cancel_requested && hasStarted && !hasCompleted && !hasVerdict && hasError && redTeamRetryErrors.includes(record.error_code as typeof redTeamRetryErrors[number]) && !hasEvidence
        : record.status === "complete" ? attempt >= 1 && !record.cancel_requested && hasStarted && hasCompleted && hasVerdict && hasEvidence && (record.verdict === "engine_error" ? hasError && ["denied", "malformed", "outcome_unknown", "exhausted"].includes(record.error_code as string) : !hasError)
          : record.status === "failed" ? attempt === 5 && !record.cancel_requested && hasStarted && hasCompleted && !hasVerdict && record.error_code === "exhausted" && !hasEvidence
            : record.status === "cancelled" && record.cancel_requested && hasCompleted && !hasVerdict && record.error_code === "cancelled" && !hasEvidence && (attempt === 0 ? !hasStarted : hasStarted);
  if (!coherent) fail();
  return value as TestRun;
}

export function decodeTestAttempt(value: unknown): TestAttempt {
  const record = exactRecord(value, ["attempt", "verdict", "objective", "behavior", "evidence", "evidence_reference", "completed_at"], ["error_code", "input_artifact"]); boundedInteger(record.attempt, 1, 5); enumValue(record.verdict, ["pass", "fail", "engine_error"]); printableString(record.objective, 1, 512); printableString(record.behavior, 1, 2048); printableString(record.evidence_reference, 1, 1024); dateTime(record.completed_at); const evidence = array(record.evidence, 64); for (const item of evidence) printableString(item, 1, 512);
  if (record.input_artifact !== undefined) {
    const input = exactRecord(record.input_artifact, ["reference", "version_id", "sha256", "size_bytes"]);
    printableString(input.reference, 8, 1024); printableString(input.version_id, 1, 512); boundedInteger(input.size_bytes, 1, 65536);
    if (/\s/u.test(input.version_id as string) || typeof input.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(input.sha256) || /^0{64}$/.test(input.sha256)) fail();
    const parts = (input.reference as string).split("/");
    if (parts.length !== 11 || parts[0] !== "s3:" || parts[1] !== "" || !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(parts[2]) || /\.\.|\.-|-\./.test(parts[2]) || parts[3] !== "organizations" || parts[5] !== "workspaces" || parts[7] !== "environments" || parts[9] !== "artifacts") fail();
    for (const index of [4, 6, 8, 10]) productID(parts[index]);
    const evidenceParts = (record.evidence_reference as string).split("/");
    if (evidenceParts.length !== 11 || parts.slice(3, 10).join("/") !== evidenceParts.slice(3, 10).join("/") || input.reference === record.evidence_reference) fail();
  }
  if (record.verdict === "engine_error") { enumValue(record.error_code, ["denied", "malformed", "outcome_unknown", "exhausted"]); if (evidence.length !== 1) fail(); } else if (record.error_code !== undefined || evidence.length < 1) fail();
  return value as TestAttempt;
}

export function decodeTestRunDetail(value: unknown): TestRunDetail {
  const record = exactRecord(value, ["id", "version", "definition_id", "definition_version", "status", "attempt", "cancel_requested", "queued_at", "attempts"], ["started_at", "completed_at", "verdict", "error_code", "evidence_reference"]); const { attempts: attemptValues, ...runValue } = record; const run = decodeTestRun(runValue); const attempts = array(attemptValues, 5); let prior = 0;
  let finalAttempt: TestAttempt | undefined;
  for (const item of attempts) { const attempt = decodeTestAttempt(item); if (attempt.attempt <= prior || attempt.attempt > run.attempt || attempt.evidence_reference !== run.evidence_reference) fail(); prior = attempt.attempt; finalAttempt = attempt; }
  if (run.status === "complete" ? attempts.length !== 1 || finalAttempt?.attempt !== run.attempt || finalAttempt.verdict !== run.verdict || finalAttempt.completed_at !== run.completed_at : attempts.length !== 0) fail();
  return value as TestRunDetail;
}

export function decodeTestRunPage(value: unknown): TestRunPage {
  const record = exactRecord(value, ["items"], ["next_cursor"]); const items = array(record.items, 100); let prior: TestRun | undefined;
  for (const item of items) { const run = decodeTestRun(item); if (prior && (run.queued_at > prior.queued_at || run.queued_at === prior.queued_at && run.id >= prior.id)) fail(); prior = run; }
  redTeamCursor(record.next_cursor, 1024); if (record.next_cursor !== undefined && items.length === 0) fail();
  return value as TestRunPage;
}

export function decodeAttackLabPreflight(value: unknown): AttackLabPreflight {
  const record = exactRecord(value, ["source_run_id", "definition_id", "definition_version", "target_id", "target_kind", "environment", "credential_class", "destination", "allowed_destinations", "success_criterion", "expected_side_effects", "decision_digest", "decision_expires_at", "limits"]);
  productID(record.source_run_id); productID(record.definition_id); boundedInteger(record.definition_version, 1, 1_000_000); productID(record.target_id);
  enumValue(record.target_kind, ["agent_endpoint", "mcp_server", "coding_agent"]); enumValue(record.environment, ["development", "test", "staging"]); enumValue(record.credential_class, ["read_only", "test_write"]); attackLabDestination(record.destination);
  const destinations = array(record.allowed_destinations, 1); if (destinations.length !== 1 || destinations[0] !== record.destination) fail(); attackLabDestination(destinations[0]);
  printableString(record.success_criterion, 1, 512); const effects = array(record.expected_side_effects, 16); if (effects.length < 1) fail(); const seen = new Set<string>(); for (const effect of effects) { printableString(effect, 1, 256); if (seen.has(effect as string)) fail(); seen.add(effect as string); }
  attackLabDigest(record.decision_digest); dateTime(record.decision_expires_at);
  decodeAttackLabLimits(record.limits);
  return value as AttackLabPreflight;
}

export function decodeAttackLabRun(value: unknown): AttackLabRun {
  const record = exactRecord(value, ["id", "version", "source_run_id", "definition_id", "definition_version", "target_id", "target_kind", "environment", "credential_class", "destination", "status", "attempt", "cancel_requested", "cleanup_state", "limits", "queued_at"], ["started_at", "attempt_started_at", "completed_at", "verdict", "error_code", "evidence_reference", "evidence_version_id", "evidence_checksum", "evidence_size"]);
  productID(record.id); boundedInteger(record.version, 1, 1_000_000); productID(record.source_run_id); productID(record.definition_id); boundedInteger(record.definition_version, 1, 1_000_000); productID(record.target_id);
  enumValue(record.target_kind, ["agent_endpoint", "mcp_server", "coding_agent"]); enumValue(record.environment, ["development", "test", "staging"]); enumValue(record.credential_class, ["read_only", "test_write"]); attackLabDestination(record.destination); enumValue(record.status, ["queued", "leased", "running", "retryable", "cleanup", "complete", "failed", "cancelled"]); boundedInteger(record.attempt, 0, 5); if (typeof record.cancel_requested !== "boolean") fail(); enumValue(record.cleanup_state, ["pending", "in_progress", "complete", "failed"]); decodeAttackLabLimits(record.limits); dateTime(record.queued_at);
  if (record.started_at !== undefined) { dateTime(record.started_at); if (Date.parse(record.started_at) < Date.parse(record.queued_at as string)) fail(); }
  if (record.attempt_started_at !== undefined) { dateTime(record.attempt_started_at); if (record.started_at === undefined || Date.parse(record.attempt_started_at) < Date.parse(record.started_at)) fail(); }
  if (((record.attempt as number) === 0) !== (record.attempt_started_at === undefined)) fail();
  if (record.completed_at !== undefined) { dateTime(record.completed_at); if (Date.parse(record.completed_at) < Date.parse(record.queued_at as string) || record.started_at !== undefined && Date.parse(record.completed_at) < Date.parse(record.started_at) || record.attempt_started_at !== undefined && Date.parse(record.completed_at) < Date.parse(record.attempt_started_at)) fail(); }
  if (record.verdict !== undefined) enumValue(record.verdict, ["verified", "not_reproduced", "inconclusive"]); if (record.error_code !== undefined) enumValue(record.error_code, ["retryable", "denied", "malformed", "outcome_unknown", "cleanup_failed", "cancelled", "exhausted"]); attackLabEvidenceLocator(record);
  const attempt = record.attempt as number; const started = record.started_at !== undefined; const completed = record.completed_at !== undefined; const verdict = record.verdict !== undefined; const failure = record.error_code !== undefined; const evidence = record.evidence_reference !== undefined;
  const coherent = record.status === "queued" ? attempt === 0 && !record.cancel_requested && record.cleanup_state === "pending" && !started && !completed && !verdict && !failure && !evidence
    : record.status === "leased" || record.status === "running" ? attempt >= 1 && record.cleanup_state === "pending" && started && !completed && !verdict && !failure && !evidence
      : record.status === "retryable" ? attempt >= 1 && attempt < 5 && !record.cancel_requested && record.cleanup_state === "pending" && started && !completed && !verdict && ["retryable", "outcome_unknown"].includes(record.error_code as string) && !evidence
        : record.status === "cleanup" ? attempt >= 1 && record.cleanup_state === "in_progress" && started && !completed && !verdict && !failure && !evidence
          : record.status === "complete" ? attempt >= 1 && !record.cancel_requested && record.cleanup_state === "complete" && started && completed && verdict && ["verified", "not_reproduced", "inconclusive"].includes(record.verdict as string) && (evidence && !failure || !evidence && record.verdict === "inconclusive" && record.error_code === "outcome_unknown")
            : record.status === "failed" ? attempt >= 1 && started && completed && !verdict && ["denied", "malformed", "outcome_unknown", "cleanup_failed", "exhausted"].includes(record.error_code as string) && !evidence && (record.error_code === "cleanup_failed" ? record.cleanup_state === "failed" : record.cleanup_state === "complete")
              : record.status === "cancelled" && record.cancel_requested && record.cleanup_state === "complete" && completed && !verdict && record.error_code === "cancelled" && (attempt === 0 ? !started && !evidence : started);
  if (!coherent) fail();
  return value as AttackLabRun;
}

export function decodeAttackLabAttempt(value: unknown): AttackLabAttempt {
  const record = exactRecord(value, ["attempt", "evidence_state", "criterion_observed", "canary_touched", "cleanup_completed", "evidence", "completed_at"], ["verdict", "error_code", "evidence_reference", "evidence_version_id", "evidence_checksum", "evidence_size"]);
  boundedInteger(record.attempt, 1, 5); enumValue(record.evidence_state, ["complete", "unavailable"]); if (typeof record.criterion_observed !== "boolean" || typeof record.canary_touched !== "boolean" || record.cleanup_completed !== true) fail(); dateTime(record.completed_at);
  if (record.verdict !== undefined) enumValue(record.verdict, ["verified", "not_reproduced", "inconclusive"]); if (record.error_code !== undefined) enumValue(record.error_code, ["retryable", "denied", "malformed", "outcome_unknown", "cleanup_failed", "cancelled", "exhausted"]); attackLabEvidenceLocator(record);
  if (record.verdict === "verified" && (!record.criterion_observed || !record.canary_touched) || record.verdict === "not_reproduced" && (record.criterion_observed || record.canary_touched)) fail();
  const evidence = array(record.evidence, 5);
  if (record.evidence_state === "unavailable") {
    if (evidence.length !== 0 || record.evidence_reference !== undefined || record.evidence_version_id !== undefined || record.evidence_checksum !== undefined || record.evidence_size !== undefined || record.criterion_observed || record.canary_touched || !(record.verdict === "inconclusive" && record.error_code === "outcome_unknown" || record.verdict === undefined && record.error_code === "cancelled")) fail();
    return value as AttackLabAttempt;
  }
  if (evidence.length !== 5 || record.evidence_reference === undefined || !(["verified", "not_reproduced", "inconclusive"].includes(record.verdict as string) || record.verdict === undefined && record.error_code === "cancelled")) fail();
  const prefixes = ["semantic:", "gateway:", "egress:", "kubernetes:", "cloud:"] as const;
  for (let index = 0; index < evidence.length; index += 1) { const item = evidence[index]; printableString(item, 1, 512); if (!(item as string).startsWith(prefixes[index]) || (item as string).length === prefixes[index].length) fail(); }
  if (!(record.error_code === undefined || record.verdict === "inconclusive" && ["denied", "malformed", "outcome_unknown", "cleanup_failed", "exhausted", "cancelled"].includes(record.error_code as string) || record.verdict === undefined && record.error_code === "cancelled")) fail();
  return value as AttackLabAttempt;
}

export function decodeAttackLabRunDetail(value: unknown): AttackLabRunDetail {
  const record = exactRecord(value, ["id", "version", "source_run_id", "definition_id", "definition_version", "target_id", "target_kind", "environment", "credential_class", "destination", "status", "attempt", "cancel_requested", "cleanup_state", "limits", "queued_at", "attempts"], ["started_at", "attempt_started_at", "completed_at", "verdict", "error_code", "evidence_reference", "evidence_version_id", "evidence_checksum", "evidence_size"]);
  const { attempts: attemptValues, ...runValue } = record; const run = decodeAttackLabRun(runValue); const attempts = array(attemptValues, 5); let prior = 0; let finalAttempt: AttackLabAttempt | undefined;
  for (const item of attempts) { const attempt = decodeAttackLabAttempt(item); if (attempt.attempt <= prior || attempt.attempt > run.attempt || attempt.evidence_reference !== run.evidence_reference || attempt.evidence_version_id !== run.evidence_version_id || attempt.evidence_checksum !== run.evidence_checksum || attempt.evidence_size !== run.evidence_size) fail(); prior = attempt.attempt; finalAttempt = attempt; }
  if (run.status === "complete") {
    if (attempts.length !== 1 || finalAttempt?.attempt !== run.attempt || finalAttempt.verdict !== run.verdict || finalAttempt.completed_at !== run.completed_at) fail();
  } else if (run.status === "cancelled" && run.attempt >= 1) {
    if (attempts.length !== 1 || finalAttempt?.attempt !== run.attempt || finalAttempt.verdict !== undefined || finalAttempt.error_code !== "cancelled" || finalAttempt.completed_at !== run.completed_at) fail();
  } else if (attempts.length !== 0) fail();
  return value as AttackLabRunDetail;
}

export function decodeAttackLabRunPage(value: unknown): AttackLabRunPage {
  const record = exactRecord(value, ["items"], ["next_cursor"]); const items = array(record.items, 100); let prior: AttackLabRun | undefined;
  for (const item of items) { const run = decodeAttackLabRun(item); if (prior && (run.queued_at > prior.queued_at || run.queued_at === prior.queued_at && run.id >= prior.id)) fail(); prior = run; }
  redTeamCursor(record.next_cursor, 1024); if (record.next_cursor !== undefined && items.length === 0) fail();
  return value as AttackLabRunPage;
}

function decodeAttackLabLimits(value: unknown): void {
  const record = exactRecord(value, ["cpu", "memory", "ephemeral_storage", "timeout_seconds"]); if (record.cpu !== "500m" || record.memory !== "1Gi" || record.ephemeral_storage !== "2Gi" || record.timeout_seconds !== 300) fail();
}

function attackLabDestination(value: unknown): asserts value is string {
  boundedString(value, 1, 253); if (value !== value.toLowerCase() || value.startsWith(".") || value.endsWith(".")) fail(); const labels = value.split("."); if (labels.some((label) => label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) fail();
}

function redTeamCursor(value: unknown, maximum: number): void { if (value === undefined) return; boundedString(value, 2, maximum); if (!CURSOR.test(value)) fail(); }

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
    const publicConnectorKey = intent.provider.startsWith("nango:") ? intent.provider.slice("nango:".length) : intent.provider;
    if (intent.provider.startsWith("nango:") && ["aws", "github", "kubernetes", "okta"].includes(publicConnectorKey)) fail();
    if (kind !== "integration" || result.id !== resourceID || result.status !== "active" || intent.integration_id !== resourceID || publicConnectorKey !== result.connector_key || idempotencyKey !== `oauth-completion:${intent.authorization_attempt_id}`) fail();
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

function attackLabDigest(value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value) || /^0{64}$/.test(value)) fail();
}

function attackLabEvidenceLocator(record: Record<string, unknown>): void {
  const present = [record.evidence_reference, record.evidence_version_id, record.evidence_checksum, record.evidence_size].map((value) => value !== undefined);
  if (!present.some(Boolean)) return;
  if (!present.every(Boolean)) fail();
  printableString(record.evidence_reference, 1, 1024);
  if (typeof record.evidence_version_id !== "string" || record.evidence_version_id.length < 1 || record.evidence_version_id.length > 512 || [...record.evidence_version_id].some((character) => { const code = character.codePointAt(0) ?? 0; return character.trim() === "" || code < 32 || code >= 127 && code <= 159; })) fail();
  attackLabDigest(record.evidence_checksum);
  boundedInteger(record.evidence_size, 1, 64 << 20);
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
function optionalCursor(value: unknown): void { if (value === undefined) return; boundedString(value, 2, 512); if (!CURSOR.test(value)) fail(); }
function stringRecord(value: unknown, maximum: number, minimum = 0, minimumValueLength = 0): void { if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length < minimum || Object.keys(value).length > maximum || Object.entries(value).some(([key, item]) => key.length < 1 || key.length > 128 || typeof item !== "string" || item.length < minimumValueLength || item.length > 2048)) fail(); }
function enumValue(value: unknown, allowed: readonly string[]): void { if (typeof value !== "string" || !allowed.includes(value)) fail(); }
function fail(): never { throw new Error("schema mismatch"); }
