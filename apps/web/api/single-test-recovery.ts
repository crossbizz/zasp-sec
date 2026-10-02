import { APITransportError, type APIClient } from "./client";
import type { SecurityAgentAuditScope } from "./security-agent-audit";
import type { SingleTestCleanupRecovery } from "./generated";
import type { RecoveryIntent } from "../../../app/features/securityagents/recovery-intent";
import { executeWorkflowMutation, requireWorkflowReceipt, requireWorkflowVersioned, workflowMutationHeaders, type WorkflowMutationAttempt, type WorkflowReceipt } from "../../../app/features/workflows/api";

export type SingleTestRecoveryView = SingleTestCleanupRecovery;
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function fail(): never { throw new APITransportError("invalid_response", "Invalid SingleTest recovery response"); }
function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const result = value as Record<string, unknown>;
  if (Object.keys(result).some(key => !keys.includes(key)) || keys.some(key => !Object.hasOwn(result, key))) fail();
  return result;
}
function id(value: unknown): value is string { return typeof value === "string" && productID.test(value); }
function digest(value: unknown): value is string { return typeof value === "string" && /^[0-9a-f]{64}$/.test(value); }
function positive(value: unknown): value is number { return typeof value === "number" && Number.isSafeInteger(value) && value > 0; }
function timestamp(value: unknown): boolean {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString().slice(0, 19) === value.slice(0, 19);
}
function scopeHeaders(runID: string, scope: SecurityAgentAuditScope) {
  if (!id(runID) || !scope || ![scope.organization_id, scope.workspace_id, scope.environment_id].every(id)) throw new APITransportError("invalid_configuration", "Invalid recovery scope");
  return { "X-Zasp-Expected-Scope": [scope.organization_id, scope.workspace_id, scope.environment_id].join("/") };
}
const reasons: Record<string, readonly string[]> = {
  not_requested: ["not_requested"], queued: ["queued"], pending: ["cleanup_pending", "dependency_unavailable"],
  repair_required: ["evidence_conflict"], complete: ["verified"],
};
export function decodeSingleTestRecovery(value: unknown, runID: string, scope: SecurityAgentAuditScope): SingleTestRecoveryView {
  scopeHeaders(runID, scope);
  const v = record(value, ["run_id", "parent_version", "status", "reason", "request_identity", "command", "accepted_at", "completion"]);
  const identity = record(v.request_identity, ["definition_version", "input_digest"]);
  if (v.run_id !== runID || !positive(v.parent_version) || !positive(identity.definition_version) || identity.definition_version > 1000000 || !digest(identity.input_digest)
    || typeof v.status !== "string" || !Object.hasOwn(reasons, v.status) || !reasons[v.status]!.includes(v.reason as string)) fail();
  if (v.status === "not_requested") {
    if (v.command !== null || v.accepted_at !== null || v.completion !== null) fail();
    return value as SingleTestRecoveryView;
  }
  if (!timestamp(v.accepted_at)) fail();
  if (v.command !== null) {
    const command = record(v.command, ["command_id", "command_digest", "start"]);
    const start = record(command.start, ["ref", "definition_version", "input_digest"]);
    const ref = record(start.ref, ["organization_id", "workspace_id", "environment_id", "run_id"]);
    if (!id(command.command_id) || !digest(command.command_digest) || start.definition_version !== identity.definition_version || start.input_digest !== identity.input_digest
      || ref.run_id !== runID || ref.organization_id !== scope.organization_id || ref.workspace_id !== scope.workspace_id || ref.environment_id !== scope.environment_id) fail();
  }
  if (v.status === "complete") {
    const c = record(v.completion, ["receipt_id", "evidence_kind", "evidence_digest", "outcome", "completed_at"]);
    if (!id(c.receipt_id) || !digest(c.evidence_digest) || !timestamp(c.completed_at)
      || !["parent", "stop", "planning_terminal", "already_complete"].includes(c.evidence_kind as string)
      || !["cancelled", "failed", "inconclusive", "needs_human", "contained", "remediated"].includes(c.outcome as string)
      || (v.command === null) !== (c.evidence_kind === "already_complete")) fail();
  } else if (v.command === null || v.completion !== null) fail();
  return value as SingleTestRecoveryView;
}
function responseBound(response: Response, value: SingleTestRecoveryView) {
  if (response.headers.get("Cache-Control") !== "no-store" || response.headers.get("ETag") !== `"${value.parent_version}"`) fail();
}
export async function getSingleTestRecovery(client: APIClient, runID: string, scope: SecurityAgentAuditScope, signal?: AbortSignal): Promise<SingleTestRecoveryView> {
  const headers = scopeHeaders(runID, scope);
  const result = await client.GET("/api/v1/security-agent-runs/{id}/cleanup-recovery", { params: { path: { id: runID } }, headers, signal });
  const decoded = requireWorkflowVersioned(result, value => decodeSingleTestRecovery(value, runID, scope));
  if (result.response.status !== 200) fail();
  responseBound(result.response, decoded.value);
  return decoded.value;
}
export async function requestSingleTestRecovery(client: APIClient, intent: RecoveryIntent, scope: SecurityAgentAuditScope, attempt: WorkflowMutationAttempt): Promise<WorkflowReceipt<SingleTestRecoveryView>> {
  const headers = scopeHeaders(intent.id, scope);
  const body = record(intent.body, ["definition_version", "input_digest", "diagnostic", "stop_original"]);
  if (!positive(intent.version) || !positive(body.definition_version) || body.definition_version > 1000000 || !digest(body.input_digest) || body.diagnostic !== "history_unavailable" || body.stop_original !== true) fail();
  return executeWorkflowMutation(async active => {
    const result = await client.POST("/api/v1/security-agent-runs/{id}/cleanup-recovery", {
      params: { path: { id: intent.id }, header: { ...workflowMutationHeaders(active), "If-Match": `"${intent.version}"` } }, headers, body: intent.body,
    });
    const receipt = requireWorkflowReceipt(result, value => decodeSingleTestRecovery(value, intent.id, scope));
    if (![200, 202].includes(result.response.status) || receipt.value.status === "not_requested" || receipt.value.parent_version < intent.version
      || receipt.value.request_identity.definition_version !== body.definition_version || receipt.value.request_identity.input_digest !== body.input_digest) fail();
    responseBound(result.response, receipt.value);
    return receipt;
  }, attempt);
}
