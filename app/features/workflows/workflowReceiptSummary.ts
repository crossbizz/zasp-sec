import type { WorkflowMutationReceipt } from "../../../apps/web/api/generated";

export type WorkflowReceiptSummaryField = Readonly<{ label: string; value: string }>;
export type WorkflowReceiptSummary = Readonly<{
  intent: readonly WorkflowReceiptSummaryField[];
  result: readonly WorkflowReceiptSummaryField[];
}>;

export function workflowReceiptSummary(receipt: WorkflowMutationReceipt): WorkflowReceiptSummary {
  const intent = receipt.intent as { body: Record<string, unknown>; expected_version: number; resource_id: string };
  const result = receipt.result as Record<string, unknown>;
  const operation = receipt.operation as string;
  if (receipt.resource_kind === "integration_sync") return syncSummary(result);
  if (receipt.resource_kind === "integration_schedule") return scheduleSummary(operation, receipt.intent as unknown as Record<string, unknown>, result, receipt.resource_version);
  switch (receipt.resource_kind) {
  case "policy":
    return { intent: policyIntent(operation, receipt.resource_id, intent.body), result: policyResult(result, receipt.resource_version) };
  case "integration":
    return { intent: operation === "completeIntegrationOAuth" ? oauthCompletionIntent(receipt.intent as unknown as Record<string, unknown>) : operation === "completeIntegrationReferenceAuthorization" ? referenceAuthorizationIntent(receipt.intent as unknown as Record<string, unknown>) : integrationIntent(operation, receipt.resource_id, intent.body), result: operation === "deleteIntegration" && result.status === "deleted" ? integrationDeletionResult(result, receipt.resource_version) : integrationResult(result, receipt.resource_version) };
  case "security_agent":
    return { intent: securityAgentIntent(operation, receipt.resource_id, intent.body), result: securityAgentResult(result, receipt.resource_version) };
  case "finding":
    return { intent: findingIntent(operation, receipt.resource_id, intent.body), result: findingResult(result, receipt.resource_version) };
  }
}

function syncSummary(result: Record<string, unknown>): WorkflowReceiptSummary {
  return {
    intent: [field("Requested change", "Manual inventory sync")],
    result: [
      field("Committed status", result.status),
      field("Discovered", result.discovered_count),
      field("Changed", result.changed_count),
      field("Removed", result.removed_count),
    ],
  };
}

function scheduleSummary(operation: string, rawIntent: Record<string, unknown>, result: Record<string, unknown>, version: number): WorkflowReceiptSummary {
  const intent = rawIntent.body && typeof rawIntent.body === "object" && !Array.isArray(rawIntent.body) ? rawIntent.body as Record<string, unknown> : {};
  return {
    intent: operation === "deleteIntegrationSchedule"
      ? [field("Requested change", "Delete automatic sync schedule")]
      : [field("Requested schedule", intent.state), field("Requested cadence", secondsLabel(intent.cadence_seconds))],
    result: [field("Committed state", result.state), field("Committed cadence", secondsLabel(result.cadence_seconds)), field("Time zone", result.time_zone), field("Committed version", version)],
  };
}

function secondsLabel(value: unknown): string {
  return typeof value === "number" && Number.isSafeInteger(value) ? `${value} seconds` : "Unavailable";
}

function oauthCompletionIntent(intent: Record<string, unknown>): readonly WorkflowReceiptSummaryField[] {
  return [field("Requested integration", intent.integration_id), field("Requested provider", intent.provider)];
}

function referenceAuthorizationIntent(intent: Record<string, unknown>): readonly WorkflowReceiptSummaryField[] {
  return [
    field("Requested integration", intent.integration_id),
    field("Requested provider", intent.provider),
    field("Requested configuration fields", configurationKeys(intent.configuration)),
  ];
}

function findingIntent(operation: string, resourceID: string, body: Record<string, unknown>): readonly WorkflowReceiptSummaryField[] {
  if (operation === "updateFinding") return [field("Requested finding", resourceID), field("Requested status", body.status)];
  if (operation === "acceptFindingRisk") return [field("Requested finding", resourceID), field("Requested acceptance reason", body.reason)];
  return [field("Rejected operation", operation)];
}

function findingResult(result: Record<string, unknown>, version: number): readonly WorkflowReceiptSummaryField[] {
  return [field("Committed resource", result.id), field("Committed finding", result.title), field("Committed status", result.status), field("Committed version", version)];
}

function policyIntent(operation: string, resourceID: string, body: Record<string, unknown>): readonly WorkflowReceiptSummaryField[] {
  if (operation === "deletePolicy") return [field("Requested change", `Delete ${resourceID}`)];
  if (operation === "disablePolicy") return [field("Requested change", `Disable ${resourceID}`)];
  if (operation === "rolloutPolicy") return [field("Requested rollout", body.state), field("Requested target", body.target_id)];
  return [field("Requested policy", body.name), field("Requested action", body.action), field("Requested rollout", body.rollout)];
}

function policyResult(result: Record<string, unknown>, version: number): readonly WorkflowReceiptSummaryField[] {
  return [field("Committed resource", result.id), field("Committed policy", result.name), field("Committed action", result.action), field("Committed rollout", result.rollout), field("Committed version", version)];
}

function integrationIntent(operation: string, resourceID: string, body: Record<string, unknown>): readonly WorkflowReceiptSummaryField[] {
  if (operation === "deleteIntegration") return [field("Requested change", `Delete ${resourceID}`)];
  const values = [field("Requested integration", body.name)];
  if (operation === "createIntegration") values.push(field("Requested connector", body.connector_key));
  values.push(field("Requested configuration fields", configurationKeys(body.configuration)));
  return values;
}

function integrationResult(result: Record<string, unknown>, version: number): readonly WorkflowReceiptSummaryField[] {
  return [
    field("Committed resource", result.id), field("Committed integration", result.name), field("Committed connector", result.connector_key), field("Committed status", result.status),
    field("Committed configuration fields", configurationKeys(result.configuration)), field("Committed version", version),
  ];
}

function integrationDeletionResult(result: Record<string, unknown>, version: number): readonly WorkflowReceiptSummaryField[] {
  return [field("Committed resource", result.id), field("Committed status", result.status), field("Committed version", version)];
}

function securityAgentIntent(operation: string, resourceID: string, body: Record<string, unknown>): readonly WorkflowReceiptSummaryField[] {
  if (operation === "deleteSecurityAgent") return [field("Requested change", `Delete ${resourceID}`)];
  return [field("Requested Security Agent", body.name), field("Requested trigger", `${body.trigger_kind} · ${body.trigger_source}`), field("Requested autonomy", body.autonomy), field("Requested enabled state", body.enabled)];
}

function securityAgentResult(result: Record<string, unknown>, version: number): readonly WorkflowReceiptSummaryField[] {
  return [field("Committed resource", result.id), field("Committed Security Agent", result.name), field("Committed trigger", `${result.trigger_kind} · ${result.trigger_source}`), field("Committed autonomy", result.autonomy), field("Committed enabled state", result.enabled), field("Committed version", version)];
}

function configurationKeys(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "None";
  return Object.keys(value).sort().join(", ") || "None";
}

function field(label: string, value: unknown): WorkflowReceiptSummaryField {
  return { label, value: typeof value === "boolean" ? (value ? "Enabled" : "Disabled") : String(value) };
}
