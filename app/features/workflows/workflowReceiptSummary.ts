import type { WorkflowMutationReceipt } from "../../../apps/web/api/generated";

export type WorkflowReceiptSummaryField = Readonly<{ label: string; value: string }>;
export type WorkflowReceiptSummary = Readonly<{
  intent: readonly WorkflowReceiptSummaryField[];
  result: readonly WorkflowReceiptSummaryField[];
}>;

export function workflowReceiptSummary(receipt: WorkflowMutationReceipt): WorkflowReceiptSummary {
  const intent = receipt.intent as { body: Record<string, unknown>; expected_version: number; resource_id: string };
  const result = receipt.result as Record<string, unknown>;
  switch (receipt.resource_kind) {
  case "policy":
    return { intent: policyIntent(receipt.operation, receipt.resource_id, intent.body), result: policyResult(result, receipt.resource_version) };
  case "integration":
    return { intent: integrationIntent(receipt.operation, receipt.resource_id, intent.body), result: integrationResult(result, receipt.resource_version) };
  case "security_agent":
    return { intent: securityAgentIntent(receipt.operation, receipt.resource_id, intent.body), result: securityAgentResult(result, receipt.resource_version) };
  }
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
