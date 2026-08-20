import { describe, expect, it } from "vitest";

import type { WorkflowMutationReceipt } from "../../../apps/web/api/generated";
import { workflowReceiptSummary } from "./workflowReceiptSummary";

const policy = { id: "policy-production", name: "Production", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" };
const base = {
  id: "pid_11111111-1111-4111-8111-111111111111", idempotency_key: "wf_11111111-1111-4111-8111-111111111111",
  resource_version: 2, audit_id: "pid_33333333-3333-4333-8333-333333333333", correlation_id: "pid_44444444-4444-4444-8444-444444444444",
  created_at: "2026-08-18T12:00:00Z", expires_at: "2026-08-25T12:00:00Z",
};

describe("truthful workflow receipt summary", () => {
  it.each([
    ["createPolicy", { body: policy, expected_version: 0, resource_id: "" }, policy, ["Requested policy", "Production", "Requested action", "monitor", "Requested rollout", "draft"]],
    ["updatePolicy", { body: policy, expected_version: 1, resource_id: policy.id }, policy, ["Requested policy", "Production", "Requested action", "monitor", "Requested rollout", "draft"]],
    ["deletePolicy", { body: {}, expected_version: 1, resource_id: policy.id }, policy, ["Requested change", "Delete policy-production"]],
    ["rolloutPolicy", { body: { state: "monitor", target_id: "pid_10000003-0000-4000-8000-000000000003" }, expected_version: 1, resource_id: policy.id }, { ...policy, rollout: "monitor" }, ["Requested rollout", "monitor", "Requested target", "pid_10000003-0000-4000-8000-000000000003"]],
    ["disablePolicy", { body: {}, expected_version: 1, resource_id: policy.id }, { ...policy, rollout: "disabled" }, ["Requested change", "Disable policy-production"]],
  ])("summarizes %s frozen intent and committed policy", (operation, intent, result, expectedIntent) => {
    const summary = workflowReceiptSummary({ ...base, operation, intent, result, resource_kind: "policy", resource_id: policy.id } as WorkflowMutationReceipt);
    expect(summary.intent.flatMap(({ label, value }) => [label, value])).toEqual(expectedIntent);
    expect(summary.result).toEqual(expect.arrayContaining([{ label: "Committed version", value: "2" }, { label: "Committed policy", value: "Production" }]));
  });

  it("summarizes integration configuration names without rendering their values", () => {
    const result = { id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "generic-webhook", name: "Webhook", configuration: { destination_url: "https://secret.invalid", signing_secret_reference: "secret_ref_1234" }, status: "configured", created_at: "2026-08-18T12:00:00Z", updated_at: "2026-08-18T12:00:00Z" };
    const receipt = { ...base, operation: "createIntegration", intent: { body: { connector_key: result.connector_key, name: result.name, configuration: result.configuration }, expected_version: 0, resource_id: "" }, result, resource_kind: "integration", resource_id: result.id } as WorkflowMutationReceipt;
    const serialized = JSON.stringify(workflowReceiptSummary(receipt));
    expect(serialized).toContain("destination_url, signing_secret_reference");
    expect(serialized).not.toContain("https://secret.invalid");
    expect(serialized).not.toContain("secret_ref_1234");
  });

  it("summarizes a terminal integration deletion receipt without assuming a live integration", () => {
    const integrationID = "pid_20000001-0000-4000-8000-000000000001";
    const receipt = { ...base, operation: "deleteIntegration", intent: { body: {}, expected_version: 1, resource_id: integrationID }, result: { id: integrationID, status: "deleted" }, resource_kind: "integration", resource_id: integrationID } as WorkflowMutationReceipt;
    expect(workflowReceiptSummary(receipt)).toEqual({
      intent: [{ label: "Requested change", value: `Delete ${integrationID}` }],
      result: [
        { label: "Committed resource", value: integrationID },
        { label: "Committed status", value: "deleted" },
        { label: "Committed version", value: "2" },
      ],
    });
  });

  it("summarizes a pending integration revocation as a live integration without exposing configuration values", () => {
    const integrationID = "pid_20000001-0000-4000-8000-000000000001";
    const result = { id: integrationID, connector_key: "github", name: "GitHub", configuration: { installation_reference: "ref:github/installation/customer-0001" }, status: "revoking", created_at: "2026-08-18T12:00:00Z", updated_at: "2026-08-18T12:00:01Z" };
    const receipt = { ...base, operation: "deleteIntegration", intent: { body: {}, expected_version: 1, resource_id: integrationID }, result, resource_kind: "integration", resource_id: integrationID } as WorkflowMutationReceipt;
    const summary = workflowReceiptSummary(receipt);
    expect(summary.result).toEqual(expect.arrayContaining([{ label: "Committed integration", value: "GitHub" }, { label: "Committed status", value: "revoking" }]));
    expect(JSON.stringify(summary)).not.toContain(result.configuration.installation_reference);
  });

	it("summarizes reference authorization intent without rendering any reference value", () => {
		const configuration = { role_arn: "arn:aws:iam::123456789012:role/zasp-discovery", external_id_reference: "ref:aws/external-id/customer-0001", region: "us-east-1" };
		const result = { id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "aws", name: "AWS", configuration, status: "active", created_at: "2026-08-18T12:00:00Z", updated_at: "2026-08-18T12:00:00Z" };
		const receipt = { ...base, operation: "completeIntegrationReferenceAuthorization", intent: { configuration, expected_version: 1, idempotency_key: base.idempotency_key, integration_id: result.id, provider: "aws", scope: { organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003" } }, result, resource_kind: "integration", resource_id: result.id } as unknown as WorkflowMutationReceipt;
		const summary = workflowReceiptSummary(receipt);
		expect(summary.intent).toEqual([
			{ label: "Requested integration", value: result.id },
			{ label: "Requested provider", value: "aws" },
			{ label: "Requested configuration fields", value: "external_id_reference, region, role_arn" },
		]);
		const serialized = JSON.stringify(summary);
		for (const hidden of Object.values(configuration)) expect(serialized).not.toContain(hidden);
	});

	it("summarizes OAuth completion intent without assuming a standard workflow body", () => {
		const result = { id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "github", name: "GitHub", configuration: { installation_reference: "ref:github/installation/customer-0001" }, status: "active", created_at: "2026-08-18T12:00:00Z", updated_at: "2026-08-18T12:00:00Z" };
		const intent = { authorization_attempt_id: "pid_55555555-5555-4555-8555-555555555555", integration_id: result.id, provider: "github" };
		const receipt = { ...base, idempotency_key: `oauth-completion:${intent.authorization_attempt_id}`, operation: "completeIntegrationOAuth", intent, result, resource_kind: "integration", resource_id: result.id } as unknown as WorkflowMutationReceipt;
		const summary = workflowReceiptSummary(receipt);
		expect(summary.intent).toEqual([
			{ label: "Requested integration", value: result.id },
			{ label: "Requested provider", value: "github" },
		]);
		expect(JSON.stringify(summary)).not.toContain(intent.authorization_attempt_id);
		expect(JSON.stringify(summary)).not.toContain(result.configuration.installation_reference);
	});

  it("summarizes Security Agent create, update, and delete receipts from allowlisted fields", () => {
    const result = { id: "pid_20000002-0000-4000-8000-000000000002", name: "Credential responder", trigger_kind: "finding", trigger_source: "credential", environment_ids: ["pid_10000003-0000-4000-8000-000000000003"], autonomy: "supervised", max_steps: 10, max_duration_seconds: 900, temporary_policy_seconds: 3600, ai_token_budget: 4000, concurrency_limit: 2, allowed_actions: ["run_test"], verification_kind: "test_run", definition_version: 1, enabled: true };
    const createInput = Object.fromEntries(Object.entries(result).filter(([key]) => key !== "id"));
    for (const [operation, body] of [["createSecurityAgent", createInput], ["updateSecurityAgent", result], ["deleteSecurityAgent", {}]] as const) {
      const summary = workflowReceiptSummary({ ...base, operation, intent: { body, expected_version: operation.startsWith("create") ? 0 : 1, resource_id: operation.startsWith("create") ? "" : result.id }, result, resource_kind: "security_agent", resource_id: result.id } as WorkflowMutationReceipt);
      expect(summary.result).toEqual(expect.arrayContaining([{ label: "Committed Security Agent", value: "Credential responder" }, { label: "Committed trigger", value: "finding · credential" }]));
      expect(JSON.stringify(summary)).not.toContain("max_duration_seconds");
    }
  });
});
