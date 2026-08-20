import { describe, expect, it } from "vitest";

import { decodeWorkflowMutationReceipt } from "./decoders";

const policy = {
  id: "policy-production", name: "Production", scope: "environment", trigger: "tool",
  conditions: [{ field: "action", operator: "equals", value: "write" }],
  action: "monitor", rollout: "draft", failure_mode: "open",
};
const integration = {
  id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "generic-webhook", name: "Webhook",
  configuration: { destination_url: "https://hooks.customer.invalid/zasp", signing_secret_reference: "secret_ref_1234" },
  status: "configured", created_at: "2026-08-18T12:00:00Z", updated_at: "2026-08-18T12:00:00Z",
};
const agent = {
  id: "pid_20000002-0000-4000-8000-000000000002", name: "Credential responder", trigger_kind: "finding", trigger_source: "credential",
  environment_ids: ["pid_10000003-0000-4000-8000-000000000003"], autonomy: "supervised", max_steps: 10,
  max_duration_seconds: 900, temporary_policy_seconds: 3600, ai_token_budget: 4000, concurrency_limit: 2,
  allowed_actions: ["run_test"], verification_kind: "test_run", definition_version: 1, enabled: true,
};

function receipt(operation: string) {
  const kind = operation.includes("Integration") ? "integration" : operation.includes("SecurityAgent") ? "security_agent" : "policy";
  const result = operation === "remediateIntegrationAuthorization" ? { ...integration, status: "pending_authorization" }
    : operation === "completeIntegrationReferenceAuthorization" ? { ...integration, connector_key: "aws", configuration: { role_arn: "arn:aws:iam::123456789012:role/zasp-discovery", external_id_reference: "ref:aws/external-id/customer-0001", region: "us-east-1" }, status: "active" }
    : kind === "integration" ? integration : kind === "security_agent" ? agent
    : operation === "rolloutPolicy" ? { ...policy, rollout: "monitor" }
    : operation === "disablePolicy" ? { ...policy, rollout: "disabled" } : policy;
  const resourceID = result.id;
  const create = operation.startsWith("create");
  let body: unknown = {};
  if (operation === "createPolicy" || operation === "updatePolicy") body = policy;
  if (operation === "rolloutPolicy") body = { state: "monitor", target_id: "pid_10000003-0000-4000-8000-000000000003" };
  if (operation === "createIntegration") body = { connector_key: integration.connector_key, name: integration.name, configuration: integration.configuration };
  if (operation === "updateIntegration") body = { name: integration.name, configuration: integration.configuration };
  if (operation === "remediateIntegrationAuthorization") body = { acknowledgement: "provider_grant_revoked_manually" };
  if (operation === "createSecurityAgent") body = Object.fromEntries(Object.entries(agent).filter(([key]) => key !== "id"));
  if (operation === "updateSecurityAgent") body = agent;
  const intent = operation === "completeIntegrationReferenceAuthorization" ? {
    configuration: result.configuration, expected_version: 1, idempotency_key: "wf_11111111-1111-4111-8111-111111111111",
    integration_id: result.id, provider: "aws",
    scope: { organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003" },
  } : { body, expected_version: create ? 0 : 1, resource_id: create ? "" : resourceID };
  return {
    id: "pid_11111111-1111-4111-8111-111111111111", operation,
    idempotency_key: "wf_11111111-1111-4111-8111-111111111111",
    intent,
    result, resource_kind: kind, resource_id: resourceID, resource_version: create ? 1 : 2,
    audit_id: "pid_33333333-3333-4333-8333-333333333333",
    correlation_id: "pid_44444444-4444-4444-8444-444444444444",
    created_at: "2026-08-18T12:00:00Z", expires_at: "2026-08-25T12:00:00Z",
  };
}

describe("workflow mutation receipt decoder", () => {
  it.each([
    "createPolicy", "updatePolicy", "deletePolicy", "rolloutPolicy", "disablePolicy",
    "createIntegration", "updateIntegration", "deleteIntegration", "remediateIntegrationAuthorization", "completeIntegrationReferenceAuthorization",
    "createSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent",
  ])("accepts an exact %s intent and authoritative result", (operation) => {
    expect(decodeWorkflowMutationReceipt(receipt(operation))).toEqual(receipt(operation));
  });

	it("accepts an exact Kubernetes reference authorization intent", () => {
		const value = receipt("completeIntegrationReferenceAuthorization");
		value.result = { ...value.result, connector_key: "kubernetes", configuration: { connection_reference: "ref:kubernetes/connection/customer-0001" } };
		value.intent = { ...value.intent, provider: "kubernetes", configuration: value.result.configuration };
		expect(decodeWorkflowMutationReceipt(value)).toEqual(value);
	});

  it.each([
    ["invalid idempotency characters", (value: ReturnType<typeof receipt>) => { value.idempotency_key = "wf_invalid key!!"; }],
    ["expiry beyond seven days", (value: ReturnType<typeof receipt>) => { value.expires_at = "2026-08-25T12:00:01Z"; }],
    ["operation and resource kind mismatch", (value: ReturnType<typeof receipt>) => { value.resource_kind = "integration"; }],
    ["kind-specific resource id mismatch", (value: ReturnType<typeof receipt>) => { value.resource_id = "pid_20000001-0000-4000-8000-000000000001"; }],
    ["contradictory result identity", (value: ReturnType<typeof receipt>) => { value.result = { ...policy, id: "policy-other" }; }],
    ["undeclared intent member", (value: ReturnType<typeof receipt>) => { value.intent = { ...value.intent, extra: true } as typeof value.intent; }],
    ["wrong create version", (value: ReturnType<typeof receipt>) => { value.intent = { ...value.intent, expected_version: 1 }; }],
    ["delete body with data", (value: ReturnType<typeof receipt>) => { value.operation = "deletePolicy"; value.intent = { body: { force: true }, expected_version: 1, resource_id: policy.id }; }],
    ["readable secret value", (value: ReturnType<typeof receipt>) => { value.operation = "createIntegration"; value.resource_kind = "integration"; value.resource_id = integration.id; value.result = { ...integration, configuration: { password: "readable-secret" } as unknown as typeof integration.configuration }; value.intent = { body: { connector_key: integration.connector_key, name: integration.name, configuration: { password: "readable-secret" } }, expected_version: 0, resource_id: "" }; }],
  ])("rejects %s", (_name, mutate) => {
    const value = receipt("createPolicy");
    mutate(value);
    expect(() => decodeWorkflowMutationReceipt(value)).toThrow("schema mismatch");
  });

	it.each([
		["extra intent member", (value: ReturnType<typeof receipt>) => { value.intent = { ...value.intent, secret: "raw" }; }],
		["mismatched provider", (value: ReturnType<typeof receipt>) => { value.intent = { ...value.intent, provider: "kubernetes" }; }],
		["mismatched integration", (value: ReturnType<typeof receipt>) => { value.intent = { ...value.intent, integration_id: "pid_20000001-0000-4000-8000-000000000099" }; }],
		["mismatched idempotency key", (value: ReturnType<typeof receipt>) => { value.intent = { ...value.intent, idempotency_key: "wf_99999999-9999-4999-8999-999999999999" }; }],
		["nested reference", (value: ReturnType<typeof receipt>) => { value.intent = { ...value.intent, configuration: { ...value.result.configuration, external_id_reference: { value: "ref:aws/external-id/customer-0001" } } }; }],
	])("rejects reference authorization %s", (_name, mutate) => {
		const value = receipt("completeIntegrationReferenceAuthorization");
		mutate(value);
		expect(() => decodeWorkflowMutationReceipt(value)).toThrow("schema mismatch");
	});
});
