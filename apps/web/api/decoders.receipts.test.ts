import { describe, expect, it } from "vitest";

import { decodeWorkflowMutationReceipt } from "./decoders";

const expectedScope = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";

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

type MutableReceipt = {
	id: string; operation: string; idempotency_key: string; intent: Record<string, unknown>; result: Record<string, unknown>;
	resource_kind: string; resource_id: string; resource_version: number; audit_id: string; correlation_id: string; created_at: string; expires_at: string;
};

function receipt(operation: string): MutableReceipt {
  const kind = operation.includes("Integration") ? "integration" : operation.includes("SecurityAgent") ? "security_agent" : "policy";
  const result = operation === "remediateIntegrationAuthorization" ? { ...integration, status: "pending_authorization" }
    : operation === "completeIntegrationOAuth" ? { ...integration, connector_key: "github", configuration: { installation_reference: "ref:github/installation/customer-0001" }, status: "active" }
    : operation === "completeIntegrationReferenceAuthorization" ? { ...integration, connector_key: "aws", configuration: { role_arn: "arn:aws:iam::123456789012:role/zasp-discovery", external_id_reference: "ref:aws/external-id/customer-0001", region: "us-east-1" }, status: "active" }
    : operation === "deleteIntegration" ? { id: integration.id, status: "deleted" }
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
  const authorizationAttemptID = "pid_55555555-5555-4555-8555-555555555555";
  const intent = operation === "completeIntegrationOAuth" ? { authorization_attempt_id: authorizationAttemptID, integration_id: result.id, provider: "github" }
  : operation === "completeIntegrationReferenceAuthorization" ? {
    configuration: (result as Record<string, unknown>).configuration, expected_version: 1, idempotency_key: "wf_11111111-1111-4111-8111-111111111111",
    integration_id: result.id, provider: "aws",
    scope: { organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003" },
  } : { body, expected_version: create ? 0 : 1, resource_id: create ? "" : resourceID };
  return {
    id: "pid_11111111-1111-4111-8111-111111111111", operation,
    idempotency_key: operation === "completeIntegrationOAuth" ? `oauth-completion:${authorizationAttemptID}` : "wf_11111111-1111-4111-8111-111111111111",
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
    "createIntegration", "updateIntegration", "deleteIntegration", "remediateIntegrationAuthorization", "completeIntegrationOAuth", "completeIntegrationReferenceAuthorization",
    "createSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent",
  ])("accepts an exact %s intent and authoritative result", (operation) => {
    expect(decodeWorkflowMutationReceipt(receipt(operation), operation === "completeIntegrationReferenceAuthorization" ? expectedScope : undefined)).toEqual(receipt(operation));
  });

  it.each([
    ["full Integration for deleteIntegration", integration],
    ["extra terminal field", { id: integration.id, status: "deleted", connector_key: "github" }],
    ["wrong terminal status", { id: integration.id, status: "revoked" }],
    ["wrong terminal identity", { id: "pid_20000001-0000-4000-8000-000000000099", status: "deleted" }],
  ])("rejects %s", (_name, result) => {
    const value = receipt("deleteIntegration");
    value.result = result;
    expect(() => decodeWorkflowMutationReceipt(value)).toThrow("schema mismatch");
  });

  it("accepts only the full revoking Integration before terminal deletion", () => {
    const value = receipt("deleteIntegration");
    value.result = { ...integration, status: "revoking" };
    expect(decodeWorkflowMutationReceipt(value)).toEqual(value);
  });

  it("rejects an integration deletion tombstone for create or update", () => {
    for (const operation of ["createIntegration", "updateIntegration"]) {
      const value = receipt(operation);
      value.result = { id: integration.id, status: "deleted" };
      expect(() => decodeWorkflowMutationReceipt(value)).toThrow("schema mismatch");
    }
  });

  it.each([
    ["create resource version drift", "createIntegration", (value: MutableReceipt) => { value.resource_version = 2; }],
    ["update resource version drift", "updateIntegration", (value: MutableReceipt) => { value.resource_version = 3; }],
    ["delete resource version drift", "deleteIntegration", (value: MutableReceipt) => { value.resource_version = 3; }],
    ["other delete resource", "deleteIntegration", (value: MutableReceipt) => { value.intent = { ...value.intent, resource_id: "pid_20000001-0000-4000-8000-000000000099" }; }],
    ["nonempty delete body", "deleteIntegration", (value: MutableReceipt) => { value.intent = { ...value.intent, body: { force: true } }; }],
    ["unrelated create body", "createIntegration", (value: MutableReceipt) => { value.intent = { ...value.intent, body: { ...(value.intent.body as Record<string, unknown>), name: "Other" } }; }],
    ["unrelated update body", "updateIntegration", (value: MutableReceipt) => { value.intent = { ...value.intent, body: { ...(value.intent.body as Record<string, unknown>), configuration: { installation_reference: "ref:github/installation/customer-9999" } } }; }],
  ])("rejects integration receipt %s", (_name, operation, mutate) => {
    const value = receipt(operation);
    mutate(value);
    expect(() => decodeWorkflowMutationReceipt(value)).toThrow("schema mismatch");
  });

	it("accepts an exact Kubernetes reference authorization intent", () => {
		const value = receipt("completeIntegrationReferenceAuthorization");
		value.result = { ...value.result, connector_key: "kubernetes", configuration: { connection_reference: "ref:kubernetes/connection/customer-0001" } };
		value.intent = { ...value.intent, provider: "kubernetes", configuration: value.result.configuration };
		expect(decodeWorkflowMutationReceipt(value, expectedScope)).toEqual(value);
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
		["nested reference", (value: ReturnType<typeof receipt>) => { value.intent = { ...value.intent, configuration: { ...(value.result.configuration as Record<string, unknown>), external_id_reference: { value: "ref:aws/external-id/customer-0001" } } }; }],
		["unsupported role partition", (value: ReturnType<typeof receipt>) => { const configuration = { ...(value.result.configuration as Record<string, unknown>), role_arn: "arn:aws-cn:iam::123456789012:role/zasp-discovery" }; value.result = { ...value.result, configuration }; value.intent = { ...value.intent, configuration }; }],
		["unsupported government region", (value: ReturnType<typeof receipt>) => { const configuration = { ...(value.result.configuration as Record<string, unknown>), region: "us-gov-west-1" }; value.result = { ...value.result, configuration }; value.intent = { ...value.intent, configuration }; }],
	])("rejects reference authorization %s", (_name, mutate) => {
		const value = receipt("completeIntegrationReferenceAuthorization");
		mutate(value);
		expect(() => decodeWorkflowMutationReceipt(value, expectedScope)).toThrow("schema mismatch");
	});

	it.each([
		["extra member", (value: ReturnType<typeof receipt>) => { value.intent = { ...value.intent, token: "raw" }; }],
		["mismatched provider", (value: ReturnType<typeof receipt>) => { value.intent = { ...value.intent, provider: "okta" }; }],
		["mismatched integration", (value: ReturnType<typeof receipt>) => { value.intent = { ...value.intent, integration_id: "pid_20000001-0000-4000-8000-000000000099" }; }],
		["mismatched idempotency key", (value: ReturnType<typeof receipt>) => { value.idempotency_key = "oauth-completion:pid_99999999-9999-4999-8999-999999999999"; }],
	])("rejects OAuth completion %s", (_name, mutate) => {
		const value = receipt("completeIntegrationOAuth");
		mutate(value);
		expect(() => decodeWorkflowMutationReceipt(value)).toThrow("schema mismatch");
	});

	it("accepts the bounded Nango OAuth provider authority", () => {
		const value = receipt("completeIntegrationOAuth");
		value.intent = { ...value.intent, provider: "nango:github-enterprise" };
		value.result = { ...(value.result as Record<string, unknown>), connector_key: "nango:github-enterprise" };
		expect(decodeWorkflowMutationReceipt(value)).toEqual(value);
	});

	it("requires reference authorization receipts to match the current captured scope", () => {
		const value = receipt("completeIntegrationReferenceAuthorization");
		expect(() => decodeWorkflowMutationReceipt(value)).toThrow("schema mismatch");
		expect(() => decodeWorkflowMutationReceipt(value, "pid_90000001-0000-4000-8000-000000000001/pid_90000002-0000-4000-8000-000000000002/pid_90000003-0000-4000-8000-000000000003")).toThrow("schema mismatch");
		expect(decodeWorkflowMutationReceipt(value, expectedScope)).toEqual(value);
	});
});
