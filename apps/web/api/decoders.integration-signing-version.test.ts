import { describe, expect, it } from "vitest";
import { decodeIntegration, decodeWorkflowMutationReceipt } from "./decoders";

describe("webhook signing-version public metadata", () => {
  it.each([32, 64])("preserves %i-character metadata in integration and mutation receipts", (length) => {
    const configuration = {
      destination_url: "https://hooks.customer.invalid/zasp",
      signing_secret_reference: "secret_ref_1234",
      signing_secret_version: "a".repeat(length),
    };
    const integration = {
      id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "generic-webhook", name: "Webhook",
      configuration, status: "configured", created_at: "2026-08-18T12:00:00Z", updated_at: "2026-08-18T12:00:00Z",
    };
    expect(decodeIntegration(integration)).toEqual(integration);
    for (const operation of ["createIntegration", "updateIntegration"]) {
      const create = operation === "createIntegration";
      const body = create ? { connector_key: integration.connector_key, name: integration.name, configuration }
        : { name: integration.name, configuration };
      const receipt = {
        id: "pid_11111111-1111-4111-8111-111111111111", operation,
        idempotency_key: "wf_11111111-1111-4111-8111-111111111111",
        intent: { body, expected_version: create ? 0 : 1, resource_id: create ? "" : integration.id },
        result: integration, resource_kind: "integration", resource_id: integration.id, resource_version: create ? 1 : 2,
        audit_id: "pid_33333333-3333-4333-8333-333333333333",
        correlation_id: "pid_44444444-4444-4444-8444-444444444444",
        created_at: "2026-08-18T12:00:00Z", expires_at: "2026-08-25T12:00:00Z",
      };
      const original = JSON.stringify(receipt);
      expect(decodeWorkflowMutationReceipt(receipt)).toEqual(receipt);
      expect(JSON.stringify(receipt)).toBe(original);
      for (const invalid of [null, 1, {}, [], "short", "x".repeat(65), "x".repeat(31) + "!", undefined]) {
        const changed = structuredClone(receipt);
        (changed.result.configuration as Record<string, unknown>).signing_secret_version = invalid;
        (changed.intent.body.configuration as Record<string, unknown>).signing_secret_version = invalid;
        expect(() => decodeWorkflowMutationReceipt(changed)).toThrow("schema mismatch");
      }
      for (const key of ["secret_version", "Signing_Secret_Version", "secret", "password", "token", "credential_value", "nested"]) {
        const changed = structuredClone(receipt);
        (changed.result.configuration as Record<string, unknown>)[key] = key === "nested" ? { password: "raw" } : "raw";
        (changed.intent.body.configuration as Record<string, unknown>)[key] = key === "nested" ? { password: "raw" } : "raw";
        expect(() => decodeWorkflowMutationReceipt(changed)).toThrow("schema mismatch");
      }
      const wrongProvider = structuredClone(receipt);
      wrongProvider.result.connector_key = "github";
      if ("connector_key" in wrongProvider.intent.body) wrongProvider.intent.body.connector_key = "github";
      expect(() => decodeWorkflowMutationReceipt(wrongProvider)).toThrow("schema mismatch");
      const wrongKind = { ...receipt, resource_kind: "policy" };
      expect(() => decodeWorkflowMutationReceipt(wrongKind)).toThrow("schema mismatch");
      const wrongOperation = { ...receipt, operation: "completeIntegrationOAuth" };
      expect(() => decodeWorkflowMutationReceipt(wrongOperation)).toThrow("schema mismatch");
      const misplaced = structuredClone(receipt);
      (misplaced.result as Record<string, unknown>).signing_secret_version = configuration.signing_secret_version;
      expect(() => decodeWorkflowMutationReceipt(misplaced)).toThrow("schema mismatch");
    }
  });
});
