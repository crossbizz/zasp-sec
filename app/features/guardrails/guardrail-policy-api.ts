import { APIProductError, APITransportError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { decodeGuardrailPolicy, type GuardrailMode, type GuardrailPolicy } from "../../../apps/web/api/decoders";
import { createWorkflowMutationAttempt } from "../workflows/api";

// The guardrail policy of the current Environment:
//   GET /api/v1/guardrails/policy  getGuardrailPolicy  (view)
//   PUT /api/v1/guardrails/policy  putGuardrailPolicy  (manage_workflows)
// A save names the version it was made from. When the policy changed in the
// meantime the server refuses it and GuardrailPolicyConflict is thrown.
export class GuardrailPolicyConflict extends Error {
  constructor() { super("The guardrail policy changed"); this.name = "GuardrailPolicyConflict"; }
}

export type GuardrailPolicyAPI = Readonly<{
  getPolicy(signal?: AbortSignal): Promise<GuardrailPolicy>;
  savePolicy(rules: Readonly<Record<string, GuardrailMode>>, version: number): Promise<GuardrailPolicy>;
}>;

function versioned(result: { data?: unknown; error?: unknown; response: Response }): GuardrailPolicy {
  const policy = requireAPIData(result, decodeGuardrailPolicy);
  if (result.response.headers.get("ETag") !== `"${policy.version}"` || result.response.headers.get("Cache-Control") !== "no-store") throw new APITransportError("invalid_response", "Guardrail policy returned invalid version metadata");
  return policy;
}

export function createGuardrailPolicyAPI(client: APIClient): GuardrailPolicyAPI {
  return {
    async getPolicy(signal) {
      return versioned(await client.GET("/api/v1/guardrails/policy", { signal }));
    },
    async savePolicy(rules, version) {
      try {
        const saved = versioned(await client.PUT("/api/v1/guardrails/policy", {
          params: { header: { "Idempotency-Key": createWorkflowMutationAttempt().idempotencyKey, "If-Match": `"${version}"` } as { "Idempotency-Key": string; "If-Match": string } },
          body: { rules: { ...rules } },
        }));
        // A save makes exactly the next version, with the modes that were sent.
        if (saved.version !== version + 1 || saved.rules.some((rule) => rules[rule.id] !== undefined && rules[rule.id] !== rule.mode)) throw new APITransportError("invalid_response", "Guardrail policy save returned a different policy");
        return saved;
      } catch (error) {
        if (error instanceof APIProductError && (error.status === 409 || error.status === 412)) throw new GuardrailPolicyConflict();
        throw error;
      }
    },
  };
}
