import { requireAPIData, type APIClient } from "./client";
import type { EnvironmentAiControls as EnvironmentAIControls, ModelQualificationPage, OrganizationAiControls as OrganizationAIControls } from "./generated";

export const modeLabels = {
  deterministic_only: "Deterministic only",
  zasp_vpc_slm: "Zasp private model",
  privatelink_bedrock: "AWS Bedrock PrivateLink",
  privatelink_vertex: "Vertex AI private connection",
  byoc_self_hosted: "Customer-hosted model",
  dev_openrouter: "Development router",
} as const;
export type Mode = keyof typeof modeLabels;
export const residencyLabels = {
  customer_vpc_only: "Customer VPC only", us_only: "United States", eu_only: "European Union", us_eu: "United States and European Union",
} as const;
export const capabilityLabels = {
  tier2_prompt_injection_enabled: "Screen untrusted content",
  tier2_purpose_drift_enabled: "Detect drift from approved purpose",
  tier2_heuristic_fp_suppression_enabled: "Review heuristic false positives",
  tier3_discovery_purpose_enabled: "Verify agent discovery and draft purposes",
  tier3_addon_audit_enabled: "Audit add-ons",
  tier3_security_agent_planner_enabled: "Plan security agent investigations",
} as const;
export const consentLabels = {
  allow_redacted_summaries: "Redacted summaries",
  allow_approved_code_snippets: "Approved code snippets",
  allow_private_addon_bytes: "Private add-on contents",
} as const;
export const bindingLabels = {
  tier2_profile: "Private model profile",
  tier3_provider: "Reasoning provider",
  tier3_model_pin: "Pinned model",
  credential_reference: "Credential reference",
  credential_digest: "Credential SHA-256 digest",
} as const;
export function keysOf<T extends object>(value: T) { return Object.keys(value) as (keyof T)[]; }

type OrganizationInput = Partial<Pick<OrganizationAIControls, "ai_enabled" | "allowed_modes" | "allowed_residency" | "allow_private_code_egress">>;
type EnvironmentInput = Partial<Pick<EnvironmentAIControls, keyof typeof capabilityLabels | keyof typeof consentLabels | keyof typeof bindingLabels | "mode" | "monthly_budget_nano_credits">>;

function record(value: unknown): Record<string, unknown> {
  if (!value || Array.isArray(value) || typeof value !== "object") throw Error("Invalid AI controls");
  return value as Record<string, unknown>;
}
function validVersion(value: unknown) { return typeof value === "number" && Number.isSafeInteger(value) && value > 0; }
function knownMode(value: unknown): value is Mode { return typeof value === "string" && Object.hasOwn(modeLabels, value); }

export function decodeOrganizationAIControls(value: unknown): OrganizationAIControls {
  const row = record(value);
  if (!validVersion(row.version) || typeof row.ai_enabled !== "boolean" || typeof row.allow_private_code_egress !== "boolean"
    || row.require_zero_retention !== true || !Array.isArray(row.allowed_modes) || !row.allowed_modes.every(knownMode)
    || !row.allowed_modes.includes("deterministic_only") || typeof row.allowed_residency !== "string" || !Object.hasOwn(residencyLabels, row.allowed_residency)) throw Error("Invalid organization AI controls");
  return value as OrganizationAIControls;
}
export function decodeEnvironmentAIControls(value: unknown): EnvironmentAIControls {
  const row = record(value);
  if (!validVersion(row.version) || !knownMode(row.mode) || !knownMode(row.effective_mode)
    || !["production", "staging", "development", "test"].includes(String(row.environment_class)) || !["metadata_only", "extended"].includes(String(row.collection_mode))
    || !Number.isSafeInteger(row.monthly_budget_nano_credits) || Number(row.monthly_budget_nano_credits) < 0
    || ![...Object.keys(capabilityLabels), ...Object.keys(consentLabels)].every(k => typeof row[k] === "boolean")
    || !Object.keys(bindingLabels).every(k => typeof row[k] === "string")) throw Error("Invalid environment AI controls");
  return value as EnvironmentAIControls;
}
export function decodeQualifications(value: unknown): ModelQualificationPage {
  const { items } = record(value);
  if (!Array.isArray(items) || items.length > 256 || !items.every(item => {
    const row = record(item);
    return [row.provider, row.model, row.purpose].every(field => typeof field === "string" && field.length > 0) && typeof row.qualified === "boolean"
      && typeof row.checked_at === "string" && Number.isFinite(Date.parse(row.checked_at)) && typeof row.evidence_digest === "string" && row.evidence_digest.length <= 71;
  })) throw Error("Invalid model qualifications");
  return value as ModelQualificationPage;
}

export function createAIControlsAPI(client: APIClient, expectedScope: string) {
  const [organizationID, , environmentID] = expectedScope.split("/");
  const scopeHeaders = { "X-Zasp-Expected-Scope": expectedScope };
  const mutation = (version: number) => ({ header: { "If-Match": `"${version}"`, "X-CSRF-Token": "" } });
  return {
    async load(signal: AbortSignal) {
      const [organization, environment, qualifications] = await Promise.all([
        client.GET("/api/v1/organization/ai-controls", { signal, headers: scopeHeaders }).then(result => requireAPIData(result, decodeOrganizationAIControls)),
        client.GET("/api/v1/settings/ai-controls", { signal, headers: scopeHeaders }).then(result => requireAPIData(result, decodeEnvironmentAIControls)),
        client.GET("/api/v1/ai/qualifications", { signal, headers: scopeHeaders }).then(result => requireAPIData(result, decodeQualifications)),
      ]);
      if (organization.organization_id !== organizationID || environment.environment_id !== environmentID) throw Error("AI controls scope changed");
      return { organization, environment, qualifications: qualifications.items };
    },
    async updateOrganization(version: number, body: OrganizationInput, signal: AbortSignal) {
      const result = requireAPIData(await client.PATCH("/api/v1/organization/ai-controls", { params: mutation(version), headers: scopeHeaders, body, signal }), decodeOrganizationAIControls);
      if (result.organization_id !== organizationID || result.version !== version + 1) throw Error("Organization update could not be confirmed");
      return result;
    },
    async updateEnvironment(version: number, body: EnvironmentInput, signal: AbortSignal) {
      const result = requireAPIData(await client.PATCH("/api/v1/settings/ai-controls", { params: mutation(version), headers: scopeHeaders, body, signal }), decodeEnvironmentAIControls);
      if (result.environment_id !== environmentID || result.version !== version + 1) throw Error("Environment update could not be confirmed");
      return result;
    },
  };
}

export type AIControlsAPI = ReturnType<typeof createAIControlsAPI>;
export type AISettings = Awaited<ReturnType<AIControlsAPI["load"]>>;
export type { OrganizationInput, EnvironmentInput };
