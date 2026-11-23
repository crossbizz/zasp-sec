import { APITransportError, requireAPIData, type APIClient } from "./client";
import { decodeInventoryReview } from "./inventory-review";
import type { AgentPostureSummary } from "./generated";

const id = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const categories = ["data_read","data_write","action_execute","identity_assume","network_egress","administration"];
const kinds = {runtime_receipt:"deployed_agent",provider_workload:"deployed_agent",repository:"repo_code",unverified:"unknown"} as const;
const validID = (v:unknown) => typeof v === "string" && id.test(v);
const invalid = (): never => { throw new APITransportError("invalid_response","Invalid agent posture evidence"); };

export function decodeAgentPosture(raw: unknown, agent: string): AgentPostureSummary {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return invalid();
  const r = raw as Record<string,unknown>;
  if (r.agent_id !== agent || !validID(agent) || typeof r.deployment_evidence !== "string" ||
    !Object.hasOwn(kinds,r.deployment_evidence) || kinds[r.deployment_evidence as keyof typeof kinds] !== r.deployment_kind ||
    (r.discovery_evidence_id !== null && !validID(r.discovery_evidence_id)) ||
    typeof r.purpose_revision !== "number" || !Number.isSafeInteger(r.purpose_revision) || r.purpose_revision < 0 ||
    !Array.isArray(r.allowed_tool_ids) || r.allowed_tool_ids.length > 64 || !r.allowed_tool_ids.every(validID) ||
    typeof r.access_known !== "boolean" || !Array.isArray(r.granted_categories) || r.granted_categories.length > 6 ||
    !r.granted_categories.every(c => categories.includes(c)) || (!r.access_known && r.granted_categories.length > 0)) return invalid();
  if (r.deployment_evidence === "runtime_receipt") {
    if (!validID(r.observed_evidence_id) || typeof r.last_observed_at !== "string" || !Number.isFinite(Date.parse(r.last_observed_at))) return invalid();
  } else if (r.observed_evidence_id !== null || r.last_observed_at !== null) return invalid();
  if (r.sync_reviews !== undefined) {
    if (!Array.isArray(r.sync_reviews) || r.sync_reviews.length > 2) return invalid();
    const seen = new Set<string>();
    for (const review of r.sync_reviews) {
      if (!review || !["agent_discovery_verify", "agent_purpose_draft"].includes(review.purpose) || seen.has(review.purpose) ||
        !["pending", "uncertain", "reviewed"].includes(review.state) || !validID(review.evidence_id) || review.evidence_id !== r.discovery_evidence_id) return invalid();
      seen.add(review.purpose);
      decodeInventoryReview({target_id: agent, purpose: review.purpose, coverage_degraded: review.state !== "reviewed", result: review.result}, agent, review.purpose);
      if (review.result && review.purpose === "agent_discovery_verify" &&
        (!review.result.evidence_refs.length || !review.result.evidence_refs.every((v:unknown) => v === review.evidence_id))) return invalid();
      if (review.result && review.purpose === "agent_purpose_draft" &&
        (!review.result.allowed_tool_ids.every(validID) || !review.result.iam_mismatches.every(validID))) return invalid();
    }
  }
  return r as AgentPostureSummary;
}

export const postureAPI = (client: APIClient) => async (id: string, signal?: AbortSignal) =>
  requireAPIData(await client.GET("/api/v1/agents/{id}/posture-summary",{params:{path:{id}},signal}),raw => decodeAgentPosture(raw,id));
