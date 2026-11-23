import { requireAPIData, type APIClient } from "./client";
import type { SessionIntent } from "./generated";

const product = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export async function loadSessionIntent(client: APIClient, id: string, signal: AbortSignal): Promise<SessionIntent> {
  const data = requireAPIData<SessionIntent>(await client.GET("/api/v1/sessions/{id}/intent", { params: { path: { id } }, signal }));
  if (data.session_id !== id || typeof data.truncated !== "boolean" || !Array.isArray(data.actions) || data.actions.length > 100) throw new Error("Invalid session outcomes");
  const seen = new Set<string>();
  for (const action of data.actions) {
    if (!product.test(action.decision_id) || seen.has(action.decision_id) || typeof action.attention !== "boolean" ||
      !["prevented", "completed", "outcome_unknown"].includes(action.outcome) || !["authenticated_workload", "gateway", "tetragon", "otlp"].includes(action.source) ||
      !Number.isFinite(Date.parse(action.observed_at)) || typeof action.operation !== "string" || !action.operation.length || action.operation.length > 256 ||
      !Array.isArray(action.evidence_ids) || action.evidence_ids.length < 1 || action.evidence_ids.length > 2 || action.evidence_ids.some((item: string) => !product.test(item))) throw new Error("Invalid session receipt");
    seen.add(action.decision_id);
  }
  return data;
}
