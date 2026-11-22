import { APITransportError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { decodeAgentPurpose } from "../../../apps/web/api/decoders";
import type { AgentPurpose } from "../../../apps/web/api/generated";

export interface PurposeAttempt { agent: string; revision: number; tools: string[]; key: string }

export function purposeAPI(client: APIClient) {
  return {
    async get(agent: string, signal?: AbortSignal) {
      const result = await client.GET("/api/v1/agents/{id}/purpose", { params: { path: { id: agent } }, signal });
      return requireAPIData(result, raw => decodeAgentPurpose(raw, agent));
    },
    async save(attempt: PurposeAttempt): Promise<AgentPurpose> {
      const result = await client.PUT("/api/v1/agents/{id}/purpose", { params: { path: { id: attempt.agent }, header: { "Idempotency-Key": attempt.key, "If-Match": `"${attempt.revision}"` } }, body: { allowed_tool_ids: attempt.tools } });
      const saved = requireAPIData(result, raw => decodeAgentPurpose(raw, attempt.agent));
      if (saved.revision !== attempt.revision + 1 || JSON.stringify(saved.allowed_tool_ids) !== JSON.stringify(attempt.tools)) throw new APITransportError("invalid_response", "Purpose change unconfirmed");
      return saved;
    },
  };
}
