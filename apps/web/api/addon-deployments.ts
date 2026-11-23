import { APITransportError, requireAPIData, type APIClient } from "./client";
import { decodeInventoryPage } from "./decoders";
import { loadAllCursorPages } from "./pagination";
import type { DeploymentApproval } from "./generated";

const path = "/api/v1/addon-versions/{id}/deployment-approvals";
const invalid = (): never => { throw new APITransportError("invalid_response", "Invalid deployment review receipt"); };
const count = (n: unknown) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
const labels = (v: unknown) => Array.isArray(v) && v.length <= 64 && v.every(x => typeof x === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(x));

export function decodeDeploymentApproval(raw: unknown, version: string, agent: string): DeploymentApproval {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return invalid();
  const r = raw as Record<string, unknown>;
  if (r.addon_version_id !== version || r.agent_id !== agent || !count(r.revision) ||
    !count(r.access_revision) || !count(r.purpose_revision) || !count(r.identity_count) ||
    typeof r.version_approved !== "boolean" || typeof r.permission_context_digest !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(r.permission_context_digest) || !labels(r.destinations) || !labels(r.classifications) ||
    !["approved","pending","needs_re_review","revoked"].includes(String(r.state))) return invalid();
  return r as DeploymentApproval;
}

export type DeploymentAttempt = { receipt: DeploymentApproval; decision: "approved" | "revoked"; key: string };

export function deploymentAPI(client: APIClient) {
  return {
    async agents(signal?: AbortSignal) {
      const result = await loadAllCursorPages(async cursor => requireAPIData(await client.GET("/api/v1/agents", {
        params: { query: { cursor, limit: 100 } }, signal,
      }), decodeInventoryPage), { maximumItems: 10000, maximumPages: 100 });
      return result.items.filter(agent => agent.management_state !== "dismissed").map(({id,name}) => ({id,name}));
    },
    async get(id: string, agent: string, signal?: AbortSignal) {
      return requireAPIData(await client.GET(path, { params: { path: { id }, query: { agent_id: agent } }, signal }), raw => decodeDeploymentApproval(raw,id,agent));
    },
    async review({receipt, decision, key}: DeploymentAttempt, signal?: AbortSignal) {
      const {addon_version_id: id, agent_id: agent, revision, permission_context_digest} = receipt;
      const response = await client.POST(path, {params: {path: {id}, query: {agent_id: agent}, header: {"If-Match": `"${revision}"`, "Idempotency-Key": key, "X-CSRF-Token": ""}},
        body: {permission_context_digest, state: decision}, signal});
      const result = requireAPIData(response, raw => decodeDeploymentApproval(raw,id,agent));
      if (result.revision !== revision + 1 || result.state !== decision || result.permission_context_digest !== permission_context_digest) return invalid();
      return result;
    },
  };
}
export type DeploymentAPI = ReturnType<typeof deploymentAPI>;
