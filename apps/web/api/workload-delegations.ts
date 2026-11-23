import { APITransportError, requireAPIData, type APIClient } from "./client";
import type { DelegationHop, WorkloadDelegationPage } from "./generated";

const pid = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const label = /^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$/;
const statuses = new Set(["issued", "verified", "denied", "delegation_unverified"]);

function invalid(): never {
  throw new APITransportError("invalid_response", "Unexpected task delegation receipt");
}

function validScope(values: readonly string[]) {
  return Array.isArray(values) && values.length > 0 && values.length <= 32 &&
    values.every(value => typeof value === "string" && label.test(value)) && new Set(values).size === values.length;
}

function validHop(hop: DelegationHop, prior?: DelegationHop) {
  if (!hop || !pid.test(hop.parent_agent_id) || !pid.test(hop.child_agent_id) || hop.parent_agent_id === hop.child_agent_id ||
    !Number.isInteger(hop.max_depth) || !Number.isInteger(hop.depth) || hop.depth < 1 || hop.depth > hop.max_depth || hop.max_depth > 8 ||
    !Number.isSafeInteger(hop.expires_at) || hop.expires_at <= 0 || !Number.isFinite(new Date(hop.expires_at * 1000).getTime()) ||
    !validScope(hop.allowed_operations) || !validScope(hop.allowed_resources)) return false;
  return !prior || (prior.child_agent_id === hop.parent_agent_id && prior.depth + 1 === hop.depth &&
    prior.max_depth >= hop.max_depth && prior.expires_at >= hop.expires_at &&
    hop.allowed_operations.every(item => prior.allowed_operations.includes(item)) &&
    hop.allowed_resources.every(item => prior.allowed_resources.includes(item)));
}

export function decodeDelegations(raw: unknown, credential: string, agent: string): WorkloadDelegationPage {
  const page = raw as WorkloadDelegationPage | null;
  if (!page || page.credential_id !== credential || page.agent_id !== agent || typeof page.truncated !== "boolean" ||
    !Array.isArray(page.items) || page.items.length > 25) return invalid();
  const seen = new Set<string>();
  for (const receipt of page.items) {
    if (!receipt || typeof receipt.id !== "string" || !/^[1-9][0-9]{0,18}$/.test(receipt.id) || seen.has(receipt.id) ||
      !statuses.has(receipt.status) || !Number.isFinite(Date.parse(receipt.observed_at)) || typeof receipt.parent_task_id !== "string" ||
      (receipt.parent_task_id !== "" && !label.test(receipt.parent_task_id)) || !Array.isArray(receipt.grants) || receipt.grants.length > 8) return invalid();
    seen.add(receipt.id);
    if (receipt.grants.some((hop: DelegationHop, i: number) => !validHop(hop, receipt.grants[i - 1]))) return invalid();
    const last = receipt.grants.at(-1);
    if (last && (receipt.status === "issued" ? last.parent_agent_id !== agent :
      receipt.status !== "verified" || last.child_agent_id !== agent)) return invalid();
  }
  return page;
}

export async function readDelegations(client: APIClient, credential: string, agent: string, signal?: AbortSignal) {
  const response = await client.GET("/api/v1/runtime/workload-bindings/{id}/delegations", { params: { path: { id: credential } }, signal });
  return requireAPIData(response, value => decodeDelegations(value, credential, agent));
}
