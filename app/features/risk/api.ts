import type { APIClient } from "../../../apps/web/api/client";
import { APITransportError, requireAPIData } from "../../../apps/web/api/client";
import { decodeAttackPath, decodeAttackPathPage, decodeBreakOptionPage, decodeFinding, decodeFindingPage, decodeInventoryDetail } from "../../../apps/web/api/decoders";
import type { AttackPath, BreakOption, Finding, FindingTicket } from "../../../apps/web/api/generated";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";

const quotedVersion = /^"[1-9][0-9]*"$/;
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

type CredentialKind = "browser" | "pat";
type APIResult = { data?: unknown; error?: unknown; response: Response };

export type RiskMutationAttempt = Readonly<{ idempotencyKey: string }>;
export type VersionedRisk<T> = Readonly<{ value: T; version: string }>;
export type RiskMutationResult = VersionedRisk<Finding> & Readonly<{ auditID: string; receiptID?: string }>;

export type ProductionRiskAPI = Readonly<{
  listFindings(signal?: AbortSignal): Promise<readonly Finding[]>;
  getFinding(id: string, signal?: AbortSignal): Promise<VersionedRisk<Finding>>;
  updateFinding(id: string, status: "open" | "under_review" | "resolved", version: string, attempt: RiskMutationAttempt, signal?: AbortSignal): Promise<RiskMutationResult>;
  acceptFindingRisk(id: string, reason: string, version: string, attempt: RiskMutationAttempt, signal?: AbortSignal): Promise<RiskMutationResult>;
	createFindingTicket(id: string, version: string, attempt: RiskMutationAttempt, signal?: AbortSignal): Promise<FindingTicket>;
  listAttackPaths(signal?: AbortSignal): Promise<readonly AttackPath[]>;
  getAttackPath(id: string, signal?: AbortSignal): Promise<AttackPath>;
  getAttackPathBreakOptions(path: AttackPath, signal?: AbortSignal): Promise<readonly BreakOption[]>;
  // The name and kind of the inventory objects on a path (agent, MCP server,
  // tool, identity, data store). A node the caller may not read is absent.
  describePathNodes?(ids: readonly string[], signal?: AbortSignal): Promise<Readonly<Record<string, PathNode>>>;
}>;

export type PathNode = Readonly<{ name: string; kind: "agent" | "tool" | "identity" | "runtime" | "asset"; sourceKind: string }>;

export function createProductionRiskAPI(client: APIClient, credentialKind: CredentialKind = "browser"): ProductionRiskAPI {
  return {
    async listFindings(signal) {
      const loaded = await loadAllCursorPages(async (cursor) => requireAPIData(await client.GET("/api/v1/findings", { params: { query: { cursor, limit: 100 } }, signal }), decodeFindingPage), { maximumItems: 10_000, maximumPages: 100 });
      return loaded.items;
    },
    async getFinding(id, signal) {
      const result = await client.GET("/api/v1/findings/{id}", { params: { path: { id } }, signal });
      return requireRiskVersioned(result, decodeFinding);
    },
    async updateFinding(id, status, version, attempt, signal) {
      const result = await client.PATCH("/api/v1/findings/{id}", { params: { path: { id }, header: mutationHeaders(version, attempt, credentialKind) }, body: { status }, signal });
      return requireRiskMutation(result, credentialKind);
    },
    async acceptFindingRisk(id, reason, version, attempt, signal) {
      const result = await client.POST("/api/v1/findings/{id}/accept-risk", { params: { path: { id }, header: mutationHeaders(version, attempt, credentialKind) }, body: { reason }, signal });
      return requireRiskMutation(result, credentialKind);
    },
		async createFindingTicket(id, version, attempt, signal) {
			const result = await client.POST("/api/v1/findings/{id}/ticket", { params: { path: { id }, header: mutationHeaders(version, attempt, credentialKind) }, signal });
			return requireAPIData(result, decodeFindingTicket);
		},
    async listAttackPaths(signal) {
      const loaded = await loadAllCursorPages(async (cursor) => requireAPIData(await client.GET("/api/v1/attack-paths", { params: { query: { cursor, limit: 100 } }, signal }), decodeAttackPathPage), { maximumItems: 10_000, maximumPages: 100 });
      return loaded.items;
    },
    async getAttackPath(id, signal) {
      return requireAPIData(await client.GET("/api/v1/attack-paths/{id}", { params: { path: { id } }, signal }), decodeAttackPath);
    },
    async getAttackPathBreakOptions(path, signal) {
      return requireAPIData(await client.GET("/api/v1/attack-paths/{id}/break-options", { params: { path: { id: path.id } }, signal }), (value) => decodeBreakOptionPage(value, path)).items;
    },
    // An inventory id does not say its kind, so each node is asked for as an
    // agent, a tool, an identity, a runtime and an asset until one answers.
    async describePathNodes(ids, signal) {
      const nodes: Record<string, PathNode> = {};
      await Promise.all(ids.slice(0, 8).filter((id) => productID.test(id)).map(async (id) => {
        for (const path of ["/api/v1/agents/{id}", "/api/v1/tools/{id}", "/api/v1/identities/{id}", "/api/v1/runtimes/{id}", "/api/v1/assets/{id}"] as const) {
          try {
            const detail = requireAPIData(await client.GET(path, { params: { path: { id } }, signal }), decodeInventoryDetail);
            if (detail.summary.id === id) { nodes[id] = { name: detail.summary.name, kind: detail.summary.kind, sourceKind: detail.summary.source_kind }; return; }
          } catch { if (signal?.aborted) return; }
        }
      }));
      return nodes;
    },
  };
}

function decodeFindingTicket(value: unknown): FindingTicket {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new APITransportError("invalid_response", "Finding ticket response was invalid");
	const record = value as Record<string, unknown>;
	if (Object.keys(record).length !== 1 || typeof record.ticket_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(record.ticket_id)) {
		throw new APITransportError("invalid_response", "Finding ticket response was invalid");
	}
	return { ticket_id: record.ticket_id };
}

function requireRiskVersioned<T>(result: APIResult, decode: (value: unknown) => T): VersionedRisk<T> {
  const value = requireAPIData(result, decode);
  const version = result.response.headers.get("ETag");
  if (!version || !quotedVersion.test(version)) throw new APITransportError("invalid_response", "Risk response omitted a valid resource version");
  return { value, version };
}

function requireRiskMutation(result: APIResult, credentialKind: CredentialKind): RiskMutationResult {
  const versioned = requireRiskVersioned(result, decodeFinding);
  const auditID = result.response.headers.get("X-Audit-ID");
  const receiptID = result.response.headers.get("X-Mutation-Receipt-ID") ?? undefined;
  if (!auditID || !productID.test(auditID) || credentialKind === "browser" && (!receiptID || !productID.test(receiptID)) || credentialKind === "pat" && receiptID !== undefined) {
    throw new APITransportError("invalid_response", "Risk mutation omitted exact durable evidence headers");
  }
  return { ...versioned, auditID, ...(receiptID ? { receiptID } : {}) };
}

function mutationHeaders(version: string, attempt: RiskMutationAttempt, credentialKind: CredentialKind): { "If-Match": string; "Idempotency-Key": string; "X-CSRF-Token": string } {
  if (!quotedVersion.test(version) || !/^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/.test(attempt.idempotencyKey)) throw new APITransportError("invalid_configuration", "Invalid risk mutation precondition");
  const headers = { "If-Match": version, "Idempotency-Key": attempt.idempotencyKey };
  // OpenAPI cannot conditionally require a header by security alternative.
  // Browser requests carry a transport-owned placeholder that the CSRF vault
  // replaces; PAT requests omit the browser-only header at transport time.
  return credentialKind === "browser" ? { ...headers, "X-CSRF-Token": "" } : headers as typeof headers & { "X-CSRF-Token": string };
}
