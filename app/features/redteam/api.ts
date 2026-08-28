import type { APIClient } from "../../../apps/web/api/client";
import { APITransportError, requireAPIData } from "../../../apps/web/api/client";
import { decodeAttackLabPreflight, decodeAttackLabRun, decodeAttackLabRunDetail, decodeAttackLabRunPage, decodeInventoryPage, decodeTestDefinition, decodeTestDefinitionPage, decodeTestRun, decodeTestRunDetail, decodeTestRunPage } from "../../../apps/web/api/decoders";
import type { AttackLabPreflight, AttackLabRun, AttackLabRunDetail, InventorySummary, TestDefinition, TestDefinitionInput, TestDefinitionUpdateInput, TestRun, TestRunDetail } from "../../../apps/web/api/generated";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";

const quotedVersion = /^"[1-9][0-9]{0,5}"$/;
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const idempotencyKey = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;

type APIResult = { data?: unknown; error?: unknown; response: Response };
type MutationAttempt = Readonly<{ idempotencyKey: string }>;

export type ProductionRedTeamAPI = Readonly<{
  listDefinitions(signal?: AbortSignal): Promise<readonly TestDefinition[]>;
  getDefinition(id: string, signal?: AbortSignal): Promise<TestDefinition>;
  createDefinition(input: TestDefinitionInput, attempt: MutationAttempt, signal?: AbortSignal): Promise<TestDefinition>;
  updateDefinition(id: string, version: number, input: TestDefinitionUpdateInput, attempt: MutationAttempt, signal?: AbortSignal): Promise<TestDefinition>;
  runDefinition(id: string, version: number, runID: string, attempt: MutationAttempt, signal?: AbortSignal): Promise<TestRun>;
  listRuns(signal?: AbortSignal): Promise<readonly TestRun[]>;
  getRun(id: string, signal?: AbortSignal): Promise<TestRunDetail>;
  cancelRun(id: string, version: number, attempt: MutationAttempt, signal?: AbortSignal): Promise<TestRun>;
  preflightAttackLab(sourceRunID: string, signal?: AbortSignal): Promise<AttackLabPreflight>;
  listAttackLabRuns(signal?: AbortSignal): Promise<readonly AttackLabRun[]>;
  getAttackLabRun(id: string, signal?: AbortSignal): Promise<AttackLabRunDetail>;
  createAttackLabRun(preflight: AttackLabPreflight, runID: string, attempt: MutationAttempt, signal?: AbortSignal): Promise<AttackLabRun>;
  cancelAttackLabRun(id: string, version: number, attempt: MutationAttempt, signal?: AbortSignal): Promise<AttackLabRun>;
  rerunAttackLabRun(sourceRunID: string, version: number, runID: string, attempt: MutationAttempt, signal?: AbortSignal): Promise<AttackLabRun>;
  listTargets(signal?: AbortSignal): Promise<readonly InventorySummary[]>;
}>;

export function createProductionRedTeamAPI(client: APIClient): ProductionRedTeamAPI {
  return {
    async listDefinitions(signal) { return loadRootCursorPages((cursor) => client.GET("/api/v1/tests", { params: { query: { cursor, limit: 100 } }, signal }), decodeTestDefinitionPage); },
    async getDefinition(id, signal) { return requireVersioned(await client.GET("/api/v1/tests/{id}", { params: { path: { id } }, signal }), decodeTestDefinition); },
    async createDefinition(input, attempt, signal) {
      requireMutationAttempt(attempt); const result = await client.POST("/api/v1/tests", { params: { header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": '"0"', "X-CSRF-Token": "" } }, body: input, signal }); return requireMutation(result, decodeTestDefinition);
    },
    async updateDefinition(id, version, input, attempt, signal) {
      requireVersion(version); requireMutationAttempt(attempt); const result = await client.PATCH("/api/v1/tests/{id}", { params: { path: { id }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": `"${version}"`, "X-CSRF-Token": "" } }, body: input, signal }); return requireMutation(result, decodeTestDefinition);
    },
    async runDefinition(id, version, runID, attempt, signal) {
      requireVersion(version); if (!productID.test(runID)) throw new APITransportError("invalid_configuration", "Invalid red team run identity"); requireMutationAttempt(attempt); const result = await client.POST("/api/v1/tests/{id}/runs", { params: { path: { id }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": `"${version}"`, "X-CSRF-Token": "" } }, body: { run_id: runID }, signal }); return requireMutation(result, decodeTestRun);
    },
    async listRuns(signal) { return loadRootCursorPages((cursor) => client.GET("/api/v1/test-runs", { params: { query: { cursor, limit: 100 } }, signal }), decodeTestRunPage); },
    async getRun(id, signal) { return requireVersioned(await client.GET("/api/v1/test-runs/{id}", { params: { path: { id } }, signal }), decodeTestRunDetail); },
    async cancelRun(id, version, attempt, signal) {
      requireVersion(version); requireMutationAttempt(attempt); const result = await client.POST("/api/v1/test-runs/{id}/cancel", { params: { path: { id }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": `"${version}"`, "X-CSRF-Token": "" } }, signal }); return requireMutation(result, decodeTestRun);
    },
    async preflightAttackLab(sourceRunID, signal) {
      requireProductID(sourceRunID); const value = requireAPIData(await client.GET("/api/v1/attack-lab/preflight", { params: { query: { source_run_id: sourceRunID } }, signal }), decodeAttackLabPreflight); if (value.source_run_id !== sourceRunID) invalidAttackLabResponse(); return value;
    },
    async listAttackLabRuns(signal) { return loadRootCursorPages((cursor) => client.GET("/api/v1/attack-lab/runs", { params: { query: { cursor, limit: 100 } }, signal }), decodeAttackLabRunPage); },
    async getAttackLabRun(id, signal) { requireProductID(id); const value = requireVersioned(await client.GET("/api/v1/attack-lab/runs/{id}", { params: { path: { id } }, signal }), decodeAttackLabRunDetail); if (value.id !== id) invalidAttackLabResponse(); return value; },
    async createAttackLabRun(preflight, runID, attempt, signal) {
      const sourceRunID = preflight.source_run_id; requireProductID(sourceRunID); requireProductID(runID); if (sourceRunID === runID || !/^[0-9a-f]{64}$/.test(preflight.decision_digest) || /^0{64}$/.test(preflight.decision_digest)) invalidAttackLabConfiguration(); requireMutationAttempt(attempt); const result = await client.POST("/api/v1/attack-lab/runs", { params: { header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": '"0"', "X-CSRF-Token": "" } }, body: { run_id: runID, source_run_id: sourceRunID, decision_digest: preflight.decision_digest, approved: true }, signal }); const value = requireMutation(result, decodeAttackLabRun); if (value.id !== runID || value.source_run_id !== sourceRunID || value.version !== 1 || value.status !== "queued" || value.attempt !== 0) invalidAttackLabResponse(); return value;
    },
    async cancelAttackLabRun(id, version, attempt, signal) {
      requireProductID(id); requireVersion(version); requireMutationAttempt(attempt); const result = await client.POST("/api/v1/attack-lab/runs/{id}/cancel", { params: { path: { id }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": `"${version}"`, "X-CSRF-Token": "" } }, signal }); const value = requireMutation(result, decodeAttackLabRun); if (value.id !== id || value.version !== version + 1 || !value.cancel_requested && value.status !== "cancelled") invalidAttackLabResponse(); return value;
    },
    async rerunAttackLabRun(sourceRunID, version, runID, attempt, signal) {
      requireProductID(sourceRunID); requireProductID(runID); if (sourceRunID === runID) invalidAttackLabConfiguration(); requireVersion(version); requireMutationAttempt(attempt); const result = await client.POST("/api/v1/attack-lab/runs/{id}/rerun", { params: { path: { id: sourceRunID }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": `"${version}"`, "X-CSRF-Token": "" } }, body: { run_id: runID }, signal }); const value = requireMutation(result, decodeAttackLabRun); if (value.id !== runID || value.version !== 1 || value.status !== "queued" || value.attempt !== 0) invalidAttackLabResponse(); return value;
    },
    async listTargets(signal) {
      const [agents, tools] = await Promise.all([
        loadAllCursorPages((cursor) => Promise.resolve(client.GET("/api/v1/agents", { params: { query: { cursor, limit: 100 } }, signal })).then((result) => requireAPIData(result, decodeInventoryPage)), { maximumItems: 10_000, maximumPages: 100 }),
        loadAllCursorPages((cursor) => Promise.resolve(client.GET("/api/v1/tools", { params: { query: { cursor, limit: 100 } }, signal })).then((result) => requireAPIData(result, decodeInventoryPage)), { maximumItems: 10_000, maximumPages: 100 }),
      ]);
      return [...agents.items, ...tools.items].sort((left, right) => left.name.localeCompare(right.name) || left.id.localeCompare(right.id));
    },
  };
}

async function loadRootCursorPages<T>(read: (cursor?: string) => Promise<APIResult>, decode: (value: unknown) => { readonly items: readonly T[]; readonly next_cursor?: string }, maximumItems = 10_000): Promise<readonly T[]> {
  const items: T[] = []; const seen = new Set<string>(); let cursor: string | undefined;
  for (let page = 0; page < 100; page += 1) {
    const value = requireAPIData(await read(cursor), decode); items.push(...value.items); if (items.length > maximumItems) throw new APITransportError("invalid_response", "Red team pagination exceeded its item bound");
    if (value.next_cursor === undefined) return items; if (value.next_cursor === cursor || seen.has(value.next_cursor)) throw new APITransportError("invalid_response", "Red team pagination repeated its cursor"); seen.add(value.next_cursor); cursor = value.next_cursor;
  }
  throw new APITransportError("invalid_response", "Red team pagination exceeded its page bound");
}

function requireVersioned<T extends { readonly version: number }>(result: APIResult, decode: (value: unknown) => T): T {
  const value = requireAPIData(result, decode); const version = result.response.headers.get("ETag"); if (version !== `"${value.version}"` || !quotedVersion.test(version)) throw new APITransportError("invalid_response", "Red team response omitted its exact version"); return value;
}

function requireMutation<T extends { readonly version: number }>(result: APIResult, decode: (value: unknown) => T): T {
  const value = requireVersioned(result, decode); const audit = result.response.headers.get("X-Audit-ID"); const receipt = result.response.headers.get("X-Mutation-Receipt-ID"); if (!audit || !receipt || !productID.test(audit) || !productID.test(receipt) || audit === receipt) throw new APITransportError("invalid_response", "Red team mutation omitted durable evidence"); return value;
}

function requireVersion(value: number): void { if (!Number.isSafeInteger(value) || value < 1 || value > 1_000_000) throw new APITransportError("invalid_configuration", "Invalid red team version"); }
function requireMutationAttempt(value: MutationAttempt): void { if (!idempotencyKey.test(value.idempotencyKey)) throw new APITransportError("invalid_configuration", "Invalid red team idempotency key"); }
function requireProductID(value: string): void { if (!productID.test(value)) invalidAttackLabConfiguration(); }
function invalidAttackLabConfiguration(): never { throw new APITransportError("invalid_configuration", "Invalid Attack Lab request configuration"); }
function invalidAttackLabResponse(): never { throw new APITransportError("invalid_response", "Attack Lab response contradicted its request authority"); }

export function redTeamProductID(): string { return `pid_${globalThis.crypto.randomUUID()}`; }
export function redTeamIdempotencyKey(): string { return `redteam_${globalThis.crypto.randomUUID()}`; }
