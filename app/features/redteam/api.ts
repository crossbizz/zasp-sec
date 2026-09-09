import type { APIClient } from "../../../apps/web/api/client";
import { APITransportError, requireAPIData } from "../../../apps/web/api/client";
import { decodeAttackLabPreflight, decodeAttackLabRun, decodeAttackLabRunDetail, decodeAttackLabRunPage, decodeInventoryPage, decodeTestDefinition, decodeTestDefinitionPage, decodeTestRun, decodeTestRunDetail, decodeTestRunPage } from "../../../apps/web/api/decoders";
import type { AttackLabPreflight, AttackLabRun, AttackLabRunDetail, InventorySummary, TestDefinition, TestDefinitionInput, TestDefinitionUpdateInput, TestRun, TestRunDetail } from "../../../apps/web/api/generated";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";
import { decodeCapabilityPage, decodeInventoryDetail } from "../../../apps/web/api/decoders";
import { recommendRedTeamPacks, type RedTeamPackRecommendation } from "./recommendations";

const quotedVersion = /^"[1-9][0-9]{0,5}"$/;
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const idempotencyKey = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;

type APIResult = { data?: unknown; error?: unknown; response: Response };
type MutationAttempt = Readonly<{ idempotencyKey: string }>;
export type RedTeamRecommendations = Readonly<{targetID:string;freshUntil:string;items:readonly RedTeamPackRecommendation[]}>;

export type ProductionRedTeamAPI = Readonly<{
  getTargetRecommendations(id:string,kind:"agent"|"tool",signal?:AbortSignal):Promise<RedTeamRecommendations>;
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

export function createProductionRedTeamAPI(client: APIClient, expectedScope?: string): ProductionRedTeamAPI {
  if (expectedScope !== undefined && (expectedScope.split("/").length !== 3 || !expectedScope.split("/").every((part) => productID.test(part)))) throw new APITransportError("invalid_configuration", "Invalid Red Team request scope");
  const scopeHeaders = expectedScope === undefined ? undefined : { "X-Zasp-Expected-Scope": expectedScope };
  return {
    async getTargetRecommendations(id, kind, signal) {
      requireRedTeamID(id);
      if(kind!=="agent" && kind!=="tool") throw new APITransportError("invalid_configuration", "Unsupported recommendation target");
      const detail=requireAPIData(await client.GET(kind==="agent"?"/api/v1/agents/{id}":"/api/v1/tools/{id}",{params:{path:{id}},headers:scopeHeaders,signal}),decodeInventoryDetail);
      if(detail.summary.id!==id || detail.summary.kind!==kind) invalidRedTeamResponse();
      const capabilities=kind==="agent"?(await loadAllCursorPages(cursor=>Promise.resolve(client.GET("/api/v1/agents/{id}/capabilities",{params:{path:{id},query:{cursor,limit:100}},headers:scopeHeaders,signal})).then(result=>requireAPIData(result,decodeCapabilityPage)),{maximumItems:10_000,maximumPages:100})).items:[];
      return {targetID:id,freshUntil:detail.summary.fresh_until,items:recommendRedTeamPacks(detail.summary,capabilities,Date.now())};
    },
    async listDefinitions(signal) { return loadRootCursorPages((cursor) => client.GET("/api/v1/tests", { params: { query: { cursor, limit: 100 } }, headers: scopeHeaders, signal }), decodeTestDefinitionPage); },
    async getDefinition(id, signal) {
      requireRedTeamID(id);
      const value = requireVersioned(await client.GET("/api/v1/tests/{id}", { params: { path: { id } }, headers: scopeHeaders, signal }), decodeTestDefinition);
      if (value.id !== id) invalidRedTeamResponse();
      return value;
    },
    async createDefinition(input, attempt, signal) {
      requireRedTeamID(input.id); requireRedTeamID(input.target_id); requireMutationAttempt(attempt);
      const result = await client.POST("/api/v1/tests", { params: { header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": '"0"', "X-CSRF-Token": "" } }, body: input, headers: scopeHeaders, signal });
      return requireDefinitionIntent(requireMutation(result, decodeTestDefinition), input.id, 1, { ...input, enabled: true });
    },
    async updateDefinition(id, version, input, attempt, signal) {
      requireRedTeamID(id); requireRedTeamID(input.target_id); requireVersion(version); requireMutationAttempt(attempt);
      const result = await client.PATCH("/api/v1/tests/{id}", { params: { path: { id }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": `"${version}"`, "X-CSRF-Token": "" } }, body: input, headers: scopeHeaders, signal });
      return requireDefinitionIntent(requireMutation(result, decodeTestDefinition), id, version + 1, input);
    },
    async runDefinition(id, version, runID, attempt, signal) {
      requireRedTeamID(id); requireRedTeamID(runID); requireVersion(version); requireMutationAttempt(attempt);
      const result = await client.POST("/api/v1/tests/{id}/runs", { params: { path: { id }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": `"${version}"`, "X-CSRF-Token": "" } }, body: { run_id: runID }, headers: scopeHeaders, signal });
      const value = requireMutation(result, decodeTestRun);
      if (value.id !== runID || value.definition_id !== id || value.definition_version !== version || value.version !== 1 || value.status !== "queued" || value.attempt !== 0 || value.cancel_requested) invalidRedTeamResponse();
      return value;
    },
    async listRuns(signal) { return loadRootCursorPages((cursor) => client.GET("/api/v1/test-runs", { params: { query: { cursor, limit: 100 } }, headers: scopeHeaders, signal }), decodeTestRunPage); },
    async getRun(id, signal) {
      requireRedTeamID(id);
      const value = requireVersioned(await client.GET("/api/v1/test-runs/{id}", { params: { path: { id } }, headers: scopeHeaders, signal }), decodeTestRunDetail);
      if (value.id !== id) invalidRedTeamResponse();
      return value;
    },
    async cancelRun(id, version, attempt, signal) {
      requireRedTeamID(id); requireVersion(version); requireMutationAttempt(attempt);
      const result = await client.POST("/api/v1/test-runs/{id}/cancel", { params: { path: { id }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": `"${version}"`, "X-CSRF-Token": "" } }, headers: scopeHeaders, signal });
      const value = requireMutation(result, decodeTestRun);
      if (value.id !== id || value.version !== version + 1 || !value.cancel_requested && value.status !== "cancelled") invalidRedTeamResponse();
      return value;
    },
    async preflightAttackLab(sourceRunID, signal) {
      requireProductID(sourceRunID); const value = requireAPIData(await client.GET("/api/v1/attack-lab/preflight", { params: { query: { source_run_id: sourceRunID } }, headers: scopeHeaders, signal }), decodeAttackLabPreflight); if (value.source_run_id !== sourceRunID) invalidAttackLabResponse(); return value;
    },
    async listAttackLabRuns(signal) { return loadRootCursorPages((cursor) => client.GET("/api/v1/attack-lab/runs", { params: { query: { cursor, limit: 100 } }, headers: scopeHeaders, signal }), decodeAttackLabRunPage); },
    async getAttackLabRun(id, signal) { requireProductID(id); const value = requireVersioned(await client.GET("/api/v1/attack-lab/runs/{id}", { params: { path: { id } }, headers: scopeHeaders, signal }), decodeAttackLabRunDetail); if (value.id !== id) invalidAttackLabResponse(); return value; },
    async createAttackLabRun(preflight, runID, attempt, signal) {
      const sourceRunID = preflight.source_run_id; requireProductID(sourceRunID); requireProductID(runID); if (sourceRunID === runID || !/^[0-9a-f]{64}$/.test(preflight.decision_digest) || /^0{64}$/.test(preflight.decision_digest)) invalidAttackLabConfiguration(); requireMutationAttempt(attempt); const result = await client.POST("/api/v1/attack-lab/runs", { params: { header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": '"0"', "X-CSRF-Token": "" } }, body: { run_id: runID, source_run_id: sourceRunID, decision_digest: preflight.decision_digest, approved: true }, headers: scopeHeaders, signal }); const value = requireMutation(result, decodeAttackLabRun); if (value.id !== runID || value.source_run_id !== sourceRunID || value.version !== 1 || value.status !== "queued" || value.attempt !== 0) invalidAttackLabResponse(); return value;
    },
    async cancelAttackLabRun(id, version, attempt, signal) {
      requireProductID(id); requireVersion(version); requireMutationAttempt(attempt); const result = await client.POST("/api/v1/attack-lab/runs/{id}/cancel", { params: { path: { id }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": `"${version}"`, "X-CSRF-Token": "" } }, headers: scopeHeaders, signal }); const value = requireMutation(result, decodeAttackLabRun); if (value.id !== id || value.version !== version + 1 || !value.cancel_requested && value.status !== "cancelled") invalidAttackLabResponse(); return value;
    },
    async rerunAttackLabRun(sourceRunID, version, runID, attempt, signal) {
      requireProductID(sourceRunID); requireProductID(runID); if (sourceRunID === runID) invalidAttackLabConfiguration(); requireVersion(version); requireMutationAttempt(attempt); const result = await client.POST("/api/v1/attack-lab/runs/{id}/rerun", { params: { path: { id: sourceRunID }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": `"${version}"`, "X-CSRF-Token": "" } }, body: { run_id: runID }, headers: scopeHeaders, signal }); const value = requireMutation(result, decodeAttackLabRun); if (value.id !== runID || value.version !== 1 || value.status !== "queued" || value.attempt !== 0) invalidAttackLabResponse(); return value;
    },
    async listTargets(signal) {
      const [agents, tools] = await Promise.all([
        loadAllCursorPages((cursor) => Promise.resolve(client.GET("/api/v1/agents", { params: { query: { cursor, limit: 100 } }, headers: scopeHeaders, signal })).then((result) => requireAPIData(result, decodeInventoryPage)), { maximumItems: 10_000, maximumPages: 100 }),
        loadAllCursorPages((cursor) => Promise.resolve(client.GET("/api/v1/tools", { params: { query: { cursor, limit: 100 } }, headers: scopeHeaders, signal })).then((result) => requireAPIData(result, decodeInventoryPage)), { maximumItems: 10_000, maximumPages: 100 }),
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
function requireDefinitionIntent(value: TestDefinition, id: string, version: number, input: TestDefinitionUpdateInput): TestDefinition {
  if (value.id !== id || value.version !== version || value.name !== input.name || value.target_id !== input.target_id || value.target_kind !== input.target_kind || value.enabled !== input.enabled || !sameStringSet(value.categories, input.categories) || value.safety.environment !== input.safety.environment || value.safety.credential_class !== input.safety.credential_class || !sameStringSet(value.safety.expected_side_effects, input.safety.expected_side_effects)) invalidRedTeamResponse();
  return value;
}
function sameStringSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && new Set(left).size === left.length && new Set(right).size === right.length && left.every((item) => right.includes(item));
}
function requireRedTeamID(value: string): void { if (!productID.test(value)) throw new APITransportError("invalid_configuration", "Invalid Red Team resource identity"); }
function invalidRedTeamResponse(): never { throw new APITransportError("invalid_response", "Red Team response contradicted its request authority"); }
function requireMutationAttempt(value: MutationAttempt): void { if (!idempotencyKey.test(value.idempotencyKey)) throw new APITransportError("invalid_configuration", "Invalid red team idempotency key"); }
function requireProductID(value: string): void { if (!productID.test(value)) invalidAttackLabConfiguration(); }
function invalidAttackLabConfiguration(): never { throw new APITransportError("invalid_configuration", "Invalid Attack Lab request configuration"); }
function invalidAttackLabResponse(): never { throw new APITransportError("invalid_response", "Attack Lab response contradicted its request authority"); }

export function redTeamProductID(): string { return `pid_${globalThis.crypto.randomUUID()}`; }
export function redTeamIdempotencyKey(): string { return `redteam_${globalThis.crypto.randomUUID()}`; }
