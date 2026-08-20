import type { APIClient } from "../../../apps/web/api/client";
import { APIProductError, APITransportError, requireAPIData } from "../../../apps/web/api/client";
import {
  decodeConnectorManifestPage,
  decodeFinding,
  decodeIntegration,
  decodeIntegrationFreshness,
  decodeIntegrationPage,
  decodeIntegrationSchedule,
  decodeIntegrationSync,
  decodeIntegrationSyncPage,
  decodePolicy,
  decodePolicyPage,
  decodePolicyRollout,
  decodeSecurityAgentDefinition,
  decodeWorkflowMutationReceiptPage,
  type Decoder,
} from "../../../apps/web/api/decoders";
import type {
  ConnectorManifest,
  Integration,
  IntegrationFreshness,
  IntegrationInput,
  IntegrationSchedule,
  IntegrationScheduleInput,
  IntegrationSync,
  IntegrationUpdateInput,
  Policy,
  PolicyRollout,
  PolicyRolloutInput,
  WorkflowMutationReceipt,
} from "../../../apps/web/api/generated";

const quotedVersion = /^"[1-9][0-9]*"$/;
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type Versioned<T> = { value: T; version: string };
export type WorkflowReceipt<T> = Versioned<T> & { auditID: string; receiptID: string };
export type WorkflowMutationAttempt = Readonly<{ idempotencyKey: string }>;
export type KnownWorkflowMutationPending = Readonly<{
  kind: "integration_revocation";
  receipt: WorkflowReceipt<Integration>;
  retryNotBefore: number;
}> | Readonly<{
  kind: "reference_authorization_conflict";
  integrationID: string;
}> | Readonly<{
  kind: "integration_discovery_conflict";
  integrationID: string;
  resource: "sync" | "schedule";
}>;
export class IntegrationRevocationPending extends Error {
  readonly receipt: WorkflowReceipt<Integration>;
  readonly retryAfterSeconds: number;

  constructor(receipt: WorkflowReceipt<Integration>, retryAfterSeconds: number) {
    super("Integration provider revocation is pending");
    this.name = "IntegrationRevocationPending";
    this.receipt = receipt;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}
export class ReferenceAuthorizationConflict extends Error {
  readonly integrationID: string;

  constructor(integrationID: string) {
    super("Reference authorization requires authoritative conflict reconciliation");
    this.name = "ReferenceAuthorizationConflict";
    this.integrationID = integrationID;
  }
}
export class IntegrationDiscoveryConflict extends Error {
  readonly integrationID: string;
  readonly resource: "sync" | "schedule";

  constructor(integrationID: string, resource: "sync" | "schedule") {
    super("Integration discovery mutation requires authoritative conflict reconciliation");
    this.name = "IntegrationDiscoveryConflict";
    this.integrationID = integrationID;
    this.resource = resource;
  }
}
export type RetainedWorkflowMutationController<I> = {
  execute<T>(intent: I, send: (intent: I, attempt: WorkflowMutationAttempt) => Promise<T>): Promise<T>;
  retry<T>(): Promise<T>;
  hasAmbiguousAttempt(): boolean;
  isUnresolved(): boolean;
  canRetry(): boolean;
  knownPending(): KnownWorkflowMutationPending | null;
  retainedIntent(): I | null;
  resolveAfterServerReconciliation(): void;
};

type APIResult<T> = { data?: T; error?: unknown; response: Response };
type WorkflowPage<T> = { readonly items: readonly T[]; readonly page_info: { readonly next_cursor: string; readonly has_more: true } | { readonly next_cursor: null; readonly has_more: false } };

export function workflowIdempotencyKey(): string {
  return `wf_${globalThis.crypto.randomUUID()}`;
}

export function requireWorkflowVersioned<T>(result: APIResult<unknown>, decode: Decoder<T>): Versioned<T> {
  const value = requireAPIData<T>(result, decode);
  const version = result.response.headers.get("ETag");
  if (!version || !quotedVersion.test(version)) throw new APITransportError("invalid_response", "Workflow response omitted a valid resource version");
  return { value, version };
}

export function requireWorkflowReceipt<T>(result: APIResult<unknown>, decode: Decoder<T>): WorkflowReceipt<T> {
	const versioned = requireWorkflowVersioned<T>(result, decode);
  const auditID = result.response.headers.get("X-Audit-ID");
  const receiptID = result.response.headers.get("X-Mutation-Receipt-ID");
  if (!auditID || !productID.test(auditID)) throw new APITransportError("invalid_response", "Workflow response omitted a valid audit identifier");
  if (!receiptID || !productID.test(receiptID)) throw new APITransportError("invalid_response", "Workflow response omitted a valid mutation receipt identifier");
  return { ...versioned, auditID, receiptID };
}

export function createWorkflowMutationAttempt(): WorkflowMutationAttempt { return Object.freeze({ idempotencyKey: workflowIdempotencyKey() }); }

export function workflowMutationHeaders(attempt: WorkflowMutationAttempt, version?: string) {
  const headers: { "Idempotency-Key": string; "If-Match"?: string } = { "Idempotency-Key": attempt.idempotencyKey };
  if (version) headers["If-Match"] = version;
  return headers;
}

export function isAmbiguousWorkflowMutationError(error: unknown): boolean {
  return error instanceof TypeError
    || error instanceof APIProductError && error.product.retryable
    || error instanceof APITransportError && ["timeout", "invalid_response", "invalid_error"].includes(error.kind);
}

function isRetainableWorkflowMutationError(error: unknown): boolean {
  return error instanceof IntegrationRevocationPending || error instanceof ReferenceAuthorizationConflict || error instanceof IntegrationDiscoveryConflict || isAmbiguousWorkflowMutationError(error);
}

export async function executeWorkflowMutation<T>(send: (attempt: WorkflowMutationAttempt) => Promise<T>, attempt: WorkflowMutationAttempt = createWorkflowMutationAttempt()): Promise<T> {
  try { return await send(attempt); } catch (error) {
    if (!isAmbiguousWorkflowMutationError(error)) throw error;
    return send(attempt);
  }
}

export function createRetainedWorkflowMutationController<I>(): RetainedWorkflowMutationController<I> {
  let pending: { attempt: WorkflowMutationAttempt; intent: I; send: (intent: I, attempt: WorkflowMutationAttempt) => Promise<unknown>; known?: KnownWorkflowMutationPending } | undefined;
  let inFlight: Promise<unknown> | undefined;
  return {
    execute<T>(intent: I, send: (intent: I, attempt: WorkflowMutationAttempt) => Promise<T>): Promise<T> {
      const frozenIntent = canonicalFrozenIntent(intent);
      if (pending) {
        if (JSON.stringify(frozenIntent) !== JSON.stringify(pending.intent)) return Promise.reject(new Error("A different workflow mutation is already unresolved"));
        if (!inFlight) return Promise.reject(new Error("Retry the retained workflow mutation explicitly"));
      } else {
        pending = { attempt: createWorkflowMutationAttempt(), intent: frozenIntent, send };
      }
      const active = pending;
      if (inFlight) return inFlight as Promise<T>;
      inFlight = active.send(active.intent, active.attempt).then(
        (result) => { if (pending === active) pending = undefined; return result; },
        (error: unknown) => {
          if (error instanceof IntegrationRevocationPending && pending === active) active.known = knownIntegrationRevocation(error);
          if (error instanceof ReferenceAuthorizationConflict && pending === active) active.known = knownReferenceAuthorizationConflict(error);
          if (error instanceof IntegrationDiscoveryConflict && pending === active) active.known = knownIntegrationDiscoveryConflict(error);
          if (!isRetainableWorkflowMutationError(error) && pending === active) pending = undefined;
          throw error;
        },
      ).finally(() => { inFlight = undefined; });
      return inFlight as Promise<T>;
    },
    retry<T>(): Promise<T> {
      if (!pending || inFlight) throw new Error("No settled ambiguous workflow mutation is available to retry");
      const active = pending;
      inFlight = active.send(active.intent, active.attempt).then(
        (result) => { if (pending === active) pending = undefined; return result; },
        (error: unknown) => {
          if (error instanceof IntegrationRevocationPending && pending === active) active.known = knownIntegrationRevocation(error);
          if (error instanceof ReferenceAuthorizationConflict && pending === active) active.known = knownReferenceAuthorizationConflict(error);
          if (error instanceof IntegrationDiscoveryConflict && pending === active) active.known = knownIntegrationDiscoveryConflict(error);
          if (!isRetainableWorkflowMutationError(error) && pending === active) pending = undefined;
          throw error;
        },
      ).finally(() => { inFlight = undefined; });
      return inFlight as Promise<T>;
    },
    hasAmbiguousAttempt() { return pending !== undefined && inFlight === undefined; },
    isUnresolved() { return pending !== undefined; },
    canRetry() { return pending !== undefined && inFlight === undefined; },
    knownPending() { return pending?.known ?? null; },
    retainedIntent() { return pending?.intent ?? null; },
    resolveAfterServerReconciliation() {
      if (inFlight) throw new Error("Cannot reconcile a workflow mutation while its request is in flight");
      pending = undefined;
    },
  };
}

function knownIntegrationRevocation(error: IntegrationRevocationPending): KnownWorkflowMutationPending {
  return Object.freeze({ kind: "integration_revocation", receipt: error.receipt, retryNotBefore: Date.now() + error.retryAfterSeconds * 1_000 });
}

function knownReferenceAuthorizationConflict(error: ReferenceAuthorizationConflict): KnownWorkflowMutationPending {
  return Object.freeze({ kind: "reference_authorization_conflict", integrationID: error.integrationID });
}

function knownIntegrationDiscoveryConflict(error: IntegrationDiscoveryConflict): KnownWorkflowMutationPending {
  return Object.freeze({ kind: "integration_discovery_conflict", integrationID: error.integrationID, resource: error.resource });
}

function canonicalFrozenIntent<I>(intent: I): I {
  const serialized = JSON.stringify(canonicalJSONValue(intent));
  if (serialized === undefined) throw new TypeError("Workflow mutation intent must be a JSON value");
  return deepFreeze(JSON.parse(serialized) as I);
}

function canonicalJSONValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalJSONValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .filter(([, nested]) => nested !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => [key, canonicalJSONValue(nested)]));
  }
  return value;
}

function deepFreeze<I>(value: I): I {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

export function createPoliciesAPI(client: APIClient) {
  return {
    async listPolicies(signal?: AbortSignal): Promise<readonly Policy[]> {
      return loadAllWorkflowPages((cursor) => client.GET("/api/v1/policies", { params: { query: { cursor, limit: 100 } }, signal }), decodePolicyPage);
    },
    async getPolicy(id: string, signal?: AbortSignal): Promise<Versioned<Policy>> {
      return requireWorkflowVersioned(await client.GET("/api/v1/policies/{id}", { params: { path: { id } }, signal }), decodePolicy);
    },
    async createPolicy(value: Policy, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<Policy>> {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.POST("/api/v1/policies", { params: { header: workflowMutationHeaders(active) }, body: value }), decodePolicy), attempt);
    },
    async updatePolicy(id: string, version: string, value: Policy, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<Policy>> {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.PATCH("/api/v1/policies/{id}", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } }, body: value }), decodePolicy), attempt);
    },
    async deletePolicy(id: string, version: string, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<void>> {
      return executeWorkflowMutation(async (active) => { const result = await client.DELETE("/api/v1/policies/{id}", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } } }); if (result.error) requireAPIData<never>(result); return requireWorkflowEmptyReceipt(result.response); }, attempt);
    },
    async rolloutPolicy(id: string, version: string, value: PolicyRolloutInput, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<PolicyRollout>> {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.POST("/api/v1/policies/{id}/rollout", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } }, body: value }), decodePolicyRollout), attempt);
    },
    async disablePolicy(id: string, version: string, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<PolicyRollout>> {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.POST("/api/v1/policies/{id}/disable", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } }, body: {} }), decodePolicyRollout), attempt);
    },
  };
}

export type PoliciesAPI = ReturnType<typeof createPoliciesAPI>;

export function createIntegrationsAPI(client: APIClient) {
  return {
    async listCatalog(signal?: AbortSignal): Promise<readonly ConnectorManifest[]> {
      return requireAPIData(await client.GET("/api/v1/integration-catalog", { signal }), decodeConnectorManifestPage).items;
    },
    async listIntegrations(signal?: AbortSignal): Promise<readonly Integration[]> {
      return loadAllWorkflowPages((cursor) => client.GET("/api/v1/integrations", { params: { query: { cursor, limit: 100 } }, signal }), decodeIntegrationPage);
    },
    async getIntegration(id: string, signal?: AbortSignal): Promise<Versioned<Integration>> {
      const integration = requireWorkflowVersioned(await client.GET("/api/v1/integrations/{id}", { params: { path: { id } }, signal }), decodeIntegration);
      if (integration.value.id !== id) throw new APITransportError("invalid_response", "Integration detail returned a different resource");
      return integration;
    },
    async getIntegrationFreshness(id: string, signal?: AbortSignal): Promise<Versioned<IntegrationFreshness>> {
      const result = await client.GET("/api/v1/integrations/{id}/freshness", { params: { path: { id } }, signal });
      const freshness = requireNoStoreVersioned(result, decodeIntegrationFreshness);
      if (freshness.value.integration_id !== id || freshness.version !== `"${freshness.value.version}"`) throw new APITransportError("invalid_response", "Integration freshness returned a different resource version");
      return freshness;
    },
    async getIntegrationSchedule(id: string, signal?: AbortSignal): Promise<Versioned<IntegrationSchedule> | null> {
      try {
        const result = await client.GET("/api/v1/integrations/{id}/schedule", { params: { path: { id } }, signal });
        const schedule = requireNoStoreVersioned(result, decodeIntegrationSchedule);
        if (schedule.value.integration_id !== id || schedule.version !== `"${schedule.value.version}"` || schedule.value.state === "deleted") throw new APITransportError("invalid_response", "Integration schedule returned a different resource version");
        return schedule;
      } catch (error) {
        if (error instanceof APIProductError && error.status === 404 && error.product.code === "not_found") return null;
        throw error;
      }
    },
    async listIntegrationSyncs(id: string, signal?: AbortSignal): Promise<readonly IntegrationSync[]> {
      return loadAllWorkflowPages(
        async (cursor) => {
          const result = await client.GET("/api/v1/integrations/{id}/syncs", { params: { path: { id }, query: { cursor, limit: 100 } }, signal });
          if (result.response.headers.get("Cache-Control") !== "no-store") throw new APITransportError("invalid_response", "Integration sync history was cacheable");
          return result;
        },
        (value) => {
          const page = decodeIntegrationSyncPage(value);
          if (page.items.some((sync) => sync.integration_id !== id)) throw new Error("schema mismatch");
          return page;
        },
      );
    },
    async getIntegrationSync(id: string, syncID: string, signal?: AbortSignal): Promise<Versioned<IntegrationSync>> {
      const result = await client.GET("/api/v1/integrations/{id}/syncs/{syncId}", { params: { path: { id, syncId: syncID } }, signal });
      const sync = requireNoStoreVersioned(result, decodeIntegrationSync);
      if (sync.value.id !== syncID || sync.value.integration_id !== id) throw new APITransportError("invalid_response", "Integration sync detail returned a different resource");
      return sync;
    },
    async createIntegration(value: IntegrationInput, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<Integration>> {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.POST("/api/v1/integrations", { params: { header: workflowMutationHeaders(active) }, body: value }), decodeIntegration), attempt);
    },
    async updateIntegration(id: string, version: string, value: IntegrationUpdateInput, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<Integration>> {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.PATCH("/api/v1/integrations/{id}", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } }, body: value }), decodeIntegration), attempt);
    },
    async authorizeIntegrationReference(id: string, version: string, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<Integration>> {
      return executeWorkflowMutation(async (active) => {
        try {
          // CSRF and expected scope remain transport-owned. Fresh auth is an
          // explicit assertion from the capability- and freshness-gated UI.
          const params = { path: { id }, header: { ...workflowMutationHeaders(active, version), "X-Zasp-Fresh-Auth": "confirmed" } } as never;
          const result = await client.POST("/api/v1/integrations/{id}/reference-authorization", { params, body: {} });
          const receipt = requireWorkflowReceipt(result, decodeIntegration);
          if (result.response.status !== 200 || result.response.headers.get("Cache-Control") !== "no-store") {
            throw new APITransportError("invalid_response", "Reference authorization returned invalid response metadata");
          }
          if (receipt.value.id !== id || !isReferenceConnector(receipt.value.connector_key) || receipt.value.status !== "active") {
            throw new APITransportError("invalid_response", "Reference authorization returned an invalid integration");
          }
          requireNextWorkflowVersion(version, receipt.version);
          return receipt;
        } catch (error) {
          if (error instanceof APIProductError && error.status === 409) throw new ReferenceAuthorizationConflict(id);
          throw error;
        }
      }, attempt);
    },
    async syncIntegration(id: string, integrationVersion: string, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<IntegrationSync>> {
      return executeWorkflowMutation(async (active) => {
        try {
          const result = await client.POST("/api/v1/integrations/{id}/sync", { params: { path: { id }, header: workflowMutationHeaders(active, integrationVersion) as { "Idempotency-Key": string; "If-Match": string } }, body: {} });
          const receipt = requireWorkflowReceipt(result, decodeIntegrationSync);
          if (result.response.status !== 202 || result.response.headers.get("Cache-Control") !== "no-store" || receipt.value.integration_id !== id || receipt.value.trigger_kind !== "manual" || receipt.value.status !== "queued" || receipt.value.attempt !== 0 || receipt.value.discovered_count !== 0 || receipt.value.changed_count !== 0 || receipt.value.removed_count !== 0) {
            throw new APITransportError("invalid_response", "Integration sync returned invalid durable acceptance metadata");
          }
          return receipt;
        } catch (error) {
          if (error instanceof APIProductError && error.status === 409) throw new IntegrationDiscoveryConflict(id, "sync");
          throw error;
        }
      }, attempt);
    },
    async putIntegrationSchedule(id: string, version: string, value: IntegrationScheduleInput, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<IntegrationSchedule>> {
      return executeWorkflowMutation(async (active) => {
        try {
          const result = await client.PUT("/api/v1/integrations/{id}/schedule", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } }, body: value });
          const receipt = requireWorkflowReceipt(result, decodeIntegrationSchedule);
          if (result.response.status !== 200 || result.response.headers.get("Cache-Control") !== "no-store" || receipt.value.integration_id !== id || receipt.value.state !== value.state || receipt.value.cadence_seconds !== value.cadence_seconds || receipt.version !== `"${receipt.value.version}"`) {
            throw new APITransportError("invalid_response", "Integration schedule returned invalid durable mutation metadata");
          }
          requireNextScheduleVersion(version, receipt.version);
          return receipt;
        } catch (error) {
          if (error instanceof APIProductError && error.status === 409) throw new IntegrationDiscoveryConflict(id, "schedule");
          throw error;
        }
      }, attempt);
    },
    async deleteIntegrationSchedule(id: string, version: string, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<void>> {
      return executeWorkflowMutation(async (active) => {
        try {
          const result = await client.DELETE("/api/v1/integrations/{id}/schedule", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } } });
          if (result.error) requireAPIData<never>(result);
          if (result.response.status !== 204 || result.data !== undefined || result.response.headers.get("Cache-Control") !== "no-store") throw new APITransportError("invalid_response", "Integration schedule deletion returned invalid durable mutation metadata");
          const receipt = requireWorkflowEmptyReceipt(result.response);
          requireNextScheduleVersion(version, receipt.version);
          return receipt;
        } catch (error) {
          if (error instanceof APIProductError && error.status === 409) throw new IntegrationDiscoveryConflict(id, "schedule");
          throw error;
        }
      }, attempt);
    },
    async deleteIntegration(id: string, version: string, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<void>> {
      return executeWorkflowMutation(async (active) => requireIntegrationDeletion(await client.DELETE("/api/v1/integrations/{id}", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } } }), id), attempt);
    },
  };
}

export type IntegrationsAPI = ReturnType<typeof createIntegrationsAPI>;

function isReferenceConnector(value: string): value is "aws" | "kubernetes" {
  return value === "aws" || value === "kubernetes";
}

function requireNextWorkflowVersion(previous: string, next: string): void {
  const previousValue = Number(previous.slice(1, -1));
  const nextValue = Number(next.slice(1, -1));
  if (!quotedVersion.test(previous) || !quotedVersion.test(next) || !Number.isSafeInteger(previousValue) || !Number.isSafeInteger(nextValue) || nextValue !== previousValue + 1) {
    throw new APITransportError("invalid_response", "Workflow mutation response did not advance the resource by exactly one version");
  }
}

function requireNextScheduleVersion(previous: string, next: string): void {
  const scheduleVersion = /^"[0-9]+"$/;
  const previousValue = Number(previous.slice(1, -1));
  const nextValue = Number(next.slice(1, -1));
  if (!scheduleVersion.test(previous) || !quotedVersion.test(next) || !Number.isSafeInteger(previousValue) || !Number.isSafeInteger(nextValue) || nextValue !== previousValue + 1) {
    throw new APITransportError("invalid_response", "Schedule mutation response did not advance the resource by exactly one version");
  }
}

function requireNoStoreVersioned<T>(result: APIResult<unknown>, decode: Decoder<T>): Versioned<T> {
  const versioned = requireWorkflowVersioned(result, decode);
  if (result.response.headers.get("Cache-Control") !== "no-store") throw new APITransportError("invalid_response", "Workflow detail response was cacheable");
  return versioned;
}

export function createWorkflowRecoveryAPI(client: APIClient, capturedScopeKey = "component-local-scope") {
  if (!capturedScopeKey) throw new APITransportError("invalid_configuration", "Workflow recovery scope is required");
  return {
    async listReceipts(signal?: AbortSignal): Promise<readonly WorkflowMutationReceipt[]> {
	  return requireAPIData(await client.GET("/api/v1/workflow-mutation-receipts", { params: { query: { limit: 50 } }, headers: { "X-Zasp-Expected-Scope": capturedScopeKey }, signal }), (value) => decodeWorkflowMutationReceiptPage(value, capturedScopeKey)).items;
    },
    async acknowledgeReceipt(id: string): Promise<void> {
      // Keep each recovery service tied to the immutable scope identity that
      // created it. The provider replaces the service when scope generation
      // changes, and the mutation registry rejects results from the old one.
      void capturedScopeKey;
      // The shared transport injects the current vault-held CSRF value. The
      // generated operation type cannot express transport-owned headers.
      const params = { path: { id } } as never;
	  const result = await client.POST("/api/v1/workflow-mutation-receipts/{id}/acknowledge", { params, headers: { "X-Zasp-Expected-Scope": capturedScopeKey }, body: {} });
      if (result.error) requireAPIData<never>(result);
      if (result.response.status !== 204) throw new APITransportError("invalid_response", "Mutation receipt acknowledgement returned an invalid response");
    },
  };
}

export type WorkflowRecoveryAPI = ReturnType<typeof createWorkflowRecoveryAPI>;

export function createWorkflowReceiptReconciler(client: APIClient, capturedScopeKey: string) {
  if (!capturedScopeKey) throw new APITransportError("invalid_configuration", "Workflow recovery scope is required");
  const headers = { "X-Zasp-Expected-Scope": capturedScopeKey };
  return async (receipt: WorkflowMutationReceipt, signal: AbortSignal): Promise<void> => {
    const expectedVersion = `"${receipt.resource_version}"`;
    switch (receipt.operation as string) {
      case "syncIntegration": {
        const intent = receipt.intent as { integration_id: string };
        const value = requireNoStoreVersioned(await client.GET("/api/v1/integrations/{id}/syncs/{syncId}", { params: { path: { id: intent.integration_id, syncId: receipt.resource_id } }, headers, signal }), decodeIntegrationSync);
        if (value.value.id !== receipt.resource_id || value.value.integration_id !== intent.integration_id) throw new APITransportError("invalid_response", "Recovered integration sync returned a different resource");
        requireRecoveredVersion(value.version, expectedVersion);
        return;
      }
      case "putIntegrationSchedule": {
        const intent = receipt.intent as { integration_id: string };
        const value = requireNoStoreVersioned(await client.GET("/api/v1/integrations/{id}/schedule", { params: { path: { id: intent.integration_id } }, headers, signal }), decodeIntegrationSchedule);
        if (value.value.integration_id !== intent.integration_id || value.value.state === "deleted") throw new APITransportError("invalid_response", "Recovered integration schedule returned a different resource");
        requireRecoveredVersion(value.version, expectedVersion);
        return;
      }
      case "deleteIntegrationSchedule": {
        const intent = receipt.intent as { integration_id: string };
        return requireRecoveredDeletion(await client.GET("/api/v1/integrations/{id}/schedule", { params: { path: { id: intent.integration_id } }, headers, signal }));
      }
      case "createPolicy": case "updatePolicy": case "rolloutPolicy": case "disablePolicy": {
        const value = requireWorkflowVersioned(await client.GET("/api/v1/policies/{id}", { params: { path: { id: receipt.resource_id } }, headers, signal }), decodePolicy);
        requireRecoveredVersion(value.version, expectedVersion);
        return;
      }
      case "deletePolicy":
        return requireRecoveredDeletion(await client.GET("/api/v1/policies/{id}", { params: { path: { id: receipt.resource_id } }, headers, signal }));
      case "createIntegration": case "updateIntegration": case "completeIntegrationReferenceAuthorization": {
        const value = requireWorkflowVersioned(await client.GET("/api/v1/integrations/{id}", { params: { path: { id: receipt.resource_id } }, headers, signal }), decodeIntegration);
        requireRecoveredVersion(value.version, expectedVersion);
        return;
      }
      case "deleteIntegration":
        return requireRecoveredDeletion(await client.GET("/api/v1/integrations/{id}", { params: { path: { id: receipt.resource_id } }, headers, signal }));
      case "createSecurityAgent": case "updateSecurityAgent": {
        const value = requireWorkflowVersioned(await client.GET("/api/v1/security-agents/{id}", { params: { path: { id: receipt.resource_id } }, headers, signal }), decodeSecurityAgentDefinition);
        requireRecoveredVersion(value.version, expectedVersion);
        return;
      }
      case "deleteSecurityAgent":
        return requireRecoveredDeletion(await client.GET("/api/v1/security-agents/{id}", { params: { path: { id: receipt.resource_id } }, headers, signal }));
      case "updateFinding": case "acceptFindingRisk": {
        const value = requireWorkflowVersioned(await client.GET("/api/v1/findings/{id}", { params: { path: { id: receipt.resource_id } }, headers, signal }), decodeFinding);
        requireRecoveredVersion(value.version, expectedVersion);
        return;
      }
    }
  };
}

function requireRecoveredVersion(actual: string, expected: string): void {
  if (actual !== expected) throw new APITransportError("invalid_response", "Authoritative resource version does not match the committed receipt");
}

function requireRecoveredDeletion(result: APIResult<unknown>): void {
  try {
    requireAPIData(result);
  } catch (error) {
    if (error instanceof APIProductError && error.status === 404 && error.product.code === "not_found") return;
    throw error;
  }
  throw new APITransportError("invalid_response", "Authoritative resource still exists after the committed deletion");
}

async function loadAllWorkflowPages<T>(request: (cursor?: string) => Promise<APIResult<unknown>>, decode: Decoder<WorkflowPage<T>>): Promise<readonly T[]> {
  const items: T[] = [];
  let cursor: string | undefined;
  for (let pageNumber = 0; pageNumber < 100; pageNumber++) {
    const page = requireAPIData(await request(cursor), decode);
    items.push(...page.items);
    if (!page.page_info.has_more) return items;
    cursor = page.page_info.next_cursor;
  }
  throw new APITransportError("invalid_response", "Workflow pagination exceeded its bounded page count");
}

export function requireWorkflowEmptyReceipt(response: Response): WorkflowReceipt<void> {
  const version = response.headers.get("ETag");
  const auditID = response.headers.get("X-Audit-ID");
  const receiptID = response.headers.get("X-Mutation-Receipt-ID");
  if (!version || !quotedVersion.test(version) || !auditID || !productID.test(auditID) || !receiptID || !productID.test(receiptID)) throw new APITransportError("invalid_response", "Workflow response omitted durable mutation headers");
  return { value: undefined, version, auditID, receiptID };
}

function requireIntegrationDeletion(result: APIResult<unknown>, requestedID: string): WorkflowReceipt<void> {
  if (result.error) requireAPIData<never>(result);
  if (result.response.status === 202) {
    const receipt = requireWorkflowReceipt(result, decodeIntegration);
    const retryAfter = result.response.headers.get("Retry-After");
    if (receipt.value.id !== requestedID || receipt.value.status !== "revoking" || !retryAfter || !/^[1-9][0-9]{0,2}$/.test(retryAfter)) {
      throw new APITransportError("invalid_response", "Integration deletion returned invalid revocation progress");
    }
    throw new IntegrationRevocationPending(receipt, Number(retryAfter));
  }
  if (result.response.status !== 204 || result.data !== undefined) {
    throw new APITransportError("invalid_response", "Integration deletion returned an invalid terminal response");
  }
  return requireWorkflowEmptyReceipt(result.response);
}
