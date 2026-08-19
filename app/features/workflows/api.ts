import type { APIClient } from "../../../apps/web/api/client";
import { APITransportError, requireAPIData } from "../../../apps/web/api/client";
import {
  decodeConnectorManifestPage,
  decodeIntegration,
  decodeIntegrationPage,
  decodePolicy,
  decodePolicyPage,
  decodePolicyRollout,
  decodePolicySimulation,
  decodeRuntimeDecisionPage,
  type Decoder,
} from "../../../apps/web/api/decoders";
import type {
  ConnectorManifest,
  Integration,
  IntegrationInput,
  IntegrationUpdateInput,
  Policy,
  PolicyRollout,
  PolicyRolloutInput,
  PolicySimulation,
  PolicySimulationInput,
  RuntimeDecision,
} from "../../../apps/web/api/generated";

const quotedVersion = /^"[1-9][0-9]*"$/;
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type Versioned<T> = { value: T; version: string };
export type WorkflowReceipt<T> = Versioned<T> & { auditID: string };
export type WorkflowMutationAttempt = Readonly<{ idempotencyKey: string }>;
export type RetainedWorkflowMutationController<I> = {
  execute<T>(intent: I, send: (intent: I, attempt: WorkflowMutationAttempt) => Promise<T>): Promise<T>;
  hasAmbiguousAttempt(): boolean;
  resolveAfterServerReconciliation(): void;
};

type APIResult<T> = { data?: T; error?: unknown; response: Response };

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
  if (!auditID || !productID.test(auditID)) throw new APITransportError("invalid_response", "Workflow response omitted a valid audit identifier");
  return { ...versioned, auditID };
}

export function createWorkflowMutationAttempt(): WorkflowMutationAttempt { return Object.freeze({ idempotencyKey: workflowIdempotencyKey() }); }

export function workflowMutationHeaders(attempt: WorkflowMutationAttempt, version?: string) {
  const headers: { "Idempotency-Key": string; "If-Match"?: string } = { "Idempotency-Key": attempt.idempotencyKey };
  if (version) headers["If-Match"] = version;
  return headers;
}

export function isAmbiguousWorkflowMutationError(error: unknown): boolean {
  return error instanceof TypeError || error instanceof APITransportError && ["timeout", "invalid_response", "invalid_error"].includes(error.kind);
}

export async function executeWorkflowMutation<T>(send: (attempt: WorkflowMutationAttempt) => Promise<T>, attempt: WorkflowMutationAttempt = createWorkflowMutationAttempt()): Promise<T> {
  try { return await send(attempt); } catch (error) {
    if (!isAmbiguousWorkflowMutationError(error)) throw error;
    return send(attempt);
  }
}

export function createRetainedWorkflowMutationController<I>(): RetainedWorkflowMutationController<I> {
  let pending: { attempt: WorkflowMutationAttempt; intent: I; send: (intent: I, attempt: WorkflowMutationAttempt) => Promise<unknown> } | undefined;
  let inFlight: Promise<unknown> | undefined;
  return {
    execute<T>(intent: I, send: (intent: I, attempt: WorkflowMutationAttempt) => Promise<T>): Promise<T> {
      if (!pending) pending = { attempt: createWorkflowMutationAttempt(), intent: canonicalFrozenIntent(intent), send };
      const active = pending;
      if (inFlight) return inFlight as Promise<T>;
      inFlight = executeWorkflowMutation((attempt) => active.send(active.intent, attempt), active.attempt).then(
        (result) => { if (pending === active) pending = undefined; return result; },
        (error: unknown) => { if (!isAmbiguousWorkflowMutationError(error) && pending === active) pending = undefined; throw error; },
      ).finally(() => { inFlight = undefined; });
      return inFlight as Promise<T>;
    },
    hasAmbiguousAttempt() { return pending !== undefined && inFlight === undefined; },
    resolveAfterServerReconciliation() {
      if (inFlight) throw new Error("Cannot reconcile a workflow mutation while its request is in flight");
      pending = undefined;
    },
  };
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
      return requireAPIData(await client.GET("/api/v1/policies", { signal }), decodePolicyPage).items;
    },
    async getPolicy(id: string, signal?: AbortSignal): Promise<Versioned<Policy>> {
      return requireWorkflowVersioned(await client.GET("/api/v1/policies/{id}", { params: { path: { id } }, signal }), decodePolicy);
    },
    async listPolicyDecisions(id: string, signal?: AbortSignal): Promise<readonly RuntimeDecision[]> {
      return requireAPIData(await client.GET("/api/v1/policies/{id}/decisions", { params: { path: { id } }, signal }), decodeRuntimeDecisionPage).items;
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
    async simulatePolicy(id: string, version: string, value: PolicySimulationInput, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<PolicySimulation>> {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.POST("/api/v1/policies/{id}/simulate", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } }, body: value }), decodePolicySimulation), attempt);
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
      return requireAPIData(await client.GET("/api/v1/integrations", { signal }), decodeIntegrationPage).items;
    },
    async getIntegration(id: string, signal?: AbortSignal): Promise<Versioned<Integration>> {
      return requireWorkflowVersioned(await client.GET("/api/v1/integrations/{id}", { params: { path: { id } }, signal }), decodeIntegration);
    },
    async createIntegration(value: IntegrationInput, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<Integration>> {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.POST("/api/v1/integrations", { params: { header: workflowMutationHeaders(active) }, body: value }), decodeIntegration), attempt);
    },
    async updateIntegration(id: string, version: string, value: IntegrationUpdateInput, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<Integration>> {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.PATCH("/api/v1/integrations/{id}", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } }, body: value }), decodeIntegration), attempt);
    },
    async deleteIntegration(id: string, version: string, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<void>> {
      return executeWorkflowMutation(async (active) => { const result = await client.DELETE("/api/v1/integrations/{id}", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } } }); if (result.error) requireAPIData<never>(result); return requireWorkflowEmptyReceipt(result.response); }, attempt);
    },
  };
}

export type IntegrationsAPI = ReturnType<typeof createIntegrationsAPI>;

export function requireWorkflowEmptyReceipt(response: Response): WorkflowReceipt<void> {
  const version = response.headers.get("ETag");
  const auditID = response.headers.get("X-Audit-ID");
  if (!version || !quotedVersion.test(version) || !auditID || !productID.test(auditID)) throw new APITransportError("invalid_response", "Workflow response omitted durable mutation headers");
  return { value: undefined, version, auditID };
}
