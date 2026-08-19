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

export async function executeWorkflowMutation<T>(send: (attempt: WorkflowMutationAttempt) => Promise<T>, attempt: WorkflowMutationAttempt = createWorkflowMutationAttempt()): Promise<T> {
  try { return await send(attempt); } catch (error) {
    const ambiguous = error instanceof TypeError || error instanceof APITransportError && ["timeout", "invalid_response", "invalid_error"].includes(error.kind);
    if (!ambiguous) throw error;
    return send(attempt);
  }
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
