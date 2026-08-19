import type { APIClient } from "../../../apps/web/api/client";
import { APITransportError, requireAPIData } from "../../../apps/web/api/client";
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
  Sensor,
  SensorCoverage,
  SensorEnrollment,
  SensorInput,
} from "../../../apps/web/api/generated";

const quotedVersion = /^"[1-9][0-9]*"$/;
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type Versioned<T> = { value: T; version: string };
export type WorkflowReceipt<T> = Versioned<T> & { auditID: string };

type APIResult<T> = { data?: T; error?: unknown; response: Response };

export function workflowIdempotencyKey(): string {
  return `wf_${globalThis.crypto.randomUUID()}`;
}

function requireVersioned<T>(result: APIResult<unknown>): Versioned<T> {
  const value = requireAPIData<T>(result);
  const version = result.response.headers.get("ETag");
  if (!version || !quotedVersion.test(version)) throw new APITransportError("invalid_response", "Workflow response omitted a valid resource version");
  return { value, version };
}

function requireReceipt<T>(result: APIResult<unknown>): WorkflowReceipt<T> {
	const versioned = requireVersioned<T>(result);
  const auditID = result.response.headers.get("X-Audit-ID");
  if (!auditID || !productID.test(auditID)) throw new APITransportError("invalid_response", "Workflow response omitted a valid audit identifier");
  return { ...versioned, auditID };
}

function mutationHeaders(version?: string) {
  const headers: { "Idempotency-Key": string; "If-Match"?: string } = { "Idempotency-Key": workflowIdempotencyKey() };
  if (version) headers["If-Match"] = version;
  return headers;
}

export function createPoliciesAPI(client: APIClient) {
  return {
    async listPolicies(signal?: AbortSignal): Promise<readonly Policy[]> {
      return requireAPIData<{ items: readonly Policy[] }>(await client.GET("/api/v1/policies", { signal })).items;
    },
    async getPolicy(id: string, signal?: AbortSignal): Promise<Versioned<Policy>> {
      return requireVersioned<Policy>(await client.GET("/api/v1/policies/{id}", { params: { path: { id } }, signal }));
    },
    async listPolicyDecisions(id: string, signal?: AbortSignal): Promise<readonly RuntimeDecision[]> {
      return requireAPIData<{ items: readonly RuntimeDecision[] }>(await client.GET("/api/v1/policies/{id}/decisions", { params: { path: { id } }, signal })).items;
    },
    async createPolicy(value: Policy): Promise<WorkflowReceipt<Policy>> {
      return requireReceipt<Policy>(await client.POST("/api/v1/policies", { params: { header: mutationHeaders() }, body: value }));
    },
    async updatePolicy(id: string, version: string, value: Policy): Promise<WorkflowReceipt<Policy>> {
      return requireReceipt<Policy>(await client.PATCH("/api/v1/policies/{id}", { params: { path: { id }, header: mutationHeaders(version) as { "Idempotency-Key": string; "If-Match": string } }, body: value }));
    },
    async deletePolicy(id: string, version: string): Promise<WorkflowReceipt<void>> {
      const result = await client.DELETE("/api/v1/policies/{id}", { params: { path: { id }, header: mutationHeaders(version) as { "Idempotency-Key": string; "If-Match": string } } });
      if (result.error) requireAPIData<never>(result);
      return requireEmptyReceipt(result.response);
    },
    async simulatePolicy(id: string, version: string, value: PolicySimulationInput): Promise<WorkflowReceipt<PolicySimulation>> {
      return requireReceipt<PolicySimulation>(await client.POST("/api/v1/policies/{id}/simulate", { params: { path: { id }, header: mutationHeaders(version) as { "Idempotency-Key": string; "If-Match": string } }, body: value }));
    },
    async rolloutPolicy(id: string, version: string, value: PolicyRolloutInput): Promise<WorkflowReceipt<PolicyRollout>> {
      return requireReceipt<PolicyRollout>(await client.POST("/api/v1/policies/{id}/rollout", { params: { path: { id }, header: mutationHeaders(version) as { "Idempotency-Key": string; "If-Match": string } }, body: value }));
    },
    async disablePolicy(id: string, version: string): Promise<WorkflowReceipt<PolicyRollout>> {
      return requireReceipt<PolicyRollout>(await client.POST("/api/v1/policies/{id}/disable", { params: { path: { id }, header: mutationHeaders(version) as { "Idempotency-Key": string; "If-Match": string } }, body: {} }));
    },
  };
}

export type PoliciesAPI = ReturnType<typeof createPoliciesAPI>;

export function createIntegrationsAPI(client: APIClient) {
  return {
    async listCatalog(signal?: AbortSignal): Promise<readonly ConnectorManifest[]> {
      return requireAPIData<{ items: readonly ConnectorManifest[] }>(await client.GET("/api/v1/integration-catalog", { signal })).items;
    },
    async listIntegrations(signal?: AbortSignal): Promise<readonly Integration[]> {
      return requireAPIData<{ items: readonly Integration[] }>(await client.GET("/api/v1/integrations", { signal })).items;
    },
    async getIntegration(id: string, signal?: AbortSignal): Promise<Versioned<Integration>> {
      return requireVersioned<Integration>(await client.GET("/api/v1/integrations/{id}", { params: { path: { id } }, signal }));
    },
    async createIntegration(value: IntegrationInput): Promise<WorkflowReceipt<Integration>> {
      return requireReceipt<Integration>(await client.POST("/api/v1/integrations", { params: { header: mutationHeaders() }, body: value }));
    },
    async updateIntegration(id: string, version: string, value: IntegrationUpdateInput): Promise<WorkflowReceipt<Integration>> {
      return requireReceipt<Integration>(await client.PATCH("/api/v1/integrations/{id}", { params: { path: { id }, header: mutationHeaders(version) as { "Idempotency-Key": string; "If-Match": string } }, body: value }));
    },
    async deleteIntegration(id: string, version: string): Promise<WorkflowReceipt<void>> {
      const result = await client.DELETE("/api/v1/integrations/{id}", { params: { path: { id }, header: mutationHeaders(version) as { "Idempotency-Key": string; "If-Match": string } } });
      if (result.error) requireAPIData<never>(result);
      return requireEmptyReceipt(result.response);
    },
  };
}

export type IntegrationsAPI = ReturnType<typeof createIntegrationsAPI>;

export function createSensorsAPI(client: APIClient) {
  return {
    async listSensors(signal?: AbortSignal): Promise<readonly Sensor[]> {
      return requireAPIData<{ items: readonly Sensor[] }>(await client.GET("/api/v1/sensors", { signal })).items;
    },
    async getSensor(id: string, signal?: AbortSignal): Promise<Versioned<Sensor>> {
      return requireVersioned<Sensor>(await client.GET("/api/v1/sensors/{id}", { params: { path: { id } }, signal }));
    },
    async getCoverage(id: string, signal?: AbortSignal): Promise<SensorCoverage> {
      return requireAPIData<SensorCoverage>(await client.GET("/api/v1/sensors/{id}/coverage", { params: { path: { id } }, signal }));
    },
    async createSensor(value: SensorInput): Promise<WorkflowReceipt<SensorEnrollment>> {
      return requireReceipt<SensorEnrollment>(await client.POST("/api/v1/sensors", { params: { header: mutationHeaders() }, body: value }));
    },
    async updateSensor(id: string, version: string, value: SensorInput): Promise<WorkflowReceipt<Sensor>> {
      return requireReceipt<Sensor>(await client.PATCH("/api/v1/sensors/{id}", { params: { path: { id }, header: mutationHeaders(version) as { "Idempotency-Key": string; "If-Match": string } }, body: value }));
    },
    async deleteSensor(id: string, version: string): Promise<WorkflowReceipt<void>> {
      const result = await client.DELETE("/api/v1/sensors/{id}", { params: { path: { id }, header: mutationHeaders(version) as { "Idempotency-Key": string; "If-Match": string } } });
      if (result.error) requireAPIData<never>(result);
      return requireEmptyReceipt(result.response);
    },
    async rotateToken(id: string, version: string): Promise<WorkflowReceipt<SensorEnrollment>> {
      return requireReceipt<SensorEnrollment>(await client.POST("/api/v1/sensors/{id}/rotate-token", { params: { path: { id }, header: mutationHeaders(version) as { "Idempotency-Key": string; "If-Match": string } }, body: {} }));
    },
  };
}

export type SensorsAPI = ReturnType<typeof createSensorsAPI>;

function requireEmptyReceipt(response: Response): WorkflowReceipt<void> {
  const version = response.headers.get("ETag");
  const auditID = response.headers.get("X-Audit-ID");
  if (!version || !quotedVersion.test(version) || !auditID || !productID.test(auditID)) throw new APITransportError("invalid_response", "Workflow response omitted durable mutation headers");
  return { value: undefined, version, auditID };
}
