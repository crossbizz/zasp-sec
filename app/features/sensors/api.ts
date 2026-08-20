import type { APIClient } from "../../../apps/web/api/client";
import { APITransportError, requireAPIData } from "../../../apps/web/api/client";
import { decodeSensor, decodeSensorCoverage, decodeSensorEnrollment, decodeSensorPage } from "../../../apps/web/api/decoders";
import type { Sensor, SensorCoverage, SensorEnrollment, SensorInput, SensorUpdateInput } from "../../../apps/web/api/generated";

const quotedVersion = /^"[1-9][0-9]*"$/;

export type SensorVersioned<T> = Readonly<{ value: T; version: string }>;
export type SensorMutationAttempt = Readonly<{ idempotencyKey: string }>;

export function createSensorMutationAttempt(): SensorMutationAttempt {
  return Object.freeze({ idempotencyKey: `sensor_${globalThis.crypto.randomUUID()}` });
}

export function createSensorsAPI(client: APIClient) {
  return {
    async listSensors(signal?: AbortSignal): Promise<readonly Sensor[]> {
      const values: Sensor[] = []; const seen = new Set<string>(); let cursor: string | undefined; let priorID = "";
      for (let pageNumber = 0; pageNumber < 100; pageNumber += 1) {
        const result = await client.GET("/api/v1/sensors", { params: { query: { cursor, limit: 100 } }, signal });
        const page = requireNoStoreData(result, decodeSensorPage);
        for (const sensor of page.items) { if (seen.has(sensor.id) || priorID !== "" && sensor.id <= priorID) invalidResponse("Sensor pagination repeated or reordered a resource"); seen.add(sensor.id); values.push(sensor); priorID = sensor.id; }
        if (!page.page_info.has_more) return values;
        if (page.page_info.next_cursor === cursor) invalidResponse("Sensor pagination did not advance");
        cursor = page.page_info.next_cursor;
      }
      return invalidResponse("Sensor pagination exceeded its bound");
    },
    async getSensor(id: string, signal?: AbortSignal): Promise<SensorVersioned<Sensor>> {
      const result = await client.GET("/api/v1/sensors/{id}", { params: { path: { id } }, signal });
      const value = requireNoStoreData(result, decodeSensor); if (value.id !== id) invalidResponse("Sensor detail returned a different resource");
      return versioned(result.response, value);
    },
    async getSensorCoverage(id: string, signal?: AbortSignal): Promise<SensorCoverage> {
      return requireNoStoreData(await client.GET("/api/v1/sensors/{id}/coverage", { params: { path: { id } }, signal }), (value) => decodeSensorCoverage(value, id));
    },
    async createSensor(value: SensorInput, attempt: SensorMutationAttempt = createSensorMutationAttempt()): Promise<SensorVersioned<SensorEnrollment>> {
      const result = await client.POST("/api/v1/sensors", { params: { header: { "Idempotency-Key": attempt.idempotencyKey, "X-Zasp-Fresh-Auth": "confirmed" } }, body: value });
      return secretVersioned(result, undefined);
    },
    async updateSensor(id: string, version: string, value: SensorUpdateInput, attempt: SensorMutationAttempt = createSensorMutationAttempt()): Promise<SensorVersioned<Sensor>> {
      const result = await client.PATCH("/api/v1/sensors/{id}", { params: { path: { id }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": version } }, body: value });
      const sensor = requireNoStoreData(result, decodeSensor); if (sensor.id !== id) invalidResponse("Sensor update returned a different resource");
      return versioned(result.response, sensor);
    },
    async deleteSensor(id: string, version: string, attempt: SensorMutationAttempt = createSensorMutationAttempt()): Promise<{ version: string }> {
      const result = await client.DELETE("/api/v1/sensors/{id}", { params: { path: { id }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": version } } });
      if (result.error) requireAPIData<never>(result); requireNoStore(result.response);
      if (result.response.status !== 204) invalidResponse("Sensor deletion returned an invalid status");
      return { version: responseVersion(result.response) };
    },
    async rotateSensorToken(id: string, version: string, attempt: SensorMutationAttempt = createSensorMutationAttempt()): Promise<SensorVersioned<SensorEnrollment>> {
      const result = await client.POST("/api/v1/sensors/{id}/rotate-token", { params: { path: { id }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": version, "X-Zasp-Fresh-Auth": "confirmed" } }, body: {} });
      return secretVersioned(result, id);
    },
  };
}

function requireNoStoreData<T>(result: { data?: unknown; error?: unknown; response: Response }, decode: (value: unknown) => T): T {
  const value = requireAPIData(result, decode); requireNoStore(result.response); return value;
}

function secretVersioned(result: { data?: unknown; error?: unknown; response: Response }, expectedID: string | undefined): SensorVersioned<SensorEnrollment> {
  const value = requireNoStoreData(result, decodeSensorEnrollment); if (expectedID !== undefined && value.id !== expectedID) invalidResponse("Sensor enrollment returned a different resource");
  if (result.response.headers.get("Pragma")?.toLowerCase() !== "no-cache") invalidResponse("Sensor enrollment response was cacheable");
  return versioned(result.response, value);
}

function versioned<T extends { readonly version: number }>(response: Response, value: T): SensorVersioned<T> {
  const version = responseVersion(response); if (version !== `"${value.version}"`) invalidResponse("Sensor response version did not match its body"); return { value, version };
}

function responseVersion(response: Response): string {
  const value = response.headers.get("ETag"); if (!value || !quotedVersion.test(value)) return invalidResponse("Sensor response omitted a valid resource version"); return value;
}

function requireNoStore(response: Response): void {
  if (response.headers.get("Cache-Control")?.toLowerCase() !== "no-store") invalidResponse("Sensor response was cacheable");
}

function invalidResponse(message: string): never { throw new APITransportError("invalid_response", message); }

export type SensorsAPI = ReturnType<typeof createSensorsAPI>;
