import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { Sensor, SensorEnrollment } from "../../../apps/web/api/generated";
import { createSensorsAPI } from "./api";

const sensorID = "pid_10000001-0000-4000-8000-000000000001";
const token = "zasp_sensor_v1.EREREREREREREREREREREQ.IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI";
const sensor: Sensor = { id: sensorID, name: "production-runtime", kind: "tetragon", mode: "metadata_only", state: "active", version: 4, token_expires_at: "2026-09-20T00:00:00Z", last_heartbeat_at: "2026-08-20T00:01:00Z", created_at: "2026-08-20T00:00:00Z", updated_at: "2026-08-20T00:01:00Z" };
const enrollment: SensorEnrollment = { ...sensor, state: "pending", version: 1, token_expires_at: "2026-09-20T00:00:00Z", last_heartbeat_at: null, token };

describe("production sensor API adapter", () => {
  it("binds the requested runtime pairing to the one-time enrollment response", async () => {
    const anchor = "pid_78200001-0000-4000-8000-000000000001";
    const paired = { ...enrollment, kind: "otlp" as const, runtime_sensor_id: anchor };
    const POST = vi.fn(async () => secretResult(paired, 201));
    const input = { name: sensor.name, kind: "otlp" as const, mode: sensor.mode, runtime_sensor_id: anchor };
    expect((await createSensorsAPI({ POST } as unknown as APIClient).createSensor(input)).value).toMatchObject({ runtime_sensor_id: anchor });
    expect(POST).toHaveBeenCalledWith("/api/v1/sensors", expect.objectContaining({ body: input }));
    const drift = vi.fn(async () => secretResult({ ...paired, runtime_sensor_id: "pid_78200009-0000-4000-8000-000000000009" }, 201));
    await expect(createSensorsAPI({ POST: drift } as unknown as APIClient).createSensor(input)).rejects.toThrow("pairing");
    const missing = vi.fn(async () => secretResult({ ...enrollment, kind: "otlp" }, 201));
    await expect(createSensorsAPI({ POST: missing } as unknown as APIClient).createSensor(input)).rejects.toThrow("pairing");
  });
  it("loads every bounded cursor page without truncation", async () => {
    const cursor = "c2Vuc29yLXBhZ2UtMg";
    const second = { ...sensor, id: "pid_10000002-0000-4000-8000-000000000002", name: "second-runtime" };
    const GET = vi.fn(async (_path: string, options: { params?: { query?: { cursor?: string } } }) => options.params?.query?.cursor
      ? jsonResult({ items: [second], page_info: { next_cursor: null, has_more: false } })
      : jsonResult({ items: [sensor], page_info: { next_cursor: cursor, has_more: true } }));
    const values = await createSensorsAPI({ GET } as unknown as APIClient).listSensors();
    expect(values.map((value) => value.id)).toEqual([sensor.id, second.id]);
    expect(GET).toHaveBeenNthCalledWith(2, "/api/v1/sensors", expect.objectContaining({ params: { query: { cursor, limit: 100 } } }));
  });

  it("binds fresh one-time mutations and displayed resource versions", async () => {
    const POST = vi.fn(async (...args: [string, unknown]) => args[0] === "/api/v1/sensors" ? secretResult(enrollment, 201) : secretResult({ ...enrollment, version: 5 }));
    const PATCH = vi.fn(async (...args: [string, unknown]) => { void args; return jsonResult({ ...sensor, version: 5 }, 200, { ETag: '"5"' }); });
    const DELETE = vi.fn(async (...args: [string, unknown]) => { void args; return { response: new Response(null, { status: 204, headers: { "Cache-Control": "no-store", ETag: '"5"' } }) }; });
    const api = createSensorsAPI({ POST, PATCH, DELETE } as unknown as APIClient);
    const attempt = { idempotencyKey: "sensor_1234567890123456" };
    await api.createSensor({ name: sensor.name, kind: sensor.kind, mode: sensor.mode }, attempt);
    await api.updateSensor(sensorID, '"4"', { name: sensor.name, mode: "full" }, attempt);
    await api.rotateSensorToken(sensorID, '"4"', attempt);
    await api.deleteSensor(sensorID, '"4"', attempt);
    expect(POST.mock.calls[0]?.[1]).toEqual(expect.objectContaining({ params: { header: { "Idempotency-Key": attempt.idempotencyKey, "X-Zasp-Fresh-Auth": "confirmed" } } }));
    expect(POST.mock.calls[1]?.[1]).toEqual(expect.objectContaining({ params: { path: { id: sensorID }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": '"4"', "X-Zasp-Fresh-Auth": "confirmed" } } }));
    expect(PATCH.mock.calls[0]?.[1]).toEqual(expect.objectContaining({ params: { path: { id: sensorID }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": '"4"' } } }));
    expect(DELETE.mock.calls[0]?.[1]).toEqual(expect.objectContaining({ params: { path: { id: sensorID }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": '"4"' } } }));
  });

  it("rejects cacheable secrets and contradictory response versions", async () => {
    const cacheable = { data: enrollment, response: new Response(JSON.stringify(enrollment), { status: 201, headers: { "Content-Type": "application/json", ETag: '"1"', Pragma: "no-cache" } }) };
    await expect(createSensorsAPI({ POST: vi.fn(async () => cacheable) } as unknown as APIClient).createSensor({ name: sensor.name, kind: sensor.kind, mode: sensor.mode })).rejects.toThrow("cacheable");
    const drifted = jsonResult(sensor, 200, { ETag: '"9"' });
    await expect(createSensorsAPI({ GET: vi.fn(async () => drifted) } as unknown as APIClient).getSensor(sensorID)).rejects.toThrow("did not match");
  });
});

function secretResult(value: SensorEnrollment, status = 200) {
  return jsonResult(value, status, { ETag: `"${value.version}"`, Pragma: "no-cache" });
}

function jsonResult(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return { data, response: new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers } }) };
}
