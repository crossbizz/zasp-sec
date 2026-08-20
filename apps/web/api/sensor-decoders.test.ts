import { describe, expect, it } from "vitest";

import { decodeSensor, decodeSensorCoverage, decodeSensorEnrollment, decodeSensorPage } from "./decoders";

const sensorID = "pid_10000001-0000-4000-8000-000000000001";
const token = "zasp_sensor_v1.EREREREREREREREREREREQ.IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI";
const sensor = {
  id: sensorID,
  name: "production-runtime",
  kind: "tetragon",
  mode: "metadata_only",
  state: "active",
  version: 4,
  token_expires_at: "2026-09-20T00:00:00Z",
  last_heartbeat_at: "2026-08-20T00:01:00Z",
  created_at: "2026-08-20T00:00:00Z",
  updated_at: "2026-08-20T00:01:00Z",
};

describe("sensor response decoders", () => {
  it("accepts exact sensor, enrollment, page, and coverage authority", () => {
    expect(decodeSensor(sensor).id).toBe(sensorID);
    expect(decodeSensorEnrollment({ ...sensor, token }).token).toBe(token);
    expect(decodeSensorPage({ items: [sensor], page_info: { next_cursor: null, has_more: false } }).items).toHaveLength(1);
    expect(decodeSensorCoverage({ sensor_id: sensorID, supported: true, status: "healthy", last_heartbeat: "2026-08-20T00:01:00Z", kernel: "6.8.0", btf: true, capabilities: ["file", "network", "process"], event_rate: 125, drops: 0 }, sensorID).status).toBe("healthy");
  });

  it("rejects secret, pagination, scope, and lifecycle drift", () => {
    expect(() => decodeSensor({ ...sensor, unexpected: true })).toThrow("schema mismatch");
    expect(() => decodeSensor({ ...sensor, state: "revoked", token_expires_at: sensor.token_expires_at })).toThrow("schema mismatch");
    expect(() => decodeSensor({ ...sensor, last_heartbeat_at: "2026-08-19T23:59:59Z" })).toThrow("schema mismatch");
    expect(() => decodeSensorEnrollment({ ...sensor, token: `${token}x` })).toThrow("schema mismatch");
    expect(() => decodeSensorPage({ items: [sensor], page_info: { next_cursor: "bad=", has_more: true } })).toThrow("schema mismatch");
    expect(() => decodeSensorCoverage({ sensor_id: sensorID, supported: true, status: "healthy", last_heartbeat: null, kernel: "6.8.0", btf: true, capabilities: ["process", "file"], event_rate: 1, drops: 0 }, "pid_20000001-0000-4000-8000-000000000001")).toThrow("schema mismatch");
  });
});
