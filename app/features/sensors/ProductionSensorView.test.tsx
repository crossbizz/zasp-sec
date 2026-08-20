import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { Sensor, SensorCoverage, SensorEnrollment } from "../../../apps/web/api/generated";
import { ProductionSensorView, type SensorsAPI } from "./ProductionSensorView";

const sensorID = "pid_10000001-0000-4000-8000-000000000001";
const token = "zasp_sensor_v1.EREREREREREREREREREREQ.IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI";
const sensor: Sensor = { id: sensorID, name: "production-runtime", kind: "tetragon", mode: "metadata_only", state: "active", version: 4, token_expires_at: "2026-09-20T00:00:00Z", last_heartbeat_at: "2026-08-20T00:01:00Z", created_at: "2026-08-20T00:00:00Z", updated_at: "2026-08-20T00:01:00Z" };
const coverage: SensorCoverage = { sensor_id: sensorID, supported: true, status: "healthy", last_heartbeat: "2026-08-20T00:01:00Z", kernel: "6.8.0", btf: true, capabilities: ["file", "network", "process"], event_rate: 125, drops: 0 };
const enrollment: SensorEnrollment = { ...sensor, version: 1, state: "pending", token_expires_at: "2026-09-20T00:00:00Z", last_heartbeat_at: null, token };

function sensorAPI(overrides: Partial<SensorsAPI> = {}): SensorsAPI {
  return {
    listSensors: async () => [sensor],
    getSensor: async () => ({ value: sensor, version: '"4"' }),
    getSensorCoverage: async () => coverage,
    createSensor: async () => ({ value: enrollment, version: '"1"' }),
    updateSensor: async (_id, _version, value) => ({ value: { ...sensor, ...value, version: 5 }, version: '"5"' }),
    deleteSensor: async () => ({ version: '"5"' }),
    rotateSensorToken: async () => ({ value: { ...enrollment, version: 5 }, version: '"5"' }),
    ...overrides,
  };
}

describe("production sensor management", () => {
  it("loads authoritative sensors and heartbeat coverage", async () => {
    const user = userEvent.setup();
    const getSensorCoverage = vi.fn(sensorAPI().getSensorCoverage);
    render(<ProductionSensorView api={sensorAPI({ getSensorCoverage })} canWrite fresh onReauthenticate={() => undefined} />);
    await user.click(await screen.findByRole("button", { name: "Open production-runtime" }));
    const dialog = screen.getByRole("dialog", { name: "production-runtime" });
    expect(await within(dialog).findByText("healthy")).toBeVisible();
    expect(within(dialog).getByText("6.8.0")).toBeVisible();
    expect(within(dialog).getByText("125 events/s")).toBeVisible();
    expect(getSensorCoverage).toHaveBeenCalledWith(sensorID, expect.any(AbortSignal));
  });

  it("reveals enrollment material once and clears it from the document on close", async () => {
    const user = userEvent.setup();
    const createSensor = vi.fn(sensorAPI().createSensor);
    render(<ProductionSensorView api={sensorAPI({ createSensor, listSensors: async () => [] })} canWrite fresh onReauthenticate={() => undefined} />);
    await user.click(await screen.findByRole("button", { name: "Enroll sensor" }));
    await user.type(screen.getByLabelText("Sensor name"), "production-runtime");
    await user.click(screen.getByRole("button", { name: "Create enrollment" }));
    expect(await screen.findByText(token)).toBeVisible();
    expect(createSensor).toHaveBeenCalledWith({ name: "production-runtime", kind: "tetragon", mode: "metadata_only" }, expect.objectContaining({ idempotencyKey: expect.stringMatching(/^sensor_/) }));
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    await user.click(screen.getByRole("button", { name: "Done" }));
    expect(screen.queryByText(token)).not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(token);
  });

  it("does not retry or fabricate a token after an ambiguous create response", async () => {
    const user = userEvent.setup();
    const createSensor = vi.fn(async () => { throw new TypeError("response lost"); });
    render(<ProductionSensorView api={sensorAPI({ createSensor, listSensors: async () => [] })} canWrite fresh onReauthenticate={() => undefined} />);
    await user.click(await screen.findByRole("button", { name: "Enroll sensor" }));
    await user.type(screen.getByLabelText("Sensor name"), "uncertain-runtime");
    await user.click(screen.getByRole("button", { name: "Create enrollment" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("may have succeeded");
    expect(screen.getByRole("alert")).toHaveTextContent("rotate its token");
    expect(createSensor).toHaveBeenCalledOnce();
    expect(document.body.innerHTML).not.toContain("zasp_sensor_v1.");
  });

  it("uses displayed versions for update, rotation, and deletion", async () => {
    const user = userEvent.setup();
    const updateSensor = vi.fn(sensorAPI().updateSensor);
    const rotateSensorToken = vi.fn(sensorAPI().rotateSensorToken);
    const deleteSensor = vi.fn(sensorAPI().deleteSensor);
    render(<ProductionSensorView api={sensorAPI({ updateSensor, rotateSensorToken, deleteSensor })} canWrite fresh onReauthenticate={() => undefined} />);
    await user.click(await screen.findByRole("button", { name: "Open production-runtime" }));
    await screen.findByText("healthy");
    await user.clear(screen.getByLabelText("Sensor name"));
    await user.type(screen.getByLabelText("Sensor name"), "renamed-runtime");
    await user.click(screen.getByRole("button", { name: "Save sensor" }));
    await waitFor(() => expect(updateSensor).toHaveBeenCalledWith(sensorID, '"4"', { name: "renamed-runtime", mode: "metadata_only" }, expect.objectContaining({ idempotencyKey: expect.stringMatching(/^sensor_/) })));
    await user.click(screen.getByRole("button", { name: "Rotate enrollment token" }));
    expect(await screen.findByText(token)).toBeVisible();
    expect(rotateSensorToken).toHaveBeenCalledWith(sensorID, '"5"', expect.objectContaining({ idempotencyKey: expect.stringMatching(/^sensor_/) }));
    await user.click(screen.getByRole("button", { name: "Delete sensor" }));
    await waitFor(() => expect(deleteSensor).toHaveBeenCalledWith(sensorID, '"5"', expect.objectContaining({ idempotencyKey: expect.stringMatching(/^sensor_/) })));
    expect(screen.queryByRole("dialog", { name: /runtime/ })).not.toBeInTheDocument();
  });

  it("requires fresh authentication before creating or rotating tokens", async () => {
    const user = userEvent.setup();
    const reauthenticate = vi.fn();
    render(<ProductionSensorView api={sensorAPI()} canWrite fresh={false} onReauthenticate={reauthenticate} />);
    await user.click(await screen.findByRole("button", { name: "Reauthenticate to enroll" }));
    expect(reauthenticate).toHaveBeenCalledOnce();
    await user.click(screen.getByRole("button", { name: "Open production-runtime" }));
    await screen.findByText("healthy");
    await user.click(screen.getByRole("button", { name: "Reauthenticate to rotate" }));
    expect(reauthenticate).toHaveBeenCalledTimes(2);
  });
});
