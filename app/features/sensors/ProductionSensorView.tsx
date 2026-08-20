"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { RadioTower, RotateCw, Trash2 } from "lucide-react";

import type { Sensor, SensorCoverage, SensorEnrollment, SensorInput, SensorMode, SensorUpdateInput } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { Badge, Button, Card, EmptyState, Field, LoadingState, MetricGrid, Modal, PageHeader, Select } from "../../components/ui";
import { createSensorMutationAttempt, createSensorsAPI, type SensorVersioned, type SensorsAPI } from "./api";

type Feedback = Readonly<{ role: "status" | "alert"; message: string }> | null;

export { type SensorsAPI } from "./api";

export function ProductionSensorSurface({ canWrite, fresh, onReauthenticate }: { canWrite: boolean; fresh: boolean; onReauthenticate(): void }) {
  const { client } = useAPI();
  const api = useMemo(() => createSensorsAPI(client), [client]);
  return <ProductionSensorView api={api} canWrite={canWrite} fresh={fresh} onReauthenticate={onReauthenticate} />;
}

export function ProductionSensorView({ api, canWrite, fresh, onReauthenticate }: { api: SensorsAPI; canWrite: boolean; fresh: boolean; onReauthenticate(): void }) {
  const [sensors, setSensors] = useState<readonly Sensor[]>([]);
  const [loadState, setLoadState] = useState<"loading" | "success" | "error">("loading");
  const [selected, setSelected] = useState<SensorVersioned<Sensor> | null>(null);
  const [coverage, setCoverage] = useState<SensorCoverage | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [enrolling, setEnrolling] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<SensorInput["kind"]>("tetragon");
  const [mode, setMode] = useState<SensorMode>("metadata_only");
  const [editName, setEditName] = useState("");
  const [editMode, setEditMode] = useState<SensorMode>("metadata_only");
  const [oneTime, setOneTime] = useState<SensorEnrollment | null>(null);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>(null);

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoadState("loading");
    try { setSensors(await api.listSensors(signal)); setLoadState("success"); } catch { if (!signal?.aborted) { setLoadState("error"); setFeedback({ role: "alert", message: "Sensors are unavailable. Retry the authoritative read." }); } }
  }, [api]);
  useEffect(() => { const controller = new AbortController(); let active = true; queueMicrotask(() => { if (active) void load(controller.signal); }); return () => { active = false; controller.abort(); }; }, [load]);

  const openSensor = async (id: string) => {
    const controller = new AbortController(); setDetailLoading(true); setFeedback(null); setOneTime(null);
    try { const [detail, currentCoverage] = await Promise.all([api.getSensor(id, controller.signal), api.getSensorCoverage(id, controller.signal)]); setSelected(detail); setCoverage(currentCoverage); setEditName(detail.value.name); setEditMode(detail.value.mode); }
    catch { setFeedback({ role: "alert", message: "Sensor detail is unavailable. Refresh and try again." }); }
    finally { setDetailLoading(false); }
  };
  const closeEnrollment = () => { setEnrolling(false); setOneTime(null); setName(""); setKind("tetragon"); setMode("metadata_only"); };
  const closeSelected = () => { setSelected(null); setCoverage(null); setOneTime(null); };
  const upsert = (value: Sensor) => setSensors((current) => [...current.filter((item) => item.id !== value.id), value].sort((left, right) => left.id.localeCompare(right.id)));
  const run = async (action: () => Promise<void>, failure: string) => { setBusy(true); setFeedback(null); try { await action(); } catch { setFeedback({ role: "alert", message: failure }); } finally { setBusy(false); } };

  const create = () => void run(async () => {
    const result = await api.createSensor({ name, kind, mode }, createSensorMutationAttempt());
    setOneTime(result.value); upsert(sensorWithoutToken(result.value)); setFeedback({ role: "status", message: "Sensor enrollment created. Copy the token before closing." });
  }, "Enrollment may have succeeded, but its one-time token was not received. Refresh sensors and rotate its token; do not reuse this attempt.");
  const update = () => selected && void run(async () => {
    const value: SensorUpdateInput = { name: editName, mode: editMode }; const result = await api.updateSensor(selected.value.id, selected.version, value, createSensorMutationAttempt());
    setSelected(result); upsert(result.value); setFeedback({ role: "status", message: "Sensor settings saved." });
  }, "Sensor settings were not confirmed. Refresh the current version before retrying.");
  const rotate = () => selected && void run(async () => {
    const result = await api.rotateSensorToken(selected.value.id, selected.version, createSensorMutationAttempt());
    setOneTime(result.value); const next = { value: sensorWithoutToken(result.value), version: result.version }; setSelected(next); upsert(next.value); setFeedback({ role: "status", message: "Enrollment token rotated. Copy it before closing." });
  }, "Token rotation may have succeeded, but its one-time token was not received. Refresh the sensor and rotate again with a new attempt.");
  const remove = () => selected && void run(async () => {
    await api.deleteSensor(selected.value.id, selected.version, createSensorMutationAttempt()); setSensors((current) => current.filter((item) => item.id !== selected.value.id)); closeSelected(); setFeedback({ role: "status", message: "Sensor deleted and its active tokens revoked." });
  }, "Sensor deletion was not confirmed. Refresh the current version before retrying.");

  const active = sensors.filter((item) => item.state === "active").length;
  const attention = sensors.filter((item) => item.state === "degraded" || item.state === "revoked").length;
  return <div className="page">
    <PageHeader title="Runtime sensors" description="Enroll and monitor scoped runtime collectors. Enrollment tokens are revealed once and never recoverable." actions={canWrite ? fresh ? <Button variant="primary" onClick={() => { setFeedback(null); setEnrolling(true); }}>Enroll sensor</Button> : <Button onClick={onReauthenticate}>Reauthenticate to enroll</Button> : undefined} />
    {feedback && <p role={feedback.role}>{feedback.message}</p>}
    <MetricGrid metrics={[{ label: "Sensors", value: sensors.length, tone: "brand" }, { label: "Active", value: active, tone: "success" }, { label: "Needs attention", value: attention, tone: attention > 0 ? "warning" : "success" }, { label: "Awaiting heartbeat", value: sensors.filter((item) => item.state === "pending").length }]} />
    <Card title="Authorized sensor coverage" action={loadState === "error" ? <Button onClick={() => void load()}>Retry</Button> : undefined}>
      {loadState === "loading" ? <LoadingState label="Loading sensors…" /> : sensors.length === 0 ? <EmptyState title="No runtime sensors" description="Enroll a scoped Tetragon or OTLP sensor to begin runtime coverage." /> : <div className="connection-list">{sensors.map((sensor) => <button key={sensor.id} type="button" disabled={busy || detailLoading} aria-label={`Open ${sensor.name}`} onClick={() => void openSensor(sensor.id)}><strong>{sensor.name}</strong><span>{sensor.kind} · {sensor.mode.replace("_", " ")}</span><span>{sensor.state}</span></button>)}</div>}
    </Card>
    <Modal open={enrolling} title="Enroll runtime sensor" onClose={closeEnrollment} closeDisabled={busy} footer={oneTime ? <Button onClick={closeEnrollment}>Done</Button> : <><Button disabled={busy} onClick={closeEnrollment}>Cancel</Button><Button variant="primary" disabled={busy || name.length < 1 || name.trim() !== name} onClick={create}>Create enrollment</Button></>}>
      {feedback && <p role={feedback.role}>{feedback.message}</p>}<div className="form-grid"><Field label="Sensor name" value={name} maxLength={128} disabled={busy || oneTime !== null} onChange={(event) => setName(event.target.value)} /><Select label="Sensor kind" value={kind} disabled={busy || oneTime !== null} onChange={(event) => setKind(event.target.value as SensorInput["kind"])}><option value="tetragon">Tetragon</option><option value="otlp">OTLP</option></Select><Select label="Collection mode" value={mode} disabled={busy || oneTime !== null} onChange={(event) => setMode(event.target.value as SensorMode)}><option value="metadata_only">Metadata only</option><option value="full">Full</option></Select></div>
      <p>The token grants private event-ingest authority for this sensor and scope only.</p>{oneTime && <OneTimeCredential value={oneTime} />}
    </Modal>
    <Modal open={selected !== null} title={selected?.value.name ?? "Sensor"} onClose={closeSelected} closeDisabled={busy} size="large" footer={selected ? <><Button disabled={busy} onClick={closeSelected}>Close</Button>{canWrite && (fresh ? <Button disabled={busy} icon={<RotateCw size={15} />} onClick={rotate}>Rotate enrollment token</Button> : <Button disabled={busy} onClick={onReauthenticate}>Reauthenticate to rotate</Button>)}{canWrite && <Button variant="danger" disabled={busy} icon={<Trash2 size={15} />} onClick={remove}>Delete sensor</Button>}</> : undefined}>
      {selected && <div className="connector-detail">{feedback && <p role={feedback.role}>{feedback.message}</p>}<div className="connector-setup-hero"><div className="connector-logo"><RadioTower /></div><div><h3>{selected.value.name}</h3><p><Badge tone={selected.value.state === "active" ? "success" : selected.value.state === "degraded" ? "warning" : "neutral"}>{selected.value.state}</Badge> Resource version {selected.version}</p></div></div>
        {canWrite && <div className="form-grid"><Field label="Sensor name" value={editName} maxLength={128} disabled={busy} onChange={(event) => setEditName(event.target.value)} /><Select label="Collection mode" value={editMode} disabled={busy} onChange={(event) => setEditMode(event.target.value as SensorMode)}><option value="metadata_only">Metadata only</option><option value="full">Full</option></Select><Button disabled={busy || editName.length < 1 || editName.trim() !== editName} onClick={update}>Save sensor</Button></div>}
        {coverage ? <><h3>Heartbeat coverage</h3><MetricGrid metrics={[{ label: "Status", value: coverage.status, tone: coverage.status === "healthy" ? "success" : "warning" }, { label: "Kernel", value: coverage.kernel || "not reported" }, { label: "Event rate", value: `${coverage.event_rate} events/s` }, { label: "Drops", value: coverage.drops, tone: coverage.drops === 0 ? "success" : "warning" }]} /><p>{coverage.capabilities.length ? coverage.capabilities.join(" · ") : "No capabilities reported"}</p></> : <LoadingState label="Loading heartbeat coverage…" />}
        {oneTime && <OneTimeCredential value={oneTime} />}
      </div>}
    </Modal>
  </div>;
}

function OneTimeCredential({ value }: { value: SensorEnrollment }) {
  return <div className="credential-once"><strong>Copy this token now</strong><p>This credential is shown once. Zasp cannot recover it after this dialog closes.</p><code>{value.token}</code><p>Expires {value.token_expires_at}</p></div>;
}

function sensorWithoutToken(value: SensorEnrollment): Sensor {
  return { id: value.id, name: value.name, kind: value.kind, mode: value.mode, state: value.state, version: value.version, token_expires_at: value.token_expires_at, last_heartbeat_at: value.last_heartbeat_at, created_at: value.created_at, updated_at: value.updated_at };
}
