"use client";

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { RadioTower, RotateCw, Trash2 } from "lucide-react";

import type { Sensor, SensorCoverage, SensorEnrollment, SensorInput, SensorMode, SensorUpdateInput } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useOptionalSession } from "../../auth/SessionProvider";
import { Badge, Button, Card, Field, LoadingState, MetricGrid, Modal, PageHeader, Select } from "../../components/ui";
import { SectionTabs } from "../../components/section-tabs";
import { createFleetAPI } from "../../../apps/web/api/endpoint-fleet";
import { TicketCohort } from "./TicketCohort";
import { EndpointPolicyCohort } from "./EndpointPolicyCohort";
import { DeviceFleet } from "./DeviceFleet";
import "../managed-device-layout.css";
import { createSensorMutationAttempt, createSensorsAPI, type SensorVersioned, type SensorsAPI } from "./api";
import { Time } from "../../components/time";
import "../onboarding/getting-started.css";

type Feedback = Readonly<{ role: "status" | "alert"; message: string }> | null;

export { type SensorsAPI } from "./api";

type SensorSurfaceProps = { startEnrollment?: boolean; canWrite: boolean; canManagePolicy?: boolean; fresh: boolean; onReauthenticate(): void };

function subscribeToNavigation(notify: () => void) {
  window.addEventListener("popstate", notify);
  return () => window.removeEventListener("popstate", notify);
}

function linkedDeviceFromLocation() {
  const values = new URLSearchParams(window.location.search).getAll("device");
  return values.length === 1 && /^pid_[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(values[0]) ? values[0] : "";
}

export function ProductionSensorSurface(props: SensorSurfaceProps) {
  const linkedDevice = useSyncExternalStore(subscribeToNavigation, linkedDeviceFromLocation, () => "");
  return <SensorSections key={linkedDevice} {...props} linkedDevice={linkedDevice} />;
}

function SensorSections({ startEnrollment, canWrite, canManagePolicy = false, fresh, onReauthenticate, linkedDevice }: SensorSurfaceProps & { linkedDevice: string }) {
  const { client, queryScopeKey, queryGeneration } = useAPI();
  const [section, setSection] = useState(linkedDevice ? "devices" : "sensors");
  const session = useOptionalSession();
  const scope = session?.status === "authenticated" ? [session.organizationID, session.workspaceID, session.environmentID].join("/") : undefined;
  const fleet = useMemo(() => createFleetAPI(client), [client]);
  const api = useMemo(() => createSensorsAPI(client), [client]);
  const scopeKey = JSON.stringify([queryScopeKey, queryGeneration]);
  return (
    <SectionTabs
      active={section}
      onChange={setSection}
      sections={[
        {
          id: "sensors",
          label: "Sensors",
          content: <ProductionSensorView startEnrollment={startEnrollment} api={api} canWrite={canWrite} fresh={fresh} onReauthenticate={onReauthenticate} />,
        },
        {
          id: "devices",
          label: "Devices",
          content: section === "devices" && (
            <div className="managed-device-space">
              <PageHeader title="Managed devices" />
              <DeviceFleet key={scopeKey} api={fleet} scope={scope} initialID={linkedDevice}
                canWrite={canManagePolicy} fresh={fresh} onReauthenticate={onReauthenticate} />
              <TicketCohort key={"cohort" + scopeKey} canWrite={canManagePolicy} fresh={fresh}
                onReauthenticate={onReauthenticate} />
              <EndpointPolicyCohort key={"pretool" + scopeKey} client={client} canManage={canManagePolicy}
                fresh={fresh} reauthenticate={onReauthenticate} />
            </div>
          ),
        },
      ]}
    />
  );
}

export function ProductionSensorView({ startEnrollment = false, api, canWrite, fresh, onReauthenticate }: { startEnrollment?: boolean; api: SensorsAPI; canWrite: boolean; fresh: boolean; onReauthenticate(): void }) {
  const [sensors, setSensors] = useState<readonly Sensor[]>([]);
  const [loadState, setLoadState] = useState<"loading" | "success" | "error">("loading");
  const [selected, setSelected] = useState<SensorVersioned<Sensor> | null>(null);
  const [coverage, setCoverage] = useState<SensorCoverage | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [enrolling, setEnrolling] = useState(startEnrollment && canWrite && fresh);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<SensorInput["kind"]>("tetragon");
  const [runtimeSensorID, setRuntimeSensorID] = useState("");
  const [mode, setMode] = useState<SensorMode>("metadata_only");
  const [editName, setEditName] = useState("");
  const [editMode, setEditMode] = useState<SensorMode>("metadata_only");
  const [oneTime, setOneTime] = useState<SensorEnrollment | null>(null);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>(null);

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoadState("loading");
    try {
      const values = await api.listSensors(signal);
      if (signal?.aborted) return;
      setSensors(values);
      setLoadState("success");
    } catch { if (!signal?.aborted) setLoadState("error"); }
  }, [api]);
  useEffect(() => { const controller = new AbortController(); let active = true; queueMicrotask(() => { if (active) void load(controller.signal); }); return () => { active = false; controller.abort(); }; }, [load]);

  const openSensor = async (id: string) => {
    const controller = new AbortController(); setDetailLoading(true); setFeedback(null); setOneTime(null);
    try { const [detail, currentCoverage] = await Promise.all([api.getSensor(id, controller.signal), api.getSensorCoverage(id, controller.signal)]); setSelected(detail); setCoverage(currentCoverage); setEditName(detail.value.name); setEditMode(detail.value.mode); }
    catch { setFeedback({ role: "alert", message: "Sensor detail is unavailable. Refresh and try again." }); }
    finally { setDetailLoading(false); }
  };
  const closeEnrollment = () => { setEnrolling(false); setOneTime(null); setName(""); setKind("tetragon"); setRuntimeSensorID(""); setMode("metadata_only"); };
  const closeSelected = () => { setSelected(null); setCoverage(null); setOneTime(null); };
  const upsert = (value: Sensor) => setSensors((current) => [...current.filter((item) => item.id !== value.id), value].sort((left, right) => left.id.localeCompare(right.id)));
  const run = async (action: () => Promise<void>, failure: string) => { setBusy(true); setFeedback(null); try { await action(); } catch { setFeedback({ role: "alert", message: failure }); } finally { setBusy(false); } };

  const create = () => canWrite && fresh && void run(async () => {
    const result = await api.createSensor({ name, kind, mode, ...(kind === "otlp" && runtimeSensorID ? { runtime_sensor_id: runtimeSensorID } : {}) }, createSensorMutationAttempt());
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
  const runtimeAnchors = sensors.filter((item) => item.kind === "tetragon" && item.state === "active");
  const pairingInvalid = runtimeSensorID !== "" && (kind !== "otlp" || loadState !== "success" || !runtimeAnchors.some((item) => item.id === runtimeSensorID));
  const attention = sensors.filter((item) => item.state === "degraded" || item.state === "revoked").length;
  const firstSensor = loadState === "success" && sensors.length === 0;
  const enrollAction = canWrite && (fresh
    ? <Button variant="primary" onClick={() => { setFeedback(null); setEnrolling(true); }}>Enroll sensor</Button>
    : <Button onClick={onReauthenticate}>Reauthenticate to enroll</Button>);
  return <div className="page">
    <PageHeader title="Runtime sensors" description="Enroll collectors and check runtime coverage in this environment." actions={!firstSensor && loadState === "success" && enrollAction} />
    {feedback && <p role={feedback.role}>{feedback.message}</p>}
    {firstSensor ? <section className="setup-guide" aria-labelledby="sensor-setup-heading">
      <header><h2 id="sensor-setup-heading">Set up your first runtime sensor</h2>
        <p>{canWrite ? "Choose the evidence you want to collect in this environment." : "Ask your environment administrator to enroll a collector. Once it reports in, you can review its coverage here."}</p>
      </header>
      <div className="sensor-setup-body">
        <Select label="Collector to set up" value={kind} onChange={event => setKind(event.target.value as SensorInput["kind"])}>
          <option value="tetragon">Tetragon · Kubernetes process and network events</option>
          <option value="otlp">OTLP · application telemetry</option>
        </Select>
        <ol>
          <li>Enroll the {kind === "tetragon" ? "Kubernetes sensor" : "OTLP source"} and save its one-time token.</li>
          <li>{kind === "tetragon" ? "Save the token in a Kubernetes Secret under the key token. Install Tetragon and the Zasp customer-edge Helm chart using the Secret name and enrollment binding." : "Configure a Zasp-compatible semantic collector with the token and enrollment binding. The collector must convert application spans to Zasp runtime events."}</li>
          <li>{kind === "tetragon" ? "Open the sensor here and check its first heartbeat and event rate." : "Send a supported session event through the collector, then open Sessions to find it."}</li>
        </ol>
        {canWrite && !fresh && <p>Confirm your sign-in to create an enrollment token.</p>}
        {enrollAction}
      </div>
    </section> : <>
    {sensors.length > 0 && <MetricGrid metrics={[{ label: "Sensors", value: sensors.length, tone: "brand" }, { label: "Active", value: active, tone: "success" }, { label: "Needs attention", value: attention, tone: attention > 0 ? "warning" : "success" }, { label: "Awaiting heartbeat", value: sensors.filter((item) => item.state === "pending").length }]} />}
    <Card title="Authorized sensor coverage" action={loadState === "error" ? <Button onClick={() => void load()}>Retry</Button> : undefined}>
      {loadState === "loading" && <LoadingState label="Loading sensors…" />}
      {loadState === "error" && <p role="alert">Sensors are unavailable. Retry to check coverage.</p>}
      {loadState !== "loading" && sensors.length > 0 && <div className="connection-list" aria-busy={detailLoading}>
        {sensors.map(sensor => (
          <button key={sensor.id} type="button" disabled={busy} aria-disabled={busy || detailLoading}
            aria-label={`Open ${sensor.name}`} onClick={() => { if (!detailLoading) void openSensor(sensor.id); }}>
            <strong>{sensor.name}</strong><span>{sensor.kind} · {sensor.mode.replace("_", " ")}</span><span>{sensor.state}</span>
          </button>
        ))}
      </div>}
    </Card></>}
    <Modal open={enrolling} title="Enroll runtime sensor" onClose={closeEnrollment} closeDisabled={busy} footer={oneTime ? <Button onClick={closeEnrollment}>Done</Button> : <><Button disabled={busy} onClick={closeEnrollment}>Cancel</Button><Button variant="primary" disabled={!canWrite || !fresh || busy || name.length < 1 || name.trim() !== name || pairingInvalid} onClick={create}>Create enrollment</Button></>}>
      {feedback && <p role={feedback.role}>{feedback.message}</p>}<div className="form-grid"><Field label="Sensor name" value={name} maxLength={128} disabled={busy || oneTime !== null} onChange={(event) => setName(event.target.value)} /><Select label="Sensor kind" value={kind} disabled={busy || oneTime !== null} onChange={(event) => { setKind(event.target.value as SensorInput["kind"]); setRuntimeSensorID(""); }}><option value="tetragon">Tetragon</option><option value="otlp">OTLP</option></Select><Select label="Collection mode" value={mode} disabled={busy || oneTime !== null} onChange={(event) => setMode(event.target.value as SensorMode)}><option value="metadata_only">Metadata only</option><option value="full">Full</option></Select>
        {kind === "otlp" && <Select label="Runtime sensor pairing" value={runtimeSensorID} disabled={busy || oneTime !== null || loadState !== "success"} onChange={(event) => setRuntimeSensorID(event.target.value)}><option value="">No pairing (semantic only)</option>{runtimeAnchors.map((item) => <option key={item.id} value={item.id}>{item.name} ({item.id})</option>)}</Select>}
      </div>
      {kind === "otlp" && <p>Pairing cannot be changed. Create a new enrollment to choose another runtime sensor.</p>}
      <p>The token grants private event-ingest authority for this sensor and scope only.</p>{oneTime && <OneTimeCredential value={oneTime} />}
    </Modal>
    <Modal open={selected !== null} title={selected?.value.name ?? "Sensor"} onClose={closeSelected} closeDisabled={busy} size="large" footer={selected ? <><Button disabled={busy} onClick={closeSelected}>Close</Button>{canWrite && (fresh ? <Button disabled={busy} icon={<RotateCw size={15} />} onClick={rotate}>Rotate enrollment token</Button> : <Button disabled={busy} onClick={onReauthenticate}>Reauthenticate to rotate</Button>)}{canWrite && <Button variant="danger" disabled={busy} icon={<Trash2 size={15} />} onClick={remove}>Delete sensor</Button>}</> : undefined}>
      {selected && <div className="connector-detail">{feedback && <p role={feedback.role}>{feedback.message}</p>}<div className="connector-setup-hero"><div className="connector-logo"><RadioTower /></div><div><h3>{selected.value.name}</h3><p><Badge tone={selected.value.state === "active" ? "success" : selected.value.state === "degraded" ? "warning" : "neutral"}>{selected.value.state}</Badge> Resource version {selected.version}</p></div></div>
        {selected.value.kind === "otlp" && <section aria-label="Configured runtime pairing"><h3>Configured runtime pairing</h3><p>{selected.value.runtime_sensor_id ?? "Unpaired semantic source"}</p><p>A configured pairing does not confirm current runtime activity or event attribution.</p></section>}
        {canWrite && <div className="form-grid"><Field label="Sensor name" value={editName} maxLength={128} disabled={busy} onChange={(event) => setEditName(event.target.value)} /><Select label="Collection mode" value={editMode} disabled={busy} onChange={(event) => setEditMode(event.target.value as SensorMode)}><option value="metadata_only">Metadata only</option><option value="full">Full</option></Select><Button disabled={busy || editName.length < 1 || editName.trim() !== editName} onClick={update}>Save sensor</Button></div>}
        {coverage ? <><h3>Heartbeat coverage</h3><MetricGrid metrics={[{ label: "Status", value: coverage.status, tone: coverage.status === "healthy" ? "success" : "warning" }, { label: "Kernel", value: coverage.kernel || "not reported" }, { label: "Event rate", value: `${coverage.event_rate} events/s` }, { label: "Drops", value: coverage.drops, tone: coverage.drops === 0 ? "success" : "warning" }]} /><p>{coverage.capabilities.length ? coverage.capabilities.join(" · ") : "No capabilities reported"}</p></> : <LoadingState label="Loading heartbeat coverage…" />}
        {oneTime && <OneTimeCredential value={oneTime} />}
      </div>}
    </Modal>
  </div>;
}

function OneTimeCredential({ value }: { value: SensorEnrollment }) {
  return <div className="credential-once"><strong>Copy this token now</strong><p>This credential is shown once. Zasp cannot recover it after this dialog closes.</p><code>{value.token}</code><p>Expires <Time value={value.token_expires_at} /></p>
    {value.kind === "tetragon" ? <>
      <strong>Helm deployment boundary</strong>
      <p>Put the token in the Kubernetes Secret’s <code>token</code> key. Install <code>deploy/staging/tetragon</code> and <code>deploy/staging/product</code> in your edge namespace. Use the customer-edge values file and your site configuration with these sensor settings.</p>
      <code>sensorAgent.enabled=true</code><code>sensorAgent.tokenSecretName=&lt;pre-created-secret-name&gt;</code><code>sensorAgent.enrollmentBinding={value.enrollment_binding}</code>
      <p>Keep the token out of Helm values and command history. After installation, open this sensor to verify its first heartbeat. Keep the enrollment binding when rotating the token.</p>
    </> : <>
      <strong>OTLP ingestion boundary</strong>
      <p>Configure your semantic collector to convert spans into Zasp runtime events and submit them to the private event-ingest service. Supply this token as its bearer credential and use the following binding.</p>
      <code>enrollment_binding={value.enrollment_binding}</code>
      <p>Send a supported session event and confirm it appears in Sessions. The collector submits its heartbeat separately.</p>
    </>}
  </div>;
}

function sensorWithoutToken(value: SensorEnrollment): Sensor {
  return { id: value.id, name: value.name, kind: value.kind, mode: value.mode, state: value.state, version: value.version, token_expires_at: value.token_expires_at, last_heartbeat_at: value.last_heartbeat_at, created_at: value.created_at, updated_at: value.updated_at, ...(value.runtime_sensor_id ? { runtime_sensor_id: value.runtime_sensor_id } : {}) };
}
