"use client";

import { useState } from "react";
import { Activity, RadioTower, RotateCw, Trash2 } from "lucide-react";

import type { Sensor, SensorCoverage } from "../../../apps/web/api/generated";
import { Badge, Button, Card, MetricGrid, Modal, PageHeader } from "../../components/ui";

const initialSensors: Sensor[] = [
  { id: "pid_10000001-0000-4000-8000-000000000001", name: "production-us-west", kind: "tetragon", mode: "metadata_only", state: "active", version: 1, token_expires_at: "2026-09-18T09:00:00.000Z", created_at: "2026-08-18T09:00:00.000Z", updated_at: "2026-08-18T10:00:00.000Z", last_heartbeat_at: "2026-08-18T10:00:00.000Z" },
  { id: "pid_10000002-0000-4000-8000-000000000002", name: "legacy-build-nodes", kind: "tetragon", mode: "metadata_only", state: "degraded", version: 1, token_expires_at: "2026-09-18T08:00:00.000Z", created_at: "2026-08-18T08:00:00.000Z", updated_at: "2026-08-18T09:30:00.000Z", last_heartbeat_at: "2026-08-18T09:30:00.000Z" },
];

const coverage: Record<string, SensorCoverage> = {
  "pid_10000001-0000-4000-8000-000000000001": { sensor_id: "pid_10000001-0000-4000-8000-000000000001", supported: true, status: "healthy", kernel: "6.8.0", btf: true, capabilities: ["file", "network", "process"], event_rate: 128, drops: 0, last_heartbeat: "2026-08-18T10:00:00.000Z" },
  "pid_10000002-0000-4000-8000-000000000002": { sensor_id: "pid_10000002-0000-4000-8000-000000000002", supported: false, status: "degraded", kernel: "4.14.0", btf: false, capabilities: ["process"], event_rate: 24, drops: 3, last_heartbeat: "2026-08-18T09:30:00.000Z" },
};

export function SensorView({ onToast }: { onToast: (message: string) => void }) {
  const [sensors, setSensors] = useState(initialSensors);
  const [selected, setSelected] = useState<Sensor | null>(null);
  const [enrolling, setEnrolling] = useState(false);
  const [oneTimeToken, setOneTimeToken] = useState("");
  const selectedCoverage = selected ? coverage[selected.id] : undefined;
  const close = () => { setSelected(null); setEnrolling(false); setOneTimeToken(""); };
  const rotate = () => { setOneTimeToken("sensor_token_shown_once_after_rotation"); onToast("Enrollment token rotated"); };
  const remove = () => { if (!selected) return; setSensors((current) => current.filter((item) => item.id !== selected.id)); onToast(`${selected.name} deleted`); close(); };
  return <div className="page">
    <PageHeader title="Runtime sensors" description="Enroll and monitor scoped runtime collectors without exposing enrollment credentials after creation." actions={<Button variant="primary" onClick={() => setEnrolling(true)}>Enroll sensor</Button>} />
    <MetricGrid metrics={[{ label: "Sensors", value: sensors.length, tone: "brand" }, { label: "Healthy", value: sensors.filter((item) => coverage[item.id]?.supported).length, tone: "success" }, { label: "Degraded", value: sensors.filter((item) => !coverage[item.id]?.supported).length, tone: "danger" }, { label: "Dropped events", value: sensors.reduce((sum, item) => sum + (coverage[item.id]?.drops ?? 0), 0), tone: "warning" }]} />
    <Card title="Sensor coverage"><div className="connection-list">{sensors.map((sensor) => { const state = coverage[sensor.id]; return <button key={sensor.id} type="button" aria-label={`View ${sensor.name} sensor`} onClick={() => setSelected(sensor)}><strong>{sensor.name}</strong><span>{state?.supported ? "Healthy" : "Unsupported kernel"}</span><span>{sensor.last_heartbeat_at ?? "Awaiting heartbeat"}</span></button>; })}</div></Card>
    <Modal open={selected !== null} title={selected?.name ?? "Sensor"} onClose={close} size="large" footer={<><Button onClick={close}>Close</Button><Button icon={<RotateCw size={15} />} onClick={rotate}>Rotate enrollment token</Button><Button variant="danger" icon={<Trash2 size={15} />} onClick={remove}>Delete sensor</Button></>}>
      {selected && selectedCoverage && <div className="connector-detail"><div className="connector-setup-hero"><div className="connector-logo"><RadioTower /></div><div><h3>{selected.name}</h3><p>Scoped {selected.mode.replace("_", " ")} runtime collection</p></div></div><h3>Coverage</h3><MetricGrid metrics={[{ label: "Status", value: selectedCoverage.status, tone: selectedCoverage.supported ? "success" : "danger" }, { label: "Kernel", value: selectedCoverage.kernel }, { label: "BTF", value: selectedCoverage.btf ? "available" : "unsupported" }, { label: "Drops", value: selectedCoverage.drops, tone: selectedCoverage.drops === 0 ? "success" : "warning" }]} /><div>{selectedCoverage.capabilities.map((item) => <Badge key={item} tone="info">{item}</Badge>)}</div>{oneTimeToken && <div className="credential-once"><strong>Copy this token now</strong><p>{oneTimeToken}</p></div>}</div>}
    </Modal>
    <Modal open={enrolling} title="Enroll runtime sensor" onClose={close} footer={<><Button onClick={close}>Cancel</Button><Button variant="primary" onClick={() => { setOneTimeToken("sensor_token_shown_once_after_enrollment"); onToast("Sensor enrollment created"); }}>Create enrollment</Button></>}><div className="connector-detail"><Activity /><h3>Scoped enrollment</h3><p>Choose metadata-only or full collection, install the generated Helm instructions, then wait for an authenticated heartbeat before coverage becomes healthy.</p>{oneTimeToken && <div className="credential-once"><strong>Copy this token now</strong><p>{oneTimeToken}</p></div>}</div></Modal>
  </div>;
}
