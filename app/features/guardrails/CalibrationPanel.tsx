"use client";

import { lazy, Suspense, useCallback, useMemo, useRef, useState } from "react";
import type { AnalystFeedback, CalibrationMetrics, RuleSuppressionMode } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button, Card, MetricGrid, Select } from "../../components/ui";
import { Time } from "../../components/time";
import { workflowIdempotencyKey } from "../workflows/api";
import { CalibrationExports } from "./CalibrationExports";
import { createCalibrationAPI } from "./calibration-api";

const Chart = lazy(() => import("./CalibrationChart"));
const percent = (v: number | null) => v === null ? "No labels" : Math.round(v * 1000) / 10 + "%";
type API = ReturnType<typeof createCalibrationAPI>;

function useCalibrationWrite(refresh: () => Promise<void>) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const attempt = useRef<{ value: string; key: string } | null>(null);
  const active = useRef(false);
  async function write(value: string, save: (key: string) => Promise<unknown>) {
    if (active.current) return;
    active.current = true;
    if (attempt.current?.value !== value) attempt.current = { value, key: workflowIdempotencyKey() };
    setBusy(true); setMessage("");
    try {
      await save(attempt.current.key);
      attempt.current = null;
      await refresh();
      setMessage("Saved.");
    } catch { setMessage("Could not confirm the change. Refresh to check the current record, or retry."); }
    finally { setBusy(false); active.current = false; }
  }
  return { busy, message, write };
}

function SuppressionSettings({ api, ruleID, canWrite }: { api: API; ruleID: string; canWrite: boolean }) {
  const query = useAPIQuery("suppression:"+ruleID, useCallback((signal?: AbortSignal) => api.rule(ruleID, signal), [api, ruleID]));
  const rule = query.data;
  const save = useCalibrationWrite(query.retry);
  if (!rule) return <p role="status">{query.status === "error" || query.status === "forbidden" ? <>Rule settings unavailable. <Button onClick={() => void query.retry()}>Retry</Button></> : "Loading rule settings…"}</p>;
  const change = (mode: RuleSuppressionMode["mode"]) => void save.write(JSON.stringify([rule.rule_id, rule.version, mode]), key => api.setMode(rule, mode, key));
  return <div><p>Current mode <strong>{rule.mode}</strong>. {rule.rule_class === "hard" ? "Hard rules always enforce their configured policy." : `${rule.shadow_labels} shadow labels · ${rule.false_alerts_avoided} false alerts avoided · ${rule.serious_missed} serious detections missed`}</p>
    {canWrite && rule.rule_class === "heuristic" && <div className="row-actions">
      {rule.mode !== "off" && <Button disabled={save.busy} onClick={() => change("off")}>Turn suppression off</Button>}
      {rule.mode !== "shadow" && <Button disabled={save.busy} onClick={() => change("shadow")}>Start shadow review</Button>}
      {rule.mode === "shadow" && rule.eligible && <Button disabled={save.busy} onClick={() => change("active")}>Activate suppression</Button>}
    </div>}
    {save.message && <p role="status">{save.message}</p>}
  </div>;
}

function Metrics({ data }: { data: CalibrationMetrics }) {
  return <>
    <MetricGrid metrics={[{ label: "Evaluations", value: data.evaluated }, { label: "Labelled", value: data.labelled },
      { label: "Calibration error", value: percent(data.ece) }, { label: "Brier score", value: data.brier?.toFixed(3) ?? "No labels" }]} />
    <Card title={<h2>Detection reliability</h2>}>{data.labelled === 0 ? <p>No labelled evaluations in the past 30 days.</p> : <>
      <Suspense fallback={<p>Loading chart…</p>}><Chart metrics={data} /></Suspense>
      <details><summary>Confidence bins</summary><div className="table-scroll"><table className="data-table"><thead><tr><th>Predicted range</th><th>Labels</th><th>Observed rate</th></tr></thead>
        <tbody>{data.bins.map(b => <tr key={b.lower}><td>{percent(b.lower)}–{percent(b.upper)}</td><td>{b.count}</td><td>{percent(b.observed_rate)}</td></tr>)}</tbody></table></div></details>
      <details><summary>Threshold trade-offs</summary><div className="table-scroll"><table className="data-table"><thead><tr>{["Threshold","True positives","False positives","True negatives","False negatives"].map(t => <th key={t}>{t}</th>)}</tr></thead>
        <tbody>{data.thresholds.map(t => <tr key={t.threshold}>{[percent(t.threshold), t.tp, t.fp, t.tn, t.fn].map((v, i) => <td key={i}>{v}</td>)}</tr>)}</tbody></table></div></details>
    </>}</Card>
    <Card title={<h2>Deployed-agent discovery</h2>}>{data.discovery.precision === null && data.discovery.recall === null ? <p>No labelled deployments in this period.</p>
      : <p>Precision <strong>{percent(data.discovery.precision)}</strong> · Recall <strong>{percent(data.discovery.recall)}</strong></p>}</Card>
  </>;
}

export function CalibrationPanel({ ruleIDs, canWrite }: { ruleIDs: readonly string[]; canWrite: boolean }) {
  const { client } = useAPI();
  const api = useMemo(() => createCalibrationAPI(client), [client]);
  const query = useAPIQuery("calibration:metrics", useCallback((signal?: AbortSignal) => api.metrics(signal), [api]));
  const save = useCalibrationWrite(query.retry);
  const [picked, setPicked] = useState("");
  const ruleID = ruleIDs.includes(picked) ? picked : ruleIDs[0];
  const data = query.data;
  const feedback = (decision: CalibrationMetrics["recent"][number], label: AnalystFeedback["label"]) => {
    const body = { decision_id: decision.decision_id, rule_id: decision.rule_id, label };
    void save.write(JSON.stringify(body), key => api.feedback(body, key));
  };
  return <div role="tabpanel" aria-label="Calibration">
    {data ? <><Metrics data={data} /><Card title={<h2>Analyst feedback</h2>}>
      {!data.recent.length ? <p>No decisions are available for review.</p> : <div className="table-scroll"><table className="data-table"><thead><tr><th>Rule</th><th>Decision time</th><th>Feedback</th></tr></thead>
        <tbody>{data.recent.map(r => <tr key={r.decision_id + r.rule_id}><td>{r.rule_id}</td><td><Time value={r.occurred_at} /></td>
          <td>{r.label === "confirm_tp" ? "True positive" : r.label === "mark_fp" ? "False positive" : "Unlabelled"}
            {canWrite && <div className="row-actions"><Button disabled={save.busy || r.label === "confirm_tp"} onClick={() => feedback(r, "confirm_tp")}>Confirm TP</Button><Button disabled={save.busy || r.label === "mark_fp"} onClick={() => feedback(r, "mark_fp")}>Mark FP</Button></div>}</td></tr>)}</tbody></table></div>}
      {save.message && <p role="status">{save.message}</p>}
    </Card></> : <p role="status">{query.status === "loading" || query.status === "idle" ? "Loading calibration…" : "Calibration data is unavailable."}</p>}
    <Button disabled={query.status === "loading"} onClick={() => void query.retry()}>Refresh metrics</Button>
    {ruleID && <Card title={<h2>Per-rule suppression</h2>}><Select label="Guardrail rule" value={ruleID} onChange={e => setPicked(e.target.value)}>
      {ruleIDs.map(id => <option key={id}>{id}</option>)}</Select><SuppressionSettings key={ruleID} api={api} ruleID={ruleID} canWrite={canWrite} /></Card>}
    <CalibrationExports />
  </div>;
}
