"use client";

import { useEffect, useState } from "react";

import type { TestAttempt, TestDefinition, TestProbeCatalog, TestSchedule } from "../../../apps/web/api/generated";
import { Badge, Button, Card, Select } from "../../components/ui";
import type { ProductionRedTeamAPI } from "./api";

type CatalogState = Readonly<{ status: "loading" | "ready" | "unavailable"; catalog?: TestProbeCatalog }>;

// The probe library is the same for every scope of one release, so a view
// reads it once and keeps what the API returned.
export function useProbeCatalog(api: ProductionRedTeamAPI): CatalogState {
  const [state, setState] = useState<CatalogState>({ status: "loading" });
  useEffect(() => {
    const controller = new AbortController();
    api.getProbeCatalog(controller.signal).then(
      (catalog) => { if (!controller.signal.aborted) setState({ status: "ready", catalog }); },
      () => { if (!controller.signal.aborted) setState({ status: "unavailable" }); },
    );
    return () => controller.abort();
  }, [api]);
  return state;
}

export function probeCountLabel(state: CatalogState, category: string): string {
  const entry = state.catalog?.categories.find((item) => item.category === category);
  return entry ? ` (${entry.probe_count} probes)` : "";
}

export function ProbeLibraryCard({ api }: { api: ProductionRedTeamAPI }) {
  const state = useProbeCatalog(api);
  return <Card title="Probe library">
    {state.status === "loading" && <p role="status">Loading the probe library…</p>}
    {state.status === "unavailable" && <p role="alert">The probe library is unavailable.</p>}
    {state.catalog && <>
      <p>{state.catalog.probe_count} reviewed probes in {state.catalog.categories.length} categories. A run executes {state.catalog.default_sample_size} probes of each selected category, chosen by the run so that repeated runs cover different probes.</p>
      <div className="table-scroll"><table className="data-table" aria-label="Probe library categories"><thead><tr><th>Category</th><th>Probes</th><th>Techniques</th><th>Frameworks</th></tr></thead><tbody>
        {state.catalog.categories.map((category) => <tr key={category.category}><td>{category.title}</td><td>{category.probe_count}</td><td>{category.techniques.length}</td><td>{category.frameworks.map((reference) => reference.control).join(", ")}</td></tr>)}
      </tbody></table></div>
    </>}
  </Card>;
}

export function ProbeResults({ results }: { results: TestAttempt["probe_results"] }) {
  if (results.length === 0) return <p>This attempt ran one curated check per category; no probe list was recorded.</p>;
  const unsafe = results.filter((item) => item.outcome === "unsafe").length;
  return <section aria-label="Probes run">
    <h4>Probes run</h4>
    <p>{results.length} probes · {results.length - unsafe} protected · {unsafe} unsafe</p>
    <div className="table-scroll"><table className="data-table"><thead><tr><th>Probe</th><th>Category</th><th>Technique</th><th>Outcome</th></tr></thead><tbody>
      {results.map((item) => <tr key={item.probe_id}><td><code>{item.probe_id}</code></td><td>{item.category.replaceAll("_", " ")}</td><td>{probeTechnique(item.probe_id, item.category)}</td><td><Badge tone={item.outcome === "protected" ? "success" : "critical"}>{item.outcome}</Badge></td></tr>)}
    </tbody></table></div>
  </section>;
}

// A probe identifier is zasp.<category>.<technique>.<objective>.<carrier>.v1.
function probeTechnique(probeID: string, category: string): string {
  return (probeID.slice(`zasp.${category}.`.length).split(".")[0] ?? "").replaceAll("_", " ");
}

const cadenceOptions = [["", "No cadence"], ["3600", "Every hour"], ["21600", "Every 6 hours"], ["86400", "Every day"], ["604800", "Every week"], ["2592000", "Every 30 days"]] as const;

export function ScheduleControl({ api, definition, canWrite, locked }: { api: ProductionRedTeamAPI; definition: TestDefinition; canWrite: boolean; locked: boolean }) {
  const [schedule, setSchedule] = useState<TestSchedule | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "unavailable" | "saving">("loading");
  const [error, setError] = useState("");
  const [cadence, setCadence] = useState("");
  const [onChange, setOnChange] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    api.getSchedule(definition.id, controller.signal).then(
      (value) => { if (controller.signal.aborted) return; setSchedule(value); setCadence(value.cadence_seconds === null ? "" : String(value.cadence_seconds)); setOnChange(value.on_target_change); setStatus("ready"); },
      () => { if (!controller.signal.aborted) setStatus("unavailable"); },
    );
    return () => controller.abort();
  }, [api, definition.id]);
  const save = async (enabled: boolean) => {
    if (!schedule || status !== "ready" || locked) return;
    setStatus("saving"); setError("");
    try {
      const saved = await api.putSchedule(definition.id, { expected_version: schedule.version, enabled, on_target_change: onChange, ...(cadence === "" ? {} : { cadence_seconds: Number(cadence) }) });
      setSchedule(saved);
    } catch {
      setError("The schedule was not saved. It may have changed, or the test no longer passes the non-production safety rule. Reload before retrying.");
    } finally { setStatus("ready"); }
  };
  const hasTrigger = cadence !== "" || onChange;
  const known = cadenceOptions.some(([value]) => value === cadence);
  return <section aria-label="Continuous re-test">
    <h3>Continuous re-test</h3>
    {status === "loading" && <p role="status">Loading the schedule…</p>}
    {status === "unavailable" && <p role="alert">The schedule is unavailable.</p>}
    {schedule && <>
      <p><Badge tone={schedule.enabled ? "success" : "neutral"}>{schedule.enabled ? "scheduled" : "not scheduled"}</Badge>{schedule.next_run_at && <> · next run {schedule.next_run_at}</>}</p>
      {schedule.last_fired_at && <p>Last scheduled occurrence {schedule.last_fired_at}: {schedule.last_trigger === "target_change" ? "the target changed" : "cadence"}, {schedule.last_outcome === "queued" ? "run queued" : schedule.last_outcome === "rejected" ? "not run: the test is disabled or no longer passes the safety rule" : "skipped: a run was still active"}.</p>}
      {canWrite && <>
        <Select disabled={locked || status !== "ready"} label="Cadence" value={cadence} onChange={(event) => setCadence(event.target.value)}>
          {cadenceOptions.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          {!known && <option value={cadence}>Every {cadence} seconds</option>}
        </Select>
        <label><input type="checkbox" disabled={locked || status !== "ready"} checked={onChange} onChange={(event) => setOnChange(event.target.checked)} /> Re-test when the target&apos;s inventory record changes</label>
        <div className="button-row">
          <Button variant="primary" disabled={locked || status !== "ready" || !hasTrigger || !definition.enabled} onClick={() => void save(true)}>{schedule.enabled ? "Update schedule" : "Enable schedule"}</Button>
          {schedule.enabled && <Button disabled={locked || status !== "ready"} onClick={() => void save(false)}>Disable schedule</Button>}
        </div>
        {!definition.enabled && <p>Enable the test before scheduling it.</p>}
        <p>Scheduled runs use the same safety rule as manual runs: development, test or staging only, checked again before each run.</p>
      </>}
      {error && <p role="alert">{error}</p>}
    </>}
  </section>;
}
