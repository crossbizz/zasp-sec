"use client";

import { useEffect, useMemo, useState } from "react";
import { createFleetAPI } from "../../../apps/web/api/endpoint-fleet";
import type { APIClient } from "../../../apps/web/api/client";
import type { ComplianceExportInput } from "../../../apps/web/api/generated";

type Choice = { id: string; cohort: string };
type PilotScope = "cohort" | "device" | "session";
const deviceID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const cohortLabel = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const sessionRef = /^[0-9a-f]{64}$/;

export function pilotSelection(scope: PilotScope, cohort: string, device: string, session: string): ComplianceExportInput | undefined {
  if (scope === "cohort") return cohortLabel.test(cohort) ? { pilot_cohort: cohort } : undefined;
  if (!deviceID.test(device)) return;
  if (scope === "device") return { device_id: device };
  if (sessionRef.test(session)) return { device_id: device, endpoint_session_ref: session };
}

export function PilotEvidenceForm({ client, fresh, busy, create, environmentID, reauthenticate }: {
  client: APIClient; environmentID: string; fresh: boolean; busy: boolean; create(input: ComplianceExportInput): void; reauthenticate?(): void;
}) {
  const fleet = useMemo(() => createFleetAPI(client), [client]);
  const [open, setOpen] = useState(false);
  const [scopeMismatch, setScopeMismatch] = useState(false);
  const [scope, setScope] = useState<PilotScope>("cohort");
  const [devices, setDevices] = useState<Choice[]>([]);
  const [cohort, setCohort] = useState(""), [device, setDevice] = useState(""), [session, setSession] = useState("");
  const [page, setPage] = useState<string | undefined>(), [next, setNext] = useState<string | null>(null);
  const [listState, setListState] = useState<"pending" | "ready" | "unavailable">("pending");
  useEffect(() => {
    const fields = new URLSearchParams(window.location.hash.slice(1));
    if (!fields.has("pilot_environment")) return;
    const requested = fields.get("pilot_environment");
    if (requested !== environmentID) {
      queueMicrotask(() => setScopeMismatch(true));
      return;
    }
    const c = fields.get("pilot_cohort") ?? "", d = fields.get("device_id") ?? "", ref = fields.get("endpoint_session_ref") ?? "";
    const kind = c ? "cohort" : ref ? "session" : "device";
    if ((c && (d || ref)) || !pilotSelection(kind, c, d, ref)) return;
    queueMicrotask(() => { setScope(kind); setCohort(c); setDevice(d); setSession(ref); setScopeMismatch(false); setOpen(true); });
  }, [environmentID]);
  useEffect(() => {
    if (!open || scopeMismatch) return;
    const controller = new AbortController();
    fleet.list(page, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      setDevices((prev) => page ? [...prev, ...result.items.filter((row) => !prev.some((old) => old.id === row.id))] : [...result.items]);
      setNext(result.next_after_id);
      setListState("ready");
    }).catch(() => { if (!controller.signal.aborted) setListState("unavailable"); });
    return () => controller.abort();
  }, [fleet, page, open, scopeMismatch]);
  const selected = pilotSelection(scope, cohort, device, session);
  if (scopeMismatch) return <p role="alert">The export link belongs to a different Environment. Switch to the requested Environment before opening the link.</p>;
  if (!open) return <button type="button" onClick={() => setOpen(true)}>Export managed pilot evidence</button>;
  return (
    <form
      aria-label="Managed pilot evidence"
      onSubmit={(event) => {
        event.preventDefault();
        if (selected && fresh && !busy) create(selected);
      }}
    >
      <h3>Managed pilot evidence</h3>
      <p>Capture registered devices, policy acknowledgments, endpoint decisions and installed digests. The report labels missing coverage and independent verification.</p>
      <fieldset disabled={busy}>
        <label>
          Report scope
          <select value={scope} onChange={(event) => setScope(event.target.value as PilotScope)}>
            <option value="cohort">Pilot cohort</option>
            <option value="device">One device</option>
            <option value="session">One device-bound session</option>
          </select>
        </label>
        {scope === "cohort" ? (
          <label>Cohort <input list="pilot-cohorts" value={cohort} onChange={(event) => setCohort(event.target.value)} /></label>
        ) : (
          <label>Device ID <input list="pilot-devices" value={device} onChange={(event) => setDevice(event.target.value)} /></label>
        )}
        <datalist id="pilot-cohorts">
          {[...new Set(devices.map((row) => row.cohort))].map((name) => <option key={name} value={name} />)}
        </datalist>
        <datalist id="pilot-devices">
          {devices.map((row) => <option key={row.id} value={row.id}>{row.cohort}</option>)}
        </datalist>
        {scope === "session" && (
          <label>Session reference from a device observation
            <input spellCheck={false} value={session} onChange={(event) => setSession(event.target.value)} />
          </label>
        )}
        {scope === "cohort" && cohort && !cohortLabel.test(cohort) && <p>Use the registered cohort label, up to 64 letters, digits, dots, underscores or hyphens.</p>}
        {scope !== "cohort" && device && !deviceID.test(device) && <p>Enter the complete device ID from the selected Environment.</p>}
        {scope === "session" && session && !sessionRef.test(session) && <p>Copy the 64-character reference from the device observation.</p>}
        {listState === "pending" && <p role="status">Loading registered devices…</p>}
        {listState === "unavailable" && <p role="status">Device suggestions unavailable. Enter a known selector for the current Environment.</p>}
        {next && devices.length < 250 && (
          <button type="button" onClick={() => { setPage(next); setNext(null); setListState("pending"); }}>
            Load more device suggestions
          </button>
        )}
        {!fresh && (
          <p>
            Renew your browser session to request a retained report.{" "}
            {reauthenticate && <button type="button" onClick={reauthenticate}>Renew session</button>}
          </p>
        )}
        <button type="submit" disabled={!selected || !fresh || busy}>Request retained pilot report</button>
      </fieldset>
    </form>
  );
}
