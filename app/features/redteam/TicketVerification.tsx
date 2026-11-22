"use client";

import { useCallback, useMemo, useState } from "react";
import { APIProductError, requireAPIData } from "../../../apps/web/api/client";
import type { TicketVerificationBundle, TicketVerificationReceipt } from "../../../apps/web/api/generated";
import { decodeTicketVerification } from "../../../apps/web/api/decoders";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button } from "../../components/ui";

export function TicketVerification({ runID, canWrite, locked }: { runID: string; canWrite: boolean; locked: boolean }) {
  const { client } = useAPI();
  const [expanded, setExpanded] = useState(false);
  const read = useCallback(async (signal?: AbortSignal) => {
    const response = await client.GET("/api/v1/test-runs/{id}/ticket-verification", { params: { path: { id: runID } }, signal });
    if (response.response.status === 404) return null;
    return requireAPIData(response, raw => decodeTicketVerification(raw, runID));
  }, [client, runID]);
  const query = useAPIQuery(`ticket-verification:${runID}`, read, expanded);
  const [files, setFiles] = useState<Partial<Record<keyof TicketVerificationBundle, File>>>({});
  const [saved, setSaved] = useState<TicketVerificationReceipt | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const value = saved ?? query.data;
  const inputs = useMemo(() => [ ["scenario", "Pinned scenario"], ["adapter", "Adapter decisions"], ["recorder", "Independent recorder readback"] ] as const, []);
  const submit = async () => {
    if (!canWrite || locked || busy || value || query.status !== "empty") return;
    setBusy(true); setError("");
    try {
      const pairs = await Promise.all(inputs.map(async ([name]) => {
        const file = files[name];
        if (!file || file.size >= 64 * 1024) throw new RangeError();
        // Keep original JSON bytes until the backend validates duplicate keys.
        const text = await file.text();
        JSON.parse(text);
        return [name, text] as const;
      }));
      const body = `{${pairs.map(([key, text]) => `${JSON.stringify(key)}:${text}`).join(",")}}`;
      if (new Blob([body]).size >= 64 * 1024) throw new RangeError();
      const response = await client.PUT("/api/v1/test-runs/{id}/ticket-verification", { params: { path: { id: runID } }, body: JSON.parse(body) as TicketVerificationBundle, bodySerializer: () => body });
      setSaved(requireAPIData(response, raw => decodeTicketVerification(raw, runID))); setFiles({});
    } catch (err) {
      if (err instanceof APIProductError && err.status === 409) { await query.retry(); setError("A different proof is already attached to this run. Open a new run to record another experiment."); }
      else setError("Import unconfirmed. Check the staged run, target, observation window and JSON exports, then retry the same files.");
    } finally { setBusy(false); }
  };
  return <section aria-label="Staging ticket verification"><h3>Staging ticket verification</h3>
    {!expanded ? <Button onClick={() => setExpanded(true)}>View ticket proof</Button> : <>
      {query.status === "loading" && <p>Looking up ticket evidence…</p>}
      {query.status === "error" || query.status === "forbidden" || query.status === "stale" ? <p role="alert">Ticket evidence is unavailable. <Button onClick={() => void query.retry()}>Retry lookup</Button></p> : null}
      {value && <><p><strong>{value.result.verdict}</strong> · {value.result.reason}</p><p>Operator-imported evidence, submitted {value.submitted_at}. Policy revision <code>{value.policy_revision}</code>. Definition version {value.definition_version}.</p><p>Evidence digest <code>{value.evidence_sha256}</code></p>
        {value.result.protected_decision_id && <p>Protected decision <code>{value.result.protected_decision_id}</code></p>}
        {value.result.control_receipt_id && <p>Allowed ticket receipt <code>{value.result.control_receipt_id}</code></p>}
        {value.result.protected_receipt_id && <p>Unexpected write receipt <code>{value.result.protected_receipt_id}</code></p>}
      </>}
      {!value && query.status === "empty" && <><p>This run has no imported ticket proof.</p>{canWrite && <fieldset disabled={locked || busy}><legend>Import a synthetic staging experiment</legend>
        <p>Use separately authenticated exports from the adapter and target recorder. Confirm the run declares <code>synthetic_ticket_update</code> with a test-write credential. An import is immutable and retains the run’s existing test verdict.</p>
        {inputs.map(([key, label]) => <label key={key}>{label}<input type="file" accept="application/json,.json" onChange={event => { const file = event.currentTarget.files?.[0]; setError(""); setFiles(previous => ({ ...previous, [key]: file })); }} /></label>)}
        <Button disabled={busy || locked || inputs.some(([key]) => !files[key])} onClick={() => void submit()}>Import ticket proof</Button>
      </fieldset>}</>}
      {error && <p role="alert">{error}</p>}
    </>}
  </section>;
}
