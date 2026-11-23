"use client";

import { useCallback, useState } from "react";
import { addonID, type AddonReviewAPI } from "../../../apps/web/api/addon-reviews";
import { useAPIQuery } from "../../api/query";
import { Time } from "../../components/time";
import { Button } from "../../components/ui";

import { addonVersionLink, type ScanTarget } from "../../domain/addon-links";

export function AddonScanReceipt({api, initial, environment}: { api: AddonReviewAPI; initial?: ScanTarget; environment: string }) {
  const targetID = initial?.state === "selected" ? initial.id : "";
  const [draft, setDraft] = useState(targetID);
  const [id, setID] = useState(targetID);
  const load = useCallback((signal?: AbortSignal) => api.scan(id, signal), [api, id]);
  const result = useAPIQuery("addon-scan-receipt:" + id, load, Boolean(id));
  if (initial?.state === "invalid" || initial?.state === "foreign") {
    return <p role="alert">{initial.state === "foreign" ? "This add-on link belongs to another Environment. Select that Environment to open it." : "This add-on link is invalid."}</p>;
  }
  const receipt = result.status === "success" ? result.data : undefined;
  return <section aria-label="Find a scan receipt">
    <h3>Find a scan receipt</h3>
    <p>Enter the scan ID printed after a findings-only submission or private scan.{environment && <> Environment <code>{environment}</code>.</>}</p>
    <form onSubmit={e => { e.preventDefault(); if (addonID.test(draft.trim())) setID(draft.trim()); }}>
      <label>Scan ID <input value={draft} maxLength={40} onChange={e => setDraft(e.target.value)} /></label>{" "}
      <Button type="submit" disabled={!addonID.test(draft.trim())}>Open receipt</Button>
    </form>
    {id && result.status === "loading" && <p role="status">Reading scan receipt…</p>}
    {id && ["error","stale","forbidden"].includes(result.status) && <p role="alert">This receipt is unavailable in the current Environment. <Button onClick={() => void result.retry()}>Retry receipt</Button></p>}
    {receipt && <section aria-label="Scan receipt">
      <h4>{receipt.completeness === "complete" ? "Complete scan" : "Partial scan"}</h4>
      <p><code>{receipt.id}</code> · <Time value={receipt.received} /></p>
      <p>Reported source {receipt.origin} · {receipt.ruleset} · Skipped entries {receipt.skipped}</p>
      {receipt.findings.length ? <ul>{receipt.findings.map(f => <li key={f.rule_id}>{f.rule_id} · {f.count}</li>)}</ul> : <p>No findings were reported by this scan.</p>}
      {receipt.completeness === "complete" ? <><p>Manifest <code>{receipt.digest}</code></p><a href={addonVersionLink(receipt.versionID, environment)}>Open version review</a></> :
        <p>Coverage is incomplete. Check the skipped entries in the local report before scanning again. Version review requires a complete scan.</p>}
    </section>}
  </section>;
}
