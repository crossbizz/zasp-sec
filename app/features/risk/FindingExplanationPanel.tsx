"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useAPI } from "../../api/APIProvider";
import { Button, Card } from "../../components/ui";
import { workflowIdempotencyKey } from "../workflows/api";
import { createFindingExplanationAPI, decodeFindingExplanation, findingExplanationVersion, type FindingExplanationAPI, type FindingExplanationIntent, type FindingExplanationResponse } from "./finding-explanation-api";

type Props = Readonly<{ findingID: string; version: string; api?: FindingExplanationAPI }>;
export function FindingExplanationPanel({ findingID, version, api: suppliedAPI }: Props) {
  const { client, queryScopeKey, queryGeneration } = useAPI();
  const api = useMemo(() => suppliedAPI ?? createFindingExplanationAPI(client), [client, suppliedAPI]);
  const findingVersion = findingExplanationVersion(version);
  if (queryScopeKey === null || queryScopeKey === "__unscoped__" || findingVersion === null) return <Card title="Optional AI explanation"><p role="status">Explanation unavailable until the current finding and access are verified. Your finding controls and evidence remain available.</p></Card>;
  return <ExplanationRequest key={JSON.stringify([queryScopeKey, queryGeneration, findingID, findingVersion])} findingID={findingID} findingVersion={findingVersion} api={api} />;
}

function ExplanationRequest({ findingID, findingVersion, api }: Readonly<{ findingID: string; findingVersion: number; api: FindingExplanationAPI }>) {
  const [intent, setIntent] = useState<FindingExplanationIntent | null>(null);
  const [response, setResponse] = useState<FindingExplanationResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [unavailable, setUnavailable] = useState(false);
  const active = useRef<AbortController | null>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; active.current?.abort(); active.current = null; }; }, []);
  const terminal = response?.state === "complete" || response?.state === "failed";
  async function request(newIntent: boolean) {
    // The ref also closes duplicate clicks before React commits loading state.
    if (active.current || (!newIntent && !intent) || (newIntent && intent && !terminal)) return;
    const controller = new AbortController(); active.current = controller;
    const selected = newIntent ? { finding_id: findingID, finding_version: findingVersion, idempotency_key: workflowIdempotencyKey() } : intent!;
    setIntent(selected); setLoading(true); setUnavailable(false);
    // A new paid request never displays output from the previous generation.
    if (newIntent) setResponse(null);
    try {
      const result = decodeFindingExplanation(await api.createAIExplanation(selected, controller.signal), selected);
      if (!mounted.current || controller.signal.aborted || active.current !== controller) return;
      setResponse(result);
    } catch {
      if (!mounted.current || controller.signal.aborted || active.current !== controller) return;
      setResponse(null); setUnavailable(true);
    } finally {
      if (mounted.current && active.current === controller) { active.current = null; setLoading(false); }
    }
  }
  return <Card title="Optional AI explanation">
    <p>Only rule, severity and evidence count are sent. Finding titles and evidence contents are excluded.</p>
    <p>Source: finding version {findingVersion}. <a href={`#finding-evidence-${findingID}`}>Review current evidence</a>.</p>
    <p>Generated guidance can be wrong. Verify it against current evidence. It does not change this finding or authorize actions.</p>
    {loading && <p role="status">Checking explanation request…</p>}
    {unavailable && <p role="alert">Explanation unavailable. The outcome may be unknown. Check the existing request before starting another. Finding controls and evidence remain available.</p>}
    {response?.state === "unknown" && <p role="status">The provider outcome is unknown. Checking this request will not send a new explanation request.</p>}
    {(response?.state === "reserved" || response?.state === "started") && <p role="status">Explanation request pending. Check the existing request for its status.</p>}
    {response?.state === "failed" && <p role="status">Explanation request failed. Your finding and evidence are unchanged.</p>}
    {response?.state === "complete" && (response.explanation || response.recommendation ? <section aria-label="Generated explanation">
      {response.explanation && <><h3>Generated explanation</h3><p style={{ whiteSpace: "pre-wrap" }}>{response.explanation}</p></>}
      {response.recommendation && <><h3>Suggested next step</h3><p style={{ whiteSpace: "pre-wrap" }}>{response.recommendation}</p></>}
      <p>This text is temporary and is not retained for replay.</p>
    </section> : <p role="status">Request complete. The explanation was not retained and cannot be replayed.</p>)}
    {!intent ? <Button disabled={loading} onClick={event => { if (event.detail < 2) void request(true); }}>Generate explanation</Button> : terminal ? <Button disabled={loading} onClick={event => { if (event.detail < 2) void request(true); }}>Generate another explanation</Button> : <Button disabled={loading} onClick={event => { if (event.detail < 2) void request(false); }}>Check existing request</Button>}
  </Card>;
}
