"use client";

import { useEffect, useMemo, useState } from "react";
import { APITransportError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import type { RuntimeSessionEvent } from "../../../apps/web/api/generated";
import { decodeRuntimeSessionEvent } from "../../../apps/web/api/runtime-session-decoders";
import { Button, LoadingState } from "../../components/ui";
import { RuntimeConfidence } from "./RuntimeConfidence";

export type RuntimeEvidenceTarget = { investigationID: string; eventID: string; evidenceID: string };
export interface RuntimeSessionEvidenceAPI {
  get(target: RuntimeEvidenceTarget, signal: AbortSignal): Promise<RuntimeSessionEvent>;
}
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function validTarget(target: RuntimeEvidenceTarget) {
  if ((target.investigationID !== "unattributed" && !productID.test(target.investigationID)) || !productID.test(target.eventID) || !productID.test(target.evidenceID)) throw new APITransportError("invalid_response", "Invalid evidence target");
}
function targetEvent(value: unknown, target: RuntimeEvidenceTarget): RuntimeSessionEvent {
  validTarget(target);
  const event = decodeRuntimeSessionEvent(value);
  if (event.id !== target.eventID || event.evidence_id !== target.evidenceID || event.session_id !== (target.investigationID === "unattributed" ? null : target.investigationID)) throw new APITransportError("invalid_response", "Evidence target mismatch");
  return event;
}
export function createRuntimeSessionEvidenceAPI(client: APIClient): RuntimeSessionEvidenceAPI {
  return { async get(target, signal) {
    validTarget(target);
    return targetEvent(requireAPIData(await client.GET("/api/v1/sessions/{id}/events/{eventId}", { params: { path: { id: target.investigationID, eventId: target.eventID } }, signal })), target);
  } };
}

export function RuntimeSessionEvidence({ target, api }: { target: RuntimeEvidenceTarget; api: RuntimeSessionEvidenceAPI }) {
  const [attempt, setAttempt] = useState(0);
  const { investigationID, eventID, evidenceID } = target;
  const query = useMemo(() => ({ target: { investigationID, eventID, evidenceID }, api, attempt }), [investigationID, eventID, evidenceID, api, attempt]);
  const [load, setLoad] = useState<{ query: typeof query; event?: RuntimeSessionEvent; error?: boolean } | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => {
      if (controller.signal.aborted) return;
      void (async () => {
        validTarget(query.target);
        const event = targetEvent(await query.api.get(query.target, controller.signal), query.target);
        if (!controller.signal.aborted) setLoad({ query, event });
      })().catch(() => { if (!controller.signal.aborted) setLoad({ query, error: true }); });
    });
    return () => controller.abort();
  }, [query]);
  const current = load?.query === query ? load : null;
  if (!current) return <LoadingState label="Loading evidence metadata…" />;
  if (current.error || !current.event) return <div role="alert"><p>Evidence metadata could not be loaded. It may be unavailable or outside your current authorization.</p><Button onClick={() => setAttempt(value => value + 1)}>Retry evidence metadata</Button></div>;
  const event = current.event;
  return <section id={`runtime-evidence-${event.id}`} aria-label="Canonical evidence metadata">
    <p>{event.label}</p>
    <dl>
      <dt>Evidence reference</dt><dd>{event.evidence_id}</dd>
      <dt>Canonical event</dt><dd>{event.id}</dd>
      <dt>Event type</dt><dd>{event.class} / {event.action}</dd>
      <dt>Source</dt><dd>{event.source}</dd>
      <dt>Correlation confidence</dt><dd><RuntimeConfidence confidence={event.confidence} /></dd>
      <dt>Agent</dt><dd>{event.agent_id ?? "Unknown"}</dd>
      <dt>Session</dt><dd>{event.session_id ?? "Unattributed collection"}</dd>
      <dt>Sandbox</dt><dd>{event.sandbox_id ?? "Unknown (not recorded)"}</dd>
      {event.sandbox_source_sensor_id && <><dt>Sandbox source sensor</dt><dd>{event.sandbox_source_sensor_id}</dd></>}
      <dt>Canonical event time</dt><dd><time dateTime={event.at}>{event.at}</time></dd>
      <dt>Projection time</dt><dd><time dateTime={event.projected_at}>{event.projected_at}</time></dd>
    </dl>
    <p>Raw archive content is not included in this view.</p>
    {(event.class === "credential" || event.class === "policy") && <p>This is a source observation, not proof of credential ownership or policy enforcement.</p>}
  </section>;
}
