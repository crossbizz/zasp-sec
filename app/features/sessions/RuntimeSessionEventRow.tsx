import type { RuntimeSessionEvent } from "../../../apps/web/api/generated";
import { RuntimeConfidence } from "./RuntimeConfidence";

const labels: Record<RuntimeSessionEvent["class"], Partial<Record<RuntimeSessionEvent["action"], string>>> = {
  tool: { invoke: "Tool invocation" }, runtime: { exec: "Process execution", exit: "Process exit" },
  network: { connect: "Network connection", accept: "Network acceptance" }, file: { read: "File read", write: "File write" },
  credential: { use: "Credential use observation" }, policy: { allow: "Policy allow observation", monitor: "Policy monitor observation", block: "Policy block observation" },
};

export function RuntimeSessionEventRow({ event, onEvidence }: { event: RuntimeSessionEvent; onEvidence?: (event: RuntimeSessionEvent) => void }) {
  return <li data-runtime-event-id={event.id} data-runtime-evidence-id={event.evidence_id} data-runtime-event-class={event.class}>
    <p><time dateTime={event.at} data-runtime-event-time={event.at}>{event.at}</time> · <strong>{labels[event.class][event.action]}</strong></p>
    <p>{event.label}</p>
    <p><RuntimeConfidence confidence={event.confidence} /> · Source: {event.source}</p>
    <p>Evidence: {onEvidence ? <a href={`#runtime-evidence-${event.id}`} aria-label={`Open evidence ${event.evidence_id}`} aria-haspopup="dialog" onClick={click => { click.preventDefault(); onEvidence(event); }}>{event.evidence_id}</a> : event.evidence_id} · Event: {event.id}</p>
  </li>;
}
