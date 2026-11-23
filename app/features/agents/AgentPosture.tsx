"use client";

import { useCallback } from "react";
import type { AgentPostureSummary, Capability } from "../../../apps/web/api/generated";
import { useAPIQuery } from "../../api/query";
import { Button } from "../../components/ui";
import { Time } from "../../components/time";

import {useOptionalSession} from "../../auth/SessionProvider";
import {ReviewedPurpose} from "./ReviewedPurpose";

type Props = {
  agent: string; capabilities: readonly Capability[];
  getPosture: (id: string, signal?: AbortSignal) => Promise<AgentPostureSummary>;
};
const evidenceLabels = {
  runtime_receipt: "Deployed agent · attributed runtime event",
  provider_workload: "Deployed agent · provider workload record",
  repository: "Repository code · awaiting deployment evidence",
  unverified: "Deployment unconfirmed",
};

export function AgentPosture({agent,capabilities,getPosture}: Props) {
  const session = useOptionalSession();
  const load = useCallback((signal?: AbortSignal) => getPosture(agent,signal),[getPosture,agent]);
  const query = useAPIQuery(`agent-posture:${agent}`,load);
  const row = query.status === "success" ? query.data : undefined;
  const outside = row?.purpose_revision ? capabilities.filter(cap => cap.reachable && cap.state !== "blocked" && cap.target_kind === "tool" && !row.allowed_tool_ids.includes(cap.target_id)) : [];
  return <section aria-label="Agent posture">
    <h3>Agent posture</h3>
    {query.status === "loading" || query.status === "idle" ? <p role="status">Loading posture…</p> : !row ? <p role="alert">Posture evidence is unavailable. <Button onClick={() => void query.retry()}>Retry posture</Button></p> : <>
      <p>{evidenceLabels[row.deployment_evidence]}</p>
      <dl>
        <dt>Approved purpose</dt><dd>{row.purpose_revision ? `${row.allowed_tool_ids.length} intended tools · revision ${row.purpose_revision}` : "Awaiting a purpose declaration"}</dd>
        <dt>Granted access</dt><dd>{row.access_known ? row.granted_categories.map(name => name.replaceAll("_"," ")).join(", ") || "No reachable capability recorded" : "Inventory coverage unavailable"}</dd>
        <dt>Observed use</dt><dd>{row.last_observed_at ? <>Last observed <Time value={row.last_observed_at}/> · evidence <code>{row.observed_evidence_id}</code></> : "No runtime activity with confirmed attribution"}</dd>
      </dl>
      {!!row.sync_reviews?.length && <section aria-label="Post-sync review"><h4>Post-sync review</h4>
        {row.sync_reviews.map(review => <div key={review.purpose}>
          <strong>{review.purpose === "agent_discovery_verify" ? "Repository classification" : "Suggested purpose"}</strong>
          {review.state === "pending" ? <p>Awaiting qualified model review.</p> : review.state === "uncertain" ? <p>Insufficient verified evidence.</p> :
            review.result && ("kind" in review.result ? <p>{review.result.kind.replaceAll("_", " ")} · evidence <code>{review.evidence_id}</code></p> :
            <><p>{review.result.allowed_tool_ids.length} proposed tools · evidence <code>{review.evidence_id}</code></p>
              {review.result.iam_mismatches.length > 0 && <p>Access evidence to review · {review.result.iam_mismatches.join(", ")}</p>}
              {session?.status === "authenticated" && session.hasCapability("policies.write") &&
               (session.isFreshAuthenticated ? <ReviewedPurpose agent={agent} tools={review.result.allowed_tool_ids} /> : <Button onClick={session.reauthenticate}>Verify identity to review declaration</Button>)}</>)}
        </div>)}
      </section>}
      {outside.length > 0 && <details><summary>Reachable tools outside the approved purpose ({outside.length})</summary>
        <ul>{outside.map(cap => <li key={`${cap.category}/${cap.target_id}/${cap.outcome}`}><code>{cap.target_id}</code> · {cap.outcome} · evidence {cap.evidence_ids.join(", ")}</li>)}</ul>
      </details>}
    </>}
  </section>;
}
