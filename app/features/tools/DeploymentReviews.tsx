"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { APIProductError } from "../../../apps/web/api/client";
import type { DeploymentAPI, DeploymentAttempt } from "../../../apps/web/api/addon-deployments";
import { useAPIQuery } from "../../api/query";
import { Button, Select } from "../../components/ui";

const titles = {pending: "Awaiting review", approved: "Approved", needs_re_review: "Permissions changed · review required", revoked: "Revoked"};

export function DeploymentReviews({api, versionID, versionRevision, canReview}: {
  api: DeploymentAPI; versionID: string; versionRevision: number; canReview: boolean;
}) {
  const [open,setOpen] = useState(false);
  const [agent,setAgent] = useState("");
  const [notice,setNotice] = useState("");
  const [attempt,setAttempt] = useState<DeploymentAttempt | null>(null);
  const [busy,setBusy] = useState(false);
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);
  const agents = useAPIQuery("addon-deployment-agents",api.agents,open);
  const load = useCallback((signal?: AbortSignal) => api.get(versionID,agent,signal),[api,versionID,agent]);
  const review = useAPIQuery(`addon-deployment:${versionID}:${versionRevision}:${agent}`,load,open && Boolean(agent));
  const row = review.status === "success" && review.data?.agent_id === agent ? review.data : null;
  const canApprove = row?.version_approved && row.purpose_revision > 0 && row.access_revision > 0 && row.identity_count > 0;
  async function submit() {
    if (!attempt || !canReview || active.current) return;
    const controller = new AbortController();
    active.current = controller; setBusy(true); setNotice("");
    try {
      await api.review(attempt,controller.signal);
      if (controller.signal.aborted) return;
      setAttempt(null); setNotice("Decision recorded."); await review.retry();
    } catch (error) {
      if (controller.signal.aborted) return;
      if (error instanceof APIProductError && error.status >= 400 && error.status < 500 && error.status !== 429) {
        setAttempt(null); setNotice("The review changed or access expired. Refresh the current decision before reviewing again."); await review.retry();
      } else setNotice("The decision is unconfirmed. Retry to retrieve its receipt.");
    } finally {
      if (!controller.signal.aborted) { setBusy(false); active.current = null; }
    }
  }
  return <section aria-label="Deployment reviews">
    <h3>Deployment reviews</h3>
    {!open ? <Button onClick={() => setOpen(true)}>Review a deployment</Button> : <>
      {(agents.status === "loading" || agents.status === "idle") && <p role="status">Loading agents…</p>}
      {agents.status === "empty" && <p>No agents are available in this environment.</p>}
      {["error","stale","forbidden"].includes(agents.status) && <p role="alert">Agent inventory is unavailable. <Button onClick={() => void agents.retry()}>Retry inventory</Button></p>}
      {agents.status === "success" && <Select label="Deployment agent" value={agent} disabled={busy || Boolean(attempt)} onChange={event => {setAgent(event.target.value);setNotice("");}}>
        <option value="">Choose an agent</option>{agents.data?.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
      </Select>}
      {agent && review.status === "loading" && <p role="status">Loading deployment permissions…</p>}
      {agent && ["error","stale","forbidden"].includes(review.status) && <p role="alert">Deployment permissions are unavailable. <Button onClick={() => void review.retry()}>Refresh permissions</Button></p>}
      {row && <><p><strong>{titles[row.state]}</strong></p><dl>
        <dt>Approved purpose</dt><dd>{row.purpose_revision ? `Revision ${row.purpose_revision}` : "Awaiting declaration"}</dd>
        <dt>Deployment identities</dt><dd>{row.identity_count} observed</dd>
        <dt>Allowed data classes</dt><dd>{row.classifications.join(", ") || "None declared"}</dd>
        <dt>Allowed destinations</dt><dd>{row.destinations.join(", ") || "None declared"}</dd>
      </dl>{!canApprove && <p>Approval requires a reviewed version, a saved purpose, action settings, and an observed deployment identity.</p>}
      {canReview && !attempt && <div className="page-actions">
        {canApprove && row.state !== "approved" && <Button onClick={() => setAttempt({receipt:row,decision:"approved",key:crypto.randomUUID()})}>Approve deployment</Button>}
        {(row.state === "approved" || row.state === "needs_re_review") && <Button onClick={() => setAttempt({receipt:row,decision:"revoked",key:crypto.randomUUID()})}>Revoke deployment approval</Button>}
      </div>}</>}
      {canReview && attempt && <div><p>Record this deployment as {attempt.decision} for the permissions shown?</p><Button disabled={busy} onClick={() => void submit()}>Confirm deployment decision</Button> <Button disabled={busy} onClick={() => setAttempt(null)}>Cancel</Button></div>}
      {notice && <p role="status">{notice}</p>}
    </>}
  </section>;
}
