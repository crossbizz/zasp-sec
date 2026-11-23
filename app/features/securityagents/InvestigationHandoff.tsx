"use client";

import { useCallback, useMemo, useState } from "react";
import type {
  AnalystThread,
  SecurityAgentApproval,
  SecurityAgentRunDetail,
  StudioReviewHandoff,
} from "../../../apps/web/api/generated";
import { listSecurityAgentActivityRuns } from "../../../apps/web/api/security-agent-activity";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { useSession } from "../../auth/SessionProvider";
import { activityLink } from "../../domain/activity-links";
import { Button } from "../../components/ui";
import { Time } from "../../components/time";
import { StudioRemediationReview } from "./StudioRemediationReview";
import { InvestigationPolicyDraft } from "./InvestigationPolicyDraft";
import { createSecurityAgentsAPI } from "./SecurityAgentsView";

type HandoffProps = { thread: AnalystThread; handoff: StudioReviewHandoff };

export function pendingSessionApproval(
  thread: AnalystThread,
  handoff: StudioReviewHandoff,
  run: SecurityAgentRunDetail,
  approval: SecurityAgentApproval,
) {
  const step = run.plan?.steps[0];
  const target = run.run_context?.trigger;
  return (
    handoff.proposal === "request_containment" &&
    target?.kind === "runtime_decision" &&
    target.id === thread.session_id &&
    run.run.state === "waiting_approval" &&
    run.plan?.steps.length === 1 &&
    step?.action === "isolate_session" &&
    step.authorization === "approval_required" &&
    step.id === approval.step_id &&
    approval.run_id === run.run.id &&
    approval.approval_context?.plan_hash === run.plan.plan_hash &&
    approval.approval_context.action === step.action &&
    approval.approval_context.target_id === thread.session_id &&
    approval.state === "pending" &&
    approval.reversible &&
    approval.ttl_seconds >= 60 &&
    approval.ttl_seconds <= 3600 &&
    Date.parse(approval.expires_at) > Date.now()
  );
}

export default function InvestigationHandoff(props: HandoffProps) {
  return props.handoff.proposal === "propose_policy" ? (
    <InvestigationPolicyDraft {...props} />
  ) : (
    <ContainmentReview {...props} />
  );
}

function ContainmentReview({ thread, handoff }: HandoffProps) {
  const session = useSession();
  const {
    client,
    queryScopeKey,
    queryGeneration,
    getSessionInvalidationGeneration,
    getScopeStaleGeneration,
  } = useAPI();
  const [open, setOpen] = useState(false);
  const [pages, setPages] = useState<string[]>([]);
  const cursor = pages.at(-1);
  const allowed =
    session.status === "authenticated" &&
    session.hasCapability("security-agents.read") &&
    queryScopeKey !== null;
  const scope = allowed ? [session.organizationID, session.workspaceID, session.environmentID].join("/") : "";
  const key = queryScopeKey === null ? null : queryScopeKey + "/" + queryGeneration;
  const api = useMemo(() => {
    const epoch = getSessionInvalidationGeneration(),
      generation = getScopeStaleGeneration();
    return createSecurityAgentsAPI(
      client,
      scope,
      () =>
        !!scope &&
        key !== null &&
        epoch === getSessionInvalidationGeneration() &&
        generation === getScopeStaleGeneration(),
    );
  }, [client, scope, key, getSessionInvalidationGeneration, getScopeStaleGeneration]);
  const read = useCallback(
    async (signal?: AbortSignal) => {
      const [organization_id, workspace_id, environment_id] = scope.split("/");
      const page = await listSecurityAgentActivityRuns(
        client,
        thread.session_id,
        "session",
        { organization_id, workspace_id, environment_id },
        { limit: 5, cursor, signal },
      );
      const found: SecurityAgentApproval[] = [];
      for (const listed of page.items) {
        if (listed.state !== "waiting_approval") continue;
        const run = await api.getSecurityAgentRun(listed.id, signal);
        if (
          run.plan?.steps.length !== 1 ||
          run.plan.steps[0].action !== "isolate_session" ||
          run.approvals.length !== 1
        )
          continue;
        const approval = await api.getSecurityAgentApproval(run.approvals[0].id, signal);
        if (pendingSessionApproval(thread, handoff, run, approval)) found.push(approval);
      }
      return { found, next: page.next_cursor };
    },
    [api, client, scope, thread, handoff, cursor],
  );
  const load = useAPIQuery(
    ["studio-approvals", thread.id, handoff.message_id, scope, cursor].join("/"),
    read,
    allowed && open,
  );
  if (!allowed) return null;
  const cited = thread.messages.find((m) => m.id === handoff.message_id && m.role === "assistant");
  if (!cited?.evidence_ids.length) return null;
  return (
    <section aria-label="Workflow handoff">
      <h3>Containment review</h3>
      <p>
        The saved workflow requests human review for this session. Its analyst response cites{" "}
        {cited.evidence_ids.length} evidence {cited.evidence_ids.length === 1 ? "record" : "records"}.
      </p>
      {!open ? (
        <Button onClick={() => setOpen(true)}>Find pending approvals</Button>
      ) : (
        <>
          {load.data ? (
            <>
              {load.data.found.length ? (
                <ul>
                  {load.data.found.map((a) => (
                    <li key={a.id}>
                      <strong>{a.expected_effect}</strong> · Expires <Time value={a.expires_at} /> ·{" "}
                      <a href={activityLink({ kind: "approval", id: a.id }, session)}>Review approval</a>
                      <StudioRemediationReview
                        thread={thread.id}
                        sessionID={thread.session_id}
                        message={handoff.message_id}
                        approval={a.id}
                      />
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No matching pending approval on this page.</p>
              )}
              <div className="row-actions">
                <Button onClick={() => void load.retry()}>Refresh approvals</Button>
                {pages.length > 0 && (
                  <Button onClick={() => setPages((p) => p.slice(0, -1))}>Previous runs</Button>
                )}
                {load.data.next && (
                  <Button onClick={() => setPages((p) => [...p, load.data!.next!])}>Next runs</Button>
                )}
              </div>
            </>
          ) : load.status === "error" || load.status === "forbidden" ? (
            <p role="alert">
              Approval records could not be loaded.{" "}
              <Button onClick={() => void load.retry()}>Retry approvals</Button>
            </p>
          ) : (
            <p role="status">Checking related workflow approvals…</p>
          )}
        </>
      )}
    </section>
  );
}
