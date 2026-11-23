"use client";

import { useCallback, useMemo, useState } from "react";
import { APIProductError, requireAPIData } from "../../../apps/web/api/client";
import type { AnalystThread, Policy, StudioReviewHandoff } from "../../../apps/web/api/generated";
import { loadSessionIntent } from "../../../apps/web/api/runtime-intent";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { useSession } from "../../auth/SessionProvider";
import { activityLink } from "../../domain/activity-links";
import { Button } from "../../components/ui";
import { createPoliciesAPI, type WorkflowReceipt } from "../workflows/api";
import { useRetainedWorkflowMutation } from "../workflows/useRetainedWorkflowMutation";

export function InvestigationPolicyDraft({
  thread,
  handoff,
}: {
  thread: AnalystThread;
  handoff: StudioReviewHandoff;
}) {
  const session = useSession();
  const { client, queryScopeKey, getSessionInvalidationGeneration, getScopeStaleGeneration } = useAPI();
  const [open, setOpen] = useState(false);
  const [operation, setOperation] = useState("");
  const [receipt, setReceipt] = useState<WorkflowReceipt<Policy>>();
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);
  const canRead =
    session.status === "authenticated" && queryScopeKey !== null && session.hasCapability("policies.read");
  const canSave = canRead && session.hasCapability("policies.write") && session.isFreshAuthenticated;
  const writer = useRetainedWorkflowMutation<Policy>("investigation-policy:" + handoff.message_id, canSave);
  const api = useMemo(() => createPoliciesAPI(client), [client]);
  const draftID = "policy-studio-" + handoff.message_id.slice(4);
  const read = useCallback(
    async (signal?: AbortSignal) => {
      const current = requireAPIData<AnalystThread>(
        await client.GET("/api/v1/security-agents/chat/threads/{id}", {
          params: { path: { id: thread.id }, query: { session_id: thread.session_id } },
          signal,
        }),
      );
      if (
        current.id !== thread.id ||
        current.session_id !== thread.session_id ||
        current.handoff?.message_id !== handoff.message_id ||
        current.handoff?.studio_id !== handoff.studio_id ||
        current.handoff?.revision !== handoff.revision ||
        current.handoff?.proposal !== "propose_policy"
      )
        throw Error("Workflow proposal changed");
      const cited = new Set(
        current.messages.find((m) => m.id === handoff.message_id && m.role === "assistant")?.evidence_ids,
      );
      const intent = await loadSessionIntent(
        client,
        thread.session_id,
        signal ?? new AbortController().signal,
      );
      const operations = intent.actions
        .filter(
          (a) =>
            a.source === "authenticated_workload" &&
            a.evidence_ids.some((id) => cited.has(id)) &&
            /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(a.operation),
        )
        .map((a) => a.operation);
      let draft: Policy | undefined;
      try {
        draft = (await api.getPolicy(draftID, signal)).value;
        if (draft.id !== draftID) throw Error("Unexpected policy");
      } catch (e) {
        if (!(e instanceof APIProductError && e.status === 404)) throw e;
      }
      return { operations: [...new Set(operations)].sort(), draft };
    },
    [api, client, draftID, handoff, thread.id, thread.session_id],
  );
  const load = useAPIQuery("studio-policy:" + handoff.message_id, read, open && canRead);
  if (!canRead) return null;
  const target = operation || load.data?.operations[0] || "";
  async function save() {
    if (!canSave || busy) return;
    const epoch = getSessionInvalidationGeneration(),
      scope = getScopeStaleGeneration();
    setError(false);
    setBusy(true);
    try {
      const draft: Policy = {
        id: draftID,
        name: "Session operation review",
        scope: "environment",
        trigger: "tool",
        conditions: [{ field: "action", operator: "equals", value: target }],
        action: "monitor",
        rollout: "draft",
        failure_mode: "closed",
      };
      const saved = writer.canRetry
        ? await writer.retry<WorkflowReceipt<Policy>>()
        : await writer.execute(draft, async (frozen, attempt) => {
            const current = await read();
            if (
              !current.operations.includes(target) ||
              epoch !== getSessionInvalidationGeneration() ||
              scope !== getScopeStaleGeneration()
            )
              throw Error("Proposal changed");
            return api.createPolicy(frozen, attempt);
          });
      if (saved.value.id !== draftID || saved.value.rollout !== "draft" || saved.value.action !== "monitor")
        throw Error("Draft readback mismatch");
      setReceipt(saved);
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section aria-label="Review policy proposal">
      <h3>Policy proposal</h3>
      {!open ? (
        <Button onClick={() => setOpen(true)}>Review cited operations</Button>
      ) : load.data ? (
        receipt || load.data.draft ? (
          <p>
            <a href={activityLink({ kind: "policy_draft", id: draftID }, session)}>Open saved policy</a>
            {receipt && (
              <>
                {" "}
                · Audit <code>{receipt.auditID}</code>
              </>
            )}
          </p>
        ) : load.data.operations.length ? (
          <>
            <label className="field">
              Observed workload operation
              <select
                value={target}
                disabled={busy || writer.isUnresolved}
                onChange={(e) => setOperation(e.target.value)}
              >
                {load.data.operations.map((op) => (
                  <option key={op}>{op}</option>
                ))}
              </select>
            </label>
            <p>
              Save a monitoring draft for this operation. Review and rollout are separate steps in Policies.
            </p>
            {session.hasCapability("policies.write") &&
              (session.isFreshAuthenticated ? (
                <Button
                  disabled={busy || (writer.isUnresolved && !writer.canRetry)}
                  onClick={() => void save()}
                >
                  {writer.canRetry ? "Retry retained draft" : "Save policy draft"}
                </Button>
              ) : (
                <Button onClick={session.reauthenticate}>Reauthenticate to save</Button>
              ))}
          </>
        ) : (
          <p>This answer has no cited workload operation available for a policy draft.</p>
        )
      ) : load.status === "error" || load.status === "forbidden" ? (
        <p role="alert">
          The workflow or its evidence has changed.{" "}
          <Button onClick={() => void load.retry()}>Retry review</Button>
        </p>
      ) : (
        <p role="status">Reading proposal evidence…</p>
      )}
      {error && (
        <p role="alert">
          The draft could not be confirmed.{" "}
          <Button onClick={() => void load.retry()}>Check saved draft</Button>
        </p>
      )}
    </section>
  );
}
