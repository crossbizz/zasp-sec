"use client";

import { useCallback, useEffect, useState } from "react";
import type { StudioRemediationAdvisory } from "../../../apps/web/api/generated";
import { requireAPIData } from "../../../apps/web/api/client";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { useSession } from "../../auth/SessionProvider";
import { Button } from "../../components/ui";

const path = "/api/v1/security-agents/chat/threads/{id}/advisory";
const labels: Record<StudioRemediationAdvisory["state"], string> = {
  available: "A private model can review this proposed isolation before you decide.",
  pending: "Private review in progress.",
  reviewed:
    "The private model recommends the proposed session isolation with timed release. Human approval is required.",
  no_recommendation: "The private model made no recommendation. The approval is ready for human review.",
  unavailable: "Private review is unavailable for this approval.",
};

export function StudioRemediationReview({
  thread,
  sessionID,
  message,
  approval,
}: {
  thread: string;
  sessionID: string;
  message: string;
  approval: string;
}) {
  const session = useSession();
  const { client, queryScopeKey, getScopeStaleGeneration, getSessionInvalidationGeneration } = useAPI();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const request = useCallback(
    async (method: "GET" | "POST", signal?: AbortSignal) => {
      const params = {
        path: { id: thread },
        query: { session_id: sessionID, message_id: message, approval_id: approval },
      };
      const result =
        method === "GET"
          ? await client.GET(path, { params, signal })
          : await client.POST(path, {
              params: { ...params, header: { "X-CSRF-Token": "", "X-Zasp-Fresh-Auth": "confirmed" } },
              body: {},
              signal,
            });
      const v = requireAPIData<StudioRemediationAdvisory>(result);
      if (
        !v ||
        !Object.hasOwn(labels, v.state) ||
        v.approval_id !== approval ||
        v.message_id !== message ||
        v.session_id !== sessionID ||
        (v.state === "reviewed") !== !!v.candidate ||
        (v.candidate &&
          (v.candidate.action !== "isolate_session" ||
            v.candidate.target_id !== sessionID ||
            v.candidate.rollback !== "ttl_release"))
      ) {
        throw Error("Unexpected advisory");
      }
      return v;
    },
    [client, thread, sessionID, message, approval],
  );
  const read = useCallback((signal?: AbortSignal) => request("GET", signal), [request]);
  const key = ["studio-advisory", thread, sessionID, message, approval].join("/");
  const { data, status, retry } = useAPIQuery(
    key,
    read,
    session.status === "authenticated" && queryScopeKey !== null,
  );
  useEffect(() => {
    if (data?.state !== "pending") return;
    const deadline = Date.now() + 60_000;
    let stopped = false;
    let timer = window.setTimeout(refresh, 3000);
    async function refresh() {
      await retry();
      if (!stopped && Date.now() < deadline) timer = window.setTimeout(refresh, 3000);
    }
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [data?.state, retry]);
  async function start() {
    if (
      busy ||
      data?.state !== "available" ||
      session.status !== "authenticated" ||
      !session.isFreshAuthenticated
    )
      return;
    const epoch = getSessionInvalidationGeneration(),
      scope = getScopeStaleGeneration();
    setBusy(true);
    setError(false);
    try {
      await request("POST");
    } catch {
      if (epoch === getSessionInvalidationGeneration() && scope === getScopeStaleGeneration()) setError(true);
    } finally {
      setBusy(false);
      if (epoch === getSessionInvalidationGeneration() && scope === getScopeStaleGeneration()) await retry();
    }
  }
  if (session.status !== "authenticated" || status === "forbidden") return null;
  if (!data || status === "stale")
    return status === "loading" ? (
      <p role="status">Checking private review availability…</p>
    ) : (
      <p>
        Private review status could not be loaded.{" "}
        <Button onClick={() => void retry()}>Retry review status</Button>
      </p>
    );
  return (
    <div>
      <p role="status">{labels[data.state]}</p>
      {error && data.state === "available" && (
        <p role="alert">The request could not be confirmed. Check the review status before trying again.</p>
      )}
      {data.state === "available" &&
        (session.isFreshAuthenticated ? (
          <Button disabled={busy} onClick={() => void start()}>
            {busy ? "Requesting review…" : "Request private review"}
          </Button>
        ) : (
          <Button onClick={() => void session.reauthenticate()}>Reauthenticate to request review</Button>
        ))}
      {data.state === "pending" && <Button onClick={() => void retry()}>Refresh review status</Button>}
    </div>
  );
}
