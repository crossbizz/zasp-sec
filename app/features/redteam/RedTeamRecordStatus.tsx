"use client";

import { useCallback } from "react";
import { redTeamStatusLink, type RedTeamStatusReference } from "../../domain/red-team-status-link";
import { useAPIQuery } from "../../api/query";
import { Button, PageHeader } from "../../components/ui";
import type { ProductionRedTeamAPI } from "./api";

type Props = {
  record: RedTeamStatusReference;
  api: ProductionRedTeamAPI;
  onComplete(): void;
};

export function RedTeamRecordStatus({ record, api, onComplete }: Props) {
  const load = useCallback(async (signal?: AbortSignal) => {
    if (record.kind === "submitted" || record.kind === "cancellation") {
      const run = await api.getRun(record.id, signal);
      if (run.id !== record.id) throw Error("Record identity changed");
      return {
        description: run.cancel_requested ? "Cancellation requested" : run.status,
        version: run.version,
        reviewed: record.kind === "submitted" || run.cancel_requested ||
          ["complete", "failed", "cancelled"].includes(run.status),
      };
    }
    const definition = await api.getDefinition(record.id, signal);
    if (definition.id !== record.id) throw Error("Record identity changed");
    return {
      description: definition.name,
      version: definition.version,
      reviewed: record.kind === "created" || definition.version > record.version,
    };
  }, [api, record]);

  const result = useAPIQuery("red-team-record-status:" + redTeamStatusLink(record), load);
  const row = result.status === "success" ? result.data : null;
  return <div className="page">
    <PageHeader title="Submitted record status" description="Review the current server record for this request."/>
    <p><code>{record.id}</code></p>
    {row ? <>
      <p>{row.description} · version {row.version}</p>
      {!row.reviewed && <p role="status">The requested change is still unconfirmed.</p>}
    </> : result.status === "loading" || result.status === "idle"
      ? <p role="status">Checking record status…</p>
      : <p role="alert">The record could not be confirmed in this scope. Keep this link and check again.</p>}
    <div className="page-actions">
      <Button disabled={result.status === "loading"} onClick={() => void result.retry()}>Refresh record status</Button>
      {row?.reviewed && <Button onClick={onComplete}>Return to Red Team records</Button>}
    </div>
  </div>;
}
