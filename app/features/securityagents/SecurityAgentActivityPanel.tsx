"use client";

import { useCallback, useState } from "react";
import { APIProductError } from "../../../apps/web/api/client";
import { listSecurityAgentActivityRuns, listSecurityAgentRunActivity, type SecurityAgentActivityKind } from "../../../apps/web/api/security-agent-activity";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button, Card, LoadingState } from "../../components/ui";
import { activityLink, type ActivityScope } from "../../domain/activity-links";

export type SecurityAgentActivityPanelProps = {
  direction: "runs" | "targets";
  kind: SecurityAgentActivityKind;
  entityID: string;
  scope: ActivityScope;
  permitted: boolean;
  disabled?: boolean;
  onNavigate(path: string): void;
};

const labels: Record<SecurityAgentActivityKind, string> = { finding: "finding", attack_path: "attack path", session: "session", audit: "audit record" };
const plurals: Record<SecurityAgentActivityKind, string> = { finding: "findings", attack_path: "attack paths", session: "sessions", audit: "audit records" };

export function SecurityAgentActivityPanel(props: SecurityAgentActivityPanelProps) {
  const { queryScopeKey, queryGeneration } = useAPI();
  const title = props.direction === "runs" ? "Related Security Agent runs" : `Related ${plurals[props.kind]}`;
  if (!props.permitted) return <Card title={title}><div role="alert">Related activity access denied.</div></Card>;
  if (queryScopeKey === null) return <Card title={title}><LoadingState label="Revalidating related activity access…" /></Card>;
  const key = JSON.stringify([queryScopeKey, queryGeneration, props.direction, props.kind, props.entityID, props.scope.organizationID, props.scope.workspaceID, props.scope.environmentID]);
  return <ActivityPage key={key} {...props} title={title} />;
}

function ActivityPage({ direction, kind, entityID, scope, disabled = false, onNavigate, title }: SecurityAgentActivityPanelProps & { title: string }) {
  const { client } = useAPI();
  const [history, setHistory] = useState<string[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const cursor = history.at(-1);
  const { organizationID, workspaceID, environmentID } = scope;
  const read = useCallback(async (signal?: AbortSignal) => {
    const bound = { organization_id: organizationID, workspace_id: workspaceID, environment_id: environmentID };
    const options = { limit: 20, cursor, signal };
    return direction === "runs" ? listSecurityAgentActivityRuns(client, entityID, kind, bound, options) : listSecurityAgentRunActivity(client, entityID, kind, bound, options);
  }, [client, direction, kind, entityID, organizationID, workspaceID, environmentID, cursor]);
  const query = useAPIQuery(`security-agent-activity:${direction}:${kind}:${entityID}:${organizationID}/${workspaceID}/${environmentID}:${cursor ?? "first"}`, read);
  const loading = refreshing || query.status === "loading" || query.status === "idle";
  const candidate = !loading && (query.status === "success" || query.status === "empty") ? query.data : undefined;
  const repeated = candidate?.next_cursor !== undefined && history.includes(candidate.next_cursor);
  const page = repeated ? undefined : candidate;
  const status = query.error instanceof APIProductError ? query.error.status : undefined;
  async function reload() { setRefreshing(true); try { await query.retry(); } finally { setRefreshing(false); } }
  return <Card title={title}>
    <div className="security-agent-activity">
      <Button disabled={disabled || loading} onClick={() => void reload()}>Reload related activity</Button>
      {loading ? <LoadingState label="Loading related activity…" /> : page ? <>
        {page.coverage === "partial" && <p role="status">Coverage is incomplete. Some legacy records do not have verified activity links.</p>}
        {page.items.length === 0 ? <p>{page.coverage === "partial" ? "No verified links on this page." : "No related records on this page."}</p> : <ul className="security-agent-activity__list">{page.items.map(item => <li key={item.id}><Button disabled={disabled} onClick={() => onNavigate(activityLink({ kind: direction === "runs" ? "run" : kind, id: item.id }, scope))}>Open {direction === "runs" ? "run" : labels[kind]} {item.id}</Button></li>)}</ul>}
      </> : <div role="alert">{status === 401 || status === 403 ? "Related activity access denied." : status === 404 ? "Related activity was not found in this scope." : "Related activity is unavailable. No links are displayed."}</div>}
      <div className="security-agent-activity__pagination">
        <Button disabled={disabled || loading || history.length === 0} onClick={() => setHistory(value => value.slice(0, -1))}>Previous related page</Button>
        <span>Page {history.length + 1}</span>
        <Button disabled={disabled || loading || !page?.next_cursor} onClick={() => { if (page?.next_cursor) setHistory(value => [...value, page.next_cursor!]); }}>Next related page</Button>
      </div>
    </div>
  </Card>;
}
