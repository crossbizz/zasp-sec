"use client";

import { useCallback } from "react";
import { APIProductError } from "../../../apps/web/api/client";
import { getSecurityAgentAuditEvent } from "../../../apps/web/api/security-agent-audit";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button, Card, LoadingState, PageHeader } from "../../components/ui";
import { activityLink, type ActivityScope } from "../../domain/activity-links";
import { SecurityAgentActivityPanel } from "./SecurityAgentActivityPanel";

export function SecurityAgentAuditView({ auditID, scope, permitted, canReadRuns, onNavigate }: { auditID: string; scope: ActivityScope; permitted: boolean; canReadRuns: boolean; onNavigate(path: string): void }) {
  const { client, queryScopeKey } = useAPI();
  const { organizationID, workspaceID, environmentID } = scope;
  const read = useCallback((signal?: AbortSignal) => getSecurityAgentAuditEvent(client, auditID, { organization_id: organizationID, workspace_id: workspaceID, environment_id: environmentID }, signal), [client, auditID, organizationID, workspaceID, environmentID]);
  const query = useAPIQuery(`security-agent-audit:${organizationID}/${workspaceID}/${environmentID}/${auditID}`, read, permitted);
  const value = query.status === "success" ? query.data : undefined;
  const status = query.error instanceof APIProductError ? query.error.status : undefined;
  return <div className="page security-agent-audit">
    <PageHeader title="Security Agent audit record" description="Recorded activity for one run in the selected organization, workspace and environment." actions={<Button onClick={() => onNavigate("/administration/audit-log")}>All audit events</Button>} />
    {!permitted ? <div role="alert">Audit access denied.</div> : queryScopeKey === null ? <LoadingState label="Revalidating audit access…" /> : <>
      <Button onClick={() => void query.retry()}>Reload audit record</Button>
      {query.status === "loading" || query.status === "idle" ? <LoadingState label="Loading audit record…" /> : value ? <Card title={value.event_kind}><div className="security-agent-audit__record">
        <dl className="detail-list">
          <dt>Audit record ID</dt><dd>{value.id}</dd>
          <dt>Actor reference</dt><dd>{value.actor_reference}</dd>
          <dt>Recorded at</dt><dd><time dateTime={value.occurred_at}>{value.occurred_at}</time></dd>
          <dt>Correlation ID</dt><dd>{value.correlation_id}</dd>
          <dt>Security Agent run</dt><dd>{value.run_id}</dd>
          <dt>Organization</dt><dd>{value.organization_id}</dd>
          <dt>Workspace</dt><dd>{value.workspace_id}</dd>
          <dt>Environment</dt><dd>{value.environment_id}</dd>
        </dl>
        {canReadRuns ? <Button onClick={() => onNavigate(activityLink({ kind: "run", id: value.run_id }, scope))}>Open Security Agent run</Button> : <p>Run access is not available for this session.</p>}
        <SecurityAgentActivityPanel direction="runs" kind="audit" entityID={value.id} scope={scope} permitted={canReadRuns} onNavigate={onNavigate} />
      </div></Card> : <div role="alert">{status === 403 ? "Audit access denied." : status === 404 ? "Audit record not found in this scope." : "Audit detail is unavailable. No record is displayed."}</div>}
    </>}
  </div>;
}
