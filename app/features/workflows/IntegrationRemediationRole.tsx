"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { APIProductError, APITransportError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { decodeIntegrationRemediationRole, type IntegrationRemediationRole as RemediationRole } from "../../../apps/web/api/decoders";
import { useAPI } from "../../api/APIProvider";
import { Button, Field } from "../../components/ui";
import { createWorkflowMutationAttempt } from "./api";

// The remediation role of an AWS integration:
//   GET /api/v1/integrations/{id}/remediation-role  getIntegrationRemediationRole (view)
//   PUT /api/v1/integrations/{id}/remediation-role  putIntegrationRemediationRole (manage_workflows)
// Security Agent remediations change the customer's account with this role
// and never with the role discovery reads with. A save names the version it
// was made from; the empty role removes the setting.

export class RemediationRoleConflict extends Error {
  constructor() { super("The remediation role changed"); this.name = "RemediationRoleConflict"; }
}

export type RemediationRoleAPI = Readonly<{
  getRole(integrationID: string, signal?: AbortSignal): Promise<RemediationRole>;
  setRole(integrationID: string, roleARN: string, version: number): Promise<RemediationRole>;
}>;

export function createRemediationRoleAPI(client: APIClient): RemediationRoleAPI {
  const versioned = (result: { data?: unknown; error?: unknown; response: Response }, integrationID: string): RemediationRole => {
    const role = requireAPIData(result, (value) => decodeIntegrationRemediationRole(value, integrationID));
    if (result.response.headers.get("ETag") !== `"${role.version}"`) throw new APITransportError("invalid_response", "Remediation role returned invalid version metadata");
    return role;
  };
  return {
    async getRole(integrationID, signal) {
      return versioned(await client.GET("/api/v1/integrations/{id}/remediation-role", { params: { path: { id: integrationID } }, signal }), integrationID);
    },
    async setRole(integrationID, roleARN, version) {
      try {
        const saved = versioned(await client.PUT("/api/v1/integrations/{id}/remediation-role", {
          params: { path: { id: integrationID }, header: { "Idempotency-Key": createWorkflowMutationAttempt().idempotencyKey, "If-Match": `"${version}"` } as { "Idempotency-Key": string; "If-Match": string } },
          body: { role_arn: roleARN },
        }), integrationID);
        if (roleARN === "" ? saved.configured : saved.role_arn !== roleARN) throw new APITransportError("invalid_response", "Remediation role save returned a different role");
        return saved;
      } catch (error) {
        if (error instanceof APIProductError && (error.status === 409 || error.status === 412)) throw new RemediationRoleConflict();
        throw error;
      }
    },
  };
}

// What the customer's remediation role must allow, and nothing else.
export const remediationRolePermissions: readonly Readonly<{ actions: string; on: string; why: string }>[] = [
  { actions: "bedrock:GetAgent, bedrock:UpdateAgent, bedrock:PrepareAgent", on: "the Bedrock agents you want changed", why: "read the agent, attach the guardrail, prepare the working draft and read the result back" },
  { actions: "iam:ListAttachedRolePolicies, iam:DetachRolePolicy", on: "the roles your agents run as", why: "prove the policy is attached, detach it and prove it is gone" },
  { actions: "iam:GetPolicy, iam:GetPolicyVersion", on: "your managed policies and AWS managed policies", why: "read the policy document: only a policy that allows every action on every resource is detached" },
];

const roleARNPattern = /^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,128}$/;

type Load = { status: "loading" } | { status: "error" } | { status: "ready"; role: RemediationRole };

export function IntegrationRemediationRole({ integrationID, canWrite, api: providedAPI }: { integrationID: string; canWrite: boolean; api?: RemediationRoleAPI }) {
  const { client } = useAPI();
  const api = useMemo(() => providedAPI ?? createRemediationRoleAPI(client), [providedAPI, client]);
  const [load, setLoad] = useState<Load>({ status: "loading" });
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const reload = useCallback(async (signal?: AbortSignal) => {
    try {
      const role = await api.getRole(integrationID, signal);
      if (signal?.aborted) return;
      setLoad({ status: "ready", role });
      setDraft(role.role_arn ?? "");
    } catch {
      if (!signal?.aborted) setLoad({ status: "error" });
    }
  }, [api, integrationID]);
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => { setLoad({ status: "loading" }); setNotice(""); setError(""); void reload(controller.signal); });
    return () => controller.abort();
  }, [reload]);

  const role = load.status === "ready" ? load.role : null;
  const candidate = draft.trim();
  const change = async (roleARN: string) => {
    if (!role || busy || !canWrite) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const saved = await api.setRole(integrationID, roleARN, role.version);
      setLoad({ status: "ready", role: saved });
      setDraft(saved.role_arn ?? "");
      setNotice(saved.configured ? "Remediation role saved." : "Remediation role removed. Remediations of this integration are refused until a role is set.");
    } catch (failure) {
      if (failure instanceof RemediationRoleConflict) {
        await reload();
        setError("The remediation role was changed by someone else since this page loaded it. The current setting is shown; nothing was saved.");
      } else if (failure instanceof APIProductError && failure.status === 400) {
        setError("The role was refused. It must be an IAM role of the same AWS account as the role discovery reads with, and it must not be that role.");
      } else {
        setError("The remediation role was not saved. Check your permission to manage workflows and try again.");
      }
    } finally {
      setBusy(false);
    }
  };

  return <section aria-label="Remediation role" className="form-stack">
    <h3>Remediation role</h3>
    <p>Optional. Two Security Agent actions change this AWS account after a person approved them: attaching a Bedrock guardrail to an agent, and detaching an administrator policy from the role an agent runs as. They use a separate IAM role that you create, never the role discovery reads with. While no remediation role is set, a remediation of this integration is refused before anything happens.</p>
    {load.status === "loading" && <p>Loading remediation role…</p>}
    {load.status === "error" && <p>The remediation role is unavailable. <Button onClick={() => { setLoad({ status: "loading" }); void reload(); }}>Retry</Button></p>}
    {role && !role.supported && <p>This provider has no remediation actions.</p>}
    {role && role.supported && <>
      <p>{role.configured ? <>Remediations use <code>{role.role_arn}</code> (set {role.updated_at}).</> : "No remediation role is set."}</p>
      {error && <p role="alert">{error}</p>}
      {notice && <p role="status">{notice}</p>}
      {canWrite ? <>
        <Field label="Remediation role ARN" placeholder="arn:aws:iam::123456789012:role/zasp-remediation" value={draft} disabled={busy} onChange={(event) => setDraft(event.target.value)} />
        {candidate !== "" && !roleARNPattern.test(candidate) && <p className="field-error">Enter the ARN of an IAM role, for example arn:aws:iam::123456789012:role/zasp-remediation</p>}
        <div className="row-actions">
          <Button variant="primary" disabled={busy || !roleARNPattern.test(candidate) || candidate === role.role_arn} onClick={() => void change(candidate)}>{busy ? "Saving…" : "Save remediation role"}</Button>
          {role.configured && <Button disabled={busy} onClick={() => void change("")}>Remove remediation role</Button>}
        </div>
      </> : <p>Changing the remediation role needs permission to manage workflows.</p>}
      <h4>What the role must allow</h4>
      <ul aria-label="Remediation role permissions">{remediationRolePermissions.map((permission) => <li key={permission.actions}><code>{permission.actions}</code> on {permission.on}: {permission.why}.</li>)}</ul>
      <p>The role must trust Zasp&apos;s action worker with the same external ID as the role discovery reads with. The policy document and the trust policy are in the AWS runbook, step 16 (<code>docs/operations/production-aws-runbook.md</code>). The role needs nothing else.</p>
    </>}
  </section>;
}
