"use client";

import { useEffect, useState } from "react";
import { Button, Field } from "../../components/ui";
import { validSecurityAgentRemediation, type SecurityAgentRemediation } from "../../../apps/web/api/decoders";
import type { Finding } from "../../../apps/web/api/generated";

// From a finding to its remediation: for the finding rules a Security Agent
// action answers, the finding offers that action. The request starts a
// supervised Security Agent run through POST /security-agents/{id}/runs with
// the finding as its trigger; nothing is changed at the provider until a
// person other than the requester approves the run.

export type FindingRemediationAction = "attach_bedrock_guardrail" | "detach_role_administrator_policy";

type RemediationRule = Readonly<{ action: FindingRemediationAction; effect: string; template: string; approval: string }>;

const remediationRules: Readonly<Record<string, RemediationRule>> = {
  agent_guardrail_missing: { action: "attach_bedrock_guardrail", effect: "Attach Bedrock guardrail", template: "Attach Bedrock Guardrail", approval: "Another person with approval rights must approve the run." },
  agent_role_administrator_access: { action: "detach_role_administrator_policy", effect: "Detach administrator policy from agent role", template: "Detach Administrator Policy from Agent Role", approval: "An identity administrator other than you must approve the run. Detaching a policy is not undone automatically; the run records what was detached." },
};

// findingRemediation returns the Security Agent action that answers an open
// finding's rule, if one does.
export function findingRemediation(finding: Pick<Finding, "rule" | "status">): RemediationRule | undefined {
  return finding.status === "open" && finding.rule ? remediationRules[finding.rule] : undefined;
}

// A Security Agent that can run the action: enabled, with the action as its
// only allowed action. version is the definition's current resource version.
export type RemediationAgent = Readonly<{ id: string; name: string; version: number; environmentID: string }>;

export type FindingRemediationAPI = Readonly<{
  listRemediationAgents(action: FindingRemediationAction, signal?: AbortSignal): Promise<readonly RemediationAgent[]>;
  startRemediation(agent: RemediationAgent, findingID: string, remediation: SecurityAgentRemediation): Promise<Readonly<{ runID: string; state: string }>>;
}>;

function failure(error: unknown): string {
  const record = error as { code?: unknown; product?: { code?: unknown } } | null;
  const code = record && typeof record.product?.code === "string" ? record.product.code : record && typeof record.code === "string" ? record.code : "";
  if (code === "remediation_role_not_configured") return "The AWS integration that describes this agent has no remediation role. Set one on the integration (PUT /api/v1/integrations/{id}/remediation-role); the role discovery reads with is never used to make changes.";
  if (code === "remediation_already_requested") return "This Security Agent already has a remediation run for this version of the finding. Open Security Agents to see it.";
  if (code === "remediation_target_unsupported") return "This finding is not on a Bedrock agent that an AWS integration describes.";
  if (code === "remediation_integration_unavailable") return "The agent is not described by an active AWS integration of its own account.";
  if (code === "remediation_rule_mismatch") return "The selected Security Agent's action does not answer this finding.";
  return "The remediation was not requested. Check that the Security Agent is enabled and that execution is switched on for this action, then try again.";
}

export function FindingRemediation({ finding, api, disabled, onNavigate }: { finding: Finding; api: FindingRemediationAPI; disabled: boolean; onNavigate(path: string): void }) {
  const rule = findingRemediation(finding);
  const action = rule?.action;
  const [agents, setAgents] = useState<readonly RemediationAgent[] | "loading" | "unavailable">("loading");
  const [agentID, setAgentID] = useState("");
  const [guardrailIdentifier, setGuardrailIdentifier] = useState("");
  const [guardrailVersion, setGuardrailVersion] = useState("");
  const [policyARN, setPolicyARN] = useState("arn:aws:iam::aws:policy/AdministratorAccess");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [started, setStarted] = useState<{ runID: string; state: string } | null>(null);

  useEffect(() => {
    if (!action) return;
    const controller = new AbortController();
    api.listRemediationAgents(action, controller.signal).then((value) => {
      if (controller.signal.aborted) return;
      setAgents(value);
      setAgentID(value[0]?.id ?? "");
    }).catch(() => { if (!controller.signal.aborted) setAgents("unavailable"); });
    return () => controller.abort();
  }, [action, api, finding.id]);

  if (!rule || !action) return null;
  const remediation: SecurityAgentRemediation = action === "attach_bedrock_guardrail"
    ? { action, parameters: { guardrail_identifier: guardrailIdentifier.trim(), guardrail_version: guardrailVersion.trim() } }
    : { action, parameters: { policy_arn: policyARN.trim() } };
  const selected = Array.isArray(agents) ? agents.find((agent) => agent.id === agentID) : undefined;
  const valid = validSecurityAgentRemediation(remediation);

  const request = async () => {
    if (!selected || !valid) return;
    setBusy(true); setError("");
    try { setStarted(await api.startRemediation(selected, finding.id, remediation)); }
    catch (caught) { setError(failure(caught)); }
    finally { setBusy(false); }
  };

  return <section aria-label="Fix with a Security Agent">
    <h3>Fix with a Security Agent</h3>
    <p>{rule.effect}. {rule.approval}</p>
    {started ? <><p role="status">Remediation run <code>{started.runID}</code> is waiting for approval.</p><Button onClick={() => onNavigate("/security-agents")}>Open Security Agents</Button></>
      : agents === "loading" ? <p>Loading Security Agents…</p>
        : agents === "unavailable" ? <p>Security Agents are not available to you in this scope.</p>
          : agents.length === 0 ? <><p>No enabled Security Agent has this action. Create one from the “{rule.template}” template and enable supervised execution.</p><Button onClick={() => onNavigate("/security-agents")}>Open Security Agents</Button></>
            : <>
              {agents.length > 1 && <label>Security Agent <select aria-label="Security Agent" value={agentID} disabled={busy || disabled} onChange={(event) => setAgentID(event.target.value)}>{agents.map((agent) => <option key={agent.id} value={agent.id}>{agent.name}</option>)}</select></label>}
              {action === "attach_bedrock_guardrail" ? <>
                <Field label="Guardrail identifier or ARN" value={guardrailIdentifier} disabled={busy || disabled} onChange={(event) => setGuardrailIdentifier(event.target.value)} />
                <Field label="Guardrail version" value={guardrailVersion} disabled={busy || disabled} onChange={(event) => setGuardrailVersion(event.target.value)} />
                <p>Name an existing guardrail of the agent’s account and Region, and a numbered version or DRAFT.</p>
              </> : <>
                <Field label="Policy ARN to detach" value={policyARN} disabled={busy || disabled} onChange={(event) => setPolicyARN(event.target.value)} />
                <p>Only a managed policy that is attached to the agent’s execution role is detached; anything else is refused.</p>
              </>}
              {error && <div role="alert" className="form-error">{error}</div>}
              <Button variant="primary" disabled={busy || disabled || !selected || !valid} onClick={() => void request()}>Request approval: {rule.effect.toLowerCase()}</Button>
            </>}
  </section>;
}
