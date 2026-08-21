"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { APITransportError, createAPIClient, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { decodeSecurityAgentApproval, decodeSecurityAgentApprovalPage, decodeSecurityAgentDefinition, decodeSecurityAgentPage, decodeSecurityAgentRun, decodeSecurityAgentRunDetail, decodeSecurityAgentRunPage, decodeSecurityAgentTemplatePage } from "../../../apps/web/api/decoders";
import type { SecurityAgentApproval, SecurityAgentApprovalPage, SecurityAgentDefinition, SecurityAgentInput, SecurityAgentPage, SecurityAgentRun, SecurityAgentRunDetail, SecurityAgentRunPage, SecurityAgentRunState, SecurityAgentTemplate } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { useSession } from "../../auth/SessionProvider";
import { Badge, Button, Card, Drawer, EmptyState, Field, LoadingState, PageHeader, Select } from "../../components/ui";
import {
  executeWorkflowMutation,
  requireWorkflowEmptyReceipt,
  requireWorkflowReceipt,
  requireWorkflowVersioned,
  workflowMutationHeaders,
  type Versioned,
  type WorkflowMutationAttempt,
  type WorkflowReceipt,
} from "../workflows/api";
import { useRetainedWorkflowMutation } from "../workflows/useRetainedWorkflowMutation";

export const securityAgentOperations = [
  "listSecurityAgentTemplates", "listSecurityAgents", "createSecurityAgent", "getSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent",
  "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval", "decideSecurityAgentApproval",
] as const;

export type SecurityAgentsAPI = {
  listSecurityAgentTemplates(signal?: AbortSignal): Promise<readonly SecurityAgentTemplate[]>;
  listSecurityAgents(options?: { cursor?: string; limit?: number }, signal?: AbortSignal): Promise<SecurityAgentPage>;
  createSecurityAgent(value: SecurityAgentInput, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentDefinition>>;
  getSecurityAgent(id: string, signal?: AbortSignal): Promise<Versioned<SecurityAgentDefinition>>;
  updateSecurityAgent(id: string, version: string, value: SecurityAgentDefinition, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentDefinition>>;
  deleteSecurityAgent(id: string, version: string, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<void>>;
  listSecurityAgentRuns(options?: { agent_id?: string; status?: SecurityAgentRunState; environment_id?: string; cursor?: string; limit?: number }, signal?: AbortSignal): Promise<SecurityAgentRunPage>;
  getSecurityAgentRun(id: string, signal?: AbortSignal): Promise<SecurityAgentRunDetail>;
  cancelSecurityAgentRun(id: string, version: number, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentRun>>;
  listSecurityAgentApprovals(options?: { state?: SecurityAgentApproval["state"]; run_id?: string; cursor?: string; limit?: number }, signal?: AbortSignal): Promise<SecurityAgentApprovalPage>;
  getSecurityAgentApproval(id: string, signal?: AbortSignal): Promise<SecurityAgentApproval>;
  decideSecurityAgentApproval(id: string, version: number, decision: "approved" | "rejected" | "cancelled", attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentApproval>>;
};

export function createSecurityAgentsAPI(client: APIClient = createAPIClient()): SecurityAgentsAPI {
  return {
    async listSecurityAgentTemplates(signal) {
      return requireAPIData(await client.GET("/api/v1/security-agent-templates", { signal }), decodeSecurityAgentTemplatePage).items;
    },
    async listSecurityAgents(options = {}, signal) {
      return requireAPIData(await client.GET("/api/v1/security-agents", { params: { query: options }, signal }), decodeSecurityAgentPage);
    },
    async createSecurityAgent(value, attempt) {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.POST("/api/v1/security-agents", { params: { header: workflowMutationHeaders(active) }, body: value }), decodeSecurityAgentDefinition), attempt);
    },
    async getSecurityAgent(id, signal) {
      return requireWorkflowVersioned(await client.GET("/api/v1/security-agents/{id}", { params: { path: { id } }, signal }), decodeSecurityAgentDefinition);
    },
    async updateSecurityAgent(id, version, value, attempt) {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.PATCH("/api/v1/security-agents/{id}", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } }, body: value }), decodeSecurityAgentDefinition), attempt);
    },
    async deleteSecurityAgent(id, version, attempt) {
      return executeWorkflowMutation(async (active) => { const result = await client.DELETE("/api/v1/security-agents/{id}", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } } }); if (result.error) requireAPIData<never>(result); return requireWorkflowEmptyReceipt(result.response); }, attempt);
    },
    async listSecurityAgentRuns(options = {}, signal) {
      const result = await client.GET("/api/v1/security-agent-runs", { params: { query: options }, signal }); requireSecurityAgentNoStore(result.response);
      return requireAPIData(result, decodeSecurityAgentRunPage);
    },
    async getSecurityAgentRun(id, signal) {
      const result = await client.GET("/api/v1/security-agent-runs/{id}", { params: { path: { id } }, signal }); requireSecurityAgentNoStore(result.response);
      const value = requireAPIData(result, decodeSecurityAgentRunDetail);
      if (value.run.id !== id) throw new TypeError("Security Agent run detail returned a different run");
      return value;
    },
    async cancelSecurityAgentRun(id, version, attempt) {
      return executeWorkflowMutation(async (active) => {
        const params = { path: { id }, header: workflowMutationHeaders(active, `"${version}"`) } as never;
        const result = await client.POST("/api/v1/security-agent-runs/{id}/cancel", { params }); requireSecurityAgentNoStore(result.response);
        const receipt = requireWorkflowReceipt(result, decodeSecurityAgentRun);
        if (receipt.value.id !== id || receipt.value.state !== "cancelled" || receipt.value.version !== version + 1) throw new TypeError("Security Agent cancellation returned invalid authority");
        return receipt;
      }, attempt);
    },
    async listSecurityAgentApprovals(options = {}, signal) {
      const result = await client.GET("/api/v1/security-agent-approvals", { params: { query: options }, signal }); requireSecurityAgentNoStore(result.response);
      return requireAPIData(result, decodeSecurityAgentApprovalPage);
    },
    async getSecurityAgentApproval(id, signal) {
      const result = await client.GET("/api/v1/security-agent-approvals/{id}", { params: { path: { id } }, signal }); requireSecurityAgentNoStore(result.response);
      const value = requireAPIData(result, decodeSecurityAgentApproval);
      if (value.id !== id) throw new TypeError("Security Agent approval detail returned a different approval");
      return value;
    },
    async decideSecurityAgentApproval(id, version, decision, attempt) {
      return executeWorkflowMutation(async (active) => {
        const params = { path: { id }, header: { ...workflowMutationHeaders(active, `"${version}"`), "X-Zasp-Fresh-Auth": "confirmed" } } as never;
        const result = await client.POST("/api/v1/security-agent-approvals/{id}/decision", { params, body: { decision } }); requireSecurityAgentNoStore(result.response);
        const receipt = requireWorkflowReceipt(result, decodeSecurityAgentApproval);
        if (receipt.value.id !== id || receipt.value.state !== decision || receipt.value.version !== version + 1) throw new TypeError("Security Agent approval decision returned invalid authority");
        return receipt;
      }, attempt);
    },
  };
}

function requireSecurityAgentNoStore(response: Response): void { if (response.headers.get("Cache-Control") !== "no-store") throw new APITransportError("invalid_response", "Security Agent response omitted no-store authority"); }

const defaultSecurityAgentsAPI = createSecurityAgentsAPI();
const maximums = { steps: 100, runtime: 86400, temporaryPolicy: 86400, aiTokens: 12000, concurrency: 10 } as const;
const triggerSources = { finding: "credential", attack_path: "verified", runtime_decision: "block" } as const;
const bounded = (value: string, maximum: number) => Math.max(1, Math.min(maximum, Number(value) || 1));
type SecurityAgentSnapshot = { agents: readonly SecurityAgentDefinition[]; templates: readonly SecurityAgentTemplate[]; runs?: readonly SecurityAgentRun[]; approvals?: readonly SecurityAgentApproval[] };
type SecurityAgentCreateIntent = { value: SecurityAgentInput };
type SecurityAgentDetailIntent =
  | { kind: "update"; id: string; version: string; value: SecurityAgentDefinition }
  | { kind: "delete"; id: string; version: string };
type SecurityAgentDetailResult =
  | { kind: "updated"; receipt: WorkflowReceipt<SecurityAgentDefinition> }
  | { kind: "deleted"; receipt: WorkflowReceipt<void> };
type SecurityAgentRunCancelIntent = { id: string; version: number };
type SecurityAgentApprovalDecisionIntent = { id: string; version: number; decision: "approved" | "rejected" | "cancelled" };

async function loadSecurityAgentSnapshot(api: SecurityAgentsAPI, signal?: AbortSignal): Promise<SecurityAgentSnapshot> {
  const [firstPage, templates, firstRuns, firstApprovals] = await Promise.all([
    api.listSecurityAgents({ limit: 100 }, signal),
    api.listSecurityAgentTemplates(signal),
    api.listSecurityAgentRuns({ limit: 100 }, signal),
    api.listSecurityAgentApprovals({ limit: 100 }, signal),
  ]);
  const agents: SecurityAgentDefinition[] = [];
  let page = firstPage;
  for (let pageNumber = 0; pageNumber < 100; pageNumber++) {
    agents.push(...page.items);
    if (!page.page_info.has_more) break;
    if (pageNumber === 99) throw new Error("Security Agent definition pagination exceeded its bounded page count");
    page = await api.listSecurityAgents({ cursor: page.page_info.next_cursor, limit: 100 }, signal);
  }
  const runs: SecurityAgentRun[] = [...firstRuns.items]; let runPage = firstRuns;
  for (let pageNumber = 1; runPage.next_cursor !== undefined; pageNumber++) { if (pageNumber === 100) throw new Error("Security Agent run pagination exceeded its bounded page count"); runPage = await api.listSecurityAgentRuns({ cursor: runPage.next_cursor, limit: 100 }, signal); runs.push(...runPage.items); }
  const approvals: SecurityAgentApproval[] = [...firstApprovals.items]; let approvalPage = firstApprovals;
  for (let pageNumber = 1; approvalPage.next_cursor !== undefined; pageNumber++) { if (pageNumber === 100) throw new Error("Security Agent approval pagination exceeded its bounded page count"); approvalPage = await api.listSecurityAgentApprovals({ cursor: approvalPage.next_cursor, limit: 100 }, signal); approvals.push(...approvalPage.items); }
  return { agents, templates, runs, approvals };
}

type SecurityAgentCreateMutation = ReturnType<typeof useRetainedWorkflowMutation<SecurityAgentCreateIntent>>;
type SecurityAgentDetailMutation = ReturnType<typeof useRetainedWorkflowMutation<SecurityAgentDetailIntent>>;
type SecurityAgentRunMutation = ReturnType<typeof useRetainedWorkflowMutation<SecurityAgentRunCancelIntent>>;
type SecurityAgentApprovalMutation = ReturnType<typeof useRetainedWorkflowMutation<SecurityAgentApprovalDecisionIntent>>;

function Builder({ templates, api, environmentID, mutation, onCreated }: { templates: readonly SecurityAgentTemplate[]; api: SecurityAgentsAPI; environmentID: string; mutation: SecurityAgentCreateMutation; onCreated(value: SecurityAgentDefinition): void }) {
  const [templateID, setTemplateID] = useState(templates[0]?.id ?? "");
  const [name, setName] = useState("Bounded response definition");
  const [steps, setSteps] = useState(10);
  const [runtime, setRuntime] = useState(900);
  const [temporaryPolicy, setTemporaryPolicy] = useState(3600);
  const [aiTokens, setAITokens] = useState(4000);
  const [concurrency, setConcurrency] = useState(2);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const selected = templates.find((value) => value.id === templateID);
  const save = async () => {
    if (!selected) return;
    setBusy(true); setError(false);
    try {
      const intent = { value: { name, trigger_kind: selected.trigger_kind, trigger_source: triggerSources[selected.trigger_kind], environment_ids: [environmentID], autonomy: "supervised" as const, max_steps: steps, max_duration_seconds: runtime, temporary_policy_seconds: temporaryPolicy, ai_token_budget: aiTokens, concurrency_limit: concurrency, allowed_actions: selected.default_actions, verification_kind: selected.verification_condition, definition_version: selected.version, enabled: true } };
      const receipt = mutation.canRetry
        ? await mutation.retry<WorkflowReceipt<SecurityAgentDefinition>>()
        : await mutation.execute(intent, (frozen, attempt) => api.createSecurityAgent(frozen.value, attempt));
      onCreated(receipt.value);
    } catch { setError(true); } finally { setBusy(false); }
  };
  return <Card title="Create a definition from a locally supported template"><div className="form-stack">
    <Select label="Definition template" value={templateID} disabled={mutation.isUnresolved} onChange={(event) => { if (!mutation.isUnresolved) setTemplateID(event.target.value); }}>{templates.map((value) => <option key={value.id} value={value.id}>{value.name}</option>)}</Select>
    <Field label="Definition name" value={name} disabled={mutation.isUnresolved} maxLength={256} onChange={(event) => setName(event.target.value)} />
    <Field label="Authorized environment" value={environmentID} readOnly />
    {selected && <p>Trigger: {selected.trigger_kind}. Template actions: {selected.default_actions.join(", ")}. Verification: {selected.verification_condition}.</p>}
    <div className="form-grid"><Field label="Step limit" type="number" min={1} max={maximums.steps} value={steps} disabled={mutation.isUnresolved} onChange={(event) => setSteps(bounded(event.target.value, maximums.steps))} /><Field label="Runtime seconds" type="number" min={1} max={maximums.runtime} value={runtime} disabled={mutation.isUnresolved} onChange={(event) => setRuntime(bounded(event.target.value, maximums.runtime))} /><Field label="Temporary-policy seconds" type="number" min={1} max={maximums.temporaryPolicy} value={temporaryPolicy} disabled={mutation.isUnresolved} onChange={(event) => setTemporaryPolicy(bounded(event.target.value, maximums.temporaryPolicy))} /><Field label="AI token budget" type="number" min={1} max={maximums.aiTokens} value={aiTokens} disabled={mutation.isUnresolved} onChange={(event) => setAITokens(bounded(event.target.value, maximums.aiTokens))} /><Field label="Concurrency" type="number" min={1} max={maximums.concurrency} value={concurrency} disabled={mutation.isUnresolved} onChange={(event) => setConcurrency(bounded(event.target.value, maximums.concurrency))} /></div>
    <p>New definitions start in supervised mode. Run plans, approvals, execution outcomes, and verification remain tenant-scoped and versioned.</p>
    {error && <p role="alert">{mutation.canRetry ? "The response was lost. Retry will reuse the exact definition and idempotency key." : "The definition was not saved."}</p>}<Button variant="primary" disabled={busy || !selected || !name || mutation.isUnresolved && !mutation.canRetry} onClick={() => void save()}>{mutation.canRetry ? "Retry retained Security Agent definition" : "Save Security Agent definition"}</Button>
  </div></Card>;
}

function AgentDetail({ selected, api, canWrite, mutation, onChange, onDelete, onClose }: { selected: Versioned<SecurityAgentDefinition>; api: SecurityAgentsAPI; canWrite: boolean; mutation: SecurityAgentDetailMutation; onChange(value: Versioned<SecurityAgentDefinition>): void; onDelete(): void; onClose(): void }) {
  const [name, setName] = useState(selected.value.name);
  const [enabled, setEnabled] = useState(selected.value.enabled);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const apply = (result: SecurityAgentDetailResult) => { if (result.kind === "updated") onChange(result.receipt); else onDelete(); };
  const run = async (operation: () => Promise<SecurityAgentDetailResult>) => { setBusy(true); setError(false); try { apply(await operation()); } catch { setError(true); } finally { setBusy(false); } };
  const save = () => void run(() => mutation.execute({ kind: "update", id: selected.value.id, version: selected.version, value: { ...selected.value, name, enabled } }, async (intent, attempt) => { if (intent.kind !== "update") throw new TypeError("Invalid retained Security Agent intent"); return { kind: "updated", receipt: await api.updateSecurityAgent(intent.id, intent.version, intent.value, attempt) }; }));
  const remove = () => void run(() => mutation.execute({ kind: "delete", id: selected.value.id, version: selected.version }, async (intent, attempt) => { if (intent.kind !== "delete") throw new TypeError("Invalid retained Security Agent intent"); return { kind: "deleted", receipt: await api.deleteSecurityAgent(intent.id, intent.version, attempt) }; }));
  const retry = () => void run(() => mutation.retry<SecurityAgentDetailResult>());
  return <Drawer open title={selected.value.name} closeDisabled={mutation.isUnresolved} onClose={onClose}><div className="detail-content"><p><Badge tone={enabled ? "success" : "neutral"}>{enabled ? "Enabled" : "Disabled"}</Badge> Resource version {selected.version}</p><Field label="Definition name" value={name} disabled={!canWrite || busy || mutation.isUnresolved} onChange={(event) => setName(event.target.value)} /><p>{selected.value.trigger_kind} · {selected.value.environment_ids.join(", ")} · supervised</p><h3>Template controls</h3><p>{selected.value.allowed_actions.join(", ")} · verification {selected.value.verification_kind}</p><h3>Limits</h3><p>{selected.value.max_steps} steps · {selected.value.max_duration_seconds}s · concurrency {selected.value.concurrency_limit}</p>{canWrite && <><label className="control-option"><input aria-label="Definition enabled" type="checkbox" checked={enabled} disabled={busy || mutation.isUnresolved} onChange={(event) => setEnabled(event.target.checked)} /><span><strong>Definition enabled</strong><small>Disabling prevents new automatic and manual runs.</small></span></label><div className="button-row">{mutation.canRetry ? <Button disabled={busy} onClick={retry}>Retry retained definition operation</Button> : <><Button disabled={busy || mutation.isUnresolved} onClick={save}>Save definition</Button><Button variant="danger" disabled={busy || mutation.isUnresolved} onClick={remove}>Delete definition</Button></>}</div></>}{error && <p role="alert">{mutation.canRetry ? "The response was lost. Retry will reuse the exact definition operation and idempotency key." : "The definition changed elsewhere or could not be updated. Close and reopen it."}</p>}</div></Drawer>;
}

function RunDetail({ value, api, canWrite, mutation, onCancelled, onClose }: { value: SecurityAgentRunDetail; api: SecurityAgentsAPI; canWrite: boolean; mutation: SecurityAgentRunMutation; onCancelled(run: SecurityAgentRun): void; onClose(): void }) {
  const [busy, setBusy] = useState(false); const [error, setError] = useState(false);
  const cancelable = ["queued", "planning", "waiting_approval", "running", "verifying"].includes(value.run.state) && value.execution.every((step) => step.outcome_id === undefined && step.result_digest === undefined);
  const cancel = async () => {
    setBusy(true); setError(false);
    try {
      const receipt = mutation.canRetry
        ? await mutation.retry<WorkflowReceipt<SecurityAgentRun>>()
        : await mutation.execute({ id: value.run.id, version: value.run.version }, (intent, attempt) => api.cancelSecurityAgentRun(intent.id, intent.version, attempt));
      onCancelled(receipt.value);
    } catch { setError(true); } finally { setBusy(false); }
  };
  return <Drawer open title={`Run ${value.run.id}`} closeDisabled={mutation.isUnresolved} onClose={onClose}><div className="detail-content">
    <p><Badge tone={value.run.state === "contained" || value.run.state === "remediated" ? "success" : value.run.state === "failed" ? "critical" : "info"}>{value.run.state}</Badge> Version {value.run.version}</p>
    <p>Definition {value.run.agent_id}, revision {value.run.definition_version}</p>
    <h3>Evidence</h3><ul>{value.evidence_ids.map((id) => <li key={id}>{id}</li>)}</ul>
    <h3>Plan</h3>{value.plan ? <><p>Plan {value.plan.plan_hash}, expires {value.plan.expires_at}</p><ol>{value.plan.steps.map((step) => <li key={step.id}>{step.action} · {step.authorization} · {step.state}</li>)}</ol></> : <p>No plan has been persisted.</p>}
    <h3>Authorization and execution</h3><p>{value.authorization} · verification {value.verification}</p>{value.execution.length ? <ul>{value.execution.map((step) => <li key={step.step_id}>{step.action} · {step.state}{step.outcome_id ? ` · outcome ${step.outcome_id}` : ""}</li>)}</ul> : <p>No action has executed.</p>}
    {canWrite && cancelable && <Button variant="danger" disabled={busy || mutation.isUnresolved && !mutation.canRetry} onClick={() => void cancel()}>{mutation.canRetry ? "Retry retained run cancellation" : "Cancel run"}</Button>}
    {error && <p role="alert">{mutation.canRetry ? "The cancellation response was lost. Retry reuses the exact run, version, and idempotency key." : "The run could not be cancelled. Reopen it to load current authority."}</p>}
  </div></Drawer>;
}

function ApprovalDetail({ value, api, canWrite, fresh, onReauthenticate, mutation, onDecided, onClose }: { value: SecurityAgentApproval; api: SecurityAgentsAPI; canWrite: boolean; fresh: boolean; onReauthenticate(): void; mutation: SecurityAgentApprovalMutation; onDecided(value: SecurityAgentApproval): void; onClose(): void }) {
  const [busy, setBusy] = useState(false); const [error, setError] = useState(false);
  const decide = async (decision: "approved" | "rejected") => {
    setBusy(true); setError(false);
    try {
      const receipt = mutation.canRetry
        ? await mutation.retry<WorkflowReceipt<SecurityAgentApproval>>()
        : await mutation.execute({ id: value.id, version: value.version, decision }, (intent, attempt) => api.decideSecurityAgentApproval(intent.id, intent.version, intent.decision, attempt));
      onDecided(receipt.value);
    } catch { setError(true); } finally { setBusy(false); }
  };
  return <Drawer open title={`Approval ${value.id}`} closeDisabled={mutation.isUnresolved} onClose={onClose}><div className="detail-content">
    <p><Badge tone={value.state === "approved" ? "success" : value.state === "rejected" || value.state === "expired" ? "critical" : "info"}>{value.state}</Badge> Version {value.version}</p>
    <p>Run {value.run_id} · step {value.step_id}</p><h3>Expected effect</h3><p>{value.expected_effect}</p><p>{value.reversible ? "Reversible" : "Not reversible"} · TTL {value.ttl_seconds}s · expires {value.expires_at}</p>
    <h3>Evidence</h3><ul>{value.evidence_summary?.map((id) => <li key={id}>{id}</li>)}</ul>
    {canWrite && value.state === "pending" && (fresh ? <div className="button-row"><Button variant="primary" disabled={busy || mutation.isUnresolved && !mutation.canRetry} onClick={() => void decide("approved")}>{mutation.canRetry ? "Retry retained approval decision" : "Approve"}</Button>{!mutation.canRetry && <Button variant="danger" disabled={busy || mutation.isUnresolved} onClick={() => void decide("rejected")}>Reject</Button>}</div> : <Button onClick={onReauthenticate}>Reauthenticate to decide</Button>)}
    {error && <p role="alert">{mutation.canRetry ? "The decision response was lost. Retry reuses the exact approval, version, decision, and idempotency key." : "The approval changed or could not be decided. Reopen it to load current authority."}</p>}
  </div></Drawer>;
}

export function SecurityAgentsView({ api = defaultSecurityAgentsAPI, environmentID = "production", canWrite = true, fresh = false, onReauthenticate = () => undefined, surface = "all", initialSnapshot, autoLoad = true }: { api?: SecurityAgentsAPI; environmentID?: string; canWrite?: boolean; fresh?: boolean; onReauthenticate?: () => void; surface?: "all" | "approvals"; initialSnapshot?: SecurityAgentSnapshot; autoLoad?: boolean }) {
  const [agents, setAgents] = useState<readonly SecurityAgentDefinition[]>(initialSnapshot?.agents ?? []);
  const [templates, setTemplates] = useState<readonly SecurityAgentTemplate[]>(initialSnapshot?.templates ?? []);
  const [runs, setRuns] = useState<readonly SecurityAgentRun[]>(initialSnapshot?.runs ?? []);
  const [approvals, setApprovals] = useState<readonly SecurityAgentApproval[]>(initialSnapshot?.approvals ?? []);
  const [builder, setBuilder] = useState(false);
  const [selected, setSelected] = useState<Versioned<SecurityAgentDefinition> | null>(null);
  const [selectedRun, setSelectedRun] = useState<SecurityAgentRunDetail | null>(null);
  const [selectedApproval, setSelectedApproval] = useState<SecurityAgentApproval | null>(null);
  const [error, setError] = useState(false);
  const createMutation = useRetainedWorkflowMutation<SecurityAgentCreateIntent>("security-agent:create");
  const detailMutation = useRetainedWorkflowMutation<SecurityAgentDetailIntent>(`security-agent:${selected?.value.id ?? "none"}`);
  const runMutation = useRetainedWorkflowMutation<SecurityAgentRunCancelIntent>(`security-agent-run:${selectedRun?.run.id ?? "none"}`, canWrite);
  const approvalMutation = useRetainedWorkflowMutation<SecurityAgentApprovalDecisionIntent>(`security-agent-approval:${selectedApproval?.id ?? "none"}`, canWrite && fresh);
  const mutationLocked = createMutation.isUnresolved || detailMutation.isUnresolved || runMutation.isUnresolved || approvalMutation.isUnresolved;
  useEffect(() => { if (!autoLoad) return; let active = true; const controller = new AbortController(); void loadSecurityAgentSnapshot(api, controller.signal).then((value) => { if (active) { setAgents(value.agents); setTemplates(value.templates); setRuns(value.runs ?? []); setApprovals(value.approvals ?? []); } }, () => { if (active) setError(true); }); return () => { active = false; controller.abort(); }; }, [api, autoLoad]);
  const open = async (id: string) => { try { setSelected(await api.getSecurityAgent(id)); } catch { setError(true); } };
  const openRun = async (id: string) => { try { setSelected(null); setSelectedApproval(null); setSelectedRun(await api.getSecurityAgentRun(id)); } catch { setError(true); } };
  const openApproval = async (id: string) => { try { setSelected(null); setSelectedRun(null); setSelectedApproval(await api.getSecurityAgentApproval(id)); } catch { setError(true); } };
  const pendingApprovals = approvals.filter((approval) => approval.state === "pending"); const approvalHistory = approvals.filter((approval) => approval.state !== "pending");
  return <div className="page"><PageHeader title={surface === "approvals" ? "Security Agent approvals" : "Security agents"} description="Tenant-scoped response definitions, redacted plans, supervised approvals, action outcomes, and verification." actions={surface === "all" && canWrite ? <Button variant="primary" disabled={mutationLocked} onClick={() => setBuilder(true)}>Create Security Agent</Button> : undefined} />
    {error && <p role="alert">Security Agent data is unavailable. Retry the page to load current tenant authority.</p>}
    {surface === "all" && <>{builder && canWrite && <Builder templates={templates} api={api} environmentID={environmentID} mutation={createMutation} onCreated={(value) => { setAgents((items) => [value, ...items]); setBuilder(false); }} />}<Card title="Security Agent definitions">{agents.length ? <div className="connection-list">{agents.map((agent) => <button type="button" key={agent.id} disabled={mutationLocked} aria-label={`Open ${agent.name}`} onClick={() => void open(agent.id)}><strong>{agent.name}</strong><span>{agent.trigger_kind}</span><span>{agent.enabled ? "enabled" : "disabled"}</span></button>)}</div> : <EmptyState title="No Security Agent definitions" description="Create one from a locally supported template." />}</Card><Card title="Security Agent runs">{runs.length ? <div className="connection-list">{runs.map((run) => <button type="button" key={run.id} disabled={mutationLocked} aria-label={`Open run ${run.id}`} onClick={() => void openRun(run.id)}><strong>{run.state}</strong><span>{run.id}</span><span>{run.evidence_ids.length} evidence item{run.evidence_ids.length === 1 ? "" : "s"}</span></button>)}</div> : <EmptyState title="No Security Agent runs" description="Automatic and manual runs appear here after durable acceptance." />}</Card></>}
    <Card title="Pending approvals">{pendingApprovals.length ? <div className="connection-list">{pendingApprovals.map((approval) => <button type="button" key={approval.id} disabled={mutationLocked} aria-label={`Open approval ${approval.id}`} onClick={() => void openApproval(approval.id)}><strong>{approval.expected_effect}</strong><span>{approval.run_id}</span><span>Expires {approval.expires_at}</span></button>)}</div> : <EmptyState title="No pending approvals" description="Supervised action requests appear here before any provider effect." />}</Card>
    {approvalHistory.length > 0 && <Card title="Approval history"><div className="connection-list">{approvalHistory.map((approval) => <button type="button" key={approval.id} disabled={mutationLocked} aria-label={`Open approval ${approval.id}`} onClick={() => void openApproval(approval.id)}><strong>{approval.state}</strong><span>{approval.expected_effect}</span><span>{approval.run_id}</span></button>)}</div></Card>}
    {selected && <AgentDetail selected={selected} api={api} canWrite={canWrite} mutation={detailMutation} onChange={(value) => { setSelected(value); setAgents((items) => items.map((item) => item.id === value.value.id ? value.value : item)); }} onDelete={() => { const id = selected.value.id; setSelected(null); setAgents((items) => items.filter((item) => item.id !== id)); }} onClose={() => setSelected(null)} />}
    {selectedRun && <RunDetail value={selectedRun} api={api} canWrite={canWrite} mutation={runMutation} onCancelled={(run) => { setRuns((items) => items.map((item) => item.id === run.id ? run : item)); setSelectedRun((detail) => detail ? { ...detail, run, authorization: "cancelled", approvals: detail.approvals.map((approval) => approval.state === "pending" ? { ...approval, state: "cancelled", version: approval.version + 1 } : approval), execution: detail.execution.map((step) => ["succeeded", "failed", "inconclusive", "cancelled"].includes(step.state) ? step : { ...step, state: "cancelled", version: step.version + 1 }), plan: detail.plan ? { ...detail.plan, steps: detail.plan.steps.map((step) => ["succeeded", "failed", "inconclusive", "cancelled"].includes(step.state) ? step : { ...step, state: "cancelled", version: step.version + 1 }) } : null } : null); }} onClose={() => setSelectedRun(null)} />}
    {selectedApproval && <ApprovalDetail value={selectedApproval} api={api} canWrite={canWrite} fresh={fresh} onReauthenticate={onReauthenticate} mutation={approvalMutation} onDecided={(approval) => { setSelectedApproval(approval); setApprovals((items) => items.map((item) => item.id === approval.id ? approval : item)); }} onClose={() => setSelectedApproval(null)} />}
  </div>;
}

export function ProductionSecurityAgentsView({ environmentID, surface = "all" }: { environmentID: string; surface?: "all" | "approvals" }) {
  const { client } = useAPI();
  const session = useSession();
  const api = useMemo(() => createSecurityAgentsAPI(client), [client]);
  const load = useCallback((signal?: AbortSignal) => loadSecurityAgentSnapshot(api, signal), [api]);
  const query = useAPIQuery(`workflow:security-agents:${environmentID}`, load);
  if (query.status === "loading" || query.status === "idle") return <LoadingState label="Loading Security Agents…" />;
  if (query.status === "forbidden") return <p role="alert">You are not authorized to view Security Agents.</p>;
  if (query.status === "error") return <p role="alert">Security Agent definitions are unavailable. <Button onClick={() => void query.retry()}>Retry</Button></p>;
  if (!query.data) return null;
  return <SecurityAgentsView key={`${environmentID}:${surface}`} api={api} initialSnapshot={query.data} autoLoad={false} environmentID={environmentID} canWrite={session.hasCapability("security-agents.write")} fresh={session.isFreshAuthenticated} onReauthenticate={session.reauthenticate} surface={surface} />;
}
