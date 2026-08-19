"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { createAPIClient, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { decodeSecurityAgentDefinition, decodeSecurityAgentPage, decodeSecurityAgentTemplatePage } from "../../../apps/web/api/decoders";
import type { SecurityAgentDefinition, SecurityAgentInput, SecurityAgentPage, SecurityAgentTemplate } from "../../../apps/web/api/generated";
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

export const securityAgentOperations = [
  "listSecurityAgentTemplates", "listSecurityAgents", "createSecurityAgent", "getSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent",
] as const;

export type SecurityAgentsAPI = {
  listSecurityAgentTemplates(signal?: AbortSignal): Promise<readonly SecurityAgentTemplate[]>;
  listSecurityAgents(signal?: AbortSignal): Promise<SecurityAgentPage>;
  createSecurityAgent(value: SecurityAgentInput, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentDefinition>>;
  getSecurityAgent(id: string, signal?: AbortSignal): Promise<Versioned<SecurityAgentDefinition>>;
  updateSecurityAgent(id: string, version: string, value: SecurityAgentDefinition, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentDefinition>>;
  deleteSecurityAgent(id: string, version: string, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<void>>;
};

export function createSecurityAgentsAPI(client: APIClient = createAPIClient()): SecurityAgentsAPI {
  return {
    async listSecurityAgentTemplates(signal) {
      return requireAPIData(await client.GET("/api/v1/security-agent-templates", { signal }), decodeSecurityAgentTemplatePage).items;
    },
    async listSecurityAgents(signal) {
      return requireAPIData(await client.GET("/api/v1/security-agents", { signal }), decodeSecurityAgentPage);
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
  };
}

const defaultSecurityAgentsAPI = createSecurityAgentsAPI();
const maximums = { steps: 100, runtime: 86400, temporaryPolicy: 86400, aiTokens: 12000, concurrency: 10 } as const;
const triggerSources = { finding: "credential", attack_path: "verified", runtime_decision: "block" } as const;
const bounded = (value: string, maximum: number) => Math.max(1, Math.min(maximum, Number(value) || 1));
type SecurityAgentSnapshot = { agents: readonly SecurityAgentDefinition[]; templates: readonly SecurityAgentTemplate[] };

async function loadSecurityAgentSnapshot(api: SecurityAgentsAPI, signal?: AbortSignal): Promise<SecurityAgentSnapshot> {
  const [page, templates] = await Promise.all([api.listSecurityAgents(signal), api.listSecurityAgentTemplates(signal)]);
  return { agents: page.items, templates };
}

function Builder({ templates, api, environmentID, onCreated }: { templates: readonly SecurityAgentTemplate[]; api: SecurityAgentsAPI; environmentID: string; onCreated(value: SecurityAgentDefinition): void }) {
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
      const receipt = await api.createSecurityAgent({ name, trigger_kind: selected.trigger_kind, trigger_source: triggerSources[selected.trigger_kind], environment_ids: [environmentID], autonomy: "supervised", max_steps: steps, max_duration_seconds: runtime, temporary_policy_seconds: temporaryPolicy, ai_token_budget: aiTokens, concurrency_limit: concurrency, allowed_actions: selected.default_actions, verification_kind: selected.verification_condition, definition_version: selected.version, enabled: true });
      onCreated(receipt.value);
    } catch { setError(true); } finally { setBusy(false); }
  };
  return <Card title="Create a definition from a locally supported template"><div className="form-stack">
    <Select label="Definition template" value={templateID} onChange={(event) => setTemplateID(event.target.value)}>{templates.map((value) => <option key={value.id} value={value.id}>{value.name}</option>)}</Select>
    <Field label="Definition name" value={name} maxLength={256} onChange={(event) => setName(event.target.value)} />
    <Field label="Authorized environment" value={environmentID} readOnly />
    {selected && <p>Trigger: {selected.trigger_kind}. Template actions: {selected.default_actions.join(", ")}. Verification: {selected.verification_condition}.</p>}
    <div className="form-grid"><Field label="Step limit" type="number" min={1} max={maximums.steps} value={steps} onChange={(event) => setSteps(bounded(event.target.value, maximums.steps))} /><Field label="Runtime seconds" type="number" min={1} max={maximums.runtime} value={runtime} onChange={(event) => setRuntime(bounded(event.target.value, maximums.runtime))} /><Field label="Temporary-policy seconds" type="number" min={1} max={maximums.temporaryPolicy} value={temporaryPolicy} onChange={(event) => setTemporaryPolicy(bounded(event.target.value, maximums.temporaryPolicy))} /><Field label="AI token budget" type="number" min={1} max={maximums.aiTokens} value={aiTokens} onChange={(event) => setAITokens(bounded(event.target.value, maximums.aiTokens))} /><Field label="Concurrency" type="number" min={1} max={maximums.concurrency} value={concurrency} onChange={(event) => setConcurrency(bounded(event.target.value, maximums.concurrency))} /></div>
    <p>Execution, simulation, approvals, and provider actions remain hidden until a real scoped executor and evidence resolver are available.</p>
    {error && <p role="alert">The definition was not saved.</p>}<Button variant="primary" disabled={busy || !selected || !name} onClick={() => void save()}>Save Security Agent definition</Button>
  </div></Card>;
}

function AgentDetail({ selected, api, canWrite, onChange, onDelete, onClose }: { selected: Versioned<SecurityAgentDefinition>; api: SecurityAgentsAPI; canWrite: boolean; onChange(value: Versioned<SecurityAgentDefinition>): void; onDelete(): void; onClose(): void }) {
  const [name, setName] = useState(selected.value.name);
  const [enabled, setEnabled] = useState(selected.value.enabled);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const save = async () => { setBusy(true); setError(false); try { const receipt = await api.updateSecurityAgent(selected.value.id, selected.version, { ...selected.value, name, enabled }); onChange(receipt); } catch { setError(true); } finally { setBusy(false); } };
  const remove = async () => { setBusy(true); setError(false); try { await api.deleteSecurityAgent(selected.value.id, selected.version); onDelete(); } catch { setError(true); setBusy(false); } };
  return <Drawer open title={selected.value.name} onClose={onClose}><div className="detail-content"><p><Badge tone={enabled ? "success" : "neutral"}>{enabled ? "Enabled" : "Disabled"}</Badge> Resource version {selected.version}</p><Field label="Definition name" value={name} disabled={!canWrite || busy} onChange={(event) => setName(event.target.value)} /><p>{selected.value.trigger_kind} · {selected.value.environment_ids.join(", ")} · supervised</p><h3>Template controls</h3><p>{selected.value.allowed_actions.join(", ")} · verification {selected.value.verification_kind}</p><h3>Limits</h3><p>{selected.value.max_steps} steps · {selected.value.max_duration_seconds}s · concurrency {selected.value.concurrency_limit}</p>{canWrite && <><label className="control-option"><input aria-label="Definition enabled" type="checkbox" checked={enabled} disabled={busy} onChange={(event) => setEnabled(event.target.checked)} /><span><strong>Definition enabled</strong><small>This does not expose execution controls.</small></span></label><div className="button-row"><Button disabled={busy} onClick={() => void save()}>Save definition</Button><Button variant="danger" disabled={busy} onClick={() => void remove()}>Delete definition</Button></div></>}{error && <p role="alert">The definition changed elsewhere or could not be updated. Close and reopen it.</p>}</div></Drawer>;
}

export function SecurityAgentsView({ api = defaultSecurityAgentsAPI, environmentID = "production", canWrite = true, initialSnapshot, autoLoad = true }: { api?: SecurityAgentsAPI; environmentID?: string; canWrite?: boolean; initialSnapshot?: SecurityAgentSnapshot; autoLoad?: boolean }) {
  const [agents, setAgents] = useState<readonly SecurityAgentDefinition[]>(initialSnapshot?.agents ?? []);
  const [templates, setTemplates] = useState<readonly SecurityAgentTemplate[]>(initialSnapshot?.templates ?? []);
  const [builder, setBuilder] = useState(false);
  const [selected, setSelected] = useState<Versioned<SecurityAgentDefinition> | null>(null);
  const [error, setError] = useState(false);
  useEffect(() => { if (!autoLoad) return; let active = true; const controller = new AbortController(); void loadSecurityAgentSnapshot(api, controller.signal).then((value) => { if (active) { setAgents(value.agents); setTemplates(value.templates); } }, () => { if (active) setError(true); }); return () => { active = false; controller.abort(); }; }, [api, autoLoad]);
  const open = async (id: string) => { try { setSelected(await api.getSecurityAgent(id)); } catch { setError(true); } };
  return <div className="page"><PageHeader title="Security agents" description="Durable, scoped response definitions. Execution controls appear only with a real evidence resolver and executor." actions={canWrite ? <Button variant="primary" onClick={() => setBuilder(true)}>Create Security Agent</Button> : undefined} />{error && <p role="alert">Security Agent definitions are unavailable.</p>}{builder && canWrite && <Builder templates={templates} api={api} environmentID={environmentID} onCreated={(value) => { setAgents((items) => [value, ...items]); setBuilder(false); }} />}<Card title="Security Agent definitions">{agents.length ? <div className="connection-list">{agents.map((agent) => <button type="button" key={agent.id} aria-label={`Open ${agent.name}`} onClick={() => void open(agent.id)}><strong>{agent.name}</strong><span>{agent.trigger_kind}</span><span>{agent.enabled ? "enabled" : "disabled"}</span></button>)}</div> : <EmptyState title="No Security Agent definitions" description="Create one from a locally supported template." />}</Card>{selected && <AgentDetail selected={selected} api={api} canWrite={canWrite} onChange={(value) => { setSelected(value); setAgents((items) => items.map((item) => item.id === value.value.id ? value.value : item)); }} onDelete={() => { const id = selected.value.id; setSelected(null); setAgents((items) => items.filter((item) => item.id !== id)); }} onClose={() => setSelected(null)} />}</div>;
}

export function ProductionSecurityAgentsView({ environmentID }: { environmentID: string }) {
  const { client } = useAPI();
  const session = useSession();
  const api = useMemo(() => createSecurityAgentsAPI(client), [client]);
  const load = useCallback((signal?: AbortSignal) => loadSecurityAgentSnapshot(api, signal), [api]);
  const query = useAPIQuery(`workflow:security-agents:${environmentID}`, load);
  if (query.status === "loading" || query.status === "idle") return <LoadingState label="Loading Security Agents…" />;
  if (query.status === "forbidden") return <p role="alert">You are not authorized to view Security Agents.</p>;
  if (query.status === "error") return <p role="alert">Security Agent definitions are unavailable. <Button onClick={() => void query.retry()}>Retry</Button></p>;
  if (!query.data) return null;
  return <SecurityAgentsView key={environmentID} api={api} initialSnapshot={query.data} autoLoad={false} environmentID={environmentID} canWrite={session.hasCapability("security-agents.write")} />;
}
