"use client";

import { useEffect, useMemo, useState } from "react";

import { createAPIClient, type APIClient } from "../../../apps/web/api/client";
import type { SecurityAction, SecurityAgentApproval, SecurityAgentApprovalDecision, SecurityAgentApprovalPage, SecurityAgentDefinition, SecurityAgentManualRunInput, SecurityAgentPage, SecurityAgentRun, SecurityAgentRunDetail, SecurityAgentRunPage, SecurityAgentSimulation, SecurityAgentSimulationInput, SecurityAgentTemplate } from "../../../apps/web/api/generated";
import { Badge, Button, Card, Drawer, Field, PageHeader, Select, Tabs } from "../../components/ui";

export const securityAgentOperations = [
  "listSecurityAgentTemplates", "listSecurityActions", "listSecurityAgents", "createSecurityAgent", "getSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent", "simulateSecurityAgent", "runSecurityAgent", "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval", "decideSecurityAgentApproval",
] as const;

export type SecurityAgentsAPI = {
  listSecurityAgentTemplates(): Promise<readonly SecurityAgentTemplate[]>;
  listSecurityActions(): Promise<readonly SecurityAction[]>;
  listSecurityAgents(): Promise<SecurityAgentPage>;
  createSecurityAgent(value: SecurityAgentDefinition): Promise<SecurityAgentDefinition>;
  getSecurityAgent(id: string): Promise<SecurityAgentDefinition>;
  updateSecurityAgent(id: string, value: SecurityAgentDefinition): Promise<SecurityAgentDefinition>;
  deleteSecurityAgent(id: string): Promise<void>;
  simulateSecurityAgent(id: string, value: SecurityAgentSimulationInput): Promise<SecurityAgentSimulation>;
  runSecurityAgent(id: string, value: SecurityAgentManualRunInput): Promise<SecurityAgentRun>;
  listSecurityAgentRuns(): Promise<SecurityAgentRunPage>;
  getSecurityAgentRun(id: string): Promise<SecurityAgentRunDetail>;
  cancelSecurityAgentRun(id: string): Promise<SecurityAgentRun>;
  listSecurityAgentApprovals(): Promise<SecurityAgentApprovalPage>;
  getSecurityAgentApproval(id: string): Promise<SecurityAgentApproval>;
  decideSecurityAgentApproval(id: string, value: SecurityAgentApprovalDecision): Promise<SecurityAgentApproval>;
};

function requireData<T>(value: { data?: unknown; error?: unknown }): T {
  if (value.error || value.data === undefined) throw new Error("Security Agent API rejected");
  return value.data as T;
}

export function createSecurityAgentsAPI(client: APIClient = createAPIClient()): SecurityAgentsAPI {
  return {
    async listSecurityAgentTemplates() { return requireData<{ items: readonly SecurityAgentTemplate[] }>(await client.GET("/api/v1/security-agent-templates")).items; },
    async listSecurityActions() { return requireData<{ items: readonly SecurityAction[] }>(await client.GET("/api/v1/security-actions")).items; },
    async listSecurityAgents() { return requireData<SecurityAgentPage>(await client.GET("/api/v1/security-agents", { params: { query: { limit: 50 } } })); },
    async createSecurityAgent(value) { return requireData<SecurityAgentDefinition>(await client.POST("/api/v1/security-agents", { body: value })); },
    async getSecurityAgent(id) { return requireData<SecurityAgentDefinition>(await client.GET("/api/v1/security-agents/{id}", { params: { path: { id } } })); },
    async updateSecurityAgent(id, value) { return requireData<SecurityAgentDefinition>(await client.PATCH("/api/v1/security-agents/{id}", { params: { path: { id } }, body: value })); },
    async deleteSecurityAgent(id) { const response = await client.DELETE("/api/v1/security-agents/{id}", { params: { path: { id } } }); if (response.error) throw new Error("Security Agent API rejected"); },
    async simulateSecurityAgent(id, value) { return requireData<SecurityAgentSimulation>(await client.POST("/api/v1/security-agents/{id}/simulate", { params: { path: { id } }, body: value })); },
    async runSecurityAgent(id, value) { return requireData<SecurityAgentRun>(await client.POST("/api/v1/security-agents/{id}/runs", { params: { path: { id } }, body: value })); },
    async listSecurityAgentRuns() { return requireData<SecurityAgentRunPage>(await client.GET("/api/v1/security-agent-runs", { params: { query: { limit: 50 } } })); },
    async getSecurityAgentRun(id) { return requireData<SecurityAgentRunDetail>(await client.GET("/api/v1/security-agent-runs/{id}", { params: { path: { id } } })); },
    async cancelSecurityAgentRun(id) { return requireData<SecurityAgentRun>(await client.POST("/api/v1/security-agent-runs/{id}/cancel", { params: { path: { id } } })); },
    async listSecurityAgentApprovals() { return requireData<SecurityAgentApprovalPage>(await client.GET("/api/v1/security-agent-approvals")); },
    async getSecurityAgentApproval(id) { return requireData<SecurityAgentApproval>(await client.GET("/api/v1/security-agent-approvals/{id}", { params: { path: { id } } })); },
    async decideSecurityAgentApproval(id, value) { return requireData<SecurityAgentApproval>(await client.POST("/api/v1/security-agent-approvals/{id}/decision", { params: { path: { id } }, body: value })); },
  };
}

const defaultSecurityAgentsAPI = createSecurityAgentsAPI();

const stages = ["Start / Trigger", "Goal / Scope", "Actions", "Autonomy", "Limits", "Verification", "Simulate"] as const;
const triggerChoices = ["finding", "attack_path", "runtime_decision"] as const;
const productLimits = { steps: 100, runtimeSeconds: 86400, temporaryPolicySeconds: 86400, aiTokens: 12000, concurrency: 10 } as const;
const triggerSources = { finding: "credential", attack_path: "verified", runtime_decision: "block" } as const;
const boundedNumber = (value: string, maximum: number) => Math.max(1, Math.min(maximum, Number(value) || 1));

function Builder({ templates, actions, agents, api, onCreated }: { templates: readonly SecurityAgentTemplate[]; actions: readonly SecurityAction[]; agents: readonly SecurityAgentDefinition[]; api: SecurityAgentsAPI; onCreated(agent: SecurityAgentDefinition): void }) {
  const [stage, setStage] = useState<(typeof stages)[number]>(stages[0]);
  const [template, setTemplate] = useState("blank");
  const [name, setName] = useState("Bounded response");
  const [trigger, setTrigger] = useState<(typeof triggerChoices)[number]>("finding");
  const [goal, setGoal] = useState("Contain the selected risk with bounded reversible actions");
  const [environment, setEnvironment] = useState("production");
  const [selectedActions, setSelectedActions] = useState<string[]>([]);
  const [autonomy, setAutonomy] = useState<"supervised" | "autonomous">("supervised");
  const [steps, setSteps] = useState(10);
  const [runtime, setRuntime] = useState(900);
  const [temporaryPolicy, setTemporaryPolicy] = useState(3600);
  const [aiTokens, setAITokens] = useState(4000);
  const [concurrency, setConcurrency] = useState(2);
  const [verification, setVerification] = useState("test_run");
  const [simulation, setSimulation] = useState<SecurityAgentSimulation | null>(null);
  const [createdAgent, setCreatedAgent] = useState<SecurityAgentDefinition | null>(null);
  const allowedActions = useMemo(() => actions, [actions]);
  const selectedTemplate = useMemo(() => templates.find((value) => value.id === template), [template, templates]);
  const selectedMetadata = useMemo(() => actions.filter((value) => selectedActions.includes(value.key)), [actions, selectedActions]);
  const verificationChoices = useMemo(() => selectedTemplate ? [selectedTemplate.verification_condition] : [...new Set(selectedMetadata.map((value) => value.verification_kind))], [selectedMetadata, selectedTemplate]);
  const verificationCompatible = selectedTemplate
    ? verification === selectedTemplate.verification_condition && selectedActions.length === selectedTemplate.default_actions.length && selectedTemplate.default_actions.every((value) => selectedActions.includes(value))
    : selectedMetadata.length > 0 && selectedMetadata.every((value) => value.verification_kind === verification);

  const chooseTemplate = (id: string) => {
    setTemplate(id);
    const selected = templates.find((value) => value.id === id);
    if (selected) {
      setTrigger(selected.trigger_kind);
      setSelectedActions([...selected.default_actions]);
      setVerification(selected.verification_condition);
    } else {
      setTrigger("finding");
      setSelectedActions([]);
      setVerification("test_run");
    }
    setCreatedAgent(null);
  };
  const chooseTrigger = (value: (typeof triggerChoices)[number]) => {
    setTrigger(value);
    setCreatedAgent(null);
  };
  const save = async () => {
    const created = await api.createSecurityAgent({
      id: "", name, trigger_kind: trigger, trigger_source: triggerSources[trigger], environment_ids: [environment], autonomy,
      max_steps: steps, max_duration_seconds: runtime, temporary_policy_seconds: temporaryPolicy, ai_token_budget: aiTokens, concurrency_limit: concurrency,
      allowed_actions: selectedActions, verification_kind: verification, definition_version: 1, enabled: true,
    });
    setCreatedAgent(created);
    onCreated(created);
  };
  const simulate = async () => {
    const agent = createdAgent || agents[0];
    if (!agent) return;
    setSimulation(await api.simulateSecurityAgent(agent.id, { goal, environment_id: environment, evidence_ids: ["evidence-selected"] }));
  };

  return <Card className="security-agent-builder">
    <div className="wizard-layout">
      <aside className="wizard-sidebar"><div className="wizard-sidebar-title">Build Security Agent</div>{stages.map((value, index) => <button key={value} className={stage === value ? "active" : ""} onClick={() => setStage(value)}><span>{index + 1}</span><div><strong>{value}</strong><small>{index < stages.indexOf(stage) ? "Configured" : "Bounded product controls"}</small></div></button>)}</aside>
      <section className="wizard-main">
        <div className="wizard-heading"><div><span className="eyebrow">Security Agent builder</span><h3>{stage}</h3><p>Definitions use registered product actions and scoped references only.</p></div><Badge tone="brand">Generated API</Badge></div>
        {stage === "Start / Trigger" && <div className="form-stack"><Field label="Definition name" value={name} maxLength={256} onChange={(event) => setName(event.target.value)} /><Select label="Start from template" value={template} onChange={(event) => chooseTemplate(event.target.value)}><option value="blank">Blank definition</option>{templates.map((value) => <option value={value.id} key={value.id}>{value.name}</option>)}</Select><Select label="Bounded trigger" value={trigger} onChange={(event) => chooseTrigger(event.target.value as typeof trigger)}>{triggerChoices.map((value) => <option value={value} key={value}>{value}</option>)}</Select></div>}
        {stage === "Goal / Scope" && <div className="form-stack"><Field label="Short goal" value={goal} maxLength={1024} onChange={(event) => setGoal(event.target.value)} /><div className="form-grid"><Select label="Workspace" value="agent-security"><option>agent-security</option></Select><Select label="Environment" value={environment} onChange={(event) => setEnvironment(event.target.value)}><option value="production">Production</option><option value="staging">Staging</option></Select><Select label="Agent selector" value="all-scoped"><option>all-scoped</option></Select><Select label="Tag selector" value="production"><option>production</option></Select></div><small>Changing the goal never changes the allowed-action list. Add or remove actions explicitly.</small></div>}
        {stage === "Actions" && <div className="form-stack">{allowedActions.map((action) => <label className="control-option" key={action.key}><input aria-label={`Select ${action.key}`} type="checkbox" checked={selectedActions.includes(action.key)} onChange={(event) => { const next = event.target.checked ? [...selectedActions, action.key] : selectedActions.filter((value) => value !== action.key); setSelectedActions(next); if (template === "blank" && next.length === 1) setVerification(action.verification_kind); setCreatedAgent(null); }} /><span><strong>{action.key}</strong><small>Risk: {action.risk_class} · Support: {action.target_types.join(", ")} · {action.reversible ? "Reversible" : "Not reversible"}</small></span></label>)}</div>}
        {stage === "Autonomy" && <div className="form-stack"><Select label="Execution mode" value={autonomy} onChange={(event) => setAutonomy(event.target.value as typeof autonomy)}><option value="supervised">Approval required</option><option value="autonomous">Automatic where product permits</option></Select><label className="control-option"><input aria-label="Mandatory product approval floor" type="checkbox" checked disabled /><span><strong>Mandatory product approval floor</strong><small>Containment, destructive, and administrator actions cannot lower their approval requirement.</small></span></label></div>}
        {stage === "Limits" && <div className="form-grid"><Field label="Step limit" type="number" min={1} max={productLimits.steps} value={steps} onChange={(event) => setSteps(boundedNumber(event.target.value, productLimits.steps))} /><Field label="Runtime seconds" type="number" min={1} max={productLimits.runtimeSeconds} value={runtime} onChange={(event) => setRuntime(boundedNumber(event.target.value, productLimits.runtimeSeconds))} /><Field label="Temporary-policy seconds" type="number" min={1} max={productLimits.temporaryPolicySeconds} value={temporaryPolicy} onChange={(event) => setTemporaryPolicy(boundedNumber(event.target.value, productLimits.temporaryPolicySeconds))} /><Field label="AI token budget" type="number" min={1} max={productLimits.aiTokens} value={aiTokens} onChange={(event) => setAITokens(boundedNumber(event.target.value, productLimits.aiTokens))} /><Field label="Concurrency" type="number" min={1} max={productLimits.concurrency} value={concurrency} onChange={(event) => setConcurrency(boundedNumber(event.target.value, productLimits.concurrency))} /></div>}
        {stage === "Verification" && <div className="form-stack"><Select label="Required terminal verification" value={verification} onChange={(event) => setVerification(event.target.value)}>{verificationChoices.map((value) => <option value={value} key={value}>{value}</option>)}</Select><small>A definition cannot be enabled without a terminal verification criterion compatible with every selected action.</small></div>}
        {stage === "Simulate" && <div className="form-stack"><p>Simulation matches scoped evidence, proposes a plan, and evaluates authorization without action side effects.</p><Button variant="primary" disabled={!name || !verificationCompatible} onClick={() => void save()}>Save Security Agent</Button><Button disabled={!(createdAgent || agents.length) || !verification} onClick={() => void simulate()}>Simulate with selected evidence</Button>{simulation && <div className="review-summary"><div><span>Matched evidence</span><strong>{simulation.matched_evidence_ids.length}</strong></div><div><span>Proposed plan</span><strong>{simulation.summary}</strong></div><div><span>Approval points</span><strong>{simulation.steps.filter((value) => value.approval_required).length}</strong></div><div><span>Side effects</span><strong>{simulation.side_effects}</strong></div>{simulation.steps.map((value) => <div key={value.index}><span>{value.action}</span><strong>authorization: {value.authorization}</strong></div>)}</div>}</div>}
      </section>
      <aside className="wizard-assistant"><div><span className="assistant-orb">S</span><strong>Definition checks</strong></div><div className="assistant-empty"><p>{selectedActions.length} explicit actions</p><p>{steps} steps · {runtime}s runtime</p><p>{autonomy} · verification required</p></div></aside>
    </div>
  </Card>;
}

function AgentDetail({ agent, runs, actions, onClose }: { agent: SecurityAgentDefinition; runs: readonly SecurityAgentRun[]; actions: readonly SecurityAction[]; onClose: () => void }) {
  const allowed = actions.filter((value) => agent.allowed_actions.includes(value.key));
  return <Drawer open title={agent.name} onClose={onClose}><div className="detail-content"><h3>Definition</h3><p>{agent.trigger_kind} · {agent.trigger_source} · version {agent.definition_version}</p><h3>Allowed actions</h3>{allowed.map((value) => <div key={value.key}><strong>{value.key}</strong> · {value.risk_class} · {value.approval_floor}</div>)}<h3>Limits</h3><p>{agent.max_steps} steps · {agent.max_duration_seconds}s · {agent.autonomy}</p><h3>Verification</h3><p>{agent.verification_kind}</p><h3>Recent runs</h3>{runs.filter((value) => value.agent_id === agent.id).slice(0, 5).map((value) => <div key={value.id}>{value.id} · {value.state}</div>)}<small>Model and provider internals are available only in protected audit metadata.</small></div></Drawer>;
}

function RunDetail({ detail, onClose }: { detail: SecurityAgentRunDetail; onClose: () => void }) {
  const plan = detail.plan as { summary?: string; steps?: Array<{ index: number; action: string; parameters?: Record<string, string> }> };
  const execution = detail.execution as unknown as ReadonlyArray<{ id?: string; action_key?: string; state?: string }>;
  return <Drawer open title={`Run ${detail.run.id}`} onClose={onClose}><div className="detail-content"><h3>Trigger / evidence</h3>{detail.evidence_ids.map((value) => <a key={value} href={`/violations?evidence_id=${encodeURIComponent(value)}#security-agent-run-${detail.run.id}`}>Scoped activity link · {value}</a>)}<h3>AI rationale</h3><p>{plan.summary || "Bounded planner rationale unavailable"}</p><h3>Deterministic authorization</h3><Badge tone="info">{detail.authorization}</Badge><h3>Ordered plan</h3>{(plan.steps || []).map((value) => <div key={value.index}><strong>{value.index + 1}. {value.action}</strong><code>{JSON.stringify(value.parameters || { protected: "[REDACTED]" })}</code></div>)}<h3>Action results</h3>{execution.map((value, index) => <div key={value.id || index}><strong>{value.action_key || `Step ${index + 1}`}</strong> · {value.state || "recorded"}<p>Protected arguments: [REDACTED]</p><p>Rollback / TTL: bounded by action metadata</p><p>Verification: {detail.verification}</p></div>)}<h3>Approvals</h3>{detail.approvals.map((value) => <div key={value.id}>{value.id} · {value.state}</div>)}</div></Drawer>;
}

function ApprovalDetail({ approval, api, onClose }: { approval: SecurityAgentApproval; api: SecurityAgentsAPI; onClose: () => void }) {
  const [value, setValue] = useState(approval);
  const decide = async (decision: SecurityAgentApprovalDecision["decision"]) => setValue(await api.decideSecurityAgentApproval(value.id, { decision }));
  return <Drawer open title={`Approval ${value.id}`} onClose={onClose}><div className="detail-content"><h3>Reason and evidence</h3>{(value.evidence_summary || []).map((item) => <a key={item} href={`/violations?evidence_id=${encodeURIComponent(item)}#security-agent-run-${value.run_id}`}>{item}</a>)}<h3>Expected side effect</h3><p>{value.expected_effect || "Bounded registered action"}</p><h3>Risk and reversibility</h3><p>{value.reversible ? "Reversible" : "Not reversible"} · TTL {value.ttl_seconds || 0}s</p><h3>Requester / run context</h3><a href={`/protect/security-agents?tab=runs&run_id=${encodeURIComponent(value.run_id)}`}>Scoped activity link · {value.run_id}</a><p>Fresh authentication is required before every sensitive decision.</p><div className="button-row"><Button onClick={() => void decide("approved")}>Approve</Button><Button onClick={() => void decide("rejected")}>Deny</Button><Button onClick={() => void decide("cancelled")}>Cancel</Button></div></div></Drawer>;
}

export function SecurityAgentsView({ api = defaultSecurityAgentsAPI }: { api?: SecurityAgentsAPI }) {
  const [tab, setTab] = useState("agents");
  const [agents, setAgents] = useState<readonly SecurityAgentDefinition[]>([]);
  const [templates, setTemplates] = useState<readonly SecurityAgentTemplate[]>([]);
  const [actions, setActions] = useState<readonly SecurityAction[]>([]);
  const [runs, setRuns] = useState<readonly SecurityAgentRun[]>([]);
  const [approvals, setApprovals] = useState<readonly SecurityAgentApproval[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<SecurityAgentDefinition | null>(null);
  const [selectedRun, setSelectedRun] = useState<SecurityAgentRunDetail | null>(null);
  const [selectedApproval, setSelectedApproval] = useState<SecurityAgentApproval | null>(null);
  const [error, setError] = useState(false);
  useEffect(() => { let active = true; void Promise.all([api.listSecurityAgents(), api.listSecurityAgentTemplates(), api.listSecurityActions(), api.listSecurityAgentRuns(), api.listSecurityAgentApprovals()]).then(([page, nextTemplates, nextActions, runPage, approvalPage]) => { if (active) { setAgents(page.items); setTemplates(nextTemplates); setActions(nextActions); setRuns(runPage.items); setApprovals(approvalPage.items); } }, () => { if (active) setError(true); }); return () => { active = false; }; }, [api]);
  const openAgent = async (id: string) => setSelectedAgent(await api.getSecurityAgent(id));
  const openRun = async (id: string) => setSelectedRun(await api.getSecurityAgentRun(id));
  const openApproval = async (id: string) => setSelectedApproval(await api.getSecurityAgentApproval(id));
  const agentsView = <Card><div className="table-scroll"><table className="data-table"><thead><tr><th>Name</th><th>Status</th><th>Trigger</th><th>Scope</th><th>Autonomy</th><th>Last outcome</th><th>Pending approvals</th><th>Owner</th></tr></thead><tbody>{agents.map((agent) => <tr key={agent.id}><td><button className="row-title" onClick={() => void openAgent(agent.id)}>{agent.name}</button></td><td><Badge tone={agent.enabled ? "success" : "neutral"}>{agent.enabled ? "Enabled" : "Disabled"}</Badge></td><td>{agent.trigger_kind}</td><td>{agent.environment_ids.join(", ")}</td><td>{agent.autonomy}</td><td>{runs.find((value) => value.agent_id === agent.id)?.state || "Awaiting first verified run"}</td><td>{approvals.filter((value) => runs.some((run) => run.agent_id === agent.id && run.id === value.run_id) && value.state === "pending").length}</td><td>Security operations</td></tr>)}</tbody></table></div>{!agents.length && !error && <p>No Security Agents in this authorized scope.</p>}</Card>;
  const runsView = <Card title="Security Agent runs"><div className="table-scroll"><table className="data-table"><thead><tr><th>Run</th><th>Agent</th><th>State</th><th>Trigger evidence</th></tr></thead><tbody>{runs.map((run) => <tr key={run.id}><td><button className="row-title" onClick={() => void openRun(run.id)}>{run.id}</button></td><td>{run.agent_id}</td><td><Badge tone={run.state === "failed" || run.state === "inconclusive" ? "warning" : "info"}>{run.state}</Badge></td><td>{run.evidence_ids.map((value) => <a key={value} href={`/violations?evidence_id=${encodeURIComponent(value)}#security-agent-run-${run.id}`}>{value}</a>)}</td></tr>)}</tbody></table></div></Card>;
  const approvalsView = <Card title="Pending approvals"><div className="table-scroll"><table className="data-table"><thead><tr><th>Action</th><th>Agent</th><th>Target</th><th>Expiry</th><th>Requester / run context</th></tr></thead><tbody>{approvals.map((approval) => <tr key={approval.id}><td><button className="row-title" onClick={() => void openApproval(approval.id)}>{approval.step_id}</button></td><td>{runs.find((run) => run.id === approval.run_id)?.agent_id}</td><td>Authorized scoped target</td><td>{approval.expires_at}</td><td>{approval.run_id}</td></tr>)}</tbody></table></div></Card>;
  return <div className="page"><PageHeader title="Security agents" description="Bounded automated response definitions, approvals, and verified outcomes." actions={<Button variant="primary" onClick={() => setTab("builder")}>Create Security Agent</Button>} /><Tabs tabs={[{ id: "agents", label: "Security Agents", count: agents.length }, { id: "runs", label: "Runs", count: runs.length }, { id: "approvals", label: "Approvals", count: approvals.filter((value) => value.state === "pending").length }, { id: "builder", label: "Builder" }]} active={tab} onChange={setTab} />{error && <div role="alert" className="form-error">Security Agent API unavailable</div>}{tab === "agents" ? agentsView : tab === "runs" ? runsView : tab === "approvals" ? approvalsView : <Builder templates={templates} actions={actions} agents={agents} api={api} onCreated={(agent) => setAgents((values) => [...values, agent])} />}{selectedAgent && <AgentDetail agent={selectedAgent} runs={runs} actions={actions} onClose={() => setSelectedAgent(null)} />}{selectedRun && <RunDetail detail={selectedRun} onClose={() => setSelectedRun(null)} />}{selectedApproval && <ApprovalDetail approval={selectedApproval} api={api} onClose={() => setSelectedApproval(null)} />}</div>;
}
