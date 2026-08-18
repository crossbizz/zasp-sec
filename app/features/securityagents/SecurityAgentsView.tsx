"use client";

import { useEffect, useMemo, useState } from "react";

import { createAPIClient, type APIClient } from "../../../apps/web/api/client";
import type { SecurityAction, SecurityAgentApproval, SecurityAgentApprovalDecision, SecurityAgentApprovalPage, SecurityAgentDefinition, SecurityAgentManualRunInput, SecurityAgentPage, SecurityAgentRun, SecurityAgentRunDetail, SecurityAgentRunPage, SecurityAgentSimulation, SecurityAgentSimulationInput, SecurityAgentTemplate } from "../../../apps/web/api/generated";
import { Badge, Button, Card, Field, PageHeader, Select, Tabs } from "../../components/ui";

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

function Builder({ templates, actions, agents, api }: { templates: readonly SecurityAgentTemplate[]; actions: readonly SecurityAction[]; agents: readonly SecurityAgentDefinition[]; api: SecurityAgentsAPI }) {
  const [stage, setStage] = useState<(typeof stages)[number]>(stages[0]);
  const [template, setTemplate] = useState("blank");
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
  const allowedActions = useMemo(() => actions, [actions]);

  const chooseTemplate = (id: string) => {
    setTemplate(id);
    const selected = templates.find((value) => value.id === id);
    if (selected) {
      setTrigger(selected.trigger_kind);
      setSelectedActions([...selected.default_actions]);
      setVerification(selected.verification_condition);
    }
  };
  const simulate = async () => {
    const agent = agents[0];
    if (!agent) return;
    setSimulation(await api.simulateSecurityAgent(agent.id, { goal, environment_id: environment, evidence_ids: ["evidence-selected"] }));
  };

  return <Card className="security-agent-builder">
    <div className="wizard-layout">
      <aside className="wizard-sidebar"><div className="wizard-sidebar-title">Build Security Agent</div>{stages.map((value, index) => <button key={value} className={stage === value ? "active" : ""} onClick={() => setStage(value)}><span>{index + 1}</span><div><strong>{value}</strong><small>{index < stages.indexOf(stage) ? "Configured" : "Bounded product controls"}</small></div></button>)}</aside>
      <section className="wizard-main">
        <div className="wizard-heading"><div><span className="eyebrow">Security Agent builder</span><h3>{stage}</h3><p>Definitions use registered product actions and scoped references only.</p></div><Badge tone="brand">Generated API</Badge></div>
        {stage === "Start / Trigger" && <div className="form-stack"><Select label="Start from template" value={template} onChange={(event) => chooseTemplate(event.target.value)}><option value="blank">Blank definition</option>{templates.map((value) => <option value={value.id} key={value.id}>{value.name}</option>)}</Select><Select label="Bounded trigger" value={trigger} onChange={(event) => setTrigger(event.target.value as typeof trigger)}>{triggerChoices.map((value) => <option value={value} key={value}>{value}</option>)}</Select></div>}
        {stage === "Goal / Scope" && <div className="form-stack"><Field label="Short goal" value={goal} maxLength={1024} onChange={(event) => setGoal(event.target.value)} /><div className="form-grid"><Select label="Workspace" value="agent-security"><option>agent-security</option></Select><Select label="Environment" value={environment} onChange={(event) => setEnvironment(event.target.value)}><option value="production">Production</option><option value="staging">Staging</option></Select><Select label="Agent selector" value="all-scoped"><option>all-scoped</option></Select><Select label="Tag selector" value="production"><option>production</option></Select></div><small>Changing the goal never changes the allowed-action list. Add or remove actions explicitly.</small></div>}
        {stage === "Actions" && <div className="form-stack">{allowedActions.map((action) => <label className="control-option" key={action.key}><input aria-label={`Select ${action.key}`} type="checkbox" checked={selectedActions.includes(action.key)} onChange={(event) => setSelectedActions(event.target.checked ? [...selectedActions, action.key] : selectedActions.filter((value) => value !== action.key))} /><span><strong>{action.key}</strong><small>Risk: {action.risk_class} · Support: {action.target_types.join(", ")} · {action.reversible ? "Reversible" : "Not reversible"}</small></span></label>)}</div>}
        {stage === "Autonomy" && <div className="form-stack"><Select label="Execution mode" value={autonomy} onChange={(event) => setAutonomy(event.target.value as typeof autonomy)}><option value="supervised">Approval required</option><option value="autonomous">Automatic where product permits</option></Select><label className="control-option"><input aria-label="Mandatory product approval floor" type="checkbox" checked disabled /><span><strong>Mandatory product approval floor</strong><small>Containment, destructive, and administrator actions cannot lower their approval requirement.</small></span></label></div>}
        {stage === "Limits" && <div className="form-grid"><Field label="Step limit" type="number" min={1} max={productLimits.steps} value={steps} onChange={(event) => setSteps(Math.min(productLimits.steps, Number(event.target.value)))} /><Field label="Runtime seconds" type="number" min={1} max={productLimits.runtimeSeconds} value={runtime} onChange={(event) => setRuntime(Math.min(productLimits.runtimeSeconds, Number(event.target.value)))} /><Field label="Temporary-policy seconds" type="number" min={1} max={productLimits.temporaryPolicySeconds} value={temporaryPolicy} onChange={(event) => setTemporaryPolicy(Math.min(productLimits.temporaryPolicySeconds, Number(event.target.value)))} /><Field label="AI token budget" type="number" min={1} max={productLimits.aiTokens} value={aiTokens} onChange={(event) => setAITokens(Math.min(productLimits.aiTokens, Number(event.target.value)))} /><Field label="Concurrency" type="number" min={1} max={productLimits.concurrency} value={concurrency} onChange={(event) => setConcurrency(Math.min(productLimits.concurrency, Number(event.target.value)))} /></div>}
        {stage === "Verification" && <div className="form-stack"><Select label="Required terminal verification" value={verification} onChange={(event) => setVerification(event.target.value)}><option value="test_run">Test no longer reproduces</option><option value="gateway_decision">Runtime decision blocks activity</option><option value="export">Evidence export completes</option></Select><small>A definition cannot be enabled without a terminal verification criterion compatible with every selected action.</small></div>}
        {stage === "Simulate" && <div className="form-stack"><p>Simulation matches scoped evidence, proposes a plan, and evaluates authorization without action side effects.</p><Button variant="primary" disabled={!agents.length || !verification} onClick={() => void simulate()}>Simulate with selected evidence</Button>{simulation && <div className="review-summary"><div><span>Matched evidence</span><strong>{simulation.matched_evidence_ids.length}</strong></div><div><span>Proposed plan</span><strong>{simulation.summary}</strong></div><div><span>Approval points</span><strong>{simulation.steps.filter((value) => value.approval_required).length}</strong></div><div><span>Side effects</span><strong>{simulation.side_effects}</strong></div>{simulation.steps.map((value) => <div key={value.index}><span>{value.action}</span><strong>authorization: {value.authorization}</strong></div>)}</div>}</div>}
      </section>
      <aside className="wizard-assistant"><div><span className="assistant-orb">S</span><strong>Definition checks</strong></div><div className="assistant-empty"><p>{selectedActions.length} explicit actions</p><p>{steps} steps · {runtime}s runtime</p><p>{autonomy} · verification required</p></div></aside>
    </div>
  </Card>;
}

export function SecurityAgentsView({ api = defaultSecurityAgentsAPI }: { api?: SecurityAgentsAPI }) {
  const [tab, setTab] = useState("agents");
  const [agents, setAgents] = useState<readonly SecurityAgentDefinition[]>([]);
  const [templates, setTemplates] = useState<readonly SecurityAgentTemplate[]>([]);
  const [actions, setActions] = useState<readonly SecurityAction[]>([]);
  const [error, setError] = useState(false);
  useEffect(() => { let active = true; void Promise.all([api.listSecurityAgents(), api.listSecurityAgentTemplates(), api.listSecurityActions()]).then(([page, nextTemplates, nextActions]) => { if (active) { setAgents(page.items); setTemplates(nextTemplates); setActions(nextActions); } }, () => { if (active) setError(true); }); return () => { active = false; }; }, [api]);
  return <div className="page"><PageHeader title="Security agents" description="Bounded automated response definitions, approvals, and verified outcomes." actions={<Button variant="primary" onClick={() => setTab("builder")}>Create Security Agent</Button>} /><Tabs tabs={[{ id: "agents", label: "Security Agents", count: agents.length }, { id: "builder", label: "Builder" }]} active={tab} onChange={setTab} />{error && <div role="alert" className="form-error">Security Agent API unavailable</div>}{tab === "agents" ? <Card><div className="table-scroll"><table className="data-table"><thead><tr><th>Name</th><th>Status</th><th>Trigger</th><th>Scope</th><th>Autonomy</th><th>Last outcome</th><th>Pending approvals</th><th>Owner</th></tr></thead><tbody>{agents.map((agent) => <tr key={agent.id}><td><strong>{agent.name}</strong></td><td><Badge tone={agent.enabled ? "success" : "neutral"}>{agent.enabled ? "Enabled" : "Disabled"}</Badge></td><td>{agent.trigger_kind}</td><td>{agent.environment_ids.join(", ")}</td><td>{agent.autonomy}</td><td>Awaiting first verified run</td><td>0</td><td>Security operations</td></tr>)}</tbody></table></div>{!agents.length && !error && <p>No Security Agents in this authorized scope.</p>}</Card> : <Builder templates={templates} actions={actions} agents={agents} api={api} />}</div>;
}
