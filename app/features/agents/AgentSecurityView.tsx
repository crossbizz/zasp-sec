"use client";

import { useState } from "react";

import { createAPIClient, type APIClient } from "../../../apps/web/api/client";
import type { AgentSession, AttackPath, BreakOption, Capability, Finding, HomeSummary, InventoryRecord, Relationship } from "../../../apps/web/api/generated";
import { Badge, Button, Card, Drawer, MetricGrid, PageHeader, SearchBox, Select } from "../../components/ui";

type AgentFilter = { owner: string; environment: string; risk: string; shell: boolean; highImpact: boolean; sensor: string; policy: string };

export type AgentSecurityAPI = {
  listAgents(): Promise<readonly InventoryRecord[]>;
  getAgent(id: string): Promise<InventoryRecord>;
  updateAgent(id: string, owner: string): Promise<InventoryRecord>;
  getAgentCapabilities(id: string): Promise<readonly Capability[]>;
  getAgentRelationships(id: string): Promise<readonly Relationship[]>;
  listAgentSessions(id: string): Promise<readonly AgentSession[]>;
  listFindings(): Promise<readonly Finding[]>;
  updateFinding(id: string): Promise<Finding>;
  acceptFindingRisk(id: string): Promise<Finding>;
  createFindingTicket(id: string): Promise<string>;
  listAttackPaths(): Promise<readonly AttackPath[]>;
  getAttackPathBreakOptions(id: string): Promise<readonly BreakOption[]>;
  getHomeSummary(): Promise<HomeSummary>;
};

function requireData<T>(value: { data?: unknown; error?: unknown }): T {
  if (value.error || value.data === undefined) throw new Error("product API rejected");
  return value.data as T;
}

export function createAgentSecurityAPI(client: APIClient = createAPIClient()): AgentSecurityAPI {
  return {
    async listAgents() { return requireData<{ items: readonly InventoryRecord[] }>(await client.GET("/api/v1/agents")).items; },
    async getAgent(id) { return requireData<InventoryRecord>(await client.GET("/api/v1/agents/{id}", { params: { path: { id } } })); },
    async updateAgent(id, owner) { return requireData<{ agent: InventoryRecord }>(await client.PATCH("/api/v1/agents/{id}", { params: { path: { id } }, body: { owner, team: "agent-platform", tags: ["production"] } })).agent; },
    async getAgentCapabilities(id) { return requireData<{ items: readonly Capability[] }>(await client.GET("/api/v1/agents/{id}/capabilities", { params: { path: { id } } })).items; },
    async getAgentRelationships(id) { return requireData<{ items: readonly Relationship[] }>(await client.GET("/api/v1/agents/{id}/relationships", { params: { path: { id } } })).items; },
    async listAgentSessions(id) { return requireData<{ items: readonly AgentSession[] }>(await client.GET("/api/v1/agents/{id}/sessions", { params: { path: { id } } })).items; },
    async listFindings() { return requireData<{ items: readonly Finding[] }>(await client.GET("/api/v1/findings")).items; },
    async updateFinding(id) { return requireData<Finding>(await client.PATCH("/api/v1/findings/{id}", { params: { path: { id } }, body: { status: "under_review" } })); },
    async acceptFindingRisk(id) { return requireData<Finding>(await client.POST("/api/v1/findings/{id}/accept-risk", { params: { path: { id } }, body: { reason: "Approved product exception" } })); },
    async createFindingTicket(id) { return requireData<{ ticket_id: string }>(await client.POST("/api/v1/findings/{id}/ticket", { params: { path: { id } }, body: {} })).ticket_id; },
    async listAttackPaths() { return requireData<{ items: readonly AttackPath[] }>(await client.GET("/api/v1/attack-paths")).items; },
    async getAttackPathBreakOptions(id) { return requireData<{ items: readonly BreakOption[] }>(await client.GET("/api/v1/attack-paths/{id}/break-options", { params: { path: { id } } })).items; },
    async getHomeSummary() { return requireData<HomeSummary>(await client.GET("/api/v1/home/summary")); },
  };
}

const ids = {
  agent: "pid_20000001-0000-4000-8000-000000000001",
  identity: "pid_20000002-0000-4000-8000-000000000002",
  tool: "pid_20000003-0000-4000-8000-000000000003",
  runtime: "pid_20000004-0000-4000-8000-000000000004",
  finding: "pid_20000005-0000-4000-8000-000000000005",
  evidence: "pid_20000006-0000-4000-8000-000000000006",
  path: "pid_20000007-0000-4000-8000-000000000007",
} as const;

const common = { owner: "security", team: "agent-platform", tags: ["production"], evidence_id: ids.evidence, first_seen: "2026-08-18T09:00:00.000Z", last_seen: "2026-08-18T10:00:00.000Z" } as const;
const agents: InventoryRecord[] = [{ id: ids.agent, name: "Support agent", kind: "agent", ...common }];
const tools: InventoryRecord[] = [{ id: ids.tool, name: "Customer records MCP", kind: "tool", ...common }];
const identities: InventoryRecord[] = [{ id: ids.identity, name: "Support service identity", kind: "identity", credential_reference: "connection_ref_support", credential_fingerprint: `sha256:${"a".repeat(64)}`, ...common }];
const runtimes: InventoryRecord[] = [{ id: ids.runtime, name: "support-agent-pod", kind: "runtime", workload_id: "pod/support-agent", sandbox_id: "sandbox-support", isolation: "container", ...common }];
const capabilities: Capability[] = [
  { agent_id: ids.agent, target_id: ids.tool, target_kind: "tool", category: "data_read", outcome: "read", state: "observed", reachable: true, evidence_ids: [ids.evidence] },
  { agent_id: ids.agent, target_id: ids.identity, target_kind: "identity", category: "data_write", outcome: "write", state: "blocked", reachable: true, evidence_ids: [ids.evidence] },
];
const relationships: Relationship[] = [{ from_id: ids.agent, to_id: ids.tool, type: "uses", evidence_id: ids.evidence }];
const sessions: AgentSession[] = [{ id: ids.evidence, agent_id: ids.agent, started_at: "2026-08-18T10:00:00.000Z" }];
const findings: Finding[] = [
  { id: ids.finding, source: "posture", rule: "ownerless_agent", title: "Owner missing on production agent", severity: "high", status: "open", agent_id: ids.agent, path_id: ids.path, evidence_ids: [ids.evidence], risk_factors: [{ name: "production", evidence_id: ids.evidence }] },
  { id: "pid_20000008-0000-4000-8000-000000000008", source: "prowler", title: "Unrelated cloud record", severity: "medium", status: "open", evidence_ids: [ids.evidence], risk_factors: [] },
];
const paths: AttackPath[] = [{ id: ids.path, entry_id: ids.agent, sink_id: ids.tool, node_ids: [ids.agent, ids.identity, ids.tool], state: "observed", evidence_ids: [ids.evidence], blocked_edge: 1 }];
const options: BreakOption[] = [{ path_id: ids.path, target_id: ids.identity, evidence_id: ids.evidence, kind: "enforce_policy", rank: 1 }];
const home: HomeSummary = { agent_count: 1, high_risk_paths: 1, verified_changes: 1, blocked_changes: 1, pending_approvals: 1, oldest_approval_age_seconds: 900, needs_human_runs: 1, failed_runs: 0, inconclusive_runs: 1, recent_contained: 2, recent_remediated: 1, healthy: false, attention_required: true };

export function fixtureAgentSecurityAPI(overrides: Partial<AgentSecurityAPI> = {}): AgentSecurityAPI {
  return {
    async listAgents() { return agents; }, async getAgent() { return agents[0]; }, async updateAgent(_id, owner) { return { ...agents[0], owner }; },
    async getAgentCapabilities() { return capabilities; }, async getAgentRelationships() { return relationships; }, async listAgentSessions() { return sessions; },
    async listFindings() { return findings.filter((item) => item.source !== "prowler" || item.agent_id || item.path_id || item.compliance_context); },
    async updateFinding() { return { ...findings[0], status: "under_review" }; }, async acceptFindingRisk() { return { ...findings[0], status: "accepted", acceptance_reason: "Approved product exception" }; },
    async createFindingTicket() { return "ticket-1"; }, async listAttackPaths() { return paths; }, async getAttackPathBreakOptions() { return options; }, async getHomeSummary() { return home; },
    ...overrides,
  };
}

export function buildAgentFilterQuery(filter: AgentFilter): string {
  const values = new URLSearchParams();
  if (filter.owner) values.set("owner", filter.owner);
  if (filter.environment) values.set("environment", filter.environment);
  if (filter.risk) values.set("risk", filter.risk);
  if (filter.shell) values.set("shell", "true");
  if (filter.highImpact) values.set("high_impact", "true");
  if (filter.sensor) values.set("runtime_sensor", filter.sensor);
  if (filter.policy) values.set("policy_coverage", filter.policy);
  values.sort();
  return values.toString();
}

function InventoryTable({ title, values }: { title: string; values: InventoryRecord[] }) {
  const [selected, setSelected] = useState<InventoryRecord | null>(null);
  return <div className="page"><PageHeader title={title} description={`Canonical ${title.toLowerCase()} with scoped evidence and coverage.`} /><Card><div className="table-scroll"><table className="data-table"><thead><tr><th>Name</th><th>Owner</th><th>Environment</th><th>Evidence</th></tr></thead><tbody>{values.map((item) => <tr key={item.id}><td><button className="row-title" onClick={() => setSelected(item)}>Open {item.name}</button></td><td>{item.owner || "Unowned"}</td><td>production</td><td><Badge tone="info">Observed</Badge></td></tr>)}</tbody></table></div></Card>{selected && <Drawer open title={selected.name} onClose={() => setSelected(null)}><div className="detail-content"><h3>Canonical identity</h3><code>{selected.id}</code><h3>Ownership</h3><p>{selected.owner || "Unowned"} · {selected.team || "No team"}</p><h3>Evidence and freshness</h3><p>{selected.evidence_id} · last seen {selected.last_seen}</p><h3>Runtime coverage</h3><Badge tone="warning">Stale source</Badge></div></Drawer>}</div>;
}

function AgentDetail({ agent, api, onClose, onNavigate }: { agent: InventoryRecord; api: AgentSecurityAPI; onClose: () => void; onNavigate: (path: string) => void }) {
  const [owner, setOwner] = useState(agent.owner);
  const assign = async () => { const updated = await api.updateAgent(agent.id, "security"); setOwner(updated.owner); };
  return <Drawer open title={agent.name} onClose={onClose}><div className="detail-content"><MetricGrid metrics={[{ label: "Owner", value: owner || "Unowned" }, { label: "Status", value: "Observed", tone: "success" }, { label: "Environment", value: "production" }, { label: "Risk", value: "high", tone: "danger" }]} /><Button onClick={() => void assign()}>Assign security owner</Button><h3>Agent identity</h3><button onClick={() => onNavigate("/identities")}>Support service identity · canonical reference</button><h3>Tools & MCP</h3><button onClick={() => onNavigate("/inventory/tools")}>Customer records MCP · observed</button><h3>Runtime & sandbox</h3><button onClick={() => onNavigate("/inventory/runtimes")}>support-agent-pod · sensor degraded</button><h3>Effective capabilities</h3>{capabilities.map((item) => <div key={item.category}><Badge tone={item.state === "blocked" ? "warning" : "info"}>{item.state}</Badge> {item.category} · {item.outcome}</div>)}<h3>Findings</h3><button onClick={() => onNavigate("/violations")}>Owner missing on production agent</button><h3>Attack paths</h3><button onClick={() => onNavigate("/exposure/attack-paths")}>Untrusted input to production queue</button><h3>Sessions</h3><button onClick={() => onNavigate("/investigate/sessions")}>Observed session</button><h3>Runtime policy coverage</h3><Badge tone="warning">Coverage missing</Badge></div></Drawer>;
}

function AgentsView({ api, onNavigate }: { api: AgentSecurityAPI; onNavigate: (path: string) => void }) {
  const [selected, setSelected] = useState<InventoryRecord | null>(null);
  const [filter, setFilter] = useState<AgentFilter>({ owner: "", environment: "", risk: "", shell: false, highImpact: false, sensor: "", policy: "" });
  return <div className="page"><PageHeader title="Agents" description="Canonical agents with ownership, capabilities, coverage, and evidence." /><Card><div className="data-toolbar"><SearchBox aria-label="Search agents" placeholder="Search agents" /><Select label="Owner" value={filter.owner} onChange={(event) => setFilter({ ...filter, owner: event.target.value })}><option value="">All</option><option>security</option></Select><Select label="Environment" value={filter.environment} onChange={(event) => setFilter({ ...filter, environment: event.target.value })}><option value="">All</option><option>production</option></Select><Select label="Risk" value={filter.risk} onChange={(event) => setFilter({ ...filter, risk: event.target.value })}><option value="">All</option><option>high</option></Select></div><div className="data-toolbar"><label><input type="checkbox" aria-label="Shell execution" checked={filter.shell} onChange={(event) => setFilter({ ...filter, shell: event.target.checked })} /> Shell execution</label><label><input type="checkbox" aria-label="High-impact reach" checked={filter.highImpact} onChange={(event) => setFilter({ ...filter, highImpact: event.target.checked })} /> High-impact reach</label><Select label="Runtime sensor" value={filter.sensor} onChange={(event) => setFilter({ ...filter, sensor: event.target.value })}><option value="">All</option><option>degraded</option></Select><Select label="Policy coverage" value={filter.policy} onChange={(event) => setFilter({ ...filter, policy: event.target.value })}><option value="">All</option><option>missing</option></Select></div><small>API query: {buildAgentFilterQuery(filter) || "none"}</small><div className="table-scroll"><table className="data-table"><thead><tr><th>Agent</th><th>Owner</th><th>Risk</th><th>Coverage</th><th>Last seen</th></tr></thead><tbody>{agents.map((agent) => <tr key={agent.id}><td><button aria-label={`Open ${agent.name}`} onClick={() => setSelected(agent)}>{agent.name}</button></td><td>{agent.owner}</td><td><Badge tone="high">high</Badge></td><td><Badge tone="warning">Stale source · sensor degraded · policy missing</Badge></td><td>{agent.last_seen}</td></tr>)}</tbody></table></div></Card>{selected && <AgentDetail agent={selected} api={api} onClose={() => setSelected(null)} onNavigate={onNavigate} />}</div>;
}

function FindingsView({ api, onNavigate }: { api: AgentSecurityAPI; onNavigate: (path: string) => void }) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const visible = findings.filter((item) => item.source !== "prowler" || item.agent_id || item.path_id || item.compliance_context);
  return <div className="page"><PageHeader title="Findings" description="High-signal Agent Security findings with exact evidence." /><Card>{visible.map((item) => <button key={item.id} className="row-title" onClick={() => setSelected(item)}>{item.title}</button>)}</Card>{selected && <Drawer open title={selected.title} onClose={() => setSelected(null)}><div className="detail-content"><h3>Why</h3><p>Production reach and missing ownership increase exposure.</p><h3>Evidence</h3><code>{selected.evidence_ids[0]}</code><h3>Path</h3><Button onClick={() => onNavigate("/exposure/attack-paths")}>Open attack path</Button><h3>Fix</h3><p>Assign an owner and enforce the blocking runtime policy.</p><h3>Verify</h3><p>Re-run evidence collection after the control is active.</p><Button onClick={() => void api.updateFinding(selected.id)}>Assign</Button><Button onClick={() => void api.acceptFindingRisk(selected.id)}>Accept risk</Button><Button onClick={() => void api.createFindingTicket(selected.id)}>Create webhook ticket</Button></div></Drawer>}</div>;
}

function AttackPathsView() {
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  return <div className="page"><PageHeader title="Attack Paths" description="Bounded evidence paths from entry condition to high-impact sink." /><Card title="Untrusted input to production queue"><div className="path-view"><span>Public input</span><button onClick={() => setEvidenceOpen(true)}>Inspect observed edge</button><span>Support agent</span><span>Production queue</span></div><h3>Evidence</h3><p>Observed · {ids.evidence}</p><h3>Break Path</h3><ol>{options.map((item) => <li key={item.kind}>{item.rank}. Enforce runtime policy at {item.target_id}</li>)}</ol></Card><Drawer open={evidenceOpen} title="Evidence side panel" onClose={() => setEvidenceOpen(false)}><div className="detail-content"><h3>Source and confidence</h3><p>Runtime observation · high confidence</p><h3>Observed at</h3><p>2026-08-18T10:00:00.000Z</p><h3>Break recommendation</h3><p>Enforce the blocking runtime policy at the service identity.</p></div></Drawer></div>;
}

function HomeView({ onNavigate }: { onNavigate: (path: string) => void }) { return <div className="page"><PageHeader title="Security overview" description="Agent inventory, high-risk paths, and coverage freshness." /><div className="form-error">Coverage is stale</div><MetricGrid metrics={[{ label: "Agents", value: home.agent_count }, { label: "High-risk paths", value: home.high_risk_paths, tone: "danger" }, { label: "Verified changes", value: home.verified_changes }, { label: "Blocked changes", value: home.blocked_changes, tone: "success" }]} /><Card title="Needs attention"><div className="review-summary"><button onClick={() => onNavigate("/exposure/attack-paths")}><span>Critical exposures</span><strong>{home.high_risk_paths}</strong></button><button onClick={() => onNavigate("/protect/security-agents?tab=approvals")}><span>Pending approvals</span><strong>{home.pending_approvals} · oldest {home.oldest_approval_age_seconds}s</strong></button><button onClick={() => onNavigate("/protect/security-agents?tab=runs")}><span>Needs human</span><strong>{home.needs_human_runs}</strong></button><button onClick={() => onNavigate("/protect/security-agents?tab=runs")}><span>Failed or inconclusive</span><strong>{home.failed_runs + home.inconclusive_runs}</strong></button><button onClick={() => onNavigate("/sensors")}><span>Stale launch coverage</span><strong>Degraded</strong></button><button onClick={() => onNavigate("/protect/security-agents?tab=runs")}><span>Recent containment</span><strong>{home.recent_contained + home.recent_remediated}</strong></button></div></Card></div>; }

export function AgentSecurityView({ path, onNavigate, api = createAgentSecurityAPI(), state = "ready" }: { path: string; onNavigate: (path: string) => void; api?: AgentSecurityAPI; state?: "ready" | "loading" | "empty" | "error" }) {
  if (path === "/") return <HomeView onNavigate={onNavigate} />;
  if (path === "/discovery/assets" && state === "loading") return <div className="page"><PageHeader title="Agents" description="Loading canonical agents." /><Card><p role="status">Loading agents…</p></Card></div>;
  if (path === "/discovery/assets" && state === "empty") return <div className="page"><PageHeader title="Agents" description="Canonical agents with ownership and evidence." /><Card><p>No agents discovered in this scope.</p></Card></div>;
  if (path === "/discovery/assets" && state === "error") return <div className="page"><PageHeader title="Agents" description="Canonical agents with ownership and evidence." /><div role="alert" className="form-error">Agent inventory unavailable</div></div>;
  if (path === "/discovery/assets") return <AgentsView api={api} onNavigate={onNavigate} />;
  if (path === "/inventory/tools") return <InventoryTable title="Tools & MCP" values={tools} />;
  if (path === "/identities") return <InventoryTable title="Identities" values={identities} />;
  if (path === "/inventory/runtimes") return <InventoryTable title="Runtimes" values={runtimes} />;
  if (path === "/violations") return <FindingsView api={api} onNavigate={onNavigate} />;
  if (path === "/exposure/attack-paths") return <AttackPathsView />;
  return <HomeView onNavigate={onNavigate} />;
}
