"use client";

import { ArrowRight, CalendarDays, CheckCircle2, CircleAlert, Clock3, ShieldCheck, Sparkles, Waypoints } from "lucide-react";
import { useZaspStore } from "../../domain/store";
import { Badge, Button, Card, DonutChart, MetricGrid, PageHeader, ProgressBar, Sparkline } from "../../components/ui";

export function OverviewView({ onNavigate }: { onNavigate: (path: string) => void }) {
  const { state } = useZaspStore();
  const critical = state.violations.filter((item) => item.severity === "critical" && item.status !== "fixed").length;
  const connected = state.connectors.filter((item) => item.status === "connected").length;
  const blocked = state.guardrailEvents.filter((item) => item.decision === "block").length;
  const severity = (["critical", "high", "medium", "low"] as const).map((level) => ({ label: level[0].toUpperCase() + level.slice(1), value: state.violations.filter((item) => item.severity === level).length, color: level === "critical" ? "#c93f25" : level === "high" ? "#dfa096" : level === "medium" ? "#e9c86d" : "#d9dde1" }));
  return <div className="page">
    <PageHeader title="Security overview" description="Your agentic estate, risks, and controls—connected through one security graph." actions={<><Button icon={<CalendarDays size={16} />}>{state.preferences.dateRange}</Button><Button variant="primary" icon={<Sparkles size={16} />} onClick={() => onNavigate("/violations")}>Investigate risk</Button></>} />
    <div className="form-error"><CircleAlert size={16} />Coverage is stale for one connected source; risk totals remain attention-required.</div>
    <div className="posture-hero">
      <div className="posture-score"><div className="score-ring"><span>73</span><small>Good</small></div><div><span className="eyebrow">Agent security posture</span><h2>Control is improving, but 4 paths remain critical.</h2><p>Identity exposure and shadow MCP access account for 82% of current risk.</p><button onClick={() => onNavigate("/violations")}>See prioritized risk <ArrowRight size={15} /></button></div></div>
      <div className="hero-trend"><div><span>30-day posture</span><strong>+6</strong></div><Sparkline values={[51, 55, 54, 59, 61, 63, 62, 67, 69, 73]} color="#8ff0c8" /></div>
    </div>
    <MetricGrid metrics={[
      { label: "Discovered components", value: state.assets.length, note: "6 types across 3 environments", tone: "brand", onClick: () => onNavigate("/discovery/assets") },
      { label: "Critical open findings", value: critical, note: "3 require action today", tone: "danger", onClick: () => onNavigate("/violations") },
      { label: "Protected interactions", value: "99.84%", note: `${blocked} blocked in this sample`, tone: "success", onClick: () => onNavigate("/protect/security-agents") },
      { label: "Connected data sources", value: `${connected}/${state.connectors.length}`, note: "Cloud, models, tools, and SIEM", onClick: () => onNavigate("/connectors") },
    ]} />
    <div className="overview-grid">
      <Card title="Risk trend" className="overview-chart" action={<Button variant="ghost" onClick={() => onNavigate("/violations")}>View findings</Button>}><div className="line-chart"><div className="chart-scale"><span>100</span><span>75</span><span>50</span><span>25</span><span>0</span></div><div className="chart-main"><Sparkline values={[84, 79, 77, 68, 64, 59, 63, 58, 55, 51, 47, 43]} color="#6d28d9" /><div className="axis-labels"><span>Jul 15</span><span>Jul 22</span><span>Jul 29</span><span>Aug 5</span><span>Aug 13</span></div></div></div></Card>
      <Card title="Findings by severity"><DonutChart segments={severity} center={<><strong>{state.violations.length}</strong><small>Total</small></>} /></Card>
      <Card title="Top risk paths" className="top-risk-card"><div className="risk-list">{[
        ["Release Agent → AWS Production", "Admin credential at runtime", "critical", 92],
        ["devtools MCP → Secrets broker", "Shared identity across services", "critical", 88],
        ["People Ops → Slack workspace", "Token outside network boundary", "high", 76],
        ["Code Review → GitHub org", "Repository admin scope", "high", 71],
      ].map(([name, issue, tone, score]) => <button key={String(name)} onClick={() => onNavigate("/violations")}><span className="risk-icon"><Waypoints size={17} /></span><span><strong>{name}</strong><small>{issue}</small></span><Badge tone={tone as "critical" | "high"}>{score}</Badge><ArrowRight size={15} /></button>)}</div></Card>
      <Card title="Control coverage"><div className="coverage-list">{[["Identity governance", 68], ["Runtime guardrails", 84], ["Red team coverage", 61], ["Data source coverage", 73]].map(([label, value]) => <button key={String(label)} onClick={() => onNavigate(label === "Identity governance" ? "/policies" : label === "Runtime guardrails" ? "/protect/security-agents" : label === "Red team coverage" ? "/red-team/results" : "/connectors")}><span><strong>{label}</strong><em>{value}%</em></span><ProgressBar value={Number(value)} /></button>)}</div></Card>
      <Card title="Recommended actions" className="recommendations"><div className="action-list">{[
        { icon: <CircleAlert />, title: "Rotate the AWS production agent key", note: "Critical · affects Release Agent", path: "/identities" },
        { icon: <ShieldCheck />, title: "Enforce the secure code guardrail", note: "7 components remain in review mode", path: "/policies" },
        { icon: <CheckCircle2 />, title: "Review 3 completed remediations", note: "Confirm controls before closing", path: "/violations" },
      ].map((action) => <button key={action.title} onClick={() => onNavigate(action.path)}><span>{action.icon}</span><span><strong>{action.title}</strong><small>{action.note}</small></span><ArrowRight size={15} /></button>)}</div></Card>
      <Card title="Recent changes"><div className="change-feed">{state.changes.slice(0, 4).map((change) => <button key={change.id} onClick={() => onNavigate("/discovery/assets")}><Clock3 size={15} /><span><strong>{change.description}</strong><small>{change.time}</small></span><Badge tone={change.risk}>{change.risk}</Badge></button>)}</div></Card>
    </div>
  </div>;
}
