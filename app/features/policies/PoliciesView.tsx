"use client";

import { useState } from "react";

import { Badge, Button, Card, PageHeader } from "../../components/ui";

type Rollout = "Draft" | "Monitor" | "Enforce" | "Disabled";

export function PoliciesView({ embedded = false }: { embedded?: boolean }) {
  const [rollout, setRollout] = useState<Rollout>("Draft");
  const [simulated, setSimulated] = useState(false);
  return <div className="page">
    {!embedded && <PageHeader title="Policies" description="Create, simulate, roll out, and inspect supported runtime controls." />}
    <div className="dashboard-grid">
      <Card title="Policy coverage"><p>Agents covered: <strong>4 of 5</strong></p><p>Runtime bundles: <Badge tone="warning">Bundle stale</Badge></p></Card>
      <Card title="Policy status"><p><Badge tone="info">Monitor</Badge> Observe matching actions</p><p><Badge tone="success">Enforce</Badge> Block matching actions</p><p><Badge tone="neutral">Disabled</Badge> Retain history only</p></Card>
    </div>
    <Card title="Create policy">
      <ol><li>Scope</li><li>Trigger</li><li>Conditions</li><li>Action</li><li>Coverage</li><li>Simulate</li><li>Rollout</li></ol>
      <p>Supported action: Monitor or Block. Unsupported controls cannot be selected.</p>
      <Button onClick={() => setSimulated(true)}>Simulate policy</Button>
      {simulated && <p>Matches: 2 · Would block: 1</p>}
    </Card>
    <Card title="Policy detail">
      <p>Current rollout: {rollout}</p>
      <p>Decision evidence: {rollout === "Enforce" ? "block" : rollout === "Monitor" ? "monitor" : "none"}</p>
      <div className="button-row"><Button onClick={() => setRollout("Monitor")}>Roll to Monitor</Button><Button variant="primary" onClick={() => setRollout("Enforce")}>Enforce policy</Button><Button onClick={() => setRollout("Disabled")}>Disable policy</Button></div>
    </Card>
  </div>;
}
