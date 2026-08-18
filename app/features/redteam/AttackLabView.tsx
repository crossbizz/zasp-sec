"use client";

import { useState } from "react";

import { Badge, Button, Card, PageHeader } from "../../components/ui";

type LabVerdict = "Verified" | "Inconclusive" | "Not Reproduced";

export function AttackLabView() {
  const [approved, setApproved] = useState(false);
  const [running, setRunning] = useState(false);
  const [verdict, setVerdict] = useState<LabVerdict>("Verified");
  return <div className="page">
    <PageHeader title="Attack lab" description="Verify one controlled path with test-only targets, credentials, destinations, and canary evidence." />
    <div className="dashboard-grid">
      <Card title="Target and credentials"><p><strong>test-canary</strong></p><p>Environment: test</p><p>Credential class: <code>test_write</code></p></Card>
      <Card title="Network and side effects"><p>Allowed destination: <strong>canary.internal</strong></p><p>Expected side effect: canary touched</p><p className="form-error">Undeclared destinations are rejected before sandbox creation.</p></Card>
      <Card title="Runtime limits and cleanup"><p>Resources: <strong>500m / 1Gi / 2Gi</strong></p><p>Timeout: <strong>300 seconds</strong></p><p>Cleanup: <strong>Destroy after evidence</strong></p></Card>
    </div>
    <Card title="Safety decision"><label><input type="checkbox" aria-label="Approve safety decision" checked={approved} onChange={(event) => setApproved(event.target.checked)} /> Approve the bounded test-only decision</label><Button variant="primary" disabled={!approved} onClick={() => setRunning(true)}>Run Attack Lab</Button></Card>
    {running && <Card title="Attack Lab result"><h3>Verdict</h3><Badge tone={verdict === "Verified" ? "success" : verdict === "Inconclusive" ? "warning" : "info"}>{verdict}</Badge><h3>Timeline</h3><p>Preflight → sandbox → canary → evidence → cleanup</p><h3>Canary</h3><p>Exact test resource touched.</p><h3>Network</h3><p>Only canary.internal was authorized.</p><h3>Evidence</h3><p>Semantic, gateway, egress, Kubernetes, and cloud side-effect references retained.</p><div className="button-row"><Button onClick={() => setVerdict("Inconclusive")}>Show infrastructure failure</Button><Button onClick={() => setVerdict("Not Reproduced")}>Show clean non-reproduction</Button><Button onClick={() => setVerdict("Verified")}>Re-run verified fixture</Button></div></Card>}
  </div>;
}
