"use client";

import { useState } from "react";
import { Badge, Button, Card, PageHeader } from "../../components/ui";

type Surface = "sessions" | "compliance" | "data-controls";

export function SessionsComplianceView({ surface }: { surface: Surface }) {
  const [exported, setExported] = useState(false);
  if (surface === "sessions") return <div className="page"><PageHeader title="Session investigations" description="Ordered metadata-only activity with explicit evidence confidence." /><Card title="Structured filters"><div className="button-row">{["Agent","Principal","Tool","Process","File","Domain","Credential","Resource","Decision"].map((value)=><Badge key={value} tone="neutral">{value}</Badge>)}</div></Card><Card title="session-1"><p>Shell requested · <Badge tone="success">Exact</Badge> · <span>evidence-1</span></p><p>Policy evaluated · <Badge tone="info">Strong</Badge></p><p>Network attributed · <Badge tone="warning">Probable</Badge></p><p>Unresolved actor · <Badge tone="neutral">Unattributed</Badge></p></Card></div>;
  if (surface === "compliance") return <div className="page"><PageHeader title="Compliance evidence" description="Evidence freshness and source attribution without attestation claims." /><div className="dashboard-grid"><Card title="SOC 2 Security"><p><Badge tone="success">Fresh</Badge></p><p><span>asset-1</span> · <span>runtime</span> · <span>evidence-1</span></p></Card><Card title="HIPAA safeguard"><p><Badge tone="warning">Stale</Badge></p><p>Missing evidence</p></Card></div><Button onClick={()=>setExported(true)}>Export evidence</Button>{exported&&<p>Export completed</p>}</div>;
  return <div className="page"><PageHeader title="Data and retention" description="Environment-scoped collection, retention, and deletion controls." /><Card title="Production defaults"><p><Badge tone="info">Metadata only</Badge></p><p>30 days</p><p>Deletion enabled</p><p>Regulated profiles require review</p></Card></div>;
}
