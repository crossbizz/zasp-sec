"use client";

import { useCallback, useMemo, useState } from "react";

import type { ConnectorManifest, Integration, Policy, PolicySimulation } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { useSession } from "../../auth/SessionProvider";
import { Badge, Button, Card, EmptyState, Field, LoadingState, Modal, PageHeader } from "../../components/ui";
import { createIntegrationsAPI, createPoliciesAPI, type Versioned } from "./api";

type Feedback = { tone: "status" | "alert"; message: string } | null;

function QueryBoundary({ status, label, onRetry }: { status: string; label: string; onRetry(): Promise<void> }) {
  if (status === "loading" || status === "idle") return <LoadingState label={`Loading ${label}…`} />;
  if (status === "forbidden") return <p role="alert">You are not authorized to view {label}.</p>;
  if (status === "error") return <p role="alert">{label} are unavailable. <Button onClick={() => void onRetry()}>Retry</Button></p>;
  if (status === "stale") return <p role="status">Showing the last confirmed {label}. <Button onClick={() => void onRetry()}>Refresh</Button></p>;
  return null;
}

function FeedbackLine({ value }: { value: Feedback }) {
  return value ? <p role={value.tone}>{value.message}</p> : null;
}

export function ProductionPoliciesView({ canWrite }: { canWrite: boolean }) {
  const { client, invalidate } = useAPI();
  const session = useSession();
  const api = useMemo(() => createPoliciesAPI(client), [client]);
  const query = useAPIQuery("workflow:policies", api.listPolicies);
  const [selected, setSelected] = useState<Versioned<Policy> | null>(null);
  const [policyID, setPolicyID] = useState("policy-production");
  const [name, setName] = useState("Production runtime policy");
  const [editName, setEditName] = useState("");
  const [simulation, setSimulation] = useState<PolicySimulation | null>(null);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [busy, setBusy] = useState(false);
  const selectedID = selected?.value.id ?? "";
  const loadDecisions = useCallback((signal?: AbortSignal) => selectedID ? api.listPolicyDecisions(selectedID, signal) : Promise.resolve([]), [api, selectedID]);
  const decisions = useAPIQuery(`workflow:policy-decisions:${selectedID || "none"}`, loadDecisions, selectedID !== "");

  const run = async (action: () => Promise<void>) => {
    setBusy(true); setFeedback(null);
    try { await action(); } catch { setFeedback({ tone: "alert", message: "The policy operation was not applied. Refresh the current version and retry." }); } finally { setBusy(false); }
  };
  const open = (id: string) => void run(async () => { const current = await api.getPolicy(id); setSelected(current); setEditName(current.value.name); setSimulation(null); });
  const create = () => void run(async () => {
    const receipt = await api.createPolicy({ id: policyID, name, scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" });
    setSelected(receipt); setEditName(receipt.value.name); invalidate(["workflow:policies"]); setFeedback({ tone: "status", message: `Policy created. Audit ${receipt.auditID}` });
  });
  const update = () => selected && void run(async () => {
    const receipt = await api.updatePolicy(selected.value.id, selected.version, { ...selected.value, name: editName });
    setSelected(receipt); invalidate(["workflow:policies"]); setFeedback({ tone: "status", message: `Policy updated. Audit ${receipt.auditID}` });
  });
  const simulate = () => selected && session.status === "authenticated" && void run(async () => {
    const receipt = await api.simulatePolicy(selected.value.id, selected.version, { events: [{ action: "write", agent_id: session.principal.id, environment_id: session.environmentID, metadata: {}, principal_id: session.principal.id, resource: "scoped-resource", session_id: session.principal.id }] });
    setSimulation(receipt.value); invalidate([`workflow:policy-decisions:${selected.value.id}`]); setFeedback({ tone: "status", message: `Simulation recorded. Audit ${receipt.auditID}` });
  });
  const rollout = (state: "monitor" | "enforced") => selected && session.status === "authenticated" && void run(async () => {
    const receipt = await api.rolloutPolicy(selected.value.id, selected.version, { state, target_id: session.environmentID });
    setSelected({ value: { ...selected.value, rollout: state }, version: receipt.version }); invalidate(["workflow:policies"]); setFeedback({ tone: "status", message: `Policy is ${state}. Audit ${receipt.auditID}` });
  });
  const disable = () => selected && void run(async () => {
    const receipt = await api.disablePolicy(selected.value.id, selected.version);
    setSelected({ value: { ...selected.value, rollout: "disabled" }, version: receipt.version }); invalidate(["workflow:policies"]); setFeedback({ tone: "status", message: `Policy disabled. Audit ${receipt.auditID}` });
  });

  return <div className="page"><PageHeader title="Policies" description="Durable scoped runtime controls with simulation, version checks, and audit receipts." />
    <FeedbackLine value={feedback} /><QueryBoundary status={query.status} label="policies" onRetry={query.retry} />
    {canWrite && <Card title="Create policy"><div className="form-grid"><Field label="Policy ID" value={policyID} pattern="policy-[a-z0-9-]+" onChange={(event) => setPolicyID(event.target.value)} /><Field label="Name" value={name} maxLength={128} onChange={(event) => setName(event.target.value)} /></div><Button variant="primary" disabled={busy || !policyID || !name} onClick={create}>Create policy</Button></Card>}
    <Card title="Authorized policies">{query.data?.length ? <div className="connection-list">{query.data.map((policy) => <button type="button" key={policy.id} onClick={() => open(policy.id)} aria-label={`Open ${policy.name}`}><strong>{policy.name}</strong><span>{policy.action}</span><span>{policy.rollout}</span></button>)}</div> : query.status === "empty" ? <EmptyState title="No policies" description="Create the first scoped runtime policy when write access is enabled." /> : null}</Card>
    {selected && <Card title={`Policy detail · ${selected.value.id}`}><p><Badge tone="info">{selected.value.rollout}</Badge> Version {selected.version}</p><Field label="Policy name" value={editName} disabled={!canWrite || busy} onChange={(event) => setEditName(event.target.value)} /><p>{selected.value.conditions.map((condition) => `${condition.field} ${condition.operator} ${condition.value}`).join(", ")}</p>{canWrite && <div className="button-row"><Button disabled={busy} onClick={update}>Save changes</Button><Button disabled={busy} onClick={simulate}>Simulate policy</Button>{selected.value.rollout === "draft" && <Button disabled={busy} onClick={() => rollout("monitor")}>Roll to monitor</Button>}{selected.value.rollout === "monitor" && <Button variant="primary" disabled={busy} onClick={() => rollout("enforced")}>Enforce policy</Button>}{(selected.value.rollout === "monitor" || selected.value.rollout === "enforced") && <Button disabled={busy} onClick={disable}>Disable policy</Button>}</div>}{simulation && <p role="status">Matches: {simulation.matches} · Would block: {simulation.would_block}</p>}<h3>Decision history</h3><QueryBoundary status={decisions.status} label="policy decisions" onRetry={decisions.retry} />{decisions.data?.map((decision) => <p key={decision.id}><Badge tone={decision.result === "block" ? "warning" : "info"}>{decision.result}</Badge> {new Date(decision.at).toLocaleString()} · correlation {decision.correlation_id}</p>)}{decisions.status === "empty" && <p>No durable decisions recorded.</p>}</Card>}
  </div>;
}

export function ProductionIntegrationsView({ canWrite }: { canWrite: boolean }) {
  const { client, invalidate } = useAPI();
  const api = useMemo(() => createIntegrationsAPI(client), [client]);
  const catalog = useAPIQuery("workflow:integration-catalog", api.listCatalog);
  const integrations = useAPIQuery("workflow:integrations", api.listIntegrations);
  const [manifest, setManifest] = useState<ConnectorManifest | null>(null);
  const [configuration, setConfiguration] = useState<Record<string, string>>({});
  const [name, setName] = useState("");
  const [selected, setSelected] = useState<Versioned<Integration> | null>(null);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [busy, setBusy] = useState(false);
  const run = async (action: () => Promise<void>) => { setBusy(true); setFeedback(null); try { await action(); } catch { setFeedback({ tone: "alert", message: "The integration operation was not applied. Refresh and retry." }); } finally { setBusy(false); } };
  const choose = (value: ConnectorManifest) => { setManifest(value); setName(value.provider); setConfiguration(Object.fromEntries(value.setup_schema.map((field) => [field.key, ""]))); };
  const create = () => manifest && void run(async () => { const receipt = await api.createIntegration({ connector_key: manifest.key, name, configuration }); setManifest(null); setSelected(receipt); invalidate(["workflow:integrations"]); setFeedback({ tone: "status", message: `Integration saved. Audit ${receipt.auditID}. Provider authorization controls remain unavailable until a real adapter is configured.` }); });
  const open = (id: string) => void run(async () => { const value = await api.getIntegration(id); setSelected(value); setName(value.value.name); setConfiguration({ ...value.value.configuration }); });
  const update = () => selected && void run(async () => { const receipt = await api.updateIntegration(selected.value.id, selected.version, { name, configuration }); setSelected(receipt); invalidate(["workflow:integrations"]); setFeedback({ tone: "status", message: `Integration updated. Audit ${receipt.auditID}` }); });
  const remove = () => selected && void run(async () => { const receipt = await api.deleteIntegration(selected.value.id, selected.version); setSelected(null); invalidate(["workflow:integrations"]); setFeedback({ tone: "status", message: `Integration deleted. Audit ${receipt.auditID}` }); });
  return <div className="page"><PageHeader title="Integrations" description="Durable local connector configuration. Provider authorization and sync controls appear only when a real adapter exists." /><FeedbackLine value={feedback} />
    <QueryBoundary status={integrations.status} label="integrations" onRetry={integrations.retry} /><Card title="Configured integrations">{integrations.data?.length ? <div className="connection-list">{integrations.data.map((value) => <button type="button" key={value.id} aria-label={`Open ${value.name}`} onClick={() => open(value.id)}><strong>{value.name}</strong><span>{value.connector_key}</span><span>{value.status}</span></button>)}</div> : integrations.status === "empty" ? <EmptyState title="No integrations" description="Choose a supported connector catalog entry to save its scoped configuration." /> : null}</Card>
    <QueryBoundary status={catalog.status} label="integration catalog" onRetry={catalog.retry} />{canWrite && <Card title="Connector catalog"><div className="connector-grid">{catalog.data?.map((value) => <article key={value.key} className="connector-card"><h3>{value.provider}</h3><p>{value.description}</p><Badge tone="info">{value.auth_mode}</Badge><Button onClick={() => choose(value)}>Configure {value.provider}</Button></article>)}</div></Card>}
    <Modal open={manifest !== null} title={`Configure ${manifest?.provider ?? "integration"}`} onClose={() => setManifest(null)} footer={<><Button onClick={() => setManifest(null)}>Cancel</Button><Button variant="primary" disabled={busy || !name || manifest?.setup_schema.some((field) => field.required && !configuration[field.key])} onClick={create}>Save integration</Button></>}>{manifest && <div className="form-stack"><p>{manifest.access_guidance}</p><Field label="Integration name" value={name} onChange={(event) => setName(event.target.value)} />{manifest.setup_schema.map((field) => <Field key={field.key} label={field.label} hint={field.description} value={configuration[field.key] ?? ""} onChange={(event) => setConfiguration((current) => ({ ...current, [field.key]: event.target.value }))} />)}</div>}</Modal>
    <Modal open={selected !== null} title={selected?.value.name ?? "Integration"} onClose={() => setSelected(null)} footer={<><Button onClick={() => setSelected(null)}>Close</Button>{canWrite && <><Button disabled={busy} onClick={update}>Save changes</Button><Button variant="danger" disabled={busy} onClick={remove}>Delete integration</Button></>}</>}>{selected && <div className="form-stack"><p><Badge tone="info">{selected.value.status}</Badge> Version {selected.version}</p><Field label="Integration name" value={name} disabled={!canWrite} onChange={(event) => setName(event.target.value)} />{Object.entries(configuration).map(([key, value]) => <Field key={key} label={key.replaceAll("_", " ")} value={value} disabled={!canWrite} onChange={(event) => setConfiguration((current) => ({ ...current, [key]: event.target.value }))} />)}<p>Provider authorization and sync are capability-hidden for this deployment.</p></div>}</Modal>
  </div>;
}
