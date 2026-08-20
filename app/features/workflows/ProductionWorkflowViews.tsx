"use client";

import { useEffect, useMemo, useState } from "react";

import { APITransportError } from "../../../apps/web/api/client";
import type { ConnectorManifest, Integration, IntegrationInput, IntegrationUpdateInput, Policy, PolicyRollout } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { useOptionalSession, useSession } from "../../auth/SessionProvider";
import { Badge, Button, Card, EmptyState, Field, LoadingState, Modal, PageHeader } from "../../components/ui";
import { createIntegrationsAPI, createPoliciesAPI, IntegrationRevocationPending, ReferenceAuthorizationConflict, type Versioned, type WorkflowReceipt } from "./api";
import { useRetainedWorkflowMutation } from "./useRetainedWorkflowMutation";

type Feedback = { tone: "status" | "alert"; message: string } | null;
type PolicyMutationIntent =
  | { kind: "create"; value: Policy }
  | { kind: "update"; id: string; version: string; value: Policy }
  | { kind: "rollout"; id: string; version: string; value: Policy; state: "monitor" | "enforced"; targetID: string }
  | { kind: "disable"; id: string; version: string; value: Policy };
type PolicyMutationResult =
  | { kind: "created" | "updated"; receipt: WorkflowReceipt<Policy> }
  | { kind: "rolled"; receipt: WorkflowReceipt<PolicyRollout>; value: Policy; state: "monitor" | "enforced" | "disabled" };
type IntegrationMutationIntent =
  | { kind: "create"; value: IntegrationInput }
  | { kind: "update"; id: string; version: string; value: IntegrationUpdateInput }
  | { kind: "authorize-reference"; id: string; version: string; connectorKey: "aws" | "kubernetes" }
  | { kind: "delete"; id: string; version: string };
type IntegrationMutationResult =
  | { kind: "created" | "updated" | "authorized"; receipt: WorkflowReceipt<Integration> }
  | { kind: "deleted"; receipt: WorkflowReceipt<void> };

function QueryBoundary({ status, label, onRetry, disabled = false }: { status: string; label: string; onRetry(): Promise<void>; disabled?: boolean }) {
  if (status === "loading" || status === "idle") return <LoadingState label={`Loading ${label}…`} />;
  if (status === "forbidden") return <p role="alert">You are not authorized to view {label}.</p>;
  if (status === "error") return <p role="alert">{label} are unavailable. <Button disabled={disabled} onClick={() => void onRetry()}>Retry</Button></p>;
  if (status === "stale") return <p role="status">Showing the last confirmed {label}. <Button disabled={disabled} onClick={() => void onRetry()}>Refresh</Button></p>;
  return null;
}

function FeedbackLine({ value }: { value: Feedback }) {
  return value ? <p role={value.tone}>{value.message}</p> : null;
}

export function ProductionPoliciesView({ canWrite }: { canWrite: boolean }) {
  const { client, invalidate } = useAPI();
  const session = useSession();
  const api = useMemo(() => createPoliciesAPI(client), [client]);
  const mutation = useRetainedWorkflowMutation<PolicyMutationIntent>("policies");
  const query = useAPIQuery("workflow:policies", api.listPolicies);
  const [selected, setSelected] = useState<Versioned<Policy> | null>(null);
  const [policyID, setPolicyID] = useState("policy-production");
  const [name, setName] = useState("Production runtime policy");
  const [editName, setEditName] = useState("");
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [busy, setBusy] = useState(false);

  const run = async (action: () => Promise<void>) => {
    setBusy(true); setFeedback(null);
    try { await action(); } catch { setFeedback({ tone: "alert", message: "The policy operation was not applied. Refresh the current version and retry." }); } finally { setBusy(false); }
  };
  const applyMutation = (result: PolicyMutationResult) => {
    if (result.kind === "rolled") {
      setSelected({ value: { ...result.value, rollout: result.state }, version: result.receipt.version }); invalidate(["workflow:policies"]); setFeedback({ tone: "status", message: `Policy is ${result.state}. Audit ${result.receipt.auditID}` });
      return;
    }
    setSelected(result.receipt); setEditName(result.receipt.value.name); invalidate(["workflow:policies"]); setFeedback({ tone: "status", message: `Policy ${result.kind}. Audit ${result.receipt.auditID}` });
  };
  const runMutation = (operation: () => Promise<PolicyMutationResult>) => void run(async () => { applyMutation(await operation()); });
  const open = (id: string) => void run(async () => { const current = await api.getPolicy(id); setSelected(current); setEditName(current.value.name); });
  const create = () => void run(async () => {
    const intent: PolicyMutationIntent = { kind: "create", value: { id: policyID, name, scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" } };
    applyMutation(await mutation.execute(intent, async (frozen, attempt) => ({ kind: "created" as const, receipt: await api.createPolicy(frozen.value, attempt) })));
  });
  const update = () => selected && runMutation(() => mutation.execute({ kind: "update", id: selected.value.id, version: selected.version, value: { ...selected.value, name: editName } }, async (intent, attempt) => { if (intent.kind !== "update") throw new TypeError("Invalid retained policy intent"); return { kind: "updated", receipt: await api.updatePolicy(intent.id, intent.version, intent.value, attempt) }; }));
  const rollout = (state: "monitor" | "enforced") => selected && session.status === "authenticated" && runMutation(() => mutation.execute({ kind: "rollout", id: selected.value.id, version: selected.version, value: selected.value, state, targetID: session.environmentID }, async (intent, attempt) => { if (intent.kind !== "rollout") throw new TypeError("Invalid retained policy intent"); return { kind: "rolled", receipt: await api.rolloutPolicy(intent.id, intent.version, { state: intent.state, target_id: intent.targetID }, attempt), value: intent.value, state: intent.state }; }));
  const disable = () => selected && runMutation(() => mutation.execute({ kind: "disable", id: selected.value.id, version: selected.version, value: selected.value }, async (intent, attempt) => { if (intent.kind !== "disable") throw new TypeError("Invalid retained policy intent"); return { kind: "rolled", receipt: await api.disablePolicy(intent.id, intent.version, attempt), value: intent.value, state: "disabled" }; }));
  const retryMutation = () => runMutation(() => mutation.retry<PolicyMutationResult>());

  return <div className="page"><PageHeader title="Policies" description="Durable scoped runtime controls with version checks and audit receipts." />
    <FeedbackLine value={feedback} /><QueryBoundary status={query.status} label="policies" onRetry={query.retry} disabled={mutation.isUnresolved} />
    {mutation.canRetry && <p role="alert">The response was lost. The exact operation and idempotency key are retained. <Button disabled={busy} onClick={retryMutation}>Retry retained policy operation</Button></p>}
    {canWrite && <Card title="Create policy"><div className="form-grid"><Field label="Policy ID" value={policyID} disabled={mutation.isUnresolved} pattern="policy-[a-z0-9-]+" onChange={(event) => setPolicyID(event.target.value)} /><Field label="Name" value={name} disabled={mutation.isUnresolved} maxLength={128} onChange={(event) => setName(event.target.value)} /></div><Button variant="primary" disabled={busy || mutation.isUnresolved || !policyID || !name} onClick={create}>Create policy</Button></Card>}
    <Card title="Authorized policies">{query.data?.length ? <div className="connection-list">{query.data.map((policy) => <button type="button" key={policy.id} disabled={busy || mutation.isUnresolved} onClick={() => open(policy.id)} aria-label={`Open ${policy.name}`}><strong>{policy.name}</strong><span>{policy.action}</span><span>{policy.rollout}</span></button>)}</div> : query.status === "empty" ? <EmptyState title="No policies" description="Create the first scoped runtime policy when write access is enabled." /> : null}</Card>
    {selected && <Card title={`Policy detail · ${selected.value.id}`}><p><Badge tone="info">{selected.value.rollout}</Badge> Version {selected.version}</p><Field label="Policy name" value={editName} disabled={!canWrite || busy || mutation.isUnresolved} onChange={(event) => setEditName(event.target.value)} /><p>{selected.value.conditions.map((condition) => `${condition.field} ${condition.operator} ${condition.value}`).join(", ")}</p>{canWrite && <div className="button-row"><Button disabled={busy || mutation.isUnresolved} onClick={update}>Save changes</Button>{selected.value.rollout === "draft" && <Button disabled={busy || mutation.isUnresolved} onClick={() => rollout("monitor")}>Roll to monitor</Button>}{selected.value.rollout === "monitor" && <Button variant="primary" disabled={busy || mutation.isUnresolved} onClick={() => rollout("enforced")}>Enforce policy</Button>}{(selected.value.rollout === "monitor" || selected.value.rollout === "enforced") && <Button disabled={busy || mutation.isUnresolved} onClick={disable}>Disable policy</Button>}</div>}</Card>}
  </div>;
}

export function ProductionIntegrationsView({ canWrite }: { canWrite: boolean }) {
  const { client, invalidate } = useAPI();
  const session = useOptionalSession();
  const fresh = session !== null && session.status === "authenticated" && session.isFreshAuthenticated;
  const api = useMemo(() => createIntegrationsAPI(client), [client]);
  const mutation = useRetainedWorkflowMutation<IntegrationMutationIntent>("integrations", canWrite);
  const catalog = useAPIQuery("workflow:integration-catalog", api.listCatalog);
  const integrations = useAPIQuery("workflow:integrations", api.listIntegrations);
  const [manifest, setManifest] = useState<ConnectorManifest | null>(null);
  const [configuration, setConfiguration] = useState<Record<string, string>>({});
  const [name, setName] = useState("");
  const [selected, setSelected] = useState<Versioned<Integration> | null>(null);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [busy, setBusy] = useState(false);
  const [revocationClock, setRevocationClock] = useState(() => Date.now());
  const pendingRevocation = mutation.knownPending?.kind === "integration_revocation" ? mutation.knownPending : null;
  const pendingReferenceConflict = mutation.knownPending?.kind === "reference_authorization_conflict" ? mutation.knownPending : null;
  const retainedReferenceAuthorization = mutation.retainedIntent?.kind === "authorize-reference";
  useEffect(() => {
    if (!pendingRevocation) return;
    const remaining = pendingRevocation.retryNotBefore - Date.now();
    if (remaining <= 0) return;
    const timer = window.setTimeout(() => setRevocationClock(pendingRevocation.retryNotBefore), remaining);
    return () => window.clearTimeout(timer);
  }, [pendingRevocation]);
  const run = async (action: () => Promise<void>) => {
    setBusy(true); setFeedback(null);
    try { await action(); } catch (error) {
      if (error instanceof IntegrationRevocationPending) {
        setSelected(error.receipt);
        setName(error.receipt.value.name);
        setConfiguration({ ...error.receipt.value.configuration });
        setFeedback({ tone: "status", message: `Provider revocation is pending. Audit ${error.receipt.auditID}` });
      } else {
        setFeedback({ tone: "alert", message: "The integration operation was not confirmed. Retry the retained operation when offered." });
      }
    } finally { setBusy(false); }
  };
  const applyMutation = (result: IntegrationMutationResult) => {
    invalidate(["workflow:integrations"]);
    if (result.kind === "deleted") { setSelected(null); setFeedback({ tone: "status", message: `Integration deleted. Audit ${result.receipt.auditID}` }); return; }
    setSelected(result.receipt); setName(result.receipt.value.name); setConfiguration({ ...result.receipt.value.configuration });
    setManifest(null); setFeedback({ tone: "status", message: `Integration ${result.kind}. Audit ${result.receipt.auditID}` });
  };
  const runMutation = (operation: () => Promise<IntegrationMutationResult>) => void run(async () => { applyMutation(await operation()); });
  const choose = (value: ConnectorManifest) => { setManifest(value); setName(value.provider); setConfiguration(Object.fromEntries(value.setup_schema.map((field) => [field.key, ""]))); };
  const create = () => manifest && runMutation(() => mutation.execute({ kind: "create", value: { connector_key: manifest.key, name, configuration } }, async (intent, attempt) => { if (intent.kind !== "create") throw new TypeError("Invalid retained integration intent"); return { kind: "created", receipt: await api.createIntegration(intent.value, attempt) }; }));
  const open = (id: string) => void run(async () => { const value = await api.getIntegration(id); setSelected(value); setName(value.value.name); setConfiguration({ ...value.value.configuration }); });
  const update = () => selected && runMutation(() => mutation.execute({ kind: "update", id: selected.value.id, version: selected.version, value: { name, configuration } }, async (intent, attempt) => { if (intent.kind !== "update") throw new TypeError("Invalid retained integration intent"); return { kind: "updated", receipt: await api.updateIntegration(intent.id, intent.version, intent.value, attempt) }; }));
  const reconcileReferenceConflict = async (integrationID: string) => {
    try {
      const current = await api.getIntegration(integrationID);
      setSelected(current); setName(current.value.name); setConfiguration({ ...current.value.configuration });
      mutation.resolveAfterServerReconciliation();
      invalidate(["workflow:integrations"]);
      setFeedback({ tone: "alert", message: "Integration changed. Review the current version before authorizing again." });
    } catch {
      setFeedback({ tone: "alert", message: "The current integration could not be confirmed. Retry the authoritative refetch." });
    }
  };
  const applyReferenceAuthorization = async (operation: () => Promise<IntegrationMutationResult>) => {
    try {
      applyMutation(await operation());
    } catch (error) {
      if (!(error instanceof ReferenceAuthorizationConflict)) throw error;
      await reconcileReferenceConflict(error.integrationID);
    }
  };
  const authorizeReference = () => {
    if (!selected || !isReferenceAuthorizationCandidate(selected.value) || !fresh) return;
    const current = selected;
    const connectorKey = current.value.connector_key;
    if (!isReferenceConnector(connectorKey)) return;
    const intent = { kind: "authorize-reference", id: current.value.id, version: current.version, connectorKey } as const;
    void run(() => applyReferenceAuthorization(() => mutation.execute(intent, async (frozen, attempt) => {
          if (frozen.kind !== "authorize-reference") throw new TypeError("Invalid retained integration intent");
          const receipt = await api.authorizeIntegrationReference(frozen.id, frozen.version, attempt);
          if (receipt.value.connector_key !== frozen.connectorKey) throw new APITransportError("invalid_response", "Reference authorization changed connector identity");
          return { kind: "authorized", receipt };
        })));
  };
  const remove = () => selected && runMutation(() => mutation.execute({ kind: "delete", id: selected.value.id, version: selected.version }, async (intent, attempt) => { if (intent.kind !== "delete") throw new TypeError("Invalid retained integration intent"); return { kind: "deleted", receipt: await api.deleteIntegration(intent.id, intent.version, attempt) }; }));
  const retryMutation = () => {
    if (retainedReferenceAuthorization && !fresh) return;
    void run(() => retainedReferenceAuthorization
      ? applyReferenceAuthorization(() => mutation.retry<IntegrationMutationResult>())
      : mutation.retry<IntegrationMutationResult>().then((result) => { applyMutation(result); }));
  };
  const retryReferenceConflictRefetch = () => pendingReferenceConflict && void run(() => reconcileReferenceConflict(pendingReferenceConflict.integrationID));
  const visibleSelected = selected ?? pendingRevocation?.receipt ?? null;
  const visibleConfiguration = selected ? configuration : pendingRevocation?.receipt.value.configuration ?? configuration;
  const revocationPending = visibleSelected?.value.status === "revoking" && mutation.isUnresolved && pendingRevocation !== null;
  const revocationRetryReady = pendingRevocation === null || revocationClock >= pendingRevocation.retryNotBefore;
  const referenceAuthorizationCandidate = selected !== null && isReferenceAuthorizationCandidate(selected.value);
  return <div className="page"><PageHeader title="Integrations" description="Durable connector configuration with reference authorization for supported AWS and Kubernetes integrations." />{!visibleSelected && <FeedbackLine value={feedback} />}{mutation.canRetry && !visibleSelected && <p role="alert">The response was lost. The exact operation and idempotency key are retained. <Button disabled={busy || retainedReferenceAuthorization && !fresh} onClick={retryMutation}>Retry retained integration operation</Button></p>}
    <QueryBoundary status={integrations.status} label="integrations" onRetry={integrations.retry} disabled={mutation.isUnresolved} /><Card title="Configured integrations">{integrations.data?.length ? <div className="connection-list">{integrations.data.map((value) => <button type="button" key={value.id} disabled={busy || mutation.isUnresolved} aria-label={`Open ${value.name}`} onClick={() => open(value.id)}><strong>{value.name}</strong><span>{value.connector_key}</span><span>{value.status}</span></button>)}</div> : integrations.status === "empty" ? <EmptyState title="No integrations" description="Choose a supported connector catalog entry to save its scoped configuration." /> : null}</Card>
    <QueryBoundary status={catalog.status} label="integration catalog" onRetry={catalog.retry} disabled={mutation.isUnresolved} />{canWrite && <Card title="Connector catalog"><div className="connector-grid">{catalog.data?.map((value) => <article key={value.key} className="connector-card"><h3>{value.provider}</h3><p>{value.description}</p><Badge tone="info">{value.auth_mode}</Badge><Button disabled={busy || mutation.isUnresolved} onClick={() => choose(value)}>Configure {value.provider}</Button></article>)}</div></Card>}
    <Modal open={manifest !== null} title={`Configure ${manifest?.provider ?? "integration"}`} closeDisabled={mutation.isUnresolved} onClose={() => setManifest(null)} footer={<><Button disabled={mutation.isUnresolved} onClick={() => setManifest(null)}>Cancel</Button><Button variant="primary" disabled={busy || mutation.isUnresolved || !name || manifest?.setup_schema.some((field) => field.required && !configuration[field.key])} onClick={create}>Save integration</Button></>}>{manifest && <div className="form-stack">{mutation.canRetry && <p role="alert">The response was lost. The exact operation and idempotency key are retained. <Button disabled={busy} onClick={retryMutation}>Retry retained integration operation</Button></p>}<p>{manifest.access_guidance}</p><Field label="Integration name" value={name} disabled={mutation.isUnresolved} onChange={(event) => setName(event.target.value)} />{manifest.setup_schema.map((field) => <Field key={field.key} label={field.label} hint={field.description} value={configuration[field.key] ?? ""} disabled={mutation.isUnresolved} onChange={(event) => setConfiguration((current) => ({ ...current, [field.key]: event.target.value }))} />)}</div>}</Modal>
    <Modal open={visibleSelected !== null} title={visibleSelected?.value.name ?? "Integration"} closeDisabled={mutation.isUnresolved} onClose={() => setSelected(null)} footer={<><Button disabled={mutation.isUnresolved} onClick={() => setSelected(null)}>Close</Button>{canWrite && <>{referenceAuthorizationCandidate && <Button variant="primary" disabled={busy || mutation.isUnresolved || !fresh} onClick={authorizeReference}>Authorize {selected?.value.connector_key === "aws" ? "AWS" : "Kubernetes"} reference</Button>}<Button disabled={busy || mutation.isUnresolved} onClick={update}>Save changes</Button><Button variant="danger" disabled={busy || mutation.isUnresolved} onClick={remove}>Delete integration</Button></>}</>}>{visibleSelected && <div className="form-stack">{pendingReferenceConflict ? <><FeedbackLine value={feedback} /><Button disabled={busy} onClick={retryReferenceConflictRefetch}>Retry authoritative integration refetch</Button></> : !revocationPending && !mutation.canRetry && <FeedbackLine value={feedback} />}{revocationPending ? <p role="status">Provider revocation is pending. The exact DELETE and idempotency key are retained. {mutation.canRetry && <Button disabled={busy || !revocationRetryReady} onClick={retryMutation}>Retry pending integration deletion</Button>}</p> : !pendingReferenceConflict && mutation.canRetry && <p role="alert">The response was lost. The exact operation and idempotency key are retained. <Button disabled={busy || retainedReferenceAuthorization && !fresh} onClick={retryMutation}>Retry retained integration operation</Button></p>}{canWrite && retainedReferenceAuthorization && !fresh && <p role="alert">Fresh authentication is required to retry this reference authorization. {session?.status === "authenticated" && <Button onClick={session.reauthenticate}>Reauthenticate</Button>}</p>}{canWrite && referenceAuthorizationCandidate && !retainedReferenceAuthorization && !fresh && <p role="alert">Fresh authentication is required to authorize this reference. {session?.status === "authenticated" && <Button onClick={session.reauthenticate}>Reauthenticate</Button>}</p>}<p><Badge tone="info">{visibleSelected.value.status}</Badge> Version {visibleSelected.version}</p><Field label="Integration name" value={selected ? name : visibleSelected.value.name} disabled={!canWrite || mutation.isUnresolved} onChange={(event) => setName(event.target.value)} />{Object.entries(visibleConfiguration).map(([key, value]) => { const reference = key.endsWith("_reference"); return <Field key={key} label={key.replaceAll("_", " ")} value={reference ? "Configured reference" : value} disabled={!canWrite || mutation.isUnresolved || reference} onChange={reference ? undefined : (event) => setConfiguration((current) => ({ ...current, [key]: event.target.value }))} />; })}<p>{isReferenceConnector(visibleSelected.value.connector_key) ? visibleSelected.value.status === "active" ? "Reference authorization is active." : "Authorization uses the configured reference without exposing its value." : "Provider authorization controls are unavailable for this connector."}</p></div>}</Modal>
  </div>;
}

function isReferenceConnector(value: string): value is "aws" | "kubernetes" {
  return value === "aws" || value === "kubernetes";
}

function isReferenceAuthorizationCandidate(value: Integration): value is Integration & { connector_key: "aws" | "kubernetes" } {
  return isReferenceConnector(value.connector_key) && (value.status === "configured" || value.status === "pending_authorization" || value.status === "degraded");
}
