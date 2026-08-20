"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import { APITransportError } from "../../../apps/web/api/client";
import type { ConnectorManifest, Integration, IntegrationFreshness, IntegrationInput, IntegrationSchedule, IntegrationScheduleInput, IntegrationSync, IntegrationUpdateInput, Policy, PolicyRollout } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { useOptionalSession, useSession } from "../../auth/SessionProvider";
import { Badge, Button, Card, EmptyState, Field, LoadingState, Modal, PageHeader } from "../../components/ui";
import { createIntegrationsAPI, createPoliciesAPI, IntegrationDiscoveryConflict, IntegrationRevocationPending, ReferenceAuthorizationConflict, type Versioned, type WorkflowReceipt } from "./api";
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
  | { kind: "sync"; id: string; version: string }
  | { kind: "put-schedule"; id: string; version: string; value: IntegrationScheduleInput }
  | { kind: "delete-schedule"; id: string; version: string }
  | { kind: "delete"; id: string; version: string };
type IntegrationMutationResult =
  | { kind: "created" | "updated" | "authorized"; receipt: WorkflowReceipt<Integration> }
  | { kind: "sync-queued"; receipt: WorkflowReceipt<IntegrationSync> }
  | { kind: "schedule-saved"; receipt: WorkflowReceipt<IntegrationSchedule> }
  | { kind: "schedule-deleted"; receipt: WorkflowReceipt<void> }
  | { kind: "deleted"; receipt: WorkflowReceipt<void> };
type DiscoveryLoad<T> = { status: "idle" | "loading" | "success" | "error"; value?: T };

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
  const [freshness, setFreshness] = useState<DiscoveryLoad<Versioned<IntegrationFreshness>>>({ status: "idle" });
  const [schedule, setSchedule] = useState<DiscoveryLoad<Versioned<IntegrationSchedule> | null>>({ status: "idle" });
  const [syncs, setSyncs] = useState<DiscoveryLoad<readonly IntegrationSync[]>>({ status: "idle" });
  const [syncDetail, setSyncDetail] = useState<DiscoveryLoad<Versioned<IntegrationSync>>>({ status: "idle" });
  const [scheduleCadence, setScheduleCadence] = useState("3600");
  const discoveryGeneration = useRef(0);
  const [revocationClock, setRevocationClock] = useState(() => Date.now());
  const pendingRevocation = mutation.knownPending?.kind === "integration_revocation" ? mutation.knownPending : null;
  const pendingReferenceConflict = mutation.knownPending?.kind === "reference_authorization_conflict" ? mutation.knownPending : null;
  const pendingDiscoveryConflict = mutation.knownPending?.kind === "integration_discovery_conflict" ? mutation.knownPending : null;
  const retainedReferenceAuthorization = mutation.retainedIntent?.kind === "authorize-reference";
  useEffect(() => {
    if (!pendingRevocation) return;
    const remaining = Math.max(0, pendingRevocation.retryNotBefore - Date.now());
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
    if (result.kind === "sync-queued") {
      setSyncs({ status: "success", value: [result.receipt.value, ...(syncs.value ?? []).filter((value) => value.id !== result.receipt.value.id)] });
      setFeedback({ tone: "status", message: `Inventory sync queued. Audit ${result.receipt.auditID}` });
      return;
    }
    if (result.kind === "schedule-saved") {
      setSchedule({ status: "success", value: result.receipt }); setScheduleCadence(String(result.receipt.value.cadence_seconds));
      setFeedback({ tone: "status", message: `Automatic sync schedule saved. Audit ${result.receipt.auditID}` });
      return;
    }
    if (result.kind === "schedule-deleted") {
      setSchedule({ status: "success", value: null }); setFeedback({ tone: "status", message: `Automatic sync schedule deleted. Audit ${result.receipt.auditID}` });
      return;
    }
    invalidate(["workflow:integrations"]);
    if (result.kind === "deleted") { discoveryGeneration.current += 1; setSelected(null); setFeedback({ tone: "status", message: `Integration deleted. Audit ${result.receipt.auditID}` }); return; }
    setSelected(result.receipt); setName(result.receipt.value.name); setConfiguration({ ...result.receipt.value.configuration });
    setManifest(null); setFeedback({ tone: "status", message: `Integration ${result.kind}. Audit ${result.receipt.auditID}` });
  };
  const runMutation = (operation: () => Promise<IntegrationMutationResult>) => void run(async () => { applyMutation(await operation()); });
  const choose = (value: ConnectorManifest) => { setManifest(value); setName(value.provider); setConfiguration(Object.fromEntries(value.setup_schema.map((field) => [field.key, ""]))); };
  const create = () => manifest && runMutation(() => mutation.execute({ kind: "create", value: { connector_key: manifest.key, name, configuration } }, async (intent, attempt) => { if (intent.kind !== "create") throw new TypeError("Invalid retained integration intent"); return { kind: "created", receipt: await api.createIntegration(intent.value, attempt) }; }));
  const loadDiscovery = (id: string) => {
    const generation = discoveryGeneration.current + 1;
    discoveryGeneration.current = generation;
    setFreshness({ status: "loading" }); setSchedule({ status: "loading" }); setSyncs({ status: "loading" }); setSyncDetail({ status: "idle" });
    void api.getIntegrationFreshness(id).then((value) => { if (discoveryGeneration.current === generation) setFreshness({ status: "success", value }); }, () => { if (discoveryGeneration.current === generation) setFreshness({ status: "error" }); });
    void api.getIntegrationSchedule(id).then((value) => { if (discoveryGeneration.current === generation) { setSchedule({ status: "success", value }); if (value) setScheduleCadence(String(value.value.cadence_seconds)); } }, () => { if (discoveryGeneration.current === generation) setSchedule({ status: "error" }); });
    void api.listIntegrationSyncs(id).then((value) => { if (discoveryGeneration.current === generation) setSyncs({ status: "success", value }); }, () => { if (discoveryGeneration.current === generation) setSyncs({ status: "error" }); });
  };
  const open = (id: string) => void run(async () => { const value = await api.getIntegration(id); setSelected(value); setName(value.value.name); setConfiguration({ ...value.value.configuration }); loadDiscovery(id); });
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
  const reconcileDiscoveryConflict = async (conflict: Pick<IntegrationDiscoveryConflict, "integrationID" | "resource">) => {
    try {
      if (conflict.resource === "sync") {
        const current = await api.getIntegration(conflict.integrationID);
        setSelected(current); setName(current.value.name); setConfiguration({ ...current.value.configuration });
        invalidate(["workflow:integrations"]);
      } else {
        const current = await api.getIntegrationSchedule(conflict.integrationID);
        setSchedule({ status: "success", value: current });
        if (current) setScheduleCadence(String(current.value.cadence_seconds));
      }
      mutation.resolveAfterServerReconciliation();
      setFeedback({ tone: "alert", message: "Discovery settings changed. Review the authoritative state before retrying." });
    } catch {
      setFeedback({ tone: "alert", message: "The current discovery state could not be confirmed. Retry the authoritative refetch." });
    }
  };
  const applyDiscoveryMutation = async (operation: () => Promise<IntegrationMutationResult>) => {
    try { applyMutation(await operation()); } catch (error) {
      if (!(error instanceof IntegrationDiscoveryConflict)) throw error;
      await reconcileDiscoveryConflict(error);
    }
  };
  const queueSync = () => {
    if (!selected) return;
    const intent = { kind: "sync", id: selected.value.id, version: selected.version } as const;
    void run(() => applyDiscoveryMutation(() => mutation.execute(intent, async (frozen, attempt) => {
      if (frozen.kind !== "sync") throw new TypeError("Invalid retained integration sync intent");
      return { kind: "sync-queued", receipt: await api.syncIntegration(frozen.id, frozen.version, attempt) };
    })));
  };
  const saveSchedule = (state?: "enabled" | "disabled") => {
    if (!selected || schedule.status !== "success") return;
    const cadence = Number(scheduleCadence);
    if (!Number.isSafeInteger(cadence) || cadence < 300 || cadence > 2_678_400) return;
    const value: IntegrationScheduleInput = { cadence_seconds: cadence, state: state ?? (schedule.value?.value.state === "disabled" ? "disabled" : "enabled") };
    const intent = { kind: "put-schedule", id: selected.value.id, version: schedule.value?.version ?? '"0"', value } as const;
    void run(() => applyDiscoveryMutation(() => mutation.execute(intent, async (frozen, attempt) => {
      if (frozen.kind !== "put-schedule") throw new TypeError("Invalid retained integration schedule intent");
      return { kind: "schedule-saved", receipt: await api.putIntegrationSchedule(frozen.id, frozen.version, frozen.value, attempt) };
    })));
  };
  const removeSchedule = () => {
    if (!selected || schedule.status !== "success" || !schedule.value) return;
    const intent = { kind: "delete-schedule", id: selected.value.id, version: schedule.value.version } as const;
    void run(() => applyDiscoveryMutation(() => mutation.execute(intent, async (frozen, attempt) => {
      if (frozen.kind !== "delete-schedule") throw new TypeError("Invalid retained integration schedule intent");
      return { kind: "schedule-deleted", receipt: await api.deleteIntegrationSchedule(frozen.id, frozen.version, attempt) };
    })));
  };
  const openSync = (syncID: string) => {
    if (!selected) return;
    const integrationID = selected.value.id;
    setSyncDetail({ status: "loading" });
    void api.getIntegrationSync(integrationID, syncID).then((value) => setSyncDetail({ status: "success", value }), () => setSyncDetail({ status: "error" }));
  };
  const remove = () => selected && runMutation(() => mutation.execute({ kind: "delete", id: selected.value.id, version: selected.version }, async (intent, attempt) => { if (intent.kind !== "delete") throw new TypeError("Invalid retained integration intent"); return { kind: "deleted", receipt: await api.deleteIntegration(intent.id, intent.version, attempt) }; }));
  const retryMutation = () => {
    if (retainedReferenceAuthorization && !fresh) return;
    void run(() => retainedReferenceAuthorization
      ? applyReferenceAuthorization(() => mutation.retry<IntegrationMutationResult>())
      : mutation.retry<IntegrationMutationResult>().then((result) => { applyMutation(result); }));
  };
  const retryReferenceConflictRefetch = () => pendingReferenceConflict && void run(() => reconcileReferenceConflict(pendingReferenceConflict.integrationID));
  const retryDiscoveryConflictRefetch = () => pendingDiscoveryConflict && void run(() => reconcileDiscoveryConflict(pendingDiscoveryConflict));
  const closeSelected = () => { discoveryGeneration.current += 1; setSelected(null); setFreshness({ status: "idle" }); setSchedule({ status: "idle" }); setSyncs({ status: "idle" }); setSyncDetail({ status: "idle" }); };
  const visibleSelected = selected ?? pendingRevocation?.receipt ?? null;
  const visibleConfiguration = selected ? configuration : pendingRevocation?.receipt.value.configuration ?? configuration;
  const revocationPending = visibleSelected?.value.status === "revoking" && mutation.isUnresolved && pendingRevocation !== null;
  const revocationRetryReady = pendingRevocation === null || revocationClock >= pendingRevocation.retryNotBefore;
  const referenceAuthorizationCandidate = selected !== null && isReferenceAuthorizationCandidate(selected.value);
  const selectedManifest = selected ? catalog.data?.find((value) => value.key === selected.value.connector_key) : undefined;
  const discoveryWriteAllowed = Boolean(canWrite && selected?.value.status === "active" && isFirstPartyConnector(selected.value.connector_key) && selectedManifest?.actions.includes("inventory_read"));
  const manualSyncAllowed = discoveryWriteAllowed && freshness.status === "success" && syncs.status === "success";
  return <div className="page"><PageHeader title="Integrations" description="Durable connector configuration with reference authorization for supported AWS and Kubernetes integrations." />{!visibleSelected && <FeedbackLine value={feedback} />}{mutation.canRetry && !visibleSelected && <p role="alert">The response was lost. The exact operation and idempotency key are retained. <Button disabled={busy || retainedReferenceAuthorization && !fresh} onClick={retryMutation}>Retry retained integration operation</Button></p>}
    <QueryBoundary status={integrations.status} label="integrations" onRetry={integrations.retry} disabled={mutation.isUnresolved} /><Card title="Configured integrations">{integrations.data?.length ? <div className="connection-list">{integrations.data.map((value) => <button type="button" key={value.id} disabled={busy || mutation.isUnresolved} aria-label={`Open ${value.name}`} onClick={() => open(value.id)}><strong>{value.name}</strong><span>{value.connector_key}</span><span>{value.status}</span></button>)}</div> : integrations.status === "empty" ? <EmptyState title="No integrations" description="Choose a supported connector catalog entry to save its scoped configuration." /> : null}</Card>
    <QueryBoundary status={catalog.status} label="integration catalog" onRetry={catalog.retry} disabled={mutation.isUnresolved} />{canWrite && <Card title="Connector catalog"><div className="connector-grid">{catalog.data?.map((value) => <article key={value.key} className="connector-card"><h3>{value.provider}</h3><p>{value.description}</p><Badge tone="info">{value.auth_mode}</Badge><Button disabled={busy || mutation.isUnresolved} onClick={() => choose(value)}>Configure {value.provider}</Button></article>)}</div></Card>}
    <Modal open={manifest !== null} title={`Configure ${manifest?.provider ?? "integration"}`} closeDisabled={mutation.isUnresolved} onClose={() => setManifest(null)} footer={<><Button disabled={mutation.isUnresolved} onClick={() => setManifest(null)}>Cancel</Button><Button variant="primary" disabled={busy || mutation.isUnresolved || !name || manifest?.setup_schema.some((field) => field.required && !configuration[field.key])} onClick={create}>Save integration</Button></>}>{manifest && <div className="form-stack">{mutation.canRetry && <p role="alert">The response was lost. The exact operation and idempotency key are retained. <Button disabled={busy} onClick={retryMutation}>Retry retained integration operation</Button></p>}<p>{manifest.access_guidance}</p><Field label="Integration name" value={name} disabled={mutation.isUnresolved} onChange={(event) => setName(event.target.value)} />{manifest.setup_schema.map((field) => <Field key={field.key} label={field.label} hint={field.description} value={configuration[field.key] ?? ""} disabled={mutation.isUnresolved} onChange={(event) => setConfiguration((current) => ({ ...current, [field.key]: event.target.value }))} />)}</div>}</Modal>
    <Modal open={visibleSelected !== null} title={visibleSelected?.value.name ?? "Integration"} closeDisabled={mutation.isUnresolved} onClose={closeSelected} footer={<><Button disabled={mutation.isUnresolved} onClick={closeSelected}>Close</Button>{canWrite && <>{referenceAuthorizationCandidate && <Button variant="primary" disabled={busy || mutation.isUnresolved || !fresh} onClick={authorizeReference}>Authorize {selected?.value.connector_key === "aws" ? "AWS" : "Kubernetes"} reference</Button>}<Button disabled={busy || mutation.isUnresolved} onClick={update}>Save changes</Button><Button variant="danger" disabled={busy || mutation.isUnresolved} onClick={remove}>Delete integration</Button></>}</>}>{visibleSelected && <div className="form-stack">{pendingReferenceConflict ? <><FeedbackLine value={feedback} /><Button disabled={busy} onClick={retryReferenceConflictRefetch}>Retry authoritative integration refetch</Button></> : pendingDiscoveryConflict ? <><FeedbackLine value={feedback} /><Button disabled={busy} onClick={retryDiscoveryConflictRefetch}>Retry authoritative discovery refetch</Button></> : !revocationPending && !mutation.canRetry && <FeedbackLine value={feedback} />}{revocationPending ? <p role="status">Provider revocation is pending. The exact DELETE and idempotency key are retained. {mutation.canRetry && <Button disabled={busy || !revocationRetryReady} onClick={retryMutation}>Retry pending integration deletion</Button>}</p> : !pendingReferenceConflict && !pendingDiscoveryConflict && mutation.canRetry && <p role="alert">The response was lost. The exact operation and idempotency key are retained. <Button disabled={busy || retainedReferenceAuthorization && !fresh} onClick={retryMutation}>Retry retained integration operation</Button></p>}{canWrite && retainedReferenceAuthorization && !fresh && <p role="alert">Fresh authentication is required to retry this reference authorization. {session?.status === "authenticated" && <Button onClick={session.reauthenticate}>Reauthenticate</Button>}</p>}{canWrite && referenceAuthorizationCandidate && !retainedReferenceAuthorization && !fresh && <p role="alert">Fresh authentication is required to authorize this reference. {session?.status === "authenticated" && <Button onClick={session.reauthenticate}>Reauthenticate</Button>}</p>}<p><Badge tone="info">{visibleSelected.value.status}</Badge> Version {visibleSelected.version}</p><Field label="Integration name" value={selected ? name : visibleSelected.value.name} disabled={!canWrite || mutation.isUnresolved} onChange={(event) => setName(event.target.value)} />{Object.entries(visibleConfiguration).map(([key, value]) => { const reference = key.endsWith("_reference"); return <Field key={key} label={key.replaceAll("_", " ")} value={reference ? "Configured reference" : value} disabled={!canWrite || mutation.isUnresolved || reference} onChange={reference ? undefined : (event) => setConfiguration((current) => ({ ...current, [key]: event.target.value }))} />; })}<p>{isReferenceConnector(visibleSelected.value.connector_key) ? visibleSelected.value.status === "active" ? "Reference authorization is active." : "Authorization uses the configured reference without exposing its value." : "Provider authorization controls are unavailable for this connector."}</p>{selected && <IntegrationDiscoveryPanel freshness={freshness} schedule={schedule} syncs={syncs} syncDetail={syncDetail} cadence={scheduleCadence} canWrite={discoveryWriteAllowed} canSync={manualSyncAllowed} locked={busy || mutation.isUnresolved} onCadence={setScheduleCadence} onSync={queueSync} onSaveSchedule={saveSchedule} onDeleteSchedule={removeSchedule} onOpenSync={openSync} />}</div>}</Modal>
  </div>;
}

function IntegrationDiscoveryPanel({ freshness, schedule, syncs, syncDetail, cadence, canWrite, canSync, locked, onCadence, onSync, onSaveSchedule, onDeleteSchedule, onOpenSync }: {
  freshness: DiscoveryLoad<Versioned<IntegrationFreshness>>;
  schedule: DiscoveryLoad<Versioned<IntegrationSchedule> | null>;
  syncs: DiscoveryLoad<readonly IntegrationSync[]>;
  syncDetail: DiscoveryLoad<Versioned<IntegrationSync>>;
  cadence: string;
  canWrite: boolean;
  canSync: boolean;
  locked: boolean;
  onCadence(value: string): void;
  onSync(): void;
  onSaveSchedule(state?: "enabled" | "disabled"): void;
  onDeleteSchedule(): void;
  onOpenSync(syncID: string): void;
}) {
  const cadenceValue = Number(cadence);
  const cadenceValid = Number.isSafeInteger(cadenceValue) && cadenceValue >= 300 && cadenceValue <= 2_678_400;
  return <section aria-label="Automatic discovery" className="form-stack">
    <h3>Automatic discovery</h3>
    {freshness.status === "loading" && <p>Loading discovery freshness…</p>}
    {freshness.status === "error" && <p>Discovery freshness is unavailable.</p>}
    {freshness.status === "success" && freshness.value && <div aria-label="Projection freshness">
      <p>Risk projection: {freshness.value.value.projections.risk.state}</p>
      <p>Graph projection: {freshness.value.value.projections.graph.state}</p>
      <p>Search projection: {freshness.value.value.projections.search.state}</p>
      {freshness.value.value.last_good && <p>Last good inventory: {freshness.value.value.last_good.discovered_count} discovered · {freshness.value.value.last_good.changed_count} changed · {freshness.value.value.last_good.removed_count} removed</p>}
    </div>}
    {canSync && <Button variant="primary" disabled={locked} onClick={onSync}>Sync inventory now</Button>}
    <h3>Automatic sync schedule</h3>
    {schedule.status === "loading" && <p>Loading automatic sync schedule…</p>}
    {schedule.status === "error" && <p>Automatic sync schedule is unavailable.</p>}
    {schedule.status === "success" && <>
      {schedule.value ? <><p>Every {schedule.value.value.cadence_seconds} seconds · {schedule.value.value.time_zone}</p><p>Schedule state: {schedule.value.value.state}</p></> : <p>No automatic sync schedule.</p>}
      {canWrite && <div className="form-stack"><Field label="Automatic sync cadence seconds" value={cadence} disabled={locked} onChange={(event) => onCadence(event.target.value)} /><div className="button-row"><Button disabled={locked || !cadenceValid} onClick={() => onSaveSchedule()}>Save automatic sync</Button>{schedule.value && <Button disabled={locked || !cadenceValid} onClick={() => onSaveSchedule(schedule.value?.value.state === "enabled" ? "disabled" : "enabled")}>{schedule.value.value.state === "enabled" ? "Disable" : "Enable"} automatic sync</Button>}{schedule.value && <Button variant="danger" disabled={locked} onClick={onDeleteSchedule}>Delete automatic sync</Button>}</div></div>}
    </>}
    <h3>Sync history</h3>
    {syncs.status === "loading" && <p>Loading sync history…</p>}
    {syncs.status === "error" && <p>Sync history is unavailable.</p>}
    {syncs.status === "success" && (syncs.value?.length ? <div className="connection-list">{syncs.value.map((value) => <button type="button" key={value.id} disabled={locked} aria-label={`Open ${value.status} sync`} onClick={() => onOpenSync(value.id)}><strong>{value.status}</strong><span>{value.trigger_kind}</span><span>{value.discovered_count} discovered</span></button>)}</div> : <p>No sync history.</p>)}
    {syncDetail.status === "loading" && <p>Loading sync detail…</p>}
    {syncDetail.status === "error" && <p>Sync detail is unavailable.</p>}
    {syncDetail.status === "success" && syncDetail.value && <p>Sync detail: {syncDetail.value.value.status} · {syncDetail.value.value.discovered_count} discovered · {syncDetail.value.value.changed_count} changed · {syncDetail.value.value.removed_count} removed</p>}
  </section>;
}

function isReferenceConnector(value: string): value is "aws" | "kubernetes" {
  return value === "aws" || value === "kubernetes";
}

function isFirstPartyConnector(value: string): value is "aws" | "kubernetes" | "github" | "okta" {
  return value === "aws" || value === "kubernetes" || value === "github" || value === "okta";
}

function isReferenceAuthorizationCandidate(value: Integration): value is Integration & { connector_key: "aws" | "kubernetes" } {
  return isReferenceConnector(value.connector_key) && (value.status === "configured" || value.status === "pending_authorization" || value.status === "degraded");
}
