"use client";

import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";

import { APIProductError, APITransportError } from "../../../apps/web/api/client";
import type { IntegrationWebhookTestStatus } from "../../../apps/web/api/generated";
import type { ConnectorManifest, Integration, IntegrationAuthorization, IntegrationFreshness, IntegrationInput, IntegrationSchedule, IntegrationScheduleInput, IntegrationSetupStatus, IntegrationSync, IntegrationUpdateInput, Policy, PolicyRollout, PolicySimulation, RuntimeDecision } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { useOptionalSession, useSession } from "../../auth/SessionProvider";
import { Badge, Button, Card, EmptyState, Field, LoadingState, Modal, PageHeader } from "../../components/ui";
import { AgentPurposeDraft } from "../policies/AgentPurposeDraft";
import "../policies/policy-forms.css";
import { PolicyDefinitionFields, defaultPolicyDefinition, validDefinition, type PolicyDefinition } from "../policies/PolicyDefinitionFields";
import { PolicyExampleSessions, ScopedReplay } from "../policies/ScopedReplay";
import { IntegrationRemediationRole } from "./IntegrationRemediationRole";
import { createNangoIntegrationsAPI, createPoliciesAPI, type IntegrationsAPI, IntegrationDiscoveryConflict, IntegrationRevocationPending, ReferenceAuthorizationConflict, type Versioned, type WorkflowReceipt } from "./api";
import { useRetainedWorkflowMutation } from "./useRetainedWorkflowMutation";
import { Time } from "../../components/time";
import { isSaaSCallback } from "./saasSignIn";
import { ConnectorCatalog } from "./ConnectorCatalog";

type Feedback = { tone: "status" | "alert"; message: string } | null;
type PolicyMutationIntent =
  | { kind: "create"; value: Policy }
  | { kind: "update"; id: string; version: string; value: Policy }
  | { kind: "rollout"; id: string; version: string; value: Policy; state: "monitor" | "enforced"; targetID: string }
  | { kind: "disable"; id: string; version: string; value: Policy }
  | { kind: "delete"; id: string; version: string };
type PolicyMutationResult =
  | { kind: "created" | "updated"; receipt: WorkflowReceipt<Policy> }
  | { kind: "deleted"; receipt: WorkflowReceipt<void>; id: string }
  | { kind: "rolled"; receipt: WorkflowReceipt<PolicyRollout>; value: Policy; state: "monitor" | "enforced" | "disabled" };
type IntegrationMutationIntent =
  | { kind: "create"; value: IntegrationInput }
  | { kind: "update"; id: string; version: string; value: IntegrationUpdateInput }
  | { kind: "authorize-oauth"; id: string; connectorKey: string; version: string }
  | { kind: "authorize-reference"; id: string; version: string; connectorKey: ReferenceConnectorKey }
  | { kind: "sync"; id: string; version: string }
  | { kind: "webhook-test"; id: string; version: string }
  | { kind: "put-schedule"; id: string; version: string; value: IntegrationScheduleInput }
  | { kind: "delete-schedule"; id: string; version: string }
  | { kind: "delete"; id: string; version: string };
type IntegrationMutationResult =
  | { kind: "webhook-tested"; status: IntegrationWebhookTestStatus }
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

function PolicyRiskField({ label, value, disabled, onChange }: { label: string; value: Policy["risk"] | ""; disabled: boolean; onChange(value: Policy["risk"] | ""): void }) {
  return <label className="field"><span>{label}</span><select value={value} disabled={disabled} onChange={event => onChange(event.target.value as Policy["risk"] | "")}><option value="">Unknown (not annotated)</option>{["low", "medium", "high", "critical"].map(risk => <option key={risk} value={risk}>{risk}</option>)}</select></label>;
}

export function ProductionPoliciesView({ canWrite, initialAgent, initialPolicy }: { canWrite: boolean; initialAgent?: string; initialPolicy?: string }) {
  const { client, invalidate } = useAPI();
  const session = useSession();
  const api = useMemo(() => createPoliciesAPI(client), [client]);
  const mutation = useRetainedWorkflowMutation<PolicyMutationIntent>("policies");
  const query = useAPIQuery("workflow:policies", api.listPolicies);
  const [selected, setSelected] = useState<Versioned<Policy> | null>(null);
  const [policyID, setPolicyID] = useState("policy-production");
  const [name, setName] = useState("Production runtime policy");
  const [definition, setDefinition] = useState<PolicyDefinition>(defaultPolicyDefinition);
  const [editedDefinition, setEditedDefinition] = useState<PolicyDefinition | null>(null);
  const [editName, setEditName] = useState("");
  const [risk, setRisk] = useState<Policy["risk"] | "">("");
  const [editRisk, setEditRisk] = useState<Policy["risk"] | "">("");
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
	const [simulation, setSimulation] = useState<DiscoveryLoad<PolicySimulation>>({ status: "idle" });
	const [decisions, setDecisions] = useState<DiscoveryLoad<readonly RuntimeDecision[]>>({ status: "idle" });
	const decisionHistoryGeneration = useRef(0);

  useEffect(() => {
    if (!initialPolicy) return;
    const controller = new AbortController();
    void api.getPolicy(initialPolicy, controller.signal).then(current => {
      if (controller.signal.aborted) return;
      if (current.value.id !== initialPolicy) throw new TypeError("The policy identifier changed");
      setSelected(current);
      setEditName(current.value.name);
      setEditRisk(current.value.risk ?? "");
      const generation = ++decisionHistoryGeneration.current;
      setDecisions({ status: "loading" });
      void api.listPolicyDecisions(initialPolicy, 100, controller.signal).then(
        value => { if (!controller.signal.aborted && generation === decisionHistoryGeneration.current) setDecisions({ status: "success", value }); },
        () => { if (!controller.signal.aborted && generation === decisionHistoryGeneration.current) setDecisions({ status: "error" }); },
      );
    }).catch(() => { if (!controller.signal.aborted) setFeedback({tone:"alert",message:"This policy draft is unavailable in the current environment."}); });
    return () => controller.abort();
  }, [api, initialPolicy]);

  const run = async (action: () => Promise<void>) => {
    setBusy(true); setFeedback(null);
    try { await action(); } catch (error) {
      // 400 means the server refused the fields themselves; a refresh does not help.
      setFeedback({ tone: "alert", message: error instanceof APIProductError && error.status === 400 ? "The server rejected the policy as invalid. Check the policy ID, name and conditions and try again." : "The policy operation was not applied. Refresh the current version and retry." });
    } finally { setBusy(false); }
  };
  const applyMutation = (result: PolicyMutationResult) => {
    setEditedDefinition(null);
    setConfirmDelete(false);
    setSimulation({ status: "idle" });
    decisionHistoryGeneration.current++;
    setDecisions({ status: "idle" });
    if (result.kind === "deleted") {
      setSelected(null); setSimulation({ status: "idle" }); setDecisions({ status: "idle" }); invalidate(["workflow:policies"]); setFeedback({ tone: "status", message: `Policy ${result.id} deleted. Audit ${result.receipt.auditID}` });
      return;
    }
    if (result.kind === "rolled") {
      setSelected({ value: { ...result.value, rollout: result.state }, version: result.receipt.version }); invalidate(["workflow:policies"]); setFeedback({ tone: "status", message: `Policy is ${result.state}. Audit ${result.receipt.auditID}` });
      return;
    }
    setSelected(result.receipt); setEditName(result.receipt.value.name); setEditRisk(result.receipt.value.risk ?? ""); invalidate(["workflow:policies"]); setFeedback({ tone: "status", message: `Policy ${result.kind}. Audit ${result.receipt.auditID}` });
  };
	const runMutation = (operation: () => Promise<PolicyMutationResult>) => void run(async () => { applyMutation(await operation()); });
	const loadDecisions = (id: string) => {
		const generation = ++decisionHistoryGeneration.current;
		setDecisions({ status: "loading" });
		void api.listPolicyDecisions(id).then(
			(value) => { if (decisionHistoryGeneration.current === generation) setDecisions({ status: "success", value }); },
			() => { if (decisionHistoryGeneration.current === generation) setDecisions({ status: "error" }); },
		);
	};
	const open = (id: string) => void run(async () => { const current = await api.getPolicy(id); setEditedDefinition(null); setSelected(current); setEditName(current.value.name); setEditRisk(current.value.risk ?? ""); setSimulation({ status: "idle" }); loadDecisions(id); });
	const simulate = () => selected && void run(async () => {
		setSimulation({ status: "loading" });
		try { setSimulation({ status: "success", value: await api.simulatePolicy(selected.value.id) }); }
		catch (error) { setSimulation({ status: "error" }); throw error; }
	});
  const createDraft = (value: Policy) => void run(async () => {
    if (!canWrite || value.rollout !== "draft" || busy || mutation.isUnresolved) return;
    const intent: PolicyMutationIntent = { kind: "create", value };
    applyMutation(await mutation.execute(intent, async (frozen, attempt) => { if (frozen.kind !== "create") throw new TypeError("Invalid retained policy intent"); return { kind: "created" as const, receipt: await api.createPolicy(frozen.value, attempt) }; }));
  });
  const create = () => createDraft({ id: policyID, name, scope: "environment", ...definition, rollout: "draft", ...(risk ? { risk } : {}) });
  const update = () => selected && runMutation(() => mutation.execute({ kind: "update", id: selected.value.id, version: selected.version, value: { ...selected.value, ...(selected.value.rollout === "draft" && editedDefinition), name: editName, risk: editRisk || undefined } }, async (intent, attempt) => { if (intent.kind !== "update") throw new TypeError("Invalid retained policy intent"); return { kind: "updated", receipt: await api.updatePolicy(intent.id, intent.version, intent.value, attempt) }; }));
  const rollout = (state: "monitor" | "enforced") => selected && session.status === "authenticated" && runMutation(() => mutation.execute({ kind: "rollout", id: selected.value.id, version: selected.version, value: selected.value, state, targetID: session.environmentID }, async (intent, attempt) => { if (intent.kind !== "rollout") throw new TypeError("Invalid retained policy intent"); return { kind: "rolled", receipt: await api.rolloutPolicy(intent.id, intent.version, { state: intent.state, target_id: intent.targetID }, attempt), value: intent.value, state: intent.state }; }));
  const disable = () => selected && runMutation(() => mutation.execute({ kind: "disable", id: selected.value.id, version: selected.version, value: selected.value }, async (intent, attempt) => { if (intent.kind !== "disable") throw new TypeError("Invalid retained policy intent"); return { kind: "rolled", receipt: await api.disablePolicy(intent.id, intent.version, attempt), value: intent.value, state: "disabled" }; }));
  const remove = () => selected && runMutation(() => mutation.execute({ kind: "delete", id: selected.value.id, version: selected.version }, async (intent, attempt) => { if (intent.kind !== "delete") throw new TypeError("Invalid retained policy intent"); return { kind: "deleted", receipt: await api.deletePolicy(intent.id, intent.version, attempt), id: intent.id }; }));
  const retryMutation = () => runMutation(() => mutation.retry<PolicyMutationResult>());
  const sessionScope = session.status === "authenticated" && session.hasCapability("sessions.read") ? session : undefined;
  const policyIDValid = /^policy-[a-z0-9-]+$/.test(policyID);

  return <div className="page policies-page"><PageHeader title="Policies" description="Durable scoped runtime controls with version checks and audit receipts." />
    <FeedbackLine value={feedback} /><QueryBoundary status={query.status} label="policies" onRetry={query.retry} disabled={mutation.isUnresolved} />
    {mutation.canRetry && <p role="alert">The response was lost. The exact operation and idempotency key are retained. <Button disabled={busy} onClick={retryMutation}>Retry retained policy operation</Button></p>}
    {canWrite && <Card title="Create policy"><div className="policy-form-body"><div className="policy-fields policy-fields--identity"><Field label="Policy ID" value={policyID} disabled={mutation.isUnresolved} pattern="policy-[a-z0-9-]+" hint="Starts with policy- followed by lowercase letters, digits or hyphens." error={policyID && !policyIDValid ? "Use the form policy-name, for example policy-production." : undefined} onChange={(event) => setPolicyID(event.target.value)} /><Field label="Name" value={name} disabled={mutation.isUnresolved} maxLength={128} onChange={(event) => setName(event.target.value)} /><PolicyRiskField label="Policy risk" value={risk} disabled={busy || mutation.isUnresolved} onChange={setRisk} /></div><PolicyDefinitionFields label="New policy" value={definition} onChange={setDefinition} disabled={busy || mutation.isUnresolved} templates /><Button variant="primary" disabled={busy || mutation.isUnresolved || !policyIDValid || !name || !validDefinition(definition)} onClick={create}>Create policy</Button></div></Card>}
    <AgentPurposeDraft key={initialAgent ?? "choose-agent"} initialAgent={initialAgent} canManage={canWrite} disabled={busy || mutation.isUnresolved} onCreate={createDraft} />
    <Card title="Authorized policies">{query.data?.length ? <div className="connection-list">{query.data.map((policy) => <button type="button" key={policy.id} disabled={busy || mutation.isUnresolved} onClick={() => open(policy.id)} aria-label={`Open ${policy.name}`}><strong>{policy.name}</strong><span>{policy.action}</span><span>{policy.rollout}</span></button>)}</div> : query.status === "empty" ? <EmptyState title="No policies" description="Create the first scoped runtime policy when write access is enabled." /> : null}</Card>
		{selected && <Card title={`Policy detail · ${selected.value.id}`}><div className="policy-form-body"><p><Badge tone="info">{selected.value.rollout}</Badge> Version {selected.version}</p><p>Rollout changes the policy in this Environment. Review its conditions and runtime decisions before enforcement. Sensors → Devices shows the cohort and acknowledged revision for each managed device’s signed ticket rule.</p><div className="policy-fields"><Field label="Policy name" value={editName} disabled={!canWrite || busy || mutation.isUnresolved} onChange={(event) => setEditName(event.target.value)} /><PolicyRiskField label="Edit policy risk" value={editRisk} disabled={!canWrite || busy || mutation.isUnresolved} onChange={setEditRisk} /></div>{canWrite && selected.value.rollout === "draft" && <PolicyDefinitionFields label="Draft policy" value={editedDefinition ?? selected.value} onChange={setEditedDefinition} disabled={busy || mutation.isUnresolved} />}<p>{selected.value.conditions.map((condition) => `${condition.field} ${condition.operator} ${condition.value}`).join(", ")}</p>{canWrite && <div className="button-row"><Button disabled={busy || mutation.isUnresolved || (editedDefinition !== null && !validDefinition(editedDefinition))} onClick={update}>Save changes</Button><Button disabled={busy || mutation.isUnresolved || simulation.status === "loading"} onClick={simulate}>Simulate against runtime history</Button>{selected.value.rollout === "draft" && <Button disabled={busy || mutation.isUnresolved} onClick={() => rollout("monitor")}>Roll to monitor</Button>}{selected.value.rollout === "monitor" && <Button variant="primary" disabled={busy || mutation.isUnresolved} onClick={() => rollout("enforced")}>Enforce policy</Button>}{selected.value.rollout === "enforced" && <Button disabled={busy || mutation.isUnresolved} title="Restore the preceding monitor state for an unedited enforcement revision" onClick={() => rollout("monitor")}>Return to monitor</Button>}{(selected.value.rollout === "monitor" || selected.value.rollout === "enforced") && <Button disabled={busy || mutation.isUnresolved} onClick={disable}>Disable policy</Button>}{confirmDelete ? <><Button variant="danger" disabled={busy || mutation.isUnresolved} onClick={remove}>Confirm delete of {selected.value.id}</Button><Button disabled={busy} onClick={() => setConfirmDelete(false)}>Keep policy</Button></> : <Button variant="danger" disabled={busy || mutation.isUnresolved} onClick={() => setConfirmDelete(true)}>Delete policy</Button>}</div>}{canWrite && <ScopedReplay key={`${selected.value.id}/${selected.version}`} policy={selected.value} version={selected.version} sessionScope={sessionScope} disabled={busy || mutation.isUnresolved} runReplay={input => api.replayPolicy(selected.value.id, input)} />}{simulation.status === "loading" && <LoadingState label="Simulating policy…" />}{simulation.status === "error" && <p role="alert">Policy simulation is unavailable.</p>}{simulation.status === "success" && simulation.value && <div><p>{simulation.value.matches} matched historical actions · {simulation.value.would_block} would block</p><p>This preview evaluates up to 100 indexed events in this Environment. Scoped replay evaluates up to 5,000 indexed events for a selected agent, time window and policy revision.</p><PolicyExampleSessions ids={simulation.value.example_session_ids} scope={sessionScope} /></div>}</div></Card>}
		{selected && <Card title="Runtime decision history">{decisions.status === "loading" && <LoadingState label="Loading policy decisions…" />}{decisions.status === "error" && <p role="alert">Runtime decision history is unavailable. <Button disabled={busy} onClick={() => loadDecisions(selected.value.id)}>Retry</Button></p>}{decisions.status === "success" && decisions.value?.length ? <ul>{decisions.value.map((decision) => <li key={decision.id}><strong>{decision.result} · {decision.at}</strong><span>{decision.correlation_id}</span></li>)}</ul> : decisions.status === "success" ? <EmptyState title="No runtime decisions" description="This policy has no durable runtime decisions in the current tenant scope." /> : null}</Card>}
  </div>;
}

type IntegrationsProps = { canWrite: boolean; navigateAuthorization?: (target: string) => void; navigate?: (target: string) => void; location?: string };
export function ProductionIntegrationsView(props: IntegrationsProps) {
  const session = useOptionalSession();
  const {client, queryScopeKey, queryGeneration} = useAPI();
  const api = useMemo(() => createNangoIntegrationsAPI(client), [client]);
  const principal = session?.status === "authenticated" ? session.principal.id : null;
  const location = props.location ?? (typeof window === "undefined" ? "" : window.location.pathname + window.location.search + window.location.hash);
  if (isSaaSCallback(location)) return <div className="page"><PageHeader title="Provider sign-in" /><Card><p>Return to the Zasp tab where you started sign-in and select <strong>Finish sign-in</strong>. You can close this tab.</p></Card></div>;
  return <IntegrationsWorkspace key={JSON.stringify([principal,queryScopeKey,queryGeneration,props.canWrite])} api={api} {...props} location={location} />;
}

type InPageSignIn = { authorization: IntegrationAuthorization; integrationID: string; version: string; owner: string; epoch: number; sessionGeneration: number; scopeGeneration: number };

export function IntegrationsWorkspace({ api, canWrite, location, navigateAuthorization = defaultNavigateAuthorization, navigate = defaultNavigateProduct }: IntegrationsProps & { api: IntegrationsAPI }) {
  const { invalidate, queryScopeKey, queryGeneration, getSessionInvalidationGeneration, getScopeStaleGeneration } = useAPI();
  const session = useOptionalSession();
  const fresh = session !== null && session.status === "authenticated" && session.isFreshAuthenticated;
  const scope = session?.status === "authenticated" ? `${session.organizationID}/${session.workspaceID}/${session.environmentID}` : null;
  const owner = session?.status === "authenticated" && canWrite && session.hasCapability("integrations.write") && queryScopeKey === scope && scope
    ? `${session.principal.id}/${scope}/${queryGeneration}` : null;
  const activeOwner = useRef<string | null>(null);
  const epoch = useRef(0);
  const initiatingRequest = useRef<{ id: string; version: string; epoch: number } | null>(null);
  const [pendingSignIn, setPendingSignIn] = useState<InPageSignIn | null>(null);
  useLayoutEffect(() => {
    activeOwner.current = owner;
    return () => { activeOwner.current = null; epoch.current += 1; };
  }, [owner]);
  const ownsSignIn = (key: string, sequence: number, expiry: number, stale: number) =>
    activeOwner.current === key && epoch.current === sequence && expiry === getSessionInvalidationGeneration() && stale === getScopeStaleGeneration();
  const mutation = useRetainedWorkflowMutation<IntegrationMutationIntent>("integrations", canWrite);
  const catalog = useAPIQuery("workflow:integration-catalog", api.listCatalog);
  const integrations = useAPIQuery("workflow:integrations", api.listIntegrations);
  const [manifest, setManifest] = useState<ConnectorManifest | null>(null);
  const [configuration, setConfiguration] = useState<Record<string, string>>({});
  const [name, setName] = useState("");
  const [selected, setSelected] = useState<Versioned<Integration> | null>(null);
  useLayoutEffect(() => () => { epoch.current += 1; }, [selected?.value.id, selected?.version]);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [busy, setBusy] = useState(false);
  const [freshness, setFreshness] = useState<DiscoveryLoad<Versioned<IntegrationFreshness>>>({ status: "idle" });
  const [setupStatus, setSetupStatus] = useState<DiscoveryLoad<IntegrationSetupStatus>>({ status: "idle" });
  const [webhookStatus, setWebhookStatus] = useState<DiscoveryLoad<IntegrationWebhookTestStatus | null>>({ status: "idle" });
  const [schedule, setSchedule] = useState<DiscoveryLoad<Versioned<IntegrationSchedule> | null>>({ status: "idle" });
  const [syncs, setSyncs] = useState<DiscoveryLoad<readonly IntegrationSync[]>>({ status: "idle" });
  const [syncDetail, setSyncDetail] = useState<DiscoveryLoad<Versioned<IntegrationSync>>>({ status: "idle" });
  const [scheduleCadence, setScheduleCadence] = useState("3600");
  const discoveryGeneration = useRef(0);
  const discoveryRefreshGeneration = useRef(0);
  const syncDetailGeneration = useRef(0);
  const selectedSyncID = useRef<string | null>(null);
  useEffect(() => () => {
    discoveryGeneration.current += 1;
    discoveryRefreshGeneration.current += 1;
    syncDetailGeneration.current += 1;
  }, []);
  const [revocationClock, setRevocationClock] = useState(() => Date.now());
  const pendingRevocation = mutation.knownPending?.kind === "integration_revocation" ? mutation.knownPending : null;
  const pendingReferenceConflict = mutation.knownPending?.kind === "reference_authorization_conflict" ? mutation.knownPending : null;
  const pendingDiscoveryConflict = mutation.knownPending?.kind === "integration_discovery_conflict" ? mutation.knownPending : null;
  const retainedReferenceAuthorization = mutation.retainedIntent?.kind === "authorize-reference";
  const retainedOAuthAuthorization = mutation.retainedIntent?.kind === "authorize-oauth";
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
    if (result.kind === "webhook-tested") {
      setWebhookStatus({ status: "success", value: result.status });
      setFeedback({ tone: result.status.delivery_status === "succeeded" ? "status" : "alert", message: `Webhook test ${result.status.delivery_status}. Audit ${result.status.audit_id}` });
      return;
    }
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
    loadDiscovery(result.receipt.value);
    setManifest(null); setFeedback({ tone: "status", message: `Integration ${result.kind}. Audit ${result.receipt.auditID}` });
  };
  const runMutation = (operation: () => Promise<IntegrationMutationResult>) => void run(async () => { applyMutation(await operation()); });
  const choose = (value: ConnectorManifest) => { setManifest(value); setName(value.provider); setConfiguration(Object.fromEntries(value.setup_schema.map((field) => [field.key, ""]))); };
  // An optional setup field left empty is not part of the configuration.
  const create = () => manifest && runMutation(() => mutation.execute({ kind: "create", value: { connector_key: manifestConnectorKey(manifest), name, configuration: manifestConfiguration(manifest, configuration) } }, async (intent, attempt) => { if (intent.kind !== "create") throw new TypeError("Invalid retained integration intent"); return { kind: "created", receipt: await api.createIntegration(intent.value, attempt) }; }));
  const loadDiscovery = (integration: Integration) => {
    const id = integration.id;
    const generation = discoveryGeneration.current + 1;
    discoveryGeneration.current = generation;
    discoveryRefreshGeneration.current += 1;
    syncDetailGeneration.current += 1;
    selectedSyncID.current = null;
    setWebhookStatus({ status: "idle" });
    if (integration.connector_key === "generic-webhook") {
      setFreshness({ status: "idle" }); setSetupStatus({ status: "idle" }); setSchedule({ status: "idle" }); setSyncs({ status: "idle" }); setSyncDetail({ status: "idle" });
      setWebhookStatus({ status: "loading" });
      void api.getIntegrationWebhookStatus(id).then((value) => { if (discoveryGeneration.current === generation) setWebhookStatus({ status: "success", value }); }, () => { if (discoveryGeneration.current === generation) setWebhookStatus({ status: "error" }); });
      return;
    }
    setFreshness({ status: "loading" }); setSetupStatus({ status: "loading" }); setSchedule({ status: "loading" }); setSyncs({ status: "loading" }); setSyncDetail({ status: "idle" });
    void api.getIntegrationFreshness(id).then((value) => { if (discoveryGeneration.current === generation) setFreshness({ status: "success", value }); }, () => { if (discoveryGeneration.current === generation) setFreshness({ status: "error" }); });
    void api.getIntegrationSetupStatus(id).then((value) => { if (discoveryGeneration.current === generation) setSetupStatus({ status: "success", value }); }, () => { if (discoveryGeneration.current === generation) setSetupStatus({ status: "error" }); });
    void api.getIntegrationSchedule(id).then((value) => { if (discoveryGeneration.current === generation) { setSchedule({ status: "success", value }); if (value) setScheduleCadence(String(value.value.cadence_seconds)); } }, () => { if (discoveryGeneration.current === generation) setSchedule({ status: "error" }); });
    void api.listIntegrationSyncs(id).then((value) => { if (discoveryGeneration.current === generation) setSyncs({ status: "success", value }); }, () => { if (discoveryGeneration.current === generation) setSyncs({ status: "error" }); });
  };
  const open = (id: string) => void run(async () => { epoch.current += 1; setPendingSignIn(null); const value = await api.getIntegration(id); setSelected(value); setName(value.value.name); setConfiguration({ ...value.value.configuration }); loadDiscovery(value.value); });
  const testWebhook = () => {
    if (!selected || selected.value.connector_key !== "generic-webhook") return;
    discoveryGeneration.current += 1;
    runMutation(() => mutation.execute({ kind: "webhook-test", id: selected.value.id, version: selected.version }, async (intent, attempt) => {
      if (intent.kind !== "webhook-test") throw new TypeError("Invalid retained webhook test intent");
      return { kind: "webhook-tested", status: await api.testIntegrationWebhook(intent.id, intent.version, attempt) };
    }));
  };
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
  const startOAuth = async (intent: Extract<IntegrationMutationIntent, { kind: "authorize-oauth" }>, request: () => Promise<IntegrationAuthorization>, replay = false) => {
    if (intent.connectorKey !== SAAS_CONNECTOR_KEY) { navigateAuthorization((await request()).authorization_url); return; }
    if (!owner || !fresh) throw new Error("Sign-in requires current access");
    const previous = initiatingRequest.current;
    if (replay && (previous?.id !== intent.id || previous.version !== intent.version || previous.epoch !== epoch.current)) {
      // Resolve the retained transport result without adopting another view's sign-in.
      await request();
      if (activeOwner.current === owner) setFeedback({ tone: "status", message: "The earlier request was reconciled. Start a new sign-in in this tab." });
      return;
    }
    const sequence = ++epoch.current;
    initiatingRequest.current = {id: intent.id, version: intent.version, epoch: sequence};
    const expiry = getSessionInvalidationGeneration(), stale = getScopeStaleGeneration();
    setPendingSignIn(null);
    const authorization = await request();
    if (ownsSignIn(owner, sequence, expiry, stale)) setPendingSignIn({ authorization, integrationID: intent.id, version: intent.version, owner, epoch: sequence, sessionGeneration: expiry, scopeGeneration: stale });
  };
  const authorizeOAuth = () => {
    if (!selected || !isOAuthAuthorizationCandidate(selected.value, selectedManifest) || session?.status !== "authenticated") return;
    const intent = { kind: "authorize-oauth", id: selected.value.id, connectorKey: selected.value.connector_key, version: selected.version } as const;
    void run(() => startOAuth(intent, () => mutation.execute(intent, async (frozen, attempt) => {
      if (frozen.kind !== "authorize-oauth") throw new TypeError("Invalid retained OAuth authorization intent");
      return api.authorizeIntegration(frozen.id, attempt);
    })));
  };
  const activeSignIn = pendingSignIn && pendingSignIn.owner === owner && pendingSignIn.integrationID === selected?.value.id && pendingSignIn.version === selected.version ? pendingSignIn : null;
  useEffect(() => {
    if (!activeSignIn) return;
    const timer = window.setTimeout(() => {
      if (epoch.current !== activeSignIn.epoch) return;
      epoch.current += 1;
      setPendingSignIn(null);
      setFeedback({ tone: "alert", message: "This provider sign-in expired. Start a new sign-in." });
    }, Math.max(0, Date.parse(activeSignIn.authorization.expires_at) - Date.now()));
    return () => window.clearTimeout(timer);
  }, [activeSignIn]);
  const finishSignIn = () => {
    const pending = activeSignIn;
    if (!pending || busy) return;
    const owns = () => ownsSignIn(pending.owner, pending.epoch, pending.sessionGeneration, pending.scopeGeneration) && Date.now() < Date.parse(pending.authorization.expires_at);
    const stop = (message: string) => {
      epoch.current += 1;
      setPendingSignIn(null);
      setFeedback({ tone: "alert", message });
    };
    void run(async () => {
      if (Date.now() >= Date.parse(pending.authorization.expires_at)) {
        stop("This provider sign-in expired. Start a new sign-in.");
        return;
      }
      if (!owns()) return;
      let status: Awaited<ReturnType<typeof api.getSaaSSignInStatus>>;
      try {
        status = await api.getSaaSSignInStatus(pending.integrationID, pending.authorization.authorization_attempt_id);
      } catch (error) {
        if (!owns()) return;
        if ((error instanceof APIProductError && [401, 403, 404, 409, 410].includes(error.status)) || (error instanceof APITransportError && error.kind === "invalid_response")) {
          stop("This sign-in is no longer available in this session. Start a new sign-in.");
          return;
        }
        setFeedback({ tone: "alert", message: "Could not verify the sign-in. Select Finish sign-in to check again." }); return;
      }
      if (!owns()) return;
      if (pending.version !== `"${status.integration_version}"` || status.status === "superseded") { stop("The integration or sign-in attempt changed. Reopen the integration and start again."); return; }
      if (status.status === "failed") { stop(saasSignInFailure(status.failure_code ?? "")); return; }
      if (status.status !== "completed" || !status.connection_reference) { setFeedback({ tone: "status", message: "Waiting for the provider. Complete sign-in in the provider tab, then check again." }); return; }
      let current: Versioned<Integration>;
      try {
        current = await api.getIntegration(pending.integrationID);
      } catch (error) {
        if (!owns()) return;
        if (error instanceof APIProductError && [401, 403, 404].includes(error.status)) {
          stop("The integration is no longer available in this session.");
        } else {
          setFeedback({ tone: "alert", message: "Could not confirm the integration version. Select Finish sign-in to check again." });
        }
        return;
      }
      if (!owns()) return;
      if (current.value.id !== pending.integrationID || current.version !== pending.version || current.value.connector_key !== SAAS_CONNECTOR_KEY || current.value.configuration.connection_reference !== undefined) { stop("The integration configuration changed. Reopen the integration before signing in again."); return; }
      const value = { name: current.value.name, configuration: { ...current.value.configuration, connection_reference: status.connection_reference } };
      const result = await mutation.execute({ kind: "update", id: pending.integrationID, version: pending.version, value }, async (intent, attempt) => {
        if (intent.kind !== "update" || !owns()) throw new Error("Sign-in authority changed");
        return { kind: "updated" as const, receipt: await api.updateIntegration(intent.id, intent.version, intent.value, attempt) };
      });
      if (!owns()) return;
      epoch.current += 1; setPendingSignIn(null); applyMutation(result);
      setFeedback({ tone: "status", message: "Signed in. Authorize the integration to start collecting." });
    });
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
  const loadSyncDetail = (integrationID: string, syncID: string) => {
    const generation = discoveryGeneration.current;
    const detailGeneration = ++syncDetailGeneration.current;
    selectedSyncID.current = syncID;
    setSyncDetail({ status: "loading" });
    const current = () => discoveryGeneration.current === generation && syncDetailGeneration.current === detailGeneration;
    void api.getIntegrationSync(integrationID, syncID).then(
      (value) => { if (current()) setSyncDetail({ status: "success", value }); },
      () => { if (current()) setSyncDetail({ status: "error" }); },
    );
  };
  const openSync = (syncID: string) => {
    if (selected) loadSyncDetail(selected.value.id, syncID);
  };
  const refreshDiscovery = () => {
    if (!selected) return;
    const id = selected.value.id;
    const generation = discoveryGeneration.current;
    const refreshGeneration = ++discoveryRefreshGeneration.current;
    const current = () => discoveryGeneration.current === generation && discoveryRefreshGeneration.current === refreshGeneration;
    setFreshness({ status: "loading" });
    setSyncs({ status: "loading" });
    void api.getIntegrationFreshness(id).then(
      (value) => { if (current()) setFreshness({ status: "success", value }); },
      () => { if (current()) setFreshness({ status: "error" }); },
    );
    void api.listIntegrationSyncs(id).then(
      (value) => { if (current()) setSyncs({ status: "success", value }); },
      () => { if (current()) setSyncs({ status: "error" }); },
    );
    if (selectedSyncID.current) loadSyncDetail(id, selectedSyncID.current);
  };
  const remove = () => selected && runMutation(() => mutation.execute({ kind: "delete", id: selected.value.id, version: selected.version }, async (intent, attempt) => { if (intent.kind !== "delete") throw new TypeError("Invalid retained integration intent"); return { kind: "deleted", receipt: await api.deleteIntegration(intent.id, intent.version, attempt) }; }));
  const retryMutation = () => {
    if (retainedReferenceAuthorization && !fresh) return;
    void run(() => retainedReferenceAuthorization
      ? applyReferenceAuthorization(() => mutation.retry<IntegrationMutationResult>())
      : retainedOAuthAuthorization
        ? startOAuth(mutation.retainedIntent as Extract<IntegrationMutationIntent, { kind: "authorize-oauth" }>, () => mutation.retry<IntegrationAuthorization>(), true)
      : mutation.retry<IntegrationMutationResult>().then((result) => { applyMutation(result); }));
  };
  const retryReferenceConflictRefetch = () => pendingReferenceConflict && void run(() => reconcileReferenceConflict(pendingReferenceConflict.integrationID));
  const retryDiscoveryConflictRefetch = () => pendingDiscoveryConflict && void run(() => reconcileDiscoveryConflict(pendingDiscoveryConflict));
  const closeSelected = () => { epoch.current += 1; setPendingSignIn(null); discoveryGeneration.current += 1; discoveryRefreshGeneration.current += 1; syncDetailGeneration.current += 1; selectedSyncID.current = null; setSelected(null); setFreshness({ status: "idle" }); setSetupStatus({ status: "idle" }); setSchedule({ status: "idle" }); setSyncs({ status: "idle" }); setSyncDetail({ status: "idle" }); };
  const visibleSelected = selected ?? pendingRevocation?.receipt ?? null;
  const visibleConfiguration = selected ? configuration : pendingRevocation?.receipt.value.configuration ?? configuration;
  const revocationPending = visibleSelected?.value.status === "revoking" && mutation.isUnresolved && pendingRevocation !== null;
  const revocationRetryReady = pendingRevocation === null || revocationClock >= pendingRevocation.retryNotBefore;
  const referenceAuthorizationCandidate = selected !== null && isReferenceAuthorizationCandidate(selected.value);
  const selectedManifest = selected ? catalog.data?.find((value) => manifestServes(value, selected.value)) : undefined;
  const oauthAuthorizationCandidate = selected !== null && isOAuthAuthorizationCandidate(selected.value, selectedManifest) && session?.status === "authenticated";
  const discoveryWriteAllowed = Boolean(canWrite && selected?.value.status === "active" && isFirstPartyConnector(selected.value.connector_key) && selectedManifest?.actions.includes("inventory_read"));
  const manualSyncAllowed = discoveryWriteAllowed && freshness.status === "success" && syncs.status === "success";
  return (
    <div className="page">
      <PageHeader
        title="Integrations"
        description="Durable connector configuration, provider authorization, and automatic inventory discovery."
      />
      {!visibleSelected && <FeedbackLine value={feedback} />}
      {mutation.canRetry && !visibleSelected && (
        <p role="alert">
          The response was lost. The exact operation and idempotency key are
          retained.{" "}
          <Button
            disabled={busy || (retainedReferenceAuthorization && !fresh)}
            onClick={retryMutation}
          >
            Retry retained integration operation
          </Button>
        </p>
      )}
      <QueryBoundary
        status={integrations.status}
        label="integrations"
        onRetry={integrations.retry}
        disabled={mutation.isUnresolved}
      />
      <Card title="Configured integrations">
        {integrations.data?.length ? (
          <div className="connection-list">
            {integrations.data.map((value) => (
              <button
                type="button"
                key={value.id}
                disabled={busy || mutation.isUnresolved}
                aria-label={`Open ${value.name}`}
                onClick={() => open(value.id)}
              >
                <strong>{value.name}</strong>
                <span>{integrationConnectorLabel(value)}</span>
                <span>{value.status}</span>
              </button>
            ))}
          </div>
        ) : integrations.status === "empty" ? (
          <EmptyState
            title="No integrations"
            description={canWrite ? "Choose a provider under Add a source to connect this environment." : "Ask an environment administrator to connect a Nango source for this environment."}
          />
        ) : null}
      </Card>
      <QueryBoundary
        status={catalog.status}
        label="integration catalog"
        onRetry={catalog.retry}
        disabled={mutation.isUnresolved}
      />
      {canWrite && (catalog.status === "success" || catalog.status === "empty") && (
        <Card title="Add a source">
          <ConnectorCatalog focusSearch={location === "/connectors#add-source"} manifests={catalog.data ?? []} disabled={busy || mutation.isUnresolved} onChoose={choose} onRefresh={catalog.retry} />
        </Card>
      )}
      <Modal
        open={manifest !== null}
        title={`Configure ${manifest?.provider ?? "integration"}`}
        closeDisabled={mutation.isUnresolved}
        onClose={() => setManifest(null)}
        footer={
          <>
            <Button
              disabled={mutation.isUnresolved}
              onClick={() => setManifest(null)}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              disabled={
                busy ||
                mutation.isUnresolved ||
                !name ||
                manifest?.setup_schema.some(
                  (field) => field.required && !configuration[field.key],
                )
              }
              onClick={create}
            >
              Save integration
            </Button>
          </>
        }
      >
        {manifest && (
          <div className="form-stack">
            {mutation.canRetry && (
              <p role="alert">
                The response was lost. The exact operation and idempotency key
                are retained.{" "}
                <Button disabled={busy} onClick={retryMutation}>
                  Retry retained integration operation
                </Button>
              </p>
            )}
            <IntegrationSetupGuide manifest={manifest} />
            <p>{manifest.access_guidance}</p>
            <Field
              label="Integration name"
              value={name}
              disabled={mutation.isUnresolved}
              onChange={(event) => setName(event.target.value)}
            />
            {manifest.setup_schema.map((field) => (
              <Field
                key={field.key}
                label={field.label}
                hint={field.description}
                value={configuration[field.key] ?? ""}
                type={field.type === "secret_reference" ? "password" : field.type === "uri" ? "url" : "text"}
                disabled={mutation.isUnresolved}
                onChange={(event) =>
                  setConfiguration((current) => ({
                    ...current,
                    [field.key]: event.target.value,
                  }))
                }
              />
            ))}
          </div>
        )}
      </Modal>
      <Modal
        open={visibleSelected !== null}
        title={visibleSelected?.value.name ?? "Integration"}
        closeDisabled={mutation.isUnresolved}
        onClose={closeSelected}
        footer={
          <>
            <Button disabled={mutation.isUnresolved} onClick={closeSelected}>
              Close
            </Button>
            {canWrite && (
              <>
                {referenceAuthorizationCandidate && (
                  <Button
                    variant="primary"
                    disabled={busy || mutation.isUnresolved || !fresh}
                    onClick={authorizeReference}
                  >
                    Authorize{" "}
                    {referenceConnectorLabel(selected?.value.connector_key, selectedManifest)}{" "}
                    reference
                  </Button>
                )}
                {oauthAuthorizationCandidate && !activeSignIn && (
                  <Button
                    variant="primary"
                    disabled={busy || mutation.isUnresolved || (selected?.value.connector_key === SAAS_CONNECTOR_KEY && (!owner || !fresh))}
                    onClick={authorizeOAuth}
                  >
                    {selected?.value.connector_key === SAAS_CONNECTOR_KEY ? "Sign in to" : "Authorize"} {selectedManifest?.provider ?? selected?.value.connector_key}
                  </Button>
                )}
                {oauthAuthorizationCandidate && selected?.value.connector_key === SAAS_CONNECTOR_KEY && !fresh && session?.status === "authenticated" && <Button onClick={session.reauthenticate}>Reauthenticate to start sign-in</Button>}
                {activeSignIn && <section aria-label="Provider sign-in">
                  <a href={activeSignIn.authorization.authorization_url} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">Continue to provider</a>
                  <p>Complete sign-in in the provider tab, then return here.</p>
                  <Button variant="primary" disabled={busy || mutation.isUnresolved} onClick={finishSignIn}>Finish sign-in</Button>
                  <Button disabled={busy || mutation.isUnresolved || !fresh} onClick={authorizeOAuth}>Start a new sign-in</Button>
                </section>}
                <Button
                  disabled={busy || mutation.isUnresolved}
                  onClick={update}
                >
                  Save changes
                </Button>
                <Button
                  variant="danger"
                  disabled={busy || mutation.isUnresolved}
                  onClick={remove}
                >
                  Delete integration
                </Button>
              </>
            )}
          </>
        }
      >
        {visibleSelected && (
          <div className="form-stack">
            {pendingReferenceConflict ? (
              <>
                <FeedbackLine value={feedback} />
                <Button disabled={busy} onClick={retryReferenceConflictRefetch}>
                  Retry authoritative integration refetch
                </Button>
              </>
            ) : pendingDiscoveryConflict ? (
              <>
                <FeedbackLine value={feedback} />
                <Button disabled={busy} onClick={retryDiscoveryConflictRefetch}>
                  Retry authoritative discovery refetch
                </Button>
              </>
            ) : (
              !revocationPending &&
              !mutation.canRetry && <FeedbackLine value={feedback} />
            )}
            {revocationPending ? (
              <p role="status">
                Provider revocation is pending. The exact DELETE and idempotency
                key are retained.{" "}
                {mutation.canRetry && (
                  <Button
                    disabled={busy || !revocationRetryReady}
                    onClick={retryMutation}
                  >
                    Retry pending integration deletion
                  </Button>
                )}
              </p>
            ) : (
              !pendingReferenceConflict &&
              !pendingDiscoveryConflict &&
              mutation.canRetry && (
                <p role="alert">
                  The response was lost. The exact operation and idempotency key
                  are retained.{" "}
                  <Button
                    disabled={
                      busy || (retainedReferenceAuthorization && !fresh)
                    }
                    onClick={retryMutation}
                  >
                    Retry retained integration operation
                  </Button>
                </p>
              )
            )}
            {canWrite && retainedReferenceAuthorization && !fresh && (
              <p role="alert">
                Fresh authentication is required to retry this reference
                authorization.{" "}
                {session?.status === "authenticated" && (
                  <Button onClick={session.reauthenticate}>
                    Reauthenticate
                  </Button>
                )}
              </p>
            )}
            {canWrite &&
              referenceAuthorizationCandidate &&
              !retainedReferenceAuthorization &&
              !fresh && (
                <p role="alert">
                  Fresh authentication is required to authorize this reference.{" "}
                  {session?.status === "authenticated" && (
                    <Button onClick={session.reauthenticate}>
                      Reauthenticate
                    </Button>
                  )}
                </p>
              )}
            <p>
              <Badge tone="info">{visibleSelected.value.status}</Badge> Version{" "}
              {visibleSelected.version}
            </p>
            <Field
              label="Integration name"
              value={selected ? name : visibleSelected.value.name}
              disabled={!canWrite || mutation.isUnresolved}
              onChange={(event) => setName(event.target.value)}
            />
            {Object.entries(visibleConfiguration).map(([key, value]) => {
              const reference = key.endsWith("_reference");
              // The platform of a saas integration is what the integration is; it is not edited.
              const fixed = visibleSelected.value.connector_key === SAAS_CONNECTOR_KEY && key === "platform";
              return (
                <Field
                  key={key}
                  label={key.replaceAll("_", " ")}
                  value={reference ? "Configured reference" : value}
                  disabled={!canWrite || mutation.isUnresolved || reference || fixed}
                  onChange={
                    reference
                      ? undefined
                      : (event) =>
                          setConfiguration((current) => ({
                            ...current,
                            [key]: event.target.value,
                          }))
                  }
                />
              );
            })}
            <p>
              {isSaaSSignInPending(visibleSelected.value, selectedManifest)
                ? "Sign in to the platform to connect this integration. The provider's credentials stay with Nango and are never returned to this browser."
                : isReferenceConnector(visibleSelected.value.connector_key)
                ? visibleSelected.value.status === "active"
                  ? "Reference authorization is active."
                  : "Authorization uses the configured reference without exposing its value."
                : isOAuthConnectorManifest(selectedManifest, visibleSelected.value.connector_key)
                  ? "Authorization continues on the provider site. Provider credentials are never returned to this browser."
                  : "Provider authorization controls are unavailable for this connector."}
            </p>
            {selectedManifest && <IntegrationSetupGuide manifest={selectedManifest} integration={visibleSelected.value} freshness={freshness} setupStatus={setupStatus} webhookStatus={webhookStatus} onNavigate={navigate} />}
            {visibleSelected.value.connector_key === "aws" && <IntegrationRemediationRole key={visibleSelected.value.id} integrationID={visibleSelected.value.id} canWrite={canWrite} />}
            {selected?.value.connector_key === "generic-webhook" && <section aria-label="Webhook delivery" className="form-stack">
              <h3>Webhook delivery</h3>
              <p>Uses the saved HTTPS destination and signing secret. Save configuration changes before testing. Receivers must verify the HMAC-SHA256 signature and deduplicate the delivery ID.</p>
              {webhookStatus.status === "loading" && <p>Loading delivery status…</p>}
              {webhookStatus.status === "error" && <p role="alert">Delivery status is unavailable.</p>}
              {webhookStatus.status === "success" && !webhookStatus.value && <p>No delivery test for the current configuration.</p>}
              {webhookStatus.status === "success" && webhookStatus.value && <div>
                <p>Delivery status: {webhookStatus.value.delivery_status}</p>
                <p>{webhookStatus.value.signature_status === "signed" ? "Signed by Zasp; endpoint accepted the test." : "Signature and acceptance are unconfirmed."}</p>
                <p>Delivery ID: {webhookStatus.value.delivery_id}</p>
                <p>Attempted: <Time value={webhookStatus.value.attempted_at} /></p>
                {webhookStatus.value.completed_at && <p>Completed: <Time value={webhookStatus.value.completed_at} /></p>}
                {webhookStatus.value.error_code && <p role="alert">Delivery failed. Check the endpoint allowlist, signing secret, and empty HTTP 204 response before testing again.</p>}
              </div>}
              <div className="button-row">
                {canWrite && selectedManifest?.auth_mode === "signed_webhook" && <Button disabled={busy || mutation.isUnresolved || selected.value.status !== "configured"} onClick={testWebhook}>Test signed delivery</Button>}
                <Button disabled={busy || mutation.isUnresolved} onClick={() => loadDiscovery(selected.value)}>Refresh delivery status</Button>
              </div>
            </section>}
            {selected && selected.value.connector_key !== "generic-webhook" && (
              <IntegrationDiscoveryPanel
                freshness={freshness}
                schedule={schedule}
                syncs={syncs}
                syncDetail={syncDetail}
                cadence={scheduleCadence}
                canWrite={discoveryWriteAllowed}
                canSync={manualSyncAllowed}
                locked={busy || mutation.isUnresolved}
                onCadence={setScheduleCadence}
                onSync={queueSync}
                onSaveSchedule={saveSchedule}
                onDeleteSchedule={removeSchedule}
                onOpenSync={openSync}
                onRefresh={refreshDiscovery}
              />
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}

function IntegrationDiscoveryPanel({ freshness, schedule, syncs, syncDetail, cadence, canWrite, canSync, locked, onCadence, onSync, onSaveSchedule, onDeleteSchedule, onOpenSync, onRefresh }: {
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
  onRefresh(): void;
}) {
  const cadenceValue = Number(cadence);
  const cadenceValid = Number.isSafeInteger(cadenceValue) && cadenceValue >= 300 && cadenceValue <= 2_678_400;
  return <section aria-label="Automatic discovery" className="form-stack">
    <h3>Automatic discovery</h3>
    <Button disabled={locked || freshness.status === "loading" || syncs.status === "loading"} onClick={onRefresh}>Refresh discovery status</Button>
    {freshness.status === "loading" && <p>Loading discovery freshness…</p>}
    {freshness.status === "error" && <p>Discovery freshness is unavailable.</p>}
    {freshness.status === "success" && freshness.value && <div aria-label="Projection freshness">
      <p>Risk projection: {freshness.value.value.projections.risk.state}</p>
      <p>Graph projection: {freshness.value.value.projections.graph.state}</p>
      <p>Search projection: {freshness.value.value.projections.search.state}</p>
      {freshness.value.value.last_good && <p>Last good inventory: {freshness.value.value.last_good.discovered_count} discovered · {freshness.value.value.last_good.changed_count} changed · {freshness.value.value.last_good.removed_count} removed</p>}
    </div>}
    {freshness.status === "success" && freshness.value && freshness.value.value.coverage_gaps.length > 0 && <>
      <h4>Agent discovery coverage</h4>
      <ul aria-label="Agent discovery coverage">{freshness.value.value.coverage_gaps.map((gap) => <li key={gap.service}>{coverageGapText(gap)}</li>)}</ul>
    </>}
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

// The read-role actions each AI service needs before its agents can be listed.
const coverageGapActions: Readonly<Record<string, readonly string[]>> = {
  "bedrock-agent": ["bedrock:ListAgents", "bedrock:GetAgent"],
  "bedrock-agentcore": ["bedrock-agentcore:ListAgentRuntimes", "bedrock-agentcore:GetAgentRuntime", "bedrock-agentcore:ListGateways"],
  lambda: ["lambda:ListFunctions"],
  cloudtrail: ["cloudtrail:LookupEvents"],
  "resolver-query-logs": ["route53resolver:ListResolverQueryLogConfigs", "logs:StartQuery", "logs:GetQueryResults"],
  "vpc-flow-logs": ["ec2:DescribeFlowLogs", "logs:StartQuery", "logs:GetQueryResults"],
};

// The account's own logs the agentless runtime signal is read from, and what
// to turn on when one is not there.
const coverageGapLogSources: Readonly<Record<string, string>> = {
  cloudtrail: "CloudTrail event history could not be read in this account's regions, so roles that invoke models are not found from the audit log.",
  "resolver-query-logs": "not delivered to CloudWatch Logs. Turn on Route 53 Resolver query logging for the VPCs with a CloudWatch Logs destination; workloads that reach model APIs are then found without anything installed.",
  "vpc-flow-logs": "not delivered to CloudWatch Logs. Create a VPC flow log with a CloudWatch Logs destination; it confirms that a workload connected to the model API it resolved.",
};

// The Google APIs a Google Cloud collection reads, with the read-only role
// that lets the service account read each. The role names are Google Cloud's
// predefined roles as listed in the Google Cloud runbook.
const gcpCoverageGapRoles: Readonly<Record<string, string>> = {
  "resource-manager": "roles/browser",
  "agent-engine": "roles/aiplatform.viewer",
  "vertex-endpoints": "roles/aiplatform.viewer",
  "conversational-agents": "roles/dialogflow.viewer",
  "gemini-enterprise": "roles/discoveryengine.viewer",
  "cloud-run": "roles/run.viewer",
  "cloud-functions": "roles/cloudfunctions.viewer",
  iam: "roles/iam.securityReviewer",
  "model-armor": "roles/modelarmor.viewer",
  "audit-logs": "roles/logging.privateLogViewer",
  "iam-inherited": "roles/iam.securityReviewer",
};

// Why agents of one AI service are missing, and what to do about it.
function coverageGapText(gap: IntegrationFreshness["coverage_gaps"][number]): string {
  if (Object.hasOwn(gcpCoverageGapRoles, gap.service)) {
    if (gap.status === "unavailable") return `${gap.name}: the API is switched off in every project that was read, so there was nothing to list there.`;
    if (gap.service === "iam-inherited") return `${gap.name}: the IAM policy of a folder or of the organization above at least one project could not be read, so roles a service account holds through inheritance are not checked. Grant the read-only service account ${gcpCoverageGapRoles[gap.service]} on the organization.`;
    return `${gap.name}: at least one project refused the read-only service account. Grant it ${gcpCoverageGapRoles[gap.service]} on the organization, folder or project.`;
  }
  if (gap.service === "mcp-links") return `${gap.name}: the discovery credential may not list Services, so no agent is related to the MCP servers that run in the cluster. Allow list on services for the discovery identity.`;
  if (gap.service === "mcp-link-configmaps") return `${gap.name}: the discovery credential may not list ConfigMaps, so an agent is related to an MCP server only when its arguments or environment values name the server. Allow list on configmaps for the discovery identity.`;
  if (gap.service === "foundry-agents") return `${gap.name}: permission missing. Assign the application the Azure AI User role on the AI Foundry account or its projects; the agents of a project are listed on the project's own endpoint.`;
  if (gap.service === "runtime-observations") return `${gap.name}: the discovery credential may not list ConfigMaps, so what the node sensor saw workloads call at run time is not counted. Allow list on configmaps for the discovery identity.`;
  if (gap.status === "unavailable" && Object.hasOwn(coverageGapLogSources, gap.service)) return `${gap.name}: ${coverageGapLogSources[gap.service]}`;
  if (gap.status === "unavailable") return `${gap.name}: not offered in this account's regions.`;
  const actions = Object.hasOwn(coverageGapActions, gap.service) ? coverageGapActions[gap.service] : [];
  return actions.length > 0 ? `${gap.name}: permission missing. Add ${actions.join(", ")} to the read role.` : `${gap.name}: permission missing. Add this service's list and read actions to the read role.`;
}

// Connectors authorized by a reference to customer material held outside
// the browser, not by a provider OAuth flow.
type ReferenceConnectorKey = "aws" | "kubernetes" | "microsoft" | "salesforce" | "saas" | "gcp";

function isReferenceConnector(value: string): value is ReferenceConnectorKey {
  return value === "aws" || value === "kubernetes" || value === "microsoft" || value === "salesforce" || value === SAAS_CONNECTOR_KEY || value === "gcp";
}

function referenceConnectorLabel(value: string | undefined, manifest?: ConnectorManifest): string {
  if (value === "aws") return "AWS";
  if (value === "microsoft") return "Microsoft";
  if (value === "salesforce") return "Salesforce";
  if (value === "gcp") return "Google Cloud";
  if (value === SAAS_CONNECTOR_KEY) return manifest?.provider ?? "SaaS";
  return "Kubernetes";
}

// The generic saas connector. The catalog lists one entry per SaaS platform
// the API knows; an entry names its platform, and its integration is created
// with the connector key "saas" and that platform in its configuration.
// Nothing here names a platform: a new one appears when the API lists it.
const SAAS_CONNECTOR_KEY = "saas";

function manifestConnectorKey(manifest: ConnectorManifest): string {
  return manifest.platform === undefined ? manifest.key : SAAS_CONNECTOR_KEY;
}

function manifestConfiguration(manifest: ConnectorManifest, configuration: Readonly<Record<string, string>>): Record<string, string> {
  const values = withoutEmptyOptionalFields(manifest, configuration);
  return manifest.platform === undefined ? values : { ...values, platform: manifest.platform };
}

function manifestServes(manifest: ConnectorManifest, integration: Integration): boolean {
  if (manifest.platform === undefined) return manifest.key === integration.connector_key;
  return integration.connector_key === SAAS_CONNECTOR_KEY && integration.configuration.platform === manifest.platform;
}

function integrationConnectorLabel(integration: Integration): string {
  return integration.connector_key === SAAS_CONNECTOR_KEY ? integration.configuration.platform ?? SAAS_CONNECTOR_KEY : integration.connector_key;
}

function withoutEmptyOptionalFields(manifest: ConnectorManifest, configuration: Readonly<Record<string, string>>): Record<string, string> {
  const optional = new Set(manifest.setup_schema.filter((field) => !field.required).map((field) => field.key));
  return Object.fromEntries(Object.entries(configuration).filter(([key, value]) => value !== "" || !optional.has(key)));
}

function IntegrationSetupGuide({ manifest, integration, freshness, setupStatus, webhookStatus, onNavigate }: {
  manifest: ConnectorManifest;
  integration?: Integration;
  freshness?: DiscoveryLoad<Versioned<IntegrationFreshness>>;
  setupStatus?: DiscoveryLoad<IntegrationSetupStatus>;
  webhookStatus?: DiscoveryLoad<IntegrationWebhookTestStatus | null>;
  onNavigate?(target: string): void;
}) {
  const steps = integrationSetupSteps(manifest.key);
  const freshnessValue = freshness?.status === "success" ? freshness.value?.value : undefined;
  const setupValue = setupStatus?.status === "success" ? setupStatus.value : undefined;
  const completedSteps = manifest.key === "generic-webhook"
    ? integration === undefined ? 0 : webhookStatus?.status === "success" && webhookStatus.value?.integration_id === integration.id && webhookStatus.value.delivery_status === "succeeded" ? steps.length : 1
    : integrationSetupCompletedSteps(manifest.key, integration, setupValue, freshnessValue, steps.length);
  const remediation = integration?.status === "degraded"
    ? integrationSetupRemediation(manifest.key, freshnessValue?.latest_sync?.last_error_code)
    : null;
  return <section aria-label={`${manifest.provider} setup`} className="form-stack">
    <h3>Setup progress</h3>
    <ol className="setup-progress">
      {steps.map((step, index) => <li key={step}><strong>{step}</strong>{" "}<span>{index < completedSteps ? "Complete" : index === completedSteps ? "Current" : "Pending"}</span></li>)}
    </ol>
    <p><strong>Connection test</strong> {manifest.test_semantics}</p>
    <p><strong>Collected data</strong>{" "}{manifest.data_types.map(titleCase).join(", ")}</p>
    {setupStatus?.status === "loading" && <p>Loading authoritative provider scope…</p>}
    {setupStatus?.status === "error" && <p role="alert">Authoritative provider scope is unavailable. Setup remains incomplete.</p>}
    {setupValue && <IntegrationSetupAuthority status={setupValue} onNavigate={onNavigate} />}
    {remediation && <p role="alert">{remediation}</p>}
  </section>;
}

function integrationSetupSteps(connectorKey: string): readonly string[] {
  if (connectorKey === "kubernetes") return ["Choose coverage", "Authorize cluster", "Enroll Runtime sensor", "Verify heartbeat", "Initial sync", "Review coverage"];
  if (connectorKey === "github") return ["Review access", "Authorize GitHub organization", "Validate organization and repository scope", "Initial sync", "Review coverage"];
  if (connectorKey === "okta") return ["Review directory access", "Authorize Okta", "Test directory connection", "Initial sync", "Review coverage"];
  if (connectorKey === "microsoft") return ["Register the Entra application", "Configure", "Authorize tenant", "Initial sync", "Review coverage"];
  if (connectorKey === "salesforce") return ["Create the connected app", "Configure", "Authorize org", "Initial sync", "Review coverage"];
  if (connectorKey === "gcp") return ["Create the read-only service account", "Configure", "Authorize scope", "Initial sync", "Review coverage"];
  if (connectorKey === "generic-webhook") return ["Configure destination", "Test signed delivery", "Review delivery status"];
  return ["Review access", "Configure", "Test connection", "Initial sync", "Review coverage"];
}

function integrationSetupCompletedSteps(connectorKey: string, integration: Integration | undefined, status: IntegrationSetupStatus | undefined, freshness: IntegrationFreshness | undefined, total: number): number {
  if (integration === undefined) return 0;
  const authorized = integration.status === "active" && status?.authorization.state === "verified";
  if (connectorKey === "kubernetes") {
    if (!authorized) return 1;
    if (status?.runtime_coverage.state === "not_enrolled") return 2;
    if (status?.runtime_coverage.state !== "healthy") return 3;
    if (freshness?.last_good == null) return 4;
    return Object.values(freshness.projections).every((projection) => projection.state === "current") ? total : 5;
  }
  const authorityComplete = connectorKey === "github" || connectorKey === "okta" ? 3 : integration.status === "active" ? 3 : 2;
  if (!authorized && (connectorKey === "github" || connectorKey === "okta")) return 1;
  if (freshness?.last_good == null) return authorityComplete;
  return Object.values(freshness.projections).every((projection) => projection.state === "current") ? total : total - 1;
}

function IntegrationSetupAuthority({ status, onNavigate }: { status: IntegrationSetupStatus; onNavigate?(target: string): void }) {
  const authorization = status.authorization;
  const coverage = status.runtime_coverage;
  if (authorization.state !== "verified") return <p role="alert">Provider authorization is {authorization.state}. No provider scope is trusted until verification succeeds.</p>;
  if (status.connector_key === "github") return <div aria-label="GitHub provider scope"><p><strong>Organization scope</strong> {authorization.scope_label}</p><p><strong>Repository scope</strong> {authorization.repository_selection === "all" ? "All repositories" : "Selected repositories"}</p><p><strong>Read-only permissions</strong> {authorization.permissions.join(", ")}</p></div>;
  if (status.connector_key === "okta") return <div aria-label="Okta provider scope"><p><strong>Okta tenant</strong> {authorization.scope_label}</p><p><strong>Directory scopes</strong> {authorization.permissions.join(", ")}</p><p>This secures your Okta directory integration; it is separate from Zasp sign-in.</p></div>;
  if (status.connector_key === "kubernetes") return <div aria-label="Kubernetes runtime coverage"><p><strong>Cluster scope</strong> {authorization.scope_label}</p><p><strong>Environment Runtime sensors</strong> {coverage.healthy_sensor_count} of {coverage.sensor_count} healthy</p>{coverage.state === "not_enrolled" && <p role="alert">Runtime coverage is not enrolled. Inventory sync does not include Runtime sensor telemetry.</p>}{coverage.reason === "missing_gateway" && <p role="alert">A Runtime sensor heartbeat is missing. Coverage remains incomplete.</p>}{coverage.reason === "unsupported_kernel" && <p role="alert">The cluster kernel does not provide required BTF support. Coverage remains incomplete.</p>}{coverage.state !== "healthy" && onNavigate && <Button onClick={() => onNavigate("/integrations/sensors")}>Enroll or repair Runtime sensors</Button>}</div>;
  if (status.connector_key === "microsoft") return <p><strong>Microsoft Entra tenant</strong> {authorization.scope_label}</p>;
  if (status.connector_key === "salesforce") return <p><strong>Salesforce org</strong> {authorization.scope_label}</p>;
  if (status.connector_key === "gcp") return <p><strong>Google Cloud scope</strong> {authorization.scope_label}</p>;
  if (status.connector_key === SAAS_CONNECTOR_KEY) return <p><strong>Tenant</strong> {authorization.scope_label}</p>;
  return <p><strong>AWS account scope</strong> {authorization.scope_label}</p>;
}

function integrationSetupRemediation(connectorKey: string, errorCode: string | null | undefined): string {
  if (errorCode === "denied" || errorCode === "revoked") {
    if (connectorKey === "aws") return "AWS read role was denied. Add the documented read-only permissions, then run Test connection again.";
    if (connectorKey === "kubernetes") return "Kubernetes inventory access was denied. Grant the documented get, list, and watch permissions, then run Test connection again.";
    if (connectorKey === "github") return "GitHub installation access is missing required organization or repository scope. Review the installation scope, then authorize again.";
    if (connectorKey === "okta") return "Okta directory access is missing a required read-only scope. Review the directory integration scopes, then authorize again.";
    if (connectorKey === "microsoft") return "Microsoft refused the application. Check the client secret, the admin-consented application permissions and, for Copilot Studio, the Dataverse application user, then authorize again.";
    if (connectorKey === "salesforce") return "Salesforce refused the connected app. Check the consumer secret, the client credentials flow, the run-as user's permissions and the organization ID, then authorize again.";
    if (connectorKey === "gcp") return "Google Cloud refused the service account. Check that the workload identity pool provider trusts this deployment's AWS roles, that they may impersonate the service account (or that the stored key is current), and that the service account can read the organization, folder or project, then authorize again.";
    if (connectorKey.startsWith(`${SAAS_CONNECTOR_KEY}-`)) return "The platform refused the Nango connection. Check that the connection is still authorized in Nango and has the read access this connector lists, then authorize again.";
  }
  if (errorCode === "rate_limited") return "The provider rate limit delayed collection. Keep the last good coverage visible and retry after the published provider window.";
  return "Coverage is degraded. Review the stable discovery status and retry the connection test before starting another sync.";
}

function titleCase(value: string): string {
  return value.length === 0 ? value : value[0]!.toUpperCase() + value.slice(1);
}

function isOAuthConnectorManifest(manifest: ConnectorManifest | undefined, connectorKey: string): boolean {
  return manifest?.key === connectorKey && (manifest.auth_mode === "github_app_oauth" || manifest.auth_mode === "okta_oauth_pkce" || manifest.auth_mode === "managed_oauth");
}

function isFirstPartyConnector(value: string): value is "aws" | "kubernetes" | "github" | "okta" | "microsoft" | "salesforce" | "saas" | "gcp" {
  return value === "aws" || value === "kubernetes" || value === "github" || value === "okta" || value === "microsoft" || value === "salesforce" || value === SAAS_CONNECTOR_KEY || value === "gcp";
}

function isReferenceAuthorizationCandidate(value: Integration): value is Integration & { connector_key: ReferenceConnectorKey } {
  // A saas integration is authorized by reference once it names its connection.
  if (value.connector_key === SAAS_CONNECTOR_KEY && value.configuration.connection_reference === undefined) return false;
  return isReferenceConnector(value.connector_key) && (value.status === "configured" || value.status === "pending_authorization" || value.status === "degraded");
}

function isOAuthAuthorizationCandidate(value: Integration, manifest: ConnectorManifest | undefined): boolean {
  if (isSaaSSignInPending(value, manifest)) return true;
  return isOAuthConnectorManifest(manifest, value.connector_key) && (value.status === "configured" || value.status === "pending_authorization" || value.status === "active");
}

// A saas integration of a platform with a sign-in that names no connection
// yet: the person signs in to the platform, and Nango creates the connection.
function isSaaSSignInPending(value: Integration, manifest: ConnectorManifest | undefined): boolean {
  return value.connector_key === SAAS_CONNECTOR_KEY && manifest !== undefined && manifest.auth_mode === "nango_sign_in" && manifestServes(manifest, value) &&
    value.configuration.connection_reference === undefined && (value.status === "configured" || value.status === "pending_authorization");
}

function saasSignInFailure(code: string): string {
  if (code === "tenant_mismatch") return "The sign-in did not reach the tenant this integration names, or the account may not read it. Check the tenant and sign in with an account of that tenant.";
  if (code === "provider_access_denied") return "The sign-in was cancelled at the provider. Nothing was connected.";
  if (code.startsWith("provider_") && code !== "provider_unavailable") return "The provider refused the sign-in. Nothing was connected.";
  return "The sign-in could not be finished. Nothing was connected; sign in again.";
}

function defaultNavigateAuthorization(target: string): void {
  window.location.assign(target);
}

function defaultNavigateProduct(target: string): void {
  window.history.pushState({}, "", target);
  window.dispatchEvent(new PopStateEvent("popstate"));
}
