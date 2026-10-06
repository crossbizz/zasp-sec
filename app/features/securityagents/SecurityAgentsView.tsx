"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApprovalContext, ApprovalContextFields } from "./ApprovalContext";
import { activityLink, type ActivityScope } from "../../domain/activity-links";

import { APIProductError, APITransportError, createAPIClient, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { decodeSecurityActionPage, decodeSecurityAgentActivationState, decodeSecurityAgentApproval, decodeSecurityAgentApprovalPage, decodeSecurityAgentDefinition, decodeSecurityAgentExecutionControlResult, decodeSecurityAgentExecutionControls, decodeSecurityAgentPage, decodeSecurityAgentRun, decodeSecurityAgentRunDetail, decodeSecurityAgentRunPage, decodeSecurityAgentSimulation, decodeSecurityAgentTemplatePage } from "../../../apps/web/api/decoders";
import type { SecurityAction, SecurityAgentActivationState, SecurityAgentApproval, SecurityAgentApprovalPage, SecurityAgentDefinition, SecurityAgentExecutionControlResult, SecurityAgentExecutionControls, SecurityAgentInput, SecurityAgentPage, SecurityAgentRun, SecurityAgentRunDetail, SecurityAgentRunPage, SecurityAgentRunState, SecurityAgentSimulation, SecurityAgentTemplate } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { useSession } from "../../auth/SessionProvider";
import { Badge, Button, Card, Drawer, EmptyState, Field, LoadingState, PageHeader, Select } from "../../components/ui";
import {
  executeWorkflowMutation,
  requireWorkflowEmptyReceipt,
  requireWorkflowReceipt,
  requireWorkflowVersioned,
  workflowMutationHeaders,
  type Versioned,
  type WorkflowMutationAttempt,
  type WorkflowReceipt,
} from "../workflows/api";
import { useRetainedWorkflowMutation } from "../workflows/useRetainedWorkflowMutation";
import { ActionDetails } from "./ActionDetails";
import { SecurityAgentActivityPanel } from "./SecurityAgentActivityPanel";
import type { SecurityAgentActivityKind } from "../../../apps/web/api/security-agent-activity";
import type { SecurityAgentExistingTestReference, TestDefinition } from "../../../apps/web/api/generated";
import { createProductionRedTeamAPI } from "../redteam/api";
import { ExistingTestPicker } from "./ExistingTestPicker";
import { TriggerRuleFields, triggerRuleDraft, triggerRuleSource, triggerRuleValue } from "./TriggerRuleFields";
import { ExportPanel, type AgentExportAPI } from "./ExportPanel";
import { createSecurityAgentExportAPI } from "./export-api";

type ActivityPermissions = Readonly<Partial<Record<SecurityAgentActivityKind, boolean>>>;
const activityKinds: readonly SecurityAgentActivityKind[] = ["finding", "attack_path", "session", "audit"];
import { decodeAttackPath, decodeFinding, decodeOrderedSecurityAgentApproval, decodeSecurityAgentCancellation, decodeSecurityAgentManualRunInput } from "../../../apps/web/api/decoders";
import type { SecurityAgentCancellation, SecurityAgentManualRunInput } from "../../../apps/web/api/generated";
import { OrderedExecution } from "./OrderedExecution";
import { SingleTestRecovery, type SingleTestRecoveryAPI, type SingleTestRecoveryMutation } from "./SingleTestRecovery";
import type { RecoveryIntent } from "./recovery-intent";
import { getSingleTestRecovery, requestSingleTestRecovery } from "../../../apps/web/api/single-test-recovery";

export const securityAgentOperations = [
  "getSingleTestCleanupRecovery", "requestSingleTestCleanupRecovery",
  "getSecurityAgentExport", "createSecurityAgentExportDownloadGrant", "downloadSecurityAgentExport",
  "listTests",
  "listSecurityAgentTemplates", "listSecurityActions", "getSecurityAgentExecutionControls", "setSecurityAgentExecutionControl", "listSecurityAgents", "createSecurityAgent", "getSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent", "getSecurityAgentActivation", "activateSecurityAgent", "simulateSecurityAgent", "runSecurityAgent",
  "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval", "decideSecurityAgentApproval",
] as const;

export type SecurityAgentsAPI = {
  recovery?: SingleTestRecoveryAPI;
  exports?: AgentExportAPI;
  listExistingTests(signal?: AbortSignal): Promise<readonly TestDefinition[]>;
  listSecurityAgentTemplates(signal?: AbortSignal): Promise<readonly SecurityAgentTemplate[]>;
  listSecurityActions(signal?: AbortSignal): Promise<readonly SecurityAction[]>;
  getSecurityAgentExecutionControls(signal?: AbortSignal): Promise<SecurityAgentExecutionControls>;
  setSecurityAgentExecutionControl(target: "environment" | "action", actionKey: "*" | "create_evidence_export" | "create_temporary_policy" | "isolate_session" | "rerun_test" | "revoke_integration_connection" | "run_test" | "start_attack_lab" | "update_finding_response", version: number, enabled: boolean, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentExecutionControlResult>>;
  listSecurityAgents(options?: { cursor?: string; limit?: number }, signal?: AbortSignal): Promise<SecurityAgentPage>;
  createSecurityAgent(value: SecurityAgentInput, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentDefinition>>;
  getSecurityAgent(id: string, signal?: AbortSignal): Promise<Versioned<SecurityAgentDefinition>>;
  updateSecurityAgent(id: string, version: string, value: SecurityAgentDefinition, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentDefinition>>;
  deleteSecurityAgent(id: string, version: string, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<void>>;
  getSecurityAgentActivation(id: string, signal?: AbortSignal): Promise<SecurityAgentActivationState>;
  activateSecurityAgent(id: string, version: number, activation: "validated" | "supervised" | "autonomous", attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentActivationState>>;
  simulateSecurityAgent(id: string, version: number, value: { goal: string; environment_id: string; evidence_ids: readonly string[] }, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentSimulation>>;
  getTriggerEvidence?(kind: "finding" | "attack_path", id: string, signal?: AbortSignal): Promise<{ id: string; version: number }>;
  runSecurityAgent(id: string, version: number, value: SecurityAgentManualRunInput | { environment_id: string } & ({ trigger_kind: "finding" | "attack_path" | "session"; trigger_id: string } | { trigger_kind?: never; trigger_id?: never }), attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentRun>>;
  listSecurityAgentRuns(options?: { agent_id?: string; status?: SecurityAgentRunState; environment_id?: string; cursor?: string; limit?: number }, signal?: AbortSignal): Promise<SecurityAgentRunPage>;
  getSecurityAgentRun(id: string, signal?: AbortSignal): Promise<SecurityAgentRunDetail>;
  cancelSecurityAgentRun(id: string, version: number, attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentCancellation>>;
  listSecurityAgentApprovals(options?: { state?: SecurityAgentApproval["state"]; run_id?: string; cursor?: string; limit?: number }, signal?: AbortSignal): Promise<SecurityAgentApprovalPage>;
  getSecurityAgentApproval(id: string, signal?: AbortSignal): Promise<SecurityAgentApproval>;
  decideSecurityAgentApproval(id: string, version: number, decision: "approved" | "rejected" | "cancelled", attempt?: WorkflowMutationAttempt): Promise<WorkflowReceipt<SecurityAgentApproval>>;
};

export function createSecurityAgentsAPI(client: APIClient = createAPIClient(), expectedScope?: string, exportBoundaryCurrent?: () => boolean): SecurityAgentsAPI {
  const boundaryCurrent = exportBoundaryCurrent ?? (() => true);
  const orderedApprovals = new Map<string, SecurityAgentApproval>();
  const scopeHeaders = expectedScope === undefined ? {} : { "X-Zasp-Expected-Scope": expectedScope };
  const requireCurrent = () => { if (!boundaryCurrent()) { orderedApprovals.clear(); throw new APITransportError("invalid_configuration", "Security Agent scope changed"); } };
  const decodeApproval = (value: unknown): SecurityAgentApproval => {
    const linked = value && typeof value === "object" && "id" in value ? orderedApprovals.get(String(value.id)) : undefined;
    if (!linked) return decodeSecurityAgentApproval(value);
    const approval = decodeOrderedSecurityAgentApproval(value);
    for (const key of ["run_id", "step_id", "expires_at", "expected_effect", "reversible", "ttl_seconds", "evidence_summary"] as const) {
      if (JSON.stringify(approval[key]) !== JSON.stringify(linked[key])) throw new TypeError("Ordered approval linkage changed");
    }
    return approval;
  };
  return {
    recovery: {
      async get(id, signal) {
        requireCurrent();
        const [organization_id, workspace_id, environment_id, extra] = (expectedScope ?? "").split("/");
        if (extra !== undefined) throw new APITransportError("invalid_configuration", "Invalid recovery scope");
        const value = await getSingleTestRecovery(client, id, { organization_id: organization_id ?? "", workspace_id: workspace_id ?? "", environment_id: environment_id ?? "" }, signal);
        requireCurrent(); return value;
      },
      async request(intent, attempt) {
        requireCurrent();
        const [organization_id, workspace_id, environment_id, extra] = (expectedScope ?? "").split("/");
        if (extra !== undefined) throw new APITransportError("invalid_configuration", "Invalid recovery scope");
        const receipt = await requestSingleTestRecovery(client, intent, { organization_id: organization_id ?? "", workspace_id: workspace_id ?? "", environment_id: environment_id ?? "" }, attempt);
        requireCurrent(); return receipt;
      },
    },
    exports: createSecurityAgentExportAPI(client, expectedScope, exportBoundaryCurrent),
    listExistingTests: createProductionRedTeamAPI(client, expectedScope).listDefinitions,
    async getTriggerEvidence(kind, id, signal) {
      requireCurrent();
      const value = kind === "finding"
        ? requireAPIData(await client.GET("/api/v1/findings/{id}", { params: { path: { id } }, headers: scopeHeaders, signal }), decodeFinding)
        : requireAPIData(await client.GET("/api/v1/attack-paths/{id}", { params: { path: { id } }, headers: scopeHeaders, signal }), decodeAttackPath);
      requireCurrent();
      if (value.id !== id) throw new TypeError("Trigger evidence identity changed");
      return { id: value.id, version: value.version };
    },
    async listSecurityAgentTemplates(signal) {
      return requireAPIData(await client.GET("/api/v1/security-agent-templates", { signal }), decodeSecurityAgentTemplatePage).items;
    },
    async listSecurityActions(signal) {
      return requireAPIData(await client.GET("/api/v1/security-actions", { signal }), decodeSecurityActionPage).items;
    },
    async getSecurityAgentExecutionControls(signal) {
      const result = await client.GET("/api/v1/security-agent-execution-controls", { signal }); requireSecurityAgentNoStore(result.response);
      return requireAPIData(result, decodeSecurityAgentExecutionControls);
    },
    async setSecurityAgentExecutionControl(target, actionKey, version, enabled, attempt) {
      if (target === "environment" && actionKey !== "*" || target === "action" && actionKey !== "create_evidence_export" && actionKey !== "create_temporary_policy" && actionKey !== "isolate_session" && actionKey !== "rerun_test" && actionKey !== "run_test" && actionKey !== "start_attack_lab" && actionKey !== "revoke_integration_connection" && actionKey !== "update_finding_response") throw new TypeError("Security Agent execution control target is invalid");
      return executeWorkflowMutation(async (active) => {
        const params = { header: { ...workflowMutationHeaders(active, `"${version}"`), "X-Zasp-Fresh-Auth": "confirmed" } } as never;
        const result = await client.PUT("/api/v1/security-agent-execution-controls", { params, body: { target, action_key: actionKey, enabled } }); requireSecurityAgentNoStore(result.response);
        const receipt = requireWorkflowReceipt(result, decodeSecurityAgentExecutionControlResult);
        if (receipt.value.target !== target || receipt.value.action_key !== actionKey || receipt.value.enabled !== enabled || receipt.value.version !== version + 1 || receipt.value.audit_id !== receipt.auditID || receipt.value.receipt_id !== receipt.receiptID) throw new TypeError("Security Agent execution control returned invalid authority");
        return receipt;
      }, attempt);
    },
    async listSecurityAgents(options = {}, signal) {
      return requireAPIData(await client.GET("/api/v1/security-agents", { params: { query: options }, signal }), decodeSecurityAgentPage);
    },
    async createSecurityAgent(value, attempt) {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.POST("/api/v1/security-agents", { params: { header: workflowMutationHeaders(active) }, body: value }), decodeSecurityAgentDefinition), attempt);
    },
    async getSecurityAgent(id, signal) {
      return requireWorkflowVersioned(await client.GET("/api/v1/security-agents/{id}", { params: { path: { id } }, signal }), decodeSecurityAgentDefinition);
    },
    async updateSecurityAgent(id, version, value, attempt) {
      return executeWorkflowMutation(async (active) => requireWorkflowReceipt(await client.PATCH("/api/v1/security-agents/{id}", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } }, body: value }), decodeSecurityAgentDefinition), attempt);
    },
    async deleteSecurityAgent(id, version, attempt) {
      return executeWorkflowMutation(async (active) => { const result = await client.DELETE("/api/v1/security-agents/{id}", { params: { path: { id }, header: workflowMutationHeaders(active, version) as { "Idempotency-Key": string; "If-Match": string } } }); if (result.error) requireAPIData<never>(result); return requireWorkflowEmptyReceipt(result.response); }, attempt);
    },
    async getSecurityAgentActivation(id, signal) {
      const result = await client.GET("/api/v1/security-agents/{id}/activation", { params: { path: { id } }, signal }); requireSecurityAgentNoStore(result.response);
      const value = requireAPIData(result, decodeSecurityAgentActivationState); if (value.id !== id) throw new TypeError("Security Agent activation returned a different definition"); return value;
    },
    async activateSecurityAgent(id, version, activation, attempt) {
      return executeWorkflowMutation(async (active) => {
        const params = { path: { id }, header: { ...workflowMutationHeaders(active, `"${version}"`), "X-Zasp-Fresh-Auth": "confirmed" } } as never;
        const result = await client.POST("/api/v1/security-agents/{id}/activation", { params, body: { activation } }); requireSecurityAgentNoStore(result.response);
        const receipt = requireWorkflowReceipt(result, decodeSecurityAgentActivationState); if (receipt.value.id !== id || receipt.value.activation !== activation || receipt.value.version !== version + 1) throw new TypeError("Security Agent activation returned invalid authority"); return receipt;
      }, attempt);
    },
    async simulateSecurityAgent(id, version, value, attempt) {
      return executeWorkflowMutation(async (active) => {
        const params = { path: { id }, header: workflowMutationHeaders(active, `"${version}"`) } as never;
        const result = await client.POST("/api/v1/security-agents/{id}/simulate", { params, body: value }); requireSecurityAgentNoStore(result.response);
        const receipt = requireWorkflowReceipt(result, decodeSecurityAgentSimulation); if (receipt.value.definition_id !== id || receipt.value.definition_version !== version || receipt.value.matched_evidence_ids.join("\u0000") !== [...value.evidence_ids].sort().join("\u0000")) throw new TypeError("Security Agent simulation returned invalid authority"); return receipt;
      }, attempt);
    },
    async runSecurityAgent(id, version, value, attempt) {
      if (Object.keys(value).length !== 1 || !("environment_id" in value)) decodeSecurityAgentManualRunInput(value);
      return executeWorkflowMutation(async (active) => {
        requireCurrent();
        const params = { path: { id }, header: workflowMutationHeaders(active, `"${version}"`) } as never;
        const result = await client.POST("/api/v1/security-agents/{id}/runs", { params, headers: scopeHeaders, body: value }); requireCurrent(); requireSecurityAgentNoStore(result.response);
        const receipt = requireWorkflowReceipt(result, decodeSecurityAgentRun);
        const matchesTrigger = value.trigger_id === undefined
          ? receipt.value.manual_trigger?.version === 1 && receipt.value.evidence_ids.length === 0
          : receipt.value.manual_trigger === undefined && receipt.value.evidence_ids.length === 1 && receipt.value.evidence_ids[0] === value.trigger_id;
        if (receipt.value.agent_id !== id || receipt.value.definition_version !== version || !matchesTrigger) throw new TypeError("Security Agent run returned invalid authority"); return receipt;
      }, attempt);
    },
    async listSecurityAgentRuns(options = {}, signal) {
      const result = await client.GET("/api/v1/security-agent-runs", { params: { query: options }, signal }); requireSecurityAgentNoStore(result.response);
      return requireAPIData(result, decodeSecurityAgentRunPage);
    },
    async getSecurityAgentRun(id, signal) {
      requireCurrent();
      const result = await client.GET("/api/v1/security-agent-runs/{id}", { params: { path: { id }, header: { "X-Zasp-Budget-Details": "v1", "X-Zasp-Run-Context": "v1", "X-Zasp-Action-Details": "v1" } }, headers: scopeHeaders, signal }); requireCurrent(); requireSecurityAgentNoStore(result.response);
      const value = requireAPIData(result, decodeSecurityAgentRunDetail);
      if (value.run.id !== id) throw new TypeError("Security Agent run detail returned a different run");
      for (const [approvalID, approval] of orderedApprovals) if (approval.run_id === id) orderedApprovals.delete(approvalID);
      if (value.ordered) for (const approval of value.approvals) orderedApprovals.set(approval.id, approval);
      return value;
    },
    async cancelSecurityAgentRun(id, version, attempt) {
      return executeWorkflowMutation(async (active) => {
        requireCurrent();
        const params = { path: { id }, header: workflowMutationHeaders(active, `"${version}"`) } as never;
        const result = await client.POST("/api/v1/security-agent-runs/{id}/cancel", { params, headers: scopeHeaders }); requireCurrent(); requireSecurityAgentNoStore(result.response);
        const receipt = requireWorkflowReceipt(result, decodeSecurityAgentCancellation);
        if (receipt.value.id !== id || (receipt.value.state !== "cancelled" && !(receipt.value.ordered && receipt.value.state === "needs_human")) || receipt.value.version !== version + 1) throw new TypeError("Security Agent cancellation returned invalid authority");
        return receipt;
      }, attempt);
    },
    async listSecurityAgentApprovals(options = {}, signal) {
      const result = await client.GET("/api/v1/security-agent-approvals", { params: { query: options, header: { "X-Zasp-Approval-Context": "v1" } }, signal }); requireSecurityAgentNoStore(result.response);
      const page = requireAPIData(result, (value) => {
        if (!value || typeof value !== "object" || !("items" in value) || !Array.isArray(value.items) || value.items.length > 100) throw new TypeError("Invalid approval page");
        decodeSecurityAgentApprovalPage({ ...value, items: [] });
        return value as SecurityAgentApprovalPage;
      });
      const items: SecurityAgentApproval[] = [];
      for (const item of page.items) {
        try { items.push(decodeApproval(item)); }
        catch {
          if (!item || typeof item.run_id !== "string" || !/^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(item.run_id)) throw new TypeError("Invalid approval linkage");
          const detail = await this.getSecurityAgentRun(item.run_id, signal);
          if (!detail.ordered || !orderedApprovals.has(item.id)) throw new TypeError("Ordered approval linkage unavailable");
          items.push(decodeApproval(item));
        }
      }
      return { ...page, items };
    },
    async getSecurityAgentApproval(id, signal) {
      requireCurrent();
      const result = await client.GET("/api/v1/security-agent-approvals/{id}", { params: { path: { id }, header: { "X-Zasp-Approval-Context": "v1" } }, headers: scopeHeaders, signal }); requireCurrent(); requireSecurityAgentNoStore(result.response);
      let value: SecurityAgentApproval;
      try { value = requireAPIData(result, decodeApproval); }
      catch (error) {
        const candidate = result.data;
        if (!candidate || typeof candidate.run_id !== "string" || !/^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(candidate.run_id)) throw error;
        const detail = await this.getSecurityAgentRun(candidate.run_id, signal);
        if (!detail.ordered || !orderedApprovals.has(id)) throw new TypeError("Ordered approval linkage unavailable");
        value = requireAPIData(result, decodeApproval);
      }
      if (value.id !== id) throw new TypeError("Security Agent approval detail returned a different approval");
      return value;
    },
    async decideSecurityAgentApproval(id, version, decision, attempt) {
      if (orderedApprovals.has(id) && decision === "cancelled") throw new TypeError("Cancel the ordered run, not its approval");
      return executeWorkflowMutation(async (active) => {
        requireCurrent();
        const params = { path: { id }, header: { ...workflowMutationHeaders(active, `"${version}"`), "X-Zasp-Fresh-Auth": "confirmed" } } as never;
        const result = await client.POST("/api/v1/security-agent-approvals/{id}/decision", { params, headers: scopeHeaders, body: { decision } }); requireCurrent(); requireSecurityAgentNoStore(result.response);
        const receipt = requireWorkflowReceipt(result, decodeApproval);
        if (receipt.value.id !== id || receipt.value.state !== decision || receipt.value.version !== version + 1) throw new TypeError("Security Agent approval decision returned invalid authority");
        return receipt;
      }, attempt);
    },
  };
}

function requireSecurityAgentNoStore(response: Response): void { if (response.headers.get("Cache-Control") !== "no-store") throw new APITransportError("invalid_response", "Security Agent response omitted no-store authority"); }

const defaultSecurityAgentsAPI = createSecurityAgentsAPI();
const maximums = { steps: 100, runtime: 86400, temporaryPolicy: 86400, aiTokens: 12000, concurrency: 10 } as const;
const triggerSources = { finding: "credential", attack_path: "verified", runtime_decision: "block" } as const;
const bounded = (value: string, maximum: number) => Math.max(1, Math.min(maximum, Number(value) || 1));
type SecurityAgentSnapshot = { agents: readonly SecurityAgentDefinition[]; templates: readonly SecurityAgentTemplate[]; actions?: readonly SecurityAction[]; runs?: readonly SecurityAgentRun[]; approvals?: readonly SecurityAgentApproval[]; controls?: SecurityAgentExecutionControls };
type SecurityAgentCreateIntent = { value: SecurityAgentInput };
type SecurityAgentDetailIntent =
  | { kind: "update"; id: string; version: string; value: SecurityAgentDefinition }
  | { kind: "delete"; id: string; version: string };
type SecurityAgentDetailResult =
  | { kind: "updated"; receipt: WorkflowReceipt<SecurityAgentDefinition> }
  | { kind: "deleted"; receipt: WorkflowReceipt<void> };
type SecurityAgentRunCancelIntent = { id: string; version: number };
type SecurityAgentApprovalDecisionIntent = { id: string; version: number; decision: "approved" | "rejected" | "cancelled" };
type SecurityAgentActivationIntent = { id: string; version: number; activation: "validated" | "supervised" | "autonomous" };
type SecurityAgentSimulationIntent = { id: string; version: number; goal: string; environmentID: string; evidenceIDs: readonly string[] };
type SecurityAgentManualRunIntent = { id: string; version: number; value: Parameters<SecurityAgentsAPI["runSecurityAgent"]>[2] };
type SecurityAgentControlIntent = { target: "environment" | "action"; actionKey: "*" | "create_evidence_export" | "create_temporary_policy" | "isolate_session" | "rerun_test" | "revoke_integration_connection" | "run_test" | "start_attack_lab" | "update_finding_response"; version: number; enabled: boolean };

async function loadSecurityAgentSnapshot(api: SecurityAgentsAPI, includeControls = false, signal?: AbortSignal, catalogAvailable = true): Promise<SecurityAgentSnapshot> {
  const [firstPage, templates, actions, firstRuns, firstApprovals, controls] = await Promise.all([
    api.listSecurityAgents({ limit: 100 }, signal),
    catalogAvailable ? api.listSecurityAgentTemplates(signal) : Promise.resolve([]),
    catalogAvailable ? api.listSecurityActions(signal) : Promise.resolve([]),
    api.listSecurityAgentRuns({ limit: 100 }, signal),
    api.listSecurityAgentApprovals({ limit: 100 }, signal),
    includeControls ? api.getSecurityAgentExecutionControls(signal) : Promise.resolve(undefined),
  ]);
  const agents: SecurityAgentDefinition[] = [];
  let page = firstPage;
  for (let pageNumber = 0; pageNumber < 100; pageNumber++) {
    agents.push(...page.items);
    if (!page.page_info.has_more) break;
    if (pageNumber === 99) throw new Error("Security Agent definition pagination exceeded its bounded page count");
    page = await api.listSecurityAgents({ cursor: page.page_info.next_cursor, limit: 100 }, signal);
  }
  const runs: SecurityAgentRun[] = [...firstRuns.items]; let runPage = firstRuns;
  for (let pageNumber = 1; runPage.next_cursor !== undefined; pageNumber++) { if (pageNumber === 100) throw new Error("Security Agent run pagination exceeded its bounded page count"); runPage = await api.listSecurityAgentRuns({ cursor: runPage.next_cursor, limit: 100 }, signal); runs.push(...runPage.items); }
  const approvals: SecurityAgentApproval[] = [...firstApprovals.items]; let approvalPage = firstApprovals;
  for (let pageNumber = 1; approvalPage.next_cursor !== undefined; pageNumber++) { if (pageNumber === 100) throw new Error("Security Agent approval pagination exceeded its bounded page count"); approvalPage = await api.listSecurityAgentApprovals({ cursor: approvalPage.next_cursor, limit: 100 }, signal); approvals.push(...approvalPage.items); }
  return { agents, templates, actions, runs, approvals, controls };
}

type SecurityAgentCreateMutation = ReturnType<typeof useRetainedWorkflowMutation<SecurityAgentCreateIntent>>;
type SecurityAgentDetailMutation = ReturnType<typeof useRetainedWorkflowMutation<SecurityAgentDetailIntent>>;
type SecurityAgentRunMutation = ReturnType<typeof useRetainedWorkflowMutation<SecurityAgentRunCancelIntent>>;
type SecurityAgentApprovalMutation = ReturnType<typeof useRetainedWorkflowMutation<SecurityAgentApprovalDecisionIntent>>;
type SecurityAgentActivationMutation = ReturnType<typeof useRetainedWorkflowMutation<SecurityAgentActivationIntent>>;
type SecurityAgentSimulationMutation = ReturnType<typeof useRetainedWorkflowMutation<SecurityAgentSimulationIntent>>;
type SecurityAgentManualRunMutation = ReturnType<typeof useRetainedWorkflowMutation<SecurityAgentManualRunIntent>>;
type SecurityAgentControlMutation = ReturnType<typeof useRetainedWorkflowMutation<SecurityAgentControlIntent>>;

function ExecutionControls({ value, api, fresh, mutation, onReauthenticate, onChange }: { value: SecurityAgentExecutionControls; api: SecurityAgentsAPI; fresh: boolean; mutation: SecurityAgentControlMutation; onReauthenticate(): void; onChange(value: SecurityAgentExecutionControls): void }) {
  const [busy, setBusy] = useState(false); const [error, setError] = useState(false);
  const change = async (target: "environment" | "action", actionKey: SecurityAgentControlIntent["actionKey"]) => {
    const current = target === "environment" ? value.environment : value.actions.find((action) => action.action_key === actionKey);
    if (!current) return;
    setBusy(true); setError(false);
    try {
      const intent = { target, actionKey, version: current.version, enabled: !current.enabled };
      const receipt = mutation.canRetry ? await mutation.retry<WorkflowReceipt<SecurityAgentExecutionControlResult>>() : await mutation.execute(intent, (frozen, attempt) => api.setSecurityAgentExecutionControl(frozen.target, frozen.actionKey, frozen.version, frozen.enabled, attempt));
      const next = { target: receipt.value.target, action_key: receipt.value.action_key, enabled: receipt.value.enabled, version: receipt.value.version } as const;
      onChange(target === "environment" ? { ...value, environment: next } : { ...value, actions: value.actions.map((action) => action.action_key === next.action_key ? next : action) });
    } catch (reason) {
      if (reason instanceof APIProductError && reason.status === 409) {
        try { onChange(await api.getSecurityAgentExecutionControls()); } catch { setError(true); }
      } else setError(true);
    } finally { setBusy(false); }
  };
  return <Card title="Execution controls"><div className="form-stack">
    <p><Badge tone={value.global.enabled ? "success" : "critical"}>{value.global.enabled ? "Platform execution enabled" : "Platform execution disabled"}</Badge> Platform authority is read-only to tenant administrators.</p>
    <p><strong>{value.environment.enabled ? "Environment automation enabled" : "Environment automation disabled"}</strong> · version {value.environment.version}</p>
    {value.actions.map((action) => <p key={action.action_key}><strong>{action.enabled ? `${action.action_key} enabled` : `${action.action_key} disabled`}</strong> · version {action.version}</p>)}
    {!fresh ? <Button onClick={onReauthenticate}>Reauthenticate to change execution controls</Button> : <div className="button-row">
      <Button disabled={busy || mutation.isUnresolved && !mutation.canRetry || !value.global.enabled && !value.environment.enabled} onClick={() => void change("environment", "*")}>{mutation.canRetry && mutation.retainedIntent?.target === "environment" ? "Retry retained environment control" : value.environment.enabled ? "Disable environment automation" : "Enable environment automation"}</Button>
      {value.actions.map((action) => <Button key={action.action_key} disabled={busy || mutation.isUnresolved && !mutation.canRetry || !action.enabled && (!value.global.enabled || !value.environment.enabled)} onClick={() => void change("action", action.action_key)}>{mutation.canRetry && mutation.retainedIntent?.target === "action" && mutation.retainedIntent.actionKey === action.action_key ? `Retry retained ${action.action_key} control` : action.enabled ? `Disable ${action.action_key}` : `Enable ${action.action_key}`}</Button>)}
    </div>}
    {error && <p role="alert">Execution controls changed or the response was lost. Retry the retained change or reload current authority.</p>}
  </div></Card>;
}

function Builder({ templates, actions, canReadTests, api, environmentID, mutation, onCreated }: { templates: readonly SecurityAgentTemplate[]; actions: readonly SecurityAction[]; canReadTests: boolean; api: SecurityAgentsAPI; environmentID: string; mutation: SecurityAgentCreateMutation; onCreated(value: SecurityAgentDefinition): void }) {
  const exportAvailable = actions.some(action => action.key === "create_evidence_export" && action.verification_kind === "export" && action.risk_class === "low" && action.approval_floor === "none" && action.reversible && action.target_types.length === 1 && action.target_types[0] === "evidence");
  const choices = templates.filter(template => !template.default_actions.includes("create_evidence_export"));
  if (exportAvailable) choices.push({ id: "export-only", name: "Run-scoped evidence export", version: 1, trigger_kind: "finding", default_actions: ["create_evidence_export"], verification_condition: "export" });
  const [templateID, setTemplateID] = useState(choices[0]?.id ?? "");
  const exportOnly = templateID === "export-only";
  const [name, setName] = useState("Bounded response definition");
  const [steps, setSteps] = useState(10);
  const [runtime, setRuntime] = useState(900);
  const [temporaryPolicy, setTemporaryPolicy] = useState(3600);
  const [aiTokens, setAITokens] = useState(4000);
  const [costBudget, setCostBudget] = useState("");
  const validCostBudget = !exportOnly && costBudget === "" || /^[0-9]{1,13}$/.test(costBudget) && Number(costBudget) >= 1 && Number(costBudget) <= 1000000000000;
  const [concurrency, setConcurrency] = useState(2);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const selected = choices.find((value) => value.id === templateID);
  const [ruleDraft, setRuleDraft] = useState(() => triggerRuleDraft(triggerSources[choices[0]?.trigger_kind ?? "finding"]));
  const triggerSource = selected ? triggerRuleSource(ruleDraft, selected.trigger_kind, triggerSources[selected.trigger_kind]) : "";
  const triggerRules = selected ? triggerRuleValue(ruleDraft, selected.trigger_kind, triggerSource) : null;
  const [temporaryMode, setTemporaryMode] = useState<"" | "monitor" | "block">("");
  const temporaryOnly = selected?.default_actions.length === 1 && selected.default_actions[0] === "create_temporary_policy" && selected.verification_condition === "policy_state" && actions.some(action => action.key === "create_temporary_policy" && action.verification_kind === "policy_state" && action.approval_floor === "operator" && action.reversible);
  const monitor = temporaryOnly && temporaryMode === "monitor";
  const [existingTest, setExistingTest] = useState<SecurityAgentExistingTestReference | null>(null);
  const needsTest = selected?.default_actions.some(action => action === "run_test" || action === "rerun_test" || action === "start_attack_lab") ?? false;
  const testSupported = selected?.default_actions.length === 1 && (selected.default_actions[0] === "start_attack_lab" ? selected.verification_condition === "attack_lab_run" : selected.verification_condition === "test_run") && actions.some(action => action.key === selected.default_actions[0] && action.verification_kind === selected.verification_condition && (action.key !== "start_attack_lab" || action.approval_floor === "operator"));
  const testReady = !needsTest || testSupported && canReadTests && existingTest !== null;
  const save = async () => {
    if (!selected || !validCostBudget || triggerRules === null || !testReady && !mutation.canRetry) return;
    setBusy(true); setError(false);
    try {
      const intent = { value: { name, trigger_kind: selected.trigger_kind, trigger_source: triggerSource, ...(triggerRules ? { trigger_rules: triggerRules } : {}), environment_ids: [environmentID], autonomy: "supervised" as const, max_steps: exportOnly || monitor ? 1 : steps, max_duration_seconds: runtime, temporary_policy_seconds: temporaryPolicy, ...(temporaryOnly && temporaryMode ? { temporary_policy_mode: temporaryMode } : {}), ai_token_budget: aiTokens, ...(costBudget === "" ? {} : { max_ai_cost_nano_credits: Number(costBudget) }), concurrency_limit: concurrency, allowed_actions: selected.default_actions, verification_kind: selected.verification_condition, definition_version: selected.version, enabled: false, ...(needsTest && existingTest ? { existing_test: existingTest } : {}) } };
      const receipt = mutation.canRetry
        ? await mutation.retry<WorkflowReceipt<SecurityAgentDefinition>>()
        : await mutation.execute(intent, (frozen, attempt) => api.createSecurityAgent(frozen.value, attempt));
      onCreated(receipt.value);
    } catch { setError(true); } finally { setBusy(false); }
  };
  return <Card title="Create a supported Security Agent definition"><div className="form-stack">
    <Select label="Definition template" value={templateID} disabled={mutation.isUnresolved} onChange={(event) => { if (!mutation.isUnresolved) { setExistingTest(null); setTemporaryMode(""); setTemplateID(event.target.value); } }}>{choices.map((value) => <option key={value.id} value={value.id}>{value.name}</option>)}</Select>
    {temporaryOnly && <><Select label="Temporary policy mode" value={temporaryMode || "block"} disabled={mutation.isUnresolved || busy} onChange={event => { const mode = event.target.value; if (mode === "monitor" || mode === "block") { setTemporaryMode(mode); if (mode === "monitor") { setSteps(1); setTemporaryPolicy(Math.max(60, Math.min(3600, temporaryPolicy))); } } }}><option value="block">Block</option><option value="monitor">Monitor</option></Select>{monitor && <p>Monitor observes traffic and never claims containment or remediation. This supervised draft uses one action. Saving creates a disabled draft with one action. Monitor execution is currently unavailable.</p>}</>}
    {exportOnly && <p>Export-only definitions use one step. Start a supervised run after validation, activation, and execution controls are enabled.</p>}
    {needsTest && (testSupported && canReadTests ? <ExistingTestPicker key={templateID} api={api} value={existingTest} onChange={setExistingTest} locked={busy || mutation.isUnresolved} /> : <p role="status">Existing-test actions require an available executor and Red Team read permission.</p>)}
    <Field label="Definition name" value={name} disabled={mutation.isUnresolved} maxLength={256} onChange={(event) => setName(event.target.value)} />
    <Field label="Authorized environment" value={environmentID} readOnly />
    <Field label="AI cost budget (nano OpenRouter credits)" inputMode="numeric" value={costBudget} disabled={mutation.isUnresolved} onChange={(event) => setCostBudget(event.target.value)} />
    <p>1 OpenRouter credit = 1,000,000,000 nano-credits, not dollars. Enter an integer from 1 to 1,000,000,000,000. {exportOnly ? "Export drafts require an explicit AI cost budget before saving; paid planning also requires a verified cost policy." : "Leave blank to save a draft without cost authority; paid planning requires an explicit budget and a verified cost policy."}</p>
    {selected && <p>Trigger: {selected.trigger_kind}. Template actions: {selected.default_actions.join(", ")}. Verification: {selected.verification_condition}.</p>}
    {selected && <TriggerRuleFields value={ruleDraft} kind={selected.trigger_kind} disabled={busy || mutation.isUnresolved} onChange={setRuleDraft} />}
    <div className="form-grid"><Field label="Step limit" type="number" min={1} max={exportOnly || monitor ? 1 : maximums.steps} value={exportOnly || monitor ? 1 : steps} disabled={exportOnly || monitor || mutation.isUnresolved} onChange={(event) => setSteps(bounded(event.target.value, maximums.steps))} /><Field label="Runtime seconds" type="number" min={1} max={maximums.runtime} value={runtime} disabled={mutation.isUnresolved} onChange={(event) => setRuntime(bounded(event.target.value, maximums.runtime))} /><Field label="Temporary-policy seconds" type="number" min={monitor ? 60 : 1} max={monitor ? 3600 : maximums.temporaryPolicy} value={temporaryPolicy} disabled={mutation.isUnresolved} onChange={(event) => setTemporaryPolicy(bounded(event.target.value, maximums.temporaryPolicy))} /><Field label="AI token budget" type="number" min={1} max={maximums.aiTokens} value={aiTokens} disabled={mutation.isUnresolved} onChange={(event) => setAITokens(bounded(event.target.value, maximums.aiTokens))} /><Field label="Concurrency" type="number" min={1} max={maximums.concurrency} value={concurrency} disabled={mutation.isUnresolved} onChange={(event) => setConcurrency(bounded(event.target.value, maximums.concurrency))} /></div>
    <p>New definitions start in supervised mode. Run plans, approvals, execution outcomes, and verification remain tenant-scoped and versioned.</p>
    {error && <p role="alert">{mutation.canRetry ? "The response was lost. Retry will reuse the exact definition and idempotency key." : "The definition was not saved."}</p>}<Button variant="primary" disabled={busy || !selected || !name || !validCostBudget || triggerRules === null || !testReady && !mutation.canRetry || mutation.isUnresolved && !mutation.canRetry} onClick={() => void save()}>{mutation.canRetry ? "Retry retained Security Agent definition" : "Save Security Agent definition"}</Button>
  </div></Card>;
}

function AgentDetail({ selected, activation, actions, catalogAvailable, api, canWrite, fresh, onReauthenticate, mutation, activationMutation, simulationMutation, manualRunMutation, onChange, onActivation, onRun, onDelete, onClose }: { selected: Versioned<SecurityAgentDefinition>; activation: SecurityAgentActivationState; actions: readonly SecurityAction[]; catalogAvailable: boolean; api: SecurityAgentsAPI; canWrite: boolean; fresh: boolean; onReauthenticate(): void; mutation: SecurityAgentDetailMutation; activationMutation: SecurityAgentActivationMutation; simulationMutation: SecurityAgentSimulationMutation; manualRunMutation: SecurityAgentManualRunMutation; onChange(value: Versioned<SecurityAgentDefinition>): void; onActivation(value: SecurityAgentActivationState): void; onRun(value: SecurityAgentRun): void; onDelete(): void; onClose(): void }) {
  const [name, setName] = useState(selected.value.name);
  const [ruleDraft, setRuleDraft] = useState(() => triggerRuleDraft(selected.value.trigger_source, selected.value.trigger_rules));
  const triggerSource = triggerRuleSource(ruleDraft, selected.value.trigger_kind, selected.value.trigger_source);
  const triggerRules = triggerRuleValue(ruleDraft, selected.value.trigger_kind, triggerSource);
  const rulesDirty = JSON.stringify(ruleDraft) !== JSON.stringify(triggerRuleDraft(selected.value.trigger_source, selected.value.trigger_rules));
  const [enabled, setEnabled] = useState(selected.value.enabled);
  const [costBudget, setCostBudget] = useState(selected.value.max_ai_cost_nano_credits?.toString() ?? "");
  const requiresExportBudget = selected.value.allowed_actions.includes("create_evidence_export");
  const validCostBudget = !requiresExportBudget && costBudget === "" || /^[0-9]{1,13}$/.test(costBudget) && Number(costBudget) >= 1 && Number(costBudget) <= 1000000000000;
  const savedCostBudget = selected.value.max_ai_cost_nano_credits;
  const costDirty = costBudget !== (savedCostBudget?.toString() ?? "");
  const [costRefused, setCostRefused] = useState(false);
  const costConfigured = Number.isSafeInteger(savedCostBudget) && savedCostBudget! >= 1 && savedCostBudget! <= 1000000000000;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [goal, setGoal] = useState("Review this evidence with the bounded response plan");
  const [evidenceID, setEvidenceID] = useState("");
  const [simulation, setSimulation] = useState<SecurityAgentSimulation | null>(null);
  const [reads] = useState(() => new AbortController());
  useEffect(() => () => reads.abort(), [reads]);
  const apply = (result: SecurityAgentDetailResult) => { if (result.kind === "updated") { setEnabled(false); setCostRefused(false); setCostBudget(result.receipt.value.max_ai_cost_nano_credits?.toString() ?? ""); setRuleDraft(triggerRuleDraft(result.receipt.value.trigger_source, result.receipt.value.trigger_rules)); onChange(result.receipt); } else onDelete(); };
  const run = async (operation: () => Promise<SecurityAgentDetailResult>) => { setBusy(true); setError(false); try { apply(await operation()); } catch { setError(true); } finally { setBusy(false); } };
  const save = () => {
    if (!validCostBudget || triggerRules === null) return;
    const value = { ...selected.value, name, enabled: false, trigger_source: triggerSource };
    if (triggerRules) value.trigger_rules = triggerRules;
    else delete value.trigger_rules;
    if (costBudget === "") delete value.max_ai_cost_nano_credits;
    else value.max_ai_cost_nano_credits = Number(costBudget);
    void run(() => mutation.execute({ kind: "update", id: selected.value.id, version: selected.version, value }, async (intent, attempt) => { if (intent.kind !== "update") throw new TypeError("Invalid retained Security Agent intent"); return { kind: "updated", receipt: await api.updateSecurityAgent(intent.id, intent.version, intent.value, attempt) }; }));
  };
  const remove = () => void run(() => mutation.execute({ kind: "delete", id: selected.value.id, version: selected.version }, async (intent, attempt) => { if (intent.kind !== "delete") throw new TypeError("Invalid retained Security Agent intent"); return { kind: "deleted", receipt: await api.deleteSecurityAgent(intent.id, intent.version, attempt) }; }));
  const retry = () => void run(() => mutation.retry<SecurityAgentDetailResult>());
  const autonomousAllowed = !selected.value.allowed_actions.includes("create_temporary_policy") && !selected.value.allowed_actions.includes("revoke_integration_connection");
  const monitorUnavailable = selected.value.temporary_policy_mode === "monitor";
  const nextActivation = monitorUnavailable ? null : activation.activation === "draft" ? "validated" : activation.activation === "validated" ? "supervised" : activation.activation === "supervised" && autonomousAllowed ? "autonomous" : null;
  const activate = async () => {
    if (!nextActivation || costDirty || rulesDirty || costRefused || nextActivation !== "validated" && !costConfigured) return;
    if (!fresh) { onReauthenticate(); return; }
    setBusy(true); setError(false);
    try {
      const receipt = activationMutation.canRetry ? await activationMutation.retry<WorkflowReceipt<SecurityAgentActivationState>>() : await activationMutation.execute({ id: selected.value.id, version: activation.version, activation: nextActivation }, (intent, attempt) => api.activateSecurityAgent(intent.id, intent.version, intent.activation, attempt));
      onActivation(receipt.value); setEnabled(receipt.value.enabled);
    } catch (reason) { setCostRefused(reason instanceof APIProductError && reason.status === 400 && reason.product.code === "cost_budget_required"); setError(true); } finally { setBusy(false); }
  };
  const simulate = async () => {
    if (monitorUnavailable) return;
    setBusy(true); setError(false);
    try {
      const evidenceIDs = [evidenceID];
      const receipt = simulationMutation.canRetry ? await simulationMutation.retry<WorkflowReceipt<SecurityAgentSimulation>>() : await simulationMutation.execute({ id: selected.value.id, version: activation.version, goal, environmentID: selected.value.environment_ids[0]!, evidenceIDs }, (intent, attempt) => api.simulateSecurityAgent(intent.id, intent.version, { goal: intent.goal, environment_id: intent.environmentID, evidence_ids: intent.evidenceIDs }, attempt));
      setSimulation(receipt.value);
    } catch { setError(true); } finally { setBusy(false); }
  };
  const startRun = async () => {
    if (monitorUnavailable) return;
    setBusy(true); setError(false);
    try {
      const triggerKind = selected.value.trigger_kind === "runtime_decision" ? "session" : selected.value.trigger_kind;
      const orderedIntent = selected.value.allowed_actions.length === 2 && selected.value.allowed_actions[0] === "create_temporary_policy" && selected.value.allowed_actions[1] === "run_test";
      let triggerVersion: number | undefined;
      if (orderedIntent && !manualRunMutation.canRetry) {
        if (triggerKind === "session" || !api.getTriggerEvidence || !selected.value.trigger_source) throw new TypeError("Ordered trigger authority unavailable");
        const evidence = await api.getTriggerEvidence(triggerKind, evidenceID, reads.signal);
        if (reads.signal.aborted || evidence.id !== evidenceID) throw new TypeError("Trigger evidence authority changed");
        triggerVersion = evidence.version;
        decodeSecurityAgentManualRunInput({ environment_id: selected.value.environment_ids[0], trigger_kind: triggerKind, trigger_id: evidenceID, trigger_version: triggerVersion, trigger_source: selected.value.trigger_source });
      }
      let value: Parameters<SecurityAgentsAPI["runSecurityAgent"]>[2] = evidenceID === "" ? { environment_id: selected.value.environment_ids[0]! } : { environment_id: selected.value.environment_ids[0]!, trigger_kind: triggerKind, trigger_id: evidenceID };
      if (orderedIntent && !manualRunMutation.canRetry) value = decodeSecurityAgentManualRunInput({ environment_id: selected.value.environment_ids[0]!, trigger_kind: triggerKind, trigger_id: evidenceID, trigger_version: triggerVersion, trigger_source: selected.value.trigger_source });
      const receipt = manualRunMutation.canRetry ? await manualRunMutation.retry<WorkflowReceipt<SecurityAgentRun>>() : await manualRunMutation.execute({ id: selected.value.id, version: activation.version, value }, (intent, attempt) => api.runSecurityAgent(intent.id, intent.version, intent.value, attempt));
      onRun(receipt.value);
    } catch { setError(true); } finally { setBusy(false); }
  };
  const supported = actions.filter((action) => selected.value.allowed_actions.includes(action.key));
  const locked = mutation.isUnresolved || activationMutation.isUnresolved || simulationMutation.isUnresolved || manualRunMutation.isUnresolved;
  return <Drawer open title={selected.value.name} closeDisabled={locked} onClose={onClose}><div className="detail-content">{monitorUnavailable && <p>Monitor execution is currently unavailable.</p>}<p><Badge tone={activation.enabled ? "success" : "neutral"}>{activation.activation}</Badge> Resource version {activation.version}</p><Field label="Definition name" value={name} disabled={!canWrite || busy || locked} onChange={(event) => setName(event.target.value)} /><p>{selected.value.trigger_kind} · {selected.value.environment_ids.join(", ")} · {selected.value.autonomy}</p><TriggerRuleFields value={ruleDraft} kind={selected.value.trigger_kind} disabled={!canWrite || busy || locked} onChange={setRuleDraft} /><h3>Supported action catalog</h3>{!catalogAvailable ? <p>Environment catalog access is unavailable. Configured resource actions remain subject to their own authorization.</p> : supported.length ? <ul>{supported.map((action) => <li key={action.key}>{action.key} · {action.risk_class} · approval {action.approval_floor} · verification {action.verification_kind}</li>)}</ul> : <p>This server does not support the configured actions.</p>}<h3>Template controls</h3><p>{selected.value.allowed_actions.join(", ")} · verification {selected.value.verification_kind}</p>{selected.value.existing_test && <section aria-label="Pinned existing test"><h3>Existing test</h3><p>{selected.value.existing_test.definition_id}</p><p>Test definition version {selected.value.existing_test.definition_version}</p><p>This definition retains the selected test version. Its target, prompts, credentials, and safety settings are not overridden here.</p></section>}<h3>Limits</h3><Field label="AI cost budget (nano OpenRouter credits)" inputMode="numeric" value={costBudget} disabled={!canWrite || busy || locked} onChange={(event) => setCostBudget(event.target.value)} /><p>1 OpenRouter credit = 1,000,000,000 nano-credits, not dollars. Saving returns this definition to a disabled draft and requires revalidation. Existing run limits do not change.</p>{requiresExportBudget && <p>Export drafts require an integer AI cost budget from 1 to 1,000,000,000,000 before saving. This budget cannot be left blank.</p>}{!costConfigured && <p role="status">Cost budget configuration required. Save an explicit budget before enabling execution.</p>}<p>{selected.value.max_steps} steps · {selected.value.max_duration_seconds}s · concurrency {selected.value.concurrency_limit}</p>{canWrite && <><label className="control-option"><input aria-label="Definition enabled" type="checkbox" checked={enabled} disabled readOnly /><span><strong>Definition enabled</strong><small>Activated definitions use the audited activation state. Draft edits remain disabled.</small></span></label><div className="button-row">{mutation.canRetry ? <Button disabled={busy} onClick={retry}>Retry retained definition operation</Button> : <><Button disabled={busy || locked || !validCostBudget || triggerRules === null} onClick={save}>{activation.activation === "draft" ? "Save definition" : "Save as disabled draft"}</Button><Button variant="danger" disabled={busy || locked} onClick={remove}>Delete definition</Button></>}</div>{nextActivation && <Button variant="primary" disabled={busy || locked && !activationMutation.canRetry || costDirty || rulesDirty || costRefused || !catalogAvailable || supported.length !== selected.value.allowed_actions.length || nextActivation !== "validated" && !costConfigured} onClick={() => void activate()}>{activationMutation.canRetry ? "Retry retained activation" : fresh ? nextActivation === "validated" ? "Validate definition" : nextActivation === "supervised" ? "Enable supervised execution" : "Enable autonomous execution" : "Reauthenticate to activate"}</Button>}</>}
    {!monitorUnavailable && activation.activation !== "draft" && <><h3>Zero-effect simulation</h3><Field label="Simulation goal" value={goal} maxLength={1024} disabled={busy || locked} onChange={(event) => setGoal(event.target.value)} /><Field label="Evidence ID" value={evidenceID} maxLength={128} disabled={busy || locked} onChange={(event) => setEvidenceID(event.target.value)} /><p>Evidence ID is optional for a manual run. Simulation still requires evidence.</p><div className="button-row"><Button disabled={busy || locked || !goal || !evidenceID} onClick={() => void simulate()}>{simulationMutation.canRetry ? "Retry retained simulation" : "Simulate plan"}</Button>{activation.enabled && <Button variant="primary" disabled={!canWrite || busy || locked && !manualRunMutation.canRetry} onClick={() => void startRun()}>{manualRunMutation.canRetry ? "Retry retained manual run" : activation.activation === "autonomous" ? "Start autonomous run" : "Start supervised run"}</Button>}</div>{simulation && <section aria-label="Simulation result">
      <p>Simulation only. This does not execute the proposed steps.</p>
      <h4>Simulation summary</h4><p>{simulation.summary}</p>
      <p>Plan {simulation.plan_hash}, zero side effects, expires {simulation.expires_at}</p>
      <h4>Matched evidence</h4>
      <ul aria-label="Matched evidence">{simulation.matched_evidence_ids.map((id) => <li key={id}>{id}</li>)}</ul>
      <h4>Proposed steps</h4>
      <ol aria-label="Proposed steps">{simulation.steps.map((step) => <li key={step.index} value={step.index + 1}>
        <p>{step.action}</p>
        <p>Authorization: {step.authorization}</p>
        <p>{step.approval_required ? "Approval required" : "Approval not required"}</p>
      </li>)}</ol>
    </section>}</>}
    {error && <p role="alert">{costRefused ? "Save an explicit AI cost budget as a disabled draft, then validate it again before enabling execution." : mutation.canRetry || activationMutation.canRetry || simulationMutation.canRetry || manualRunMutation.canRetry ? "The response was lost. Retry will reuse the exact retained operation." : "The Security Agent operation was rejected, changed elsewhere, or execution controls are disabled."}</p>}</div></Drawer>;
}

function RunDetail({ value, cancellation, api, canWrite, canReadTests, mutation, recoveryMutation, onRecoverySettled, onCancelled, onClose, activityScope, onNavigate, activityPermissions }: { value: SecurityAgentRunDetail; cancellation?: SecurityAgentCancellation | null; canReadTests: boolean; activityPermissions: ActivityPermissions; api: SecurityAgentsAPI; canWrite: boolean; mutation: SecurityAgentRunMutation; recoveryMutation: SingleTestRecoveryMutation; onRecoverySettled(): Promise<void>; onCancelled(run: SecurityAgentCancellation): Promise<void>; onClose(): void; activityScope?: ActivityScope; onNavigate?: (path: string) => void }) {
  const [busy, setBusy] = useState(false); const [error, setError] = useState(false);
  const locked = mutation.isUnresolved || recoveryMutation.isUnresolved;
  const trigger = value.run_context?.trigger;
  // Registered migration 24 persists the scoped session_id as trigger_id for
  // runtime_decision receipts. Manual receipt IDs have no typed destination.
  const triggerTarget: { kind: SecurityAgentActivityKind; id: string } | null = trigger && trigger.kind !== "manual" ? { kind: trigger.kind === "runtime_decision" ? "session" : trigger.kind, id: trigger.id } : null;
  const pendingAttackLab = value.execution.length === 1 && value.action_details?.length === 1 && value.action_details[0].action === "start_attack_lab" && value.action_details[0].step_id === value.execution[0].step_id && value.execution[0].action === "start_attack_lab" && value.action_details[0].result?.state === "pending" && value.action_details[0].result.outcome_id === value.execution[0].outcome_id && value.action_details[0].result.result_digest !== undefined && value.action_details[0].result.result_digest === value.execution[0].result_digest && value.action_details[0].attack_lab?.settlement === null && !value.action_details[0].attack_lab.cleanup_complete && ["queued", "leased", "running", "retryable", "cleanup"].includes(value.action_details[0].attack_lab.state);
  const cancelable = ["queued", "planning", "waiting_approval", "running", "verifying"].includes(value.run.state) && (value.ordered !== undefined || pendingAttackLab || value.execution.every((step) => step.outcome_id === undefined && step.result_digest === undefined));
  const cancel = async () => {
    setBusy(true); setError(false);
    try {
      const receipt = mutation.canRetry
        ? await mutation.retry<WorkflowReceipt<SecurityAgentCancellation>>()
        : await mutation.execute({ id: value.run.id, version: value.run.version }, (intent, attempt) => api.cancelSecurityAgentRun(intent.id, intent.version, attempt));
      await onCancelled(receipt.value);
    } catch { setError(true); } finally { setBusy(false); }
  };
  return <Drawer open title={`Run ${value.run.id}`} closeDisabled={locked} onClose={onClose}><div className="detail-content">
    <p><Badge tone={value.run.state === "contained" || value.run.state === "remediated" ? "success" : value.run.state === "failed" ? "critical" : "info"}>{value.run.state}</Badge> Version {value.run.version}</p>
    <p>Definition {value.run.agent_id}, revision {value.run.definition_version}</p>
    {value.budget_stop_reason && <p role="alert">{{
      budget_deadline_exceeded: "Run time limit reached.",
      budget_steps_exceeded: "Run step limit reached.",
      budget_tokens_exceeded: "AI token budget reached.",
      budget_cost_exceeded: "AI cost budget reached.",
      budget_usage_unknown: "AI usage or pricing could not be verified.",
    }[value.budget_stop_reason]} Review this run and any required cleanup before starting another run. Definition edits do not reset this run&apos;s limits.</p>}
    {value.run_context?.preflight_stop_reason === "attack_lab_preflight_unavailable" && <p role="alert">Attack Lab preflight unavailable. No eligible completed failed source was available for the exact test version. No reproduction was started. Review the test and start a new run when its source is ready.</p>}
    <h3>Trigger</h3>{value.run_context?.trigger ? <p>{value.run_context.trigger.kind} · {value.run_context.trigger.id} · version {value.run_context.trigger.version}</p> : <p>No trigger context is available for this run.</p>}
    {value.run.manual_trigger && <p>Manual intent: {value.run.manual_trigger.intent_digest} · version {value.run.manual_trigger.version}</p>}
    {triggerTarget && activityPermissions[triggerTarget.kind] && activityScope && onNavigate && <Button disabled={locked} onClick={() => onNavigate(activityLink(triggerTarget, activityScope))}>Open trigger record</Button>}
    {activityScope && onNavigate && activityKinds.map(kind => <SecurityAgentActivityPanel key={kind} direction="targets" kind={kind} entityID={value.run.id} scope={activityScope} permitted={activityPermissions[kind] === true} disabled={locked} onNavigate={onNavigate} />)}
    {cancellation?.ordered && <p role="status">Cleanup required: {cancellation.ordered.cleanup_required ? "yes" : "no"}</p>}
    {api.recovery && <SingleTestRecovery api={api.recovery} runID={value.run.id} version={value.run.version} canManage={canWrite}
      blocked={locked} mutation={recoveryMutation} onSettled={onRecoverySettled} />}
    {value.ordered && <OrderedExecution value={value.ordered} />}
    <h3>Evidence</h3><ul>{value.evidence_ids.map((id) => <li key={id}>{id}</li>)}</ul>
    <section className="security-agent-rationale" aria-label="AI rationale">
      <h3>AI rationale</h3>
      <p className="security-agent-rationale__disclaimer">AI-generated explanation. This does not authorize any action.</p>
      <p>{value.run_context?.rationale?.state === "available" ? value.run_context.rationale.summary : value.run_context?.rationale?.state === "withheld" ? "AI rationale was withheld by the redaction policy." : "No AI rationale is available for this run."}</p>
    </section>
    <h3>Plan</h3>{value.plan ? <><p>Plan {value.plan.plan_hash}, expires {value.plan.expires_at}</p><ol>{value.plan.steps.map((step) => <li key={step.id}>{step.action} · {step.authorization} · {step.state}</li>)}</ol></> : <p>No plan has been persisted.</p>}
    <h3>Authorization and execution</h3><p>{value.authorization} · verification {value.verification}</p>{value.execution.length ? <ul>{value.execution.map((step) => <li key={step.step_id}>{step.action} · {step.state}{step.outcome_id ? ` · outcome ${step.outcome_id}` : ""}<ActionDetails activityScope={activityScope} onNavigate={locked ? undefined : onNavigate} canReadTests={canReadTests} stepID={step.step_id} value={value.action_details?.find(detail => detail.step_id === step.step_id)} />{step.action === "create_evidence_export" && api.exports && <ExportPanel api={api.exports} runID={value.run.id} stepID={step.step_id} disabled={locked} />}</li>)}</ul> : <p>No action has executed.</p>}
    {canWrite && cancelable && !cancellation && <Button variant="danger" disabled={busy || recoveryMutation.isUnresolved || mutation.isUnresolved && !mutation.canRetry} onClick={() => void cancel()}>{mutation.canRetry ? "Retry retained run cancellation" : "Cancel run"}</Button>}
    {error && <p role="alert">{mutation.canRetry ? "The cancellation response was lost. Retry reuses the exact run, version, and idempotency key." : "The run could not be cancelled. Reopen it to load current authority."}</p>}
  </div></Drawer>;
}

function ApprovalDetail({ value, api, canWrite, canApproveIrreversible, fresh, onReauthenticate, mutation, onDecisionBoundary, onDecided, onClose }: { value: SecurityAgentApproval; api: SecurityAgentsAPI; canWrite: boolean; canApproveIrreversible: boolean; fresh: boolean; onReauthenticate(): void; mutation: SecurityAgentApprovalMutation; onDecisionBoundary(): void; onDecided(value: SecurityAgentApproval): void; onClose(): void }) {
  const operatorAttackLab = value.attack_lab !== undefined && value.approval_context?.action === "start_attack_lab";
  const approvalAuthority = value.reversible || operatorAttackLab || canApproveIrreversible;
  const [busy, setBusy] = useState(false); const [error, setError] = useState(false);
  const [contextRead, setContextRead] = useState<{ id: string; version: number; pending: boolean; failed: boolean; value?: SecurityAgentApproval } | null>(null);
  const contextRequest = useRef<AbortController | null>(null);
  useEffect(() => () => contextRequest.current?.abort(), [value.id]);
  const currentRead = contextRead?.id === value.id && contextRead.version === value.version ? contextRead : null;
  const refreshContext = async () => {
    const controller = new AbortController(); contextRequest.current?.abort(); contextRequest.current = controller;
    setContextRead({ id: value.id, version: value.version, pending: true, failed: false });
    try {
      const refreshed = await api.getSecurityAgentApproval(value.id, controller.signal);
      if (controller.signal.aborted) return;
      const { approval_context: priorContext, ...priorAuthority } = value;
      const { approval_context: nextContext, ...nextAuthority } = refreshed;
      void priorContext;
      if (Object.keys(priorAuthority).some((key) => JSON.stringify(priorAuthority[key as keyof typeof priorAuthority]) !== JSON.stringify(nextAuthority[key as keyof typeof nextAuthority]))) throw new TypeError("Approval authority changed");
      setContextRead({ id: value.id, version: value.version, pending: false, failed: false, value: { ...value, approval_context: nextContext } });
    } catch { if (!controller.signal.aborted) setContextRead({ id: value.id, version: value.version, pending: false, failed: true }); }
  };
  const decide = async (decision?: "approved" | "rejected" | "cancelled") => {
    onDecisionBoundary();
    setBusy(true); setError(false);
    try {
      let receipt: WorkflowReceipt<SecurityAgentApproval>;
      if (mutation.canRetry) receipt = await mutation.retry<WorkflowReceipt<SecurityAgentApproval>>();
      else {
        if (!decision) throw new TypeError("Approval decision is required");
        receipt = await mutation.execute({ id: value.id, version: value.version, decision }, (intent, attempt) => api.decideSecurityAgentApproval(intent.id, intent.version, intent.decision, attempt));
      }
      onDecided(receipt.value);
    } catch { setError(true); } finally { onDecisionBoundary(); setBusy(false); }
  };
  return <Drawer open title={`Approval ${value.id}`} closeDisabled={mutation.isUnresolved} onClose={onClose}><div className="detail-content">
    <p><Badge tone={value.state === "approved" ? "success" : value.state === "rejected" || value.state === "expired" ? "critical" : "info"}>{value.state}</Badge> Version {value.version}</p>
    <p>Run {value.run_id} · step {value.step_id}</p><ApprovalContext value={currentRead?.value ?? value} />
    {value.state !== "pending" && !mutation.isUnresolved && <Button disabled={currentRead?.pending} onClick={() => void refreshContext()}>Refresh approval context</Button>}
    {currentRead?.failed && <p role="status">Context could not be refreshed. The recorded decision is unchanged.</p>}
    <h3>Expected effect</h3><p>{value.expected_effect}</p><p>{value.reversible ? "Reversible" : "Not reversible"} · TTL {value.ttl_seconds}s · expires {value.expires_at}</p>
    <h3>Evidence</h3><ul>{value.evidence_summary?.map((id) => <li key={id}>{id}</li>)}</ul>
    {!approvalAuthority && <p>Identity administrator approval required</p>}
    {canWrite && value.state === "pending" && (fresh ? <div className="button-row">
      {mutation.canRetry ? <Button variant="primary" disabled={busy} onClick={() => void decide()}>Retry retained approval decision</Button> : <>
        {approvalAuthority && <Button variant="primary" disabled={busy || mutation.isUnresolved} onClick={() => void decide("approved")}>Approve</Button>}
        <Button variant="danger" disabled={busy || mutation.isUnresolved} onClick={() => void decide("rejected")}>Reject</Button>
        <Button disabled={busy || mutation.isUnresolved} onClick={() => void decide("cancelled")}>Cancel approval</Button>
      </>}
    </div> : <Button onClick={onReauthenticate}>Reauthenticate to decide</Button>)}
    {error && <p role="alert">{mutation.canRetry ? "The decision response was lost. Retry reuses the exact approval, version, decision, and idempotency key." : "The approval changed or could not be decided. Reopen it to load current authority."}</p>}
  </div></Drawer>;
}

export function SecurityAgentsView(props: Parameters<typeof SecurityAgentsScopedView>[0] & { boundaryKey?: string }) {
  return <SecurityAgentsScopedView key={`${props.boundaryKey ?? "local"}:${props.environmentID ?? "production"}`} {...props} />;
}

function SecurityAgentsScopedView({ api = defaultSecurityAgentsAPI, environmentID = "production", canWrite = true, canReadTests = false, catalogAvailable = true, canManageControls = false, canApproveIrreversible = false, fresh = false, onReauthenticate = () => undefined, surface = "all", initialSnapshot, autoLoad = true, initialRunID, activityScope, onNavigate, activityPermissions = {} }: { api?: SecurityAgentsAPI; activityPermissions?: ActivityPermissions; environmentID?: string; canWrite?: boolean; canReadTests?: boolean; catalogAvailable?: boolean; canManageControls?: boolean; canApproveIrreversible?: boolean; fresh?: boolean; onReauthenticate?: () => void; surface?: "all" | "approvals"; initialSnapshot?: SecurityAgentSnapshot; autoLoad?: boolean; initialRunID?: string; activityScope?: ActivityScope; onNavigate?: (path: string) => void }) {
  const [agents, setAgents] = useState<readonly SecurityAgentDefinition[]>(initialSnapshot?.agents ?? []);
  const [templates, setTemplates] = useState<readonly SecurityAgentTemplate[]>(initialSnapshot?.templates ?? []);
  const [actions, setActions] = useState<readonly SecurityAction[]>(initialSnapshot?.actions ?? []);
  const [runs, setRuns] = useState<readonly SecurityAgentRun[]>(initialSnapshot?.runs ?? []);
  const [approvals, setApprovals] = useState<readonly SecurityAgentApproval[]>(initialSnapshot?.approvals ?? []);
  const [controls, setControls] = useState<SecurityAgentExecutionControls | undefined>(initialSnapshot?.controls);
  const [builder, setBuilder] = useState(false);
  const [selected, setSelected] = useState<Versioned<SecurityAgentDefinition> | null>(null);
  const [selectedActivation, setSelectedActivation] = useState<SecurityAgentActivationState | null>(null);
  const [loadedRun, setSelectedRun] = useState<SecurityAgentRunDetail | null>(null);
  const selectedRun = loadedRun && (!initialRunID || loadedRun.run.id === initialRunID) ? loadedRun : null;
  const [selectedApproval, setSelectedApproval] = useState<SecurityAgentApproval | null>(null);
  const [cancellation, setCancellation] = useState<SecurityAgentCancellation | null>(null);
  const [reads] = useState(() => new AbortController());
  const readGeneration = useRef(0);
  useEffect(() => () => { reads.abort(); readGeneration.current++; }, [reads]);
  const [error, setError] = useState(false);
  const createMutation = useRetainedWorkflowMutation<SecurityAgentCreateIntent>("security-agent:create");
  const detailMutation = useRetainedWorkflowMutation<SecurityAgentDetailIntent>(`security-agent:${selected?.value.id ?? "none"}`);
  const runMutation = useRetainedWorkflowMutation<SecurityAgentRunCancelIntent>(`security-agent-run:${selectedRun?.run.id ?? "none"}`, canWrite);
  const recoveryMutation = useRetainedWorkflowMutation<RecoveryIntent>(`single-test-recovery:${selectedRun?.run.id ?? "none"}`, canWrite && Boolean(api.recovery));
  const approvalMutation = useRetainedWorkflowMutation<SecurityAgentApprovalDecisionIntent>(`security-agent-approval:${selectedApproval?.id ?? "none"}`, canWrite && fresh);
  const activationMutation = useRetainedWorkflowMutation<SecurityAgentActivationIntent>(`security-agent-activation:${selected?.value.id ?? "none"}`, canWrite && fresh);
  const simulationMutation = useRetainedWorkflowMutation<SecurityAgentSimulationIntent>(`security-agent-simulation:${selected?.value.id ?? "none"}`, canWrite);
  const manualRunMutation = useRetainedWorkflowMutation<SecurityAgentManualRunIntent>(`security-agent-manual-run:${selected?.value.id ?? "none"}`, canWrite);
  const controlMutation = useRetainedWorkflowMutation<SecurityAgentControlIntent>(`security-agent-controls:${environmentID}`, canManageControls && fresh);
  const mutationLocked = createMutation.isUnresolved || detailMutation.isUnresolved || runMutation.isUnresolved || recoveryMutation.isUnresolved || approvalMutation.isUnresolved || activationMutation.isUnresolved || simulationMutation.isUnresolved || manualRunMutation.isUnresolved || controlMutation.isUnresolved;
  const detailRead = useRef<AbortController | null>(null);
  const openRun = useCallback(async (id: string) => {
    readGeneration.current++; setCancellation(null);
    detailRead.current?.abort();
    const controller = new AbortController(); detailRead.current = controller;
    setError(false); setSelected(null); setSelectedApproval(null); setSelectedRun(null);
    try {
      const value = await api.getSecurityAgentRun(id, controller.signal);
      if (controller.signal.aborted || detailRead.current !== controller) return;
      if (value.run.id !== id) throw new TypeError("Run detail identity mismatch");
      setSelectedRun(value);
    } catch { if (!controller.signal.aborted && detailRead.current === controller) setError(true); }
  }, [api]);
  useEffect(() => { if (!autoLoad || initialRunID) return; let active = true; const controller = new AbortController(); void loadSecurityAgentSnapshot(api, canManageControls, controller.signal, catalogAvailable).then((value) => { if (active) { setAgents(value.agents); setTemplates(value.templates); setActions(value.actions ?? []); setRuns(value.runs ?? []); setApprovals(value.approvals ?? []); setControls(value.controls); } }, () => { if (active) setError(true); }); return () => { active = false; controller.abort(); }; }, [api, autoLoad, canManageControls, catalogAvailable, initialRunID]);
  useEffect(() => {
    let active = true;
    queueMicrotask(() => { if (active && initialRunID) void openRun(initialRunID); });
    return () => { active = false; detailRead.current?.abort(); };
  }, [openRun, initialRunID]);
  const open = async (id: string) => {
    readGeneration.current++;
    detailRead.current?.abort(); const controller = new AbortController(); detailRead.current = controller;
    setError(false); setSelectedRun(null); setSelectedApproval(null); setSelected(null);
    try {
      const [definition, activation] = await Promise.all([api.getSecurityAgent(id, controller.signal), api.getSecurityAgentActivation(id, controller.signal)]);
      if (controller.signal.aborted || detailRead.current !== controller) return;
      if (definition.value.id !== id || activation.id !== id || Number(definition.version.replaceAll('"', '')) !== activation.version || definition.value.enabled !== activation.enabled) throw new TypeError("Security Agent definition and activation authority diverged");
      setSelected(definition); setSelectedActivation(activation);
    } catch { if (!controller.signal.aborted && detailRead.current === controller) setError(true); }
  };
  const openApproval = async (id: string) => {
    readGeneration.current++;
    detailRead.current?.abort(); const controller = new AbortController(); detailRead.current = controller;
    setError(false); setSelected(null); setSelectedRun(null); setSelectedApproval(null);
    try {
      const value = await api.getSecurityAgentApproval(id, controller.signal);
      if (controller.signal.aborted || detailRead.current !== controller) return;
      if (value.id !== id) throw new TypeError("Approval detail identity mismatch");
      setSelectedApproval(value);
    } catch { if (!controller.signal.aborted && detailRead.current === controller) setError(true); }
  };
  const refreshRun = useCallback(async (id: string) => {
    const generation = ++readGeneration.current;
    try {
      const value = await api.getSecurityAgentRun(id, reads.signal);
      if (reads.signal.aborted || generation !== readGeneration.current) return;
      setSelectedRun(value); setRuns((items) => items.map((item) => item.id === id ? value.run : item));
      setApprovals((items) => [...items.filter((item) => item.run_id !== id), ...value.approvals]);
    } catch { if (!reads.signal.aborted && generation === readGeneration.current) { setSelectedRun(null); setError(true); } }
  }, [api, reads]);
  const selectedRunID = selectedRun?.run.id;
  const selectedApprovalID = selectedApproval?.id;
  const selectedApprovalRunID = selectedApproval?.run_id;
  useEffect(() => {
    if (!selectedApprovalID || !selectedApprovalRunID || mutationLocked) return;
    const refresh = async () => {
      const generation = ++readGeneration.current;
      try {
        const value = await api.getSecurityAgentApproval(selectedApprovalID, reads.signal);
        if (reads.signal.aborted || generation !== readGeneration.current) return;
        setSelectedApproval(value); setApprovals((items) => items.map((item) => item.id === value.id ? value : item));
      } catch { if (!reads.signal.aborted && generation === readGeneration.current) { setSelectedApproval(null); setError(true); } }
    };
    const reconnect = () => { void refresh(); };
    const timer = window.setInterval(reconnect, 5000);
    window.addEventListener("online", reconnect); window.addEventListener("focus", reconnect);
    return () => { window.clearInterval(timer); window.removeEventListener("online", reconnect); window.removeEventListener("focus", reconnect); };
  }, [api, reads, selectedApprovalID, selectedApprovalRunID, mutationLocked]);
  useEffect(() => {
    if (!selectedRunID || mutationLocked) return;
    const refresh = () => { void refreshRun(selectedRunID); };
    const timer = window.setInterval(refresh, 5000);
    window.addEventListener("online", refresh); window.addEventListener("focus", refresh);
    return () => { window.clearInterval(timer); window.removeEventListener("online", refresh); window.removeEventListener("focus", refresh); };
  }, [selectedRunID, mutationLocked, refreshRun]);
  const pendingApprovals = approvals.filter((approval) => approval.state === "pending"); const approvalHistory = approvals.filter((approval) => approval.state !== "pending");
  return <div className="page"><PageHeader title={surface === "approvals" ? "Security Agent approvals" : "Security agents"} description="Tenant-scoped response definitions, redacted plans, supervised approvals, autonomous actions, outcomes, and verification." actions={!initialRunID && surface === "all" && canWrite && catalogAvailable ? <Button variant="primary" disabled={mutationLocked} onClick={() => setBuilder(true)}>Create Security Agent</Button> : undefined} />
    {initialRunID && <Card title="Linked Security Agent run"><p><code>{initialRunID}</code></p>{!selectedRun && !error && <p>Open the run to inspect its current authority.</p>}{onNavigate && <Button disabled={mutationLocked} onClick={() => onNavigate("/protect/security-agents")}>All Security Agent runs</Button>}<Button disabled={mutationLocked} onClick={() => void openRun(initialRunID)}>Reload linked run</Button></Card>}
    {error && <p role="alert">Security Agent data is unavailable. Retry the page to load current tenant authority.</p>}
    {!initialRunID && surface === "all" && canManageControls && controls && <ExecutionControls value={controls} api={api} fresh={fresh} mutation={controlMutation} onReauthenticate={onReauthenticate} onChange={setControls} />}
    {!initialRunID && surface === "all" && !catalogAvailable && <p role="status">Environment catalog access is unavailable. Creating definitions requires catalog access; permitted resources remain available.</p>}
    {!initialRunID && surface === "all" && <>{builder && canWrite && catalogAvailable && <Builder templates={templates} actions={actions} canReadTests={canReadTests} api={api} environmentID={environmentID} mutation={createMutation} onCreated={(value) => { setAgents((items) => [value, ...items]); setBuilder(false); }} />}<Card title="Security Agent definitions">{agents.length ? <div className="connection-list">{agents.map((agent) => <button type="button" key={agent.id} disabled={mutationLocked} aria-label={`Open ${agent.name}`} onClick={() => void open(agent.id)}><strong>{agent.name}</strong><span>{agent.trigger_kind}</span><span>{agent.enabled ? "enabled" : "disabled"}</span></button>)}</div> : <EmptyState title="No Security Agent definitions" description="Create one from a locally supported template." />}</Card><Card title="Security Agent runs">{runs.length ? <div className="connection-list">{runs.map((run) => <button type="button" key={run.id} disabled={mutationLocked} aria-label={`Open run ${run.id}`} onClick={() => void openRun(run.id)}><strong>{run.state}</strong><span>{run.id}</span><span>{run.evidence_ids.length} evidence item{run.evidence_ids.length === 1 ? "" : "s"}</span></button>)}</div> : <EmptyState title="No Security Agent runs" description="Automatic and manual runs appear here after durable acceptance." />}</Card></>}
    {!initialRunID && <Card title="Pending approvals">{pendingApprovals.length ? <div className="connection-list">{pendingApprovals.map((approval) => <button type="button" className="security-agent-approval-row" key={approval.id} disabled={mutationLocked} aria-label={`Open approval ${approval.id}`} aria-describedby={`approval-context-${approval.id}`} onClick={() => void openApproval(approval.id)}><strong>{approval.expected_effect}</strong><ApprovalContextFields id={`approval-context-${approval.id}`} value={approval} /></button>)}</div> : <EmptyState title="No pending approvals" description="Supervised action requests appear here before any provider effect." />}</Card>}
    {!initialRunID && approvalHistory.length > 0 && <Card title="Approval history"><div className="connection-list">{approvalHistory.map((approval) => <button type="button" className="security-agent-approval-row" key={approval.id} disabled={mutationLocked} aria-label={`Open approval ${approval.id}`} aria-describedby={`approval-context-${approval.id}`} onClick={() => void openApproval(approval.id)}><strong>{approval.state} · {approval.expected_effect}</strong><ApprovalContextFields id={`approval-context-${approval.id}`} value={approval} /></button>)}</div></Card>}
    {selected && selectedActivation && <AgentDetail selected={selected} activation={selectedActivation} actions={actions} catalogAvailable={catalogAvailable} api={api} canWrite={canWrite} fresh={fresh} onReauthenticate={onReauthenticate} mutation={detailMutation} activationMutation={activationMutation} simulationMutation={simulationMutation} manualRunMutation={manualRunMutation} onChange={(value) => { setSelected(value); setSelectedActivation((current) => current ? { ...current, activation: "draft", enabled: false, version: Number(value.version.replaceAll('"', '')) } : null); setAgents((items) => items.map((item) => item.id === value.value.id ? value.value : item)); }} onActivation={(value) => { const autonomy = value.activation === "autonomous" ? "autonomous" : "supervised"; setSelectedActivation(value); setSelected((current) => current ? { value: { ...current.value, autonomy, enabled: value.enabled }, version: `"${value.version}"` } : null); setAgents((items) => items.map((item) => item.id === value.id ? { ...item, autonomy, enabled: value.enabled } : item)); }} onRun={(value) => setRuns((items) => [value, ...items.filter((item) => item.id !== value.id)])} onDelete={() => { const id = selected.value.id; setSelected(null); setSelectedActivation(null); setAgents((items) => items.filter((item) => item.id !== id)); }} onClose={() => { setSelected(null); setSelectedActivation(null); }} />}
    {selectedRun && <RunDetail canReadTests={canReadTests} activityPermissions={activityPermissions} activityScope={activityScope} onNavigate={onNavigate} value={selectedRun} cancellation={cancellation} api={api} canWrite={canWrite} mutation={runMutation} recoveryMutation={recoveryMutation} onRecoverySettled={() => refreshRun(selectedRun.run.id)} onCancelled={async (run) => { if (reads.signal.aborted) return; setCancellation(run); await refreshRun(run.id); }} onClose={() => { readGeneration.current++; setSelectedRun(null); setCancellation(null); }} />}
    {selectedApproval && <ApprovalDetail value={selectedApproval} api={api} canWrite={canWrite} canApproveIrreversible={canApproveIrreversible} fresh={fresh} onReauthenticate={onReauthenticate} mutation={approvalMutation} onDecisionBoundary={() => { readGeneration.current++; }} onDecided={(approval) => { setSelectedApproval(approval); setApprovals((items) => items.map((item) => item.id === approval.id ? approval : item)); }} onClose={() => { readGeneration.current++; setSelectedApproval(null); }} />}
  </div>;
}

export function ProductionSecurityAgentsView({ environmentID, surface = "all", selectedID, onNavigate }: { environmentID: string; surface?: "all" | "approvals"; selectedID?: string; onNavigate?: (path: string) => void }) {
  const { client, queryScopeKey, queryGeneration, getSessionInvalidationGeneration, getScopeStaleGeneration } = useAPI();
  const session = useSession();
  const expectedScope = session.status === "authenticated" ? `${session.organizationID}/${session.workspaceID}/${session.environmentID}` : undefined;
  const exportBoundaryKey = queryScopeKey === null ? null : `${queryScopeKey}/${queryGeneration}`;
  const api = useMemo(() => {
    const sessionEpoch = getSessionInvalidationGeneration(), scopeEpoch = getScopeStaleGeneration();
    return createSecurityAgentsAPI(client, expectedScope, () => expectedScope !== undefined && exportBoundaryKey !== null && getSessionInvalidationGeneration() === sessionEpoch && getScopeStaleGeneration() === scopeEpoch);
  }, [client, expectedScope, exportBoundaryKey, getSessionInvalidationGeneration, getScopeStaleGeneration]);
  const catalogAvailable = session.status === "authenticated" && session.hasCapability("security-agents.catalog.read");
  const canManageControls = session.status === "authenticated" && session.hasCapability("security-agents.controls.manage");
  const activityPermissions: ActivityPermissions = session.status === "authenticated" ? { finding: session.hasCapability("findings.read"), attack_path: session.hasCapability("attack-paths.read"), session: session.hasCapability("sessions.read"), audit: session.hasCapability("audit.read") } : {};
  const load = useCallback((signal?: AbortSignal) => loadSecurityAgentSnapshot(api, canManageControls, signal, catalogAvailable), [api, canManageControls, catalogAvailable]);
  const query = useAPIQuery(`workflow:security-agents:${environmentID}`, load, !selectedID);
  if (selectedID && queryScopeKey !== null && session.status === "authenticated") return <SecurityAgentsView key={`${queryScopeKey}/${queryGeneration}/${selectedID}`} api={api} initialRunID={selectedID} canReadTests={session.hasCapability("red-team.read")} catalogAvailable={catalogAvailable} autoLoad={false} environmentID={environmentID} canWrite={session.hasCapability("security-agents.write")} fresh={session.isFreshAuthenticated} activityScope={session} activityPermissions={activityPermissions} onNavigate={onNavigate} />;
  if (query.status === "loading" || query.status === "idle") return <LoadingState label="Loading Security Agents…" />;
  if (query.status === "forbidden") return <p role="alert">You are not authorized to view Security Agents.</p>;
  if (query.status === "error") return <p role="alert">Security Agent definitions are unavailable. <Button onClick={() => void query.retry()}>Retry</Button></p>;
  if (!query.data) return null;
  return <SecurityAgentsView key={`${queryScopeKey}/${queryGeneration}/${surface}`} api={api} initialSnapshot={query.data} catalogAvailable={catalogAvailable} autoLoad={false} environmentID={environmentID} canWrite={session.hasCapability("security-agents.write")} canReadTests={session.hasCapability("red-team.read")} canManageControls={canManageControls} canApproveIrreversible={canManageControls} fresh={session.isFreshAuthenticated} onReauthenticate={session.reauthenticate} surface={surface} activityScope={session.status === "authenticated" ? session : undefined} activityPermissions={activityPermissions} onNavigate={onNavigate} />;
}
