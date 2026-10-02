import { render, screen, within } from "@testing-library/react";
import { expect, it } from "vitest";
import { decodeSecurityAgentApproval, decodeSecurityAgentRunDetail } from "../../../apps/web/api/decoders";
import { ApprovalContext } from "./ApprovalContext";

const run = "pid_78000001-0000-4000-8000-000000000001";
const step = "pid_78000002-0000-4000-8000-000000000002";
const source = "pid_78000003-0000-4000-8000-000000000003";
const selection = [{ source_kind: "finding", source_id: source, source_version: 7, association_digest: `sha256:${"a".repeat(64)}` }];
const approval = {
  id: step, run_id: run, step_id: step, state: "pending", expires_at: "2030-01-01T00:00:00Z", version: 1,
  expected_effect: "Create run-scoped evidence export", reversible: true, ttl_seconds: 0, evidence_summary: [source],
  approval_context: { agent_id: source, action: "create_evidence_export", target_id: run,
    plan_hash: `sha256:${"b".repeat(64)}`, catalog_version: "security-agent-actions-v1",
    requester: { state: "withheld", id: null }, reason: { code: "operator_approval_required", source: "persisted_step" },
    risk: { class: "low", source: "action_catalog" }, rationale: null, export_selection: selection },
};

it("shows the decoded approved selection and limits of artifact expiry", () => {
  render(<ApprovalContext value={decodeSecurityAgentApproval(approval)} />);
  const items = within(screen.getByRole("list", { name: "Approved export evidence" })).getAllByRole("listitem");
  expect(items).toHaveLength(1);
  expect(items[0]).toHaveTextContent(`finding: ${source} · version 7`);
  expect(screen.getByText(/cannot recall files already downloaded/i)).toBeInTheDocument();
});

it("refuses missing, foreign or malformed export authority", () => {
  for (const context of [
    { ...approval.approval_context, export_selection: undefined },
    { ...approval.approval_context, export_selection: [] },
    { ...approval.approval_context, export_selection: [selection[0], selection[0]] },
    { ...approval.approval_context, export_selection: [{ ...selection[0], key: "private" }] },
    { ...approval.approval_context, target_id: step },
  ]) expect(() => decodeSecurityAgentApproval({ ...approval, approval_context: context })).toThrow();
  for (const delta of [{ ttl_seconds: 60 }, { reversible: false }, { expected_effect: "Move finding to under review" }]) {
    expect(() => decodeSecurityAgentApproval({ ...approval, ...delta })).toThrow();
  }
  expect(() => decodeSecurityAgentApproval({ ...approval, expected_effect: "Move finding to under review", approval_context: { ...approval.approval_context, action: "update_finding_response" } })).toThrow();
});

it("binds the export approval to the run's matching planned action", () => {
  const value = { run: { id: run, agent_id: source, state: "waiting_approval", evidence_ids: [source], definition_version: 1, version: 1 },
    evidence_ids: [source], authorization: "approval_required", verification: "not_started", approvals: [approval],
    plan: { plan_hash: approval.approval_context.plan_hash, catalog_version: "security-agent-actions-v1", expires_at: approval.expires_at,
      steps: [{ id: step, index: 0, action: "create_evidence_export", authorization: "approval_required", state: "waiting_approval", version: 1 }] },
    execution: [{ step_id: step, action: "create_evidence_export", state: "waiting_approval", version: 1 }] };
  expect(decodeSecurityAgentRunDetail(value)).toEqual(value);
  expect(() => decodeSecurityAgentRunDetail({ ...value, plan: { ...value.plan, steps: [{ ...value.plan.steps[0], action: "run_test" }] }, execution: [{ ...value.execution[0], action: "run_test" }] })).toThrow();
});
