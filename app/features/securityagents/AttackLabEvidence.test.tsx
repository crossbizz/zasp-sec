import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ActionDetails } from "./ActionDetails";
import { ApprovalContext } from "./ApprovalContext";
import type { SecurityAgentActionDetail, SecurityAgentApproval } from "../../../apps/web/api/generated";

const id = "pid_78000001-0000-4000-8000-000000000001";
const source = "pid_78000002-0000-4000-8000-000000000002";
const execution = "pid_78000003-0000-4000-8000-000000000003";
const action: SecurityAgentActionDetail = { step_id: id, action: "start_attack_lab", arguments: { target_id: id, expected_version: 7 }, result: { state: "succeeded", outcome_id: id, result_digest: `sha256:${"a".repeat(64)}` }, ttl_seconds: null, control_expires_at: null, rollback: { support: "not_supported", state: "unavailable", verification: { state: "unavailable", source: "none" } }, verification: { state: "pending", source: "effect_record" }, attack_lab: { definition_id: id, definition_version: 7, source_run_id: source, source_attempt: 2, execution_id: execution, attempt: 1, state: "complete", verdict: "verified", cleanup_state: "complete", cleanup_complete: true, cancel_requested: false, evidence: { reference_digest: "b".repeat(64), version_id: "version-1", sha256: "c".repeat(64), size_bytes: 128 }, settlement: { outcome: "needs_human", reason: "attack_lab_unsafe_condition_reproduced", proof_digest: `sha256:${"a".repeat(64)}` } } };

describe("Attack Lab user evidence", () => {
 it.each(["verified", "not_reproduced"] as const)("renders %s as human interpretation, never remediation", verdict => {
  render(<ActionDetails stepID={id} value={{ ...action, attack_lab: { ...action.attack_lab!, verdict, settlement: { ...action.attack_lab!.settlement!, reason: verdict === "verified" ? "attack_lab_unsafe_condition_reproduced" : "attack_lab_not_reproduced_in_bounded_run" } } }} />);
  expect(screen.getByText("Attack Lab outcome: Needs human")).toBeInTheDocument();
  expect(screen.getByText(verdict === "verified" ? "Unsafe condition reproduced." : "Not reproduced in this bounded run.")).toBeInTheDocument();
  expect(screen.getByText(`Source run: ${source} · attempt 2`)).toBeInTheDocument();
  expect(screen.getByText(`Execution run: ${execution} · attempt 1`)).toBeInTheDocument();
  expect(screen.getByText("Sandbox cleanup confirmed.")).toBeInTheDocument();
  expect(screen.queryByText(/Remediated/)).not.toBeInTheDocument();
 });
 it("keeps cleanup obligations visible without a terminal settlement", () => {
  render(<ActionDetails stepID={id} value={{ ...action, attack_lab: { ...action.attack_lab!, state: "cleanup", cleanup_state: "pending", cleanup_complete: false, settlement: null, cancel_requested: true } }} />);
  expect(screen.getByText("Sandbox cleanup pending. This obligation remains after the Security Agent stops.")).toBeInTheDocument();
  expect(screen.getByText("Cancellation requested; execution may already have occurred.")).toBeInTheDocument();
 });
 it("shows exact bounded approval source and non-production authority", () => {
  const approval: SecurityAgentApproval = { id, run_id: id, step_id: id, state: "pending", expires_at: "2030-01-01T00:00:00Z", version: 1, expected_effect: "Run a bounded Attack Lab reproduction; human interpretation required", reversible: false, ttl_seconds: 0, evidence_summary: [id], attack_lab: { source_run_id: source, source_attempt: 2, definition_id: id, definition_version: 7, target_id: execution, target_kind: "agent_endpoint", environment: "test", credential_class: "test_write", destination: "canary.example.test", decision_expires_at: "2030-01-01T00:00:00Z", limits: { cpu: "500m", memory: "1Gi", ephemeral_storage: "2Gi", timeout_seconds: 300 }, expected_side_effects: ["Isolated canary write"] } };
  render(<ApprovalContext value={approval} />);
  expect(screen.getByText(`Approved source: ${source} · attempt 2`)).toBeInTheDocument();
  expect(screen.getByText("Environment: test · credential class: test_write")).toBeInTheDocument();
  expect(screen.getByText("Isolated canary write")).toBeInTheDocument();
  expect(screen.getByText(/Distinct operator approval is required in both autonomy modes/)).toBeInTheDocument();
 });
});
