import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { SecurityAgentApproval } from "../../../apps/web/api/generated";
import { ApprovalContext } from "./ApprovalContext";

const id = "pid_78000001-0000-4000-8000-000000000001";
const assignee = "pid_78000002-0000-4000-8000-000000000002";
const note = "<img src=x onerror=alert(1)> Read persisted evidence";

describe("finding approval boundary", () => {
  it.each([["open", "open"], ["investigating", "under_review"]] as const)("renders proposed %s metadata as text without claiming approval or effect", (response_status, target_status) => {
    const value: SecurityAgentApproval = { id, run_id: id, step_id: id, state: "pending", expires_at: "2030-01-01T00:00:00Z", version: 1,
      expected_effect: "Assign investigator and update finding response", reversible: true, ttl_seconds: 0, evidence_summary: [id],
      approval_context: { agent_id: id, action: "update_finding_response", target_id: id, plan_hash: `sha256:${"a".repeat(64)}`, catalog_version: "security-agent-actions-v1",
        requester: { state: "withheld", id: null }, reason: { code: "operator_approval_required", source: "persisted_step" }, risk: { class: "low", source: "action_catalog" }, rationale: null,
        finding_response: { target_id: id, expected_version: 7, target_status, assignee_id: assignee, response_status, note } } };
    const { container, rerender } = render(<ApprovalContext value={value} />);
    for (const state of ["pending", "approved", "rejected", "expired", "cancelled"] as const) {
      rerender(<ApprovalContext value={{ ...value, state }} />);
      expect(screen.getByRole("region", { name: "Proposed finding response" })).toBeInTheDocument();
      expect(screen.queryByText("Approved finding response")).not.toBeInTheDocument();
    }
    expect(screen.getByText(`Assignee: ${assignee}`)).toBeInTheDocument();
    expect(screen.getByText(`Response status: ${response_status}`)).toBeInTheDocument();
    expect(screen.getByText(`Response note: ${note}`)).toBeInTheDocument();
    expect(screen.getByText(`Target status: ${target_status}`)).toBeInTheDocument();
    expect(screen.getByText("Expected finding version: 7")).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });
  it("does not invent finding metadata for legacy approval", () => {
    const value: SecurityAgentApproval = { id, run_id: id, step_id: id, state: "pending", expires_at: "2030-01-01T00:00:00Z", version: 1,
      expected_effect: "Move finding to under review", reversible: true, ttl_seconds: 0, evidence_summary: [id] };
    render(<ApprovalContext value={value} />);
    expect(screen.queryByText(/^Assignee:|^Response note:|^Response status:/)).not.toBeInTheDocument();
  });
});
