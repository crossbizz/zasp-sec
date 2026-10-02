import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { SecurityAgentActionDetail } from "../../../apps/web/api/generated";
import { ActionDetails } from "./ActionDetails";

const target = "pid_78000001-0000-4000-8000-000000000001";
const assignee = "pid_78000002-0000-4000-8000-000000000002";
const note = "<img src=x onerror=alert(1)> Check persisted evidence";
const base: SecurityAgentActionDetail = {
  step_id: target, action: "update_finding_response",
  arguments: { target_id: target, expected_version: 2, target_status: "under_review" },
  result: null, ttl_seconds: null, control_expires_at: null,
  rollback: { support: "manual", state: "unavailable", verification: { state: "unavailable", source: "none" } },
  verification: { state: "unavailable", source: "none" },
};

describe("persisted finding response details", () => {
  // Missing metadata rendering or HTML interpretation must fail this test.
  it.each([["open", "open"], ["investigating", "under_review"]] as const)("renders actual %s metadata safely as text", (response_status, target_status) => {
    const enriched = { ...base, arguments: { target_id: target, expected_version: 2, target_status, assignee_id: assignee, response_status, note } };
    const { container } = render(<ActionDetails value={enriched} stepID={target} />);
    expect(screen.getByText(`Assignee: ${assignee}`)).toBeInTheDocument();
    expect(screen.getByText(`Response status: ${response_status}`)).toBeInTheDocument();
    expect(screen.getByText(`Response note: ${note}`)).toBeInTheDocument();
    expect(screen.getByText(`Target status: ${target_status}`)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("No effect result recorded.")).toBeInTheDocument();
    expect(screen.getByText("Manual restoration only")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("keeps legacy details without inventing assignment or notes", () => {
    render(<ActionDetails value={base} stepID={target} />);
    expect(screen.getByText("Target status: under_review")).toBeInTheDocument();
    expect(screen.queryByText(/^Assignee:|^Response status:|^Response note:/)).not.toBeInTheDocument();
  });
});
