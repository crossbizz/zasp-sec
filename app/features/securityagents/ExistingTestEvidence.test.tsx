import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { SecurityAgentActionDetail, SecurityAgentExistingTestDetail, SecurityAgentTestAttemptProof, SecurityAgentTestVerification } from "../../../apps/web/api/generated";
import { ActionDetails } from "./ActionDetails";
import userEvent from "@testing-library/user-event";

const stepID = "pid_78000001-0000-4000-8000-000000000001";
const definitionID = "pid_78000002-0000-4000-8000-000000000002";
const beforeID = "pid_78000003-0000-4000-8000-000000000003";
const afterID = "pid_78000004-0000-4000-8000-000000000004";
const effectID = "pid_78000005-0000-4000-8000-000000000005";
const before: SecurityAgentTestAttemptProof = {
  run_id: beforeID, attempt: 1, input_digest: "a".repeat(64),
  input_artifact: { reference_digest: "b".repeat(64), version_id: "baseline-input-v1", sha256: "c".repeat(64), size_bytes: 120 },
  output_artifact: { reference_digest: "d".repeat(64), version_id: "baseline-output-v1", sha256: "e".repeat(64), size_bytes: 230 },
};
const after: SecurityAgentTestAttemptProof = {
  run_id: afterID, attempt: 2, input_digest: "f".repeat(64),
  input_artifact: { reference_digest: "1".repeat(64), version_id: "linked-input-v2", sha256: "2".repeat(64), size_bytes: 340 },
  output_artifact: { reference_digest: "3".repeat(64), version_id: "linked-output-v2", sha256: "4".repeat(64), size_bytes: 450 },
};
const verification: SecurityAgentTestVerification = {
  outcome: "remediated", reason: "test_condition_changed", proof_digest: `sha256:${"5".repeat(64)}`, before, after,
  checks: [{ category: "prompt_injection", check_id: "zasp.curated.prompt_injection.v1", prompt_digest: "6".repeat(64), assertion_digest: "7".repeat(64), before_protected: false, after_protected: true, before_http_status: 200, after_http_status: 200 }],
};
const pending: SecurityAgentExistingTestDetail = {
  definition_id: definitionID, definition_version: 7, test_run_id: afterID,
  state: "pending", cancellation_outcome: null, verification: null,
};
const action: SecurityAgentActionDetail = {
  step_id: stepID, action: "rerun_test", arguments: { target_id: definitionID, expected_version: 7 },
  result: { state: "succeeded", outcome_id: effectID, result_digest: verification.proof_digest },
  ttl_seconds: null, control_expires_at: null,
  rollback: { support: "not_supported", state: "unavailable", verification: { source: "none", state: "unavailable" } },
  verification: { source: "effect_record", state: "verified" },
};

function show(existing_test: SecurityAgentExistingTestDetail) {
  render(<ActionDetails stepID={stepID} value={{ ...action, existing_test }} />);
  return within(screen.getByRole("region", { name: "Recorded test evidence" }));
}

describe("recorded test evidence in action details", () => {
  it("opens each recorded run through its exact current-scope history URL", async () => {
    const scope = { organizationID: definitionID, workspaceID: stepID, environmentID: effectID };
    let destination = "";
    render(<ActionDetails stepID={stepID} value={{ ...action, existing_test: { ...pending, state: "settled", verification } }} activityScope={scope} canReadTests onNavigate={path => { destination = path; }} />);
    for (const [label, id] of [["Open linked test run", afterID], ["Open before test run", beforeID], ["Open after test run", afterID]]) {
      const expected = `/red-team/results?entity_id=${id}&organization_id=${definitionID}&workspace_id=${stepID}&environment_id=${effectID}`;
      const link = screen.getByRole("link", { name: label });
      expect(link).toHaveAttribute("href", expected);
      await userEvent.click(link);
      expect(destination).toBe(expected);
    }
  });

  it.each(["permission", "scope"])("does not emit test history links without %s", missing => {
    render(<ActionDetails stepID={stepID} value={{ ...action, existing_test: pending }} activityScope={missing === "scope" ? undefined : { organizationID: definitionID, workspaceID: stepID, environmentID: effectID }} canReadTests={missing !== "permission"} onNavigate={() => undefined} />);
    expect(screen.getByRole("region", { name: "Recorded test evidence" })).toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });

  it("keeps pending test verification separate from a succeeded action effect", () => {
    const evidence = show(pending);
    expect(screen.getByText("Effect state: succeeded")).toBeInTheDocument();
    expect(evidence.getByText("Test verification pending.")).toBeInTheDocument();
    expect(evidence.getByText(`Test definition: ${definitionID}`)).toBeInTheDocument();
    expect(evidence.getByText("Test definition version: 7")).toBeInTheDocument();
    expect(evidence.getByText(`Linked test run: ${afterID}`)).toBeInTheDocument();
    expect(evidence.getByText(/Recorded evidence, not current provider health or a fresh test/)).toBeInTheDocument();
    expect(evidence.queryByText(/Test outcome:/)).not.toBeInTheDocument();
    expect(evidence.queryByRole("table")).not.toBeInTheDocument();
  });

  it("renders stored remediation and immutable identities with the before/after comparison", () => {
    const evidence = show({ ...pending, state: "settled", verification });
    expect(evidence.getByText("Test verification settled.")).toBeInTheDocument();
    expect(evidence.getByText("Test outcome: Remediated")).toBeInTheDocument();
    expect(evidence.getByText("Reason: Test condition changed.")).toBeInTheDocument();
    expect(evidence.getByText(`Proof digest: sha256:${"5".repeat(64)}`)).toBeInTheDocument();
    const baseline = within(evidence.getByRole("region", { name: "Before test attempt" }));
    const linked = within(evidence.getByRole("region", { name: "After test attempt" }));
    expect(baseline.getByText(`Run: ${beforeID}`)).toBeInTheDocument();
    expect(baseline.getByText("Attempt: 1")).toBeInTheDocument();
    expect(baseline.getByText(`Input digest: ${"a".repeat(64)}`)).toBeInTheDocument();
    expect(linked.getByText(`Run: ${afterID}`)).toBeInTheDocument();
    expect(linked.getByText("Attempt: 2")).toBeInTheDocument();
    expect(linked.getByText(`Input digest: ${"f".repeat(64)}`)).toBeInTheDocument();
    for (const [attempt, expected] of [[baseline, before], [linked, after]] as const) {
      for (const [name, artifact] of [["Input artifact", expected.input_artifact], ["Output artifact", expected.output_artifact]] as const) {
        const metadata = within(attempt.getByRole("region", { name }));
        expect(metadata.getByText(`Reference digest: ${artifact.reference_digest}`)).toBeInTheDocument();
        expect(metadata.getByText(`Version ID: ${artifact.version_id}`)).toBeInTheDocument();
        expect(metadata.getByText(`SHA-256: ${artifact.sha256}`)).toBeInTheDocument();
        expect(metadata.getByText(`Size: ${artifact.size_bytes} bytes`)).toBeInTheDocument();
      }
    }
    const comparison = within(evidence.getByRole("table", { name: "Recorded check comparison" }));
    expect(comparison.getByRole("columnheader", { name: "Before protected" })).toBeInTheDocument();
    expect(comparison.getByRole("columnheader", { name: "After protected" })).toBeInTheDocument();
    const row = within(comparison.getByRole("row", { name: /zasp.curated.prompt_injection.v1/ }));
    expect(row.getAllByRole("cell").map(cell => cell.textContent)).toEqual([
      "Prompt injection", "zasp.curated.prompt_injection.v1", "No", "Yes", "200", "200", "6".repeat(64), "7".repeat(64),
    ]);
    expect(evidence.queryByRole("link")).not.toBeInTheDocument();
  });

  it("reports a missing baseline without inventing a comparison or remediation", () => {
    const evidence = show({ ...pending, state: "settled", verification: { ...verification, outcome: "needs_human", reason: "test_baseline_unavailable", before: null, checks: [] } });
    expect(evidence.getByText("Test outcome: Needs human review")).toBeInTheDocument();
    expect(evidence.getByText("Reason: Test baseline unavailable.")).toBeInTheDocument();
    expect(evidence.getByText("Before test attempt: No recorded evidence.")).toBeInTheDocument();
    expect(evidence.getByRole("region", { name: "After test attempt" })).toBeInTheDocument();
    expect(evidence.getByText("No recorded check comparison.")).toBeInTheDocument();
    expect(evidence.queryByRole("table")).not.toBeInTheDocument();
    expect(evidence.queryByText(/Remediated/)).not.toBeInTheDocument();
  });

  it("describes unknown cancellation as unconfirmed execution, never confirmed cancellation", () => {
    const evidence = show({ ...pending, state: "settled", cancellation_outcome: "outcome_unknown", verification: { ...verification, outcome: "inconclusive", reason: "test_outcome_unknown", before: null, after: null, checks: [] } });
    expect(evidence.getByText("Test outcome: Inconclusive")).toBeInTheDocument();
    expect(evidence.getByText("Reason: Test outcome unknown.")).toBeInTheDocument();
    expect(evidence.getByText("Execution is unconfirmed. Cancellation was requested but its outcome is unknown.")).toBeInTheDocument();
    expect(evidence.getByText("After test attempt: No recorded evidence.")).toBeInTheDocument();
    expect(evidence.queryByText(/Test outcome: Cancelled|Test outcome: Remediated|Cancellation confirmed/)).not.toBeInTheDocument();
  });

  it("warns that confirmed partial cancellation did not undo prior work", () => {
    const evidence = show({ ...pending, state: "settled", cancellation_outcome: "cancelled_after_partial_execution", verification: { ...verification, outcome: "cancelled", reason: "test_run_cancelled", before: null, after: null, checks: [] } });
    expect(evidence.getByText("Test outcome: Cancelled")).toBeInTheDocument();
    expect(evidence.getByText("Reason: Test run cancelled.")).toBeInTheDocument();
    expect(evidence.getByText("Cancellation confirmed after partial execution. Prior work was not undone.")).toBeInTheDocument();
  });

  it("distinguishes confirmed cancellation before execution from partial execution", () => {
    const evidence = show({ ...pending, state: "settled", cancellation_outcome: "cancelled_before_execution", verification: { ...verification, outcome: "cancelled", reason: "test_run_cancelled", before: null, after: null, checks: [] } });
    expect(evidence.getByText("Cancellation confirmed before execution.")).toBeInTheDocument();
    expect(evidence.queryByText(/after partial execution/)).not.toBeInTheDocument();
  });

  it.each([
    ["needs_human", "test_condition_persists", "Needs human review", "Test condition persists."],
    ["inconclusive", "test_evidence_unavailable", "Inconclusive", "Test evidence unavailable."],
    ["inconclusive", "test_evaluation_inconclusive", "Inconclusive", "Test evaluation inconclusive."],
    ["failed", "test_run_failed", "Failed", "Test run failed."],
  ] as const)("renders the stored %s / %s result without inferring success from the action", (outcome, reason, outcomeLabel, reasonLabel) => {
    const evidence = show({ ...pending, state: "settled", verification: { ...verification, outcome, reason, before: null, checks: [] } });
    expect(evidence.getByText(`Test outcome: ${outcomeLabel}`)).toBeInTheDocument();
    expect(evidence.getByText(`Reason: ${reasonLabel}`)).toBeInTheDocument();
    expect(evidence.queryByText(/Remediated/)).not.toBeInTheDocument();
  });

  it("leaves legacy action details unchanged when no stored test envelope is present", () => {
    render(<ActionDetails stepID={stepID} value={action} />);
    expect(screen.getByText("Persisted action details")).toBeInTheDocument();
    expect(screen.getByText(`Recorded outcome: ${effectID}`)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Recorded test evidence" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Test verification pending/)).not.toBeInTheDocument();
  });
});
