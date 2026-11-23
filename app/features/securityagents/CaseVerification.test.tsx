import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import type { SecurityCaseVerification } from "../../../apps/web/api/generated";
import { CaseVerification } from "./CaseVerification";

const caseID = "pid_10000000-0000-4000-8000-000000000001";
const fixture = "pid_10000000-0000-4000-8000-000000000002";
const open: SecurityCaseVerification = {
  case_id: caseID, state: "open", reason: "owner_fixture_required", fixture_run_id: null, security_check_passed: false,
  business_task_preserved: false, security_receipt_id: null, business_receipt_id: null,
};
it("requires explicit approval and displays both persisted receipts", async () => {
  const verified: SecurityCaseVerification = { ...open, state: "verified_complete", fixture_run_id: fixture, security_check_passed: true,
    business_task_preserved: true, security_receipt_id: "blocked-1", business_receipt_id: "business-2", reason: "applied_block_and_complete_target_readback" };
  const api = { get: vi.fn().mockResolvedValue(open), submit: vi.fn().mockResolvedValue(verified) };
  render(<CaseVerification id={caseID} api={api} canWrite fresh locked={false} reauthenticate={vi.fn()} />);
  await userEvent.type(await screen.findByLabelText("Fixture run ID"), fixture);
  expect(screen.getByRole("button", { name: "Verify both checks" })).toBeDisabled();
  await userEvent.click(screen.getByRole("checkbox"));
  await userEvent.click(screen.getByRole("button", { name: "Verify both checks" }));
  expect(await screen.findByText("Verified complete")).toBeVisible();
  expect(screen.getByText("blocked-1")).toBeVisible();
  expect(screen.getByText("business-2")).toBeVisible();
});

it("records the owner's missing-fixture attestation without showing business success", async () => {
  const fallback: SecurityCaseVerification = { ...open, state: "closed_business_task_unverified", fixture_run_id: fixture,
    security_check_passed: true, security_receipt_id: "blocked-1", reason: "owner_attested_no_business_fixture" };
  const api = { get: vi.fn().mockResolvedValue(open), submit: vi.fn().mockResolvedValue(fallback) };
  render(<CaseVerification id={caseID} api={api} canWrite fresh locked={false} reauthenticate={vi.fn()} />);
  await userEvent.type(await screen.findByLabelText("Fixture run ID"), fixture);
  await userEvent.selectOptions(screen.getByRole("combobox", {name:"Business task fixture"}), "unavailable");
  const save = screen.getByRole("button", {name:"Record security check only"});
  expect(save).toBeDisabled();
  await userEvent.click(screen.getByRole("checkbox"));
  await userEvent.click(save);
  expect(await screen.findByText("Closed · business task unverified")).toBeVisible();
  expect(api.submit).toHaveBeenCalledWith(caseID, fixture, true);
  expect(screen.getByText("Unverified")).toBeVisible();
});
