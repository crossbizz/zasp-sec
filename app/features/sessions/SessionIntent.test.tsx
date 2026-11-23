import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { SessionIntentPanel } from "./SessionIntent";

const session = "pid_10000000-0000-4000-8000-000000000001";
const receipt = "pid_10000000-0000-4000-8000-000000000002";
it("keeps an unknown outcome open and shows a late block with its evidence on refresh", async () => {
  let calls = 0;
  const read = vi.fn(async () => ({
    session_id: session, truncated: false, links: [], actions: [{
      decision_id: session, operation: "Draft reply", observed_at: "2026-11-20T10:00:00Z",
      source: "authenticated_workload" as const, evidence_ids: [receipt],
      outcome: calls++ === 0 ? "outcome_unknown" as const : "prevented" as const, attention: true,
    }],
  }));
  render(<SessionIntentPanel id={session} read={read} />);
  await userEvent.click(screen.getByRole("button", { name: "View outcomes" }));
  expect(await screen.findByText(/Open evidence gap/)).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Source receipt" }));
  expect(screen.getByText(receipt)).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Refresh outcomes" }));
  expect(await screen.findByText(/Review this blocked attempt/)).toBeVisible();
});

it("keeps possible follow-ups distinct from source receipts and lets the analyst inspect each step", async () => {
  const next = "pid_10000000-0000-4000-8000-000000000003";
  const read = async () => ({
    session_id: session, truncated: false, links: [{source:session, target:next, reason:"read_then_activity" as const}],
    actions: [{decision_id: next, operation:"Process executed", source:"tetragon" as const, observed_at:"2026-11-20T10:01:00Z", evidence_ids:[next], outcome:"completed" as const,attention:false},
      {decision_id:session,operation:"Read observed",source:"tetragon" as const,observed_at:"2026-11-20T10:00:00Z",evidence_ids:[receipt],outcome:"outcome_unknown" as const,attention:true}],
  });
  render(<SessionIntentPanel id={session} read={read} />);
  await userEvent.click(screen.getByRole("button",{name:"View outcomes"}));
  expect(await screen.findByText(/Dashed links connect observations/)).toBeVisible();
  await userEvent.click(screen.getByRole("button",{name:"Read observed"}));
  expect(screen.getByRole("combobox",{name:"Inspect an action"})).toHaveValue(session);
  expect(screen.getByText(/Open evidence gap/)).toBeVisible();
});
