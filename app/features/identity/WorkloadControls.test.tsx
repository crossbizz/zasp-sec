import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import { WorkloadControls, decodeBinding, decodeContainment } from "./WorkloadControls";

const id = (i: number) => "pid_11111111-1111-4111-8111-" + String(i).padStart(12, "0");
const [token, agent, session, actor, run, step, approval, block, release] = [1, 2, 3, 4, 5, 6, 7, 8, 9].map(
  id,
);
const stamp = "2026-04-02T12:00:00Z";
const binding = {
  credential_id: token,
  agent_id: agent,
  session_id: session,
  source: "administrator_bound_credential",
  created_by: actor,
  created_at: stamp,
};
const containment = {
  credential_id: token,
  run_id: run,
  step_id: step,
  session_id: session,
  approval_id: approval,
  authorized_by: actor,
  authorized_at: stamp,
  expires_at: stamp,
  state: "pending_readback",
  block_receipt_id: null,
  release_receipt_id: null,
};
const ok = (data: unknown) => ({ data, response: new Response() });
const tokens = [
  {
    id: token,
    name: "Ticket workload",
    permissions: ["decide_actions"],
    expiresAt: "2100-01-01T00:00:00Z",
    revokedAt: null,
  },
];
it("reports a pending approval, then shows adapter readback and explicit release", async () => {
  const client = {
    GET: vi
      .fn()
      .mockResolvedValueOnce(ok(binding))
      .mockResolvedValueOnce(ok({ ...containment, state: "adapter_confirmed", block_receipt_id: block })),
    PUT: vi.fn().mockResolvedValue(ok(containment)),
    DELETE: vi
      .fn()
      .mockResolvedValue(
        ok({ ...containment, state: "released", block_receipt_id: block, release_receipt_id: release }),
      ),
  };
  render(<WorkloadControls tokens={tokens} client={client as unknown as APIClient} canContain fresh />);
  fireEvent.change(screen.getByRole("combobox"), { target: { value: token } });
  await screen.findByText(session);
  fireEvent.change(screen.getByLabelText("Security Agent run ID"), { target: { value: run } });
  fireEvent.change(screen.getByLabelText("Approved isolation step ID"), { target: { value: step } });
  fireEvent.click(screen.getByRole("button", { name: "Apply approved isolation" }));
  await screen.findByText(/State pending readback/);
  expect(client.PUT).toHaveBeenCalledWith(
    expect.anything(),
    expect.objectContaining({ body: { step_id: step }, params: { path: { id: token, runId: run } } }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Check containment" }));
  await screen.findByText(/State adapter confirmed/);
  fireEvent.click(screen.getByRole("button", { name: "Release this run’s isolation" }));
  await screen.findByText(/State released/);
  expect(screen.getByText(new RegExp(release))).toBeTruthy();
});
it("rejects a valid-looking receipt for a different credential, run, or session", () => {
  expect(() => decodeBinding(binding, id(10))).toThrow();
  expect(() => decodeContainment(containment, token, id(10), session)).toThrow();
  expect(() => decodeContainment(containment, token, run, id(11))).toThrow();
});
