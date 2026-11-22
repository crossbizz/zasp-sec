import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import type { AgentActionAnalysis } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { ActionAnalysis, readAnalysis } from "./ActionAnalysis";

const agent = "pid_71000001-0000-4000-8000-000000000001",
  session = "pid_71000002-0000-4000-8000-000000000002",
  decision = "pid_71000003-0000-4000-8000-000000000003";
const initial: AgentActionAnalysis = {
  agent_id: agent,
  revision: 1,
  updated_at: "2026-01-01T00:00:00Z",
  source: "bound_workload_reported",
  pending: 2,
  analyzed: 7,
  unknown_destination: 3,
  truncated: false,
  settings: {
    allowed_operations: ["ticket.read"],
    allowed_classifications: ["internal"],
    allowed_destinations: ["internal"],
    blocked_transitions: [],
  },
  findings: [
    {
      decision_id: decision,
      session_id: session,
      operation: "ticket.send",
      classification: "sensitive",
      destination_class: null,
      previous_operation: "ticket.read",
      occurred_at: "2026-01-01T01:00:00Z",
      issues: ["classification_outside_purpose"],
    },
  ],
};
const ok = (data: unknown) => ({ data, response: new Response(null, { status: 200 }) });
it("keeps missing destinations and action outcomes explicit for a reader", async () => {
  const get = vi.fn(async () => ok(initial)),
    put = vi.fn();
  const client = { GET: get, PUT: put } as unknown as APIClient;
  render(
    <APIProvider client={client}>
      <ActionAnalysis agent={agent} canManage={false} disabled={false} />
    </APIProvider>,
  );
  expect(get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Inspect workload action analysis" }));
  expect(await screen.findByText(/7 analyzed, 2 pending, 3 with unknown destination/)).toBeVisible();
  expect(screen.getByText("Reported data classification outside declaration")).toBeVisible();
  expect(screen.getByText(/destination unknown/)).toBeVisible();
  expect(screen.getByText(decision)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Save analysis settings" })).toBeNull();
  expect(put).not.toHaveBeenCalled();
  expect(() => readAnalysis({ ...initial, agent_id: session }, agent)).toThrow();
});
it("previews a bounded declaration, then submits it only with the current revision", async () => {
  const put = vi.fn(async (_path: string, params: { body: AgentActionAnalysis["settings"] }) =>
    ok({ ...initial, settings: params.body, revision: 2 }),
  );
  const client = { GET: async () => ok(initial), PUT: put } as unknown as APIClient;
  render(
    <APIProvider client={client}>
      <ActionAnalysis agent={agent} canManage disabled={false} />
    </APIProvider>,
  );
  fireEvent.click(screen.getByRole("button", { name: "Inspect workload action analysis" }));
  const field = await screen.findByLabelText("Allowed operations", { exact: false });
  fireEvent.change(field, { target: { value: "ticket.send\nticket.read" } });
  fireEvent.change(screen.getByLabelText("Restricted operation sequences", { exact: false }), {
    target: { value: "ticket.read -> ticket.send" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save analysis settings" }));
  await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
  expect(put).toHaveBeenCalledWith(
    "/api/v1/agents/{id}/action-analysis",
    expect.objectContaining({
      params: expect.objectContaining({
        header: expect.objectContaining({ "If-Match": '"1"', "Idempotency-Key": expect.any(String) }),
      }),
      body: expect.objectContaining({
        allowed_operations: ["ticket.read", "ticket.send"],
        blocked_transitions: [{ from: "ticket.read", to: "ticket.send" }],
      }),
    }),
  );
  expect(await screen.findByText("Saved action analysis revision 2.")).toBeVisible();
});
