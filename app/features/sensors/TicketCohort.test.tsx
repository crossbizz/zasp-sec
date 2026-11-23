import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import type { TicketCohortView } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { TicketCohort, readCohort } from "./TicketCohort";

const uid = (n: number) => `pid_7100000${n}-0000-4000-8000-00000000000${n}`;
const member = {
  id: uid(4),
  version: 1,
  generation: 1,
  policy_revision: 0,
  managed_revision: 0,
  managed_generation: 0,
  managed_mode: "",
  adapter: "macos_claude_ticket",
  state: "active",
  online: true,
  acknowledged: false,
  allowed_observed: false,
  outside_observed: false,
  queue_clear: true,
};
const v: TicketCohortView = {
  cohort: "pilot",
  environment_class: "staging",
  revision: 0,
  phase: "none",
  allowed_destination: "",
  assigned: 1,
  members: [member],
  reason: "ready",
  plan: {
    schema_version: "ticket-cohort-plan.v1",
    cohort: "pilot",
    phase: "monitor",
    expected_rollout_revision: 0,
    items: [
      {
        expected_device_version: 1,
        policy: {
          audience: "zasp.endpoint-policy.v1",
          binding: {
            organization_id: uid(1),
            workspace_id: uid(2),
            environment_id: uid(3),
            device_id: member.id,
            credential_generation: 1,
          },
          revision: 1,
          mode: "monitor",
          tool: "mcp__pilot__update_ticket",
          allowed_destination: "internal",
          issued_at: "2026-01-01T00:00:00Z",
          expires_at: "2026-01-01T01:00:00Z",
        },
      },
    ],
  },
};
it("separates signing from publication and recovers an acknowledged cohort receipt", async () => {
  const get = vi.fn(async () => ({
    data: v,
    response: new Response(null, { status: 200 }),
  }));
  const put = vi.fn(async () => ({
    data: {
      cohort: "pilot",
      phase: "monitor",
      revision: 1,
      allowed_destination: "internal",
      target_ids: [member.id],
      submitted_by: uid(5),
      submitted_at: "2026-01-01T00:00:00Z",
      request_sha256: "f".repeat(64),
    },
    response: new Response(null, { status: 200 }),
  }));
  render(
    <APIProvider client={{ GET: get, PUT: put } as unknown as APIClient}>
      <TicketCohort canWrite fresh onReauthenticate={() => {}} />
    </APIProvider>,
  );
  fireEvent.change(screen.getByLabelText("Cohort name"), {
    target: { value: "pilot" },
  });
  fireEvent.change(screen.getByLabelText("Allowed ticket destination"), {
    target: { value: "internal" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Inspect cohort" }));
  expect(
    await screen.findByRole("button", { name: "Download signing plan" }),
  ).toBeVisible();
  expect(screen.getByRole("rowheader", { name: member.id })).toHaveAttribute("scope", "row");
  expect(screen.getByRole("columnheader", { name: "Observed ticket calls" })).toHaveAttribute("scope", "col");
  expect(put).not.toHaveBeenCalled();
  const raw = JSON.stringify({
    schema_version: "ticket-cohort-bundle.v1",
    cohort: "pilot",
    phase: "monitor",
    expected_rollout_revision: 0,
    items: [
      {
        expected_device_version: 1,
        bundle: {
          payload: btoa(JSON.stringify(v.plan!.items[0].policy)),
          signature: "AQ==",
        },
      },
    ],
  });
  fireEvent.change(screen.getByLabelText("Signed cohort bundle"), {
    target: {
      files: [new File([raw], "signed.json", { type: "application/json" })],
    },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Publish signed monitor" }),
  );
  await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
  expect(
    await screen.findByText(/Published monitor revision 1 to 1 devices/),
  ).toBeVisible();
});
it("explains the independent-proof gate and withholds operator controls from readers", async () => {
  const result = {
    ...v,
    phase: "canary",
    revision: 2,
    plan: null,
    reason: "independent_ticket_proof_required",
  };
  render(
    <APIProvider
      client={
        {
          GET: async () => ({
            data: result,
            response: new Response(null, { status: 200 }),
          }),
        } as unknown as APIClient
      }
    >
      <TicketCohort
        canWrite={false}
        fresh={false}
        onReauthenticate={() => {}}
      />
    </APIProvider>,
  );
  fireEvent.change(screen.getByLabelText("Cohort name"), {
    target: { value: "pilot" },
  });
  fireEvent.change(screen.getByLabelText("Rollout phase"), {
    target: { value: "promote" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Inspect cohort" }));
  expect(
    await screen.findByText(/Attach the canary’s paired action digests/),
  ).toBeVisible();
  expect(screen.queryByLabelText("Signed cohort bundle")).toBeNull();
  expect(() =>
    readCohort({ ...v, members: [] }, v.cohort, "monitor"),
  ).toThrow();
  expect(() =>
    readCohort(v, v.cohort, "monitor", {
      organizationID: uid(9),
      workspaceID: uid(2),
      environmentID: uid(3),
    }),
  ).toThrow();
});
