import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { APIProductError, type APIClient } from "../../../apps/web/api/client";
import type {
  AnalystThread,
  Policy,
  SecurityAgentApproval,
  SecurityAgentRunDetail,
  StudioReviewHandoff,
} from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { InvestigationPolicyDraft } from "./InvestigationPolicyDraft";
import { pendingSessionApproval } from "./InvestigationHandoff";

const sessionID = "pid_10000000-0000-4000-8000-000000000001",
  receipt = "pid_10000000-0000-4000-8000-000000000002";
vi.mock("../../auth/SessionProvider", () => ({
  useSession: () => ({
    status: "authenticated",
    organizationID: sessionID,
    workspaceID: sessionID,
    environmentID: sessionID,
    hasCapability: () => true,
    isFreshAuthenticated: true,
    reauthenticate: vi.fn(),
  }),
}));

const handoff: StudioReviewHandoff = {
  studio_id: receipt,
  revision: 1,
  proposal: "propose_policy",
  message_id: receipt,
};
const thread: AnalystThread = {
  id: receipt,
  session_id: sessionID,
  created_at: "2026-11-21T11:00:00Z",
  handoff,
  messages: [
    {
      id: receipt,
      created_at: "2026-11-21T11:01:00Z",
      role: "assistant",
      text: "Recorded session evidence",
      evidence_ids: [receipt],
    },
  ],
};
const result = (data: unknown, status = 200, headers = {}) => ({
  data,
  response: new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  }),
});

it("rechecks the cited action before saving a retained monitoring draft for human review", async () => {
  let current = true;
  const GET = vi.fn(async (path: string) => {
    if (path.endsWith("threads/{id}")) return result(current ? thread : { ...thread, handoff: undefined });
    if (path.endsWith("/intent"))
      return result({
        session_id: sessionID,
        links: [],
        truncated: false,
        actions: [
          {
            decision_id: sessionID,
            operation: "draft_reply",
            observed_at: "2026-11-21T11:00:00Z",
            source: "authenticated_workload",
            evidence_ids: [receipt],
            outcome: "completed",
            attention: false,
          },
        ],
      });
    throw new APIProductError(404, {
      code: "not_found",
      message: "Unavailable",
      correlation_id: receipt,
      retryable: false,
    });
  });
  const POST = vi.fn(async (_path: string, { body }: { body: Policy }) =>
    result(body, 201, { ETag: '"1"', "X-Audit-ID": receipt, "X-Mutation-Receipt-ID": receipt }),
  );
  render(
    <APIProvider client={{ GET, POST } as unknown as APIClient}>
      <InvestigationPolicyDraft thread={thread} handoff={handoff} />
    </APIProvider>,
  );
  await userEvent.click(screen.getByRole("button", { name: "Review cited operations" }));
  const save = await screen.findByRole("button", { name: "Save policy draft" });
  current = false;
  await userEvent.click(save);
  expect(await screen.findByRole("alert")).toBeVisible();
  expect(POST).not.toHaveBeenCalled();
  current = true;
  await userEvent.click(save);
  const link = await screen.findByRole("link", { name: "Open saved policy" });
  expect(link).toHaveAttribute("href", expect.stringContaining("/policies?draft_id=policy-studio-"));
  expect(POST).toHaveBeenCalledTimes(1);
  expect(POST.mock.calls[0][1].body).toMatchObject({
    rollout: "draft",
    action: "monitor",
    conditions: [{ field: "action", operator: "equals", value: "draft_reply" }],
  });
});

it("offers only an unexpired reversible single-step approval with the exact session, plan and action", () => {
  const containment = { ...handoff, proposal: "request_containment" as const };
  const run = {
    run: { id: receipt, state: "waiting_approval" },
    run_context: { trigger: { kind: "runtime_decision", id: sessionID } },
    plan: {
      plan_hash: "digest",
      steps: [{ id: receipt, action: "isolate_session", authorization: "approval_required" }],
    },
  } as unknown as SecurityAgentRunDetail;
  const approval = {
    id: receipt,
    run_id: receipt,
    step_id: receipt,
    state: "pending",
    ttl_seconds: 60,
    reversible: true,
    expires_at: new Date(Date.now() + 60000).toISOString(),
    approval_context: { plan_hash: "digest", action: "isolate_session", target_id: sessionID },
  } as SecurityAgentApproval;
  expect(pendingSessionApproval(thread, containment, run, approval)).toBe(true);
  expect(pendingSessionApproval({ ...thread, session_id: receipt }, containment, run, approval)).toBe(false);
  expect(pendingSessionApproval(thread, containment, run, { ...approval, reversible: false })).toBe(false);
  expect(
    pendingSessionApproval(thread, containment, run, { ...approval, expires_at: "2021-01-01T00:00:00Z" }),
  ).toBe(false);
  expect(pendingSessionApproval(thread, containment, run, { ...approval, approval_context: undefined })).toBe(
    false,
  );
});
