import { describe, expect, it, vi } from "vitest";

import { APITransportError, type APIClient } from "../../../apps/web/api/client";
import type { Policy } from "../../../apps/web/api/generated";
import { createPoliciesAPI, createRetainedWorkflowMutationController, createWorkflowMutationAttempt, workflowIdempotencyKey } from "./api";

const policy: Policy = { id: "policy-production", name: "Production", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" };
const environmentID = "pid_10000003-0000-4000-8000-000000000003";

describe("production workflow API", () => {
  it("uses a caller key and quoted version from the generated contract", async () => {
    const GET = vi.fn(async () => ({ data: policy, response: new Response(JSON.stringify(policy), { status: 200, headers: { ETag: '"3"', "Content-Type": "application/json" } }) }));
    const POST = vi.fn(async () => ({ data: { policy_id: policy.id, state: "enforced", target_id: environmentID }, response: new Response("{}", { status: 200, headers: { ETag: '"4"', "X-Audit-ID": "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Content-Type": "application/json" } }) }));
    const api = createPoliciesAPI({ GET, POST } as unknown as APIClient);
    const current = await api.getPolicy(policy.id);
    await api.rolloutPolicy(policy.id, current.version, { state: "enforced", target_id: environmentID });

    expect(current).toEqual({ value: policy, version: '"3"' });
    expect(POST).toHaveBeenCalledWith("/api/v1/policies/{id}/rollout", expect.objectContaining({
      params: { path: { id: policy.id }, header: { "Idempotency-Key": expect.stringMatching(/^wf_/), "If-Match": '"3"' } },
    }));
  });

  it("retains the exact attempt key when reconciling an ambiguous lost response", async () => {
    let calls = 0;
    const POST = vi.fn(async () => {
      calls++;
      if (calls === 1) throw new APITransportError("timeout", "response lost");
      return { data: policy, response: new Response(JSON.stringify(policy), { status: 201, headers: { ETag: '"1"', "X-Audit-ID": "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Content-Type": "application/json" } }) };
    });
    const attempt = createWorkflowMutationAttempt();
    const api = createPoliciesAPI({ POST } as unknown as APIClient);
    await expect(api.createPolicy(policy, attempt)).resolves.toMatchObject({ value: policy, version: '"1"' });
    expect(POST).toHaveBeenCalledTimes(2);
    const requestCalls = POST.mock.calls as unknown as Array<[string, { params: { header: Record<string, string> } }]>;
    expect(requestCalls[0]?.[1].params.header).toEqual({ "Idempotency-Key": attempt.idempotencyKey });
    expect(requestCalls[1]?.[1].params.header).toEqual({ "Idempotency-Key": attempt.idempotencyKey });
  });

  it("replays a native fetch rejection with the same client attempt", async () => {
    const POST = vi.fn()
      .mockRejectedValueOnce(new TypeError("fetch failed after commit"))
      .mockResolvedValueOnce({ data: policy, response: new Response(JSON.stringify(policy), { status: 201, headers: { ETag: '"1"', "X-Audit-ID": "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Content-Type": "application/json" } }) });
    const attempt = createWorkflowMutationAttempt();
    const api = createPoliciesAPI({ POST } as unknown as APIClient);

    await expect(api.createPolicy(policy, attempt)).resolves.toMatchObject({ version: '"1"' });
    expect(POST.mock.calls.map(([, options]) => options.params.header["Idempotency-Key"])).toEqual([attempt.idempotencyKey, attempt.idempotencyKey]);
  });

  it("freezes one attempt and canonical intent across two lost responses and a manual retry", async () => {
    const controller = createRetainedWorkflowMutationController<{ name: string; configuration: Record<string, string> }>();
    const observed: Array<{ key: string; intent: { name: string; configuration: Record<string, string> } }> = [];
    let calls = 0;
    const send = vi.fn(async (intent: { name: string; configuration: Record<string, string> }, attempt: { idempotencyKey: string }) => {
      observed.push({ key: attempt.idempotencyKey, intent });
      calls++;
      if (calls <= 2) throw new TypeError("response lost after commit");
      return "replayed";
    });
    const mutableIntent = { name: "Original", configuration: { account: "production" } };

    await expect(controller.execute(mutableIntent, send)).rejects.toThrow("response lost after commit");
    expect(controller.hasAmbiguousAttempt()).toBe(true);
    mutableIntent.name = "Changed after send";
    mutableIntent.configuration.account = "foreign";

    await expect(controller.execute({ name: "Ordinary retry must be ignored", configuration: { account: "other" } }, send)).resolves.toBe("replayed");
    expect(new Set(observed.map(({ key }) => key)).size).toBe(1);
    expect(observed.map(({ intent }) => intent)).toEqual([
      { name: "Original", configuration: { account: "production" } },
      { name: "Original", configuration: { account: "production" } },
      { name: "Original", configuration: { account: "production" } },
    ]);
    expect(observed.every(({ intent }) => Object.isFrozen(intent) && Object.isFrozen(intent.configuration))).toBe(true);
    expect(controller.hasAmbiguousAttempt()).toBe(false);
  });

  it("permits a fresh attempt only after a definitive result or explicit server reconciliation", async () => {
    const controller = createRetainedWorkflowMutationController<{ name: string }>();
    const keys: string[] = [];
    const ambiguous = async (_intent: Readonly<{ name: string }>, attempt: { idempotencyKey: string }) => {
      keys.push(attempt.idempotencyKey);
      throw new APITransportError("timeout", "lost");
    };
    await expect(controller.execute({ name: "one" }, ambiguous)).rejects.toThrow("lost");
    await expect(controller.execute({ name: "two" }, ambiguous)).rejects.toThrow("lost");
    expect(new Set(keys).size).toBe(1);

    controller.resolveAfterServerReconciliation();
    await expect(controller.execute({ name: "two" }, ambiguous)).rejects.toThrow("lost");
    expect(new Set(keys).size).toBe(2);
  });

  it("generates unique bounded protocol keys", () => {
    const first = workflowIdempotencyKey();
    const second = workflowIdempotencyKey();
    expect(first).not.toBe(second);
    expect(first).toMatch(/^wf_[0-9a-f-]{36}$/);
    expect(first.length).toBeGreaterThanOrEqual(16);
    expect(first.length).toBeLessThanOrEqual(128);
  });

  it("loads durable policy decisions through the generated operation", async () => {
    const decision = { id: "pid_30000005-0000-4000-8000-000000000005", policy_id: policy.id, environment_id: environmentID, result: "monitor" as const, correlation_id: "pid_30000006-0000-4000-8000-000000000006", at: "2026-08-18T12:00:00Z" };
    const GET = vi.fn(async () => ({ data: { items: [decision] }, response: new Response(JSON.stringify({ items: [decision] }), { status: 200, headers: { "Content-Type": "application/json" } }) }));
    const api = createPoliciesAPI({ GET } as unknown as APIClient);

    await expect(api.listPolicyDecisions(policy.id)).resolves.toEqual([decision]);
    expect(GET).toHaveBeenCalledWith("/api/v1/policies/{id}/decisions", { params: { path: { id: policy.id } }, signal: undefined });
  });
});
