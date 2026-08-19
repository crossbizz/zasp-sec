import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { Policy } from "../../../apps/web/api/generated";
import { createPoliciesAPI, workflowIdempotencyKey } from "./api";

const policy: Policy = { id: "policy-production", name: "Production", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" };

describe("production workflow API", () => {
  it("uses a caller key and quoted version from the generated contract", async () => {
    const GET = vi.fn(async () => ({ data: policy, response: new Response(JSON.stringify(policy), { status: 200, headers: { ETag: '"3"', "Content-Type": "application/json" } }) }));
    const POST = vi.fn(async () => ({ data: { policy_id: policy.id, state: "enforced", target_id: "environment" }, response: new Response("{}", { status: 200, headers: { ETag: '"4"', "X-Audit-ID": "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Content-Type": "application/json" } }) }));
    const api = createPoliciesAPI({ GET, POST } as unknown as APIClient);
    const current = await api.getPolicy(policy.id);
    await api.rolloutPolicy(policy.id, current.version, { state: "enforced", target_id: "environment" });

    expect(current).toEqual({ value: policy, version: '"3"' });
    expect(POST).toHaveBeenCalledWith("/api/v1/policies/{id}/rollout", expect.objectContaining({
      params: { path: { id: policy.id }, header: { "Idempotency-Key": expect.stringMatching(/^wf_/), "If-Match": '"3"' } },
    }));
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
    const decision = { id: "decision-1", policy_id: policy.id, environment_id: "environment", result: "monitor" as const, correlation_id: "correlation-1", at: "2026-08-18T12:00:00Z" };
    const GET = vi.fn(async () => ({ data: { items: [decision] }, response: new Response(JSON.stringify({ items: [decision] }), { status: 200, headers: { "Content-Type": "application/json" } }) }));
    const api = createPoliciesAPI({ GET } as unknown as APIClient);

    await expect(api.listPolicyDecisions(policy.id)).resolves.toEqual([decision]);
    expect(GET).toHaveBeenCalledWith("/api/v1/policies/{id}/decisions", { params: { path: { id: policy.id } }, signal: undefined });
  });
});
