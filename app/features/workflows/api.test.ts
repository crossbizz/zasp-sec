import { describe, expect, it, vi } from "vitest";

import { APIProductError, APITransportError, type APIClient } from "../../../apps/web/api/client";
import { decodeIntegrationPage, decodePolicyPage } from "../../../apps/web/api/decoders";
import type { Integration, Policy } from "../../../apps/web/api/generated";
import { createSecurityAgentsAPI } from "../securityagents/SecurityAgentsView";
import { createIntegrationsAPI, createPoliciesAPI, createRetainedWorkflowMutationController, createWorkflowMutationAttempt, createWorkflowRecoveryAPI, workflowIdempotencyKey } from "./api";

const policy: Policy = { id: "policy-production", name: "Production", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" };
const environmentID = "pid_10000003-0000-4000-8000-000000000003";

describe("production workflow API", () => {
	it("sends no wire body for every retained DELETE operation", async () => {
		const calls: Array<{ path: string; options: unknown }> = [];
		const client = {
			DELETE: vi.fn(async (path: string, options: unknown) => {
				calls.push({ path, options });
				return { response: new Response(null, { status: 204, headers: { ETag: `"2"`, "X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001", "X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002" } }) };
			}),
		} as unknown as APIClient;
		const attempt = createWorkflowMutationAttempt();
		await Promise.all([
			createPoliciesAPI(client).deletePolicy("policy-production", `"1"`, attempt),
			createIntegrationsAPI(client).deleteIntegration("pid_20000001-0000-4000-8000-000000000001", `"1"`, attempt),
			createSecurityAgentsAPI(client).deleteSecurityAgent("pid_20000002-0000-4000-8000-000000000002", `"1"`, attempt),
		]);
		expect(calls.map((call) => call.path)).toEqual([
			"/api/v1/policies/{id}",
			"/api/v1/integrations/{id}",
			"/api/v1/security-agents/{id}",
		]);
		for (const call of calls) expect(call.options).not.toHaveProperty("body");
	});

	it("pins receipt acknowledgement and relist to the captured scope assertion", async () => {
		const captured = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
		const headers: string[] = [];
		const client = {
			GET: vi.fn(async (_path: string, options: { headers?: Record<string, string> }) => {
				headers.push(options.headers?.["X-Zasp-Expected-Scope"] ?? "");
				return { data: { items: [] }, response: new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } }) };
			}),
			POST: vi.fn(async (_path: string, options: { headers?: Record<string, string> }) => {
				headers.push(options.headers?.["X-Zasp-Expected-Scope"] ?? "");
				return { response: new Response(null, { status: 204 }) };
			}),
		} as unknown as APIClient;
		const recovery = createWorkflowRecoveryAPI(client, captured);
		await Promise.all([
			recovery.acknowledgeReceipt("pid_60000001-0000-4000-8000-000000000001"),
			recovery.listReceipts(),
		]);
		expect(headers).toHaveLength(2);
		expect(headers).toEqual([captured, captured]);
	});
	it("strictly decodes paginated policy and integration pages", () => {
		const final = { next_cursor: null, has_more: false } as const;
		expect(() => decodePolicyPage({ items: [policy] })).toThrow();
		expect(() => decodePolicyPage({ items: [policy], page_info: final, extra: true })).toThrow();
		expect(() => decodeIntegrationPage({ items: [], page_info: { next_cursor: "bad=", has_more: true } })).toThrow();
		expect(decodePolicyPage({ items: [policy], page_info: final })).toEqual({ items: [policy], page_info: final });
	});

	it("loads every policy and integration page with a fixed request bound", async () => {
		const integration: Integration = { id: "pid_90000001-0000-4000-8000-000000000001", connector_key: "generic-webhook", name: "Webhook", configuration: { destination_url: "https://example.test/hook" }, status: "configured", created_at: "2026-08-18T00:00:00Z", updated_at: "2026-08-18T00:00:00Z" };
		for (const test of [
			{ path: "/api/v1/policies", load: (client: APIClient) => createPoliciesAPI(client).listPolicies(), item: policy },
			{ path: "/api/v1/integrations", load: (client: APIClient) => createIntegrationsAPI(client).listIntegrations(), item: integration },
		] as const) {
			const GET = vi.fn(async (_path: string, options: { params: { query: { cursor?: string; limit: number } } }) => {
				const continuing = options.params.query.cursor === undefined;
				const data = { items: [test.item], page_info: continuing ? { next_cursor: "b3JnLXBhZ2UtMg", has_more: true as const } : { next_cursor: null, has_more: false as const } };
				return { data, response: new Response(JSON.stringify(data), { status: 200, headers: { "Content-Type": "application/json" } }) };
			});
			const items = await test.load({ GET } as unknown as APIClient);
			expect(items).toEqual([test.item, test.item]);
			expect(GET).toHaveBeenNthCalledWith(1, test.path, expect.objectContaining({ params: { query: { cursor: undefined, limit: 100 } } }));
			expect(GET).toHaveBeenNthCalledWith(2, test.path, expect.objectContaining({ params: { query: { cursor: "b3JnLXBhZ2UtMg", limit: 100 } } }));
		}
	});
  it("uses a caller key and quoted version from the generated contract", async () => {
    const GET = vi.fn(async () => ({ data: policy, response: new Response(JSON.stringify(policy), { status: 200, headers: { ETag: '"3"', "Content-Type": "application/json" } }) }));
    const POST = vi.fn(async () => ({ data: { policy_id: policy.id, state: "enforced", target_id: environmentID }, response: new Response("{}", { status: 200, headers: { ETag: '"4"', "X-Audit-ID": "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "X-Mutation-Receipt-ID": "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "Content-Type": "application/json" } }) }));
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
      return { data: policy, response: new Response(JSON.stringify(policy), { status: 201, headers: { ETag: '"1"', "X-Audit-ID": "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "X-Mutation-Receipt-ID": "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "Content-Type": "application/json" } }) };
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
      .mockResolvedValueOnce({ data: policy, response: new Response(JSON.stringify(policy), { status: 201, headers: { ETag: '"1"', "X-Audit-ID": "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "X-Mutation-Receipt-ID": "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "Content-Type": "application/json" } }) });
    const attempt = createWorkflowMutationAttempt();
    const api = createPoliciesAPI({ POST } as unknown as APIClient);

    await expect(api.createPolicy(policy, attempt)).resolves.toMatchObject({ version: '"1"' });
    expect(POST.mock.calls.map(([, options]) => options.params.header["Idempotency-Key"])).toEqual([attempt.idempotencyKey, attempt.idempotencyKey]);
  });

  it("freezes one attempt and canonical intent across two lost responses and a manual retry", async () => {
    const controller = createRetainedWorkflowMutationController<Policy>();
    const observed: Array<{ key: string; intent: Policy }> = [];
    const POST = vi.fn()
      .mockRejectedValueOnce(new TypeError("first response lost after commit"))
      .mockRejectedValueOnce(new TypeError("second response lost after replay"))
      .mockResolvedValueOnce({ data: policy, response: new Response(JSON.stringify(policy), { status: 201, headers: { ETag: '"1"', "X-Audit-ID": "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "X-Mutation-Receipt-ID": "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "Content-Type": "application/json" } }) });
    const api = createPoliciesAPI({ POST } as unknown as APIClient);
    const send = (intent: Policy, attempt: { idempotencyKey: string }) => {
      observed.push({ key: attempt.idempotencyKey, intent });
      return api.createPolicy(intent, attempt);
    };
    const mutableIntent = structuredClone(policy);

    await expect(controller.execute(mutableIntent, send)).rejects.toThrow("second response lost after replay");
    expect(controller.hasAmbiguousAttempt()).toBe(true);
    (mutableIntent as { name: string }).name = "Changed after send";

    await expect(controller.execute({ ...policy, name: "Competing intent" }, send)).rejects.toThrow("different workflow mutation");
    await expect(controller.retry()).resolves.toMatchObject({ version: '"1"' });
    expect(new Set(observed.map(({ key }) => key)).size).toBe(1);
    expect(observed.map(({ intent }) => intent)).toEqual([
      policy,
      policy,
    ]);
    expect(POST).toHaveBeenCalledTimes(3);
    expect(new Set(POST.mock.calls.map(([, options]) => options.params.header["Idempotency-Key"])).size).toBe(1);
    expect(observed.every(({ intent }) => Object.isFrozen(intent) && Object.isFrozen(intent.conditions))).toBe(true);
    expect(controller.hasAmbiguousAttempt()).toBe(false);
  });

  it("retains a committed attempt after a valid retryable product error", async () => {
    const controller = createRetainedWorkflowMutationController<Policy>();
    const keys: string[] = [];
    const send = async (_intent: Policy, attempt: { idempotencyKey: string }) => {
      keys.push(attempt.idempotencyKey);
      if (keys.length < 2) throw new APIProductError(503, {
        code: "temporarily_unavailable",
        message: "The committed mutation response is not yet available.",
        correlation_id: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        retryable: true,
      });
      return "reconciled";
    };

    await expect(controller.execute(policy, send)).rejects.toMatchObject({ status: 503 });
    expect(controller.hasAmbiguousAttempt()).toBe(true);
    await expect(controller.retry()).resolves.toBe("reconciled");
    expect(new Set(keys).size).toBe(1);
  });

  it("permits a fresh attempt only after a definitive result or explicit server reconciliation", async () => {
    const controller = createRetainedWorkflowMutationController<{ name: string }>();
    const keys: string[] = [];
    const ambiguous = async (_intent: Readonly<{ name: string }>, attempt: { idempotencyKey: string }) => {
      keys.push(attempt.idempotencyKey);
      throw new APITransportError("timeout", "lost");
    };
    await expect(controller.execute({ name: "one" }, ambiguous)).rejects.toThrow("lost");
    await expect(controller.execute({ name: "two" }, ambiguous)).rejects.toThrow("different workflow mutation");
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

});
