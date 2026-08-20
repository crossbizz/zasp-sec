import { describe, expect, it, vi } from "vitest";

import { APIProductError, APITransportError, createAPIClient, type APIClient } from "../../../apps/web/api/client";
import { decodeIntegrationPage, decodePolicyPage } from "../../../apps/web/api/decoders";
import type { Integration, Policy } from "../../../apps/web/api/generated";
import { createSecurityAgentsAPI } from "../securityagents/SecurityAgentsView";
import { createIntegrationsAPI, createPoliciesAPI, createRetainedWorkflowMutationController, createWorkflowMutationAttempt, createWorkflowReceiptReconciler, createWorkflowRecoveryAPI, workflowIdempotencyKey } from "./api";

const policy: Policy = { id: "policy-production", name: "Production", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" };
const environmentID = "pid_10000003-0000-4000-8000-000000000003";
const capturedScope = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
const integration: Integration = { id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "github", name: "GitHub", configuration: { authorization_mode: "github_app" }, status: "revoking", created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:01:00Z" };
const referenceIntegration: Integration = { id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "aws", name: "AWS", configuration: { role_arn: "arn:aws:iam::123456789012:role/zasp-discovery", external_id_reference: "ref:aws/external-id/customer-0001", region: "us-east-1" }, status: "active", created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:01:00Z" };

function referenceAuthorizationReceipt(scope = capturedScope) {
	const [organizationID, workspaceID, environmentID] = scope.split("/");
	return {
		id: "pid_11111111-1111-4111-8111-111111111111",
		operation: "completeIntegrationReferenceAuthorization",
		idempotency_key: "wf_11111111-1111-4111-8111-111111111111",
		intent: {
			configuration: referenceIntegration.configuration,
			expected_version: 1,
			idempotency_key: "wf_11111111-1111-4111-8111-111111111111",
			integration_id: referenceIntegration.id,
			provider: "aws",
			scope: { organization_id: organizationID, workspace_id: workspaceID, environment_id: environmentID },
		},
		result: referenceIntegration,
		resource_kind: "integration",
		resource_id: referenceIntegration.id,
		resource_version: 2,
		audit_id: "pid_33333333-3333-4333-8333-333333333333",
		correlation_id: "pid_44444444-4444-4444-8444-444444444444",
		created_at: "2026-08-19T00:00:00Z",
		expires_at: "2026-08-25T00:00:00Z",
	};
}

describe("production workflow API", () => {
	it("sends an exact fresh scoped reference-authorization mutation and strictly accepts its receipt", async () => {
		const attempt = createWorkflowMutationAttempt();
		const requests: Array<{ url: string; method: string; credentials: RequestCredentials; redirect: RequestRedirect; headers: Headers; body: string }> = [];
		const client = createAPIClient({
			getCSRFToken: () => "csrf_12345678901234567890123456789012",
			getExpectedScope: () => capturedScope,
			fetch: async (value) => {
				const copy = value.clone();
				requests.push({ url: copy.url, method: copy.method, credentials: copy.credentials, redirect: copy.redirect, headers: new Headers(copy.headers), body: await copy.text() });
				return new Response(JSON.stringify(referenceIntegration), { status: 200, headers: {
					"Content-Type": "application/json", "Cache-Control": "no-store", ETag: '"2"',
					"X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001",
					"X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002",
				} });
			},
		});

		await expect(createIntegrationsAPI(client).authorizeIntegrationReference(referenceIntegration.id, '"1"', attempt)).resolves.toMatchObject({
			value: referenceIntegration, version: '"2"', auditID: "pid_30000001-0000-4000-8000-000000000001", receiptID: "pid_30000002-0000-4000-8000-000000000002",
		});
		const request = requests[0];
		expect(requests).toHaveLength(1);
		expect(new URL(request!.url).pathname).toBe(`/api/v1/integrations/${referenceIntegration.id}/reference-authorization`);
		expect(request!.method).toBe("POST");
		expect(request!.credentials).toBe("same-origin");
		expect(request!.redirect).toBe("error");
		expect(request!.headers.get("Content-Type")).toBe("application/json");
		expect(request!.headers.get("Idempotency-Key")).toBe(attempt.idempotencyKey);
		expect(request!.headers.get("If-Match")).toBe('"1"');
		expect(request!.headers.get("X-CSRF-Token")).toBe("csrf_12345678901234567890123456789012");
		expect(request!.headers.get("X-Zasp-Expected-Scope")).toBe(capturedScope);
		expect(request!.headers.get("X-Zasp-Fresh-Auth")).toBe("confirmed");
		expect(request!.body).toBe("{}");
	});

	it.each([
		["missing no-store", referenceIntegration, { ...receiptHeadersForReference(), "Cache-Control": undefined }],
		["foreign integration", { ...referenceIntegration, id: "pid_20000001-0000-4000-8000-000000000099" }, receiptHeadersForReference()],
		["non-reference connector", { ...referenceIntegration, connector_key: "github", configuration: { authorization_mode: "github_app" } }, receiptHeadersForReference()],
		["non-active result", { ...referenceIntegration, status: "pending_authorization" }, receiptHeadersForReference()],
	])("rejects a reference-authorization success with %s", async (_name, value, headerValues) => {
		const headers = Object.fromEntries(Object.entries(headerValues).filter(([, item]) => item !== undefined)) as Record<string, string>;
		const POST = vi.fn(async () => ({ data: value, response: new Response(JSON.stringify(value), { status: 200, headers: { "Content-Type": "application/json", ...headers } }) }));

		await expect(createIntegrationsAPI({ POST } as unknown as APIClient).authorizeIntegrationReference(referenceIntegration.id, '"1"')).rejects.toMatchObject({ kind: "invalid_response" });
	});

	it.each(["2", "999"])("retains a strictly decoded 202 integration revocation with Retry-After %s", async (retryAfter) => {
		const DELETE = vi.fn(async () => ({
			data: integration,
			response: new Response(JSON.stringify(integration), { status: 202, headers: {
				"Content-Type": "application/json", ETag: '"2"', "Retry-After": retryAfter,
				"X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001",
				"X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002",
			} }),
		}));
		const attempt = createWorkflowMutationAttempt();

		await expect(createIntegrationsAPI({ DELETE } as unknown as APIClient).deleteIntegration(integration.id, '"1"', attempt)).rejects.toMatchObject({
			name: "IntegrationRevocationPending",
			retryAfterSeconds: Number(retryAfter),
			receipt: { value: integration, version: '"2"', auditID: "pid_30000001-0000-4000-8000-000000000001", receiptID: "pid_30000002-0000-4000-8000-000000000002" },
		});
		expect(DELETE).toHaveBeenCalledOnce();
		const calls = DELETE.mock.calls as unknown as Array<[string, { params: { header: Record<string, string> } }]>;
		expect(calls[0]?.[1]).toMatchObject({ params: { header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": '"1"' } } });
	});

	it.each([undefined, "0", "1000"])("rejects invalid Retry-After %s on a 202 integration deletion", async (retryAfter) => {
		const headers: Record<string, string> = {
			"Content-Type": "application/json", ETag: '"2"',
			"X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001",
			"X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002",
		};
		if (retryAfter !== undefined) headers["Retry-After"] = retryAfter;
		const DELETE = vi.fn(async () => ({
			data: integration,
			response: new Response(JSON.stringify(integration), { status: 202, headers }),
		}));

		await expect(createIntegrationsAPI({ DELETE } as unknown as APIClient).deleteIntegration(integration.id, '"1"')).rejects.toMatchObject({ kind: "invalid_response" });
	});

	it("rejects a 202 integration deletion response for a different integration", async () => {
		const mismatched = { ...integration, id: "pid_20000001-0000-4000-8000-000000000099" };
		const DELETE = vi.fn(async () => ({
			data: mismatched,
			response: new Response(JSON.stringify(mismatched), { status: 202, headers: {
				"Content-Type": "application/json", ETag: '"2"', "Retry-After": "2",
				"X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001",
				"X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002",
			} }),
		}));

		await expect(createIntegrationsAPI({ DELETE } as unknown as APIClient).deleteIntegration(integration.id, '"1"')).rejects.toMatchObject({ kind: "invalid_response" });
	});

	it("rejects a 202 integration deletion response unless it is exactly revoking", async () => {
		const invalid = { ...integration, status: "active" };
		const DELETE = vi.fn(async () => ({
			data: invalid,
			response: new Response(JSON.stringify(invalid), { status: 202, headers: {
				"Content-Type": "application/json", ETag: '"2"', "Retry-After": "1",
				"X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001",
				"X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002",
			} }),
		}));

		await expect(createIntegrationsAPI({ DELETE } as unknown as APIClient).deleteIntegration(integration.id, '"1"')).rejects.toMatchObject({ kind: "invalid_response" });
	});

	it("retains one integration DELETE attempt through a lost response, 202 progress, and terminal retry", async () => {
		const terminalHeaders = { ETag: '"2"', "X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001", "X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002" };
		const DELETE = vi.fn()
			.mockRejectedValueOnce(new TypeError("response lost after commit"))
			.mockResolvedValueOnce({ data: integration, response: new Response(JSON.stringify(integration), { status: 202, headers: { ...terminalHeaders, "Content-Type": "application/json", "Retry-After": "1" } }) })
			.mockResolvedValueOnce({ response: new Response(null, { status: 204, headers: terminalHeaders }) });
		const api = createIntegrationsAPI({ DELETE } as unknown as APIClient);
		const controller = createRetainedWorkflowMutationController<{ id: string; version: string }>();
		const intent = { id: integration.id, version: '"1"' };
		const send = (frozen: typeof intent, attempt: { idempotencyKey: string }) => api.deleteIntegration(frozen.id, frozen.version, attempt);

		await expect(controller.execute(intent, send)).rejects.toMatchObject({ name: "IntegrationRevocationPending" });
		expect(controller.canRetry()).toBe(true);
		await expect(controller.retry()).resolves.toMatchObject({ value: undefined, version: '"2"' });
		const requestCalls = DELETE.mock.calls as unknown as Array<[string, { params: { header: Record<string, string> } }]>;
		expect(requestCalls).toHaveLength(3);
		expect(new Set(requestCalls.map(([, options]) => options.params.header["Idempotency-Key"])).size).toBe(1);
		expect(new Set(requestCalls.map(([, options]) => options.params.header["If-Match"]))).toEqual(new Set(['"1"']));
	});

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
		const recovery = createWorkflowRecoveryAPI(client, capturedScope);
		await Promise.all([
			recovery.acknowledgeReceipt("pid_60000001-0000-4000-8000-000000000001"),
			recovery.listReceipts(),
		]);
		expect(headers).toHaveLength(2);
		expect(headers).toEqual([capturedScope, capturedScope]);
	});

	it("rejects a recovered reference authorization receipt from a foreign valid scope", async () => {
		const foreignScope = "pid_90000001-0000-4000-8000-000000000001/pid_90000002-0000-4000-8000-000000000002/pid_90000003-0000-4000-8000-000000000003";
		const data = { items: [referenceAuthorizationReceipt(foreignScope)] };
		const GET = vi.fn(async () => ({ data, response: new Response(JSON.stringify(data), { status: 200, headers: { "Content-Type": "application/json" } }) }));

		await expect(createWorkflowRecoveryAPI({ GET } as unknown as APIClient, capturedScope).listReceipts()).rejects.toMatchObject({ kind: "invalid_response" });
	});

	it("authoritatively refetches reference authorization recovery and requires its exact receipt version", async () => {
		const GET = vi.fn()
			.mockResolvedValueOnce({ data: referenceIntegration, response: new Response(JSON.stringify(referenceIntegration), { status: 200, headers: { "Content-Type": "application/json", ETag: '"2"' } }) })
			.mockResolvedValueOnce({ data: referenceIntegration, response: new Response(JSON.stringify(referenceIntegration), { status: 200, headers: { "Content-Type": "application/json", ETag: '"3"' } }) });
		const reconcile = createWorkflowReceiptReconciler({ GET } as unknown as APIClient, capturedScope);
		const receipt = referenceAuthorizationReceipt() as unknown as Parameters<typeof reconcile>[0];

		await expect(reconcile(receipt, new AbortController().signal)).resolves.toBeUndefined();
		await expect(reconcile(receipt, new AbortController().signal)).rejects.toMatchObject({ kind: "invalid_response" });
		expect(GET).toHaveBeenNthCalledWith(1, "/api/v1/integrations/{id}", {
			params: { path: { id: referenceIntegration.id } },
			headers: { "X-Zasp-Expected-Scope": capturedScope },
			signal: expect.any(AbortSignal),
		});
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

function receiptHeadersForReference() {
	return {
		"Cache-Control": "no-store",
		ETag: '"2"',
		"X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001",
		"X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002",
	};
}
