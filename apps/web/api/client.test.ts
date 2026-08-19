import { describe, expect, expectTypeOf, it, vi } from "vitest";

import { APIProductError, APITransportError, createAPIClient, requireAPIData } from "./client";
import { decodeHomeSummary, decodeIntegration, decodeInventoryPage, decodePolicySimulation, decodeRuntimeDecisionPage, decodeSecurityAgentDefinition, decodeSessionBootstrap } from "./decoders";
import type { ProductID } from "./client";
import type {
  Cursor,
  PageInfo,
  paths,
  ProductError,
} from "./generated";

function assertProductErrorIsReadonly(value: ProductError) {
  // @ts-expect-error -- generated state is immutable by contract.
  value.code = "changed";
}

describe("generated API client", () => {
	it("fails successful visible-operation payloads closed through strict decoders", () => {
		const response = new Response("{}", { status: 200 });
		expect(() => requireAPIData({ data: { agent_count: 1 }, response }, decodeHomeSummary)).toThrow(expect.objectContaining({ kind: "invalid_response" }));
		expect(() => requireAPIData({ data: { items: [{ id: "pid_20000001-0000-4000-8000-000000000001", name: "Agent", kind: "agent", owner: "", team: "", tags: [], evidence_id: "pid_20000006-0000-4000-8000-000000000006", first_seen: "2026-08-18T09:00:00Z", last_seen: "2026-08-18T10:00:00Z", unexpected: true }] }, response }, decodeInventoryPage)).toThrow(expect.objectContaining({ kind: "invalid_response" }));
		expect(() => requireAPIData({ data: { principal: {}, capabilities: ["inventory.read"] }, response }, decodeSessionBootstrap)).toThrow(expect.objectContaining({ kind: "invalid_response" }));
	});
	it("enforces exact workflow response bounds without narrowing bounded identifiers", () => {
		expect(() => decodePolicySimulation({ matches: 101, would_block: 0, example_session_ids: [] })).toThrow("schema mismatch");
		expect(() => decodeIntegration({ id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "generic-webhook", name: "Local", configuration: {}, status: "configured", created_at: "2026-08-18T12:00:00Z", updated_at: "2026-08-18T12:00:00Z" })).toThrow("schema mismatch");
		expect(() => decodeSecurityAgentDefinition({ id: "pid_20000001-0000-4000-8000-000000000001", name: "Definition", trigger_kind: "finding", trigger_source: "credential", environment_ids: ["pid_10000003-0000-4000-8000-000000000003"], autonomy: "supervised", max_steps: 10, max_duration_seconds: 900, temporary_policy_seconds: 3600, ai_token_budget: 4000, concurrency_limit: 11, allowed_actions: ["run_test"], verification_kind: "test_run", definition_version: 1, enabled: true })).toThrow("schema mismatch");
		expect(decodeRuntimeDecisionPage({ items: [{ id: "decision-1", policy_id: "policy-production", environment_id: "environment-production", result: "monitor", correlation_id: "correlation-1", at: "2026-08-18T12:00:00Z" }] }).items[0]?.id).toBe("decision-1");
	});
	it("preserves a validated product error with status and correlation", () => {
		const error = {
			code: "authorization_rejected", message: "Authorization rejected",
			correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false,
		};
		expect(() => requireAPIData({ error, response: new Response(JSON.stringify(error), { status: 403 }) }))
			.toThrow(expect.objectContaining({ name: "APIProductError", status: 403, product: error }));
		try {
			requireAPIData({ error, response: new Response(JSON.stringify(error), { status: 403 }) });
		} catch (caught) {
			expect(caught).toBeInstanceOf(APIProductError);
			expect((caught as APIProductError).correlationID).toBe(error.correlation_id);
		}
	});
  it("exposes the exact immutable root component and identity-path types", () => {
    const correlationID = "pid_12345678-1234-4123-8123-123456789abc" as ProductID;
    const cursor = "YQ" as Cursor;
    const error: ProductError = {
      code: "invalid_request",
      message: "Request rejected",
      correlation_id: correlationID,
      retryable: false,
    };
    const continuingPage: PageInfo = { next_cursor: cursor, has_more: true };
    const finalPage: PageInfo = { next_cursor: null, has_more: false };

    expect(error).toEqual({
      code: "invalid_request",
      message: "Request rejected",
      correlation_id: correlationID,
      retryable: false,
    });
    expect(continuingPage.has_more).toBe(true);
    expect(finalPage.has_more).toBe(false);
		type PublicPath = keyof paths;
		expectTypeOf<"/api/v1/findings">().toMatchTypeOf<PublicPath>();
		expectTypeOf<"/api/v1/attack-paths/{id}/break-options">().toMatchTypeOf<PublicPath>();
		expectTypeOf<Extract<PublicPath, "/api/v1/ai/explanations">>().toEqualTypeOf<never>();
		expectTypeOf<Extract<PublicPath, "/api/v1/findings/{id}/ticket">>().toEqualTypeOf<never>();
    expectTypeOf(error.code).toEqualTypeOf<string>();

    expect(assertProductErrorIsReadonly).toBeTypeOf("function");
  });

  it("constructs the typed Fetch client without performing I/O", () => {
    const fetch = vi.fn(async () => new Response(null, { status: 204 }));
    const client = createAPIClient({
      fetch,
    });

    expect(client).toBeDefined();
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(["https://evil.example", "//evil.example", "/\\evil.example", "/%2f%2fevil.example", "/api?next=//evil.example", "/api#evil"])(
    "rejects non-relative or redirect-like base URL %s",
    (baseUrl) => {
      expect(() => createAPIClient({ baseUrl })).toThrow(APITransportError);
    },
  );

  it("enforces same-origin credentials, correlation, CSRF, and redirect policy", async () => {
    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(new URL(String(input), "https://app.zasp.test"), init);
      expect(request.credentials).toBe("same-origin");
      expect(request.redirect).toBe("error");
      expect(request.headers.get("X-Correlation-ID")).toBe("pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
      expect(request.headers.get("X-CSRF-Token")).toBe("csrf-value");
	  expect(request.headers.get("X-Zasp-Expected-Scope")).toBe("pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");
      expect(request.url).toBe(`${window.location.origin}/api/v1/findings/pid_20000001-0000-4000-8000-000000000001`);
      return jsonResponse({ id: "pid_20000001-0000-4000-8000-000000000001", source: "posture", title: "Finding", severity: "high", status: "resolved", evidence_ids: [], risk_factors: [] });
    });
    const client = createAPIClient({
      fetch,
      getCSRFToken: () => "csrf-value",
	  getExpectedScope: () => "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003",
      generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    });

    const result = await client.PATCH("/api/v1/findings/{id}", {
		params: { path: { id: "pid_20000001-0000-4000-8000-000000000001" }, header: { "Idempotency-Key": "idem-finding-update-0001", "If-Match": `"1"`, "X-CSRF-Token": "" } },
      body: { status: "resolved" },
    });
    expect(result.error).toBeUndefined();
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("bounds time and preserves caller aborts", async () => {
    const waitForAbort = vi.fn((input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      const signal = input instanceof Request ? input.signal : init?.signal;
      signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
    }));
    const timed = createAPIClient({ fetch: waitForAbort, timeoutMs: 5 });
    await expect(timed.GET("/api/v1/home/summary")).rejects.toMatchObject({ kind: "timeout" });

    const controller = new AbortController();
    const aborted = createAPIClient({ fetch: waitForAbort, timeoutMs: 1000 });
    const pending = aborted.GET("/api/v1/home/summary", { signal: controller.signal });
    controller.abort(new DOMException("caller stopped", "AbortError"));
    await expect(pending).rejects.toMatchObject({ name: "AbortError", message: "caller stopped" });
  });

  it.each([
    ["HTML error", new Response("<html>no</html>", { status: 500, headers: { "Content-Type": "text/html" } }), "invalid_error"],
    ["malformed success", new Response("not-json", { status: 200, headers: { "Content-Type": "application/json" } }), "invalid_response"],
    ["oversized body", jsonResponse({ value: "x".repeat(100) }), "response_too_large"],
  ])("rejects %s without returning simulated data", async (_name, response, kind) => {
    const client = createAPIClient({ fetch: async () => response.clone(), maximumResponseBytes: 64 });
    await expect(client.GET("/api/v1/home/summary")).rejects.toMatchObject({ kind });
  });

  it("notifies once when the fixed product envelope reports session expiry", async () => {
    const expired = vi.fn();
    const client = createAPIClient({
      fetch: async () => jsonResponse({ code: "authentication_required", message: "Authentication required", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false }, 401),
      onSessionExpired: expired,
    });
    const result = await client.GET("/api/v1/home/summary");
    expect(result.error).toMatchObject({ code: "authentication_required" });
    expect(expired).toHaveBeenCalledOnce();
  });

  it("invalidates fresh-only state only for the exact fixed fresh-auth envelope", async () => {
    const freshRequired = vi.fn();
    const responses = [
      { code: "fresh_auth_required", message: "Fresh authentication required", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false },
      { code: "authorization_rejected", message: "Authorization rejected", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false },
    ];
    const client = createAPIClient({
      fetch: async () => jsonResponse(responses.shift(), 403),
      onFreshAuthRequired: freshRequired,
    });

    expect((await client.GET("/api/v1/home/summary")).error).toMatchObject({ code: "fresh_auth_required" });
    expect(freshRequired).toHaveBeenCalledOnce();
    expect((await client.GET("/api/v1/home/summary")).error).toMatchObject({ code: "authorization_rejected" });
    expect(freshRequired).toHaveBeenCalledOnce();
  });

	it("preserves an explicit captured scope and requests rebootstrap on scope-stale", async () => {
		const stale = vi.fn();
		let currentScope = "pid_10000001-0000-4000-8000-000000000001/pid_10000022-0000-4000-8000-000000000022/pid_10000023-0000-4000-8000-000000000023";
		const observed: string[] = [];
		const client = createAPIClient({
			fetch: async (request: Request) => {
				observed.push(request.headers.get("X-Zasp-Expected-Scope") ?? "");
				return jsonResponse({ code: "scope_stale", message: "Session scope changed; rebootstrap required", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 409);
			},
			getExpectedScope: () => currentScope,
			onScopeStale: stale,
		});
		const captured = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
		const result = await client.GET("/api/v1/workflow-mutation-receipts", { headers: { "X-Zasp-Expected-Scope": captured } });
		currentScope = captured;
		expect(result.error).toMatchObject({ code: "scope_stale", retryable: true });
		expect(observed).toEqual([captured]);
		expect(stale).toHaveBeenCalledOnce();
	});

	it("ignores a scope-stale response that completes after caller cancellation", async () => {
		let resolveResponse: ((response: Response) => void) | undefined;
		const response = new Promise<Response>((resolve) => { resolveResponse = resolve; });
		const stale = vi.fn();
		const client = createAPIClient({
			fetch: async () => response,
			onScopeStale: stale,
		});
		const controller = new AbortController();
		const pending = client.GET("/api/v1/home/summary", { signal: controller.signal });

		controller.abort(new DOMException("newer recovery owns the session", "AbortError"));
		resolveResponse?.(jsonResponse({ code: "scope_stale", message: "Session scope changed; rebootstrap required", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 409));

		await expect(pending).rejects.toMatchObject({ name: "AbortError", message: "newer recovery owns the session" });
		expect(stale).not.toHaveBeenCalled();
	});
});

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
