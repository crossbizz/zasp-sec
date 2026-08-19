import { describe, expect, expectTypeOf, it, vi } from "vitest";

import { APIProductError, APITransportError, createAPIClient, requireAPIData } from "./client";
import { decodeHomeSummary, decodeInventoryPage, decodeSessionBootstrap } from "./decoders";
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
    expectTypeOf<keyof paths>().toEqualTypeOf<
      | "/api/v1/admin/api-tokens"
      | "/api/v1/admin/api-tokens/{id}"
      | "/api/v1/admin/group-mappings"
      | "/api/v1/admin/members"
      | "/api/v1/admin/roles"
      | "/api/v1/admin/scim-connections"
      | "/api/v1/admin/scim-connections/{id}"
      | "/api/v1/admin/sso-connections"
      | "/api/v1/admin/sso-connections/{id}"
      | "/api/v1/admin/sso-connections/{id}/test"
      | "/api/v1/agents"
      | "/api/v1/agents/{id}"
      | "/api/v1/agents/{id}/capabilities"
      | "/api/v1/agents/{id}/relationships"
      | "/api/v1/agents/{id}/sessions"
      | "/api/v1/ai/explanations"
      | "/api/v1/assets/{id}"
      | "/api/v1/attack-paths"
      | "/api/v1/attack-paths/{id}"
      | "/api/v1/attack-paths/{id}/break-options"
      | "/api/v1/attack-lab/runs"
      | "/api/v1/attack-lab/runs/{id}"
      | "/api/v1/attack-lab/runs/{id}/cancel"
      | "/api/v1/attack-lab/runs/{id}/rerun"
      | "/api/v1/audit-events"
      | "/api/v1/audit-exports"
      | "/api/v1/audit-exports/{id}"
      | "/api/v1/compliance/controls"
      | "/api/v1/compliance/evidence"
      | "/api/v1/compliance/exports"
      | "/api/v1/compliance/exports/{id}"
      | "/api/v1/environments"
      | "/api/v1/environments/{id}"
      | "/api/v1/findings"
      | "/api/v1/findings/{id}"
      | "/api/v1/findings/{id}/accept-risk"
      | "/api/v1/findings/{id}/ticket"
      | "/api/v1/home/summary"
      | "/api/v1/integration-catalog"
      | "/api/v1/integrations"
      | "/api/v1/integrations/{id}"
      | "/api/v1/integrations/{id}/authorize"
      | "/api/v1/integrations/{id}/sync"
      | "/api/v1/integrations/{id}/syncs"
      | "/api/v1/integrations/{id}/syncs/{syncId}"
      | "/api/v1/identities"
      | "/api/v1/identities/{id}"
      | "/api/v1/me"
      | "/api/v1/organization"
      | "/api/v1/policies"
      | "/api/v1/policies/{id}"
      | "/api/v1/policies/{id}/decisions"
      | "/api/v1/policies/{id}/disable"
      | "/api/v1/policies/{id}/rollout"
      | "/api/v1/policies/{id}/simulate"
      | "/api/v1/sensors"
      | "/api/v1/sensors/{id}"
      | "/api/v1/sensors/{id}/coverage"
      | "/api/v1/sensors/{id}/rotate-token"
      | "/api/v1/runtimes"
      | "/api/v1/runtimes/{id}"
      | "/api/v1/search"
      | "/api/v1/session/bootstrap"
      | "/api/v1/session/callback"
      | "/api/v1/session/sign-out"
	  | "/api/v1/session/scopes"
	  | "/api/v1/session/scope"
	  | "/api/v1/session/start"
      | "/api/v1/security-actions"
      | "/api/v1/security-agent-approvals"
      | "/api/v1/security-agent-approvals/{id}"
      | "/api/v1/security-agent-approvals/{id}/decision"
      | "/api/v1/security-agent-runs"
      | "/api/v1/security-agent-runs/{id}"
      | "/api/v1/security-agent-runs/{id}/cancel"
      | "/api/v1/security-agent-templates"
      | "/api/v1/security-agents"
      | "/api/v1/security-agents/{id}"
      | "/api/v1/security-agents/{id}/runs"
      | "/api/v1/security-agents/{id}/simulate"
      | "/api/v1/sessions"
      | "/api/v1/sessions/{id}"
      | "/api/v1/sessions/{id}/events"
      | "/api/v1/settings/data-controls"
      | "/api/v1/settings/external-data-flows"
      | "/api/v1/system/components"
      | "/api/v1/system/status"
      | "/api/v1/system/version"
      | "/api/v1/test-runs"
      | "/api/v1/test-runs/{id}"
      | "/api/v1/test-runs/{id}/cancel"
      | "/api/v1/tests"
      | "/api/v1/tests/{id}"
      | "/api/v1/tests/{id}/runs"
      | "/api/v1/tools"
      | "/api/v1/tools/{id}"
      | "/api/v1/workspaces"
      | "/api/v1/workspaces/{id}"
    >();
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
      expect(request.url).toBe(`${window.location.origin}/api/v1/findings/pid_20000001-0000-4000-8000-000000000001`);
      return jsonResponse({ id: "pid_20000001-0000-4000-8000-000000000001", source: "posture", title: "Finding", severity: "high", status: "resolved", evidence_ids: [], risk_factors: [] });
    });
    const client = createAPIClient({
      fetch,
      getCSRFToken: () => "csrf-value",
      generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    });

    const result = await client.PATCH("/api/v1/findings/{id}", {
      params: { path: { id: "pid_20000001-0000-4000-8000-000000000001" } },
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
});

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
