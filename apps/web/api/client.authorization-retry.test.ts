import { describe, expect, it, vi } from "vitest";

import { createAPIClient } from "./client";

const correlation = "pid_50000001-0000-4000-8000-000000000001";
const json = (body: unknown, status: number) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const settling = (code: string, status: number) => json({ code, message: "Authorization unavailable", correlation_id: correlation, retryable: true }, status);
const version = { version: "1.0.0", commit: "abcdef0", built_at: "2026-11-14T00:00:00Z" };

describe("authorization projection lag", () => {
  it("repeats a read that met the lag and reports the waiting state once", async () => {
    const answers = [settling("authorization_unavailable", 503), settling("authorization_changed", 409), json(version, 200)];
    const fetch = vi.fn(async () => answers.shift()!);
    const states: boolean[] = [];
    const client = createAPIClient({ fetch, authorizationRetryDelaysMs: [1, 1, 1], onAuthorizationSettling: (value) => states.push(value) });
    const result = await client.GET("/api/v1/system/version");
    expect(result.response.status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(states).toEqual([true, false]);
  });

  it("returns the last answer when the lag outlasts the configured delays", async () => {
    const fetch = vi.fn(async () => settling("authorization_unavailable", 503));
    const states: boolean[] = [];
    const client = createAPIClient({ fetch, authorizationRetryDelaysMs: [1, 1], onAuthorizationSettling: (value) => states.push(value) });
    const result = await client.GET("/api/v1/system/version");
    expect(result.response.status).toBe(503);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(states).toEqual([true, false]);
  });

  it("does not repeat by default, other errors, session routes or changes without an idempotency key", async () => {
    const lagging = vi.fn(async () => settling("authorization_unavailable", 503));
    await createAPIClient({ fetch: lagging }).GET("/api/v1/system/version");
    expect(lagging).toHaveBeenCalledTimes(1);

    const other = vi.fn(async () => json({ code: "provider_unavailable", message: "Provider unavailable", correlation_id: correlation, retryable: true }, 503));
    await createAPIClient({ fetch: other, authorizationRetryDelaysMs: [1] }).GET("/api/v1/system/version");
    expect(other).toHaveBeenCalledTimes(1);

    const session = vi.fn(async () => settling("authorization_pending", 409));
    await createAPIClient({ fetch: session, authorizationRetryDelaysMs: [1] }).GET("/api/v1/session/bootstrap");
    expect(session).toHaveBeenCalledTimes(1);

    const change = vi.fn(async () => settling("authorization_unavailable", 503));
    const client = createAPIClient({ fetch: change, authorizationRetryDelaysMs: [1] });
    await client.POST("/api/v1/session/sign-out" as never, {} as never);
    await client.POST("/api/v1/workflow-mutation-receipts/{id}/acknowledge", { params: { path: { id: correlation } } } as never);
    expect(change).toHaveBeenCalledTimes(2);
  });

  it("repeats a change that carries an idempotency key with the same key and body", async () => {
    const seen: { key: string | null; body: string }[] = [];
    const answers = [settling("authorization_unavailable", 503), json({ ok: true }, 200)];
    const client = createAPIClient({ fetch: async (request) => { seen.push({ key: request.headers.get("Idempotency-Key"), body: await request.clone().text() }); return answers.shift()!; }, authorizationRetryDelaysMs: [1] });
    await client.POST("/api/v1/security-agent-runs/{id}/close", { params: { path: { id: correlation }, header: { "Idempotency-Key": "attempt-000000000001", "If-Match": '"3"' } }, body: { reason: "no_action_required" } } as never);
    expect(seen).toEqual([{ key: "attempt-000000000001", body: '{"reason":"no_action_required"}' }, { key: "attempt-000000000001", body: '{"reason":"no_action_required"}' }]);
  });

  it("repeats a read, but never a change, that met 409 operation_conflict", async () => {
    const conflict = () => json({ code: "operation_conflict", message: "Operation conflicted", correlation_id: correlation, retryable: false }, 409);
    const answers = [conflict(), json(version, 200)];
    const read = vi.fn(async () => answers.shift()!);
    expect((await createAPIClient({ fetch: read, authorizationRetryDelaysMs: [1] }).GET("/api/v1/system/version")).response.status).toBe(200);
    expect(read).toHaveBeenCalledTimes(2);
    const change = vi.fn(async () => conflict());
    await createAPIClient({ fetch: change, authorizationRetryDelaysMs: [1] }).POST("/api/v1/security-agent-runs/{id}/close", { params: { path: { id: correlation }, header: { "Idempotency-Key": "attempt-000000000001", "If-Match": '"3"' } }, body: { reason: "no_action_required" } } as never);
    expect(change).toHaveBeenCalledTimes(1);
  });

  it("stops waiting when the request is aborted", async () => {
    const controller = new AbortController();
    const fetch = vi.fn(async () => { queueMicrotask(() => controller.abort(new DOMException("stopped", "AbortError"))); return settling("authorization_unavailable", 503); });
    const client = createAPIClient({ fetch, authorizationRetryDelaysMs: [5000] });
    await expect(client.GET("/api/v1/system/version", { signal: controller.signal })).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
