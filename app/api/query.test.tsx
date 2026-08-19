import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { APIProvider, useAPI } from "./APIProvider";
import { useAPIMutation, useAPIQuery } from "./query";

describe("API query state machine", () => {
  it("moves through loading, empty, success, forbidden, and retryable error", async () => {
    let resolve: (value: readonly string[]) => void = () => undefined;
    const query = vi.fn(() => new Promise<readonly string[]>((done) => { resolve = done; }));
    const wrapper = ({ children }: { children: ReactNode }) => <APIProvider>{children}</APIProvider>;
    const { result, rerender } = renderHook(() => useAPIQuery("agents", query), { wrapper });
    expect(result.current.status).toBe("loading");
    await waitFor(() => expect(query).toHaveBeenCalledOnce());
    act(() => resolve([]));
    await waitFor(() => expect(result.current.status).toBe("empty"));

    query.mockResolvedValueOnce(["agent-1"]);
    await act(async () => result.current.retry());
    await waitFor(() => expect(result.current).toMatchObject({ status: "success", data: ["agent-1"] }));

    query.mockRejectedValueOnce({ response: { status: 403 }, error: { code: "authorization_rejected" } });
    await act(async () => result.current.retry());
    await waitFor(() => expect(result.current.status).toBe("forbidden"));
    expect(result.current.data).toBeUndefined();

    query.mockRejectedValueOnce({ response: { status: 403 }, error: { code: "authorization_rejected" } });
    rerender();
    const isolated = renderHook(() => useAPIQuery("forbidden", query), { wrapper });
    await waitFor(() => expect(isolated.result.current.status).toBe("forbidden"));
  });

  it("invalidates only named queries after a successful mutation", async () => {
    const agents = vi.fn(async () => ["agent-1"]);
    const findings = vi.fn(async () => ["finding-1"]);
    const mutate = vi.fn(async () => ({ status: "resolved" }));
    const wrapper = ({ children }: { children: ReactNode }) => <APIProvider>{children}</APIProvider>;
    const { result } = renderHook(() => ({
      agents: useAPIQuery("agents", agents),
      findings: useAPIQuery("findings", findings),
      mutation: useAPIMutation(mutate, ["findings"]),
    }), { wrapper });
    await waitFor(() => expect(result.current.findings.status).toBe("success"));
    await act(async () => { await result.current.mutation.run(); });
    await waitFor(() => expect(findings).toHaveBeenCalledTimes(2));
    expect(agents).toHaveBeenCalledTimes(1);
  });

	it("rotates protected query generation without expiring the authenticated session", async () => {
		const query = vi.fn(async () => ["agent-1"]);
		const wrapper = ({ children }: { children: ReactNode }) => <APIProvider>{children}</APIProvider>;
		const { result } = renderHook(() => ({ query: useAPIQuery("agents", query), api: useAPI() }), { wrapper });
		await waitFor(() => expect(query).toHaveBeenCalledOnce());
		expect(result.current.api.sessionExpiry).toBe(0);
		act(() => result.current.api.clearQueryCache());
		await waitFor(() => expect(query).toHaveBeenCalledTimes(2));
		expect(result.current.api.sessionExpiry).toBe(0);
	});

	it("never exposes prior-scope data while the next scope is delayed or fails", async () => {
		type Deferred = {
			promise: Promise<readonly string[]>;
			resolve(value: readonly string[]): void;
			reject(error: unknown): void;
		};
		const deferred = (): Deferred => {
			let resolve: Deferred["resolve"] = () => undefined;
			let reject: Deferred["reject"] = () => undefined;
			const promise = new Promise<readonly string[]>((done, fail) => { resolve = done; reject = fail; });
			return { promise, resolve, reject };
		};
		const initial = deferred();
		const scopeA = deferred();
		const lateScopeA = deferred();
		const scopeB = deferred();
		const attempts = [initial, scopeA, lateScopeA, scopeB];
		const signals: AbortSignal[] = [];
		const query = vi.fn((signal?: AbortSignal) => {
			if (signal) signals.push(signal);
			const attempt = attempts[query.mock.calls.length - 1];
			if (!attempt) throw new Error("unexpected query attempt");
			return attempt.promise;
		});
		const wrapper = ({ children }: { children: ReactNode }) => <APIProvider>{children}</APIProvider>;
		const { result } = renderHook(() => ({ query: useAPIQuery("agents", query), api: useAPI() }), { wrapper });

		await waitFor(() => expect(query).toHaveBeenCalledTimes(1));
		act(() => result.current.api.setQueryScope("organization-a/workspace-a/environment-a"));
		await waitFor(() => expect(query).toHaveBeenCalledTimes(2));
		expect(signals[0]?.aborted).toBe(true);
		act(() => scopeA.resolve(["scope-a-agent"]));
		await waitFor(() => expect(result.current.query).toMatchObject({ status: "success", data: ["scope-a-agent"] }));

		act(() => { void result.current.query.retry(); });
		await waitFor(() => expect(query).toHaveBeenCalledTimes(3));
		act(() => result.current.api.setQueryScope("organization-a/workspace-b/environment-b"));
		expect(result.current.query.status).toBe("loading");
		expect(result.current.query.data).toBeUndefined();
		await waitFor(() => expect(query).toHaveBeenCalledTimes(4));
		expect(signals[2]?.aborted).toBe(true);
		act(() => scopeB.reject(new Error("scope B provider unavailable")));
		await waitFor(() => expect(result.current.query.status).toBe("error"));
		expect(result.current.query.data).toBeUndefined();

		act(() => lateScopeA.resolve(["late-scope-a-agent"]));
		act(() => initial.resolve(["initial-unscoped-agent"]));
		await waitFor(() => expect(result.current.query.status).toBe("error"));
		expect(result.current.query.data).toBeUndefined();
	});

  it("keeps authoritative data stale when refresh fails", async () => {
    const query = vi.fn<() => Promise<readonly string[]>>()
      .mockResolvedValueOnce(["finding-1"])
      .mockRejectedValueOnce(new Error("provider unavailable"));
    const wrapper = ({ children }: { children: ReactNode }) => <APIProvider>{children}</APIProvider>;
    const { result } = renderHook(() => useAPIQuery("findings", query), { wrapper });
    await waitFor(() => expect(result.current.status).toBe("success"));
    await act(async () => result.current.retry());
    await waitFor(() => expect(result.current.status).toBe("stale"));
    expect(result.current.data).toEqual(["finding-1"]);
  });
});
