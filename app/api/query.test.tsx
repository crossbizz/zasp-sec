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
