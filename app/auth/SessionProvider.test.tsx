import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { createAPIClient } from "../../apps/web/api/client";
import { APIProvider, useAPI } from "../api/APIProvider";
import { useAPIQuery } from "../api/query";
import { buildSignInURL, SessionProvider, useSession } from "./SessionProvider";

function Consumer() {
  const session = useSession();
  return <div>
    <span>{session.status}</span>
	<span>scope {session.scopeSwitch.status}</span>
	{session.scopeSwitch.error && <span>scope error {session.scopeSwitch.error.code}</span>}
    <span>{session.hasCapability("inventory.read") ? "inventory enabled" : "inventory hidden"}</span>
    {session.status === "authenticated" && <button onClick={() => void session.signOut()}>Sign out</button>}
	{session.status === "authenticated" && session.scopes.length > 1 && <button onClick={() => void session.switchScope(session.scopes[1].workspace_id, session.scopes[1].environment_id)}>Switch scope</button>}
	{session.scopeSwitch.status === "error" && <button onClick={() => void session.scopeSwitch.retry()}>Retry scope switch</button>}
  </div>;
}

function FreshAuthConsumer() {
	const session = useSession();
	return <div>
		<span>{session.status} {session.status === "authenticated" && session.isFreshAuthenticated ? "fresh active" : "fresh expired"}</span>
		<button disabled={session.status !== "authenticated" || !session.isFreshAuthenticated}>Sensitive action</button>
	</div>;
}

function ScopedQueryConsumer({ query }: { query: (signal?: AbortSignal) => Promise<readonly string[]> }) {
  const session = useSession();
  const scoped = useAPIQuery("scoped-records", query, session.status === "authenticated");
  return <div>
    <span>session {session.status}</span>
    <span>query {scoped.status}</span>
    {scoped.data?.map((item) => <span key={item}>{item}</span>)}
    {session.status === "authenticated" && session.scopes.length > 1 && <button onClick={() => void session.switchScope(session.scopes[1].workspace_id, session.scopes[1].environment_id)}>Switch scoped query</button>}
    <button onClick={() => void scoped.retry()}>Refresh scoped query</button>
  </div>;
}

function ScopeStaleConsumer() {
	const session = useSession();
	const { client } = useAPI();
	return <div>
		<span>stale session {session.status}</span>
		<button onClick={() => void session.retry()}>Retry session</button>
		{session.status === "authenticated" && <>
			<span>active environment {session.environmentID}</span>
			<span>{session.hasCapability("scope-a-only") ? "scope A capability" : session.hasCapability("scope-b-only") ? "scope B capability" : "shared capability"}</span>
			<button onClick={() => void client.GET("/api/v1/home/summary")}>Load scoped data</button>
			<button onClick={() => void session.signOut()}>Sign out recovered session</button>
		</>}
	</div>;
}

function ScopeProbe() {
		const { client } = useAPI();
		return <button onClick={() => void client.GET("/api/v1/home/summary")}>Probe request scope</button>;
}

function ScopeSwitchOverlapConsumer() {
	const session = useSession();
	const { client } = useAPI();
	return <div>
		<span>overlap session {session.status}</span>
		<span>overlap switch {session.scopeSwitch.status}</span>
		{session.scopeSwitch.error && <span>overlap error {session.scopeSwitch.error.code}</span>}
		{session.status === "authenticated" && <>
			<span>overlap environment {session.environmentID}</span>
			{session.scopes.length > 1 && <button onClick={() => void session.switchScope(session.scopes[1].workspace_id, session.scopes[1].environment_id)}>Start overlapping switch</button>}
			<button onClick={() => void client.GET("/api/v1/home/summary")}>Trigger overlapping stale scope</button>
		</>}
		{session.scopeSwitch.status === "error" && <button onClick={() => void session.scopeSwitch.retry()}>Retry overlapping reconciliation</button>}
	</div>;
}

const emptySessionInvalidationQuery = async (): Promise<readonly string[]> => [];

function SessionInvalidationConsumer({ query }: { query?: (signal?: AbortSignal) => Promise<readonly string[]> }) {
	const session = useSession();
	const { client } = useAPI();
	const [queryEnabled, setQueryEnabled] = useState(false);
	const protectedQuery = useAPIQuery("session-invalidation-query", query ?? emptySessionInvalidationQuery, queryEnabled && query !== undefined);
	return <div>
		<span>invalidation session {session.status}</span>
		<span>{session.hasCapability("scope-a-only") ? "invalidation A capability" : session.hasCapability("scope-b-only") ? "invalidation B capability" : "invalidation capability hidden"}</span>
		<span>invalidation query {protectedQuery.status}</span>
		{protectedQuery.data?.map((item) => <span key={item}>{item}</span>)}
		<button onClick={() => void session.retry()}>Retry invalidated session</button>
		<button onClick={() => void client.GET("/api/v1/home/summary", { headers: { "X-Test-Response": "expiry" } })}>Trigger validated expiry</button>
		<button onClick={() => void client.GET("/api/v1/home/summary", { headers: { "X-Test-Response": "stale" } })}>Trigger stale before expiry</button>
		<button onClick={() => void client.POST("/api/v1/session/sign-out", { params: { header: { "X-CSRF-Token": "" } } })}>Probe invalidated security</button>
		<button onClick={() => setQueryEnabled(true)}>Enable invalidation query</button>
		<button onClick={() => void protectedQuery.retry()}>Refresh invalidation query</button>
	</div>;
}

type Deferred<T> = {
	promise: Promise<T>;
	resolve(value: T): void;
	reject(error: unknown): void;
};

function deferred<T>(): Deferred<T> {
	let resolve: Deferred<T>["resolve"] = () => undefined;
	let reject: Deferred<T>["reject"] = () => undefined;
	const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
	return { promise, resolve, reject };
}

function wrapper(fetch: (request: Request) => Promise<Response>) {
  const client = createAPIClient({ fetch, generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" });
  function Wrapper({ children }: { children: ReactNode }) {
    return <APIProvider client={client}><SessionProvider>{children}</SessionProvider></APIProvider>;
  }
  return Wrapper;
}

describe("SessionProvider", () => {
	it("uses the exact bootstrap expiry to disable sensitive actions before a server rejection", async () => {
		const fetch = vi.fn(async () => jsonResponse({
			...sessionBootstrap(),
			capabilities: ["inventory.read"],
			fresh_auth_expires_at: new Date(Date.now() - 1_000).toISOString(),
		}));
		const Wrapper = wrapper(fetch);
		render(<Wrapper><FreshAuthConsumer /></Wrapper>);
		expect(await screen.findByText("authenticated fresh expired")).toBeVisible();
		expect(screen.getByRole("button", { name: "Sensitive action" })).toBeDisabled();
	});

	it("keeps the newest A-B-A recovery when an older scope list succeeds late", async () => {
		const staleResponses = [deferred<Response>(), deferred<Response>()];
		const oldScopeList = deferred<Response>();
		const recoverySignals: AbortSignal[] = [];
		const observedHomeScopes: string[] = [];
		const observedSignOutSecurity: Array<{ csrf: string; scope: string }> = [];
		let bootstrapCalls = 0;
		let scopeCalls = 0;
		let homeCalls = 0;
		const fetch = vi.fn(async (request: Request) => {
			const path = new URL(request.url).pathname;
			if (path === "/api/v1/session/bootstrap") {
				bootstrapCalls += 1;
				recoverySignals.push(request.signal);
				return jsonResponse(sessionBootstrap(bootstrapCalls === 2, bootstrapCalls === 2 ? "scope-b-only" : "scope-a-only"));
			}
			if (path === "/api/v1/session/scopes") {
				scopeCalls += 1;
				recoverySignals.push(request.signal);
				if (scopeCalls === 2) return oldScopeList.promise;
				return jsonResponse(sessionScopes());
			}
			if (path === "/api/v1/home/summary") {
				homeCalls += 1;
				observedHomeScopes.push(request.headers.get("X-Zasp-Expected-Scope") ?? "");
				if (homeCalls <= 2) return staleResponses[homeCalls - 1]!.promise;
				return jsonResponse({ agent_count: 0, finding_count: 0, critical_finding_count: 0, attack_path_count: 0 });
			}
			if (path === "/api/v1/session/sign-out") {
				observedSignOutSecurity.push({
					csrf: request.headers.get("X-CSRF-Token") ?? "",
					scope: request.headers.get("X-Zasp-Expected-Scope") ?? "",
				});
				return new Response(null, { status: 204 });
			}
			throw new Error(`unexpected request ${path}`);
		});
		vi.stubGlobal("fetch", fetch);
		try {
			render(<APIProvider><SessionProvider><ScopeStaleConsumer /></SessionProvider></APIProvider>);
			await screen.findByText("scope A capability");
			await userEvent.click(screen.getByRole("button", { name: "Load scoped data" }));
			await userEvent.click(screen.getByRole("button", { name: "Load scoped data" }));

			act(() => staleResponses[0]!.resolve(scopeStaleResponse()));
			await waitFor(() => expect(scopeCalls).toBe(2));
			expect(screen.getByText("stale session loading")).toBeVisible();
			act(() => staleResponses[1]!.resolve(scopeStaleResponse()));
			await waitFor(() => expect(bootstrapCalls).toBe(3));
			await screen.findByText("scope A capability");
			expect(recoverySignals[3]?.aborted).toBe(true);

			act(() => oldScopeList.resolve(jsonResponse(sessionScopes())));
			await act(async () => { await oldScopeList.promise; await Promise.resolve(); });
			expect(screen.getByText("stale session authenticated")).toBeVisible();
			expect(screen.getByText("scope A capability")).toBeVisible();
			expect(screen.queryByText("scope B capability")).not.toBeInTheDocument();

			await userEvent.click(screen.getByRole("button", { name: "Load scoped data" }));
			await waitFor(() => expect(homeCalls).toBe(3));
			expect(observedHomeScopes.at(-1)).toBe("pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");
			await userEvent.click(screen.getByRole("button", { name: "Sign out recovered session" }));
			await waitFor(() => expect(observedSignOutSecurity).toHaveLength(1));
			expect(observedSignOutSecurity).toEqual([{
				csrf: "cccccccccccccccccccccccccccccccc",
				scope: "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003",
			}]);
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it("keeps the newest recovery when an aborted older scope list errors late", async () => {
		const staleResponses = [deferred<Response>(), deferred<Response>()];
		const oldScopeList = deferred<Response>();
		let bootstrapCalls = 0;
		let scopeCalls = 0;
		let homeCalls = 0;
		const fetch = vi.fn(async (request: Request) => {
			const path = new URL(request.url).pathname;
			if (path === "/api/v1/session/bootstrap") {
				bootstrapCalls += 1;
				return jsonResponse(sessionBootstrap(bootstrapCalls === 2, bootstrapCalls === 2 ? "scope-b-only" : "scope-a-only"));
			}
			if (path === "/api/v1/session/scopes") {
				scopeCalls += 1;
				if (scopeCalls === 2) return oldScopeList.promise;
				return jsonResponse(sessionScopes());
			}
			if (path === "/api/v1/home/summary") {
				homeCalls += 1;
				if (homeCalls <= 2) return staleResponses[homeCalls - 1]!.promise;
				return jsonResponse({ agent_count: 0, finding_count: 0, critical_finding_count: 0, attack_path_count: 0 });
			}
			throw new Error(`unexpected request ${path}`);
		});
		vi.stubGlobal("fetch", fetch);
		try {
			render(<APIProvider><SessionProvider><ScopeStaleConsumer /></SessionProvider></APIProvider>);
			await screen.findByText("scope A capability");
			await userEvent.click(screen.getByRole("button", { name: "Load scoped data" }));
			await userEvent.click(screen.getByRole("button", { name: "Load scoped data" }));
			act(() => staleResponses[0]!.resolve(scopeStaleResponse()));
			await waitFor(() => expect(scopeCalls).toBe(2));
			act(() => staleResponses[1]!.resolve(scopeStaleResponse()));
			await screen.findByText("scope A capability");

			act(() => oldScopeList.reject(new Error("obsolete scope list failed")));
			await act(async () => { try { await oldScopeList.promise; } catch { /* expected fixture failure */ } await Promise.resolve(); });
			expect(screen.getByText("stale session authenticated")).toBeVisible();
			expect(screen.getByText("scope A capability")).toBeVisible();
			expect(screen.queryByText("stale session error")).not.toBeInTheDocument();
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it("shows the latest recovery error and allows a later retry to finish", async () => {
		let bootstrapCalls = 0;
		let homeCalls = 0;
		const fetch = vi.fn(async (request: Request) => {
			const path = new URL(request.url).pathname;
			if (path === "/api/v1/session/bootstrap") {
				bootstrapCalls += 1;
				if (bootstrapCalls === 2) return jsonResponse({ code: "provider_unavailable", message: "Provider unavailable", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 503);
				return jsonResponse(sessionBootstrap(bootstrapCalls === 3, bootstrapCalls === 3 ? "scope-b-only" : "scope-a-only"));
			}
			if (path === "/api/v1/session/scopes") return jsonResponse(sessionScopes());
			if (path === "/api/v1/home/summary") {
				homeCalls += 1;
				return homeCalls === 1 ? scopeStaleResponse() : jsonResponse({ agent_count: 0, finding_count: 0, critical_finding_count: 0, attack_path_count: 0 });
			}
			throw new Error(`unexpected request ${path}`);
		});
		vi.stubGlobal("fetch", fetch);
		try {
			render(<APIProvider><SessionProvider><ScopeStaleConsumer /></SessionProvider></APIProvider>);
			await screen.findByText("scope A capability");
			await userEvent.click(screen.getByRole("button", { name: "Load scoped data" }));
			await screen.findByText("stale session error");
			expect(screen.queryByText("stale session loading")).not.toBeInTheDocument();

			await userEvent.click(screen.getByRole("button", { name: "Retry session" }));
			await screen.findByText("scope B capability");
			expect(screen.getByText("stale session authenticated")).toBeVisible();
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it("aborts bootstrap on unmount and cannot publish its late scope", async () => {
		const bootstrap = deferred<Response>();
		let bootstrapSignal: AbortSignal | undefined;
		const observedHomeScopes: string[] = [];
		const fetch = vi.fn(async (request: Request) => {
			const path = new URL(request.url).pathname;
			if (path === "/api/v1/session/bootstrap") {
				bootstrapSignal = request.signal;
				return bootstrap.promise;
			}
			if (path === "/api/v1/session/scopes") return jsonResponse(sessionScopes());
			if (path === "/api/v1/home/summary") {
				observedHomeScopes.push(request.headers.get("X-Zasp-Expected-Scope") ?? "");
				return jsonResponse({ agent_count: 0, finding_count: 0, critical_finding_count: 0, attack_path_count: 0 });
			}
			throw new Error(`unexpected request ${path}`);
		});
		vi.stubGlobal("fetch", fetch);
		try {
			const rendered = render(<APIProvider><SessionProvider><ScopeStaleConsumer /></SessionProvider></APIProvider>);
			await waitFor(() => expect(bootstrapSignal).toBeDefined());
			rendered.rerender(<APIProvider><ScopeProbe /></APIProvider>);
			expect(bootstrapSignal?.aborted).toBe(true);

			act(() => bootstrap.resolve(jsonResponse(sessionBootstrap(false, "scope-a-only"))));
			await act(async () => { await bootstrap.promise; await Promise.resolve(); });
			await userEvent.click(screen.getByRole("button", { name: "Probe request scope" }));
			await waitFor(() => expect(observedHomeScopes).toHaveLength(1));
			expect(observedHomeScopes).toEqual([""]);
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it("fails closed and rebootstraps through an A-to-B-to-A cross-tab scope race", async () => {
		let activeScope = false;
		let bootstrapCalls = 0;
		const scopedAssertions: string[] = [];
		const fetch = vi.fn(async (request: Request) => {
			const path = new URL(request.url).pathname;
			if (path === "/api/v1/session/bootstrap") {
				bootstrapCalls += 1;
				expect(request.headers.get("X-Zasp-Expected-Scope")).toBeNull();
				return jsonResponse(sessionBootstrap(activeScope));
			}
			if (path === "/api/v1/session/scopes") return jsonResponse(sessionScopes());
			if (path === "/api/v1/home/summary") {
				scopedAssertions.push(request.headers.get("X-Zasp-Expected-Scope") ?? "");
				activeScope = !activeScope;
				return jsonResponse({ code: "scope_stale", message: "Session scope changed; rebootstrap required", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 409);
			}
			throw new Error(`unexpected request ${path}`);
		});
		vi.stubGlobal("fetch", fetch);
		try {
			render(<APIProvider><SessionProvider><ScopeStaleConsumer /></SessionProvider></APIProvider>);
			await screen.findByText("active environment pid_10000003-0000-4000-8000-000000000003");
			await userEvent.click(screen.getByRole("button", { name: "Load scoped data" }));
			await screen.findByText("active environment pid_10000023-0000-4000-8000-000000000023");
			await userEvent.click(screen.getByRole("button", { name: "Load scoped data" }));
			await screen.findByText("active environment pid_10000003-0000-4000-8000-000000000003");
			expect(bootstrapCalls).toBe(3);
			expect(scopedAssertions).toEqual([
				"pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003",
				"pid_10000001-0000-4000-8000-000000000001/pid_10000022-0000-4000-8000-000000000022/pid_10000023-0000-4000-8000-000000000023",
			]);
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it.each([
		["success", new Response(null, { status: 204 })],
		["error", jsonResponse({ code: "provider_unavailable", message: "Provider unavailable", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 503)],
	])("lets the newest authoritative target settle a pending switch before its old %s completes", async (_completion, oldSwitchResponse) => {
		const oldSwitch = deferred<Response>();
		let bootstrapCalls = 0;
		const fetch = vi.fn(async (request: Request) => {
			const path = new URL(request.url).pathname;
			if (path === "/api/v1/session/bootstrap") {
				bootstrapCalls += 1;
				return jsonResponse(sessionBootstrap(bootstrapCalls > 1));
			}
			if (path === "/api/v1/session/scopes") return jsonResponse(sessionScopes());
			if (path === "/api/v1/session/scope") return oldSwitch.promise;
			if (path === "/api/v1/home/summary") return scopeStaleResponse();
			throw new Error(`unexpected request ${path}`);
		});
		vi.stubGlobal("fetch", fetch);
		try {
			render(<APIProvider><SessionProvider><ScopeSwitchOverlapConsumer /></SessionProvider></APIProvider>);
			await userEvent.click(await screen.findByRole("button", { name: "Start overlapping switch" }));
			expect(screen.getByText("overlap switch pending")).toBeVisible();
			await userEvent.click(screen.getByRole("button", { name: "Trigger overlapping stale scope" }));

			await screen.findByText("overlap environment pid_10000023-0000-4000-8000-000000000023");
			await waitFor(() => expect(screen.getByText("overlap switch idle")).toBeVisible());
			expect(bootstrapCalls).toBe(2);

			act(() => oldSwitch.resolve(oldSwitchResponse));
			await act(async () => { await oldSwitch.promise; await Promise.resolve(); });
			expect(screen.getByText("overlap switch idle")).toBeVisible();
			expect(screen.getByText("overlap environment pid_10000023-0000-4000-8000-000000000023")).toBeVisible();
			expect(bootstrapCalls).toBe(2);
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it("clears pending when the newest authoritative load confirms a different A-B-A scope", async () => {
		const oldSwitch = deferred<Response>();
		let bootstrapCalls = 0;
		const fetch = vi.fn(async (request: Request) => {
			const path = new URL(request.url).pathname;
			if (path === "/api/v1/session/bootstrap") {
				bootstrapCalls += 1;
				return jsonResponse(sessionBootstrap(false));
			}
			if (path === "/api/v1/session/scopes") return jsonResponse(sessionScopes());
			if (path === "/api/v1/session/scope") return oldSwitch.promise;
			if (path === "/api/v1/home/summary") return scopeStaleResponse();
			throw new Error(`unexpected request ${path}`);
		});
		vi.stubGlobal("fetch", fetch);
		try {
			render(<APIProvider><SessionProvider><ScopeSwitchOverlapConsumer /></SessionProvider></APIProvider>);
			await userEvent.click(await screen.findByRole("button", { name: "Start overlapping switch" }));
			await userEvent.click(screen.getByRole("button", { name: "Trigger overlapping stale scope" }));

			await screen.findByText("overlap error scope_not_applied");
			expect(screen.getByText("overlap switch error")).toBeVisible();
			expect(screen.getByText("overlap environment pid_10000003-0000-4000-8000-000000000003")).toBeVisible();
			expect(bootstrapCalls).toBe(2);

			act(() => oldSwitch.resolve(jsonResponse({ code: "provider_unavailable", message: "Provider unavailable", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 503)));
			await act(async () => { await oldSwitch.promise; await Promise.resolve(); });
			expect(screen.getByText("overlap error scope_not_applied")).toBeVisible();
			expect(bootstrapCalls).toBe(2);
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it("leaves a failed newest switch-owned load on the reconciliation retry path", async () => {
		const oldSwitch = deferred<Response>();
		let bootstrapCalls = 0;
		const fetch = vi.fn(async (request: Request) => {
			const path = new URL(request.url).pathname;
			if (path === "/api/v1/session/bootstrap") {
				bootstrapCalls += 1;
				if (bootstrapCalls === 2) return jsonResponse({ code: "provider_unavailable", message: "Provider unavailable", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 503);
				return jsonResponse(sessionBootstrap(bootstrapCalls > 2));
			}
			if (path === "/api/v1/session/scopes") return jsonResponse(sessionScopes());
			if (path === "/api/v1/session/scope") return oldSwitch.promise;
			if (path === "/api/v1/home/summary") return scopeStaleResponse();
			throw new Error(`unexpected request ${path}`);
		});
		vi.stubGlobal("fetch", fetch);
		try {
			render(<APIProvider><SessionProvider><ScopeSwitchOverlapConsumer /></SessionProvider></APIProvider>);
			await userEvent.click(await screen.findByRole("button", { name: "Start overlapping switch" }));
			await userEvent.click(screen.getByRole("button", { name: "Trigger overlapping stale scope" }));

			await screen.findByText("overlap error scope_reconciliation_failed");
			expect(screen.getByText("overlap session error")).toBeVisible();
			await userEvent.click(screen.getByRole("button", { name: "Retry overlapping reconciliation" }));
			await screen.findByText("overlap environment pid_10000023-0000-4000-8000-000000000023");
			expect(screen.getByText("overlap switch idle")).toBeVisible();

			act(() => oldSwitch.resolve(jsonResponse({ code: "provider_unavailable", message: "Provider unavailable", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 503)));
			await act(async () => { await oldSwitch.promise; await Promise.resolve(); });
			expect(screen.getByText("overlap switch idle")).toBeVisible();
			expect(bootstrapCalls).toBe(3);
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it.each([
		["bootstrap", "success"],
		["bootstrap", "error"],
		["scope list", "success"],
		["scope list", "error"],
	] as const)("invalidates a delayed %s %s after a validated 401 and permits newer reauthentication", async (phase, completion) => {
		const delayed = deferred<Response>();
		const delayedSignals: AbortSignal[] = [];
		const observedSecurity: Array<{ csrf: string; scope: string }> = [];
		let bootstrapCalls = 0;
		let scopeCalls = 0;
		const queryInitial = deferred<readonly string[]>();
		const queryLate = deferred<readonly string[]>();
		const querySignals: AbortSignal[] = [];
		const query = vi.fn((signal?: AbortSignal) => {
			if (signal) querySignals.push(signal);
			return query.mock.calls.length === 1 ? queryInitial.promise : queryLate.promise;
		});
		const fetch = vi.fn(async (request: Request) => {
			const path = new URL(request.url).pathname;
			if (path === "/api/v1/session/bootstrap") {
				bootstrapCalls += 1;
				if (bootstrapCalls === 2 && phase === "bootstrap") {
					delayedSignals.push(request.signal);
					return delayed.promise;
				}
				return jsonResponse(sessionBootstrap(bootstrapCalls > 1, bootstrapCalls > 1 ? "scope-b-only" : "scope-a-only"));
			}
			if (path === "/api/v1/session/scopes") {
				scopeCalls += 1;
				if (scopeCalls === 2 && phase === "scope list") {
					delayedSignals.push(request.signal);
					return delayed.promise;
				}
				return jsonResponse(sessionScopes());
			}
			if (path === "/api/v1/home/summary") return authenticationRequiredResponse();
			if (path === "/api/v1/session/sign-out") {
				observedSecurity.push({
					csrf: request.headers.get("X-CSRF-Token") ?? "",
					scope: request.headers.get("X-Zasp-Expected-Scope") ?? "",
				});
				return new Response(null, { status: 204 });
			}
			throw new Error(`unexpected request ${path}`);
		});
		vi.stubGlobal("fetch", fetch);
		try {
			render(<APIProvider><SessionProvider><SessionInvalidationConsumer query={query} /></SessionProvider></APIProvider>);
			await screen.findByText("invalidation A capability");
			await userEvent.click(screen.getByRole("button", { name: "Enable invalidation query" }));
			await waitFor(() => expect(query).toHaveBeenCalledOnce());
			act(() => queryInitial.resolve(["protected-scope-a-record"]));
			await screen.findByText("protected-scope-a-record");
			await userEvent.click(screen.getByRole("button", { name: "Refresh invalidation query" }));
			await waitFor(() => expect(query).toHaveBeenCalledTimes(2));
			await userEvent.click(screen.getByRole("button", { name: "Retry invalidated session" }));
			await waitFor(() => expect(delayedSignals).toHaveLength(1));

			await userEvent.click(screen.getByRole("button", { name: "Trigger validated expiry" }));
			await screen.findByText("invalidation session unauthenticated");
			expect(screen.getByText("invalidation capability hidden")).toBeVisible();
			expect(screen.getByText("invalidation query idle")).toBeVisible();
			expect(screen.queryByText("protected-scope-a-record")).not.toBeInTheDocument();
			expect(delayedSignals[0]?.aborted).toBe(true);
			expect(querySignals[1]?.aborted).toBe(true);

			if (completion === "success") {
				act(() => delayed.resolve(phase === "bootstrap" ? jsonResponse(sessionBootstrap(true, "scope-b-only")) : jsonResponse(sessionScopes())));
				await act(async () => { await delayed.promise; await Promise.resolve(); });
			} else {
				act(() => delayed.reject(new Error(`obsolete ${phase} failed`)));
				await act(async () => { try { await delayed.promise; } catch { /* expected fixture failure */ } await Promise.resolve(); });
			}
			expect(screen.getByText("invalidation session unauthenticated")).toBeVisible();
			expect(screen.getByText("invalidation capability hidden")).toBeVisible();

			await userEvent.click(screen.getByRole("button", { name: "Probe invalidated security" }));
			await waitFor(() => expect(observedSecurity).toHaveLength(1));
			expect(observedSecurity).toEqual([{ csrf: "", scope: "" }]);

			await userEvent.click(screen.getByRole("button", { name: "Retry invalidated session" }));
			await screen.findByText("invalidation B capability");
			expect(bootstrapCalls).toBe(3);
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it("lets session invalidation supersede an overlapping stale-scope recovery", async () => {
		const staleBootstrap = deferred<Response>();
		let bootstrapCalls = 0;
		const observedSecurity: Array<{ csrf: string; scope: string }> = [];
		let staleBootstrapSignal: AbortSignal | undefined;
		const fetch = vi.fn(async (request: Request) => {
			const path = new URL(request.url).pathname;
			if (path === "/api/v1/session/bootstrap") {
				bootstrapCalls += 1;
				if (bootstrapCalls === 2) {
					staleBootstrapSignal = request.signal;
					return staleBootstrap.promise;
				}
				return jsonResponse(sessionBootstrap(bootstrapCalls > 2, bootstrapCalls > 2 ? "scope-b-only" : "scope-a-only"));
			}
			if (path === "/api/v1/session/scopes") return jsonResponse(sessionScopes());
			if (path === "/api/v1/home/summary") return request.headers.get("X-Test-Response") === "stale" ? scopeStaleResponse() : authenticationRequiredResponse();
			if (path === "/api/v1/session/sign-out") {
				observedSecurity.push({ csrf: request.headers.get("X-CSRF-Token") ?? "", scope: request.headers.get("X-Zasp-Expected-Scope") ?? "" });
				return new Response(null, { status: 204 });
			}
			throw new Error(`unexpected request ${path}`);
		});
		vi.stubGlobal("fetch", fetch);
		try {
			render(<APIProvider><SessionProvider><SessionInvalidationConsumer /></SessionProvider></APIProvider>);
			await screen.findByText("invalidation A capability");
			await userEvent.click(screen.getByRole("button", { name: "Trigger stale before expiry" }));
			await waitFor(() => expect(staleBootstrapSignal).toBeDefined());
			await userEvent.click(screen.getByRole("button", { name: "Trigger validated expiry" }));
			await screen.findByText("invalidation session unauthenticated");
			expect(staleBootstrapSignal?.aborted).toBe(true);

			act(() => staleBootstrap.resolve(jsonResponse(sessionBootstrap(true, "scope-b-only"))));
			await act(async () => { await staleBootstrap.promise; await Promise.resolve(); });
			expect(screen.getByText("invalidation session unauthenticated")).toBeVisible();
			expect(screen.getByText("invalidation capability hidden")).toBeVisible();
			await userEvent.click(screen.getByRole("button", { name: "Probe invalidated security" }));
			await waitFor(() => expect(observedSecurity).toEqual([{ csrf: "", scope: "" }]));

			await userEvent.click(screen.getByRole("button", { name: "Retry invalidated session" }));
			await screen.findByText("invalidation B capability");
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it("clears authenticated transport state and active loads when SessionProvider unmounts", async () => {
		const delayedBootstrap = deferred<Response>();
		let bootstrapCalls = 0;
		let delayedSignal: AbortSignal | undefined;
		const fetch = vi.fn(async (request: Request) => {
			const path = new URL(request.url).pathname;
			if (path === "/api/v1/session/bootstrap") {
				bootstrapCalls += 1;
				if (bootstrapCalls === 2) {
					delayedSignal = request.signal;
					return delayedBootstrap.promise;
				}
				return jsonResponse(sessionBootstrap(false, "scope-a-only"));
			}
			if (path === "/api/v1/session/scopes") return jsonResponse(sessionScopes());
			if (path === "/api/v1/home/summary") return jsonResponse({ agent_count: 0, finding_count: 0, critical_finding_count: 0, attack_path_count: 0 });
			throw new Error(`unexpected request ${path}`);
		});
		vi.stubGlobal("fetch", fetch);
		try {
			const rendered = render(<APIProvider><SessionProvider><SessionInvalidationConsumer /></SessionProvider></APIProvider>);
			await screen.findByText("invalidation A capability");
			await userEvent.click(screen.getByRole("button", { name: "Retry invalidated session" }));
			await waitFor(() => expect(delayedSignal).toBeDefined());
			rendered.rerender(<APIProvider><ScopeProbe /></APIProvider>);
			expect(delayedSignal?.aborted).toBe(true);

			act(() => delayedBootstrap.resolve(jsonResponse(sessionBootstrap(true, "scope-b-only"))));
			await act(async () => { await delayedBootstrap.promise; await Promise.resolve(); });
			await userEvent.click(screen.getByRole("button", { name: "Probe request scope" }));
			await waitFor(() => expect(fetch).toHaveBeenCalled());
			const probeRequest = fetch.mock.calls.at(-1)?.[0];
			expect(probeRequest?.headers.get("X-Zasp-Expected-Scope")).toBeNull();
		} finally {
			vi.unstubAllGlobals();
		}
	});
  it("bootstraps principal scope and server capabilities then signs out", async () => {
    const fetch = vi.fn(async (request: Request) => {
      if (request.url.endsWith("/api/v1/session/sign-out")) return new Response(null, { status: 204 });
	  if (request.url.endsWith("/api/v1/session/scopes")) return jsonResponse(sessionScopes());
      return jsonResponse(sessionBootstrap());
    });
    const Wrapper = wrapper(fetch);
    render(<Wrapper><Consumer /></Wrapper>);
    expect(screen.getByText("loading")).toBeVisible();
    await waitFor(() => expect(screen.getByText("authenticated")).toBeVisible());
    expect(screen.getByText("inventory enabled")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(screen.getByText("unauthenticated")).toBeVisible());
	expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("switches only a listed scope and clears protected query state before rebootstrap", async () => {
	let switched = false;
	const fetch = vi.fn(async (request: Request) => {
		if (request.url.endsWith("/api/v1/session/scope")) { switched = true; expect(request.method).toBe("PUT"); return new Response(null, { status: 204 }); }
		if (request.url.endsWith("/api/v1/session/scopes")) return jsonResponse(sessionScopes());
		return jsonResponse(sessionBootstrap(switched));
	});
	const Wrapper = wrapper(fetch); render(<Wrapper><Consumer /></Wrapper>);
	await screen.findByRole("button", { name: "Switch scope" });
	await userEvent.click(screen.getByRole("button", { name: "Switch scope" }));
	await waitFor(() => expect(fetch.mock.calls.filter(([request]) => request.url.endsWith("/api/v1/session/bootstrap"))).toHaveLength(2));
  });

	it("reconciles an ambiguous scope failure and exposes bounded retry state", async () => {
		let scopeAttempts = 0;
		let bootstrapCalls = 0;
		let activeScope = false;
		let releaseFirst: (() => void) | undefined;
		const firstScopeResponse = new Promise<void>((resolve) => { releaseFirst = resolve; });
		const fetch = vi.fn(async (request: Request) => {
			if (request.url.endsWith("/api/v1/session/scope")) {
				scopeAttempts += 1;
				expect(request.headers.get("X-CSRF-Token")).toBe("cccccccccccccccccccccccccccccccc");
				if (scopeAttempts === 1) {
					await firstScopeResponse;
					return jsonResponse({ code: "provider_unavailable", message: "Provider unavailable", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 503);
				}
				activeScope = true;
				return new Response(null, { status: 204 });
			}
			if (request.url.endsWith("/api/v1/session/scopes")) return jsonResponse(sessionScopes());
			bootstrapCalls += 1;
			return jsonResponse(sessionBootstrap(activeScope));
		});
		const Wrapper = wrapper(fetch);
		render(<Wrapper><Consumer /></Wrapper>);
		await screen.findByRole("button", { name: "Switch scope" });
		await userEvent.click(screen.getByRole("button", { name: "Switch scope" }));
		expect(screen.getByText("scope pending")).toBeVisible();
		releaseFirst?.();
		await screen.findByText("scope error");
		expect(bootstrapCalls).toBe(2);
		await userEvent.click(screen.getByRole("button", { name: "Retry scope switch" }));
		await waitFor(() => expect(screen.getByText("scope idle")).toBeVisible());
		expect(scopeAttempts).toBe(2);
		expect(bootstrapCalls).toBe(3);
	});

	it("treats an errored mutation as success when bootstrap proves the target scope", async () => {
		let activeScope = false;
		let scopeAttempts = 0;
		const fetch = vi.fn(async (request: Request) => {
			if (request.url.endsWith("/api/v1/session/scope")) {
				scopeAttempts += 1;
				activeScope = true;
				return jsonResponse({ code: "provider_unavailable", message: "Provider unavailable", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 503);
			}
			if (request.url.endsWith("/api/v1/session/scopes")) return jsonResponse(sessionScopes());
			return jsonResponse(sessionBootstrap(activeScope));
		});
		const Wrapper = wrapper(fetch);
		render(<Wrapper><Consumer /></Wrapper>);
		await userEvent.click(await screen.findByRole("button", { name: "Switch scope" }));
		await waitFor(() => expect(screen.getByText("scope idle")).toBeVisible());
		expect(screen.queryByText(/scope error/)).not.toBeInTheDocument();
		expect(scopeAttempts).toBe(1);
	});

	it("retries failed reconciliation before resending a successful mutation", async () => {
		let activeScope = false;
		let scopeAttempts = 0;
		let bootstrapCalls = 0;
		const fetch = vi.fn(async (request: Request) => {
			if (request.url.endsWith("/api/v1/session/scope")) {
				scopeAttempts += 1;
				activeScope = true;
				return new Response(null, { status: 204 });
			}
			if (request.url.endsWith("/api/v1/session/scopes")) return jsonResponse(sessionScopes());
			bootstrapCalls += 1;
			if (bootstrapCalls === 2) return jsonResponse({ code: "provider_unavailable", message: "Provider unavailable", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 503);
			return jsonResponse(sessionBootstrap(activeScope));
		});
		const Wrapper = wrapper(fetch);
		render(<Wrapper><Consumer /></Wrapper>);
		await userEvent.click(await screen.findByRole("button", { name: "Switch scope" }));
		await screen.findByText("scope error scope_reconciliation_failed");
		expect(scopeAttempts).toBe(1);
		await userEvent.click(screen.getByRole("button", { name: "Retry scope switch" }));
		await waitFor(() => expect(screen.getByText("scope idle")).toBeVisible());
		expect(scopeAttempts).toBe(1);
		expect(bootstrapCalls).toBe(3);
	});

	it("reports the authoritative different scope before allowing a resend", async () => {
		let scopeAttempts = 0;
		let activeScope = false;
		const fetch = vi.fn(async (request: Request) => {
			if (request.url.endsWith("/api/v1/session/scope")) {
				scopeAttempts += 1;
				if (scopeAttempts === 2) activeScope = true;
				return new Response(null, { status: 204 });
			}
			if (request.url.endsWith("/api/v1/session/scopes")) return jsonResponse(sessionScopes());
			return jsonResponse(sessionBootstrap(activeScope));
		});
		const Wrapper = wrapper(fetch);
		render(<Wrapper><Consumer /></Wrapper>);
		await userEvent.click(await screen.findByRole("button", { name: "Switch scope" }));
		await screen.findByText("scope error scope_not_applied");
		expect(scopeAttempts).toBe(1);
		await userEvent.click(screen.getByRole("button", { name: "Retry scope switch" }));
		await waitFor(() => expect(screen.getByText("scope idle")).toBeVisible());
		expect(scopeAttempts).toBe(2);
	});

	it("removes scope A data before a delayed failing scope B query and ignores late A completion", async () => {
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
		const scopeA = deferred();
		const lateScopeA = deferred();
		const scopeB = deferred();
		const attempts = [scopeA, lateScopeA, scopeB];
		const signals: AbortSignal[] = [];
		const query = vi.fn((signal?: AbortSignal) => {
			if (signal) signals.push(signal);
			const attempt = attempts[query.mock.calls.length - 1];
			if (!attempt) throw new Error("unexpected scoped query attempt");
			return attempt.promise;
		});
		let activeScope = false;
		const fetch = vi.fn(async (request: Request) => {
			if (request.url.endsWith("/api/v1/session/scope")) {
				activeScope = true;
				return new Response(null, { status: 204 });
			}
			if (request.url.endsWith("/api/v1/session/scopes")) return jsonResponse(sessionScopes());
			return jsonResponse(sessionBootstrap(activeScope));
		});
		const Wrapper = wrapper(fetch);
		render(<Wrapper><ScopedQueryConsumer query={query} /></Wrapper>);
		await waitFor(() => expect(query).toHaveBeenCalledTimes(1));
		act(() => scopeA.resolve(["scope-a-agent"]));
		await screen.findByText("scope-a-agent");

		await userEvent.click(screen.getByRole("button", { name: "Refresh scoped query" }));
		await waitFor(() => expect(query).toHaveBeenCalledTimes(2));
		await userEvent.click(screen.getByRole("button", { name: "Switch scoped query" }));
		await waitFor(() => expect(query).toHaveBeenCalledTimes(3));
		expect(signals[1]?.aborted).toBe(true);
		expect(screen.queryByText("scope-a-agent")).not.toBeInTheDocument();
		expect(screen.getByText("query loading")).toBeVisible();

		act(() => scopeB.reject(new Error("scope B provider unavailable")));
		await screen.findByText("query error");
		expect(screen.queryByText("scope-a-agent")).not.toBeInTheDocument();
		act(() => lateScopeA.resolve(["late-scope-a-agent"]));
		await waitFor(() => expect(screen.getByText("query error")).toBeVisible());
		expect(screen.queryByText("late-scope-a-agent")).not.toBeInTheDocument();
	});

  it("fails closed and exposes no capability when the session expired", async () => {
    const fetch = vi.fn(async () => jsonResponse({
      code: "authentication_required", message: "Authentication required",
      correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false,
    }, 401));
    const Wrapper = wrapper(fetch);
    render(<Wrapper><Consumer /></Wrapper>);
    await waitFor(() => expect(screen.getByText("unauthenticated")).toBeVisible());
    expect(screen.getByText("inventory hidden")).toBeVisible();
  });

  it("builds a same-origin sign-in redirect from a bounded return path", () => {
    expect(buildSignInURL("/violations?status=open")).toBe("/sign-in?return_to=%2Fviolations%3Fstatus%3Dopen");
    expect(buildSignInURL("https://evil.example/steal")).toBe("/sign-in?return_to=%2F");
    expect(buildSignInURL("//evil.example/steal")).toBe("/sign-in?return_to=%2F");
  });
});

function sessionBootstrap(switched = false, exclusiveCapability?: "scope-a-only" | "scope-b-only") {
  return {
    principal: {
      id: "pid_10000004-0000-4000-8000-000000000004",
      organization_id: "pid_10000001-0000-4000-8000-000000000001",
      organization_reference: "organization-live-a", member_reference: "member-live-a",
      role: "security_admin", active: true,
    },
    organization_id: "pid_10000001-0000-4000-8000-000000000001",
	workspace_id: switched ? "pid_10000022-0000-4000-8000-000000000022" : "pid_10000002-0000-4000-8000-000000000002",
	environment_id: switched ? "pid_10000023-0000-4000-8000-000000000023" : "pid_10000003-0000-4000-8000-000000000003",
    permissions: ["view", "manage_findings"],
	capabilities: ["inventory.read", "scope.switch", ...(exclusiveCapability ? [exclusiveCapability] : [])],
	csrf_token: switched ? "dddddddddddddddddddddddddddddddd" : "cccccccccccccccccccccccccccccccc",
	fresh_auth_expires_at: new Date(Date.now() + 60_000).toISOString(),
    correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
  };
}

function sessionScopes() { return { items: [
	{ organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003", label: "Production" },
	{ organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000022-0000-4000-8000-000000000022", environment_id: "pid_10000023-0000-4000-8000-000000000023", label: "Staging" },
] }; }

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function scopeStaleResponse() {
		return jsonResponse({ code: "scope_stale", message: "Session scope changed; rebootstrap required", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }, 409);
}

function authenticationRequiredResponse() {
	return jsonResponse({ code: "authentication_required", message: "Authentication required", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false }, 401);
}
