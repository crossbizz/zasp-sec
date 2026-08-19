import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { createAPIClient } from "../../apps/web/api/client";
import { APIProvider } from "../api/APIProvider";
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

function wrapper(fetch: (request: Request) => Promise<Response>) {
  const client = createAPIClient({ fetch, generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" });
  function Wrapper({ children }: { children: ReactNode }) {
    return <APIProvider client={client}><SessionProvider>{children}</SessionProvider></APIProvider>;
  }
  return Wrapper;
}

describe("SessionProvider", () => {
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

function sessionBootstrap(switched = false) {
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
	capabilities: ["inventory.read", "scope.switch"],
    csrf_token: "cccccccccccccccccccccccccccccccc",
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
