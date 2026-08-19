import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { createAPIClient } from "../../apps/web/api/client";
import { APIProvider } from "../api/APIProvider";
import { buildSignInURL, SessionProvider, useSession } from "./SessionProvider";

function Consumer() {
  const session = useSession();
  return <div>
    <span>{session.status}</span>
    <span>{session.hasCapability("inventory.read") ? "inventory enabled" : "inventory hidden"}</span>
    {session.status === "authenticated" && <button onClick={() => void session.signOut()}>Sign out</button>}
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
      return jsonResponse(sessionBootstrap());
    });
    const Wrapper = wrapper(fetch);
    render(<Wrapper><Consumer /></Wrapper>);
    expect(screen.getByText("loading")).toBeVisible();
    await waitFor(() => expect(screen.getByText("authenticated")).toBeVisible());
    expect(screen.getByText("inventory enabled")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(screen.getByText("unauthenticated")).toBeVisible());
    expect(fetch).toHaveBeenCalledTimes(2);
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

function sessionBootstrap() {
  return {
    principal: {
      id: "pid_10000004-0000-4000-8000-000000000004",
      organization_id: "pid_10000001-0000-4000-8000-000000000001",
      organization_reference: "organization-live-a", member_reference: "member-live-a",
      role: "security_admin", active: true,
    },
    organization_id: "pid_10000001-0000-4000-8000-000000000001",
    workspace_id: "pid_10000002-0000-4000-8000-000000000002",
    environment_id: "pid_10000003-0000-4000-8000-000000000003",
    permissions: ["view", "manage_findings"],
    capabilities: ["inventory.read", "findings.read", "findings.manage"],
    csrf_token: "cccccccccccccccccccccccccccccccc",
    correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
  };
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
