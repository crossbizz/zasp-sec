import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../apps/web/api/client";
import { CallbackCompletion, callbackBody } from "./callback/page";
import { buildIdentityStartURL, safeReturnPath } from "./browser-flow";

describe("browser sign-in flow", () => {
  it("starts identity only through the bounded same-origin API", () => {
    expect(buildIdentityStartURL("/discovery/assets?owner=security"))
      .toBe("/api/v1/session/start?return_to=%2Fdiscovery%2Fassets%3Fowner%3Dsecurity");
    expect(buildIdentityStartURL("//evil.example/steal")).toBe("/api/v1/session/start?return_to=%2F");
    expect(safeReturnPath("//evil.example/steal")).toBe("/");
  });

  it("exchanges the callback and replaces with the bounded deep link", async () => {
    window.history.replaceState({}, "", `/auth/callback?token=stytch-oauth-token&state=${"s".repeat(32)}&return_to=%2Fdiscovery%2Fassets`);
		const replace = vi.fn();
    const POST = vi.fn(async () => ({ data: { return_to: "/discovery/assets" }, error: undefined, response: new Response(null, { status: 200 }) }));
		render(<CallbackCompletion suppliedClient={{ POST } as unknown as APIClient} replaceLocation={replace} />);
    await waitFor(() => expect(POST).toHaveBeenCalledWith("/api/v1/session/callback", { body: { provider_token: "stytch-oauth-token", state: "s".repeat(32) } }));
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/discovery/assets"));
  });

  it("accepts an identity provider invitation that arrives without product state", async () => {
    window.history.replaceState({}, "", "/auth/callback?stytch_token_type=multi_tenant_magic_links&token=invitation-token");
    const replace = vi.fn();
    const POST = vi.fn(async () => ({ data: { return_to: "/" }, error: undefined, response: new Response(null, { status: 200 }) }));
    render(<CallbackCompletion suppliedClient={{ POST } as unknown as APIClient} replaceLocation={replace} />);
    await waitFor(() => expect(POST).toHaveBeenCalledWith("/api/v1/session/callback", { body: { provider_token: "invitation-token", provider_token_type: "multi_tenant_magic_links" } }));
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/"));
  });

  it("requires product state for every redirect except an invitation", () => {
    const state = "s".repeat(32);
    expect(callbackBody("token", state, null)).toEqual({ provider_token: "token", state });
    expect(callbackBody("token", state, "oauth")).toEqual({ provider_token: "token", state });
    expect(callbackBody("token", state, "multi_tenant_magic_links")).toEqual({ provider_token: "token", state, provider_token_type: "multi_tenant_magic_links" });
    expect(callbackBody("token", "", null)).toBeNull();
    expect(callbackBody("token", "", "oauth")).toBeNull();
    expect(callbackBody("token", "short", "multi_tenant_magic_links")).toBeNull();
    expect(callbackBody("token", state, "sso")).toBeNull();
    expect(callbackBody("token", "", "session_jwt")).toBeNull();
    expect(callbackBody("", "", "multi_tenant_magic_links")).toBeNull();
  });

  it("does not call the API for an unsupported provider token type", async () => {
    window.history.replaceState({}, "", `/auth/callback?stytch_token_type=sso&token=sso-token&state=${"s".repeat(32)}`);
    const POST = vi.fn();
    render(<CallbackCompletion suppliedClient={{ POST } as unknown as APIClient} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("invalid or expired");
    expect(POST).not.toHaveBeenCalled();
  });

  it("does not call the API for a malformed callback", async () => {
    window.history.replaceState({}, "", "/auth/callback?token=stytch-oauth-token&state=short");
    const POST = vi.fn();
    render(<CallbackCompletion suppliedClient={{ POST } as unknown as APIClient} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("invalid or expired");
    expect(POST).not.toHaveBeenCalled();
  });
});
