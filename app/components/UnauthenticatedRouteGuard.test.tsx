import { render, screen, waitFor } from "@testing-library/react";
import { renderToString } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { UnauthenticatedRouteGuard } from "./UnauthenticatedRouteGuard";

describe("UnauthenticatedRouteGuard", () => {
  it("renders children only for a render decision", () => {
    render(<UnauthenticatedRouteGuard pathname="/sign-in" sessionState="unauthenticated" onRedirect={vi.fn()}><h1>Sign in</h1></UnauthenticatedRouteGuard>);
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeVisible();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("renders one fixed pending status without session or provider details", () => {
    const { container } = render(<UnauthenticatedRouteGuard pathname="/private" sessionState="loading" onRedirect={vi.fn()}><h1>Secret</h1></UnauthenticatedRouteGuard>);
    expect(screen.getByRole("status")).toHaveTextContent(/^Checking session$/);
    expect(screen.queryByRole("heading", { name: "Secret" })).not.toBeInTheDocument();
    expect(container.textContent).not.toMatch(/loading|unauthenticated|authenticated|Stytch/i);
  });

  it("redirects after render exactly once to a closed path", async () => {
    const onRedirect = vi.fn();
    render(<UnauthenticatedRouteGuard pathname="/private" sessionState="unauthenticated" onRedirect={onRedirect}><h1>Secret</h1></UnauthenticatedRouteGuard>);
    expect(screen.getByRole("status")).toHaveTextContent(/^Checking session$/);
    await waitFor(() => expect(onRedirect).toHaveBeenCalledOnce());
    expect(onRedirect).toHaveBeenCalledWith("/sign-in");
  });

  it("does not redirect during server render", () => {
    const onRedirect = vi.fn();
    expect(renderToString(<UnauthenticatedRouteGuard pathname="/sign-in" sessionState="authenticated" onRedirect={onRedirect}><h1>Sign in</h1></UnauthenticatedRouteGuard>)).toContain("Checking session");
    expect(onRedirect).not.toHaveBeenCalled();
  });

  it("uses the current callback when a pending decision becomes a redirect", async () => {
    const staleRedirect = vi.fn();
    const currentRedirect = vi.fn();
    const view = render(<UnauthenticatedRouteGuard pathname="/private" sessionState="loading" onRedirect={staleRedirect}><span>Private</span></UnauthenticatedRouteGuard>);
    view.rerender(<UnauthenticatedRouteGuard pathname="/private" sessionState="unauthenticated" onRedirect={currentRedirect}><span>Private</span></UnauthenticatedRouteGuard>);
    await waitFor(() => expect(currentRedirect).toHaveBeenCalledOnce());
    expect(staleRedirect).not.toHaveBeenCalled();
    view.rerender(<UnauthenticatedRouteGuard pathname="/private" sessionState="unauthenticated" onRedirect={currentRedirect}><span>Private</span></UnauthenticatedRouteGuard>);
    expect(currentRedirect).toHaveBeenCalledOnce();
  });
});
