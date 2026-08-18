import { describe, expect, it } from "vitest";
import { resolveRouteAccess } from "./route-guard";

describe("unauthenticated route guard decision", () => {
  it.each([
    ["loading", "/sign-in", { action: "pending" }],
    ["loading", "/", { action: "pending" }],
    ["unauthenticated", "/sign-in", { action: "render" }],
    ["unauthenticated", "/", { action: "redirect", path: "/sign-in" }],
    ["unauthenticated", "/future/123", { action: "redirect", path: "/sign-in" }],
    ["authenticated", "/sign-in", { action: "redirect", path: "/" }],
    ["authenticated", "/", { action: "render" }],
    ["authenticated", "/future/123", { action: "render" }],
  ] as const)("maps %s at %s to the closed decision", (state, pathname, expected) => {
    const decision = resolveRouteAccess(pathname, state);
    expect(decision).toEqual(expected);
    expect(Object.isFrozen(decision)).toBe(true);
  });

  it("fails closed for malformed paths and runtime session values", () => {
    for (const pathname of ["", "sign-in", "//sign-in", "/a//b", "/a/./b", "/a/../b", "/a/%2e%2e/b", "/a\\b", "/a?next=/", "/a#fragment", "/a/", "/A", "/é", "/a\u0000b", "/a\nb"]) {
      expect(resolveRouteAccess(pathname, "authenticated")).toEqual({ action: "pending" });
    }
    expect(resolveRouteAccess("/", "forged" as never)).toEqual({ action: "pending" });
  });

  it("never derives a redirect target from the input path", () => {
    const targets = new Set<string>();
    for (const pathname of ["/", "/future", "/future/123", "/sign-in"]) {
      for (const state of ["loading", "unauthenticated", "authenticated"] as const) {
        const decision = resolveRouteAccess(pathname, state);
        if (decision.action === "redirect") targets.add(decision.path);
      }
    }
    expect([...targets].sort()).toEqual(["/", "/sign-in"]);
  });
});
