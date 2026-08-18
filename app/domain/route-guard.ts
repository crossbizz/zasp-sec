export type SessionState = "loading" | "unauthenticated" | "authenticated";

export type RouteAccess =
  | Readonly<{ action: "pending" }>
  | Readonly<{ action: "render" }>
  | Readonly<{ action: "redirect"; path: "/" | "/sign-in" }>;

const pending: RouteAccess = Object.freeze({ action: "pending" });
const render: RouteAccess = Object.freeze({ action: "render" });
const redirectHome: RouteAccess = Object.freeze({ action: "redirect", path: "/" });
const redirectSignIn: RouteAccess = Object.freeze({ action: "redirect", path: "/sign-in" });
const canonicalPath = /^\/(?:[a-z0-9-]+(?:\/[a-z0-9-]+)*)?$/;

export function resolveRouteAccess(pathname: string, state: SessionState): RouteAccess {
  if (typeof pathname !== "string" || !canonicalPath.test(pathname)) return pending;
  if (state !== "loading" && state !== "unauthenticated" && state !== "authenticated") return pending;
  if (state === "loading") return pending;

  const isPublic = pathname === "/sign-in";
  if (state === "unauthenticated") return isPublic ? render : redirectSignIn;
  return isPublic ? redirectHome : render;
}
