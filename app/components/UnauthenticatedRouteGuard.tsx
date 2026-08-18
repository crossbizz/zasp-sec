"use client";

import { useEffect, type ReactNode } from "react";
import { resolveRouteAccess, type SessionState } from "../domain/route-guard";

export function UnauthenticatedRouteGuard({ pathname, sessionState, onRedirect, children }: {
  pathname: string;
  sessionState: SessionState;
  onRedirect: (path: "/" | "/sign-in") => void;
  children: ReactNode;
}) {
  const decision = resolveRouteAccess(pathname, sessionState);

  useEffect(() => {
    if (decision.action === "redirect") onRedirect(decision.path);
  }, [decision, onRedirect]);

  if (decision.action === "render") return children;
  return <div role="status">Checking session</div>;
}
