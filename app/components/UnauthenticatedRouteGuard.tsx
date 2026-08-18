"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { resolveRouteAccess, type SessionState } from "../domain/route-guard";

export function UnauthenticatedRouteGuard({ pathname, sessionState, onRedirect, children }: {
  pathname: string;
  sessionState: SessionState;
  onRedirect: (path: "/" | "/sign-in") => void;
  children: ReactNode;
}) {
  const decision = resolveRouteAccess(pathname, sessionState);
  const redirectCallback = useRef(onRedirect);
  const redirectedPath = useRef<"/" | "/sign-in" | null>(null);

  useEffect(() => {
    redirectCallback.current = onRedirect;
  }, [onRedirect]);

  useEffect(() => {
    if (decision.action !== "redirect") {
      redirectedPath.current = null;
      return;
    }
    if (redirectedPath.current === decision.path) return;
    redirectedPath.current = decision.path;
    redirectCallback.current(decision.path);
  }, [decision]);

  if (decision.action === "render") return children;
  return <div role="status">Checking session</div>;
}
