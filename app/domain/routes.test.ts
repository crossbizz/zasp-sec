import { describe, expect, it } from "vitest";
import { allRoutes, resolveRoute } from "./routes";

describe("route registry", () => {
  it("keeps every promised workspace reachable", () => {
    expect(allRoutes.map((route) => route.path)).toEqual([
      "/",
      "/discovery/assets",
      "/discovery/endpoints",
      "/discovery/sensitive-data",
      "/discovery/recent-changes",
      "/identities",
      "/violations",
      "/policies",
      "/guardrails/dashboard",
      "/guardrails/activity",
      "/guardrails/actors",
      "/guardrails/components",
      "/guardrails/policies",
      "/red-team/results",
      "/red-team/scans",
      "/connectors",
      "/prompt-hardening",
      "/reports",
    ]);
  });

  it("falls back to overview for an unknown route", () => {
    expect(resolveRoute("/not-a-route").path).toBe("/");
  });
});
