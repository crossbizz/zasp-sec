import { describe, expect, it } from "vitest";
import type { Policy } from "./types";
import { DEMO_STATE } from "./seed";
import { demoReducer, hydrateDemoState, serializeDemoState } from "./store";

const POLICY_FIXTURE: Policy = {
  id: "policy-new",
  name: "Protect production agent credentials",
  description: "Protects production identities",
  status: "active",
  severity: "high",
  scopeAssetIds: ["asset-release-agent"],
  scopeIdentityIds: [],
  violationCount: 0,
  segregation: true,
  expirationTracking: true,
  flagExpired: true,
  maxAgeDays: 45,
  warningDays: 14,
  created: "Aug 13, 2026",
  modified: "Aug 13, 2026",
  lastTriggered: "Never",
  raw: "name: Protect production agent credentials",
};

describe("demo state", () => {
  it("marks a violation fixed and records its remediation", () => {
    const next = demoReducer(DEMO_STATE, {
      type: "violation.remediate",
      violationId: "vio-admin-runtime",
      remediation: "Credential rotated",
    });
    expect(next.violations.find((item) => item.id === "vio-admin-runtime")).toMatchObject({
      status: "fixed",
      remediation: "Credential rotated",
    });
  });

  it("adds a created policy without removing seeded policies", () => {
    const next = demoReducer(DEMO_STATE, { type: "policy.create", policy: POLICY_FIXTURE });
    expect(next.policies[0].id).toBe(POLICY_FIXTURE.id);
    expect(next.policies.length).toBe(DEMO_STATE.policies.length + 1);
  });

  it("connects a connector after a successful setup", () => {
    const next = demoReducer(DEMO_STATE, { type: "connector.connect", connectorId: "aws" });
    expect(next.connectors.find((item) => item.id === "aws")?.status).toBe("connected");
  });

  it("round trips persisted demo state", () => {
    expect(hydrateDemoState(serializeDemoState(DEMO_STATE))).toEqual(DEMO_STATE);
  });

  it("rejects invalid persisted data", () => {
    expect(hydrateDemoState('{"version":2}')).toEqual(DEMO_STATE);
    expect(hydrateDemoState("not json")).toEqual(DEMO_STATE);
  });
});
