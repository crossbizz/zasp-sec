"use client";

import { createContext, useContext, useEffect, useReducer, type Dispatch, type ReactNode } from "react";
import { DEMO_STATE } from "./seed";
import type { DemoAction, DemoState } from "./types";

export function demoReducer(state: DemoState, action: DemoAction): DemoState {
  switch (action.type) {
    case "violation.remediate":
      return { ...state, violations: state.violations.map((item) => item.id === action.violationId ? { ...item, status: "fixed", remediation: action.remediation, timeline: [{ time: "Now", event: action.remediation }, ...item.timeline] } : item) };
    case "violation.status":
      return { ...state, violations: state.violations.map((item) => item.id === action.violationId ? { ...item, status: action.status } : item) };
    case "policy.create":
      return { ...state, policies: [action.policy, ...state.policies] };
    case "policy.status":
      return { ...state, policies: state.policies.map((item) => item.id === action.policyId ? { ...item, status: action.status, modified: "Aug 13, 2026" } : item) };
    case "guardrailPolicy.create":
      return { ...state, guardrailPolicies: [action.policy, ...state.guardrailPolicies] };
    case "guardrailEvent.status":
      return { ...state, guardrailEvents: state.guardrailEvents.map((item) => item.id === action.eventId ? { ...item, status: action.status } : item) };
    case "connector.connect":
      return { ...state, connectors: state.connectors.map((item) => item.id === action.connectorId ? { ...item, status: "connected", lastSync: "Now", assetsDiscovered: item.assetsDiscovered ?? 12 } : item) };
    case "connector.disconnect":
      return { ...state, connectors: state.connectors.map((item) => item.id === action.connectorId ? { ...item, status: "disconnected", lastSync: undefined } : item) };
    case "scan.create":
      return { ...state, scans: [action.scan, ...state.scans] };
    case "scan.complete":
      return { ...state, scans: state.scans.map((item) => item.id === action.scanId ? { ...item, status: "complete", progress: 100, completed: "Now", findings: action.findings } : item) };
    case "report.schedule":
      return { ...state, reports: state.reports.map((item) => item.id === action.reportId ? { ...item, scheduled: true, frequency: action.frequency, recipient: action.recipient } : item) };
    case "preferences.update":
      return { ...state, preferences: { ...state.preferences, ...action.preferences } };
    case "notifications.read":
      return { ...state, notifications: state.notifications.map((item) => ({ ...item, read: true })) };
    case "reset":
      return DEMO_STATE;
    default:
      return state;
  }
}

export function serializeDemoState(state: DemoState): string {
  return JSON.stringify(state);
}

export function hydrateDemoState(value: string | null): DemoState {
  if (!value) return DEMO_STATE;
  try {
    const parsed = JSON.parse(value) as Partial<DemoState>;
    if (parsed.version !== 1 || !Array.isArray(parsed.assets) || !Array.isArray(parsed.violations) || !Array.isArray(parsed.connectors)) return DEMO_STATE;
    return parsed as DemoState;
  } catch {
    return DEMO_STATE;
  }
}

interface StoreValue { state: DemoState; dispatch: Dispatch<DemoAction> }
const StoreContext = createContext<StoreValue | null>(null);

export function ZaspStoreProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(demoReducer, DEMO_STATE, (seed) => typeof window === "undefined" ? seed : hydrateDemoState(window.localStorage.getItem("zasp-demo-state")));
  useEffect(() => { window.localStorage.setItem("zasp-demo-state", serializeDemoState(state)); }, [state]);
  return <StoreContext.Provider value={{ state, dispatch }}>{children}</StoreContext.Provider>;
}

export function useZaspStore(): StoreValue {
  const value = useContext(StoreContext);
  if (!value) throw new Error("useZaspStore must be used inside ZaspStoreProvider");
  return value;
}
