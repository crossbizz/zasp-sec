import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import { APIProvider } from "../../api/APIProvider";
import { createProductionAgentSecurityAPI, ProductionAgentSecurityView } from "./ProductionAgentSecurityView";

const counts = { agent_count: 4, high_risk_paths: 0, verified_changes: 2, blocked_changes: 1, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0 };

function renderHome(value: unknown) {
  const client = { GET: async (path: string) => {
    if (path !== "/api/v1/home/summary") throw new Error("unexpected home request");
    return { data: value, response: new Response(null, { status: 200 }) };
  } } as unknown as APIClient;
  const api = createProductionAgentSecurityAPI(client);
  return render(<APIProvider><ProductionAgentSecurityView path="/" api={api} onNavigate={() => undefined} /></APIProvider>);
}

describe("connected home visibility", () => {
  it("does not turn unknown environment health and zero visible attention counts into a verdict", async () => {
    renderHome({ ...counts, healthy: null, attention_required: null });
    expect(await screen.findByText("Authorized resources only")).toBeVisible();
    expect(screen.getByText("Environment health unavailable")).toBeVisible();
    expect(screen.getByText("4")).toBeVisible();
    for (const text of ["Healthy", "Degraded", "Coverage is degraded", "Needs attention"]) expect(screen.queryByText(text)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Stale launch coverage/ })).not.toBeInTheDocument();
  });
  it("shows visible attention counts while withholding environment health", async () => {
    renderHome({ ...counts, pending_approvals: 3, oldest_approval_age_seconds: 80, healthy: null, attention_required: null });
    expect(await screen.findByText("Needs attention")).toBeVisible();
    expect(screen.getByText("3 · oldest 80s")).toBeVisible();
    expect(screen.getByText("Authorized resources only")).toBeVisible();
    expect(screen.getByText("Environment health unavailable")).toBeVisible();
    for (const text of ["Healthy", "Degraded", "Coverage is degraded"]) expect(screen.queryByText(text)).not.toBeInTheDocument();
  });
  it("preserves full-view degraded coverage and attention presentation", async () => {
    renderHome({ ...counts, healthy: false, attention_required: true });
    expect(await screen.findByText("Coverage is degraded")).toBeVisible();
    expect(screen.getByRole("button", { name: /Stale launch coverage.*Degraded/ })).toBeVisible();
    expect(screen.getByText("Needs attention")).toBeVisible();
    expect(screen.queryByText("Authorized resources only")).not.toBeInTheDocument();
    expect(screen.queryByText("Environment health unavailable")).not.toBeInTheDocument();
  });
  it("preserves full-view healthy coverage with visible attention", async () => {
    renderHome({ ...counts, pending_approvals: 1, healthy: true, attention_required: false });
    expect(await screen.findByText("Needs attention")).toBeVisible();
    expect(screen.getByRole("button", { name: /Stale launch coverage.*Healthy/ })).toBeVisible();
    expect(screen.queryByText("Coverage is degraded")).not.toBeInTheDocument();
    expect(screen.queryByText("Environment health unavailable")).not.toBeInTheDocument();
  });
});
