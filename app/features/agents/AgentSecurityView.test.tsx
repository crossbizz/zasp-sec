import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { AgentSecurityView, buildAgentFilterQuery, fixtureAgentSecurityAPI } from "./AgentSecurityView";

describe("M4 Agent Security product surfaces", () => {
  it("renders the filtered Agent list and complete evidence-linked detail", async () => {
    const user = userEvent.setup();
    const updateAgent = vi.fn(fixtureAgentSecurityAPI().updateAgent);
    render(<AgentSecurityView path="/discovery/assets" api={fixtureAgentSecurityAPI({ updateAgent })} onNavigate={() => {}} />);
    expect(screen.getByRole("heading", { name: "Agents" })).toBeInTheDocument();
    for (const label of ["Owner", "Environment", "Risk", "Shell execution", "High-impact reach", "Runtime sensor", "Policy coverage"]) expect(screen.getByLabelText(label)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Open Support agent" }));
    for (const heading of ["Agent identity", "Tools & MCP", "Runtime & sandbox", "Effective capabilities", "Findings", "Attack paths", "Sessions", "Runtime policy coverage"]) expect(screen.getByRole("heading", { name: heading })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Assign security owner" }));
    expect(updateAgent).toHaveBeenCalledTimes(1);
  });

  it("renders inventory details, high-signal findings, bounded paths, and stale Home state", async () => {
    const user = userEvent.setup();
    const api = fixtureAgentSecurityAPI();
    const navigate = vi.fn();
    const { rerender } = render(<AgentSecurityView path="/inventory/tools" api={api} onNavigate={navigate} />);
    expect(screen.getByRole("heading", { name: "Tools & MCP" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Open Customer records MCP" }));
    expect(screen.getByRole("heading", { name: "Evidence and freshness" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close" }));
    rerender(<AgentSecurityView path="/identities" api={api} onNavigate={navigate} />);
    expect(screen.getByRole("heading", { name: "Identities" })).toBeInTheDocument();
    rerender(<AgentSecurityView path="/inventory/runtimes" api={api} onNavigate={navigate} />);
    expect(screen.getByRole("heading", { name: "Runtimes" })).toBeInTheDocument();
    rerender(<AgentSecurityView path="/violations" api={api} onNavigate={navigate} />);
    expect(screen.getByText("Owner missing on production agent")).toBeInTheDocument();
    expect(screen.queryByText("Unrelated cloud record")).not.toBeInTheDocument();
    rerender(<AgentSecurityView path="/exposure/attack-paths" api={api} onNavigate={navigate} />);
    expect(screen.getByText("Untrusted input to production queue")).toBeInTheDocument();
    expect(screen.getByText("Break Path")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Inspect observed edge" }));
    expect(screen.getByRole("dialog", { name: "Evidence side panel" })).toHaveTextContent("high confidence");
    rerender(<AgentSecurityView path="/" api={api} onNavigate={navigate} />);
    expect(screen.getByText("Coverage is stale")).toBeInTheDocument();
    expect(screen.queryByText("No risk detected")).not.toBeInTheDocument();
  });

  it("renders bounded Agent loading, empty, and error states", () => {
    const api = fixtureAgentSecurityAPI();
    const navigate = vi.fn();
    const { rerender } = render(<AgentSecurityView path="/discovery/assets" state="loading" api={api} onNavigate={navigate} />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading agents");
    rerender(<AgentSecurityView path="/discovery/assets" state="empty" api={api} onNavigate={navigate} />);
    expect(screen.getByText("No agents discovered in this scope.")).toBeInTheDocument();
    rerender(<AgentSecurityView path="/discovery/assets" state="error" api={api} onNavigate={navigate} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Agent inventory unavailable");
  });

  it("generates the exact bounded Agent filter query", () => {
    expect(buildAgentFilterQuery({ owner: "security", environment: "production", risk: "high", shell: true, highImpact: true, sensor: "degraded", policy: "missing" })).toBe("environment=production&high_impact=true&owner=security&policy_coverage=missing&risk=high&runtime_sensor=degraded&shell=true");
  });
});
