import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { resolveRoute } from "../domain/routes";
import { LeftNav } from "./LeftNav";

const labels = [
  "Overview", "Agents", "Tools & MCP", "Identities", "Runtimes", "Findings",
  "Attack Paths", "Red Team", "Attack Lab", "Policies", "Security Agents",
  "Approvals", "Sessions", "Evidence", "Connections", "Sensors",
  "Identity & Access", "Audit Log", "Data & Retention", "External Data Flows",
  "System Health", "API Access",
] as const;

const paths = [
  "/", "/discovery/assets", "/inventory/tools", "/identities", "/inventory/runtimes",
  "/violations", "/exposure/attack-paths", "/red-team/results", "/test/attack-lab",
  "/policies", "/protect/security-agents", "/protect/approvals", "/investigate/sessions",
  "/compliance/evidence", "/connectors", "/integrations/sensors",
  "/administration/identity-access", "/administration/audit-log",
  "/administration/data-retention", "/administration/external-data-flows",
  "/administration/system-health", "/administration/api-access",
] as const;

describe("LeftNav", () => {
  it("renders the exact accessible product navigation with no provider labels", () => {
    render(<LeftNav route={resolveRoute("/violations")} openFindingCount={12} onNavigate={vi.fn()} onClose={vi.fn()} />);
    const navigation = screen.getByRole("navigation", { name: "Main navigation" });
    const links = within(navigation).getAllByRole("link");
    expect(links).toHaveLength(22);
    expect(links.map((link) => link.getAttribute("aria-label"))).toEqual(labels);
    expect(links.map((link) => link.getAttribute("href"))).toEqual(paths);
    for (const group of ["Home", "Inventory", "Exposure", "Test", "Protect", "Investigate", "Compliance", "Integrations", "Administration"]) {
      expect(within(navigation).getByText(group, { selector: ".nav-group-label" })).toBeVisible();
    }
    expect(screen.getByRole("link", { name: "Findings" })).toHaveAttribute("aria-current", "page");
    expect(within(screen.getByRole("link", { name: "Findings" })).getByText("12")).toBeVisible();
    expect(navigation.textContent).not.toMatch(/Cartography|Prowler|Nango|Promptfoo|Neo4j|Tetragon|OpenTelemetry|LocalStack|Stytch/i);
  });

  it("enhances real links with bounded navigation and close callbacks", async () => {
    const onNavigate = vi.fn();
    const onClose = vi.fn();
    render(<LeftNav route={resolveRoute("/")} openFindingCount={0} onNavigate={onNavigate} onClose={onClose} />);
    await userEvent.click(screen.getByRole("link", { name: "Agents" }));
    expect(onNavigate).toHaveBeenCalledOnce();
    expect(onNavigate).toHaveBeenCalledWith("/discovery/assets");
    expect(onClose).toHaveBeenCalledOnce();
    await userEvent.click(screen.getByRole("button", { name: "Close navigation" }));
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 1_000, "17", null])("does not render an invalid finding count %s", (openFindingCount) => {
    render(<LeftNav route={resolveRoute("/")} openFindingCount={openFindingCount} onNavigate={vi.fn()} onClose={vi.fn()} />);
    expect(within(screen.getByRole("link", { name: "Findings" })).queryByText(String(openFindingCount))).not.toBeInTheDocument();
    expect(screen.queryByTestId("open-findings-count")).not.toBeInTheDocument();
  });
});
