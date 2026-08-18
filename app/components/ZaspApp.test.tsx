import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";
import { ZaspApp } from "./ZaspApp";

describe("Zasp application", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState({}, "", "/");
  });

  it.each([
    ["Agents", "Agentic assets"],
    ["Identities", "Non-human identities"],
    ["Findings", "Identity violations"],
    ["Policies", "Identity policies"],
    ["Red Team", "Red team results"],
    ["Connections", "Connectors"],
  ])("navigates from %s to its workspace", async (link, heading) => {
    render(<ZaspApp />);
    await userEvent.click(screen.getByRole("link", { name: link }));
    expect(screen.getByRole("heading", { name: heading })).toBeVisible();
  });

  it("investigates a risky identity and remediates its critical violation", async () => {
    render(<ZaspApp />);
    await userEvent.click(screen.getByRole("link", { name: "Identities" }));
    await userEvent.click(screen.getByRole("tab", { name: /Risky identities/ }));
    await userEvent.click(screen.getByRole("button", { name: /aws-prod-agent-key/ }));
    expect(screen.getByText("Maya Chen → Release Agent → aws-prod-agent-key → AWS Production")).toBeVisible();
    await userEvent.click(screen.getByRole("tab", { name: /Violations/ }));
    await userEvent.click(screen.getByRole("button", { name: "Admin credential exposed to agent runtime" }));
    await userEvent.click(screen.getByRole("tab", { name: "Remediation" }));
    await userEvent.click(screen.getByRole("button", { name: "Rotate credential" }));
    await userEvent.click(screen.getByRole("button", { name: "Confirm remediation" }));
    expect(screen.getByText("Fixed")).toBeVisible();
  });

  it("connects a cloud inventory source", async () => {
    render(<ZaspApp />);
    await userEvent.click(screen.getByRole("link", { name: "Connections" }));
    await userEvent.click(screen.getByRole("button", { name: "Connect Amazon Web Services" }));
    await userEvent.type(screen.getByLabelText("Role ARN"), "arn:aws:iam::123456789012:role/ZaspReadOnly");
    await userEvent.type(screen.getByLabelText("External ID"), "northstar-prod");
    await userEvent.click(screen.getByRole("button", { name: "Connect now" }));
    expect(screen.getByRole("status")).toHaveTextContent("Amazon Web Services connected");
  });

  it("renders connection catalog, freshness list, bounded detail history, and supported actions", async () => {
    render(<ZaspApp />);
    await userEvent.click(screen.getByRole("link", { name: "Connections" }));
    expect(screen.getByRole("heading", { name: "Connected integrations" })).toBeVisible();
    expect(screen.getByRole("button", { name: "View Microsoft Azure connection" })).toBeVisible();
    expect(screen.queryByText(/cartography|prowler|nango/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "View Kubernetes connection" }));
    const dialog = screen.getByRole("dialog", { name: "Kubernetes" });
    expect(dialog).toHaveTextContent("Production / us-west");
    expect(dialog).toHaveTextContent("Runtime signals");
    expect(dialog).toHaveTextContent("3h ago");
    expect(dialog).toHaveTextContent("failed");
    expect(screen.getByRole("button", { name: "Sync now" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Delete connection" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Review access" })).toBeVisible();
  });

  it("renders provider-specific connection setup and remediation flows", async () => {
    render(<ZaspApp />);
    await userEvent.click(screen.getByRole("link", { name: "Connections" }));
    await userEvent.click(screen.getByRole("button", { name: "Connect Amazon Web Services" }));
    const aws = screen.getByRole("dialog", { name: "Connect Amazon Web Services" });
    for (const label of ["Review access", "Role and external ID", "Test connection", "Initial sync", "Coverage"]) expect(aws).toHaveTextContent(label);
    expect(aws).toHaveTextContent("Missing iam:GetRole permission");
    await userEvent.click(screen.getByRole("button", { name: "Close" }));

    await userEvent.click(screen.getByRole("button", { name: "View GitHub connection" }));
    await userEvent.click(screen.getByRole("button", { name: "Review access" }));
    expect(screen.getByRole("dialog", { name: "Review GitHub access" })).toHaveTextContent("Repository and Organization scope");
    expect(screen.getByRole("dialog", { name: "Review GitHub access" })).toHaveTextContent("Scope validation");
  });

  it("keeps directory security and signed webhooks separate and bounded", async () => {
    render(<ZaspApp />);
    await userEvent.click(screen.getByRole("link", { name: "Connections" }));
    await userEvent.click(screen.getByRole("button", { name: "Connect Workforce Directory" }));
    expect(screen.getByRole("dialog", { name: "Connect Workforce Directory" })).toHaveTextContent("Directory security integration");
    expect(screen.getByRole("dialog", { name: "Connect Workforce Directory" })).toHaveTextContent("separate from product sign-in");
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    await userEvent.click(screen.getByRole("button", { name: "Connect Generic Webhook" }));
    expect(screen.getByRole("dialog", { name: "Connect Generic Webhook" })).toHaveTextContent("Signature status");
    expect(screen.queryByLabelText(/action url/i)).not.toBeInTheDocument();
  });

  it("renders sensor list, coverage, enrollment, rotation, and deletion controls", async () => {
    render(<ZaspApp />);
    await userEvent.click(screen.getByRole("link", { name: "Sensors" }));
    expect(screen.getByRole("heading", { name: "Runtime sensors" })).toBeVisible();
    expect(screen.getByText("Unsupported kernel")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "View production-us-west sensor" }));
    expect(screen.getByRole("dialog", { name: "production-us-west" })).toHaveTextContent("Coverage");
    expect(screen.getByRole("button", { name: "Rotate enrollment token" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Delete sensor" })).toBeVisible();
  });

  it.each([
    [/^Protected interactions/, "Security agents"],
    [/^Runtime guardrails/, "Security agents"],
    [/^Enforce the secure code guardrail/, "Identity policies"],
    [/^Market Research Agent first observed/, "Agentic assets"],
  ])("keeps the Overview action %s inside the canonical product routes", async (action, heading) => {
    render(<ZaspApp />);
    await userEvent.click(screen.getByRole("button", { name: action }));
    expect(screen.getByRole("heading", { name: heading })).toBeVisible();
  });

  it("opens the bounded Attack Lab destination from Red Team", async () => {
    render(<ZaspApp />);
    await userEvent.click(screen.getByRole("link", { name: "Red Team" }));
    await userEvent.click(screen.getByRole("button", { name: "Run scan" }));
    expect(screen.getByRole("heading", { name: "Attack lab" })).toBeVisible();
  });

  it("routes Identity & Access through the generated-client product surface", () => {
    window.history.replaceState({}, "", "/administration/identity-access");
    render(<ZaspApp />);
    expect(screen.getByText("Loading identity and access…")).toBeVisible();
  });
});
