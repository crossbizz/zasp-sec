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
});
