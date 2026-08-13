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
    ["Agentic assets", "Agentic assets"],
    ["Identities", "Non-human identities"],
    ["Guardrail activity", "Guardrail activity"],
    ["Red team results", "Red team results"],
    ["Connectors", "Connectors"],
    ["Reports", "Reports"],
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

  it("configures and starts an agent red-team scan", async () => {
    render(<ZaspApp />);
    await userEvent.click(screen.getByRole("link", { name: "Scan runs" }));
    await userEvent.click(screen.getByRole("button", { name: "Run new scan" }));
    await userEvent.click(screen.getByRole("button", { name: "Start scan" }));
    expect(screen.getByRole("status")).toHaveTextContent("Scan queued");
  });

  it("connects a cloud inventory source", async () => {
    render(<ZaspApp />);
    await userEvent.click(screen.getByRole("link", { name: "Connectors" }));
    await userEvent.click(screen.getByRole("button", { name: "Connect Amazon Web Services" }));
    await userEvent.type(screen.getByLabelText("Role ARN"), "arn:aws:iam::123456789012:role/ZaspReadOnly");
    await userEvent.type(screen.getByLabelText("External ID"), "northstar-prod");
    await userEvent.click(screen.getByRole("button", { name: "Connect now" }));
    expect(screen.getByRole("status")).toHaveTextContent("Amazon Web Services connected");
  });
});
