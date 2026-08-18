import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { PoliciesView } from "./PoliciesView";

describe("Policies administration surface", () => {
  it("renders status, coverage, wizard, simulation, decisions, rollout, and disable", async () => {
    const user = userEvent.setup();
    render(<PoliciesView />);
    for (const text of ["Monitor", "Enforce", "Disabled", "Bundle stale", "Scope", "Trigger", "Conditions", "Action", "Coverage", "Simulate", "Rollout"]) expect(screen.getAllByText(text).length).toBeGreaterThan(0);
    expect(screen.queryByText("Approval")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Simulate policy" }));
    expect(screen.getByText("Matches: 2 · Would block: 1")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Roll to Monitor" }));
    await user.click(screen.getByRole("button", { name: "Enforce policy" }));
    expect(screen.getByText("Current rollout: Enforce")).toBeVisible();
    expect(screen.getByText("Decision evidence: block")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Disable policy" }));
    expect(screen.getByText("Current rollout: Disabled")).toBeVisible();
  });
});
