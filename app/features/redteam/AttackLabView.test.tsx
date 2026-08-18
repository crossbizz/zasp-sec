import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { AttackLabView } from "./AttackLabView";

describe("Attack Lab safety and result surface", () => {
  it("requires approved preflight and distinguishes bounded verdicts", async () => {
    const user = userEvent.setup();
    render(<AttackLabView />);
    for (const text of ["test-canary", "test_write", "canary.internal", "500m / 1Gi / 2Gi", "300 seconds", "Destroy after evidence"]) expect(screen.getByText(text)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run Attack Lab" })).toBeDisabled();
    expect(screen.getByText("Undeclared destinations are rejected before sandbox creation.")).toBeVisible();
    await user.click(screen.getByRole("checkbox", { name: "Approve safety decision" }));
    await user.click(screen.getByRole("button", { name: "Run Attack Lab" }));
    for (const heading of ["Verdict", "Timeline", "Canary", "Network", "Evidence"]) expect(screen.getByRole("heading", { name: heading })).toBeVisible();
    expect(screen.getByText("Verified")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Show infrastructure failure" }));
    expect(screen.getByText("Inconclusive")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Show clean non-reproduction" }));
    expect(screen.getByText("Not Reproduced")).toBeVisible();
  });
});
