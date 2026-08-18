import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { SessionsComplianceView } from "./SessionsComplianceView";

describe("Sessions, compliance, and data controls", () => {
  it("renders ordered mixed-confidence sessions", () => {
    render(<SessionsComplianceView surface="sessions" />);
    for (const text of ["Session investigations", "Agent", "Principal", "Tool", "Process", "File", "Domain", "Credential", "Resource", "Decision", "Exact", "Strong", "Probable", "Unattributed", "evidence-1"]) expect(screen.getAllByText(text).length).toBeGreaterThan(0);
  });
  it("renders fresh/stale compliance evidence and export states", async () => {
    const user = userEvent.setup();
    render(<SessionsComplianceView surface="compliance" />);
    for (const text of ["SOC 2 Security", "HIPAA safeguard", "Fresh", "Stale", "Missing evidence", "asset-1", "runtime", "evidence-1"]) expect(screen.getByText(text)).toBeVisible();
    expect(screen.queryByText(/certified|certification/i)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Export evidence" }));
    expect(screen.getByText("Export completed")).toBeVisible();
  });
  it("renders metadata-only production data controls", () => {
    render(<SessionsComplianceView surface="data-controls" />);
    expect(screen.getByText("Metadata only")).toBeVisible();
    expect(screen.getByText("30 days")).toBeVisible();
    expect(screen.getByText("Deletion enabled")).toBeVisible();
  });
});
