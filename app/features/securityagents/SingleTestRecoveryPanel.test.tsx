import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SingleTestRecoveryPanel, type RecoveryPanelView, type SingleTestRecoveryPanelProps } from "./SingleTestRecoveryPanel";

const runID = "pid_78000003-0000-4000-8000-000000000003";
const value: RecoveryPanelView = { run_id: runID, parent_version: 7, status: "not_requested",
  request_identity: { definition_version: 3, input_digest: "a".repeat(64) }, completion: null };
function props(overrides: Partial<SingleTestRecoveryPanelProps> = {}): SingleTestRecoveryPanelProps {
  return { runID, version: 7, state: "ready", value, canManage: true, onRequest: vi.fn(async () => {}), onRetry: vi.fn(async () => {}), onRefresh: vi.fn(), ...overrides };
}
describe("SingleTest cleanup recovery panel", () => {
  it("requires explicit stop confirmation and sends only the server-bound original identity", async () => {
    const p = props(); render(<SingleTestRecoveryPanel {...p} />);
    const button = screen.getByRole("button", { name: "Request cleanup recovery" });
    expect(button).toBeDisabled();
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(button);
    await waitFor(() => expect(p.onRequest).toHaveBeenCalledExactlyOnceWith({ id: runID, version: 7,
      body: { definition_version: 3, input_digest: "a".repeat(64), diagnostic: "history_unavailable", stop_original: true } }));
    expect(screen.getByRole("checkbox")).not.toBeChecked();
  });
  it.each(["loading", "stale", "forbidden", "unavailable"] as const)("hides recorded evidence and mutations when %s", state => {
    render(<SingleTestRecoveryPanel {...props({ state, value: { ...value, status: "complete", completion: { receipt_id: "private-receipt", outcome: "cancelled" } } })} />);
    expect(screen.queryByText(/private-receipt/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Request cleanup recovery" })).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(/unavailable|Loading|Refresh|permission/i);
  });
  it.each(["queued", "pending", "repair_required"])("does not create a new recovery for %s", status => {
    render(<SingleTestRecoveryPanel {...props({ value: { ...value, status } })} />);
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(screen.getByText(/pending|attention|queued/i)).toBeInTheDocument();
    expect(screen.queryByText("Cleanup complete.")).not.toBeInTheDocument();
  });
  it("displays verified cleanup separately from the stored product outcome", () => {
    render(<SingleTestRecoveryPanel {...props({ value: { ...value, status: "complete", completion: { receipt_id: runID, outcome: "needs_human" } } })} />);
    expect(screen.getByText("Cleanup complete.")).toBeInTheDocument();
    expect(screen.getByText("Recorded run outcome: needs_human")).toBeInTheDocument();
    expect(screen.getByText(/does not mean the security issue was remediated/)).toBeInTheDocument();
  });
  it("does not display complete without a completion receipt", () => {
    render(<SingleTestRecoveryPanel {...props({ value: { ...value, status: "complete" } })} />);
    expect(screen.queryByText("Cleanup complete.")).not.toBeInTheDocument();
    expect(screen.getByText(/unavailable/i)).toBeInTheDocument();
  });
  it.each([{ run_id: "pid_78000004-0000-4000-8000-000000000004" }, { parent_version: 8 }])("rejects run/version drift", drift => {
    render(<SingleTestRecoveryPanel {...props({ value: { ...value, ...drift } })} />);
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh recovery status" })).toBeInTheDocument();
  });
  it("removes write actions on permission loss", async () => {
    const p = props(); const mounted = render(<SingleTestRecoveryPanel {...p} />);
    await userEvent.click(screen.getByRole("checkbox"));
    mounted.rerender(<SingleTestRecoveryPanel {...p} canManage={false} />);
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(p.onRequest).not.toHaveBeenCalled();
  });
  it("retries the retained operation without constructing a new request", async () => {
    const p = props({ canRetry: true, blocked: true }); render(<SingleTestRecoveryPanel {...p} />);
    expect(screen.getByRole("status")).toHaveTextContent(/outcome is unknown/i);
    expect(screen.queryByText("Cleanup recovery has not been requested.")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry retained cleanup request" }));
    expect(p.onRetry).toHaveBeenCalledOnce();
    expect(p.onRequest).not.toHaveBeenCalled();
  });
});
