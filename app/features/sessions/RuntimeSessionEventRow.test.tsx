import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { RuntimeSessionEvent } from "../../../apps/web/api/generated";
import { RuntimeSessionEventRow } from "./RuntimeSessionEventRow";

const id = "pid_10000001-0000-4000-8000-000000000001";
const event: RuntimeSessionEvent = { id, session_id: null, agent_id: null, class: "runtime", action: "exec", label: "Canonical event", evidence_id: id, source: "tetragon", confidence: "unattributed", at: "2026-09-09T10:00:00Z", projected_at: "2026-09-09T10:00:01Z" };

describe("runtime session event rows", () => {
  it.each<[RuntimeSessionEvent["class"], RuntimeSessionEvent["action"], RuntimeSessionEvent["source"], string]>([
    ["tool", "invoke", "otlp", "Tool invocation"], ["runtime", "exec", "tetragon", "Process execution"],
    ["network", "connect", "tetragon", "Network connection"], ["file", "read", "tetragon", "File read"],
    ["credential", "use", "otlp", "Credential use observation"], ["policy", "block", "otlp", "Policy block observation"],
  ])("renders %s with a deterministic label and exact evidence link", async (kind, action, source, label) => {
    const value = { ...event, class: kind, action, source }, onEvidence = vi.fn();
    render(<ol><RuntimeSessionEventRow event={value} onEvidence={onEvidence} /></ol>);
    expect(screen.getByText(label)).toBeVisible();
    const link = screen.getByRole("link", { name: `Open evidence ${id}` });
    expect(link).toHaveAttribute("href", `#runtime-evidence-${id}`);
    await userEvent.click(link);
    expect(onEvidence).toHaveBeenCalledExactlyOnceWith(value);
    expect(screen.getByRole("listitem")).toHaveTextContent(source);
  });
  it("visibly distinguishes Probable from Exact without assigning unknown evidence", () => {
    render(<ol><RuntimeSessionEventRow event={{ ...event, confidence: "probable" }} /><RuntimeSessionEventRow event={{ ...event, id: "pid_10000002-0000-4000-8000-000000000002", confidence: "exact", session_id: id, agent_id: id }} /></ol>);
    expect(screen.getByText("probable")).toHaveClass("badge--warning");
    expect(screen.getByText("exact")).toHaveClass("badge--success");
  });
});
