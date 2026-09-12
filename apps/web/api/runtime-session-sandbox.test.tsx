import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { decodeRuntimeSessionEvent, decodeRuntimeSessionEventPage } from "./runtime-session-decoders";
import { RuntimeSessionEventRow } from "../../../app/features/sessions/RuntimeSessionEventRow";
import { RuntimeSessionEvidence } from "../../../app/features/sessions/RuntimeSessionEvidence";

const session = "pid_10000001-0000-4000-8000-000000000001";
const agent = "pid_10000002-0000-4000-8000-000000000002";
const sensor = "pid_10000003-0000-4000-8000-000000000003";
const event = { id: session, session_id: session, agent_id: agent, class: "runtime", action: "exec", label: "Process executed", evidence_id: session, source: "tetragon", confidence: "strong", at: "2026-09-09T10:00:00Z", projected_at: "2026-09-09T10:00:01Z" };
const bound = { ...event, sandbox_id: "sandbox-blue", sandbox_source_sensor_id: sensor };

describe("source-qualified sandbox API boundary", () => {
  it.each(["exact", "strong"])("retains %s binding without rewriting the source or confidence", confidence => {
    const value = { ...bound, confidence };
    expect(decodeRuntimeSessionEvent(value)).toEqual(value);
    expect(decodeRuntimeSessionEventPage({ items: [value], page_info: { next_cursor: null, has_more: false } }).items[0]).toEqual(value);
  });
  it("keeps historical and unknown sandbox identity absent", () => {
    expect(decodeRuntimeSessionEvent(event)).toEqual(event);
    const unknown = { ...event, confidence: "probable", session_id: null, agent_id: null };
    expect(decodeRuntimeSessionEvent(unknown)).toEqual(unknown);
  });
  it.each([
    { sandbox_source_sensor_id: undefined }, { sandbox_source_sensor_id: null }, { sandbox_source_sensor_id: "otlp" },
    { sandbox_id: undefined }, { sandbox_id: null }, { sandbox_id: "" }, { sandbox_id: 3 },
    { sandbox_id: "é".repeat(129) }, { sandbox_id: "\u0085blue" }, { sandbox_id: "blue\u00a0" },
    { sandbox_id: "blue\nother" }, { sandbox_id: "blue\rother" }, { sandbox_id: "blue\u0000other" }, { sandbox_id: "\ud800" },
    { confidence: "probable", session_id: null, agent_id: null },
    { confidence: "unattributed", session_id: null, agent_id: null }, { agent_id: session },
    { extra_sandbox: "not-allowed" },
  ])("rejects malformed or ambiguous binding %j", override => {
    expect(() => decodeRuntimeSessionEvent({ ...bound, ...override })).toThrow("schema mismatch");
  });
  it("accepts the byte boundary without trimming or rewriting sandbox values", () => {
    for (const sandbox_id of ["é".repeat(128), "\ufeffblue"]) {
      const value = { ...bound, sandbox_id };
      expect(decodeRuntimeSessionEvent(value)).toEqual(value);
    }
  });
  it.each([9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288])("rejects Go whitespace U+%i at either edge", code => {
    const space = String.fromCodePoint(code);
    for (const sandbox_id of [space + "blue", "blue" + space]) expect(() => decodeRuntimeSessionEvent({ ...bound, sandbox_id })).toThrow("schema mismatch");
  });
  it("renders the sandbox and sensor with Strong confidence in the timeline", () => {
    render(<ol><RuntimeSessionEventRow event={decodeRuntimeSessionEvent(bound)} /></ol>);
    expect(screen.getByText(/Sandbox: sandbox-blue/)).toBeVisible();
    expect(screen.getByText(new RegExp(`Sandbox source sensor: ${sensor}`))).toBeVisible();
    expect(screen.getByText("Strong")).toBeVisible();
    expect(screen.queryByText("Exact")).not.toBeInTheDocument();
  });
  it("shows the same retained binding in canonical evidence", async () => {
    render(<RuntimeSessionEvidence target={{ investigationID: session, eventID: session, evidenceID: session }} api={{ get: async () => decodeRuntimeSessionEvent(bound) }} />);
    expect(await screen.findByText("sandbox-blue")).toBeVisible();
    expect(screen.getByText(sensor)).toBeVisible();
    expect(screen.getByText("Strong")).toBeVisible();
  });
  it("doesn't invent sandbox identity for a historical event", () => {
    render(<ol><RuntimeSessionEventRow event={decodeRuntimeSessionEvent(event)} /></ol>);
    expect(screen.getByText("Sandbox: Unknown (not recorded)")).toBeVisible();
    expect(screen.queryByText(/Sandbox source sensor:/)).not.toBeInTheDocument();
  });
  it("retains nanosecond order and visible times for precise events in one millisecond", () => {
    // IDs deliberately sort opposite to time. Millisecond coercion would reject
    // this valid page or reverse its chronology at the API boundary.
    const earlier = { ...bound, id: sensor, at: "2026-09-09T10:00:00.123456788Z" };
    const later = { ...bound, id: agent, at: "2026-09-09T10:00:00.123456789Z" };
    const page = { items: [earlier, later], page_info: { next_cursor: null, has_more: false } };
    const decoded = decodeRuntimeSessionEventPage(page);
    expect(decoded.items).toEqual([earlier, later]);
    expect(() => decodeRuntimeSessionEventPage({ ...page, items: [later, earlier] })).toThrow("schema mismatch");
    render(<ol>{decoded.items.map(item => <RuntimeSessionEventRow key={item.id} event={item} />)}</ol>);
    expect(screen.getByText(earlier.at)).toHaveAttribute("datetime", earlier.at);
    expect(screen.getByText(later.at)).toHaveAttribute("datetime", later.at);
    const rows = screen.getAllByRole("listitem");
    expect(rows[0]).toHaveTextContent(earlier.at);
    expect(rows[1]).toHaveTextContent(later.at);
    expect(screen.getAllByText("Strong")).toHaveLength(2);
    expect(screen.queryByText("Exact")).not.toBeInTheDocument();
  });
});
