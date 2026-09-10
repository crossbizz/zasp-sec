import { act, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import type { RuntimeSessionEvent } from "../../../apps/web/api/generated";
import { createRuntimeSessionEvidenceAPI, RuntimeSessionEvidence, type RuntimeSessionEvidenceAPI } from "./RuntimeSessionEvidence";

const id = "pid_10000001-0000-4000-8000-000000000001", evidenceID = "pid_10000002-0000-4000-8000-000000000002";
const event: RuntimeSessionEvent = { id, session_id: null, agent_id: null, class: "credential", action: "use", label: "Observed credential use", evidence_id: evidenceID, source: "otlp", confidence: "unattributed", at: "2026-09-09T10:00:00Z", projected_at: "2026-09-09T10:00:01Z" };
const target = { investigationID: "unattributed", eventID: id, evidenceID };

describe("runtime evidence metadata", () => {
  it("uses the generated exact-event API and binds the returned evidence reference", async () => {
    const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => { requests.push(request); return new Response(JSON.stringify(event), { headers: { "content-type": "application/json" } }); } });
    const api = createRuntimeSessionEvidenceAPI(client), signal = new AbortController().signal;
    expect(await api.get(target, signal)).toEqual(event);
    expect(new URL(requests[0].url).pathname).toBe(`/api/v1/sessions/unattributed/events/${id}`);
    await expect(api.get({ ...target, evidenceID: id }, signal)).rejects.toThrow();
    await expect(api.get({ ...target, eventID: evidenceID }, signal)).rejects.toThrow();
    await expect(api.get({ ...target, investigationID: id }, signal)).rejects.toThrow();
  });

  it("shows exact canonical metadata without raw content or enforcement claims", async () => {
    render(<RuntimeSessionEvidence target={target} api={{ get: async () => event }} />);
    expect(await screen.findByText("Observed credential use")).toBeVisible();
    expect(screen.getByText(/Raw archive content is not included/)).toBeVisible();
    expect(screen.getByText(/not proof of credential ownership or policy enforcement/)).toBeVisible();
    expect(screen.getByText("Unattributed")).toBeVisible();
    expect(screen.getByText(evidenceID)).toBeVisible();
    expect(screen.queryByRole("link", { name: /Download/ })).not.toBeInTheDocument();
  });

  it.each(["provider", "evidence", "event", "investigation"])("rejects %s failure without displaying stale evidence", async fault => {
    const api: RuntimeSessionEvidenceAPI = { get: async () => {
      if (fault === "provider") throw new Error("secret upstream response");
      return fault === "evidence" ? { ...event, evidence_id: id } : fault === "event" ? { ...event, id: evidenceID } : { ...event, session_id: id, agent_id: id, confidence: "exact" };
    } };
    render(<RuntimeSessionEvidence target={target} api={api} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Evidence metadata could not be loaded");
    expect(screen.queryByText("Observed credential use")).not.toBeInTheDocument();
    expect(screen.queryByText(/secret upstream/)).not.toBeInTheDocument();
  });

  it("cancels an old authorized client and fences its late response", async () => {
    let finish!: (value: RuntimeSessionEvent) => void;
    const get = vi.fn<RuntimeSessionEvidenceAPI["get"]>(() => new Promise(resolve => { finish = resolve; }));
    const view = render(<RuntimeSessionEvidence target={target} api={{ get }} />);
    await waitFor(() => expect(get).toHaveBeenCalledTimes(1));
    view.rerender(<RuntimeSessionEvidence target={target} api={{ get: async () => { throw new Error("not authorized in new scope"); } }} />);
    await screen.findByRole("alert");
    expect(get.mock.calls[0][1].aborted).toBe(true);
    await act(async () => finish(event));
    expect(screen.queryByText("Observed credential use")).not.toBeInTheDocument();
  });
});
