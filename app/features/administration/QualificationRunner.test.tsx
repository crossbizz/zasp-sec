import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import type { AISettings } from "../../../apps/web/api/ai-controls";
import { QualificationRunner } from "./QualificationRunner";

it("runs a pinned job, follows its saved status and refreshes qualified models", async () => {
  const ids = [1, 2, 3, 4].map(n => `pid_0000000${n}-0000-4000-8000-00000000000${n}`);
  const expectedScope = ids.slice(0, 3).join("/");
  const refreshQualifications = vi.fn().mockResolvedValue(undefined);
  const row = { id: ids[3], environment_id: ids[2], provider: "zasp_vpc_slm", model: "local-profile", purpose: "indirect_injection_screen", requested_at: "2026-11-01T12:00:00Z" };
  const client = createAPIClient({ getCSRFToken: () => "session-csrf", fetch: async request => {
    expect(request.headers.get("X-Zasp-Expected-Scope")).toBe(expectedScope);
    if (request.method === "POST") {
      expect(request.headers.get("X-CSRF-Token")).toBe("session-csrf");
      expect(request.headers.get("Idempotency-Key")).toBeTruthy();
      expect(await request.json()).toEqual({ provider: row.provider, model: row.model, purpose: row.purpose });
    } else expect(new URL(request.url).pathname).toBe("/api/v1/ai/qualifications/runs/" + ids[3]);
    return new Response(JSON.stringify({ ...row, status: request.method === "POST" ? "queued" : "passed", finished_at: request.method === "POST" ? null : "2026-11-01T12:01:00Z" }), { headers: { "Content-Type": "application/json" } });
  } });
  const environment = { environment_id: ids[2], effective_mode: "zasp_vpc_slm", tier2_profile: "local-profile" } as AISettings["environment"];
  render(<QualificationRunner client={client} expectedScope={expectedScope} environment={environment} canEdit fresh refreshQualifications={refreshQualifications} />);
  await userEvent.click(screen.getByRole("button", { name: "Run qualification" }));
  expect(await screen.findByText(/Qualification queued/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Run qualification" })).toBeDisabled();
  expect(await screen.findByText(/Qualification passed/, {}, { timeout: 5000 })).toBeVisible();
  expect(refreshQualifications).toHaveBeenCalledOnce();
}, 10_000);
