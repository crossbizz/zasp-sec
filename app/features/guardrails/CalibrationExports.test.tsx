import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import { CalibrationExports } from "./CalibrationExports";

const state = vi.hoisted(() => ({
  client: {} as ReturnType<typeof createAPIClient>,
  allowed: true,
  fresh: true,
  reauthenticate: vi.fn(),
}));
const ids = [1, 2, 3, 4, 5].map(i => `pid_0000000${i}-0000-4000-8000-00000000000${i}`);
vi.mock("../../auth/SessionProvider", () => ({
  useOptionalSession: () => ({
    status: "authenticated", organizationID: ids[0], workspaceID: ids[1], environmentID: ids[2],
    hasCapability: () => state.allowed, isFreshAuthenticated: state.fresh, reauthenticate: state.reauthenticate,
  }),
}));
vi.mock("../../api/APIProvider", () => ({ useAPI: () => ({ client: state.client, queryGeneration: 0 }) }));

const job = () => ({
  id: ids[3], environment_id: ids[2], status: "ready", samples: 1,
  requested_at: new Date().toISOString(), expires_at: new Date(Date.now() + 600_000).toISOString(),
});
const json = (value: unknown) => new Response(JSON.stringify(value), {
  headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
});
beforeEach(() => { state.fresh = true; state.allowed = true; });

it("binds the export to the signed-in scope and rejects another environment's result", async () => {
  const user = userEvent.setup();
  const requests: Request[] = [];
  state.client = createAPIClient({ getCSRFToken: () => "csrf", fetch: async request => {
    requests.push(request);
    return json({ ...job(), environment_id: ids[4] });
  } });
  render(<CalibrationExports />);
  await user.click(screen.getByRole("button", { name: "Create export" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Could not confirm");
  await user.click(screen.getByRole("button", { name: "Create export" }));
  expect(requests).toHaveLength(2);
  expect(requests[0].headers.get("Idempotency-Key")).toBeTruthy();
  expect(requests[1].headers.get("Idempotency-Key")).toBe(requests[0].headers.get("Idempotency-Key"));
  expect(requests[0].headers.get("X-Zasp-Expected-Scope")).toBe(ids.slice(0, 3).join("/"));
  expect(requests[0].headers.get("X-CSRF-Token")).toBe("csrf");
  expect(screen.queryByText("Get download grant")).toBeNull();
});

it("exposes the one-use grant only after a user requests it and refuses a substituted file", async () => {
  const user = userEvent.setup();
  const token = "a".repeat(64);
  state.client = createAPIClient({ fetch: async request => {
    const path = new URL(request.url).pathname;
    if (path.endsWith("/exports")) return json(job());
    if (path.endsWith("/download-grants")) return json({ grant: token, expires_at: job().expires_at });
    expect(await request.json()).toEqual({ grant: token });
    return json({ environment_id: ids[4], filename: "another-file", sha256: token, jsonl: "{}\n" });
  } });
  render(<CalibrationExports />);
  await user.click(screen.getByRole("button", { name: "Create export" }));
  await user.click(await screen.findByRole("button", { name: "Get download grant" }));
  await user.click(screen.getByText("Use this grant with zaspctl"));
  expect(screen.getByLabelText("Single-use grant")).toHaveValue(token);
  await user.click(screen.getByRole("button", { name: "Download JSONL" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Could not confirm");
  expect(screen.queryByLabelText("Single-use grant")).toBeNull();
});

it("requires export access and asks for fresh authentication", async () => {
  state.allowed = false;
  const view = render(<CalibrationExports />);
  expect(screen.queryByRole("heading", { name: "Export calibration labels" })).toBeNull();
  state.allowed = true; state.fresh = false;
  view.rerender(<CalibrationExports />);
  await userEvent.click(screen.getByRole("button", { name: "Verify identity to export" }));
  expect(state.reauthenticate).toHaveBeenCalled();
  expect(screen.queryByRole("button", { name: "Create export" })).toBeNull();
});
