import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import { BrowserProfiles, decodeBrowserProfile } from "./BrowserProfiles";

const id = "pid_00000000-0000-4000-8000-000000000001";
const environment = "pid_00000000-0000-4000-8000-000000000002";
const token = { id, name: "Pilot", workspaceId: "w", environmentId: environment, permissions: ["report_browser_usage"], version: 1,
  expiresAt: "2026-12-01T00:00:00Z", lastUsedAt: null, revokedAt: null };
const profile = { credential_id: id, environment_id: environment, origins: ["https://claude.ai"], state: "awaiting_profile",
  expires_at: token.expiresAt, last_sync: null, last_observation: null, observations: [] };
it("rejects a profile from another Environment and an observation outside the profile allowlist", () => {
  expect(() => decodeBrowserProfile({ ...profile, environment_id: "other" }, id, environment)).toThrow();
  expect(() => decodeBrowserProfile({ ...profile, observations: [{ day: "2026-11-01", origin: "https://chatgpt.com" }] }, id, environment)).toThrow();
});
it("registers the selected profile and shows a pending heartbeat", async () => {
  const user = userEvent.setup();
  const get = vi.fn().mockResolvedValue({ response: new Response(null, { status: 404 }) });
  const put = vi.fn().mockResolvedValue({ data: profile, response: new Response() });
  render(<BrowserProfiles client={{ GET: get, PUT: put } as unknown as APIClient} tokens={[token]} environment={environment} fresh />);
  const key = await screen.findByLabelText("Profile public key");
  await user.type(key, "B" + "a".repeat(86) + "=");
  await user.click(screen.getByLabelText("https://claude.ai"));
  await user.click(screen.getByRole("button", { name: "Register profile public key" }));
  expect(await screen.findByText("Awaiting the profile’s first heartbeat")).toBeInTheDocument();
  expect(put).toHaveBeenCalledWith("/api/v1/browser-profiles/{id}", expect.objectContaining({ params: { path: { id }, header: { "X-CSRF-Token": "" } }, body: { public_key: "B" + "a".repeat(86) + "=", origins: ["https://claude.ai"] } }));
});

it("resets loading on scope change and ignores a late response from the previous Environment", async () => {
  const other = "pid_00000000-0000-4000-8000-000000000009";
  type Reply = { data?: unknown; response: Response };
  let finishFirst: ((reply: Reply) => void) | undefined;
  let finishSecond: ((reply: Reply) => void) | undefined;
  const get = vi.fn()
    .mockImplementationOnce(() => new Promise<Reply>((resolve) => { finishFirst = resolve; }))
    .mockImplementationOnce(() => new Promise<Reply>((resolve) => { finishSecond = resolve; }));
  const client = { GET: get } as unknown as APIClient;
  const view = render(<BrowserProfiles client={client} tokens={[token]} environment={environment} fresh />);
  expect(screen.getByRole("button", { name: "Refresh profile status" })).toBeDisabled();
  view.rerender(<BrowserProfiles client={client} tokens={[{ ...token, environmentId: other }]} environment={other} fresh />);
  expect(get.mock.calls[0][1].signal.aborted).toBe(true);
  await act(async () => { finishSecond?.({ response: new Response(null, { status: 404 }) }); });
  expect(screen.getByLabelText("Profile public key")).toBeInTheDocument();
  await act(async () => { finishFirst?.({ data: profile, response: new Response() }); });
  expect(screen.getByLabelText("Profile public key")).toBeInTheDocument();
  expect(screen.queryByText("Awaiting the profile’s first heartbeat")).not.toBeInTheDocument();
});
