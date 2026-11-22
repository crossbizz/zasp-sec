import { render, screen } from "@testing-library/react";
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
