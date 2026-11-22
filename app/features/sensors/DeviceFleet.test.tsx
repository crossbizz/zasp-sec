import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { APIProvider } from "../../api/APIProvider";
import { DeviceFleet } from "./DeviceFleet";
import { decodeDetail, decodeFleet, type EndpointFleetAPI } from "../../../apps/web/api/endpoint-fleet";
import type { EndpointDetail } from "../../../apps/web/api/generated";

const device: EndpointDetail = {
  id: "pid_00000000-0000-4000-8000-000000000001",
  cohort: "Pilot",
  state: "active",
  version: 2,
  credential_generation: 1,
  last_seen: null,
  connection: "stale",
  policy_revision: 7,
  reported_policy_revision: 6,
  acknowledged: false,
  queued_receipts: 1,
  dropped_receipts: 0,
  inventory_partitions: 1,
  observation_count: 1,
  reported_adapter: "macos_claude_ticket",
  partition_summaries: [
    {
      partition_id: "a".repeat(64),
      generation: 2,
      complete: false,
      observed_count: 0,
      observed_installations: [],
      last_complete_generation: 1,
      confirmed_count: 1,
      confirmed_installations: [
        { installation_id: "b".repeat(64), manifest_digest: "sha256:" + "c".repeat(64) },
      ],
    },
  ],
  recent_observations: [
    {
      action_id: "d".repeat(64),
      session_ref: "e".repeat(64),
      credential_generation: 1,
      observed_at: "2026-01-01T00:00:00Z",
      policy_revision: 6,
      mode: "monitor",
      verdict: "continue",
      would_block: true,
      target_class: "outside_allowed_destination",
      skill_usage: "unknown",
      target_effect: "unknown",
      graph_evidence_id: "pid_00000000-0000-4000-8000-000000000011",
      graph_state: "pending",
    },
  ],
};
function fixture(): EndpointFleetAPI {
  let row = device;
  return {
    list: async () => ({
      items: [row],
      next_after_id: null,
      counts: { expected: 3, enrolled: 2, online: 1, acknowledged: 1 },
    }),
    get: async () => row,
    register: vi.fn(async () => row),
    retire: vi.fn(async () => {
      row = { ...row, state: "retired", connection: "retired", version: 3 };
      return row;
    }),
  };
}
it("distinguishes assigned fleet from current coverage and confirms retirement", async () => {
  const user = userEvent.setup(),
    api = fixture();
  render(
    <APIProvider>
      <DeviceFleet api={api} canWrite fresh onReauthenticate={() => {}} />
    </APIProvider>,
  );
  expect(await screen.findByText("3 assigned · 2 enrolled · 1 online · 1 acknowledged policy")).toBeVisible();
  await user.click(screen.getByRole("button", { name: device.id }));
  expect(await screen.findByText("7 / 6")).toBeVisible();
  expect(screen.getByText("macOS · Claude Code ticket hook")).toBeVisible();
  await user.click(screen.getByText(/Partial scan/));
  expect(screen.getByText("Last complete scan · generation 1")).toBeVisible();
  expect(screen.getByText("sha256:" + "c".repeat(64))).toBeVisible();
  await user.click(screen.getByText(/Would block in enforce mode/));
  expect(screen.getByText(/Awaiting projection/)).toBeVisible();
  expect(screen.getByText("e".repeat(64))).toBeVisible();
  expect(screen.getByText(/Skill use and target outcome are unknown/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Retire device" }));
  expect(api.retire).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Confirm retirement" }));
  expect(await screen.findByText("retired")).toBeVisible();
  expect(api.retire).toHaveBeenCalledWith(device, expect.any(String), expect.any(AbortSignal));
});
it("requires fresh browser authentication before registering a new device", async () => {
  const auth = vi.fn(),
    user = userEvent.setup(),
    api = fixture();
  render(
    <APIProvider>
      <DeviceFleet api={api} canWrite fresh={false} onReauthenticate={auth} />
    </APIProvider>,
  );
  await user.click(await screen.findByRole("button", { name: "Enroll pilot device" }));
  expect(auth).toHaveBeenCalledOnce();
  expect(api.register).not.toHaveBeenCalled();
});
it("refuses malformed fleet counts and cursor identities", () => {
  const sample = {
    items: [device],
    next_after_id: null,
    counts: { expected: 1, enrolled: 1, online: 0, acknowledged: 0 },
  };
  expect(decodeFleet(sample).counts).toEqual(sample.counts);
  expect(() => decodeFleet({ ...sample, counts: { ...sample.counts, expected: -1 } })).toThrow();
  expect(() => decodeFleet({ ...sample, next_after_id: "unexpected" })).toThrow();
});

it("validates bounded device evidence and preserves uncertainty", () => {
  expect(decodeDetail(device, device.id)).toEqual(device);
  expect(() => decodeDetail({ ...device, partition_summaries: [] }, device.id)).toThrow();
  expect(() =>
    decodeDetail(
      { ...device, recent_observations: [{ ...device.recent_observations[0], skill_usage: "executed" }] },
      device.id,
    ),
  ).toThrow();
  expect(() =>
    decodeDetail(
      {
        ...device,
        partition_summaries: [
          {
            ...device.partition_summaries[0],
            confirmed_installations: [{ installation_id: "/home/private/user" }],
          },
        ],
      },
      device.id,
    ),
  ).toThrow();
});

it("reads redacted pre-tool decisions and rejects raw paths in rule evidence", () => {
  const v2 = {
    ...device.recent_observations[0],
    adapter: "macos_codex_pretool_v2",
    reason_code: "mcp_tool_restricted",
    rule_id: "support-tools",
    tool_class: "mcp",
  };
  const entry = { ...device, reported_adapter: "macos_codex_pretool_v2", recent_observations: [v2] };
  expect(decodeDetail(entry, device.id).recent_observations[0]).toMatchObject(v2);
  expect(() => decodeDetail({ ...entry, reported_adapter: "unspecified_runtime" }, device.id)).toThrow();
  expect(() => decodeDetail({ ...entry, recent_observations: [{...v2, rule_id:"/home/person/file"}] }, device.id)).toThrow();
});
