import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { APIProvider } from "../../api/APIProvider";
import { DeviceFleet } from "./DeviceFleet";
import { createAPIClient } from "../../../apps/web/api/client";
import { createFleetAPI, decodeDetail, decodeFleet, type EndpointFleetAPI } from "../../../apps/web/api/endpoint-fleet";
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
    publish: vi.fn(),
    rotate: vi.fn(),
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
  const table = screen.getByRole("table");
  expect(within(table).getAllByRole("columnheader").map((header) => header.textContent)).toEqual([
    "Device", "Cohort", "Connection", "Policy",
  ]);
  expect(within(table).getByRole("row", { name: new RegExp(device.id) })).toHaveAccessibleName(
    [device.id, device.cohort, device.connection, "No current acknowledgment"].join(" "),
  );
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

const organizationID = "pid_00000000-0000-4000-8000-000000000010";
const workspaceID = "pid_00000000-0000-4000-8000-000000000020";
const environmentID = "pid_00000000-0000-4000-8000-000000000030";
const scope = [organizationID, workspaceID, environmentID].join("/");
const replacementID = "pid_00000000-0000-4000-8000-000000000031";
function policyEnvelope(boundDevice = device.id) {
  return {
    payload: btoa(
      JSON.stringify({
        audience: "zasp.endpoint-policy.v2",
        mode: "monitor",
        revision: 8,
        binding: {
          organization_id: organizationID,
          workspace_id: workspaceID,
          environment_id: environmentID,
          device_id: boundDevice,
          credential_generation: device.credential_generation,
        },
      }),
    ),
    signature: btoa("s".repeat(64)),
  };
}

it("publishes only the selected device's signed envelope, rotates its credential and reloads both receipts through the product client", async () => {
  const user = userEvent.setup(),
    writes: Array<{ path: string; method: string; body: unknown; headers: Headers }> = [];
  const envelope = policyEnvelope(),
    key = btoa("k".repeat(32));
  let state = { ...device },
    reads = 0;
  const client = createAPIClient({
    getCSRFToken: () => "c".repeat(32),
    getExpectedScope: () => scope,
    fetch: async (req) => {
      const path = new URL(req.url).pathname;
      if (req.method === "GET") {
        expect(path).toBe("/api/v1/devices/" + device.id);
        reads++;
      } else {
        writes.push({ path, method: req.method, body: await req.json(), headers: req.headers });
        state =
          req.method === "PUT"
            ? { ...state, version: 3, policy_revision: 8 }
            : {
                ...state,
                version: 4,
                state: "pending",
                credential_generation: 2,
                connection: "never_seen",
                acknowledged: false,
              };
      }
      return Response.json(state, { headers: { "Cache-Control": "no-store" } });
    },
  });
  render(
    <APIProvider>
      <DeviceFleet
        api={createFleetAPI(client)}
        initialID={device.id}
        scope={scope}
        canWrite
        fresh
        onReauthenticate={() => {}}
      />
    </APIProvider>,
  );
  await user.click(await screen.findByRole("button", { name: "Publish signed policy" }));
  const upload = screen.getByLabelText("Signed policy envelope");
  await user.upload(
    upload,
    new File([JSON.stringify(policyEnvelope(replacementID))], "other.json", { type: "application/json" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent("Choose a signed policy");
  expect(writes).toHaveLength(0);
  await user.upload(
    upload,
    new File([JSON.stringify(envelope)], "approved.json", { type: "application/json" }),
  );
  await user.click(await screen.findByRole("button", { name: "Publish revision 8" }));
  expect(await screen.findByText("8 / 6")).toBeVisible();
  expect(screen.getByText(/revision 8 assigned/i)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Rotate device credential" }));
  await user.type(screen.getByLabelText("Replacement endpoint credential ID"), replacementID);
  await user.type(screen.getByLabelText("Replacement device public key"), key);
  await user.click(screen.getByRole("button", { name: "Confirm credential rotation" }));
  expect(await screen.findByText("pending")).toBeVisible();
  expect(screen.getByText(/generation 2 assigned/i)).toBeVisible();
  expect(reads).toBe(3);
  expect(writes.map(({ path, method, body }) => ({ path, method, body }))).toEqual([
    { path: "/api/v1/devices/" + device.id + "/policy-bundle", method: "PUT", body: envelope },
    {
      path: "/api/v1/devices/" + device.id + "/credential-rotations",
      method: "POST",
      body: { credential_id: replacementID, device_public_key: key },
    },
  ]);
  for (const [index, write] of writes.entries()) {
    expect(write.headers.get("If-Match")).toBe(`"${index + 2}"`);
    expect(write.headers.get("X-CSRF-Token")).toBe("c".repeat(32));
    expect(write.headers.get("X-Zasp-Expected-Scope")).toBe(scope);
    expect(write.headers.get("Idempotency-Key")).toBeTruthy();
  }
  expect(writes[0].headers.get("Idempotency-Key")).not.toBe(writes[1].headers.get("Idempotency-Key"));
});

it("keeps an uncertain rotation retry bound to the original request and refuses writes while freshness is expired", async () => {
  const user = userEvent.setup(),
    api = fixture(),
    reauthenticate = vi.fn();
  const attempt = vi.mocked(api.rotate).mockRejectedValue(new Error("no reply"));
  const panel = (fresh: boolean) => (
    <APIProvider>
      <DeviceFleet
        api={api}
        initialID={device.id}
        scope={scope}
        canWrite
        fresh={fresh}
        onReauthenticate={reauthenticate}
      />
    </APIProvider>
  );
  const rendered = render(panel(false));
  await user.click(await screen.findByRole("button", { name: "Rotate device credential" }));
  expect(reauthenticate).toHaveBeenCalledOnce();
  expect(screen.queryByLabelText("Replacement endpoint credential ID")).toBeNull();
  rendered.rerender(panel(true));
  await user.click(screen.getByRole("button", { name: "Rotate device credential" }));
  await user.type(screen.getByLabelText("Replacement endpoint credential ID"), replacementID);
  await user.type(screen.getByLabelText("Replacement device public key"), btoa("k".repeat(32)));
  await user.click(screen.getByRole("button", { name: "Confirm credential rotation" }));
  expect(await screen.findByText(/could not be confirmed/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Confirm credential rotation" }));
  expect(attempt).toHaveBeenCalledTimes(2);
  expect(attempt.mock.calls[0][2]).toBe(attempt.mock.calls[1][2]);
});

it("rejects malformed mutation receipts and hides device writes from a reader", async () => {
  const client = createAPIClient({
    getCSRFToken: () => "c".repeat(32),
    getExpectedScope: () => scope,
    fetch: async () => Response.json(device, { headers: { "Cache-Control": "no-store" } }),
  });
  const api = createFleetAPI(client);
  await expect(api.publish(device, policyEnvelope(), 8, "test-key")).rejects.toThrow();
  await expect(
    api.rotate(device, { credential_id: replacementID, device_public_key: btoa("a".repeat(32)) }, "test-key"),
  ).rejects.toThrow();
  render(
    <APIProvider>
      <DeviceFleet api={fixture()} initialID={device.id} canWrite={false} fresh onReauthenticate={() => {}} />
    </APIProvider>,
  );
  expect(await screen.findByText("7 / 6")).toBeVisible();
  for (const name of ["Publish signed policy", "Rotate device credential", "Retire device"])
    expect(screen.queryByRole("button", { name })).toBeNull();
});
