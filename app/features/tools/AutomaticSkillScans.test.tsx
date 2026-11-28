import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import { decodeDetail } from "../../../apps/web/api/endpoint-fleet";
import { decodeAddonVersion } from "../../../apps/web/api/addon-reviews";
import { APIProvider } from "../../api/APIProvider";
import { AutomaticSkillScans } from "./AutomaticSkillScans";

const device = "pid_00000000-0000-4000-8000-000000000001";
const environment = "pid_00000000-0000-4000-8000-000000000002";
const version = "pid_00000000-0000-4000-8000-000000000003";
const digest = "sha256:" + "c".repeat(64);
const row = { id: device, cohort: "Developer", state: "active", connection: "online", last_seen: null, version: 1,
  credential_generation: 1, acknowledged: false, queued_receipts: 0, dropped_receipts: 0, policy_revision: 0, reported_policy_revision: 0 };
const complete = { installation_id: "1".repeat(64), manifest_digest: digest, skill_version_id: version,
  skill_scan: { ruleset: "zasp-static.v2", rule_counts: { "instruction.override": 2 }, skipped_count: 0 } };
const partial = { installation_id: "2".repeat(64), skill_scan: { ruleset: "zasp-static.v2", rule_counts: {}, skipped_count: 3 } };
const legacy = { installation_id: "3".repeat(64), manifest_digest: digest };

function detail(installations: unknown[]) {
  return { ...row, inventory_partitions: 1, reported_adapter: "unknown", observation_count: 0, recent_observations: [], partition_summaries: [{
    partition_id: "4".repeat(64), generation: 2, complete: false, observed_count: installations.length, observed_installations: installations,
    last_complete_generation: null, confirmed_count: null, confirmed_installations: [],
  }] };
}
function show(fetchJSON: (path: string) => unknown) {
  const client = createAPIClient({ fetch: async request => {
    const body = fetchJSON(new URL(request.url).pathname);
    return new Response(JSON.stringify(body), { status: body ? 200 : 503, headers: { "Content-Type": "application/json" } });
  } });
  render(<APIProvider client={client}><AutomaticSkillScans environment={environment} /></APIProvider>);
}
const empty = { items: [], next_after_id: null, counts: { enrolled: 0, expected: 0, acknowledged: 0, online: 0 } };

it("separates enrolled devices, complete scans, partial scans and inventory without a scan", async () => {
  show(path => path === "/api/v1/devices" ? { ...empty, items: [row], counts: { enrolled: 1, expected: 2, acknowledged: 0, online: 1 } }
    : path === "/api/v1/devices/" + device ? detail([complete, partial, legacy]) : null);
  expect(await screen.findByText("1 device enrolled · 1 online")).toBeVisible();
  const completeRow = await screen.findByRole("row", { name: /Complete/ });
  expect(within(completeRow).getByText("Instructions contain an override directive")).toBeVisible();
  expect(within(completeRow).getByRole("link", { name: "Open version review" })).toHaveAttribute("href", `/inventory/tools?addon=${version}&environment_id=${environment}`);
  expect(screen.getByRole("row", { name: /Partial · 3 skipped/ })).toHaveTextContent("0 reported");
  expect(screen.getByRole("row", { name: /No scan reported/ })).toHaveTextContent("Unknown");
  expect(screen.getAllByRole("link", { name: "Open version review" })).toHaveLength(1);
  expect(screen.getByText(/discovery was incomplete/)).toBeVisible();
});

it("shows enrollment instructions only after a confirmed empty fleet read", async () => {
  let failed = true;
  show(() => failed ? null : empty);
  expect(await screen.findByRole("alert")).toHaveTextContent("Device coverage is unavailable");
  expect(screen.queryByText(/0 devices enrolled/)).toBeNull();
  failed = false;
  await userEvent.click(screen.getByRole("button", { name: "Retry device coverage" }));
  expect(await screen.findByText("0 devices enrolled · 0 online")).toBeVisible();
  expect(screen.getByRole("link", { name: "enroll a device" })).toHaveAttribute("href", "/integrations/sensors?tab=devices");
  expect(screen.queryByRole("table")).toBeNull();
});

it("rejects malformed endpoint evidence and unsupported review links", () => {
  for (const installation of [
    { ...partial, skill_version_id: version }, { ...legacy, skill_version_id: version },
    { ...complete, skill_scan: { ...complete.skill_scan, rule_counts: { "arbitrary.rule": 2 } } },
    { ...complete, skill_scan: { ...complete.skill_scan, rule_counts: { "instruction.override": 1025 } } },
    { ...partial, skill_scan: { ...partial.skill_scan, skipped_count: 1025 } },
  ]) expect(() => decodeDetail(detail([installation]), device)).toThrow();
  expect(decodeAddonVersion({ id: version, manifest_digest: digest, ruleset: "zasp-static.v2", origin: "endpoint", provenance: "reported",
    findings: [], review_state: "pending", revision: 1 }).origin).toBe("endpoint");
});
