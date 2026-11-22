import React from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { decodeAddonInstallationPage } from "../../../apps/web/api/addon-installations";
import { APIProvider } from "../../api/APIProvider";
import { AddonReviews, addonFromSearch } from "./AddonReviews";
import {
  decodeAddonVersion,
  type AddonVersion,
  type AddonReviewAPI,
} from "../../../apps/web/api/addon-reviews";

const row: AddonVersion = {
  id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
  manifest_digest: "sha256:" + "3".repeat(64),
  origin: "local",
  provenance: "reported",
  ruleset: "zasp-static.v1",
  findings: [],
  review_state: "pending",
  revision: 1,
};
function api() {
  let version = row;
  return {
    list: vi.fn(async () => ({ items: [version], next_cursor: null })),
    get: vi.fn(async () => version),
    ciOrigin: vi.fn(async () => null),
    installations: vi.fn(async () => ({ items: [], next_cursor: null })),
    review: vi.fn<AddonReviewAPI["review"]>(async (old, state) => {
      version = { ...old, review_state: state, revision: old.revision + 1 };
      return version;
    }),
  };
}
describe("private add-on review", () => {
  it("shows what a reported version proves and requires an explicit review confirmation", async () => {
    const user = userEvent.setup(),
      registry = api();
    render(
      <APIProvider>
        <AddonReviews initialID={row.id} api={registry} canReview />
      </APIProvider>,
    );
    expect(await screen.findByText(row.manifest_digest)).toBeVisible();
    expect(screen.getByText(/reported by submitter/)).toBeVisible();
    expect(screen.getByText("Unknown")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Approve version" }));
    expect(registry.review).not.toHaveBeenCalled();
    await user.click(
      within(screen.getByRole("region", { name: "Confirm review" })).getByText(
        "Confirm decision",
      ),
    );
    expect(await screen.findByText("approved · revision 2")).toBeVisible();
    expect(registry.review).toHaveBeenCalledWith(
      row,
      "approved",
      expect.any(String),
      expect.any(AbortSignal),
    );
  });
  it("lets a read-only reviewer navigate from the list without exposing a mutation", async () => {
    const user = userEvent.setup(),
      registry = api();
    render(
      <APIProvider>
        <AddonReviews api={registry} canReview={false} />
      </APIProvider>,
    );
    await user.click(
      await screen.findByRole("button", {
        name: row.manifest_digest.slice(0, 24) + "…",
      }),
    );
    expect(
      await screen.findByText("No findings from this scan."),
    ).toBeVisible();
    expect(screen.queryByText("Approve version")).toBeNull();
    await user.click(screen.getByRole("button", { name: "All versions" }));
    expect(await screen.findByRole("table")).toBeVisible();
  });
  it("shows retained matching installations and the review scope after revocation", async () => {
    const device = "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const entry = {
      device_id: device,
      cohort: "mac-pilot",
      device_state: "active" as const,
      partition_id: "a".repeat(64),
      installation_id: "b".repeat(64),
      observation: "last_complete" as const,
      generation: 2,
      latest_generation: 3,
      reported_at: "2026-02-01T10:00:00Z",
      latest_reported_at: "2026-02-02T10:00:00Z",
    };
    const registry = {
      ...api(),
      get: vi.fn(async () => ({ ...row, review_state: "revoked" as const })),
      installations: vi.fn(async () => ({ items: [entry], next_cursor: null })),
    };
    render(
      <APIProvider>
        <AddonReviews api={registry} initialID={row.id} canReview={false} />
      </APIProvider>,
    );
    const area = await screen.findByRole("region", {
      name: "Matching device installations",
    });
    expect(
      await within(area).findByRole("link", { name: device }),
    ).toHaveAttribute("href", "/integrations/sensors?device=" + device);
    expect(
      within(area).getByText(/latest snapshot 3 was partial/i),
    ).toBeVisible();
    expect(
      within(area).getByText(
        /removal and policy acknowledgment require separate evidence/i,
      ),
    ).toBeVisible();
    expect(() =>
      decodeAddonInstallationPage({
        items: [{ ...entry, generation: 4 }],
        next_cursor: null,
      }),
    ).toThrow();
  });
  it("binds response identity and rejects unrecognized attribution and decision data", () => {
    expect(decodeAddonVersion(row, row.id)).toEqual(row);
    for (const variant of [
      { id: "invalid" },
      { provenance: "verified" },
      { manifest_digest: "raw path" },
      { review_state: "safe" },
      { findings: [{ rule_id: "a path", count: 1 }] },
    ]) {
      expect(() =>
        decodeAddonVersion({ ...row, ...variant }, row.id),
      ).toThrow();
    }
    expect(addonFromSearch("?addon=" + row.id)).toBe(row.id);
    expect(addonFromSearch("?addon=" + row.id + "&addon=" + row.id)).toBe("");
  });
});
