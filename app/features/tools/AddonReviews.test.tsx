import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { decodeAddonInstallationPage } from "../../../apps/web/api/addon-installations";
import { APIProvider } from "../../api/APIProvider";
import { scopedAddonFromSearch, scanReceiptLink, addonVersionLink } from "../../domain/addon-links";
import { parseActivityLink } from "../../domain/activity-links";
import { createAPIClient } from "../../../apps/web/api/client";
import { AddonReviews, addonFromSearch } from "./AddonReviews";
import {
  decodeAddonScan,
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
    scan: vi.fn<AddonReviewAPI["scan"]>(),
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
  it("binds static references to the reviewed ruleset and exact version", async () => {
    const ref = { rule_id: "dependency.unpinned", rule_version: "zasp-static.v1", evidence_kind: "static_scan" as const,
      framework: "owasp_agentic_top10", edition: "2026", upstream_id: "ASI04", title: "Agentic Supply Chain Vulnerabilities" };
    const version = { ...row, findings: [{ rule_id: ref.rule_id, count: 2 }], framework_evidence: [ref] };
    const registry = { ...api(), get: vi.fn(async () => decodeAddonVersion(version, row.id)) };
    render(<APIProvider><AddonReviews initialID={row.id} api={registry} canReview={false} /></APIProvider>);
    const refs = await screen.findByRole("list", { name: "Framework references for dependency.unpinned" });
    expect(refs).toHaveTextContent("ASI04");
    expect(refs).toHaveTextContent("2026");
    expect(refs).toHaveTextContent("Static scan");
    expect(screen.getByText(row.manifest_digest)).toBeVisible();
    for (const invalid of [
      { ...ref, rule_version: "unreviewed" }, { ...ref, evidence_kind: "prevention" },
      { ...ref, rule_id: "script.network_access" },
    ]) {
      expect(() => decodeAddonVersion({ ...version, framework_evidence: [invalid] }, row.id)).toThrow();
    }
    expect(() => decodeAddonVersion({ ...version, framework_evidence: [ref, ref] })).toThrow();
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

describe("scan receipt lookup", () => {
  const scan = "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const environment = "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const partial = { scan_id:scan, version_id:null, manifest_digest:null, completeness:"partial", review_path:null,
    origin:"local", ruleset:"zasp-static.v2", findings:[{rule_id:"dependency.unpinned",count:1}], skipped_count:1, received_at:"2026-11-22T12:34:56+00:00" };
  const complete = { ...partial, version_id:row.id, completeness:"complete", review_path:"/inventory/tools?addon=" + row.id, manifest_digest:row.manifest_digest, skipped_count:0 };
  const scope = [scan,row.id,environment].join("/");

  it("reads a partial scan through the typed client with the selected scope and offers no version action", async () => {
    const requests: Request[] = [];
    const client = createAPIClient({getExpectedScope:() => scope, fetch:async req => {
      requests.push(req);
      return Response.json(new URL(req.url).pathname.endsWith(scan) ? partial : {items:[],next_cursor:null});
    }});
    const user = userEvent.setup();
    render(<APIProvider client={client}><AddonReviews canReview environment={environment} /></APIProvider>);
    expect(screen.getByRole("button",{name:"Open receipt"})).toBeDisabled();
    await user.type(screen.getByLabelText("Scan ID"),scan);
    await user.click(screen.getByRole("button",{name:"Open receipt"}));
    const receipt = await screen.findByRole("region",{name:"Scan receipt"});
    expect(within(receipt).getByText("Partial scan")).toBeVisible();
    expect(receipt).toHaveTextContent("Skipped entries 1");
    expect(receipt).toHaveTextContent("dependency.unpinned · 1");
    expect(within(receipt).queryByRole("link")).toBeNull();
    expect(requests.filter(req => new URL(req.url).pathname === "/api/v1/addon-scans/"+scan).map(req => [req.method,req.headers.get("X-Zasp-Expected-Scope")])).toEqual([["GET",scope]]);
    expect(requests.some(req => new URL(req.url).pathname.includes("/addon-versions/"))).toBe(false);
  });

  it("binds complete receipts to the exact version, hides a foreign link, and suppresses previously read data", async () => {
    const target = scanReceiptLink(scan, environment).split("?")[1];
    const registry = api();
    registry.scan.mockResolvedValue(decodeAddonScan(complete,scan));
    const view = render(<APIProvider><AddonReviews canReview={false} environment={environment} api={registry} initialScan={{ state:"selected", id:scan }} /></APIProvider>);
    expect(await screen.findByRole("link",{name:"Open version review"})).toHaveAttribute("href",complete.review_path + "&environment_id=" + environment);
    expect(screen.getByText(row.manifest_digest)).toBeVisible();
    view.rerender(<APIProvider><AddonReviews canReview={false} environment={row.id} api={registry} initialScan={{ state:"foreign" }} /></APIProvider>);
    expect(await screen.findByRole("alert")).toHaveTextContent("another Environment");
    expect(screen.queryByText(row.manifest_digest)).toBeNull();
    expect(registry.scan).toHaveBeenCalledTimes(1);
    expect(registry.list).not.toHaveBeenCalled();
    const versionQuery = addonVersionLink(row.id,environment).split("?")[1];
    expect(scopedAddonFromSearch(target,environment)).toEqual({state:"selected",id:scan});
    expect(scopedAddonFromSearch(target,row.id)).toEqual({state:"foreign"});
    expect(scopedAddonFromSearch(versionQuery,environment)).toEqual({state:"version",id:row.id});
    expect(scopedAddonFromSearch(versionQuery,row.id)).toEqual({state:"foreign"});
    const routeScope = {organizationID:scan, workspaceID:row.id, environmentID:environment};
    for (const query of [target,versionQuery]) {
      expect(parseActivityLink("/inventory/tools?"+query,routeScope)).toEqual({state:"none"});
      expect(parseActivityLink("/inventory/tools?"+query,{...routeScope,environmentID:row.id})).toEqual({state:"scope_mismatch"});
      expect(parseActivityLink("/inventory/tools?"+query+"&extra=untrusted",routeScope)).toEqual({state:"invalid"});
    }
    expect(scopedAddonFromSearch("?addon="+row.id,environment)).toBeUndefined();
    expect(scopedAddonFromSearch(target+"&addon="+row.id,environment)).toEqual({state:"invalid"});
    expect(scopedAddonFromSearch("?scan="+scan,environment)).toEqual({state:"invalid"});
    expect(scopedAddonFromSearch("?scan="+scan+"&scan="+scan,environment)).toEqual({state:"invalid"});
    for (const bad of [{...partial,version_id:row.id},{...partial,manifest_digest:complete.manifest_digest},{...partial,review_path:complete.review_path},{...partial,scan_id:row.id},{...complete,review_path:"https://example.invalid/"},{...partial,findings:[{rule_id:"dependency.unpinned",count:1_000_001}]},{...complete,skipped_count:1}]) {
      expect(()=>decodeAddonScan(bad,scan)).toThrow();
    }
  });
});
