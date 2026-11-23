import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import { decodeCoverage, decodeCoverageEvidence, type CatalogFramework } from "../../../apps/web/api/framework-coverage";
import { catalogLink, parseCatalogLink } from "../../domain/coverage-links";
import { parseActivityLink } from "../../domain/activity-links";
import { SessionsComplianceView } from "./SessionsComplianceView";
import { SourceFrameworkEvidence } from "./FrameworkCoverage";

const productID = (n: number) => "pid_00000000-0000-4000-8000-" + String(n).padStart(12, "0");
const organizationID = productID(1), workspaceID = productID(2), environmentID = productID(3);
const boundary = { organizationID, workspaceID, environmentID, principalID: productID(4), fresh: true, permitted: true, isCurrent: () => true, generation: 0 };
const digest = "sha256:" + "d".repeat(64);
const at = "2026-11-21T10:00:00Z";
const owner = "Application security";
const framework: CatalogFramework = "owasp_agentic_top10";
const entry = { framework, edition: "2026", upstream_id: "ASI04" };
const reference = { ...entry, manifest_digest: digest, rule: "dependency.unpinned", rule_version: "2026.1", evidence_kind: "static_scan", source_id: productID(7), source_kind: "addon_version", occurred_at: at };

function coverage(framework: string, edition: string, hasEvidence = true) {
  const first = framework === "owasp_agentic_top10" ? "ASI04" : "LLM03";
  const row = (id: string, title: string, counts: object) => ({
    control: {
      framework, edition, upstream_id: id, title, owner, scope: "Skills", rationale: "Applicable to installed skills.",
      applicability: "applicable", source_url: "https://owasp.org/", source_digest: digest, license: "CC BY-SA 4.0",
      attribution: "OWASP", digest_basis: "reviewed_index", kind: "risk", status: "active",
    }, evidence_counts: counts, last_verified_at: null,
  });
  return {
    framework, edition, source_digest: digest, total_controls: 10, matched_controls: 10, collected_at: at, next_after: "next",
    summary: { applicable_controls: 8, verified_applicable_controls: 0, unassessed_controls: 2, out_of_scope_controls: 0, risks: 10, techniques: 0, subtechniques: 0, mitigations: 0 },
    items: [row(first, "Supply chain", hasEvidence ? { static_scan: 2 } : {}), row("A10", "Uninstrumented surface", {})],
  };
}

function setup(args: { denyDetail?: boolean; blank?: boolean; environment?: string; verified?: string } = {}) {
  const requests: { path: string; body?: unknown; scope?: string | null }[] = [];
  const client = createAPIClient({
    getCSRFToken: () => "c".repeat(32), getExpectedScope: () => [organizationID, workspaceID, args.environment ?? environmentID].join("/"),
    fetch: async req => {
      const url = new URL(req.url), path = url.pathname, q = url.searchParams;
      requests.push({ path: path + url.search, scope: req.headers.get("X-Zasp-Expected-Scope"), body: req.method === "POST" ? await req.clone().json() : undefined });
      const response = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
      if (path.endsWith("/coverage/evidence")) {
        if (args.denyDetail) return response({ code: "authorization_rejected", message: "denied", correlation_id: productID(20), retryable: false }, 403);
        return response({ items: args.blank ? [] : [reference], next_after: null });
      }
      if (path.endsWith("/coverage")) {
        const page = coverage(q.get("framework")!, q.get("edition")!, !args.blank);
        if (args.verified) Object.assign(page.items[0], {last_verified_at:args.verified});
        if (q.get("upstream_id") || q.get("evidence_kind")) {
          page.items = page.items.filter(item => (!q.has("upstream_id") || item.control.upstream_id === q.get("upstream_id")) &&
            (!q.has("evidence_kind") || Object.hasOwn(item.evidence_counts, q.get("evidence_kind")!)));
          page.matched_controls = page.items.length;
          return response({ ...page, next_after: null });
        }
        return response(page);
      }
      if (path.endsWith("/editions")) return response({ items: [
        { framework, edition: "2026" }, { framework: "owasp_llm_top10", edition: "2025" }, { framework: "owasp_llm_top10", edition: "2026" },
      ].map(item => ({ ...item, source_digest: digest, total_controls: 10 })) });
      if (path.endsWith("/exports")) return response({ id: productID(8), status: "pending", formats: ["json","csv","human"], created_at: at, expires_at: "2099-01-01T00:00:00Z", failure_code: null, mapping_revision: "product-evidence-v1" }, 201);
      if (path.endsWith("/controls") || path.endsWith("/evidence")) return response({ items: [], page_info: { has_more: false, next_cursor: null } });
      if (path.includes("/exports/")) return response({ code: "source_unavailable", message: "Unavailable" }, 404);
      throw new Error(path);
    },
  });
  return { client, requests };
}

describe("Edition-qualified framework coverage", () => {
  it("keeps the full denominator and unknown coverage, drills into a static scan and exports the same scope and filters", async () => {
    const { client, requests } = setup();
    render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} />);
    await userEvent.click(await screen.findByRole("button", { name: "Framework coverage" }));
    expect(await screen.findByText("10 of 10 catalog entries")).toBeVisible();
    expect(screen.getByText("Unknown — no mapped evidence")).toBeVisible();
    await userEvent.selectOptions(screen.getByLabelText("Evidence kind"), "static_scan");
    expect(await screen.findByText("1 of 10 catalog entries")).toBeVisible();
    await userEvent.type(screen.getByLabelText("Control ID"), "ASI04");
    await userEvent.click(screen.getByRole("button", { name: "Apply control" }));
    const target = await screen.findByRole("link", { name: "Open add-on version" });
    expect(screen.getByText("Skill manifest digest")).toBeVisible();
    expect(target).toHaveAttribute("href", "/inventory/tools?addon=" + productID(7) + "&environment_id=" + environmentID);
    expect(parseActivityLink(target.getAttribute("href")!, boundary).state).toBe("none");
    expect(screen.getByText("No verification recorded")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Export this selection" }));
    expect(await screen.findByText("Export queued")).toBeVisible();
    expect(requests.find(req => req.body)?.body).toEqual({ ...entry, evidence_kind: "static_scan" });
    expect(requests.some(req => req.path.includes("coverage/evidence?") && req.path.includes("upstream_id=ASI04") && req.path.includes("evidence_kind=static_scan"))).toBe(true);
  });

  it("selects separate LLM editions, clears previous control filters, and keeps the whole denominator on an empty evidence filter", async () => {
    const { client, requests } = setup({ blank: true });
    render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={{ ...boundary, fresh: false }} selectedCatalog={entry} />);
    await screen.findByRole("button", { name: "ASI04 · Supply chain" });
    expect(screen.getByRole("button", { name: "Export this selection" })).toBeDisabled();
    await userEvent.selectOptions(screen.getByLabelText("Catalog framework"), "owasp_llm_top10");
    await userEvent.selectOptions(screen.getByLabelText("Edition"), "2026");
    expect(screen.getByLabelText("Control ID")).toHaveValue("");
    await userEvent.selectOptions(screen.getByLabelText("Evidence kind"), "verified_prevention");
    expect(await screen.findByText("0 of 10 catalog entries")).toBeVisible();
    expect(screen.queryByText("ASI04 · Supply chain")).toBeNull();
    expect(requests.some(req => req.path.includes("framework=owasp_llm_top10&edition=2026"))).toBe(true);
  });

  it("reloads the same edition in a second Environment and discards the first Environment’s counts", async () => {
    const first = setup();
    const view = render(<SessionsComplianceView surface="compliance" client={first.client} complianceBoundary={boundary} selectedCatalog={entry} />);
    expect(await screen.findByText("Static scan · 2")).toBeVisible();
    const other = productID(23), second = setup({ blank: true, environment: other });
    view.rerender(<SessionsComplianceView surface="compliance" client={second.client} selectedCatalog={entry}
      complianceBoundary={{ ...boundary, environmentID: other, generation: 2 }} />);
    expect(screen.queryByText("Static scan · 2")).toBeNull();
    expect(await screen.findByText("Unknown — no mapped evidence")).toBeVisible();
    expect(second.requests.filter(r => r.path.includes("/coverage?")).map(r => r.scope)).toEqual([[organizationID, workspaceID, other].join("/")]);
  });

  it("marks older prevention proof stale and rejects verification dated after collection", async () => {
    const stale=setup({verified:"2026-10-20T10:00:00Z"});
    const view=render(<SessionsComplianceView surface="compliance" client={stale.client} complianceBoundary={boundary} selectedCatalog={entry}/>);
    expect(await screen.findByText("Stale")).toBeVisible();
    const edge=setup({verified:"2026-10-22T10:00:00Z"});
    view.rerender(<SessionsComplianceView surface="compliance" client={edge.client} complianceBoundary={{...boundary,generation:2}} selectedCatalog={entry}/>);
    expect(await screen.findByText("Current")).toBeVisible();
    const future = coverage(framework,"2026");
    Object.assign(future.items[0],{last_verified_at:"2026-11-23T00:00:00Z"});
    expect(() => decodeCoverage(future,{framework,edition:"2026"})).toThrow();
  });

  it("hides protected sources on denial, and an unauthorized page never queries the catalog", async () => {
    const { client } = setup({ denyDetail: true });
    const view = render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} selectedCatalog={entry} />);
    const details = await screen.findByRole("region", { name: "ASI04 details" });
    expect(await within(details).findByRole("alert")).toHaveTextContent("unavailable");
    expect(screen.queryByRole("link", { name: "Open add-on version" })).toBeNull();
    const second = setup();
    view.rerender(<SessionsComplianceView surface="compliance" client={second.client} complianceBoundary={{ ...boundary, permitted: false, generation: 2 }} selectedCatalog={entry} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Access denied");
    expect(second.requests).toEqual([]);
  });

  it("looks up memberships for an exact authorized source and rejects cross-scope or ambiguous links", async () => {
    const { client, requests } = setup();
    render(<SourceFrameworkEvidence client={client} scope={boundary} kind="addon_version" id={productID(7)} />);
    expect(requests).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: "View framework references" }));
    const link = await screen.findByRole("link", { name: /2026 · ASI04/ });
    const href = catalogLink(entry, boundary);
    expect(link).toHaveAttribute("href", href);
    expect(parseCatalogLink(href, boundary)).toEqual({ state: "selected", target: entry });
    expect(parseCatalogLink(href, { ...boundary, environmentID: productID(9) }).state).toBe("scope_mismatch");
    expect(parseCatalogLink(href + "&edition=2025", boundary).state).toBe("invalid");
    expect(requests[0].path).toContain("source_id=" + productID(7));
    expect(() => decodeCoverageEvidence({ items: [reference], next_after: null }, { source_kind: "runtime_action", source_id: productID(7) })).toThrow();
    expect(() => decodeCoverage({ ...coverage(framework, "2026"), edition: "2025" }, entry)).toThrow();
  });
});
