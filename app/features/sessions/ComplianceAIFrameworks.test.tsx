import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import { decodeComplianceControlPage } from "../../../apps/web/api/administration-decoders";
import { complianceFrameworks } from "./ComplianceEvidenceView";
import { SessionsComplianceView } from "./SessionsComplianceView";

const organization = "pid_10000001-0000-4000-8000-000000000001";
const workspace = "pid_10000002-0000-4000-8000-000000000002";
const environment = "pid_10000003-0000-4000-8000-000000000003";
const principal = "pid_10000004-0000-4000-8000-000000000004";
const findingA = "pid_6b000001-0000-4000-8000-000000000001";
const findingB = "pid_6b000002-0000-4000-8000-000000000002";
const boundary = { principalID: principal, organizationID: organization, workspaceID: workspace, environmentID: environment, generation: 1, permitted: true, fresh: true, isCurrent: () => true };
const product = { id: "soc2_security-policies", framework: "soc2_security", name: "Policy definitions", evidence_ids: [], fresh_until: "1970-01-01T00:00:00Z", freshness: "missing" };
const identity = { id: "ASI03", framework: "owasp_agentic_top10_2026", name: "Identity and Privilege Abuse", evidence_ids: [findingA, findingB], fresh_until: "2026-11-15T00:00:00Z", freshness: "fresh", finding_count: 2 };
const rogue = { id: "ASI10", framework: "owasp_agentic_top10_2026", name: "Rogue Agents", evidence_ids: [], fresh_until: "1970-01-01T00:00:00Z", freshness: "missing", finding_count: 0 };
const inventory = { id: "GOVERN 1.6", framework: "nist_ai_rmf_1_0", name: "Mechanisms are in place to inventory AI systems", evidence_ids: [findingA], fresh_until: "2026-11-15T00:00:00Z", freshness: "fresh", finding_count: 140 };
function response(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }); }
function client(requests: { path: string; body?: unknown }[] = []) {
  return createAPIClient({ getCSRFToken: () => "c".repeat(32), getExpectedScope: () => `${organization}/${workspace}/${environment}`, fetch: async request => {
    const url = new URL(request.url);
    requests.push({ path: url.pathname + url.search, body: request.method === "POST" ? await request.clone().json() : undefined });
    if (url.pathname.endsWith("/controls")) return response({ items: [product, identity, rogue, inventory], page_info: { has_more: false, next_cursor: null } });
    if (url.pathname.endsWith("/evidence")) return response({ items: [], page_info: { has_more: false, next_cursor: null } });
    if (url.pathname.endsWith("/exports")) return response({ id: principal, status: "pending", formats: ["json", "csv", "human"], created_at: "2026-11-14T00:00:00Z", expires_at: "2099-01-01T00:00:00Z", failure_code: null, mapping_revision: "product-evidence-v1" }, 201);
    throw new Error(`Unexpected compliance request ${url.pathname}`);
  } });
}

describe("AI security frameworks on the compliance page", () => {
  it("offers the eight frameworks", async () => {
    render(<SessionsComplianceView surface="compliance" client={client()} complianceBoundary={boundary} />);
    const select = await screen.findByLabelText("Framework");
    expect(within(select).getAllByRole("option").map(option => (option as HTMLOptionElement).value)).toEqual(["", "soc2_security", "hipaa", "owasp_agentic_top10_2026", "owasp_llm_top10_2025", "mitre_atlas", "nist_ai_rmf_1_0", "iso_iec_42001_2023", "eu_ai_act"]);
    expect(complianceFrameworks).toHaveLength(8);
  });

  it("lists each AI control with its finding count and links to the findings", async () => {
    render(<SessionsComplianceView surface="compliance" client={client()} complianceBoundary={boundary} />);
    expect(await screen.findByText("OWASP Top 10 for Agentic Applications · ASI03 · Identity and Privilege Abuse")).toBeVisible();
    expect(screen.getByText("2 findings")).toBeVisible();
    const findings = within(screen.getByRole("list", { name: "Findings for ASI03" })).getAllByRole("link");
    expect(findings.map(link => link.getAttribute("href"))).toEqual([findingA, findingB].map(id => expect.stringContaining(id)));
    expect(findings[0].getAttribute("href")).toContain("/violations?entity_id=");
    // A control without findings says so; it is not "missing required evidence".
    expect(screen.getByText("OWASP Top 10 for Agentic Applications · ASI10 · Rogue Agents")).toBeVisible();
    expect(screen.getByText("No findings")).toBeVisible();
    expect(screen.queryByRole("list", { name: "Findings for ASI10" })).not.toBeInTheDocument();
    // More findings than the bounded preview.
    expect(screen.getByText("140 findings")).toBeVisible();
    expect(screen.getByText("Showing the first 1 of 140 findings.")).toBeVisible();
    // The product control is unchanged.
    expect(screen.getByText("Missing required evidence")).toBeVisible();

    await userEvent.selectOptions(screen.getByLabelText("Framework"), "nist_ai_rmf_1_0");
    expect(screen.queryByText(/ASI03/)).not.toBeInTheDocument();
    expect(screen.getByText("NIST AI RMF 1.0 · GOVERN 1.6 · Mechanisms are in place to inventory AI systems")).toBeVisible();
    expect(within(screen.getByLabelText("Control")).getByRole("option", { name: "GOVERN 1.6 · Mechanisms are in place to inventory AI systems" })).toBeInTheDocument();
  });

  it("exports the selected AI framework and control", async () => {
    const requests: { path: string; body?: unknown }[] = [];
    render(<SessionsComplianceView surface="compliance" client={client(requests)} complianceBoundary={boundary} />);
    await userEvent.selectOptions(await screen.findByLabelText("Framework"), "owasp_agentic_top10_2026");
    await userEvent.selectOptions(screen.getByLabelText("Control"), "ASI03");
    await userEvent.click(screen.getByRole("button", { name: "Create evidence export" }));
    expect(await screen.findByText("Export queued")).toBeVisible();
    expect(requests.find(request => request.path.endsWith("/exports"))?.body).toEqual({ framework: "owasp_agentic_top10_2026", control_id: "ASI03" });
  });

  it("decodes a finding count only when it covers the listed findings", () => {
    const page = (item: unknown) => ({ items: [item], page_info: { has_more: false, next_cursor: null } });
    expect(decodeComplianceControlPage(page(identity)).items[0].finding_count).toBe(2);
    expect(decodeComplianceControlPage(page(product)).items[0].finding_count).toBeUndefined();
    expect(() => decodeComplianceControlPage(page({ ...identity, finding_count: 1 }))).toThrow();
    expect(() => decodeComplianceControlPage(page({ ...identity, finding_count: "2" }))).toThrow();
    expect(() => decodeComplianceControlPage(page({ ...identity, findings: 2 }))).toThrow();
  });
});
