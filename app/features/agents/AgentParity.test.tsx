import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { decodeAgentEvidencePackResponse, decodeRelationshipPage } from "../../../apps/web/api/decoders";
import type { AgentEvidencePackResponse, Finding, InventorySummary } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { ProductionAgentSecurityView, type ProductionAgentSecurityAPI } from "./ProductionAgentSecurityView";

const ids = {
  active: "pid_10000001-0000-4000-8000-000000000001",
  inactive: "pid_10000002-0000-4000-8000-000000000002",
  unused: "pid_10000003-0000-4000-8000-000000000003",
  unknown: "pid_10000004-0000-4000-8000-000000000004",
  role: "pid_10000005-0000-4000-8000-000000000005",
  hidden: "pid_10000006-0000-4000-8000-000000000006",
  account: "pid_10000007-0000-4000-8000-000000000007",
  evidence: "pid_20000001-0000-4000-8000-000000000001",
  finding: "pid_30000001-0000-4000-8000-000000000001",
  run: "pid_40000001-0000-4000-8000-000000000001",
  test: "pid_60000001-0000-4000-8000-000000000001",
  testRun: "pid_70000001-0000-4000-8000-000000000001",
} as const;

function agent(id: string, name: string, activity: Pick<InventorySummary, "activity_state" | "last_activity_at">): InventorySummary {
  return { id, name, kind: "agent", owner: "security", team: "platform", tags: [], evidence_id: ids.evidence, confidence_basis_points: 9500, first_seen: "2026-08-19T00:00:00Z", last_seen: "2026-11-10T01:00:00Z", observed_at: "2026-11-10T01:00:00Z", fresh_until: "2026-11-11T01:00:00Z", freshness_state: "fresh", provider: "aws", source_kind: "aws_bedrock_agent", discovery: { method: "provider_api", platform: "bedrock_agent", signals: [] }, management_state: "managed", version: 1, ...activity };
}
const agents = [
  agent(ids.active, "Active agent", { activity_state: "active", last_activity_at: "2026-11-09T00:00:00Z" }),
  agent(ids.inactive, "Quiet agent", { activity_state: "inactive", last_activity_at: "2026-09-01T00:00:00Z" }),
  agent(ids.unused, "Unused role agent", { activity_state: "inactive", last_activity_at: null }),
  agent(ids.unknown, "Unmeasured agent", { activity_state: "unknown", last_activity_at: null }),
];
const source = { integration_id: ids.account, provider: "aws", source: "aws", source_identifier: `sha256:${"a".repeat(64)}`, snapshot_id: ids.role, generation: 1, evidence_id: ids.evidence, confidence_basis_points: 9500, observed_at: "2026-11-10T01:00:00Z", fresh_until: "2026-11-11T01:00:00Z", projection_version: 1, winning: true } as const;
const evidenceRecord = { id: ids.evidence, checksum: `sha256:${"b".repeat(64)}`, media_type: "application/json", schema_version: "typed_inventory_v1", parser_version: "parser_v1", tool_version: "tool_v1", collected_at: "2026-11-10T01:00:00Z", size_bytes: 128 } as const;

function api(overrides: Partial<ProductionAgentSecurityAPI> = {}): ProductionAgentSecurityAPI {
  const detail = (id: string) => ({ summary: agents.find((item) => item.id === id) ?? agents[0], sources: [], evidence: [] }) as never;
  return {
    listAgents: async () => agents, listTools: async () => [], listIdentities: async () => [], listRuntimes: async () => [],
    getAgent: async (id) => detail(id), getTool: async (id) => detail(id), getIdentity: async (id) => detail(id), getRuntime: async (id) => detail(id),
    getAgentCapabilities: async () => [], getAgentRelationships: async () => [], listAgentSessions: async () => [],
    updateAgent: async () => { throw new Error("unused"); }, getHomeSummary: async () => { throw new Error("unused"); },
    ...overrides,
  };
}
function view(value: ProductionAgentSecurityAPI, onNavigate: (path: string) => void = () => undefined) {
  window.history.replaceState({}, "", "/discovery/assets");
  return render(<APIProvider><ProductionAgentSecurityView path="/discovery/assets" api={value} onNavigate={onNavigate} /></APIProvider>);
}

afterEach(() => { vi.restoreAllMocks(); });

describe("inactive agents", () => {
  it("shows each agent's activity and filters the inactive ones", async () => {
    const user = userEvent.setup();
    view(api());
    expect(await screen.findByRole("row", { name: /Active agent.*Active · last activity 2026-11-09T00:00:00Z/ })).toBeVisible();
    expect(screen.getByRole("row", { name: /Quiet agent.*Inactive · last activity 2026-09-01T00:00:00Z/ })).toBeVisible();
    // The provider reports the role unused: inactive without a time.
    expect(within(screen.getByRole("row", { name: /Unused role agent/ })).getByText("Inactive")).toBeVisible();
    // No activity source is unknown, not inactive.
    expect(within(screen.getByRole("row", { name: /Unmeasured agent/ })).getByText("Unknown")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Inactive (2)" }));
    expect(screen.getByRole("button", { name: "Inactive (2)" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getAllByRole("row")).toHaveLength(3);
    expect(screen.getByRole("button", { name: "Open Quiet agent" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Open Unused role agent" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Open Unmeasured agent" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Open Active agent" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Open Unused role agent" }));
    expect(await screen.findByText(/The provider reports its execution role unused for 90 days/)).toBeVisible();
  });

  it("says so when no agent is inactive and does not count a dismissed one", async () => {
    const user = userEvent.setup();
    const dismissed = { ...agent(ids.inactive, "False positive", { activity_state: "inactive", last_activity_at: null }), discovery: { method: "inferred" as const, platform: "lambda_function", signals: ["env:openai"] }, tags: ["not-an-agent"], management_state: "dismissed" as const };
    view(api({ listAgents: async () => [agents[0], agents[3], dismissed] }));
    await user.click(await screen.findByRole("button", { name: "Inactive (0)" }));
    expect(screen.getByText(/No inactive agents in this scope. An agent with no activity source is reported as unknown, not inactive./)).toBeVisible();
  });
});

describe("agent credential inventory", () => {
  const relationships = [
    { id: "pid_50000001-0000-4000-8000-000000000001", from_id: ids.active, to_id: ids.role, type: "uses_identity", evidence_id: ids.evidence, from: { name: "Active agent", kind: "agent", provider: "aws", source_kind: "aws_bedrock_agent" }, to: { name: "support-agent-role", kind: "identity", provider: "aws", source_kind: "aws_role" } },
    // An identity the caller may not read: the identifier only.
    { id: "pid_50000002-0000-4000-8000-000000000002", from_id: ids.active, to_id: ids.hidden, type: "uses_identity", evidence_id: ids.evidence, from: { name: "Active agent", kind: "agent", provider: "aws", source_kind: "aws_bedrock_agent" } },
    { id: "pid_50000003-0000-4000-8000-000000000003", from_id: ids.account, to_id: ids.active, type: "contains", evidence_id: ids.evidence, from: { name: "123456789012", kind: "asset", provider: "aws", source_kind: "aws_account" }, to: { name: "Active agent", kind: "agent", provider: "aws", source_kind: "aws_bedrock_agent" } },
  ] as const;

  it("lists the identities an agent uses by name and links to each", async () => {
    const user = userEvent.setup();
    const onNavigate = vi.fn();
    view(api({ getAgentRelationships: async () => relationships }), onNavigate);
    await user.click(await screen.findByRole("button", { name: "Open Active agent" }));
    const list = await screen.findByRole("list", { name: "Identities and credentials" });
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("support-agent-role · IAM role · AWS");
    expect(items[1]).toHaveTextContent(`${ids.hidden} · not readable with your access`);
    const link = within(list).getByRole("link", { name: "Open identity support-agent-role" });
    expect(link).toHaveAttribute("href", `/identities?inventory=${ids.role}`);
    await user.click(link);
    expect(onNavigate).toHaveBeenCalledWith(`/identities?inventory=${ids.role}`);
    // The account that contains the agent is a relationship, not a credential.
    expect(within(list).queryByText(/123456789012/)).toBeNull();
    expect(screen.getByText(/contains · 123456789012 → Active agent/)).toBeVisible();
  });

  it("says when no identity is recorded", async () => {
    const user = userEvent.setup();
    view(api());
    await user.click(await screen.findByRole("button", { name: "Open Active agent" }));
    expect(await screen.findByText("No identity or credential is recorded for this agent.")).toBeVisible();
  });

  it("decodes named ends strictly", () => {
    const page = (items: readonly unknown[]) => ({ items, page_info: { next_cursor: null, has_more: false } });
    expect(decodeRelationshipPage(page(relationships)).items).toHaveLength(3);
    const [named] = relationships;
    for (const refused of [
      { ...named, to: { ...named.to, name: "" } },
      { ...named, to: { ...named.to, kind: "credential" } },
      { ...named, to: { ...named.to, provider: "gcp" } },
      { ...named, to: { ...named.to, source_kind: "AWS Role" } },
      { ...named, to: { ...named.to, arn: "arn:aws:iam::123456789012:role/x" } },
      { ...named, target: named.to },
    ]) expect(() => decodeRelationshipPage(page([refused]))).toThrow();
  });
});

describe("agent evidence pack", () => {
  const finding: Finding = { id: ids.finding, source: "posture", rule: "ownerless_agent", title: "Agent has no owner", severity: "high", status: "open", agent_id: ids.active, evidence_ids: [ids.evidence], risk_factors: [], version: 1, created_at: "2026-11-01T00:00:00Z", updated_at: "2026-11-02T00:00:00Z", frameworks: [{ framework: "owasp_agentic_top10_2026", control: "ASI10", title: "Rogue Agents" }] };
  function pack(overrides: Partial<AgentEvidencePackResponse["pack"]> = {}): AgentEvidencePackResponse {
    return { markdown: "# Agent evidence pack: Active agent\n", pack: {
      schema_version: "agent-evidence-pack-v1", generated_at: "2026-11-14T09:00:00Z", organization_id: ids.account, workspace_id: ids.account, environment_id: ids.account,
      agent: { summary: agents[0], sources: [source], evidence: [evidenceRecord] },
      findings: { status: "complete", items: [finding] },
      security_agent_runs: { status: "complete", items: [{ finding_ids: [ids.finding], run: { run: { id: ids.run }, approvals: [] } }] },
      red_team_tests: { status: "complete", items: [{ id: ids.test, target_id: ids.active } as never] },
      red_team_runs: { status: "complete", items: [{ id: ids.testRun, definition_id: ids.test } as never] },
      ...overrides,
    } };
  }
  function downloads() {
    const saved: { name: string; type: string }[] = [];
    Object.assign(URL, { createObjectURL: vi.fn((blob: Blob) => { saved.push({ name: "", type: blob.type }); return "blob:pack"; }), revokeObjectURL: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { saved[saved.length - 1].name = this.download; });
    return saved;
  }

  it("downloads the pack as JSON and Markdown from the agent detail", async () => {
    const user = userEvent.setup();
    const saved = downloads();
    const getAgentEvidencePack = vi.fn(async () => pack());
    view(api({ getAgentEvidencePack }));
    await user.click(await screen.findByRole("button", { name: "Open Active agent" }));
    await user.click(await screen.findByRole("button", { name: "Download evidence pack" }));
    expect(await screen.findByText("Evidence pack downloaded as JSON and Markdown.")).toBeVisible();
    expect(getAgentEvidencePack).toHaveBeenCalledWith(ids.active);
    expect(saved).toEqual([{ name: "agent-evidence-Active-agent.json", type: "application/json" }, { name: "agent-evidence-Active-agent.md", type: "text/markdown" }]);
  });

  it("says which sections the pack does not hold", async () => {
    const user = userEvent.setup();
    downloads();
    view(api({ getAgentEvidencePack: async () => pack({ findings: { status: "not_permitted", items: [] }, security_agent_runs: { status: "not_permitted", items: [] }, red_team_runs: { status: "truncated", items: [{ id: ids.testRun, definition_id: ids.test } as never] } }) }));
    await user.click(await screen.findByRole("button", { name: "Open Active agent" }));
    await user.click(await screen.findByRole("button", { name: "Download evidence pack" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Not complete — Findings: not readable with your access; Security Agent actions: not readable with your access; Red team results: more records than the pack holds.");
  });

  it("reports a failure and offers no download where the service has no pack", async () => {
    const user = userEvent.setup();
    const saved = downloads();
    const { unmount } = view(api({ getAgentEvidencePack: async () => { throw new Error("unavailable"); } }));
    await user.click(await screen.findByRole("button", { name: "Open Active agent" }));
    await user.click(await screen.findByRole("button", { name: "Download evidence pack" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The evidence pack could not be generated. Retry.");
    expect(saved).toHaveLength(0);
    unmount();
    view(api());
    await user.click(await screen.findByRole("button", { name: "Open Active agent" }));
    await screen.findByRole("heading", { name: "Activity" });
    expect(screen.queryByRole("button", { name: "Download evidence pack" })).toBeNull();
  });

  it("decodes a pack bound to its agent", () => {
    expect(decodeAgentEvidencePackResponse(pack(), ids.active).pack.findings.items).toHaveLength(1);
    const value = pack();
    for (const refused of [
      { ...value, markdown: "" },
      { ...value, pack: { ...value.pack, schema_version: "agent-evidence-pack-v2" } },
      // A pack of another agent, or holding another agent's records.
      { ...value, pack: { ...value.pack, agent: { ...value.pack.agent, summary: agents[1] } } },
      { ...value, pack: { ...value.pack, findings: { status: "complete", items: [{ ...finding, agent_id: ids.inactive }] } } },
      { ...value, pack: { ...value.pack, red_team_tests: { status: "complete", items: [{ id: ids.test, target_id: ids.inactive }] } } },
      { ...value, pack: { ...value.pack, red_team_runs: { status: "complete", items: [{ id: ids.testRun, definition_id: ids.run }] } } },
      // A run that names a finding the pack does not hold.
      { ...value, pack: { ...value.pack, security_agent_runs: { status: "complete", items: [{ finding_ids: [ids.run], run: {} }] } } },
      // A section that is not readable holds nothing.
      { ...value, pack: { ...value.pack, findings: { status: "not_permitted", items: [finding] }, security_agent_runs: { status: "not_permitted", items: [] } } },
      { ...value, pack: { ...value.pack, findings: { status: "partial", items: [] }, security_agent_runs: { status: "complete", items: [] } } },
      { ...value, pack: { ...value.pack, signature: "none" } },
    ]) expect(() => decodeAgentEvidencePackResponse(refused, ids.active)).toThrow();
    expect(() => decodeAgentEvidencePackResponse(value, ids.inactive)).toThrow();
  });
});
