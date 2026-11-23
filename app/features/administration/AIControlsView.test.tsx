import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import { AIControlsView } from "./AIControlsView";

const ids = [1, 2, 3].map(n => `pid_0000000${n}-0000-4000-8000-00000000000${n}`);
const expectedScope = ids.join("/");
const initialOrg = { organization_id: ids[0], ai_enabled: true, allowed_modes: ["deterministic_only", "zasp_vpc_slm", "dev_openrouter"], allowed_residency: "us_eu", allow_private_code_egress: true, require_zero_retention: true, version: 4 };
const initialEnv = { environment_id: ids[2], environment_class: "production", collection_mode: "metadata_only", mode: "deterministic_only", effective_mode: "deterministic_only", tier2_prompt_injection_enabled: false, tier2_purpose_drift_enabled: false, tier2_heuristic_fp_suppression_enabled: false, tier3_discovery_purpose_enabled: false, tier3_addon_audit_enabled: false, tier3_security_agent_planner_enabled: false, allow_redacted_summaries: false, allow_approved_code_snippets: false, allow_private_addon_bytes: false, tier2_profile: "review-model", tier3_provider: "", tier3_model_pin: "", credential_reference: "", credential_digest: "", monthly_budget_nano_credits: 0, version: 3 };

function setup(props: Partial<{ canEditOrganization: boolean; canEditEnvironment: boolean; fresh: boolean }> = {}, conflict = false) {
  const records = { organization: { ...initialOrg }, settings: { ...initialEnv } };
  const patches: { scope: string; body: unknown; headers: Headers }[] = [];
  const reauthenticate = vi.fn();
  const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
  const client = createAPIClient({ getCSRFToken: () => "session-token", fetch: async request => {
    expect(request.headers.get("X-Zasp-Expected-Scope")).toBe(expectedScope);
    if (request.url.endsWith("/qualifications")) return json({ items: [{ provider: "zasp_vpc_slm", model: "review-model", purpose: "indirect_injection_screen", qualified: true, checked_at: "2026-11-01T00:00:00Z", evidence_digest: "sha256:" + "a".repeat(64) }] });
    const scope = request.url.includes("/organization/") ? "organization" : "settings";
    if (request.method === "PATCH") {
      const body = await request.json();
      patches.push({ scope, headers: request.headers, body });
      if (conflict) return json({ code: "operation_conflict", retryable: false, message: "Changed", correlation_id: ids[0] }, 409);
      Object.assign(records[scope], body, { version: records[scope].version + 1 });
    }
    return json(records[scope]);
  } });
  render(<AIControlsView client={client} expectedScope={expectedScope} canEditOrganization canEditEnvironment fresh reauthenticate={reauthenticate} {...props} />);
  return { patches, reauthenticate };
}

describe("AI & Models", () => {
  it("edits the environment with scope, CSRF and version checks and enforces the privacy ceiling", async () => {
    const { patches } = setup();
    await userEvent.click(await screen.findByRole("button", { name: "Edit environment policy" }));
    const mode = screen.getByLabelText("Environment hosting mode");
    expect(screen.queryByRole("option", { name: "Development router" })).toBeNull();
    await userEvent.selectOptions(mode, "zasp_vpc_slm");
    expect(screen.getByLabelText(/Approved code snippets/)).toBeDisabled();
    expect(screen.getByLabelText(/Detect drift from approved purpose/)).toBeDisabled();
    await userEvent.click(screen.getByLabelText("Redacted summaries"));
    await userEvent.click(screen.getByLabelText("Screen untrusted content"));
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByText("Environment AI controls saved.")).toBeVisible();
    expect(patches).toHaveLength(1);
    expect(patches[0].body).toEqual({ mode: "zasp_vpc_slm", allow_redacted_summaries: true, tier2_prompt_injection_enabled: true });
    expect(patches[0].headers.get("If-Match")).toBe('"3"');
    expect(patches[0].headers.get("X-CSRF-Token")).toBe("session-token");
  });

  it("uses the organization version and requires an explicit reload after a conflict", async () => {
    const { patches } = setup({}, true);
    await userEvent.click(await screen.findByRole("button", { name: "Edit organization policy" }));
    await userEvent.click(screen.getByLabelText("Enable optional AI"));
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("policy changed");
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Reload settings" }));
    expect(await screen.findByRole("button", { name: "Edit organization policy" })).toBeEnabled();
    expect(patches[0].headers.get("If-Match")).toBe('"4"');
    expect(patches[0].body).toEqual({ ai_enabled: false });
  });

  it("keeps viewers read-only and requires fresh authentication for an editor", async () => {
    const { reauthenticate } = setup({ canEditOrganization: false, fresh: false });
    await waitFor(() => expect(screen.getByRole("button", { name: "Edit environment policy" })).toBeDisabled());
    expect(screen.queryByRole("button", { name: "Edit organization policy" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Reauthenticate" }));
    expect(reauthenticate).toHaveBeenCalledOnce();
  });
});
